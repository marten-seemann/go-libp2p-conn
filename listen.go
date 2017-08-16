package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	tec "github.com/jbenet/go-temp-err-catcher"
	"github.com/jbenet/goprocess"
	goprocessctx "github.com/jbenet/goprocess/context"
	ic "github.com/libp2p/go-libp2p-crypto"
	iconn "github.com/libp2p/go-libp2p-interface-conn"
	ipnet "github.com/libp2p/go-libp2p-interface-pnet"
	peer "github.com/libp2p/go-libp2p-peer"
	tpt "github.com/libp2p/go-libp2p-transport"
	filter "github.com/libp2p/go-maddr-filter"
	smux "github.com/libp2p/go-stream-muxer"
	ma "github.com/multiformats/go-multiaddr"
	msmux "github.com/multiformats/go-multistream"
)

const (
	SecioTag        = "/secio/1.0.0"
	NoEncryptionTag = "/plaintext/1.0.0"
)

var (
	connAcceptBuffer  = 32
	ConnAcceptTimeout = 60 * time.Second
)

// ConnWrapper is any function that wraps a raw multiaddr connection
type ConnWrapper func(tpt.Conn) tpt.Conn

// listener is an object that can accept connections. It implements Listener
type listener struct {
	tpt.Listener

	local  peer.ID    // LocalPeer is the identity of the local Peer
	privk  ic.PrivKey // private key to use to initialize secure conns
	protec ipnet.Protector

	streamMuxer smux.Transport

	filters *filter.Filters

	wrapper ConnWrapper
	catcher tec.TempErrCatcher

	proc goprocess.Process

	mux *msmux.MultistreamMuxer

	incoming chan connOrErr

	ctx context.Context
}

var _ iconn.Listener = &listener{}

func (l *listener) teardown() error {
	defer log.Debugf("listener closed: %s %s", l.local, l.Multiaddr())
	return l.Listener.Close()
}

func (l *listener) Close() error {
	log.Debugf("listener closing: %s %s", l.local, l.Multiaddr())
	return l.proc.Close()
}

func (l *listener) String() string {
	return fmt.Sprintf("<Listener %s %s>", l.local, l.Multiaddr())
}

func (l *listener) SetAddrFilters(fs *filter.Filters) {
	l.filters = fs
}

type connOrErr struct {
	conn iconn.Conn
	err  error
}

// Accept waits for and returns the next connection to the listener.
func (l *listener) Accept() (iconn.Conn, error) {
	if l.privk == nil || !iconn.EncryptConnections {
		log.Warningf("listener %s listening INSECURELY!", l)
	}

	for c := range l.incoming {
		if c.err != nil {
			return nil, c.err
		}
		return c.conn, nil
	}
	return nil, errors.New("listener is closed")
}

func (l *listener) Addr() net.Addr {
	return l.Listener.Addr()
}

// Multiaddr is the identity of the local Peer.
// If there is an error converting from net.Addr to ma.Multiaddr,
// the return value will be nil.
func (l *listener) Multiaddr() ma.Multiaddr {
	return l.Listener.Multiaddr()
}

// LocalPeer is the identity of the local Peer.
func (l *listener) LocalPeer() peer.ID {
	return l.local
}

func (l *listener) Loggable() map[string]interface{} {
	return map[string]interface{}{
		"listener": map[string]interface{}{
			"peer":      l.LocalPeer(),
			"address":   l.Multiaddr(),
			"secure":    (l.privk != nil),
			"inPrivNet": (l.protec != nil),
		},
	}
}

func (l *listener) handleIncoming() {
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		close(l.incoming)
	}()

	wg.Add(1)
	defer wg.Done()

	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if l.catcher.IsTemporary(err) {
				continue
			}
			l.incoming <- connOrErr{err: err}
			return
		}

		if l.filters != nil && l.filters.AddrBlocked(conn.RemoteMultiaddr()) {
			log.Debugf("blocked connection from %s", conn.RemoteMultiaddr())
			conn.Close()
			continue
		}

		log.Debugf("listener %s got connection: %s <---> %s", l, conn.LocalMultiaddr(), conn.RemoteMultiaddr())

		wg.Add(1)
		go func() {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(l.ctx, ConnAcceptTimeout)
			defer cancel()

			done := make(chan struct{})
			go func() {
				defer close(done)

				if l.protec != nil {
					pc, err := l.protec.Protect(conn)
					if err != nil {
						conn.Close()
						log.Warning("protector failed: ", err)
						return
					}
					conn = pc
				}

				// If we have a wrapper func, wrap this conn
				if l.wrapper != nil {
					conn = l.wrapper(conn)
				}

				var stream io.ReadWriteCloser
				switch conn := conn.(type) {
				case tpt.SingleStreamConn:
					stream = conn
				case tpt.MultiStreamConn:
					stream, err = conn.AcceptStream()
					if err != nil {
						conn.Close()
						log.Warning("accepting stream failed: ", err)
						return
					}
					defer stream.Close()
				}

				if _, _, err := l.mux.Negotiate(stream); err != nil {
					log.Warning("incoming conn: negotiation of crypto protocol failed: ", err)
					conn.Close()
					return
				}

				c, err := newSingleConn(ctx, l.local, "", l.privk, conn, l.streamMuxer, true)
				if err != nil {
					log.Warning("connection setup failed: ", err)
					conn.Close()
					return
				}

				l.incoming <- connOrErr{conn: c}
			}()

			select {
			case <-ctx.Done():
				log.Warning("incoming conn: conn not established in time:", ctx.Err().Error())
				conn.Close()
				return
			case <-done: // connection completed (or errored)
			}
		}()
	}
}

func WrapTransportListener(ctx context.Context, ml tpt.Listener, local peer.ID, pstpt smux.Transport,
	sk ic.PrivKey) (iconn.Listener, error) {
	return WrapTransportListenerWithProtector(ctx, ml, local, sk, pstpt, nil)
}

func WrapTransportListenerWithProtector(ctx context.Context, ml tpt.Listener, local peer.ID,
	sk ic.PrivKey, pstpt smux.Transport, protec ipnet.Protector) (iconn.Listener, error) {
	if protec == nil && ipnet.ForcePrivateNetwork {
		log.Error("tried to listen with no Private Network Protector but usage" +
			" of Private Networks is forced by the enviroment")
		return nil, ipnet.ErrNotInPrivateNetwork
	}

	l := &listener{
		Listener:    ml,
		local:       local,
		privk:       sk,
		protec:      protec,
		mux:         msmux.NewMultistreamMuxer(),
		incoming:    make(chan connOrErr, connAcceptBuffer),
		ctx:         ctx,
		streamMuxer: pstpt,
	}
	l.proc = goprocessctx.WithContextAndTeardown(ctx, l.teardown)
	l.catcher.IsTemp = func(e error) bool {
		// ignore connection breakages up to this point. but log them
		if e == io.EOF {
			log.Debugf("listener ignoring conn with EOF: %s", e)
			return true
		}

		te, ok := e.(tec.Temporary)
		if ok {
			log.Debugf("listener ignoring conn with temporary err: %s", e)
			return te.Temporary()
		}
		return false
	}

	if iconn.EncryptConnections && sk != nil {
		l.mux.AddHandler(SecioTag, nil)
	} else {
		l.mux.AddHandler(NoEncryptionTag, nil)
	}

	go l.handleIncoming()

	log.Debugf("Conn Listener on %s", l.Multiaddr())
	log.Event(ctx, "swarmListen", l)
	return l, nil
}

type ListenerConnWrapper interface {
	SetConnWrapper(ConnWrapper)
}

// SetConnWrapper assigns a maconn ConnWrapper to wrap all incoming
// connections with. MUST be set _before_ calling `Accept()`
func (l *listener) SetConnWrapper(cw ConnWrapper) {
	l.wrapper = cw
}
