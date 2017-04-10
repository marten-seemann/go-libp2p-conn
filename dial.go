package conn

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	ci "github.com/libp2p/go-libp2p-crypto"
	iconn "github.com/libp2p/go-libp2p-interface-conn"
	ipnet "github.com/libp2p/go-libp2p-interface-pnet"
	lgbl "github.com/libp2p/go-libp2p-loggables"
	peer "github.com/libp2p/go-libp2p-peer"
	tpt "github.com/libp2p/go-libp2p-transport"
	smux "github.com/libp2p/go-stream-muxer"
	ma "github.com/multiformats/go-multiaddr"
	msmux "github.com/multiformats/go-multistream"
)

type WrapFunc func(tpt.Conn) tpt.Conn

type timeoutReadWriteCloser interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Dialer is an object that can open connections. We could have a "convenience"
// Dial function as before, but it would have many arguments, as dialing is
// no longer simple (need a peerstore, a local peer, a context, a network, etc)
type Dialer struct {
	// LocalPeer is the identity of the local Peer.
	LocalPeer peer.ID

	// LocalAddrs is a set of local addresses to use.
	//LocalAddrs []ma.Multiaddr

	// Dialers are the sub-dialers usable by this dialer
	// selected in order based on the address being dialed
	Dialers []tpt.Dialer

	// PrivateKey used to initialize a secure connection.
	// Warning: if PrivateKey is nil, connection will not be secured.
	PrivateKey ci.PrivKey

	// Protector makes dialer part of a private network.
	// It includes implementation details how connection are protected.
	// Can be nil, then dialer is in public network.
	Protector ipnet.Protector

	// Wrapper to wrap the raw connection (optional)
	Wrapper WrapFunc

	fallback tpt.Dialer

	streamMuxer smux.Transport
}

func NewDialer(p peer.ID, pk ci.PrivKey, wrap WrapFunc, sm smux.Transport) *Dialer {
	return &Dialer{
		LocalPeer:   p,
		PrivateKey:  pk,
		Wrapper:     wrap,
		fallback:    new(tpt.FallbackDialer),
		streamMuxer: sm,
	}
}

// String returns the string rep of d.
func (d *Dialer) String() string {
	return fmt.Sprintf("<Dialer %s ...>", d.LocalPeer)
}

// Dial connects to a peer over a particular address
// Ensures raddr is part of peer.Addresses()
// Example: d.DialAddr(ctx, peer.Addresses()[0], peer)
func (d *Dialer) Dial(ctx context.Context, raddr ma.Multiaddr, remote peer.ID) (iconn.Conn, error) {
	logdial := lgbl.Dial("conn", d.LocalPeer, remote, nil, raddr)
	logdial["encrypted"] = (d.PrivateKey != nil) // log wether this will be an encrypted dial or not.
	logdial["inPrivNet"] = (d.Protector != nil)

	defer log.EventBegin(ctx, "connDial", logdial).Done()

	if d.Protector == nil && ipnet.ForcePrivateNetwork {
		log.Error("tried to dial with no Private Network Protector but usage" +
			" of Private Networks is forced by the enviroment")
		return nil, ipnet.ErrNotInPrivateNetwork
	}

	var connOut iconn.Conn
	var errOut error
	done := make(chan struct{})

	// do it async to ensure we respect done context
	go func() {
		defer func() {
			select {
			case done <- struct{}{}:
			case <-ctx.Done():
			}
		}()

		tptConn, err := d.rawConnDial(ctx, raddr, remote)
		if err != nil {
			errOut = err
			return
		}

		if d.Protector != nil {
			var pconn tpt.Conn
			pconn, err = d.Protector.Protect(tptConn)
			if err != nil {
				tptConn.Close()
				errOut = err
				return
			}
			tptConn = pconn
		}

		if d.Wrapper != nil {
			tptConn = d.Wrapper(tptConn)
		}

		cryptoProtoChoice := SecioTag
		if !iconn.EncryptConnections || d.PrivateKey == nil {
			cryptoProtoChoice = NoEncryptionTag
		}

		var stream timeoutReadWriteCloser
		switch con := tptConn.(type) {
		case tpt.SingleStreamConn:
			stream = con
		case tpt.MultiStreamConn:
			stream, err = con.OpenStream()
			if err != nil {
				errOut = err
				return
			}
			defer stream.Close()
		}

		stream.SetReadDeadline(time.Now().Add(NegotiateReadTimeout))
		err = msmux.SelectProtoOrFail(cryptoProtoChoice, stream)
		if err != nil {
			errOut = err
			return
		}

		// clear deadline
		stream.SetReadDeadline(time.Time{})

		c, err := newSingleConn(ctx, d.LocalPeer, remote, d.PrivateKey, tptConn, d.streamMuxer, false)
		if err != nil {
			tptConn.Close()
			errOut = err
			return
		}

		connOut = c
	}()

	select {
	case <-ctx.Done():
		logdial["error"] = ctx.Err().Error()
		logdial["dial"] = "failure"
		return nil, ctx.Err()
	case <-done:
		// whew, finished.
	}

	if errOut != nil {
		logdial["error"] = errOut.Error()
		logdial["dial"] = "failure"
		return nil, errOut
	}

	logdial["dial"] = "success"
	return connOut, nil
}

func (d *Dialer) AddDialer(pd tpt.Dialer) {
	d.Dialers = append(d.Dialers, pd)
}

// returns dialer that can dial the given address
func (d *Dialer) subDialerForAddr(raddr ma.Multiaddr) tpt.Dialer {
	for _, pd := range d.Dialers {
		if pd.Matches(raddr) {
			return pd
		}
	}

	if d.fallback.Matches(raddr) {
		return d.fallback
	}

	return nil
}

// rawConnDial dials the underlying net.Conn + manet.Conns
func (d *Dialer) rawConnDial(ctx context.Context, raddr ma.Multiaddr, remote peer.ID) (tpt.Conn, error) {
	if strings.HasPrefix(raddr.String(), "/ip4/0.0.0.0") {
		log.Event(ctx, "connDialZeroAddr", lgbl.Dial("conn", d.LocalPeer, remote, nil, raddr))
		return nil, fmt.Errorf("Attempted to connect to zero address: %s", raddr)
	}

	sd := d.subDialerForAddr(raddr)
	if sd == nil {
		return nil, fmt.Errorf("no dialer for %s", raddr)
	}

	return sd.DialContext(ctx, raddr)
}
