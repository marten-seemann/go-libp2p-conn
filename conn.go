package conn

import (
	"context"
	"errors"
	"io"
	"net"

	logging "github.com/ipfs/go-log"
	ci "github.com/libp2p/go-libp2p-crypto"
	ic "github.com/libp2p/go-libp2p-crypto"
	iconn "github.com/libp2p/go-libp2p-interface-conn"
	lgbl "github.com/libp2p/go-libp2p-loggables"
	peer "github.com/libp2p/go-libp2p-peer"
	secio "github.com/libp2p/go-libp2p-secio"
	tpt "github.com/libp2p/go-libp2p-transport"
	smux "github.com/libp2p/go-stream-muxer"
	ma "github.com/multiformats/go-multiaddr"
)

var log = logging.Logger("conn")

// singleConn represents a single stream-multipexed connection to another Peer (IPFS Node).
type singleConn struct {
	streamConn smux.Conn
	tptConn    tpt.Conn

	secSession secio.Session

	event io.Closer
}

var _ iconn.Conn = &singleConn{}

// newSingleConn constructs a new connection
func newSingleConn(ctx context.Context, local, remote peer.ID, privKey ci.PrivKey, tptConn tpt.Conn, pstpt smux.Transport, isServer bool) (iconn.Conn, error) {
	ml := lgbl.Dial("conn", local, remote, tptConn.LocalMultiaddr(), tptConn.RemoteMultiaddr())

	var streamConn smux.Conn
	var secSession secio.Session
	switch conn := tptConn.(type) {
	case tpt.DuplexConn:
		c := conn
		// 1. secure the connection
		if privKey != nil && iconn.EncryptConnections {
			var err error
			secSession, err = setupSecureSession(ctx, local, privKey, conn)
			if err != nil {
				return nil, err
			}
			c = &secureDuplexConn{
				insecure: conn,
				secure:   secSession,
			}
		} else {
			log.Warning("creating INSECURE connection %s at %s", tptConn.LocalMultiaddr(), tptConn.RemoteMultiaddr())
		}

		// 2. start stream multipling
		var err error
		streamConn, err = pstpt.NewConn(c, isServer)
		if err != nil {
			return nil, err
		}
	case tpt.MultiplexConn:
		panic("not implemented yet")
	}

	conn := &singleConn{
		streamConn: streamConn,
		tptConn:    tptConn,
		secSession: secSession,
		event:      log.EventBegin(ctx, "connLifetime", ml),
	}

	log.Debugf("newSingleConn %p: %v to %v", conn, local, remote)
	return conn, nil
}

func setupSecureSession(ctx context.Context, local peer.ID, privKey ci.PrivKey, ch io.ReadWriteCloser) (secio.Session, error) {
	if local == "" {
		return nil, errors.New("local peer is nil")
	}
	if privKey == nil {
		return nil, errors.New("private key is nil")
	}
	sessgen := secio.SessionGenerator{
		LocalID:    local,
		PrivateKey: privKey,
	}
	secSession, err := sessgen.NewSession(ctx, ch)
	if err != nil {
		return nil, err
	}
	// force the handshake right now
	// TODO: find a better solution for this
	b := []byte("handshake")
	if _, err := secSession.ReadWriter().Write(b); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(secSession.ReadWriter(), b); err != nil {
		return nil, err
	}
	return secSession, nil
}

// close is the internal close function, called by ContextCloser.Close
func (c *singleConn) Close() error {
	defer func() {
		if c.event != nil {
			c.event.Close()
			c.event = nil
		}
	}()

	// closing the stream muxer also closes the underlying net.Conn
	return c.streamConn.Close()
}

// ID is an identifier unique to this connection.
func (c *singleConn) ID() string {
	return iconn.ID(c)
}

func (c *singleConn) String() string {
	return iconn.String(c, "singleConn")
}

func (c *singleConn) LocalAddr() net.Addr {
	return c.tptConn.LocalAddr()
}

func (c *singleConn) RemoteAddr() net.Addr {
	return c.tptConn.RemoteAddr()
}

func (c *singleConn) LocalPrivateKey() ic.PrivKey {
	if c.secSession != nil {
		return c.secSession.LocalPrivateKey()
	}
	return nil
}

func (c *singleConn) RemotePublicKey() ic.PubKey {
	if c.secSession != nil {
		return c.secSession.RemotePublicKey()
	}
	return nil
}

// LocalMultiaddr is the Multiaddr on this side
func (c *singleConn) LocalMultiaddr() ma.Multiaddr {
	return c.tptConn.LocalMultiaddr()
}

// RemoteMultiaddr is the Multiaddr on the remote side
func (c *singleConn) RemoteMultiaddr() ma.Multiaddr {
	return c.tptConn.RemoteMultiaddr()
}

func (c *singleConn) Transport() tpt.Transport {
	return c.tptConn.Transport()
}

// LocalPeer is the Peer on this side
func (c *singleConn) LocalPeer() peer.ID {
	return c.secSession.LocalPeer()
}

// RemotePeer is the Peer on the remote side
func (c *singleConn) RemotePeer() peer.ID {
	return c.secSession.RemotePeer()
}

func (c *singleConn) AcceptStream() (smux.Stream, error) {
	return c.streamConn.AcceptStream()
}

func (c *singleConn) OpenStream() (smux.Stream, error) {
	return c.streamConn.OpenStream()
}

func (c *singleConn) IsClosed() bool {
	return c.streamConn.IsClosed()
}
