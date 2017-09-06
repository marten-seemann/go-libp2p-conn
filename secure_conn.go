package conn

import (
	"net"
	"time"

	secio "github.com/libp2p/go-libp2p-secio"
	tpt "github.com/libp2p/go-libp2p-transport"
	ma "github.com/multiformats/go-multiaddr"
)

// secureDuplexConn wraps another DuplexConn object with an encrypted channel.
type secureDuplexConn struct {
	insecure tpt.DuplexConn // the wrapped conn
	secure   secio.Session  // secure Session
}

var _ tpt.DuplexConn = &secureDuplexConn{}

func (c *secureDuplexConn) Read(buf []byte) (int, error) {
	return c.secure.ReadWriter().Read(buf)
}

func (c *secureDuplexConn) Write(buf []byte) (int, error) {
	return c.secure.ReadWriter().Write(buf)
}

func (c *secureDuplexConn) Close() error {
	return c.secure.Close()
}

func (c *secureDuplexConn) LocalAddr() net.Addr {
	return c.insecure.LocalAddr()
}

func (c *secureDuplexConn) LocalMultiaddr() ma.Multiaddr {
	return c.insecure.LocalMultiaddr()
}

func (c *secureDuplexConn) RemoteAddr() net.Addr {
	return c.insecure.RemoteAddr()
}

func (c *secureDuplexConn) RemoteMultiaddr() ma.Multiaddr {
	return c.insecure.RemoteMultiaddr()
}

func (c *secureDuplexConn) SetDeadline(t time.Time) error {
	return c.insecure.SetDeadline(t)
}

func (c *secureDuplexConn) SetReadDeadline(t time.Time) error {
	return c.insecure.SetDeadline(t)
}

func (c *secureDuplexConn) SetWriteDeadline(t time.Time) error {
	return c.insecure.SetDeadline(t)
}

func (c *secureDuplexConn) Transport() tpt.Transport {
	return c.insecure.Transport()
}
