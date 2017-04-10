package conn

import (
	"net"
	"time"

	secio "github.com/libp2p/go-libp2p-secio"
	tpt "github.com/libp2p/go-libp2p-transport"
	ma "github.com/multiformats/go-multiaddr"
)

// secureSingleStreamConn wraps another SingleStreamConn object with an encrypted channel.
type secureSingleStreamConn struct {
	insecure tpt.SingleStreamConn // the wrapped conn
	secure   secio.Session        // secure Session
}

var _ tpt.SingleStreamConn = &secureSingleStreamConn{}

func (c *secureSingleStreamConn) Read(buf []byte) (int, error) {
	return c.secure.ReadWriter().Read(buf)
}

func (c *secureSingleStreamConn) Write(buf []byte) (int, error) {
	return c.secure.ReadWriter().Write(buf)
}

func (c *secureSingleStreamConn) Close() error {
	return c.secure.Close()
}

func (c *secureSingleStreamConn) LocalAddr() net.Addr {
	return c.insecure.LocalAddr()
}

func (c *secureSingleStreamConn) LocalMultiaddr() ma.Multiaddr {
	return c.insecure.LocalMultiaddr()
}

func (c *secureSingleStreamConn) RemoteAddr() net.Addr {
	return c.insecure.RemoteAddr()
}

func (c *secureSingleStreamConn) RemoteMultiaddr() ma.Multiaddr {
	return c.insecure.RemoteMultiaddr()
}

func (c *secureSingleStreamConn) SetDeadline(t time.Time) error {
	return c.insecure.SetDeadline(t)
}

func (c *secureSingleStreamConn) SetReadDeadline(t time.Time) error {
	return c.insecure.SetDeadline(t)
}

func (c *secureSingleStreamConn) SetWriteDeadline(t time.Time) error {
	return c.insecure.SetDeadline(t)
}

func (c *secureSingleStreamConn) Transport() tpt.Transport {
	return c.insecure.Transport()
}
