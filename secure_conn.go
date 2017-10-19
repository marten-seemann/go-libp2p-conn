package conn

import (
	"net"
	"time"

	secio "github.com/libp2p/go-libp2p-secio"
	tpt "github.com/libp2p/go-libp2p-transport"
	ma "github.com/multiformats/go-multiaddr"
)

// secureConn wraps another Conn object with an encrypted channel.
type secureConn struct {
	insecure tpt.Conn      // the wrapped conn
	secure   secio.Session // secure Session
}

var _ tpt.Conn = &secureConn{}

func (c *secureConn) Read(buf []byte) (int, error) {
	return c.secure.ReadWriter().Read(buf)
}

func (c *secureConn) Write(buf []byte) (int, error) {
	return c.secure.ReadWriter().Write(buf)
}

func (c *secureConn) Close() error {
	return c.secure.Close()
}

func (c *secureConn) LocalAddr() net.Addr {
	return c.insecure.LocalAddr()
}

func (c *secureConn) LocalMultiaddr() ma.Multiaddr {
	return c.insecure.LocalMultiaddr()
}

func (c *secureConn) RemoteAddr() net.Addr {
	return c.insecure.RemoteAddr()
}

func (c *secureConn) RemoteMultiaddr() ma.Multiaddr {
	return c.insecure.RemoteMultiaddr()
}

func (c *secureConn) SetDeadline(t time.Time) error {
	return c.insecure.SetDeadline(t)
}

func (c *secureConn) SetReadDeadline(t time.Time) error {
	return c.insecure.SetDeadline(t)
}

func (c *secureConn) SetWriteDeadline(t time.Time) error {
	return c.insecure.SetDeadline(t)
}

func (c *secureConn) Transport() tpt.Transport {
	return c.insecure.Transport()
}
