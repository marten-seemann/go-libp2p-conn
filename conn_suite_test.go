package conn

import (
	"context"
	"strings"
	"testing"
	"time"

	ci "github.com/libp2p/go-libp2p-crypto"
	iconn "github.com/libp2p/go-libp2p-interface-conn"
	peer "github.com/libp2p/go-libp2p-peer"
	tpt "github.com/libp2p/go-libp2p-transport"
	tcpt "github.com/libp2p/go-tcp-transport"
	tu "github.com/libp2p/go-testutil"
	quict "github.com/marten-seemann/libp2p-quic-transport"
	ma "github.com/multiformats/go-multiaddr"
	yamux "github.com/whyrusleeping/go-smux-yamux"
	grc "github.com/whyrusleeping/gorocheck"
	"github.com/whyrusleeping/mafmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestGoLibp2pConn(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "go-libp2p-conn Suite")
}

var _ = AfterEach(func() {
	time.Sleep(300 * time.Millisecond)
	Expect(grc.CheckForLeaks(func(r *grc.Goroutine) bool {
		return strings.Contains(r.Function, "go-log.") ||
			strings.Contains(r.Stack[0], "testing.(*T).Run") ||
			strings.Contains(r.Function, "specrunner.") ||
			strings.Contains(r.Function, "runtime.gopark")
	})).To(Succeed())
})

// the stream muxer used for tests using the single stream connection
var streamMuxer = yamux.DefaultTransport

type transportType uint8

const (
	singleStreamTransport transportType = 1 + iota
	multiStreamTransport
)

var transportTypes = []transportType{singleStreamTransport}

func (t transportType) String() string {
	if t == multiStreamTransport {
		return "multi-stream transport"
	}
	return "single-stream transport"
}

// dialRawConn dials a tpt.Conn
// but it stops there. It doesn't do protocol selection and handshake
func dialRawConn(laddr, raddr ma.Multiaddr) tpt.Conn {
	var d tpt.Dialer
	if mafmt.QUIC.Matches(laddr) {
		var err error
		d, err = quict.NewQuicTransport().Dialer(laddr)
		Expect(err).ToNot(HaveOccurred())
	} else {
		var err error
		d, err = tcpt.NewTCPTransport().Dialer(laddr)
		Expect(err).ToNot(HaveOccurred())
	}
	c, err := d.Dial(raddr)
	Expect(err).ToNot(HaveOccurred())
	return c
}

// getTransport gets the right transport for a multiaddr
func getTransport(a ma.Multiaddr) tpt.Transport {
	if mafmt.QUIC.Matches(a) {
		return quict.NewQuicTransport()
	}
	return tcpt.NewTCPTransport()
}

// getListener creates a listener based on the PeerNetParams
// it updates the PeerNetParams to reflect the local address that was selected by the kernel
func getListener(ctx context.Context, p *tu.PeerNetParams) iconn.Listener {
	tptListener, err := getTransport(p.Addr).Listen(p.Addr)
	Expect(err).ToNot(HaveOccurred())
	list, err := WrapTransportListener(ctx, tptListener, p.ID, streamMuxer, p.PrivKey)
	Expect(err).ToNot(HaveOccurred())
	p.Addr = list.Multiaddr()
	return list
}

func getDialer(localPeer peer.ID, privKey ci.PrivKey, addr ma.Multiaddr) *Dialer {
	d := NewDialer(localPeer, privKey, nil, streamMuxer)
	d.fallback = nil // unset the fallback dialer. We want tests use the configured dialer, and to fail otherwise
	tptd, err := getTransport(addr).Dialer(addr)
	Expect(err).ToNot(HaveOccurred())
	d.AddDialer(tptd)
	return d
}

// randPeerNetParams works like testutil.RandPeerNetParams
// if called for a multi-stream transport, it replaces the address with a QUIC address
func randPeerNetParams(tr transportType) *tu.PeerNetParams {
	p, err := tu.RandPeerNetParams()
	Expect(err).ToNot(HaveOccurred())
	if tr == multiStreamTransport {
		p.Addr, err = ma.NewMultiaddr("/ip4/127.0.0.1/udp/0/quic")
		Expect(err).ToNot(HaveOccurred())
	}
	return p
}
