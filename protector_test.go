package conn

import (
	"context"
	"errors"

	ipnet "github.com/libp2p/go-libp2p-interface-pnet"
	tpt "github.com/libp2p/go-libp2p-transport"
	tcpt "github.com/libp2p/go-tcp-transport"
	tu "github.com/libp2p/go-testutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type fakeProtector struct {
	used bool
}

func (f *fakeProtector) Fingerprint() []byte {
	return make([]byte, 32)
}

func (f *fakeProtector) Protect(c tpt.Conn) (tpt.Conn, error) {
	f.used = true
	return &rot13Crypt{c}, nil
}

type rot13Crypt struct {
	tpt.Conn
}

func (r *rot13Crypt) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	for i := 0; i < n; i++ {
		b[i] = b[i] - 13
	}
	return n, err
}

func (r *rot13Crypt) Write(b []byte) (int, error) {
	p := make([]byte, len(b)) // write MUST NOT modify b
	for i := range b {
		p[i] = b[i] + 13
	}
	return r.Conn.Write(p)
}

var errProtect = errors.New("protecting failed")

type erroringProtector struct{}

func (f *erroringProtector) Fingerprint() []byte {
	return make([]byte, 32)
}

func (f *erroringProtector) Protect(c tpt.Conn) (tpt.Conn, error) {
	return nil, errProtect
}

var _ = Describe("using the protector", func() {
	It("uses a protector for single-stream connections", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		p1 := randPeerNetParams()
		p2 := randPeerNetParams()
		p1Protec := &fakeProtector{}
		p2Protec := &fakeProtector{}

		list, err := tcpt.NewTCPTransport().Listen(p1.Addr)
		Expect(err).ToNot(HaveOccurred())
		l1, err := WrapTransportListenerWithProtector(ctx, list, p1.ID, p1.PrivKey, streamMuxer, p1Protec)
		Expect(err).ToNot(HaveOccurred())
		p1.Addr = l1.Multiaddr() // Addr has been determined by kernel.

		d2 := getDialer(p2.ID, p2.PrivKey, p2.Addr)
		d2.Protector = p2Protec

		accepted := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := l1.Accept()
			Expect(err).ToNot(HaveOccurred())
			close(accepted)
		}()

		c2, err := d2.Dial(ctx, p1.Addr, p1.ID)
		Expect(err).ToNot(HaveOccurred())
		defer c2.Close()

		Expect(p2Protec.used).To(BeTrue())
		Eventually(accepted).Should(BeClosed())
		Expect(p1Protec.used).To(BeTrue())
	})

	Context("forcing a private network", func() {
		var p1, p2 *tu.PeerNetParams
		var list tpt.Listener

		BeforeEach(func() {
			ipnet.ForcePrivateNetwork = true
			p1 = randPeerNetParams()
			p2 = randPeerNetParams()
			var err error
			list, err = tcpt.NewTCPTransport().Listen(p1.Addr)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			ipnet.ForcePrivateNetwork = false
		})

		It("errors if no protector is specified for the listener", func() {
			_, err := WrapTransportListenerWithProtector(context.Background(), list, p1.ID, p1.PrivKey, streamMuxer, nil)
			Expect(err).To(Equal(ipnet.ErrNotInPrivateNetwork))
		})

		It("errors if no protector is specified for the dialer", func() {
			d := getDialer(p2.ID, p2.PrivKey, p2.Addr)
			_, err := d.Dial(context.Background(), list.Multiaddr(), p1.ID)
			Expect(err).To(Equal(ipnet.ErrNotInPrivateNetwork))
		})
	})

	It("correctly handles a protected that errors", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		p1 := randPeerNetParams()
		p2 := randPeerNetParams()
		p1Protec := &erroringProtector{}
		p2Protec := &erroringProtector{}

		list, err := tcpt.NewTCPTransport().Listen(p1.Addr)
		Expect(err).ToNot(HaveOccurred())
		l1, err := WrapTransportListenerWithProtector(ctx, list, p1.ID, p1.PrivKey, streamMuxer, p1Protec)
		Expect(err).ToNot(HaveOccurred())
		p1.Addr = l1.Multiaddr() // Addr has been determined by kernel.

		d2 := getDialer(p2.ID, p2.PrivKey, p2.Addr)
		d2.Protector = p2Protec

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, _ = l1.Accept()
			close(done)
		}()

		_, err = d2.Dial(ctx, p1.Addr, p1.ID)
		Expect(err).To(MatchError(errProtect))
		// make sure no connection was accepted
		Consistently(done).ShouldNot(BeClosed())
	})
})
