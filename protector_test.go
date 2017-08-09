package conn

import (
	"context"
	"errors"

	iconn "github.com/libp2p/go-libp2p-interface-conn"
	ipnet "github.com/libp2p/go-libp2p-interface-pnet"
	tpt "github.com/libp2p/go-libp2p-transport"
	smux "github.com/libp2p/go-stream-muxer"
	tcpt "github.com/libp2p/go-tcp-transport"
	tu "github.com/libp2p/go-testutil"
	quict "github.com/marten-seemann/libp2p-quic-transport"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type fakeSingleStreamProtector struct {
	used bool
}

func (f *fakeSingleStreamProtector) Fingerprint() []byte {
	return make([]byte, 32)
}

func (f *fakeSingleStreamProtector) Protect(c tpt.Conn) (tpt.Conn, error) {
	f.used = true
	return &rot13CryptSingleStream{c.(tpt.SingleStreamConn)}, nil
}

type rot13CryptSingleStream struct {
	tpt.SingleStreamConn
}

func (r *rot13CryptSingleStream) Read(b []byte) (int, error) {
	n, err := r.SingleStreamConn.Read(b)
	for i := 0; i < n; i++ {
		b[i] = b[i] - 13
	}
	return n, err
}

func (r *rot13CryptSingleStream) Write(b []byte) (int, error) {
	p := make([]byte, len(b)) // write MUST NOT modify b
	for i := range b {
		p[i] = b[i] + 13
	}
	return r.SingleStreamConn.Write(p)
}

type fakeMultiStreamProtector struct {
	used  bool
	crypt *rot13CryptMultiStream
}

func (f *fakeMultiStreamProtector) Fingerprint() []byte {
	return make([]byte, 32)
}

func (f *fakeMultiStreamProtector) Protect(c tpt.Conn) (tpt.Conn, error) {
	f.used = true
	f.crypt = &rot13CryptMultiStream{c.(tpt.MultiStreamConn), 0, 0}
	return f.crypt, nil
}

type rot13CryptMultiStream struct {
	tpt.MultiStreamConn
	openedStreams   int
	acceptedStreams int
}

func (r *rot13CryptMultiStream) OpenStream() (smux.Stream, error) {
	r.openedStreams++
	str, err := r.MultiStreamConn.OpenStream()
	return &rot13Stream{str}, err
}

func (r *rot13CryptMultiStream) AcceptStream() (smux.Stream, error) {
	r.acceptedStreams++
	str, err := r.MultiStreamConn.AcceptStream()
	return &rot13Stream{str}, err
}

type rot13Stream struct {
	smux.Stream
}

var errProtect = errors.New("protecting failed")

type erroringProtector struct{}

func (f *erroringProtector) Fingerprint() []byte {
	return make([]byte, 32)
}

func (f *erroringProtector) Protect(c tpt.Conn) (tpt.Conn, error) {
	return nil, errProtect
}

func (r *rot13Stream) Read(b []byte) (int, error) {
	n, err := r.Stream.Read(b)
	for i := 0; i < n; i++ {
		b[i] = b[i] - 13
	}
	return n, err
}

func (r *rot13Stream) Write(b []byte) (int, error) {
	p := make([]byte, len(b)) // write MUST NOT modify b
	for i := range b {
		p[i] = b[i] + 13
	}
	return r.Stream.Write(p)
}

var _ = Describe("using the protector", func() {
	It("uses a protector for single-stream connections", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		p1 := randPeerNetParams(singleStreamTransport)
		p2 := randPeerNetParams(singleStreamTransport)
		p1Protec := &fakeSingleStreamProtector{}
		p2Protec := &fakeSingleStreamProtector{}

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

	// TODO: enable this test when adding support for multi-stream connections
	PIt("uses a protector for multi-stream connections", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		p1 := randPeerNetParams(multiStreamTransport)
		p2 := randPeerNetParams(multiStreamTransport)
		p1Protec := &fakeMultiStreamProtector{}
		p2Protec := &fakeMultiStreamProtector{}

		list, err := quict.NewQuicTransport().Listen(p1.Addr)
		Expect(err).ToNot(HaveOccurred())
		l1, err := WrapTransportListenerWithProtector(ctx, list, p1.ID, p1.PrivKey, streamMuxer, p1Protec)
		Expect(err).ToNot(HaveOccurred())
		p1.Addr = l1.Multiaddr() // Addr has been determined by kernel.

		d2 := getDialer(p2.ID, p2.PrivKey, p2.Addr)
		d2.Protector = p2Protec

		var c1 iconn.Conn
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			var err error
			c1, err = l1.Accept()
			Expect(err).ToNot(HaveOccurred())
			close(done)
		}()

		c2, err := d2.Dial(ctx, p1.Addr, p1.ID)
		Expect(err).ToNot(HaveOccurred())
		defer c2.Close()

		Expect(p2Protec.used).To(BeTrue())
		<-done
		Expect(p1Protec.used).To(BeTrue())

		Expect(p1Protec.crypt.acceptedStreams).To(Equal(2))
		Expect(p1Protec.crypt.openedStreams).To(BeZero())
		Expect(p2Protec.crypt.openedStreams).To(Equal(2))
		Expect(p2Protec.crypt.acceptedStreams).To(BeZero())

		str1, err := c1.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = str1.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		_, err = c2.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(p1Protec.crypt.acceptedStreams).To(Equal(2))
		Expect(p1Protec.crypt.openedStreams).To(Equal(1))
		Expect(p2Protec.crypt.openedStreams).To(Equal(2))
		Expect(p2Protec.crypt.acceptedStreams).To(Equal(1))
	})

	Context("forcing a private network", func() {
		var p1, p2 *tu.PeerNetParams
		var list tpt.Listener

		BeforeEach(func() {
			ipnet.ForcePrivateNetwork = true
			p1 = randPeerNetParams(singleStreamTransport)
			p2 = randPeerNetParams(singleStreamTransport)
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

		p1 := randPeerNetParams(singleStreamTransport)
		p2 := randPeerNetParams(singleStreamTransport)
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
