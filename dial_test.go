package conn

import (
	"context"
	"net"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("dialing", func() {
	It("errors when it can't dial the raw connection", func() {
		p := randPeerNetParams()
		d := getDialer(p.ID, p.PrivKey, p.Addr)
		raddr, err := ma.NewMultiaddr("/ip4/1.2.3.4/tcp/0")
		Expect(err).ToNot(HaveOccurred())
		_, err = d.Dial(context.Background(), raddr, p.ID)
		Expect(err).To(HaveOccurred())
	})

	It("returns immediately when the context is canceled", func() {
		p1 := randPeerNetParams()
		tptList, err := getTransport(p1.Addr).Listen(p1.Addr)
		Expect(err).ToNot(HaveOccurred())
		defer tptList.Close()

		dialed := make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			defer GinkgoRecover()
			p2 := randPeerNetParams()
			d := getDialer(p2.ID, p2.PrivKey, p2.Addr)
			_, err = d.Dial(ctx, tptList.Multiaddr(), p2.ID)
			Expect(err).To(MatchError(context.Canceled))
			close(dialed)
		}()
		Consistently(dialed).ShouldNot(BeClosed())
		cancel()
		Eventually(dialed).Should(BeClosed())
	})

	It("times out during multistream selection", func() {
		old := DialTimeout
		DialTimeout = time.Second
		defer func() { DialTimeout = old }()

		p1 := randPeerNetParams()
		p2 := randPeerNetParams()
		tptList, err := getTransport(p1.Addr).Listen(p1.Addr)
		Expect(err).ToNot(HaveOccurred())
		defer tptList.Close()

		d := getDialer(p2.ID, p2.PrivKey, p2.Addr)
		_, err = d.Dial(context.Background(), tptList.Multiaddr(), p2.ID)
		Expect(err).To(HaveOccurred())
		Expect(err.(net.Error).Timeout()).To(BeTrue())
		Expect(err.(net.Error).Temporary()).To(BeTrue())
	})
})
