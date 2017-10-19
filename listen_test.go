package conn

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	tpt "github.com/libp2p/go-libp2p-transport"
	filter "github.com/libp2p/go-maddr-filter"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Listener", func() {
	Context("accepting connections", func() {
		It("returns immediately when the context is cancelled", func() {
			p1 := randPeerNetParams()
			ctx, cancel := context.WithCancel(context.Background())
			l := getListener(ctx, p1)

			accepted := make(chan struct{})
			go func() {
				_, _ = l.Accept()
				close(accepted)
			}()
			Consistently(accepted).ShouldNot(BeClosed())
			cancel()
			Eventually(accepted).Should(BeClosed())
		})

		It("returns immediately when it is closed", func() {
			p1 := randPeerNetParams()
			l := getListener(context.Background(), p1)

			accepted := make(chan struct{})
			go func() {
				_, _ = l.Accept()
				close(accepted)
			}()
			Consistently(accepted).ShouldNot(BeClosed())
			l.Close()
			Eventually(accepted).Should(BeClosed())
		})

		It("continues accepting connections after one accept failed", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			p1 := randPeerNetParams()
			p2 := randPeerNetParams()

			l1 := getListener(ctx, p1)
			defer l1.Close()

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				c := dialRawConn(p2.Addr, l1.Multiaddr())
				defer c.Close()
				// write some garbage. This will fail the protocol selection
				_, err := c.Write(bytes.Repeat([]byte{255}, 1000))
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()

			accepted := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				c, err := l1.Accept()
				Expect(err).ToNot(HaveOccurred())
				c.Close()
				close(accepted)
			}()

			// make sure it doesn't accept the raw connection
			Eventually(done).Should(BeClosed())
			Consistently(accepted).ShouldNot(BeClosed())

			// now dial the real connection, and make sure it is accepted
			d := getDialer(p2.ID, p2.PrivKey, p2.Addr)
			_, err := d.Dial(ctx, p1.Addr, p1.ID)
			Expect(err).ToNot(HaveOccurred())

			Eventually(accepted).Should(BeClosed())
		})

		// This test kicks off N (=10) concurrent dials, which wait d (=20ms) seconds before failing.
		// That wait holds up the handshake (multistream AND crypto), which will happen BEFORE
		// l1.Accept() returns a connection. This test checks that the handshakes all happen
		// concurrently in the listener side, and not sequentially. This ensures that a hanging dial
		// will not block the listener from accepting other dials concurrently.
		It("accepts concurrently", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			p1 := randPeerNetParams()
			p2 := randPeerNetParams()

			l1 := getListener(ctx, p1)
			defer l1.Close()

			n := 10
			delay := 50 * time.Millisecond

			accepted := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				for i := 0; i < n; i++ {
					conn, err := l1.Accept()
					Expect(err).ToNot(HaveOccurred())
					defer conn.Close()
				}
				close(accepted)
			}()

			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					d2 := getDialer(p2.ID, p2.PrivKey, p2.Addr)
					d2.Wrapper = func(c tpt.Conn) tpt.Conn {
						time.Sleep(delay)
						return c
					}
					before := time.Now()
					_, err := d2.Dial(ctx, p1.Addr, p1.ID)
					Expect(err).ToNot(HaveOccurred())
					// make sure the delay actually worked
					Expect(time.Now()).To(BeTemporally(">", before.Add(delay)))
				}()
			}

			wg.Wait()
			// the Eventually timeout is 100ms, which is a lot smaller than n*delay = 500ms
			Eventually(accepted).Should(BeClosed())
		})

		Context("address filters", func() {
			It("doesn't accept connections from filtered addresses", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				p1 := randPeerNetParams()
				p2 := randPeerNetParams()

				filt := filter.NewFilters()
				_, ipnet, err := net.ParseCIDR("127.0.1.2/16")
				Expect(err).ToNot(HaveOccurred())
				filt.AddDialFilter(ipnet)
				Expect(filt.AddrBlocked(p2.Addr)).To(BeTrue())

				l := getListener(ctx, p1)
				defer l.Close()
				l.SetAddrFilters(filt)

				accepted := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, _ = l.Accept()
					close(accepted)
				}()

				d := getDialer(p2.ID, p2.PrivKey, p2.Addr)
				_, err = d.Dial(ctx, p1.Addr, p1.ID)
				Expect(err).To(HaveOccurred())
				Eventually(accepted).ShouldNot(BeClosed())
			})

			It("accepts connections from addresses that are not filtered", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				p1 := randPeerNetParams()
				p2 := randPeerNetParams()

				filt := filter.NewFilters()
				_, ipnet, err := net.ParseCIDR("192.168.1.2/16")
				Expect(err).ToNot(HaveOccurred())
				filt.AddDialFilter(ipnet)
				Expect(filt.AddrBlocked(p2.Addr)).To(BeFalse())

				l := getListener(ctx, p1)
				defer l.Close()
				l.SetAddrFilters(filt)

				accepted := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := l.Accept()
					Expect(err).ToNot(HaveOccurred())
					close(accepted)
				}()

				d := getDialer(p2.ID, p2.PrivKey, p2.Addr)
				c2, err := d.Dial(ctx, p1.Addr, p1.ID)
				Expect(err).ToNot(HaveOccurred())
				defer c2.Close()
				Eventually(accepted).Should(BeClosed())
				time.Sleep(time.Second)
			})
		})
	})
})
