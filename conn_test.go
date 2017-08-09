package conn

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	iconn "github.com/libp2p/go-libp2p-interface-conn"
	tpt "github.com/libp2p/go-libp2p-transport"
	smux "github.com/libp2p/go-stream-muxer"
)

var _ = Describe("Connections", func() {
	It("uses the right handshake protocol", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		p1 := randPeerNetParams(singleStreamTransport)
		l1 := getListener(ctx, p1)
		defer l1.Close()
		go l1.Accept()
	})

	for _, val := range transportTypes {
		tr := val

		Context(fmt.Sprintf("using a %s", tr), func() {
			for _, val := range []bool{true, false} {
				secure := val

				It(fmt.Sprintf("establishes a connection (secure: %t)", secure), func() {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					p1 := randPeerNetParams(tr)
					p2 := randPeerNetParams(tr)
					if !secure {
						p1.PrivKey = nil
						p2.PrivKey = nil
					}

					l1 := getListener(ctx, p1)
					defer l1.Close()

					// accept a connection, accept a stream on this connection and echo everything
					go func() {
						defer GinkgoRecover()
						c, err := l1.Accept()
						Expect(err).ToNot(HaveOccurred())
						str, err := c.AcceptStream()
						Expect(err).ToNot(HaveOccurred())
						go io.Copy(str, str)
					}()

					d2 := getDialer(p2.ID, p2.PrivKey, p2.Addr)
					c, err := d2.Dial(ctx, p1.Addr, p1.ID)
					Expect(err).ToNot(HaveOccurred())
					defer c.Close()
					str, err := c.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					_, err = str.Write([]byte("beep"))
					Expect(err).ToNot(HaveOccurred())
					_, err = str.Write([]byte("boop"))
					Expect(err).ToNot(HaveOccurred())

					out := make([]byte, 8)
					_, err = io.ReadFull(str, out)
					Expect(err).ToNot(HaveOccurred())
					Expect(out).To(Equal([]byte("beepboop")))
				})
			}

			It("continues accepting connections while another accept is hanging", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				p1 := randPeerNetParams(tr)
				p2 := randPeerNetParams(tr)

				l1 := getListener(ctx, p1)
				defer l1.Close()

				go func() {
					defer GinkgoRecover()
					conn := dialRawConn(p2.Addr, l1.Multiaddr())
					defer conn.Close() // hang this connection

					// ensure that the first conn hits first
					time.Sleep(50 * time.Millisecond)
					d2 := getDialer(p2.ID, p2.PrivKey, p2.Addr)
					conn2, err := d2.Dial(ctx, p1.Addr, p1.ID)
					Expect(err).ToNot(HaveOccurred())
					defer conn2.Close()
				}()

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := l1.Accept()
					Expect(err).ToNot(HaveOccurred())
					close(done)
				}()
				Eventually(done).Should(BeClosed())
			})

			It("timeouts", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				old := NegotiateReadTimeout
				NegotiateReadTimeout = 3 * time.Second
				defer func() { NegotiateReadTimeout = old }()

				p1 := randPeerNetParams(tr)
				p2 := randPeerNetParams(tr)

				l1 := getListener(ctx, p1)
				defer l1.Close()

				n := 20

				before := time.Now()
				var wg sync.WaitGroup
				for i := 0; i < n; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						var conn io.Reader
						c := dialRawConn(p2.Addr, l1.Multiaddr())
						defer c.Close()
						switch tr {
						case singleStreamTransport:
							conn = c.(tpt.SingleStreamConn)
						case multiStreamTransport:
							var err error
							conn, err = c.(tpt.MultiStreamConn).OpenStream()
							Expect(err).ToNot(HaveOccurred())
						}
						// hang this connection until timeout
						io.ReadFull(conn, make([]byte, 1000))
					}()
				}

				// wait to make sure the hanging dials have started
				time.Sleep(50 * time.Millisecond)

				accepted := make(chan struct{}) // this chan is closed once all good connections have been accepted
				goodN := 10
				for i := 0; i < goodN; i++ {
					go func(i int) {
						defer GinkgoRecover()
						d2 := getDialer(p2.ID, p2.PrivKey, p2.Addr)
						conn, err := d2.Dial(ctx, p1.Addr, p1.ID)
						Expect(err).ToNot(HaveOccurred())
						<-accepted
						conn.Close()
					}(i)
				}

				for i := 0; i < goodN; i++ {
					_, err := l1.Accept()
					Expect(err).ToNot(HaveOccurred())
				}
				close(accepted)
				Expect(time.Now()).To(BeTemporally("<", before.Add(NegotiateReadTimeout/4)))
				Eventually(func() bool {
					wg.Wait() // wait for the timeouts for the raw connections to occur
					return true
				}, NegotiateReadTimeout).Should(BeTrue())
				Expect(time.Now()).To(BeTemporally(">", before.Add(NegotiateReadTimeout)))

				// make sure we can dial in still after a bunch of timeouts
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := l1.Accept()
					Expect(err).ToNot(HaveOccurred())
					close(done)
				}()

				d2 := getDialer(p2.ID, p2.PrivKey, p2.Addr)
				conn, err := d2.Dial(ctx, p1.Addr, p1.ID)
				Expect(err).ToNot(HaveOccurred())
				defer conn.Close()
				Eventually(done).Should(BeClosed())
			})

			It("doesn't complete the handshake with the wrong keys", func() {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				p1 := randPeerNetParams(tr)
				p2 := randPeerNetParams(tr)

				l1 := getListener(ctx, p1)
				defer l1.Close()

				// use the wrong private key here, correct would be: p2.PrivKey
				d2 := getDialer(p2.ID, p1.PrivKey, p2.Addr)

				accepted := make(chan struct{})
				go func() {
					l1.Accept()
					close(accepted)
				}()

				_, err := d2.Dial(ctx, p1.Addr, p1.ID)
				Expect(err).To(MatchError("peer.ID does not match PrivateKey"))
				// make sure no connection was accepted
				Consistently(accepted).ShouldNot(BeClosed())
			})

			Context("closing", func() {
				setupConn := func(ctx context.Context, tr transportType) (iconn.Conn, iconn.Conn) {
					p1 := randPeerNetParams(tr)
					p2 := randPeerNetParams(tr)

					l1 := getListener(ctx, p1)

					var c2 iconn.Conn
					d2 := getDialer(p2.ID, p2.PrivKey, p2.Addr)
					done := make(chan error)
					go func() {
						defer GinkgoRecover()
						var err error
						c2, err = d2.Dial(ctx, p1.Addr, p1.ID)
						Expect(err).ToNot(HaveOccurred())
						close(done)
					}()

					c1, err := l1.Accept()
					Expect(err).ToNot(HaveOccurred())
					Eventually(done).Should(BeClosed())
					return c1, c2
				}

				openStreamAndSend := func(c1, c2 iconn.Conn) {
					str1, err := c1.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					m1 := []byte("hello")
					_, err = str1.Write(m1)
					Expect(err).ToNot(HaveOccurred())
					str2, err := c2.AcceptStream()
					Expect(err).ToNot(HaveOccurred())
					m2 := make([]byte, len(m1))
					_, err = str2.Read(m2)
					Expect(err).ToNot(HaveOccurred())
					Expect(m1).To(Equal(m2))
				}

				checkStreamOpenAcceptFails := func(c1, c2 iconn.Conn) {
					_, err := c1.OpenStream()
					Expect(err).To(HaveOccurred())
					accepted := make(chan struct{})
					go func() {
						_, err := c2.AcceptStream()
						Expect(err).To(HaveOccurred())
						close(accepted)
					}()
					Eventually(accepted).Should(BeClosed())
				}

				It("closes", func() {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					c1, c2 := setupConn(ctx, tr)
					openStreamAndSend(c1, c2)
					openStreamAndSend(c2, c1)

					c1.Close()
					Expect(c1.IsClosed()).To(BeTrue())
					Eventually(c2.IsClosed).Should(BeTrue())
					checkStreamOpenAcceptFails(c2, c1)
					checkStreamOpenAcceptFails(c1, c2)
				})

				It("doesn't leak", func() {
					// runPair opens one stream and sends num messages
					runPair := func(c1, c2 iconn.Conn, num int) {
						var str2 smux.Stream
						str1, err := c1.OpenStream()
						Expect(err).ToNot(HaveOccurred())

						for i := 0; i < num; i++ {
							b1 := []byte("beep")
							_, err := str1.Write(b1)
							Expect(err).ToNot(HaveOccurred())
							if str2 == nil {
								str2, err = c2.AcceptStream()
								Expect(err).ToNot(HaveOccurred())
							}
							b2 := make([]byte, len(b1))
							_, err = str2.Read(b2)
							Expect(err).ToNot(HaveOccurred())
							Expect(b1).To(Equal(b2))
						}
					}

					var cons = 10
					var msgs = 10
					var wg sync.WaitGroup
					for i := 0; i < cons; i++ {
						wg.Add(1)
						ctx, cancel := context.WithCancel(context.Background())
						c1, c2 := setupConn(ctx, tr)
						go func(c1, c2 iconn.Conn) {
							defer GinkgoRecover()
							defer cancel()
							runPair(c1, c2, msgs)
							c1.Close()
							c2.Close()
							wg.Done()
						}(c1, c2)
					}

					wg.Wait()
				})
			})
		})
	}
})
