package server_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
)

// emptyAnswerGate is a resolver in front of upstream that, once empty is set,
// answers every query itself with an empty NOERROR reply - what a resolver
// that strips, filters or truncates the tunnel's TXT answers sends. Until then
// it relays, so the client's MTU scan and handshake see a working path.
//
// It listens on its own loopback address: the client keeps one resolver per
// IP, whatever the port.
func emptyAnswerGate(t *testing.T, upstream *net.UDPAddr, last byte, empty *atomic.Bool, answered *atomic.Int64) *net.UDPAddr {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, last)})
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu   sync.Mutex
		back = map[string]*net.UDPConn{}
		wg   sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if empty.Load() {
				if response, err := DnsParser.BuildEmptyNoErrorResponse(buf[:n]); err == nil {
					_, _ = front.WriteToUDP(response, from)
					answered.Add(1)
				}
				continue
			}
			mu.Lock()
			conn := back[from.String()]
			if conn == nil {
				if conn, err = net.DialUDP("udp", nil, upstream); err != nil {
					mu.Unlock()
					continue
				}
				back[from.String()] = conn
				wg.Add(1)
				go func(conn *net.UDPConn, peer *net.UDPAddr) {
					defer wg.Done()
					rb := make([]byte, 65535)
					for {
						n, err := conn.Read(rb)
						if err != nil {
							return
						}
						_, _ = front.WriteToUDP(rb[:n], peer)
					}
				}(conn, from)
			}
			mu.Unlock()
			_, _ = conn.Write(buf[:n])
		}
	}()
	t.Cleanup(func() {
		_ = front.Close()
		mu.Lock()
		for _, c := range back {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return front.LocalAddr().(*net.UDPAddr)
}

// The fastest resolver starts answering with empty replies while the other
// keeps carrying the tunnel. The client credited each empty reply as a
// success - the quickest one it had, never lost - so the balancer kept every
// query on the path that delivers nothing, and an open stream stalled for as
// long as that lasted: 0 of 21 bytes in 3 s, 37 empty replies (strategy 3,
// the app's default, and 6 alike). Empty replies now count as failures and
// the stream moves to the working path within about a second.
func TestE2E_AResolverAnsweringEmptyDoesNotStallTheTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end")
	}
	for _, strategy := range []int{3, 6, 8} {
		t.Run(fmt.Sprintf("strategy_%d", strategy), func(t *testing.T) {
			node := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: startPerfNode(t, startWeakNetworkEcho(t))}
			working := startLossyRelay(t, node, perfPath{delay: 40 * time.Millisecond, seed: 11})
			fast := startLossyRelay(t, node, perfPath{delay: 2 * time.Millisecond, seed: 12})
			var empty atomic.Bool
			var emptyAnswers atomic.Int64
			gate := emptyAnswerGate(t, fast, 2, &empty, &emptyAnswers)
			// The app's "balanced" profile, one copy of each packet so a
			// query on the empty path is not rescued by a copy on the other.
			profile := strings.NewReplacer(
				`SESSION_V2 = "auto"`, `SESSION_V2 = "on"`,
				"RESOLVER_BALANCING_STRATEGY = 3", fmt.Sprintf("RESOLVER_BALANCING_STRATEGY = %d", strategy),
				"PACKET_DUPLICATION_COUNT = 3", "PACKET_DUPLICATION_COUNT = 1",
				"SETUP_PACKET_DUPLICATION_COUNT = 5", "SETUP_PACKET_DUPLICATION_COUNT = 2",
			).Replace(perfClientConfig)
			port := startPerfClientProfile(t, []*net.UDPAddr{working, gate}, profile, "SESSION_INIT_RACING_COUNT = 2\n")

			conn, reader, err := socksDial(port, "", 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// Both paths carry the stream first, so the fast one is the
			// balancer's favourite when it turns empty.
			for i := 0; i < 8; i++ {
				msg := []byte(fmt.Sprintf("warm-up-%d\n", i))
				if _, err := conn.Write(msg); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(msg, got) {
					t.Fatalf("warm-up: %v", err)
				}
			}

			empty.Store(true)
			msg := []byte("data-after-empty-DNS\n")
			started := time.Now()
			// Generous: the fixed client delivers in about a second; the old
			// one never did while the path stayed empty.
			_ = conn.SetDeadline(started.Add(6 * time.Second))
			if _, err := conn.Write(msg); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(msg))
			n, err := io.ReadFull(reader, got)
			if emptyAnswers.Load() == 0 {
				t.Fatal("invalid experiment: no query reached the empty path")
			}
			if err != nil || !bytes.Equal(msg, got) {
				t.Fatalf("the stream stalled on the empty path: %d of %d bytes in %v (%d empty replies): %v",
					n, len(msg), time.Since(started).Round(time.Millisecond), emptyAnswers.Load(), err)
			}
			t.Logf("delivered in %v past %d empty replies", time.Since(started).Round(time.Millisecond), emptyAnswers.Load())
		})
	}
}
