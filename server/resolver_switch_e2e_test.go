package server_test

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// silentGate is a resolver in front of node on its own loopback address (the
// client keeps one resolver per IP) that answers nothing once silent is set,
// and counts the queries it is given.
func silentGate(t *testing.T, node *net.UDPAddr, last byte, silent *atomic.Bool, queries *atomic.Int64) *net.UDPAddr {
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
	const delay = 30 * time.Millisecond
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			queries.Add(1)
			if silent.Load() {
				continue
			}
			mu.Lock()
			conn := back[from.String()]
			if conn == nil {
				if conn, err = net.DialUDP("udp", nil, node); err != nil {
					mu.Unlock()
					continue
				}
				back[from.String()] = conn
				wg.Add(1)
				go func(conn *net.UDPConn, peer *net.UDPAddr) {
					defer wg.Done()
					rb := make([]byte, 65535)
					for {
						m, err := conn.Read(rb)
						if err != nil {
							return
						}
						if silent.Load() {
							continue
						}
						cp := append([]byte(nil), rb[:m]...)
						time.AfterFunc(delay, func() { _, _ = front.WriteToUDP(cp, peer) })
					}
				}(conn, from)
			}
			mu.Unlock()
			cp := append([]byte(nil), buf[:n]...)
			time.AfterFunc(delay, func() { _, _ = conn.Write(cp) })
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

// The busiest of four resolvers goes silent mid-stream. With one copy of each
// packet and loss-then-latency balancing, an unanswered query used to count as
// lost only after the request timeout - 5 s with four resolvers - so the
// balancer kept every packet on the dead path, the tunnel's retransmissions
// backed off behind it, and one message took 11-13 s. Each resolver's loss
// timeout now follows its own round trip: the stream moves within about a
// second.
func TestE2E_AStreamMovesOffAResolverThatGoesSilent(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end")
	}
	node := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: startPerfNode(t, startWeakNetworkEcho(t))}
	const resolvers = 4
	silent := make([]atomic.Bool, resolvers)
	queries := make([]atomic.Int64, resolvers)
	addrs := make([]*net.UDPAddr, resolvers)
	for i := range addrs {
		addrs[i] = silentGate(t, node, byte(2+i), &silent[i], &queries[i])
	}
	profile := strings.NewReplacer(
		`SESSION_V2 = "auto"`, `SESSION_V2 = "on"`,
		"RESOLVER_BALANCING_STRATEGY = 3", "RESOLVER_BALANCING_STRATEGY = 6",
		"PACKET_DUPLICATION_COUNT = 3", "PACKET_DUPLICATION_COUNT = 1",
		"SETUP_PACKET_DUPLICATION_COUNT = 5", "SETUP_PACKET_DUPLICATION_COUNT = 2",
	).Replace(perfClientConfig)
	port := startPerfClientProfile(t, addrs, profile, "")

	conn, reader, err := socksDial(port, "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	seq := 0
	buf := make([]byte, 64)
	echo := func() time.Duration {
		seq++
		msg := fmt.Sprintf("msg-%06d\n", seq)
		started := time.Now()
		_ = conn.SetDeadline(started.Add(30 * time.Second))
		if _, err := io.WriteString(conn, msg); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(reader, buf[:len(msg)]); err != nil || string(buf[:len(msg)]) != msg {
			t.Fatalf("echo %d: %v", seq, err)
		}
		took := time.Since(started)
		if rest := 100*time.Millisecond - took; rest > 0 {
			time.Sleep(rest)
		}
		return took
	}
	for warm := time.Now().Add(2 * time.Second); time.Now().Before(warm); {
		echo()
	}
	var before [resolvers]int64
	for i := range queries {
		before[i] = queries[i].Load()
	}
	for warm := time.Now().Add(2 * time.Second); time.Now().Before(warm); {
		echo()
	}
	busiest, most := 0, int64(-1)
	for i := range queries {
		if got := queries[i].Load() - before[i]; got > most {
			busiest, most = i, got
		}
	}

	silent[busiest].Store(true)
	var worst time.Duration
	for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
		if took := echo(); took > worst {
			worst = took
		}
	}
	// Generous: 1-3 s now, 11.5-13.5 s before (measured).
	if worst > 6*time.Second {
		t.Fatalf("a message took %v after the busiest resolver went silent", worst.Round(time.Millisecond))
	}
	t.Logf("worst round trip after the busiest resolver went silent: %v", worst.Round(time.Millisecond))
}
