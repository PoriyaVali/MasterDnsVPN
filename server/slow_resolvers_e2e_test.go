package server_test

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// delayGate is a resolver in front of node on its own loopback address that
// delivers every query and answer after delay.
func delayGate(t *testing.T, node *net.UDPAddr, last byte, delay time.Duration) *net.UDPAddr {
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

// Every resolver answers in 3.4 s - resolvers under load, as on a national
// network that is throttling - and the MTU test gives each probe 1 s. No
// resolver passed the scan, the client rescanned with the same timeout
// forever and never connected. The resolvers that failed now get patient
// probes (4 s), and session init waits for them too (it gave each attempt
// three MTU timeouts, 3 s).
func TestE2E_ConnectsWhenEveryResolverAnswersInSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end")
	}
	node := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: startPerfNode(t, startWeakNetworkEcho(t))}
	var addrs []*net.UDPAddr
	for i := 0; i < 3; i++ {
		addrs = append(addrs, delayGate(t, node, byte(30+i), 1700*time.Millisecond))
	}
	profile := strings.Replace(perfClientConfig, "MTU_TEST_TIMEOUT = 1.5", "MTU_TEST_TIMEOUT = 1.0", 1)
	port := startPerfClientProfile(t, addrs, profile, "")

	conn, reader, err := socksDial(port, "", 90*time.Second)
	if err != nil {
		t.Fatalf("no tunnel with every resolver answering in 3.4 s: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	const msg = "through-slow-resolvers\n"
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(reader, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo through slow resolvers: %q %v", buf, err)
	}
}
