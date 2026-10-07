package server_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	mdns "masterdnsvpn-go/server"
)

// A latency/throughput harness, not a pass/fail test: the real client and the
// real server, with resolvers simulated by relays that add a one-way delay,
// jitter and loss. It measures what users of chat apps, Instagram and ordinary
// sites feel:
//
//   connect   SOCKS CONNECT to the first byte of an answer (every new
//             connection a page or app opens pays this)
//   chat      round trip of a small message on an open connection
//   push      delay of a message the far side sends after the connection has
//             been quiet for a while (an incoming Telegram/WhatsApp message)
//   download  one bulk transfer
//   parallel  several transfers at once (a feed loading its images)
//
// Run with: MDNS_PERF=1 go test ./server -run TestPerf -v -timeout 20m
// MDNS_PERF_DELAY (ms one way, default 60), MDNS_PERF_LOSS (0..1, default
// 0.02) and MDNS_PERF_IDLE (s, default 40) change the path.

type perfPath struct {
	delay  time.Duration
	jitter time.Duration
	loss   float64
}

// startLossyRelay is a resolver on a bad path: each datagram, either way, is
// dropped with probability loss or delivered after delay plus up to jitter.
func startLossyRelay(t *testing.T, node *net.UDPAddr, path perfPath) *net.UDPAddr {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = front.Close() })

	var rngMu sync.Mutex
	rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 7))
	later := func(b []byte, send func([]byte)) {
		rngMu.Lock()
		drop := rng.Float64() < path.loss
		var j time.Duration
		if path.jitter > 0 {
			j = time.Duration(rng.Int64N(int64(path.jitter)))
		}
		rngMu.Unlock()
		if drop {
			return
		}
		cp := append([]byte(nil), b...)
		time.AfterFunc(path.delay+j, func() { send(cp) })
	}

	var mu sync.Mutex
	back := map[string]*net.UDPConn{}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			conn := back[from.String()]
			if conn == nil {
				conn, err = net.DialUDP("udp", nil, node)
				if err != nil {
					mu.Unlock()
					continue
				}
				back[from.String()] = conn
				go func(conn *net.UDPConn, client *net.UDPAddr) {
					rb := make([]byte, 65535)
					for {
						m, err := conn.Read(rb)
						if err != nil {
							return
						}
						later(rb[:m], func(b []byte) { _, _ = front.WriteToUDP(b, client) })
					}
				}(conn, from)
			}
			mu.Unlock()
			later(buf[:n], func(b []byte) { _, _ = conn.Write(b) })
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range back {
			_ = c.Close()
		}
	})
	return front.LocalAddr().(*net.UDPAddr)
}

// startPerfApp is the far side of every connection. The first line picks the
// behaviour:
//
//	ECHO          echo every line back
//	PUSH <ms>     after ms, send one line carrying the send time (UnixNano)
//	GET <n>       send n bytes, then close
func startPerfApp(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				fields := strings.Fields(line)
				if len(fields) == 0 {
					return
				}
				switch fields[0] {
				case "ECHO":
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if _, err := io.WriteString(c, l); err != nil {
							return
						}
					}
				case "PUSH":
					ms, _ := strconv.Atoi(fields[1])
					time.Sleep(time.Duration(ms) * time.Millisecond)
					_, _ = fmt.Fprintf(c, "%d\n", time.Now().UnixNano())
					_, _ = io.Copy(io.Discard, br)
				case "GET":
					n, _ := strconv.Atoi(fields[1])
					chunk := make([]byte, 16*1024)
					for n > 0 {
						k := min(n, len(chunk))
						if _, err := c.Write(chunk[:k]); err != nil {
							return
						}
						n -= k
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startPerfNode(t *testing.T, app string) int {
	t.Helper()
	egress := startEgressProxy(t, app)
	port := freeUDPPort(t)
	srv, err := mdns.New(mdns.Options{
		Domains:           []string{e2eDomain},
		UDPHost:           "127.0.0.1",
		UDPPort:           port,
		EncryptionMethod:  2,
		EncryptionKey:     e2eKey,
		NodeSecret:        e2eSecret,
		LogLevel:          "error",
		UseExternalSOCKS5: true,
		ForwardIP:         "127.0.0.1",
		ForwardPort:       egress,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.AddUser(e2eUUID)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return port
}

// perfClientConfig mirrors what the Android app writes for its "balanced"
// network profile (mdns_profile.dart).
const perfClientConfig = `PROTOCOL_TYPE = "SOCKS5"
DOMAINS = [%q]
DATA_ENCRYPTION_METHOD = 2
ENCRYPTION_KEY = %q
UUID = %q
NODE_SECRET = %q
SESSION_V2 = "auto"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = %d
LOCAL_DNS_ENABLED = false
LOCAL_DNS_CACHE_PERSIST_TO_FILE = false
RESOLVER_BALANCING_STRATEGY = 3
PACKET_DUPLICATION_COUNT = 3
SETUP_PACKET_DUPLICATION_COUNT = 5
MAX_UPLOAD_MTU = 150
MAX_DOWNLOAD_MTU = 512
MAX_PACKETS_PER_BATCH = 32
RX_TX_WORKERS = 24
MTU_TEST_TIMEOUT = 1.5
MTU_TEST_RETRIES = 2
LOG_LEVEL = "ERROR"
%s
`

func startPerfClient(t *testing.T, relays []*net.UDPAddr, extra string) int {
	t.Helper()
	dir := t.TempDir()
	socksPort := freeTCPPort(t)
	cfg := fmt.Sprintf(perfClientConfig, e2eDomain, e2eKey, e2eUUID, e2eSecret, socksPort, extra)
	path := filepath.Join(dir, "client_config.toml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range relays {
		lines = append(lines, r.String())
	}
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := client.Bootstrap(path, "", configOverridesNone())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = app.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
		}
	})
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 200*time.Millisecond); err == nil {
			_ = c.Close()
			return socksPort
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("client never opened its SOCKS5 port")
	return 0
}

// socksDial opens a tunnelled connection and sends the app's first line.
func socksDial(socksPort int, first string, timeout time.Duration) (net.Conn, *bufio.Reader, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, nil, err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		c.Close()
		return nil, nil, err
	}
	host := "app.perf.example"
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, 443)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, nil, err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		c.Close()
		return nil, nil, fmt.Errorf("socks connect: %v %v", reply, err)
	}
	if _, err := io.WriteString(c, first); err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, bufio.NewReader(c), nil
}

type perfStats []time.Duration

func (s perfStats) String() string {
	if len(s) == 0 {
		return "n/a"
	}
	sorted := append(perfStats(nil), s...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p := func(q float64) time.Duration { return sorted[int(q*float64(len(sorted)-1))] }
	return fmt.Sprintf("p50 %4dms  p90 %4dms  max %4dms  (n=%d)",
		p(0.5).Milliseconds(), p(0.9).Milliseconds(), sorted[len(sorted)-1].Milliseconds(), len(sorted))
}

func envFloat(name string, def float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(name), 64); err == nil {
		return v
	}
	return def
}

func TestPerf(t *testing.T) {
	if os.Getenv("MDNS_PERF") == "" {
		t.Skip("set MDNS_PERF=1 to run the latency/throughput harness")
	}
	path := perfPath{
		delay:  time.Duration(envFloat("MDNS_PERF_DELAY", 60)) * time.Millisecond,
		jitter: 20 * time.Millisecond,
		loss:   envFloat("MDNS_PERF_LOSS", 0.02),
	}
	idle := time.Duration(envFloat("MDNS_PERF_IDLE", 40)) * time.Second

	app := startPerfApp(t)
	node := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: startPerfNode(t, app)}
	var relays []*net.UDPAddr
	for i := 0; i < 4; i++ {
		relays = append(relays, startLossyRelay(t, node, path))
	}
	port := startPerfClient(t, relays, os.Getenv("MDNS_PERF_EXTRA"))
	time.Sleep(2 * time.Second)

	t.Logf("path: %v one way + up to %v jitter, %.0f%% loss each way, 4 resolvers", path.delay, path.jitter, path.loss*100)

	// push: the far side speaks first after the tunnel has been idle. Measured
	// first, on a quiet tunnel: closing connections keeps it busy for a while.
	var push perfStats
	{
		var pwg sync.WaitGroup
		var pmu sync.Mutex
		for i := 0; i < 3; i++ {
			pwg.Add(1)
			go func() {
				defer pwg.Done()
				pc, pbr, err := socksDial(port, fmt.Sprintf("PUSH %d\n", idle.Milliseconds()), idle+60*time.Second)
				if err != nil {
					t.Error(err)
					return
				}
				defer pc.Close()
				line, err := pbr.ReadString('\n')
				if err != nil {
					t.Errorf("push: %v", err)
					return
				}
				sent, _ := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
				pmu.Lock()
				push = append(push, time.Since(time.Unix(0, sent)))
				pmu.Unlock()
			}()
		}
		pwg.Wait()
	}
	t.Logf("push      %s  (after %v idle)", push, idle)

	// connect: a fresh connection to the first echoed byte, from idle.
	var connect perfStats
	for i := 0; i < 8; i++ {
		start := time.Now()
		c, br, err := socksDial(port, "ECHO\nhello\n", 30*time.Second)
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		if _, err := br.ReadString('\n'); err != nil {
			t.Fatalf("connect %d echo: %v", i, err)
		}
		connect = append(connect, time.Since(start))
		c.Close()
		time.Sleep(1500 * time.Millisecond)
	}
	t.Logf("connect   %s", connect)

	// chat: round trips on one open connection, a message every 1.5 s.
	c, br, err := socksDial(port, "ECHO\n", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var chat perfStats
	for i := 0; i < 15; i++ {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		start := time.Now()
		if _, err := io.WriteString(c, "message\n"); err != nil {
			t.Fatal(err)
		}
		if _, err := br.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		chat = append(chat, time.Since(start))
		time.Sleep(1500 * time.Millisecond)
	}
	c.Close()
	t.Logf("chat      %s", chat)

	// download: one bulk transfer.
	const bulk = 512 * 1024
	start := time.Now()
	dc, dbr, err := socksDial(port, fmt.Sprintf("GET %d\n", bulk), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, dbr)
	dc.Close()
	if err != nil || n != bulk {
		t.Fatalf("download: %d bytes, %v", n, err)
	}
	elapsed := time.Since(start)
	t.Logf("download  %d KiB in %v = %.1f KiB/s", bulk/1024, elapsed.Round(time.Millisecond), float64(bulk)/1024/elapsed.Seconds())

	// parallel: a feed loading its images.
	const each, parallel = 64 * 1024, 8
	start = time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, parallel)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pc, pbr, err := socksDial(port, fmt.Sprintf("GET %d\n", each), 5*time.Minute)
			if err != nil {
				errs <- err
				return
			}
			defer pc.Close()
			if n, err := io.Copy(io.Discard, pbr); err != nil || n != each {
				errs <- fmt.Errorf("%d bytes, %v", n, err)
			}
			if os.Getenv("MDNS_PERF_EACH") != "" {
				t.Logf("  stream done at %v", time.Since(start).Round(time.Millisecond))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("parallel: %v", err)
	}
	elapsed = time.Since(start)
	t.Logf("parallel  %d x %d KiB in %v = %.1f KiB/s", parallel, each/1024, elapsed.Round(time.Millisecond), float64(parallel*each)/1024/elapsed.Seconds())
}

func configOverridesNone() config.ClientConfigOverrides { return config.ClientConfigOverrides{} }
