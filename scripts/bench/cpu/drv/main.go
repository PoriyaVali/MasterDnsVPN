//go:build linux

// Command drv measures a MasterDnsVPN node's CPU and service quality under the
// Android app's "balanced" client profile, through simulated resolvers.
//
// It runs the node (bin/node, from ../node) and real clients (bin/client, from
// cmd/client) as their own processes, so the node's CPU time is read from
// /proc and covers nothing else. The resolvers, the SOCKS5 egress and the
// far-side app live here. Every byte transferred is checked.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	binDir    = flag.String("bin", ".bench/cpu/bin", "directory holding node and client")
	clients   = flag.Int("clients", 1, "client processes (one user each)")
	resolvers = flag.Int("resolvers", 4, "simulated resolvers")
	delayMS   = flag.Float64("delay", 10, "one-way resolver delay, ms")
	jitterMS  = flag.Float64("jitter", 0, "extra random one-way delay up to this, ms")
	loss      = flag.Float64("loss", 0, "drop probability per packet and direction")
	phases    = flag.String("phases", "idle,download,upload,rtt,connect", "phases to run")
	idleSec   = flag.Float64("idle", 10, "idle phase length, s")
	size      = flag.Int("size", 2<<20, "bytes per stream for download/upload")
	streams   = flag.Int("streams", 2, "parallel streams per client")
	rounds    = flag.Int("rounds", 100, "round trips per client in rtt")
	conns     = flag.Int("conns", 20, "new connections per client in connect")
	profile   = flag.String("profile", "", "node profile prefix (one CPU profile per phase)")
	extra     = flag.String("extra", "", "extra client config lines")
	label     = flag.String("label", "", "label for the JSON result")
	jsonOut   = flag.String("json", "", "append the result as one JSON line here")
	srvEnv    = flag.String("srvenv", "", "extra environment for the node only, comma separated (GOMAXPROCS=1)")
)

const clientConfig = `PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["t.e2e.test"]
DATA_ENCRYPTION_METHOD = 2
ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"
UUID = %q
NODE_SECRET = "e2e-node-secret"
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

func uuidFor(i int) string { return fmt.Sprintf("5f0c6a8e-1111-4222-8333-%012d", i) }

// ---- simulated resolvers -------------------------------------------------

type relay struct {
	front  *net.UDPConn
	server *net.UDPAddr
	mu     sync.Mutex
	up     map[string]*net.UDPConn
}

var packetsUp, packetsDown atomic.Int64

func pathDelay() time.Duration {
	d := *delayMS
	if *jitterMS > 0 {
		d += rand.Float64() * *jitterMS
	}
	return time.Duration(d * float64(time.Millisecond))
}

func later(f func()) {
	if d := pathDelay(); d > 0 {
		time.AfterFunc(d, f)
		return
	}
	f()
}

func startRelay(server *net.UDPAddr) *relay {
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	_ = front.SetReadBuffer(4 << 20)
	_ = front.SetWriteBuffer(4 << 20)
	r := &relay{front: front, server: server, up: map[string]*net.UDPConn{}}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if *loss > 0 && rand.Float64() < *loss {
				continue
			}
			packetsUp.Add(1)
			up := r.upstream(from)
			p := append([]byte(nil), buf[:n]...)
			later(func() { _, _ = up.Write(p) })
		}
	}()
	return r
}

// upstream gives every client address its own socket toward the node, as a
// resolver's queries arrive from its own address.
func (r *relay) upstream(client *net.UDPAddr) *net.UDPConn {
	key := client.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.up[key]; c != nil {
		return c
	}
	c, err := net.DialUDP("udp", nil, r.server)
	must(err)
	_ = c.SetReadBuffer(4 << 20)
	r.up[key] = c
	dst := &net.UDPAddr{IP: client.IP, Port: client.Port}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			if *loss > 0 && rand.Float64() < *loss {
				continue
			}
			packetsDown.Add(1)
			p := append([]byte(nil), buf[:n]...)
			later(func() { _, _ = r.front.WriteToUDP(p, dst) })
		}
	}()
	return c
}

// ---- far side: app and egress ---------------------------------------------

// stream is the pseudo-random, incompressible content of one transfer.
type stream struct{ s uint64 }

func newStream(seed uint64) *stream { return &stream{s: seed*0x9E3779B97F4A7C15 + 1} }

func (g *stream) fill(p []byte) {
	for i := 0; i < len(p); i += 8 {
		g.s ^= g.s >> 12
		g.s ^= g.s << 25
		g.s ^= g.s >> 27
		var w [8]byte
		binary.LittleEndian.PutUint64(w[:], g.s*0x2545F4914F6CDD1D)
		copy(p[i:], w[:])
	}
}

func startApp() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveApp(c)
		}
	}()
	return ln.Addr().String()
}

func serveApp(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	f := strings.Fields(line)
	if len(f) == 0 {
		return
	}
	switch f[0] {
	case "GET": // GET <bytes> <seed>
		n, _ := strconv.Atoi(f[1])
		seed, _ := strconv.ParseUint(f[2], 10, 64)
		g := newStream(seed)
		buf := make([]byte, 16<<10)
		for n > 0 {
			k := min(n, len(buf))
			g.fill(buf[:(k+7)&^7])
			if _, err := c.Write(buf[:k]); err != nil {
				return
			}
			n -= k
		}
	case "PUT": // PUT <bytes> <seed>; answers OK or BAD
		n, _ := strconv.Atoi(f[1])
		seed, _ := strconv.ParseUint(f[2], 10, 64)
		if verify(br, n, seed) {
			_, _ = io.WriteString(c, "OK\n")
		} else {
			_, _ = io.WriteString(c, "BAD\n")
		}
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
	}
}

// verify reads n bytes and compares them with the stream for seed.
func verify(r io.Reader, n int, seed uint64) bool {
	g := newStream(seed)
	want := make([]byte, 16<<10+8)
	got := make([]byte, 16<<10)
	for n > 0 {
		k := min(n, len(got))
		if _, err := io.ReadFull(r, got[:k]); err != nil {
			return false
		}
		g.fill(want[:(k+7)&^7])
		for i := 0; i < k; i++ {
			if got[i] != want[i] {
				return false
			}
		}
		n -= k
	}
	return true
}

func startEgress(target string) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(br, hdr); err != nil {
					return
				}
				if _, err := io.ReadFull(br, make([]byte, hdr[1])); err != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0})
				req := make([]byte, 4)
				if _, err := io.ReadFull(br, req); err != nil {
					return
				}
				switch req[3] {
				case 1:
					_, _ = io.ReadFull(br, make([]byte, 6))
				case 3:
					l, _ := br.ReadByte()
					_, _ = io.ReadFull(br, make([]byte, int(l)+2))
				case 4:
					_, _ = io.ReadFull(br, make([]byte, 18))
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				go func() { _, _ = io.Copy(up, br); _ = up.(*net.TCPConn).CloseWrite() }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// ---- processes ------------------------------------------------------------

func freePort(network string) int {
	if network == "udp" {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		must(err)
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func cpuSeconds(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+2:])
	u, _ := strconv.ParseFloat(f[11], 64)
	k, _ := strconv.ParseFloat(f[12], 64)
	return (u + k) / 100
}

type proc struct {
	cmd *exec.Cmd
	out *strings.Builder
}

var (
	cleanupMu sync.Mutex
	cleanups  []*exec.Cmd
)

func stopAll() {
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	for i := len(cleanups) - 1; i >= 0; i-- {
		_ = cleanups[i].Process.Signal(syscall.SIGTERM)
		_ = cleanups[i].Wait()
	}
	cleanups = nil
}

func start(name string, args ...string) *proc { return startEnv(nil, name, args...) }

func startEnv(env []string, name string, args ...string) *proc {
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	for _, e := range env {
		if e != "" {
			cmd.Env = append(cmd.Env, e)
		}
	}
	out := &strings.Builder{}
	cmd.Stdout, cmd.Stderr = &lockedWriter{w: out}, &lockedWriter{w: out}
	cmd.Stdin = nil
	must(cmd.Start())
	cleanupMu.Lock()
	cleanups = append(cleanups, cmd)
	cleanupMu.Unlock()
	return &proc{cmd: cmd, out: out}
}

type lockedWriter struct {
	mu sync.Mutex
	w  *strings.Builder
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func waitTCP(port int, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %d never opened", port)
}

// ---- SOCKS5 through a client ----------------------------------------------

func dial(socks int, first string, timeout time.Duration) (net.Conn, *bufio.Reader, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socks), 5*time.Second)
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
	host := "app.bench.example"
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
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

// ---- phases ---------------------------------------------------------------

type phaseResult struct {
	Phase      string  `json:"phase"`
	Wall       float64 `json:"wall_s"`
	NodeCPU    float64 `json:"node_cpu_s"`
	ClientCPU  float64 `json:"client_cpu_s"`
	Bytes      int64   `json:"bytes,omitempty"`
	MiBps      float64 `json:"mib_per_s,omitempty"`
	CPUmsPerMB float64 `json:"node_cpu_ms_per_mib,omitempty"`
	P50ms      float64 `json:"p50_ms,omitempty"`
	P95ms      float64 `json:"p95_ms,omitempty"`
	P99ms      float64 `json:"p99_ms,omitempty"`
	PktUp      int64   `json:"packets_up"`
	PktDown    int64   `json:"packets_down"`
	USPerPkt   float64 `json:"node_us_per_packet"`
	Errors     int64   `json:"errors"`
	Corrupt    int64   `json:"corrupt"`
}

func percentile(d []time.Duration, p float64) float64 {
	if len(d) == 0 {
		return 0
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	i := int(float64(len(d)-1) * p)
	return float64(d[i]) / float64(time.Millisecond)
}

func main() {
	flag.Parse()
	app := startApp()
	egress := startEgress(app)
	port := freePort("udp")
	nodeAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	var relays []*relay
	for i := 0; i < *resolvers; i++ {
		relays = append(relays, startRelay(nodeAddr))
	}
	args := []string{"-port", strconv.Itoa(port), "-egress", strconv.Itoa(egress), "-users", strconv.Itoa(*clients)}
	if *profile != "" {
		args = append(args, "-profile", *profile)
	}
	node := startEnv(strings.Split(*srvEnv, ","), filepath.Join(*binDir, "node"), args...)
	defer stopAll()
	for i := 0; !strings.Contains(node.out.String(), "READY"); i++ {
		if i > 100 {
			fail("node did not start: " + node.out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	tmp, err := os.MkdirTemp("", "mdns-bench-")
	must(err)
	defer os.RemoveAll(tmp)
	var lines []string
	for _, r := range relays {
		lines = append(lines, r.front.LocalAddr().String())
	}
	var socks []int
	var procs []*proc
	for i := 0; i < *clients; i++ {
		dir := filepath.Join(tmp, strconv.Itoa(i))
		must(os.MkdirAll(dir, 0o700))
		p := freePort("tcp")
		must(os.WriteFile(filepath.Join(dir, "client_config.toml"), []byte(fmt.Sprintf(clientConfig, uuidFor(i), p, *extra)), 0o600))
		must(os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o600))
		c := start(filepath.Join(*binDir, "client"), "-config", filepath.Join(dir, "client_config.toml"))
		procs = append(procs, c)
		socks = append(socks, p)
	}
	for i, p := range socks {
		if err := waitTCP(p, 120*time.Second); err != nil {
			fail(fmt.Sprintf("client %d: %v\n%s", i, err, procs[i].out.String()))
		}
	}
	// Warm up: the first transfer opens each session and settles MTUs.
	var wg sync.WaitGroup
	for _, p := range socks {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if c, br, err := dial(p, "GET 65536 7\n", 120*time.Second); err == nil {
				_, _ = io.Copy(io.Discard, br)
				c.Close()
			}
		}(p)
	}
	wg.Wait()

	clientCPU := func() float64 {
		t := 0.0
		for _, c := range procs {
			t += cpuSeconds(c.cmd.Process.Pid)
		}
		return t
	}
	var results []phaseResult
	for _, ph := range strings.Split(*phases, ",") {
		ph = strings.TrimSpace(ph)
		if ph == "" {
			continue
		}
		if *profile != "" {
			_ = node.cmd.Process.Signal(syscall.SIGUSR1)
			time.Sleep(20 * time.Millisecond)
		}
		n0, c0, t0 := cpuSeconds(node.cmd.Process.Pid), clientCPU(), time.Now()
		u0, d0 := packetsUp.Load(), packetsDown.Load()
		res := phaseResult{Phase: ph}
		switch ph {
		case "idle":
			time.Sleep(time.Duration(*idleSec * float64(time.Second)))
		case "download", "upload":
			res.Bytes, res.Errors, res.Corrupt = transfer(ph, socks)
		case "rtt":
			var lat []time.Duration
			lat, res.Errors = roundTrips(socks)
			res.P50ms, res.P95ms, res.P99ms = percentile(lat, .5), percentile(lat, .95), percentile(lat, .99)
		case "connect":
			var lat []time.Duration
			lat, res.Errors = connects(socks)
			res.P50ms, res.P95ms, res.P99ms = percentile(lat, .5), percentile(lat, .95), percentile(lat, .99)
		default:
			fail("unknown phase " + ph)
		}
		res.Wall = time.Since(t0).Seconds()
		res.NodeCPU = cpuSeconds(node.cmd.Process.Pid) - n0
		res.ClientCPU = clientCPU() - c0
		res.PktUp, res.PktDown = packetsUp.Load()-u0, packetsDown.Load()-d0
		if res.PktUp > 0 {
			res.USPerPkt = res.NodeCPU * 1e6 / float64(res.PktUp)
		}
		if res.Bytes > 0 {
			mib := float64(res.Bytes) / (1 << 20)
			res.MiBps = mib / res.Wall
			res.CPUmsPerMB = res.NodeCPU * 1000 / mib
		}
		if *profile != "" {
			_ = node.cmd.Process.Signal(syscall.SIGUSR2)
			time.Sleep(200 * time.Millisecond)
		}
		results = append(results, res)
		fmt.Printf("%-9s wall %6.2fs  node CPU %6.2fs (%5.1f%%)  client CPU %6.2fs", ph, res.Wall, res.NodeCPU, 100*res.NodeCPU/res.Wall, res.ClientCPU)
		if res.Bytes > 0 {
			fmt.Printf("  %7.3f MiB/s  %7.1f node-ms/MiB", res.MiBps, res.CPUmsPerMB)
		}
		if res.P50ms > 0 {
			fmt.Printf("  p50 %6.1f p95 %6.1f p99 %6.1f ms", res.P50ms, res.P95ms, res.P99ms)
		}
		fmt.Printf("  pkts %d/%d  %.1f us/pkt  errors %d corrupt %d\n", res.PktUp, res.PktDown, res.USPerPkt, res.Errors, res.Corrupt)
	}
	if *jsonOut != "" {
		f, err := os.OpenFile(*jsonOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		must(err)
		b, _ := json.Marshal(map[string]any{"label": *label, "clients": *clients, "resolvers": *resolvers, "delay_ms": *delayMS, "loss": *loss, "results": results})
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
}

func transfer(ph string, socks []int) (int64, int64, int64) {
	var bytes, errs, corrupt atomic.Int64
	var wg sync.WaitGroup
	seed := uint64(time.Now().UnixNano())
	for ci, p := range socks {
		for s := 0; s < *streams; s++ {
			wg.Add(1)
			go func(p int, sd uint64) {
				defer wg.Done()
				if ph == "download" {
					c, br, err := dial(p, fmt.Sprintf("GET %d %d\n", *size, sd), 10*time.Minute)
					if err != nil {
						errs.Add(1)
						return
					}
					defer c.Close()
					if !verify(br, *size, sd) {
						corrupt.Add(1)
						return
					}
					bytes.Add(int64(*size))
					return
				}
				c, br, err := dial(p, fmt.Sprintf("PUT %d %d\n", *size, sd), 10*time.Minute)
				if err != nil {
					errs.Add(1)
					return
				}
				defer c.Close()
				g := newStream(sd)
				buf := make([]byte, 16<<10)
				for n := *size; n > 0; {
					k := min(n, len(buf))
					g.fill(buf[:(k+7)&^7])
					if _, err := c.Write(buf[:k]); err != nil {
						errs.Add(1)
						return
					}
					n -= k
				}
				line, err := br.ReadString('\n')
				if err != nil {
					errs.Add(1)
					return
				}
				if strings.TrimSpace(line) != "OK" {
					corrupt.Add(1)
					return
				}
				bytes.Add(int64(*size))
			}(p, seed+uint64(ci*1000+s))
		}
	}
	wg.Wait()
	return bytes.Load(), errs.Load(), corrupt.Load()
}

func roundTrips(socks []int) ([]time.Duration, int64) {
	var mu sync.Mutex
	var lat []time.Duration
	var errs atomic.Int64
	var wg sync.WaitGroup
	for _, p := range socks {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			c, br, err := dial(p, "ECHO\n", 5*time.Minute)
			if err != nil {
				errs.Add(1)
				return
			}
			defer c.Close()
			for i := 0; i < *rounds; i++ {
				t := time.Now()
				msg := fmt.Sprintf("ping %d %s\n", i, strings.Repeat("x", 40))
				if _, err := io.WriteString(c, msg); err != nil {
					errs.Add(1)
					return
				}
				got, err := br.ReadString('\n')
				if err != nil || got != msg {
					errs.Add(1)
					return
				}
				d := time.Since(t)
				mu.Lock()
				lat = append(lat, d)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return lat, errs.Load()
}

// connects opens fresh connections one after another and times each until its
// first byte comes back: the tunnel's connection setup as a user feels it.
func connects(socks []int) ([]time.Duration, int64) {
	var mu sync.Mutex
	var lat []time.Duration
	var errs atomic.Int64
	var wg sync.WaitGroup
	for _, p := range socks {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < *conns; i++ {
				t := time.Now()
				c, br, err := dial(p, "GET 1024 3\n", time.Minute)
				if err != nil {
					errs.Add(1)
					continue
				}
				_, err = br.ReadByte()
				d := time.Since(t)
				if err != nil {
					errs.Add(1)
				} else {
					mu.Lock()
					lat = append(lat, d)
					mu.Unlock()
				}
				_, _ = io.Copy(io.Discard, br)
				c.Close()
			}
		}(p)
	}
	wg.Wait()
	return lat, errs.Load()
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "drv:", msg)
	stopAll()
	os.Exit(1)
}
