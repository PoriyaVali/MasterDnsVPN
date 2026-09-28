package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
	mdns "masterdnsvpn-go/server"
)

// End to end, over real sockets: the real client, the public server package
// as V2bX embeds it, and a recording "resolver" in between that sees exactly
// what a network observer (or the censor) would. Traffic is an HTTP download
// through the client's SOCKS5 port, carrying a marker the test then looks for
// on the wire.

const (
	e2eDomain = "t.e2e.test"
	e2eKey    = "0123456789abcdef0123456789abcdef"
	e2eSecret = "e2e-node-secret"
	e2eUUID   = "5f0c6a8e-1111-4222-8333-944455556666"
	e2eMarker = "E2E-MARKER-7f3a9c1d-THIS-MUST-NOT-CROSS-THE-WIRE-IN-CLEAR"
)

type wireRecorder struct {
	mu   sync.Mutex
	down bytes.Buffer // server -> client
	up   bytes.Buffer // client -> server
}

func (w *wireRecorder) downstream() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.down.Bytes()...)
}

// startRelay stands in for a recursive resolver: it forwards every datagram
// from the client to the node and every answer back, keeping a copy.
func startRelay(t *testing.T, node *net.UDPAddr, rec *wireRecorder) *net.UDPAddr {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = front.Close() })

	var mu sync.Mutex
	back := map[string]*net.UDPConn{}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			rec.mu.Lock()
			rec.up.Write(buf[:n])
			rec.mu.Unlock()

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
						rec.mu.Lock()
						rec.down.Write(rb[:m])
						rec.mu.Unlock()
						_, _ = front.WriteToUDP(rb[:m], client)
					}
				}(conn, from)
			}
			mu.Unlock()
			_, _ = conn.Write(buf[:n])
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

// startTarget is the "website": an HTTP server whose body carries the marker.
func startTarget(t *testing.T, body []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// startEgressProxy is the operator's upstream SOCKS5 (USE_EXTERNAL_SOCKS5): it
// accepts any CONNECT and joins it to the target, so the test needs neither the
// internet nor an exception to the node's inside-address rule.
func startEgressProxy(t *testing.T, target string) int {
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
					_, _ = io.ReadFull(br, make([]byte, 4+2))
				case 3:
					l, _ := br.ReadByte()
					_, _ = io.ReadFull(br, make([]byte, int(l)+2))
				case 4:
					_, _ = io.ReadFull(br, make([]byte, 16+2))
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type e2eNode struct {
	relay   *net.UDPAddr
	wire    *wireRecorder
	mu      sync.Mutex
	devices []string
	srv     *mdns.Server
	start   func() *mdns.Server
}

// restart stops the node and brings up a fresh one on the same port - the
// sessions it held are gone, as after a V2bX update or a crash.
func (n *e2eNode) restart(t *testing.T) {
	t.Helper()
	_ = n.srv.Close()
	n.srv = n.start()
}

func (n *e2eNode) seenDevices() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.devices...)
}

func startNode(t *testing.T, body []byte) *e2eNode {
	t.Helper()
	egress := startEgressProxy(t, startTarget(t, body))
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
	_ = srv
	node := &e2eNode{wire: &wireRecorder{}}
	node.start = func() *mdns.Server {
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
		srv.SetSessionAuthorizer(func(uuid, device string) bool {
			node.mu.Lock()
			node.devices = append(node.devices, device)
			node.mu.Unlock()
			return true
		})
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		return srv
	}
	node.srv = node.start()
	t.Cleanup(func() { _ = node.srv.Close() })
	node.relay = startRelay(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, node.wire)
	return node
}

// startClient runs the real client against the relay and returns its SOCKS5
// port once it is accepting connections.
func startClient(t *testing.T, relay *net.UDPAddr, extra string) int {
	t.Helper()
	dir := t.TempDir()
	socksPort := freeTCPPort(t)
	cfg := fmt.Sprintf(`PROTOCOL_TYPE = "SOCKS5"
DOMAINS = [%q]
DATA_ENCRYPTION_METHOD = 2
ENCRYPTION_KEY = %q
UUID = %q
NODE_SECRET = %q
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = %d
LOCAL_DNS_ENABLED = false
LOCAL_DNS_CACHE_PERSIST_TO_FILE = false
MIN_UPLOAD_MTU = 38
MIN_DOWNLOAD_MTU = 100
MAX_UPLOAD_MTU = 150
MAX_DOWNLOAD_MTU = 900
MTU_TEST_TIMEOUT = 1.0
LOG_LEVEL = "ERROR"
%s
`, e2eDomain, e2eKey, e2eUUID, e2eSecret, socksPort, extra)
	path := filepath.Join(dir, "client_config.toml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte(relay.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	app, err := client.Bootstrap(path, "", config.ClientConfigOverrides{})
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
		case <-time.After(10 * time.Second):
		}
	})

	deadline := time.Now().Add(40 * time.Second)
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

// fetch downloads the target through the client's SOCKS5 port.
func fetch(t *testing.T, socksPort int) []byte {
	t.Helper()
	got, err := tryFetch(socksPort, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func tryFetch(socksPort int, timeout time.Duration) (body []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	ft := &fetchT{}
	body = fetchWith(ft, socksPort, timeout)
	if ft.err != nil {
		return nil, ft.err
	}
	return body, nil
}

// fetchT lets the download code report instead of failing the test, so a
// caller can retry while a session is being re-established.
type fetchT struct{ err error }

func (f *fetchT) Helper() {}
func (f *fetchT) Fatal(args ...any) {
	f.err = fmt.Errorf("%v", fmt.Sprint(args...))
	panic(f.err)
}
func (f *fetchT) Fatalf(format string, args ...any) {
	f.err = fmt.Errorf(format, args...)
	panic(f.err)
}

type fataler interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

func fetchWith(t fataler, socksPort int, timeout time.Duration) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	host := "site.e2e.example"
	req := []byte{5, 1, 0}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil || greet[1] != 0 {
		t.Fatalf("socks greeting: %v %v", greet, err)
	}
	conn := []byte{5, 1, 0, 3, byte(len(host))}
	conn = append(conn, host...)
	conn = binary.BigEndian.AppendUint16(conn, 80)
	if _, err := c.Write(conn); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		t.Fatalf("socks connect: %v %v", reply, err)
	}
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func e2eBody(t *testing.T) []byte {
	t.Helper()
	filler := make([]byte, 24*1024)
	if _, err := rand.Read(filler); err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(e2eMarker), filler...), e2eMarker...)
}

func TestE2E_SessionV2SealsTheDownstream(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end")
	}
	body := e2eBody(t)
	node := startNode(t, body)
	socks := startClient(t, node.relay, `DEVICE_ID = "e2e-phone-1"
SESSION_V2 = "auto"`)

	got := fetch(t, socks)
	if !bytes.Equal(got, body) {
		t.Fatalf("downloaded %d bytes, want %d intact", len(got), len(body))
	}
	wire := node.wire.downstream()
	if len(wire) < len(body) {
		t.Fatalf("recorder saw only %d downstream bytes", len(wire))
	}
	if bytes.Contains(wire, []byte(e2eMarker)) || bytes.Contains(wire, []byte("HTTP/1.1 200")) {
		t.Fatal("v2 session: the download crossed the wire in clear")
	}
	devices := node.seenDevices()
	if len(devices) == 0 || !strings.HasPrefix(devices[0], "fd6d:6473:") {
		t.Fatalf("device limit saw %v, want the client's declared device", devices)
	}
}

// The control: the same download in v1 does show the marker on the wire, which
// proves the recorder can see plaintext when it is there - so its absence
// above is a real result, not a blind probe.
func TestE2E_SessionV1StillWorksAndIsVisible(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end")
	}
	body := e2eBody(t)
	node := startNode(t, body)
	socks := startClient(t, node.relay, `SESSION_V2 = "off"`)

	got := fetch(t, socks)
	if !bytes.Equal(got, body) {
		t.Fatalf("downloaded %d bytes, want %d intact", len(got), len(body))
	}
	if !bytes.Contains(node.wire.downstream(), []byte(e2eMarker)) {
		t.Fatal("control failed: v1 downstream should carry the marker in clear")
	}
	devices := node.seenDevices()
	if len(devices) == 0 || devices[0] != "127.0.0.1" {
		t.Fatalf("v1 device limit saw %v, want the resolver address", devices)
	}
}

// The node restarts under a connected v2 client (a V2bX update, a crash): the
// client's session is gone and the new node cannot open its sealed frames. It
// must be told, start a new session, and carry traffic again.
func TestE2E_SessionV2RecoversFromANodeRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end")
	}
	body := e2eBody(t)
	node := startNode(t, body)
	socks := startClient(t, node.relay, `DEVICE_ID = "e2e-phone-1"
SESSION_V2 = "on"`)
	if got := fetch(t, socks); !bytes.Equal(got, body) {
		t.Fatal("first download broken")
	}

	node.restart(t)

	deadline := time.Now().Add(60 * time.Second)
	for {
		got, err := tryFetch(socks, 20*time.Second)
		if err == nil && bytes.Equal(got, body) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("client never recovered after the node restarted (last error: %v)", err)
		}
		time.Sleep(time.Second)
	}
}
