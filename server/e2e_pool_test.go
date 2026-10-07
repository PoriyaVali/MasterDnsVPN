package server_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"masterdnsvpn-go/internal/client"
	"masterdnsvpn-go/internal/config"
)

// startPoolClient runs the real client in load-balancer mode, one SERVERS
// entry per node, each reached through that node's own relay.
func startPoolClient(t *testing.T, strategy string, nodes ...*e2eNode) int {
	t.Helper()
	dir := t.TempDir()
	socksPort := freeTCPPort(t)

	var servers strings.Builder
	for i, n := range nodes {
		fmt.Fprintf(&servers, "\n[[SERVERS]]\nNAME = \"node-%d\"\nRESOLVERS = [%q]\n", i+1, n.relay.String())
	}
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
LOAD_BALANCER_STRATEGY = %q
LOAD_BALANCER_STICKY = false
%s`, e2eDomain, e2eKey, e2eUUID, e2eSecret, socksPort, strategy, servers.String())
	path := filepath.Join(dir, "client_config.toml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := config.LoadClientConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := client.BootstrapPool(loaded, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = pool.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
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
	t.Fatal("load balancer never opened its SOCKS5 port")
	return 0
}

func (w *wireRecorder) downLen() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.down.Len()
}

// Every server carries part of the traffic: connections are spread, and each
// one is carried end to end by the server it was given.
func TestE2E_LoadBalancerSpreadsConnectionsAcrossServers(t *testing.T) {
	body := e2eBody(t)
	a, b := startNode(t, body), startNode(t, body)
	port := startPoolClient(t, config.LoadBalancerRoundRobin, a, b)

	// Both servers must have opened a session before the spread is measured;
	// the listener opens as soon as the first one has.
	deadline := time.Now().Add(40 * time.Second)
	for len(a.seenDevices()) == 0 || len(b.seenDevices()) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("sessions: node a %d, node b %d", len(a.seenDevices()), len(b.seenDevices()))
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(time.Second)

	beforeA, beforeB := a.wire.downLen(), b.wire.downLen()
	const fetches = 6
	for i := 0; i < fetches; i++ {
		if got := fetch(t, port); !bytes.Equal(got, body) {
			t.Fatalf("fetch %d: body differs (%d bytes, want %d)", i, len(got), len(body))
		}
	}
	grewA, grewB := a.wire.downLen()-beforeA, b.wire.downLen()-beforeB

	// Round robin over two servers: three bodies each. Pings add a little;
	// a server that carried no body would have grown by far less than one.
	if grewA < len(body) || grewB < len(body) {
		t.Fatalf("traffic was not spread: node a +%d bytes, node b +%d bytes (body %d)", grewA, grewB, len(body))
	}
}

// A server that stops answering stops getting new connections; the others
// carry them.
func TestE2E_LoadBalancerRoutesAroundADeadServer(t *testing.T) {
	body := e2eBody(t)
	a, b := startNode(t, body), startNode(t, body)
	// Failover: everything goes to node-1 while it answers.
	port := startPoolClient(t, config.LoadBalancerFailover, a, b)

	deadline := time.Now().Add(40 * time.Second)
	for len(a.seenDevices()) == 0 || len(b.seenDevices()) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("sessions: node a %d, node b %d", len(a.seenDevices()), len(b.seenDevices()))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := fetch(t, port); !bytes.Equal(got, body) {
		t.Fatal("first fetch: body differs")
	}

	_ = a.srv.Close()
	beforeB := b.wire.downLen()

	// Connections made while node-1's silence is still within an ordinary
	// round trip may stall on it; within a few seconds of that the pool
	// gives up on it and node-2 takes them.
	deadline = time.Now().Add(60 * time.Second)
	for {
		got, err := tryFetch(port, 8*time.Second)
		if err == nil && bytes.Equal(got, body) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no fetch succeeded after node-1 died: %v", err)
		}
	}
	if grew := b.wire.downLen() - beforeB; grew < len(body) {
		t.Fatalf("node-2 did not carry the fetch after node-1 died (+%d bytes)", grew)
	}
}
