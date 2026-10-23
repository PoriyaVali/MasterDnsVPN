package server_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run an actual previous-release executable against the current embeddable
// server, as used by V2bX. No network download is performed by the test itself.
//
//	MDNS_COMPAT_CLIENT=/absolute/path/to/mdns-linux-amd64 go test ./server \
//	  -run '^TestE2EOlderClient$' -count=1 -v
func TestE2EOlderClient(t *testing.T) {
	binary := os.Getenv("MDNS_COMPAT_CLIENT")
	if binary == "" {
		t.Skip("set MDNS_COMPAT_CLIENT to an older client executable")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	version, err := exec.Command(binary, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("client version: %v: %s", err, version)
	}
	body := e2eBody(t)
	node := startNode(t, body)
	dir := t.TempDir()
	socksPort := freeTCPPort(t)
	profile := strings.NewReplacer(
		"SESSION_V2 = \"auto\"", "SESSION_V2 = \"on\"",
		"RX_TX_WORKERS = 24", "RX_TX_WORKERS = 4",
	).Replace(perfClientConfig)
	configPath := filepath.Join(dir, "client_config.toml")
	config := fmt.Sprintf(profile, e2eDomain, e2eKey, e2eUUID, e2eSecret, socksPort, "DEVICE_ID = \"compat-old-client\"\n")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte(node.relay.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "client.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "-config", configPath)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, log, log
	if err := cmd.Start(); err != nil {
		cancel()
		_ = log.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = log.Close()
		if t.Failed() {
			output, _ := os.ReadFile(logPath)
			t.Logf("older client log: %s", output)
		}
	})
	deadline := time.Now().Add(45 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case <-done:
			t.Fatal("older client exited before opening SOCKS5")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("older client never opened SOCKS5")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for attempt := 0; attempt < 2; attempt++ {
		got := fetch(t, socksPort)
		if !bytes.Equal(got, body) {
			t.Fatalf("download %d: got %d bytes, want %d intact", attempt, len(got), len(body))
		}
		// Allow empty authenticated PONGs before opening another stream.
		time.Sleep(300 * time.Millisecond)
	}
	// A node upgrade replaces its in-memory sessions. The old executable
	// must also recover a session against the restarted server.
	node.restart(t)
	deadline = time.Now().Add(40 * time.Second)
	for {
		got, err := tryFetch(socksPort, 5*time.Second)
		if err == nil && bytes.Equal(got, body) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("older client did not recover after node restart: bytes=%d err=%v", len(got), err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	devices := node.seenDevices()
	if len(devices) == 0 || !strings.HasPrefix(devices[0], "fd6d:6473:") {
		t.Fatalf("older client did not establish a device-bound V2 session: %v", devices)
	}
	if bytes.Contains(node.wire.downstream(), []byte(e2eMarker)) {
		t.Fatal("older client received application data in cleartext")
	}
	t.Logf("%s: three %d-byte downloads intact over V2, including after node restart", strings.TrimSpace(string(version)), len(body))
}
