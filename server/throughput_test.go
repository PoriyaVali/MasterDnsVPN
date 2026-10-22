package server_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// A repeatable bulk-only companion to TestPerf. Fixed per-relay seeds make
// throughput comparisons cheaper without removing the latency/chat checks
// from the original harness.
func TestPerfBulk(t *testing.T) {
	if os.Getenv("MDNS_PERF") == "" {
		t.Skip("set MDNS_PERF=1 to run the throughput harness")
	}
	node := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: startPerfNode(t, startPerfApp(t))}
	var relays []*net.UDPAddr
	for i := 0; i < 4; i++ {
		relays = append(relays, startLossyRelay(t, node, perfPath{
			delay: 10 * time.Millisecond, jitter: 20 * time.Millisecond,
			loss: 0.01, seed: uint64(100 + i),
		}))
	}
	port := startPerfClient(t, relays, os.Getenv("MDNS_PERF_EXTRA"))
	time.Sleep(2 * time.Second)
	const size = 512 * 1024
	for trial := 0; trial < 3; trial++ {
		start := time.Now()
		conn, reader, err := socksDial(port, fmt.Sprintf("GET %d\n", size), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(io.Discard, reader)
		_ = conn.Close()
		if err != nil || n != size {
			t.Fatalf("download %d: %d bytes, %v", trial, n, err)
		}
		t.Logf("download trial %d: %.1f KiB/s", trial+1, float64(size)/1024/time.Since(start).Seconds())
	}
}
