package server_test

import (
	"bytes"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startWeakNetworkEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// These use real client/server sockets and validate every transferred byte,
// not just a port opening. Loss applies independently in both directions;
// jitter also reorders packets. Limits are DNS datagram sizes, not raw MTUs.
func TestWeakNetworkRoundTripAndRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("weak-path integration tests require delayed real sockets")
	}
	profiles := []struct {
		name      string
		path      perfPath
		resolvers int
	}{
		{"weak", perfPath{delay: 75 * time.Millisecond, jitter: 50 * time.Millisecond, loss: 0.10, maxQueryBytes: 340, maxAnswerBytes: 640}, 2},
		{"very_weak", perfPath{delay: 200 * time.Millisecond, jitter: 100 * time.Millisecond, loss: 0.20, maxQueryBytes: 300, maxAnswerBytes: 512}, 2},
		{"very_weak_fanout", perfPath{delay: 200 * time.Millisecond, jitter: 100 * time.Millisecond, loss: 0.20, maxQueryBytes: 300, maxAnswerBytes: 512}, 6},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			// Each profile has its own node, relays and client, and spends
			// its time waiting on delays and MTU probe timeouts, not CPU:
			// side by side, the test takes as long as its slowest profile
			// (~75 s) instead of all three in turn (~3.5 min) on every push.
			t.Parallel()
			started := time.Now()
			var blackout atomic.Bool
			var counts perfPathCounts
			node := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: startPerfNode(t, startWeakNetworkEcho(t))}
			var relays []*net.UDPAddr
			for i := 0; i < profile.resolvers; i++ {
				path := profile.path
				path.seed = uint64(100 + i)
				path.blackout, path.counts = &blackout, &counts
				relays = append(relays, startLossyRelay(t, node, path))
			}
			// Lower parallelism and bounded polling fit a constrained link;
			// setup copies remain protected. Larger configured MTUs force the
			// real discovery code to adapt to each relay's smaller limits.
			cfg := strings.NewReplacer(
				"SESSION_V2 = \"auto\"", "SESSION_V2 = \"on\"",
				"RX_TX_WORKERS = 24", "RX_TX_WORKERS = 4",
				"RESOLVER_BALANCING_STRATEGY = 3", "RESOLVER_BALANCING_STRATEGY = 6",
				"PACKET_DUPLICATION_COUNT = 3", "PACKET_DUPLICATION_COUNT = 2",
				"SETUP_PACKET_DUPLICATION_COUNT = 5", "SETUP_PACKET_DUPLICATION_COUNT = 3",
				"MTU_TEST_TIMEOUT = 1.5", "MTU_TEST_TIMEOUT = 2.5",
				"MTU_TEST_RETRIES = 2", "MTU_TEST_RETRIES = 3",
			).Replace(perfClientConfig)
			if profile.resolvers > 2 {
				cfg = strings.ReplaceAll(cfg, "PACKET_DUPLICATION_COUNT = 2", "PACKET_DUPLICATION_COUNT = 3")
				cfg = strings.ReplaceAll(cfg, "SETUP_PACKET_DUPLICATION_COUNT = 3", "SETUP_PACKET_DUPLICATION_COUNT = 5")
			}
			port := startPerfClientProfile(t, relays, cfg, "PULL_PIPELINE_DEPTH = 32\nSESSION_INIT_RACING_COUNT = 2\n")
			conn, reader, err := socksDial(port, "", 60*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			rng := rand.New(rand.NewPCG(11, 23))
			for phase := 0; phase < 2; phase++ {
				if phase == 1 {
					blackout.Store(true)
					timer := time.AfterFunc(2*time.Second, func() { blackout.Store(false) })
					defer timer.Stop()
				}
				payload := make([]byte, 4*1024)
				for i := range payload {
					payload[i] = byte(rng.Uint32())
				}
				_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
				if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
					t.Fatalf("phase %d upload: %v", phase, err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(reader, got); err != nil {
					t.Fatalf("phase %d download: %v", phase, err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("phase %d corrupted data", phase)
				}
			}
			if counts.dropped.Load() == 0 || counts.oversized.Load() == 0 {
				t.Fatal("test did not exercise both packet loss and MTU limits")
			}
			t.Logf("8 KiB echoed intact, same connection recovered from 2s blackout; dropped=%d oversized=%d elapsed=%v", counts.dropped.Load(), counts.oversized.Load(), time.Since(started).Round(time.Millisecond))
		})
	}
}
