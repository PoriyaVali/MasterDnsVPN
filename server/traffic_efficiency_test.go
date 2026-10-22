package server_test

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Counts offered DNS datagrams in both directions, including copies and
// retransmissions. This is a wire-budget experiment, not a carrier bill.
func TestTrafficEfficiency(t *testing.T) {
	if os.Getenv("MDNS_TRAFFIC") == "" {
		t.Skip("set MDNS_TRAFFIC=1 to measure traffic per useful byte")
	}
	var counts perfPathCounts
	node := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: startPerfNode(t, startWeakNetworkEcho(t))}
	var relays []*net.UDPAddr
	for i := 0; i < 6; i++ {
		relays = append(relays, startLossyRelay(t, node, perfPath{
			delay: 5 * time.Millisecond, jitter: 5 * time.Millisecond,
			seed: uint64(100 + i), counts: &counts,
		}))
	}
	profile := strings.NewReplacer(
		"SESSION_V2 = \"auto\"", "SESSION_V2 = \"on\"",
		"RX_TX_WORKERS = 24", "RX_TX_WORKERS = 4",
		"RESOLVER_BALANCING_STRATEGY = 3", "RESOLVER_BALANCING_STRATEGY = 2",
	).Replace(perfClientConfig)
	port := startPerfClientProfile(t, relays, profile, "")
	time.Sleep(100 * time.Millisecond)
	beforeUp, beforeDown := counts.upBytes.Load(), counts.downBytes.Load()
	beforePackets := counts.upPackets.Load() + counts.downPackets.Load()
	const streams, size = 4, 32 * 1024
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for worker := 0; worker < streams; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			conn, reader, err := socksDial(port, "", 30*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			rng := rand.New(rand.NewPCG(uint64(worker+1), 23))
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(rng.Uint32())
			}
			if _, err = io.Copy(conn, bytes.NewReader(payload)); err != nil {
				errs <- err
				return
			}
			got := make([]byte, size)
			if _, err = io.ReadFull(reader, got); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(payload, got) {
				errs <- fmt.Errorf("stream %d: data corrupted", worker)
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	// Include the closing ACKs; both variants use the same settling period.
	time.Sleep(200 * time.Millisecond)
	up, down := counts.upBytes.Load()-beforeUp, counts.downBytes.Load()-beforeDown
	packets := counts.upPackets.Load() + counts.downPackets.Load() - beforePackets
	ipv4UDP := up + down + 28*packets
	t.Logf("useful=%d dns_up=%d dns_down=%d datagrams=%d ipv4_udp=%d bytes_per_useful=%.3f elapsed=%v", 2*streams*size, up, down, packets, ipv4UDP, float64(ipv4UDP)/(2*streams*size), time.Since(start).Round(time.Millisecond))
}
