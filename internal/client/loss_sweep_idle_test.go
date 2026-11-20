package client

import (
	"context"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func TestLossSweepBacksOffOnlyWhileNothingIsPending(t *testing.T) {
	wait := resolverLossSweepInterval
	var steps []time.Duration
	for i := 0; i < 5; i++ {
		wait = nextLossSweepWait(wait, false)
		steps = append(steps, wait)
	}
	want := []time.Duration{500, 1000, 2000, 2000, 2000}
	for i, ms := range want {
		if steps[i] != ms*time.Millisecond {
			t.Fatalf("idle steps %v, want %v ms", steps, want)
		}
	}
	if got := nextLossSweepWait(2*time.Second, true); got != resolverLossSweepInterval {
		t.Fatalf("with a query pending the sweep waits %v, want the full rate", got)
	}
}

// The sweep used to tick every 250 ms for the whole session; it now backs off
// while nothing is in flight. A query sent after the quiet spell still has its
// loss counted on time, because sending it wakes the sweep.
func TestALossIsStillCountedOnTimeAfterAQuietSpell(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c")
	c.tunnelPacketTimeout = 10 * time.Second
	stats := c.balancer.statsForKey("a")
	for i := 0; i < 20; i++ {
		stats.observeRTT(50 * time.Millisecond) // its loss timeout is the 600 ms floor
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.runResolverLossSweep(ctx)
	time.Sleep(2 * time.Second) // quiet: the sweep is waiting 2 s by now

	sent := time.Now()
	c.balancer.TrackResolverSend(slowTestPacket(1), "192.0.2.1:53", "", "a", sent, c.tunnelPacketTimeout)
	deadline := sent.Add(600*time.Millisecond + resolverLossSweepInterval + 150*time.Millisecond)
	for stats.lost.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stats.lost.Load() == 0 {
		t.Fatalf("a silent resolver's query was not counted lost %v after it was sent; the sweep slept through it",
			time.Since(sent).Round(time.Millisecond))
	}
}
