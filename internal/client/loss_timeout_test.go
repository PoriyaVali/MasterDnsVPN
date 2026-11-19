package client

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func TestLossTimeoutFollowsTheResolversOwnRoundTrip(t *testing.T) {
	const requestTimeout = 5 * time.Second
	var unknown connectionStats
	if got := unknown.lossTimeout(requestTimeout); got != requestTimeout {
		t.Fatalf("no round trip yet: %v, want the request timeout", got)
	}

	var fast connectionStats
	for i := 0; i < 20; i++ {
		fast.observeRTT(50 * time.Millisecond)
	}
	if got := fast.lossTimeout(requestTimeout); got != lossTimeoutFloor {
		t.Fatalf("steady 50 ms path: %v, want the floor %v", got, lossTimeoutFloor)
	}

	var jittery connectionStats
	for i := 0; i < 40; i++ {
		rtt := 400 * time.Millisecond
		if i%2 == 1 {
			rtt = 1200 * time.Millisecond
		}
		jittery.observeRTT(rtt)
	}
	got := jittery.lossTimeout(requestTimeout)
	if got <= 1200*time.Millisecond || got > requestTimeout {
		t.Fatalf("400/1200 ms path: %v, want room above its slow answers and at most the request timeout", got)
	}

	if got := fast.lossTimeout(300 * time.Millisecond); got != 300*time.Millisecond {
		t.Fatalf("a request timeout under the floor wins: %v", got)
	}
}

// A resolver that answered in 50 ms and goes silent: its unanswered query
// used to count as lost only after the request timeout - 5 s with four
// resolvers - and until then it kept a clean record and the balancer's
// traffic.
func TestASilentResolverIsCountedLostWithinItsOwnTimeout(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d")
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	const tunnelTimeout = 10 * time.Second
	start := time.Now().Add(-time.Minute)
	packet := func(id uint16) []byte {
		p := make([]byte, 12)
		binary.BigEndian.PutUint16(p, id)
		return p
	}
	for i := 0; i < 20; i++ {
		at := start.Add(time.Duration(i) * 100 * time.Millisecond)
		c.balancer.TrackResolverSend(packet(uint16(i)), addr.String(), "", "a", at, tunnelTimeout)
		c.balancer.TrackResolverSuccess(packet(uint16(i)), addr, "", at.Add(50*time.Millisecond), 0)
	}
	stats := c.balancer.statsForKey("a")

	silentAt := time.Now()
	c.balancer.TrackResolverSend(packet(999), addr.String(), "", "a", silentAt, tunnelTimeout)
	c.balancer.CollectExpiredResolverTimeouts(silentAt.Add(300*time.Millisecond), tunnelTimeout)
	if got := stats.lost.Load(); got != 0 {
		t.Fatalf("counted lost after 300 ms already: %d", got)
	}
	c.balancer.CollectExpiredResolverTimeouts(silentAt.Add(lossTimeoutFloor+100*time.Millisecond), tunnelTimeout)
	if got := stats.lost.Load(); got != 1 {
		t.Fatalf("unanswered for %v and not counted lost (lost=%d); the request timeout is 5 s",
			lossTimeoutFloor+100*time.Millisecond, got)
	}

	// Only slow, not gone: the late answer takes the loss back.
	c.balancer.TrackResolverSuccess(packet(999), addr, "", silentAt.Add(2*time.Second), 0)
	if got := stats.lost.Load(); got != 0 {
		t.Fatalf("a late answer must retract the loss, lost=%d", got)
	}
}

func TestTheLossSweepCountsDueQueriesWithoutTheHealthLoop(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d")
	c.tunnelPacketTimeout = 10 * time.Second
	stats := c.balancer.statsForKey("a")
	for i := 0; i < 20; i++ {
		stats.observeRTT(50 * time.Millisecond)
	}
	key := balancerResolverSampleKey{resolverAddr: "192.0.2.1:53", dnsID: 7}
	c.balancer.pendingStoreForTest(key, balancerResolverSample{serverKey: "a", sentAt: time.Now()})
	c.balancer.schedulePendingSweepAt(time.Now().Add(lossTimeoutFloor))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.runResolverLossSweep(ctx)
	waitForResolverHealthCondition(t, 2*time.Second, func() bool {
		sample, ok := c.balancer.pendingLookupForTest(key)
		return ok && sample.timedOut
	}, "the sweep did not count the due query as lost within 2 s")
}
