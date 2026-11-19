package client

import (
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
)

func probeTestClient(t *testing.T) *Client {
	t.Helper()
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy:       BalancingLeastLossTopRoundRobin,
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d")
	for i, key := range []string{"a", "b", "c", "d"} {
		feed(t, c, key, "192.0.2."+string(rune('1'+i)), 60*time.Millisecond, 20, 0)
	}
	return c
}

// idleFor marks d idle for the given time and every other resolver busy, and
// clears the probe rate limit.
func idleFor(c *Client, d time.Duration) {
	now := time.Now().UnixNano()
	for _, key := range []string{"a", "b", "c"} {
		c.balancer.statsForKey(key).lastSentAt.Store(now)
	}
	c.balancer.statsForKey("d").lastSentAt.Store(now - int64(d))
	c.balancer.lastExploreAt.Store(0)
}

func probedD(t *testing.T, c *Client) bool {
	t.Helper()
	got, err := c.balancer.SelectTargets(Enums.PACKET_PING, 0, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	return got[0].Key == "d"
}

// While a transfer runs, a probe's answer carries a downstream packet, and a
// resolver that forwards queries but drops answers loses it: an idle
// resolver is probed far less often then, and less still while its probes
// go unanswered.
func TestProbesBackOffWhileDataFlows(t *testing.T) {
	c := probeTestClient(t)
	// Data arriving right now.
	c.pingManager.lastNonPongReceivedAt.Store(time.Now().UnixNano())

	idleFor(c, 10*time.Second)
	if probedD(t, c) {
		t.Fatal("probed a resolver idle 10 s in the middle of a transfer")
	}
	idleFor(c, busyResolverProbeAfter+time.Second)
	if !probedD(t, c) {
		t.Fatalf("no probe after %v idle", busyResolverProbeAfter+time.Second)
	}

	// The probe goes unanswered: the next waits twice as long.
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.4"), Port: 53}
	start := time.Now().Add(-time.Minute)
	c.balancer.TrackResolverSend(slowTestPacket(900), addr.String(), "", "d", start, 10*time.Second)
	c.balancer.CollectExpiredResolverTimeouts(start.Add(2*time.Second), 10*time.Second)
	idleFor(c, busyResolverProbeAfter+time.Second)
	if probedD(t, c) {
		t.Fatal("probed again at the normal pace right after an unanswered probe")
	}
	idleFor(c, 2*busyResolverProbeAfter+time.Second)
	if !probedD(t, c) {
		t.Fatal("never probed again after backing off")
	}

	// Answered in time: back to the normal pace.
	c.balancer.TrackResolverSend(slowTestPacket(901), addr.String(), "", "d", time.Now(), 10*time.Second)
	c.balancer.TrackResolverSuccess(slowTestPacket(901), addr, "", time.Now().Add(60*time.Millisecond), 0)
	idleFor(c, busyResolverProbeAfter+time.Second)
	if !probedD(t, c) {
		t.Fatal("a timely answer did not reset the back-off")
	}
}

// Nothing coming down: the server has nothing to put in a probe's answer,
// and idle resolvers are probed at the fast pace, back-off or not.
func TestProbesAreFastWhileNothingComesDown(t *testing.T) {
	c := probeTestClient(t)
	c.balancer.statsForKey("d").probeBackoff.Store(int64(resolverProbeBackoffMax))
	c.pingManager.lastNonPongReceivedAt.Store(time.Now().Add(-5 * time.Second).UnixNano())

	idleFor(c, idleResolverAfter+time.Second)
	if !probedD(t, c) {
		t.Fatalf("no probe after %v idle on a quiet tunnel", idleResolverAfter+time.Second)
	}
}

// A duplicated poll keeps a copy where the strategy puts it and spends the
// other on the probe.
func TestADuplicatedPollSpendsOneCopyOnTheProbe(t *testing.T) {
	c := probeTestClient(t)
	c.pingManager.lastNonPongReceivedAt.Store(time.Now().Add(-5 * time.Second).UnixNano())
	idleFor(c, idleResolverAfter+time.Second)

	got, err := c.balancer.SelectTargets(Enums.PACKET_PING, 0, 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if got[0].Key == "d" || got[1].Key != "d" {
		t.Fatalf("copies went to %s and %s; want a strategy pick, then the probe of d", got[0].Key, got[1].Key)
	}
}
