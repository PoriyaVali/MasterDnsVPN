package client

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
)

// feed gives resolver key n answered queries of the given round trip and
// lost ones, through the paths the runtime uses.
func feed(t *testing.T, c *Client, key string, ip string, rtt time.Duration, answered, lost int) {
	t.Helper()
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: 53}
	start := time.Now().Add(-2 * time.Minute)
	for i := 0; i < answered+lost; i++ {
		p := make([]byte, 12)
		binary.BigEndian.PutUint16(p, uint16(i))
		at := start.Add(time.Duration(i) * 50 * time.Millisecond)
		c.balancer.TrackResolverSend(p, addr.String(), "", key, at, 10*time.Second)
		if i < answered {
			c.balancer.TrackResolverSuccess(p, addr, "", at.Add(rtt), 0)
		}
	}
	c.balancer.CollectExpiredResolverTimeouts(time.Now(), 10*time.Second)
}

func picks(t *testing.T, c *Client, n int) map[string]int {
	t.Helper()
	seen := map[string]int{}
	for i := 0; i < n; i++ {
		conn, ok := c.balancer.GetBestConnection()
		if !ok {
			t.Fatal("no connection")
		}
		seen[conn.Key]++
	}
	return seen
}

func TestATopTierMemberMuchSlowerThanTheFastestLeavesTheRotation(t *testing.T) {
	for _, strategy := range []int{BalancingLeastLossTopRandom, BalancingLeastLossTopRoundRobin} {
		c := buildTestClientWithResolvers(config.ClientConfig{
			ResolverBalancingStrategy:       strategy,
			AutoDisableTimeoutServers:       true,
			AutoDisableTimeoutWindowSeconds: 30,
		}, "fast", "slow", "lossy1", "lossy2")
		feed(t, c, "fast", "192.0.2.1", 60*time.Millisecond, 20, 0)
		// Turned slow, lost nothing: every answer still comes, 1.8 s late.
		feed(t, c, "slow", "192.0.2.2", 1800*time.Millisecond, 20, 0)
		feed(t, c, "lossy1", "192.0.2.3", 60*time.Millisecond, 10, 10)
		feed(t, c, "lossy2", "192.0.2.4", 60*time.Millisecond, 10, 10)

		if got := picks(t, c, 40); got["slow"] != 0 || got["fast"] == 0 {
			t.Fatalf("strategy %d: %v - the tier rotated onto a resolver thirty times slower", strategy, got)
		}
	}
}

func TestOrdinarySpreadBetweenResolversKeepsBothInTheRotation(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy:       BalancingLeastLossTopRoundRobin,
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "near", "far", "lossy1", "lossy2")
	feed(t, c, "near", "192.0.2.1", 40*time.Millisecond, 20, 0)
	// Three times slower but only 80 ms more: ordinary spread, not a broken path.
	feed(t, c, "far", "192.0.2.2", 120*time.Millisecond, 20, 0)
	feed(t, c, "lossy1", "192.0.2.3", 60*time.Millisecond, 10, 10)
	feed(t, c, "lossy2", "192.0.2.4", 60*time.Millisecond, 10, 10)

	if got := picks(t, c, 40); got["near"] == 0 || got["far"] == 0 {
		t.Fatalf("%v - both belong in the rotation", got)
	}
}

func TestAPollProbesAResolverTheStrategyStoppedChoosing(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy:       BalancingLeastLossTopRoundRobin,
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d")
	feed(t, c, "a", "192.0.2.1", 60*time.Millisecond, 20, 0)
	feed(t, c, "b", "192.0.2.2", 60*time.Millisecond, 20, 0)
	feed(t, c, "c", "192.0.2.3", 60*time.Millisecond, 20, 0)
	// d lost a burst a while ago and has had no query since.
	feed(t, c, "d", "192.0.2.4", 60*time.Millisecond, 10, 10)
	now := time.Now().UnixNano()
	for _, key := range []string{"a", "b", "c"} {
		c.balancer.statsForKey(key).lastSentAt.Store(now)
	}
	c.balancer.statsForKey("d").lastSentAt.Store(now - int64(10*time.Second))

	for i := 0; i < 20; i++ {
		data, err := c.balancer.SelectTargets(Enums.PACKET_STREAM_DATA, 0, 1)
		if err != nil || len(data) != 1 || data[0].Key == "d" {
			t.Fatalf("data went to the idle resolver: %v %v", data, err)
		}
	}
	poll, err := c.balancer.SelectTargets(Enums.PACKET_PING, 0, 1)
	if err != nil || len(poll) != 1 || poll[0].Key != "d" {
		t.Fatalf("a poll should go to the resolver idle for 10 s: %v %v", poll, err)
	}
	// Then not again at once: one probe per idleResolverProbeEvery.
	again, err := c.balancer.SelectTargets(Enums.PACKET_PING, 0, 1)
	if err != nil || len(again) != 1 || again[0].Key == "d" {
		t.Fatalf("a second poll right after went to the idle resolver too: %v %v", again, err)
	}
}

func TestNoProbeWhileEveryResolverIsInUse(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy:       BalancingLossThenLatency,
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d")
	now := time.Now().UnixNano()
	for _, key := range []string{"a", "b", "c", "d"} {
		c.balancer.statsForKey(key).lastSentAt.Store(now)
	}
	if _, ok := c.balancer.idleResolverToProbeLocked(time.Now()); ok {
		t.Fatal("probed a resolver while every one had a query just now")
	}
}
