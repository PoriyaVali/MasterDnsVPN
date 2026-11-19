package client

import (
	"fmt"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
)

// Strategies 6, 7 and 8 took every copy of a duplicated packet from their
// pool alone, so the copy count came out at the pool's size: one copy under
// strategy 6 whenever one resolver was clearly the fastest, two at most
// under 7 and 8, and one when the latency guard left a tier of one.
func TestDuplicationKeepsItsCopyCountUnderPooledStrategies(t *testing.T) {
	cases := []struct {
		name     string
		strategy int
		rtts     [4]time.Duration
	}{
		{"loss-then-latency, one clearly fastest", BalancingLossThenLatency,
			[4]time.Duration{40 * time.Millisecond, 120 * time.Millisecond, 130 * time.Millisecond, 140 * time.Millisecond}},
		{"top tier random, all equal", BalancingLeastLossTopRandom,
			[4]time.Duration{60 * time.Millisecond, 60 * time.Millisecond, 60 * time.Millisecond, 60 * time.Millisecond}},
		{"top tier round robin, all equal", BalancingLeastLossTopRoundRobin,
			[4]time.Duration{60 * time.Millisecond, 60 * time.Millisecond, 60 * time.Millisecond, 60 * time.Millisecond}},
		{"top tier round robin, a slow member left out", BalancingLeastLossTopRoundRobin,
			[4]time.Duration{60 * time.Millisecond, 1800 * time.Millisecond, 60 * time.Millisecond, 60 * time.Millisecond}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := buildTestClientWithResolvers(config.ClientConfig{
				ResolverBalancingStrategy:       tc.strategy,
				AutoDisableTimeoutServers:       true,
				AutoDisableTimeoutWindowSeconds: 30,
			}, "a", "b", "c", "d")
			for i, key := range []string{"a", "b", "c", "d"} {
				feed(t, c, key, fmt.Sprintf("192.0.2.%d", i+1), tc.rtts[i], 20, 0)
			}
			c.balancer.EnsureStream(9)
			for _, want := range []int{2, 3, 4} {
				for _, call := range []struct {
					what       string
					packetType uint8
					streamID   uint16
				}{
					{"setup packet", Enums.PACKET_STREAM_SYN, 7},
					{"data, no stream route", Enums.PACKET_STREAM_DATA, 7},
					{"data on a routed stream", Enums.PACKET_STREAM_DATA, 9},
				} {
					got, err := c.balancer.SelectTargets(call.packetType, call.streamID, want)
					if err != nil {
						t.Fatal(err)
					}
					unique := map[string]bool{}
					for _, conn := range got {
						unique[conn.Key] = true
					}
					if len(got) != want || len(unique) != want {
						t.Fatalf("%s: asked for %d copies, got %d (%d resolvers)", call.what, want, len(got), len(unique))
					}
				}
			}
		})
	}
}

// The copies beyond the pool go to the resolvers strategy 3 would pick:
// lossless before lossy, and of equal loss the faster.
func TestCopiesBeyondThePoolGoToTheLeastLossyResolvers(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy:       BalancingLossThenLatency,
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "fast", "lossy", "clean-near", "clean-far")
	feed(t, c, "fast", "192.0.2.1", 40*time.Millisecond, 20, 0)
	feed(t, c, "lossy", "192.0.2.2", 120*time.Millisecond, 10, 10)
	feed(t, c, "clean-near", "192.0.2.3", 120*time.Millisecond, 20, 0)
	feed(t, c, "clean-far", "192.0.2.4", 300*time.Millisecond, 20, 0)

	got, err := c.balancer.SelectTargets(Enums.PACKET_STREAM_SYN, 7, 3)
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	if got[0].Key != "fast" || got[1].Key != "clean-near" || got[2].Key != "clean-far" {
		t.Fatalf("copies went to %s, %s, %s; want fast, then the lossless by round trip", got[0].Key, got[1].Key, got[2].Key)
	}
}

// On a clean network every resolver is at zero loss, and the tier was
// simply the first ones in the list.
func TestTheTopTierPrefersTheFasterOfEqualLoss(t *testing.T) {
	for _, strategy := range []int{BalancingLeastLossTopRandom, BalancingLeastLossTopRoundRobin} {
		c := buildTestClientWithResolvers(config.ClientConfig{
			ResolverBalancingStrategy:       strategy,
			AutoDisableTimeoutServers:       true,
			AutoDisableTimeoutWindowSeconds: 30,
		}, "a", "b", "c", "d")
		// b is not slow enough for the guard (200 ms against 60 ms), only
		// slower than c and d, which are just as clean.
		feed(t, c, "a", "192.0.2.1", 60*time.Millisecond, 20, 0)
		feed(t, c, "b", "192.0.2.2", 200*time.Millisecond, 20, 0)
		feed(t, c, "c", "192.0.2.3", 70*time.Millisecond, 20, 0)
		feed(t, c, "d", "192.0.2.4", 80*time.Millisecond, 20, 0)

		got := picks(t, c, 40)
		if got["b"] != 0 || got["a"] == 0 || got["c"] == 0 {
			t.Fatalf("strategy %d: %v - the tier should be the two fastest of the equally clean", strategy, got)
		}
	}
}
