package client

import (
	"sync"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

// testPool builds a pool of n idle members, all up, without any sockets.
func testPool(t *testing.T, strategy string, sticky bool, weights ...int) *Pool {
	t.Helper()
	cfg := config.ClientConfig{
		ProtocolType:              "SOCKS5",
		LoadBalancerStrategy:      strategy,
		LoadBalancerSticky:        sticky,
		LoadBalancerStickySeconds: 60,
	}
	p := newPool(cfg, nil)
	now := time.Unix(1_700_000_000, 0)
	p.nowFn = func() time.Time { return now }
	for i, w := range weights {
		c := buildTestClientWithResolvers(config.ClientConfig{}, "r")
		c.pool = p
		c.runtimeReady.Store(true)
		p.members = append(p.members, &poolMember{name: string(rune('A' + i)), weight: w, client: c})
	}
	return p
}

func addStreams(c *Client, n int) {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	base := uint16(len(c.active_streams) + 1)
	for i := 0; i < n; i++ {
		c.active_streams[base+uint16(i)] = &Stream_client{}
	}
}

func pickCounts(p *Pool, picks int, host func(int) string) map[string]int {
	counts := map[string]int{}
	for i := 0; i < picks; i++ {
		m := p.pick(host(i))
		if m == nil {
			counts["<nil>"]++
			continue
		}
		counts[m.name]++
	}
	return counts
}

func TestPoolRoundRobinFollowsWeights(t *testing.T) {
	p := testPool(t, config.LoadBalancerRoundRobin, false, 1, 3)
	counts := pickCounts(p, 400, func(int) string { return "" })
	if counts["A"] != 100 || counts["B"] != 300 {
		t.Fatalf("weighted round robin 1:3 gave %v", counts)
	}
}

func TestPoolRandomCoversEveryServer(t *testing.T) {
	p := testPool(t, config.LoadBalancerRandom, false, 1, 1, 1)
	counts := pickCounts(p, 3000, func(int) string { return "" })
	for _, name := range []string{"A", "B", "C"} {
		if counts[name] < 700 {
			t.Fatalf("random strategy starved %s: %v", name, counts)
		}
	}
}

func TestPoolLeastLoadPicksEmptiestServerForItsWeight(t *testing.T) {
	p := testPool(t, config.LoadBalancerLeastLoad, false, 1, 1, 2)
	addStreams(p.members[0].client, 5)
	addStreams(p.members[1].client, 1)
	addStreams(p.members[2].client, 3) // 3 streams on weight 2 = 1.5 each

	if m := p.pick(""); m.name != "B" {
		t.Fatalf("least load picked %s, want B", m.name)
	}
	addStreams(p.members[1].client, 3) // B: 4
	if m := p.pick(""); m.name != "C" {
		t.Fatalf("least load picked %s, want C (1.5 per weight)", m.name)
	}
}

func TestPoolLeastLoadRotatesBetweenEquallyIdleServers(t *testing.T) {
	p := testPool(t, config.LoadBalancerLeastLoad, false, 1, 1, 1)
	counts := pickCounts(p, 300, func(int) string { return "" })
	if counts["A"] != 100 || counts["B"] != 100 || counts["C"] != 100 {
		t.Fatalf("idle servers did not take turns: %v", counts)
	}
}

func TestPoolFailoverUsesFirstServerThatIsUp(t *testing.T) {
	p := testPool(t, config.LoadBalancerFailover, false, 1, 1, 1)
	if m := p.pick(""); m.name != "A" {
		t.Fatalf("failover picked %s, want A", m.name)
	}
	p.members[0].client.runtimeReady.Store(false)
	if m := p.pick(""); m.name != "B" {
		t.Fatalf("failover picked %s with A down, want B", m.name)
	}
}

func TestPoolSkipsServersWithoutSession(t *testing.T) {
	p := testPool(t, config.LoadBalancerRoundRobin, false, 1, 1, 1)
	p.members[1].client.runtimeReady.Store(false)
	counts := pickCounts(p, 100, func(int) string { return "" })
	if counts["B"] != 0 || counts["A"]+counts["C"] != 100 {
		t.Fatalf("a server without a session got connections: %v", counts)
	}

	for _, m := range p.members {
		m.client.runtimeReady.Store(false)
	}
	if m := p.pick("example.com"); m != nil {
		t.Fatalf("picked %s with every server down", m.name)
	}
}

func TestPoolAvoidsUnansweringServerUnlessAllAre(t *testing.T) {
	p := testPool(t, config.LoadBalancerRoundRobin, false, 1, 1)
	now := p.nowFn()
	p.members[0].client.awaitingReplySince.Store(now.Add(-time.Minute).UnixNano())

	counts := pickCounts(p, 10, func(int) string { return "" })
	if counts["B"] != 10 {
		t.Fatalf("a server silent for a minute still got connections: %v", counts)
	}

	// A short wait is an ordinary round trip, not a dead server.
	p.members[0].client.awaitingReplySince.Store(now.Add(-time.Second).UnixNano())
	counts = pickCounts(p, 10, func(int) string { return "" })
	if counts["A"] != 5 {
		t.Fatalf("a server one second into a round trip was avoided: %v", counts)
	}

	// Everything silent: degrade to slow, not to refused.
	for _, m := range p.members {
		m.client.awaitingReplySince.Store(now.Add(-time.Minute).UnixNano())
	}
	if m := p.pick(""); m == nil {
		t.Fatal("no server picked when all are slow")
	}
}

func TestPoolStickyKeepsADestinationOnOneServer(t *testing.T) {
	p := testPool(t, config.LoadBalancerRoundRobin, true, 1, 1, 1)
	first := p.pick("Example.COM.")
	for i := 0; i < 20; i++ {
		if m := p.memberForTarget("example.com"); m != first.client {
			t.Fatalf("sticky destination moved to another server on pick %d", i)
		}
	}

	// Different destinations still spread out.
	counts := pickCounts(p, 30, func(i int) string { return string(rune('a'+i%26)) + ".test" })
	if len(counts) < 3 {
		t.Fatalf("sticky mode put every destination on one server: %v", counts)
	}

	// Its server goes down: the destination moves, and stays where it moved.
	first.client.runtimeReady.Store(false)
	moved := p.pick("example.com")
	if moved == nil || moved == first {
		t.Fatalf("destination did not leave its downed server")
	}
	first.client.runtimeReady.Store(true)
	if m := p.pick("example.com"); m != moved {
		t.Fatalf("destination bounced back to %s instead of staying on %s", m.name, moved.name)
	}
}

func TestPoolStickyEntryExpires(t *testing.T) {
	p := testPool(t, config.LoadBalancerRoundRobin, true, 1, 1)
	now := time.Unix(1_700_000_000, 0)
	p.nowFn = func() time.Time { return now }

	first := p.pick("example.com")
	now = now.Add(2 * time.Minute) // sticky TTL is 60 s
	second := p.pick("example.com")
	if second == first {
		t.Fatalf("expired affinity still held: round robin should have moved on")
	}
}

func TestPoolAffinityMapIsBounded(t *testing.T) {
	p := testPool(t, config.LoadBalancerLeastLoad, true, 1, 1)
	for i := 0; i < poolAffinityMaxEntries*2; i++ {
		p.pick("host-" + itoaSafe(i) + ".test")
	}
	p.affinityMu.Lock()
	n := len(p.affinity)
	p.affinityMu.Unlock()
	if n > poolAffinityMaxEntries {
		t.Fatalf("affinity map grew to %d entries", n)
	}
}

func TestPoolPickIsSafeConcurrently(t *testing.T) {
	p := testPool(t, config.LoadBalancerLeastLoad, true, 1, 2, 1)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if m := p.pick("h" + itoaSafe(i%50)); m == nil {
					t.Error("nil pick")
					return
				}
				if i%100 == 0 {
					// The third server stays up throughout.
					p.members[g%2].client.runtimeReady.Store(i%200 == 0)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestPoolReportsAllServersFailingOnlyWhenEveryOneFailed(t *testing.T) {
	p := testPool(t, config.LoadBalancerLeastLoad, false, 1, 1)
	marks := make([]uint64, 2)

	p.members[0].client.sessionInitFailures.Add(3)
	p.reportAllServersFailing(marks)
	if marks[0] != 0 {
		t.Fatal("reported a pool failure while one server had not failed yet")
	}

	p.members[1].client.sessionInitFailures.Add(1)
	p.reportAllServersFailing(marks)
	if marks[0] != 3 || marks[1] != 1 {
		t.Fatalf("all servers failed but marks are %v", marks)
	}

	// The next report needs a fresh failure from every server again.
	p.members[0].client.sessionInitFailures.Add(1)
	p.reportAllServersFailing(marks)
	if marks[0] != 3 {
		t.Fatal("reported again after only one server failed")
	}
}
