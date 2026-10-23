package client

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestBalancerFollowsResolverLatencyChanges(t *testing.T) {
	for _, strategy := range []int{BalancingLowestLatency, BalancingHybridScore, BalancingLossThenLatency} {
		t.Run(fmt.Sprint(strategy), func(t *testing.T) {
			b := NewBalancer(strategy, nil)
			b.SetConnections([]*Connection{{Key: "a", IsValid: true}, {Key: "b", IsValid: true}})
			b.SetConnectionValidity("a", true)
			b.SetConnectionValidity("b", true)
			report := func(a, other time.Duration, n int) {
				for i := 0; i < n; i++ {
					b.ReportSend("a")
					b.ReportSuccess("a", a)
					b.ReportSend("b")
					b.ReportSuccess("b", other)
				}
			}
			assertBest := func(want string) {
				t.Helper()
				for i := 0; i < 10; i++ {
					got, ok := b.GetBestConnection()
					if !ok || got.Key != want {
						t.Fatalf("resolver = %q, want %q after path change", got.Key, want)
					}
				}
			}
			report(10*time.Millisecond, 100*time.Millisecond, 800)
			assertBest("a")
			// Both paths change after a long steady period: historical samples
			// must not pin traffic to the resolver that has become slower.
			report(200*time.Millisecond, 20*time.Millisecond, 32)
			assertBest("b")
			report(10*time.Millisecond, 100*time.Millisecond, 32)
			assertBest("a")
		})
	}
}

func TestBalancerLatencyIgnoresSingleOutlier(t *testing.T) {
	b := NewBalancer(BalancingLowestLatency, nil)
	b.SetConnections([]*Connection{{Key: "a", IsValid: true}, {Key: "b", IsValid: true}})
	b.SetConnectionValidity("a", true)
	b.SetConnectionValidity("b", true)
	for i := 0; i < 20; i++ {
		b.ReportSuccess("a", 10*time.Millisecond)
		b.ReportSuccess("b", 100*time.Millisecond)
	}
	b.ReportSuccess("a", 400*time.Millisecond)
	got, ok := b.GetBestConnection()
	if !ok || got.Key != "a" {
		t.Fatalf("one delayed response displaced the faster resolver: %q", got.Key)
	}
}

// A resolver that passed its recheck (recheckInactiveResolver) is seeded
// afresh: the latency it had while failing must not outweigh its new samples.
func TestBalancerReenabledResolverIsMeasuredAfresh(t *testing.T) {
	for _, strategy := range []int{BalancingLowestLatency, BalancingHybridScore, BalancingLossThenLatency} {
		t.Run(fmt.Sprint(strategy), func(t *testing.T) {
			b := NewBalancer(strategy, nil)
			b.SetConnections([]*Connection{{Key: "a", IsValid: true}, {Key: "b", IsValid: true}})
			b.SetConnectionValidity("a", true)
			b.SetConnectionValidity("b", true)
			report := func(a, other time.Duration, n int) {
				for i := 0; i < n; i++ {
					b.ReportSend("a")
					b.ReportSuccess("a", a)
					b.ReportSend("b")
					b.ReportSuccess("b", other)
				}
			}
			report(2*time.Second, 300*time.Millisecond, 50)
			b.SetConnectionValidity("a", false)
			b.SetConnectionValidity("a", true)
			b.SeedConservativeStats("a")
			report(20*time.Millisecond, 300*time.Millisecond, 8)
			got, ok := b.GetBestConnection()
			if !ok || got.Key != "a" {
				t.Fatalf("re-enabled 20 ms resolver lost to a 300 ms one: chose %q", got.Key)
			}
		})
	}
}

func TestBalancerResetServerStatsForgetsLatency(t *testing.T) {
	b := NewBalancer(BalancingLowestLatency, nil)
	b.SetConnections([]*Connection{{Key: "a"}})
	b.SetConnectionValidity("a", true)
	for i := 0; i < 20; i++ {
		b.ReportSuccess("a", 2*time.Second)
	}
	b.ResetServerStats("a")
	for i := 0; i < 5; i++ {
		b.ReportSuccess("a", 20*time.Millisecond)
	}
	b.mu.RLock()
	score := b.latencyScoreLocked(0)
	b.mu.RUnlock()
	if score != 20_000 {
		t.Fatalf("latency after a reset = %d us, want the 20000 us measured since", score)
	}
}

func BenchmarkBalancerLossThenLatency(b *testing.B) {
	for _, size := range []int{4, 32, 128} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			bal := NewBalancer(BalancingLossThenLatency, nil)
			conns := make([]*Connection, size)
			for i := range conns {
				conns[i] = &Connection{Key: fmt.Sprint(i), IsValid: true}
			}
			bal.SetConnections(conns)
			for _, conn := range conns {
				bal.SetConnectionValidity(conn.Key, true)
				for i := 0; i < 8; i++ {
					bal.ReportSend(conn.Key)
					bal.ReportSuccess(conn.Key, 10*time.Millisecond)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				bal.GetBestConnection()
			}
		})
	}
}

func TestBalancerConcurrentLatencyReports(t *testing.T) {
	b := NewBalancer(BalancingLowestLatency, nil)
	b.SetConnections([]*Connection{{Key: "a"}})
	b.SetConnectionValidity("a", true)
	var wg sync.WaitGroup
	for worker := 1; worker <= 4; worker++ {
		wg.Add(1)
		go func(delay time.Duration) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				b.ReportSend("a")
				b.ReportSuccess("a", delay)
				if _, ok := b.GetBestConnection(); !ok {
					t.Error("active resolver disappeared during concurrent reporting")
					return
				}
			}
		}(time.Duration(worker) * 10 * time.Millisecond)
	}
	wg.Wait()
	b.mu.RLock()
	score := b.latencyScoreLocked(0)
	b.mu.RUnlock()
	if score < 10_000 || score > 40_000 {
		t.Fatalf("latency estimate outside observed RTT range: %d us", score)
	}
}

func TestBalancerLossThenLatencyLargePool(t *testing.T) {
	for _, size := range []int{64, 65, 128} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			b := NewBalancer(BalancingLossThenLatency, nil)
			conns := make([]*Connection, size)
			for i := range conns {
				conns[i] = &Connection{Key: fmt.Sprint(i)}
			}
			b.SetConnections(conns)
			for i, conn := range conns {
				b.SetConnectionValidity(conn.Key, true)
				rtt := 100 * time.Millisecond
				if i == size-1 {
					rtt = time.Millisecond
				}
				for sample := 0; sample < 8; sample++ {
					b.ReportSend(conn.Key)
					b.ReportSuccess(conn.Key, rtt)
				}
			}
			winner := conns[size-1].Key
			got, ok := b.GetBestConnection()
			if !ok || got.Key != winner {
				t.Fatalf("large pool chose %q, want %q", got.Key, winner)
			}
			b.SetConnectionValidity(winner, false)
			got, ok = b.GetBestConnection()
			if !ok || got.Key == winner {
				t.Fatalf("large pool retained disabled resolver %q", got.Key)
			}
		})
	}
}
