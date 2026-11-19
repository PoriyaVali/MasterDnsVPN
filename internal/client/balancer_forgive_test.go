package client

import (
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func TestOldLossesFadeOnceAResolverAnswersCleanlyAgain(t *testing.T) {
	var s connectionStats
	s.sent.Store(300)
	s.lost.Store(30)
	lossAt := time.Now()
	s.lastLossAt.Store(lossAt.UnixNano())

	s.forgiveOldLosses(lossAt.Add(5 * time.Second))
	if got := s.lost.Load(); got != 30 {
		t.Fatalf("faded 5 s after a loss already: %d", got)
	}

	at := lossAt.Add(lossForgiveAfter)
	for i := 0; i < 6; i++ {
		s.forgiveOldLosses(at)
		at = at.Add(lossForgiveEvery)
	}
	if got := s.lost.Load(); got != 0 {
		t.Fatalf("six clean answers a second apart after the quiet period left %d losses", got)
	}

	s.lost.Store(40)
	s.forgiveOldLosses(at)
	s.forgiveOldLosses(at.Add(time.Millisecond))
	if got := s.lost.Load(); got != 20 {
		t.Fatalf("two answers a millisecond apart: %d losses, want one halving to 20", got)
	}
}

func TestAResolverStillLosingKeepsItsLosses(t *testing.T) {
	var s connectionStats
	s.sent.Store(300)
	s.lost.Store(30)
	at := time.Now()
	for i := 0; i < 20; i++ {
		// A loss every 10 s, clean answers in between.
		s.lastLossAt.Store(at.UnixNano())
		s.forgiveOldLosses(at.Add(5 * time.Second))
		s.forgiveOldLosses(at.Add(9 * time.Second))
		at = at.Add(10 * time.Second)
	}
	if got := s.lost.Load(); got != 30 {
		t.Fatalf("a resolver losing a query every 10 s had its losses faded to %d", got)
	}
}

// Strategy 3 sends nothing to a resolver with more loss than the others, so
// a burst of loss used to keep it out for good; polls probe it, and its
// clean answers now win it back.
func TestASidelinedResolverComesBackOnceItsLossesFade(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy:       BalancingLeastLoss,
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d")
	feed(t, c, "a", "192.0.2.1", 60*time.Millisecond, 20, 0)
	feed(t, c, "b", "192.0.2.2", 60*time.Millisecond, 20, 0)
	feed(t, c, "c", "192.0.2.3", 60*time.Millisecond, 20, 0)
	// A burst of loss two minutes ago.
	feed(t, c, "d", "192.0.2.4", 60*time.Millisecond, 10, 10)
	if got := picks(t, c, 40); got["d"] != 0 {
		t.Fatalf("%v - d should be out while its losses count", got)
	}

	stats := c.balancer.statsForKey("d")
	for i := 0; i < 6; i++ {
		// A probe answered, a second or more after the one before.
		stats.lastForgivenAt.Store(time.Now().Add(-lossForgiveEvery).UnixNano())
		c.balancer.ReportSend("d")
		c.balancer.ReportSuccess("d", 60*time.Millisecond)
	}
	if got := picks(t, c, 40); got["d"] == 0 {
		t.Fatalf("%v - d has answered every probe since its loss two minutes ago", got)
	}
}
