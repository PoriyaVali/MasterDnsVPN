package client

import (
	"encoding/binary"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func dnsID(id uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, id)
	return b
}

func TestQueryTrackerCountsAnswersAndCopies(t *testing.T) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	q.sent(dnsID(1), now)
	q.sent(dnsID(1), now) // the same query to a second resolver
	q.sent(dnsID(2), now)
	if n := q.inFlight(now); n != 3 {
		t.Fatalf("in flight = %d, want 3", n)
	}
	q.answered(dnsID(1), now.Add(100*time.Millisecond))
	if n := q.inFlight(now.Add(100 * time.Millisecond)); n != 2 {
		t.Fatalf("in flight after one answer = %d, want 2", n)
	}
	q.answered(dnsID(99), now) // not ours
	if n := q.inFlight(now.Add(100 * time.Millisecond)); n != 2 {
		t.Fatalf("an unknown answer changed the count to %d", n)
	}
	if q.srtt != 100*time.Millisecond {
		t.Fatalf("srtt = %v", q.srtt)
	}
}

func TestQueryTrackerForgetsLostQueries(t *testing.T) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	q.sent(dnsID(1), now)
	q.answered(dnsID(1), now.Add(100*time.Millisecond)) // srtt 100 ms
	q.sent(dnsID(2), now)
	q.sent(dnsID(3), now)
	// A lost query stops counting a few round trips later, so a lossy path
	// does not look permanently full.
	if n := q.inFlight(now.Add(2 * time.Second)); n != 0 {
		t.Fatalf("lost queries still in flight: %d", n)
	}
}

func TestQueryTrackerNilSafe(t *testing.T) {
	var q *queryTracker
	q.sent(dnsID(1), time.Now())
	q.answered(dnsID(1), time.Now())
	q.reset()
	if q.inFlight(time.Now()) != 0 {
		t.Fatal("nil tracker counted something")
	}
}

func TestPingIntervalKeepsPollingWhileStreamsAreOpen(t *testing.T) {
	cfg := config.ClientConfig{
		PingAggressiveIntervalSeconds: 0.1,
		PingLazyIntervalSeconds:       0.75,
		PingCooldownIntervalSeconds:   2,
		PingColdIntervalSeconds:       15,
		PingWarmThresholdSeconds:      8,
		PingCoolThresholdSeconds:      20,
		PingColdThresholdSeconds:      30,
		PingStreamIdleIntervalSeconds: 3,
		PingStreamIdleWindowSeconds:   120,
	}
	c := buildTestClientWithResolvers(cfg, "a")
	p := c.pingManager
	now := time.Unix(1_700_000_000, 0).UnixNano()
	idleFor := func(d time.Duration) {
		p.lastNonPingSentAt.Store(now - int64(d))
		p.lastNonPongReceivedAt.Store(now - int64(d))
	}

	idleFor(time.Minute)
	if got := p.nextInterval(now); got != 15*time.Second {
		t.Fatalf("idle with no streams: %v, want the cold 15s", got)
	}

	addStreams(c, 1)
	if got := p.nextInterval(now); got != 3*time.Second {
		t.Fatalf("idle with an open connection: %v, want 3s", got)
	}

	idleFor(5 * time.Minute)
	if got := p.nextInterval(now); got != 15*time.Second {
		t.Fatalf("past the window: %v, want the cold 15s", got)
	}

	idleFor(time.Second)
	if got := p.nextInterval(now); got != 100*time.Millisecond {
		t.Fatalf("active: %v, want the aggressive 100ms", got)
	}
}
