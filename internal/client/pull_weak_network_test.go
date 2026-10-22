package client

import (
	"net"
	"sync"
	"testing"
	"time"
)

var trackerResolver = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5300}

func TestQueryTrackerHardLimitDuringBlackout(t *testing.T) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < queryTrackerMaxEntries+100; i++ {
		q.sent(dnsID(uint16(i)), trackerResolver, "socket-a", now)
	}
	if len(q.pending) > queryTrackerMaxEntries || q.inFlight(now) > queryTrackerMaxEntries {
		t.Fatalf("unbounded tracking during blackout: entries=%d outstanding=%d", len(q.pending), q.inFlight(now))
	}
}

func TestQueryTrackerMatchesResolverAndSocket(t *testing.T) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	other := &net.UDPAddr{IP: trackerResolver.IP, Port: 5301}
	packet := dnsID(42)
	q.sent(packet, trackerResolver, "socket-a", now)
	q.sent(packet, other, "socket-a", now)
	q.sent(packet, trackerResolver, "socket-b", now)
	q.answered(packet, trackerResolver, "socket-a", now.Add(50*time.Millisecond))
	q.answered(packet, trackerResolver, "socket-a", now.Add(60*time.Millisecond)) // duplicate
	q.answered(packet, other, "unknown-socket", now.Add(70*time.Millisecond))
	if got := q.inFlight(now.Add(80 * time.Millisecond)); got != 2 {
		t.Fatalf("duplicate or foreign response consumed another path: %d", got)
	}
	q.answered(packet, other, "socket-a", now.Add(time.Second))
	q.answered(packet, trackerResolver, "socket-b", now.Add(time.Second))
	if got := q.inFlight(now.Add(time.Second)); got != 0 {
		t.Fatalf("matched responses left %d outstanding", got)
	}
}

func TestQueryTrackerKeepsSlowResolverSeparate(t *testing.T) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	slow := &net.UDPAddr{IP: trackerResolver.IP, Port: 5301}
	q.sent(dnsID(1), trackerResolver, "socket", now)
	q.answered(dnsID(1), trackerResolver, "socket", now.Add(20*time.Millisecond))
	q.sent(dnsID(2), slow, "socket", now)
	if got := q.inFlight(now.Add(time.Second)); got != 1 {
		t.Fatalf("fast resolver caused slow query to expire: %d", got)
	}
	q.answered(dnsID(2), slow, "socket", now.Add(1500*time.Millisecond))
	q.sent(dnsID(3), slow, "socket", now.Add(2*time.Second))
	if got := q.inFlight(now.Add(4 * time.Second)); got != 1 {
		t.Fatalf("learned slow path expired prematurely: %d", got)
	}
}

func TestQueryTrackerRetainsQueriesThroughJitter(t *testing.T) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	for i, rtt := range []time.Duration{50 * time.Millisecond, 50 * time.Millisecond, 1200 * time.Millisecond} {
		q.sent(dnsID(uint16(i)), trackerResolver, "socket", now)
		q.answered(dnsID(uint16(i)), trackerResolver, "socket", now.Add(rtt))
		now = now.Add(2 * time.Second)
	}
	q.sent(dnsID(10), trackerResolver, "socket", now)
	if got := q.inFlight(now.Add(1200 * time.Millisecond)); got != 1 {
		t.Fatalf("jitter margin lost a valid slow response: %d", got)
	}
	if got := q.inFlight(now.Add(31 * time.Second)); got != 0 {
		t.Fatalf("lost query was never released: %d", got)
	}
}

func TestQueryTrackerNormalizesIPv4AndRejectsAmbiguousRTT(t *testing.T) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	mapped := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}
	unmapped := &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 5300}
	q.sent(dnsID(1), mapped, "socket", now)
	q.answered(dnsID(1), unmapped, "socket", now.Add(time.Second))
	if got := q.inFlight(now.Add(time.Second)); got != 0 {
		t.Fatalf("IPv4 representation mismatch left %d queries", got)
	}
	before := q.paths[queryResolverEndpoint(mapped)]
	q.sent(dnsID(2), mapped, "socket", now)
	q.sent(dnsID(2), mapped, "socket", now.Add(100*time.Millisecond))
	q.answered(dnsID(2), unmapped, "socket", now.Add(200*time.Millisecond))
	q.answered(dnsID(2), unmapped, "socket", now.Add(300*time.Millisecond))
	if got := q.paths[queryResolverEndpoint(mapped)]; got != before {
		t.Fatalf("ambiguous reply changed timing: %+v -> %+v", before, got)
	}
}

func TestQueryTrackerResetAndDuplicateFloodStayBounded(t *testing.T) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < queryTrackerMaxEntries+100; i++ {
		q.sent(dnsID(1), trackerResolver, "socket", now)
	}
	if got := q.inFlight(now); got > queryTrackerMaxEntries {
		t.Fatalf("duplicate flood bypassed cap: %d", got)
	}
	q.reset()
	if len(q.paths) != 0 || len(q.pending) != 0 || q.inFlight(now) != 0 {
		t.Fatal("session reset retained query state")
	}
	q.sent(dnsID(2), trackerResolver, "socket", now)
	q.answered(dnsID(2), trackerResolver, "socket", now.Add(time.Second))
	if got := q.inFlight(now.Add(time.Second)); got != 0 {
		t.Fatalf("tracker did not recover after reset: %d", got)
	}
}

func TestQueryTrackerConcurrentPaths(t *testing.T) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			addr := &net.UDPAddr{IP: trackerResolver.IP, Port: 5300 + worker}
			for i := 0; i < 1000; i++ {
				packet := dnsID(uint16(i))
				q.sent(packet, addr, "socket", now)
				q.answered(packet, addr, "socket", now.Add(time.Second))
				q.inFlight(now)
			}
		}(worker)
	}
	wg.Wait()
	if got := q.inFlight(now); got != 0 {
		t.Fatalf("concurrent responses left %d queries", got)
	}
}

func BenchmarkQueryTrackerRoundTrip(b *testing.B) {
	q := newQueryTracker()
	packet := dnsID(1)
	now := time.Unix(1_700_000_000, 0)
	replyAt := now.Add(1200 * time.Millisecond)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		q.sent(packet, trackerResolver, "socket", now)
		q.answered(packet, trackerResolver, "socket", replyAt)
	}
}

func BenchmarkQueryTrackerBlackout(b *testing.B) {
	q := newQueryTracker()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < queryTrackerMaxEntries; i++ {
		q.sent(dnsID(uint16(i)), trackerResolver, "socket", now)
	}
	packet := dnsID(65535)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.sent(packet, trackerResolver, "socket", now)
	}
}
