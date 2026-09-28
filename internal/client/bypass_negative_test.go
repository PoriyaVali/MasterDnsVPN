package client

import (
	"sync"
	"testing"
	"time"

	dnsCache "masterdnsvpn-go/internal/dnscache"
)

// withAuthority marks a header as carrying one authority record (the SOA an
// honest resolver attaches to a negative answer).
func withAuthority(b []byte) []byte {
	b[9] = 1
	return b
}

// An honest "no such record" - NODATA or NXDOMAIN with the zone's SOA - is an
// answer. AAAA and HTTPS lookups for IPv4-only sites get exactly this, and
// rejecting it sent every one of them on to the tunnel.
func TestUsableDNSReplyAcceptsHonestNegativeAnswers(t *testing.T) {
	q := hdr(0x4242, false, 0, 0)
	if !usableDNSReply(withAuthority(hdr(0x4242, true, 0, 0)), q) {
		t.Fatal("NODATA with an SOA must be accepted")
	}
	if !usableDNSReply(withAuthority(hdr(0x4242, true, 3, 0)), q) {
		t.Fatal("NXDOMAIN with an SOA must be accepted")
	}
	if usableDNSReply(withAuthority(hdr(0x4242, true, 2, 0)), q) {
		t.Fatal("SERVFAIL is never an answer, SOA or not")
	}
}

// A resolver answers once. When every resolver has answered and none of the
// answers is usable, the race is over - it must not sit out the deadline.
func TestBypassRaceEndsWhenEveryResolverHasAnswered(t *testing.T) {
	bare := hdr(0x4242, true, 0, 0) // NOERROR, empty, no SOA: not usable
	var servers []string
	for i := 0; i < 3; i++ {
		servers = append(servers, startEchoResolver(t, bare, 0))
	}
	c := &Client{}
	c.cfg.BypassDNSServers = servers

	start := time.Now()
	got := c.resolveBypassDirect(hdr(0x4242, false, 0, 0))
	elapsed := time.Since(start)
	if got != nil {
		t.Fatal("an unusable answer was returned")
	}
	if elapsed > bypassDNSTimeout/2 {
		t.Fatalf("took %v: every resolver had answered, yet the race waited for the deadline", elapsed)
	}
}

func TestBypassRaceReturnsAnHonestNegativeAnswer(t *testing.T) {
	nodata := withAuthority(hdr(0x4242, true, 0, 0))
	c := &Client{}
	c.cfg.BypassDNSServers = []string{startEchoResolver(t, nodata, 0)}
	start := time.Now()
	if got := c.resolveBypassDirect(hdr(0x4242, false, 0, 0)); got == nil {
		t.Fatal("an honest NODATA was thrown away")
	}
	if time.Since(start) > bypassDNSTimeout/2 {
		t.Fatal("an honest NODATA took the whole deadline")
	}
}

// 🔴 When the bypass fails and the name goes to the tunnel instead, the caller
// must be parked on the answer - otherwise the tunnel's reply is stored and
// given to nobody, and the app hears silence until it retries.
func TestBypassFallbackParksTheCallerOnTheTunnelAnswer(t *testing.T) {
	servfail := hdr(0x4242, true, 2, 0)
	c := &Client{
		bypass:        NewBypassMatcher(),
		localDNSCache: dnsCache.New(64, time.Minute, time.Minute),
	}
	c.bypass.Load([]string{"example.com"})
	c.cfg.BypassDNSServers = []string{startEchoResolver(t, servfail, 0)}
	c.sessionReady = true

	var mu sync.Mutex
	var answered [][]byte
	// Same transaction ID the fake resolver answers with, so its SERVFAIL is
	// read as this query's answer rather than as a stray datagram.
	query := dnsMessage(0x4242, false)
	c.ProcessDNSQuery(query, nil, func(resp []byte) {
		mu.Lock()
		answered = append(answered, resp)
		mu.Unlock()
	})

	key := dnsCache.BuildKey("example.com", 1, 1)
	// Well inside the bypass deadline: every resolver has already answered.
	deadline := time.Now().Add(bypassDNSTimeout / 2)
	for {
		c.dnsWaitersMu.Lock()
		parked := len(c.dnsWaiters[key])
		c.dnsWaitersMu.Unlock()
		if parked > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fallback sent the name to the tunnel without parking the caller")
		}
		time.Sleep(10 * time.Millisecond)
	}

	c.deliverDNSAnswer(key, dnsMessage(0x0001, true))
	mu.Lock()
	defer mu.Unlock()
	if len(answered) != 1 {
		t.Fatalf("caller got %d answers, want 1", len(answered))
	}
	if answered[0][0] != 0x42 || answered[0][1] != 0x42 {
		t.Fatal("the answer was not patched to the caller's transaction ID")
	}
}
