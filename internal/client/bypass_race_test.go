package client

import (
	"net"
	"testing"
	"time"
)

// A resolver that answers, and one that swallows the query, so a race can be
// measured rather than argued about.
func startEchoResolver(t *testing.T, reply []byte, delay time.Duration) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if reply == nil {
				continue // a black hole: reachable, never answers
			}
			if delay > 0 {
				time.Sleep(delay)
			}
			_ = n
			_, _ = pc.WriteTo(reply, addr)
		}
	}()
	return pc.LocalAddr().String()
}

// 🔑 The scenario the whole feature exists for: the foreign internet is gone,
// most domestic resolvers are down, one still answers. Asked in turn, each dead
// one costs its full timeout first - so this must finish in about the time of
// the one good answer, not the sum of the failures.
func TestBypassRaceSurvivesMostlyDeadResolvers(t *testing.T) {
	reply := []byte{0x42, 0x42, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}

	var servers []string
	for i := 0; i < 6; i++ {
		servers = append(servers, startEchoResolver(t, nil, 0)) // never answers
	}
	good := startEchoResolver(t, reply, 20*time.Millisecond)
	servers = append(servers, good)

	c := &Client{}
	c.cfg.BypassDNSServers = servers

	start := time.Now()
	got := c.resolveBypassDirect([]byte{0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0})
	elapsed := time.Since(start)

	if got == nil {
		t.Fatal("the one working resolver was not used")
	}
	// Serial would be six timeouts before reaching it. The bound is deliberately
	// loose - the point is "nowhere near the sum of the failures", not a
	// stopwatch.
	if elapsed > bypassDNSTimeout {
		t.Fatalf("took %v, which means the dead resolvers were waited on in turn", elapsed)
	}
}

func TestBypassRaceReturnsNilWhenAllDead(t *testing.T) {
	// All silent: the caller must be told to fall back to the tunnel rather
	// than being handed a wrong answer or hanging past the deadline.
	var servers []string
	for i := 0; i < 3; i++ {
		servers = append(servers, startEchoResolver(t, nil, 0))
	}
	c := &Client{}
	c.cfg.BypassDNSServers = servers

	start := time.Now()
	if got := c.resolveBypassDirect([]byte{0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}); got != nil {
		t.Fatal("expected nil so the caller falls back to the tunnel")
	}
	if elapsed := time.Since(start); elapsed > bypassDNSTimeout+time.Second {
		t.Fatalf("overshot the deadline: %v", elapsed)
	}
}

func TestBypassNoServersConfiguredIsNotAnError(t *testing.T) {
	// An empty list means the feature is off, not that lookups should fail.
	c := &Client{}
	if got := c.resolveBypassDirect([]byte{0x42}); got != nil {
		t.Fatal("expected nil with no resolvers configured")
	}
}
