package client

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

// AUTO_DISABLE_TIMEOUT_SERVERS decides whether a resolver may be disabled
// for timing out. With it off, no query was ever counted lost - not an
// unanswered one, not a SERVFAIL - and every strategy that balances on loss
// saw all resolvers at zero.
func TestLossesStillCountWithAutoDisableOff(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverBalancingStrategy:       BalancingLeastLoss,
		AutoDisableTimeoutServers:       false,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d")
	feed(t, c, "a", "192.0.2.1", 60*time.Millisecond, 20, 0)
	feed(t, c, "b", "192.0.2.2", 60*time.Millisecond, 20, 0)
	feed(t, c, "c", "192.0.2.3", 60*time.Millisecond, 20, 0)
	// d answers nothing at all.
	feed(t, c, "d", "192.0.2.4", 60*time.Millisecond, 0, 20)

	if got := c.balancer.statsForKey("d").lost.Load(); got != 20 {
		t.Fatalf("d left 20 queries unanswered and has %d counted lost", got)
	}
	if got := picks(t, c, 40); got["d"] != 0 {
		t.Fatalf("%v - the strategy still chose the resolver that answers nothing", got)
	}
	if got := c.balancer.ActiveCount(); got != 4 {
		t.Fatalf("%d active - a resolver was disabled with AUTO_DISABLE_TIMEOUT_SERVERS off", got)
	}

	// A SERVFAIL counts too.
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p, 0x4242)
	c.balancer.TrackResolverSend(p, addr.String(), "", "a", time.Now(), 10*time.Second)
	c.balancer.TrackResolverFailure(p, addr, "", time.Now())
	if got := c.balancer.statsForKey("a").lost.Load(); got != 1 {
		t.Fatalf("a SERVFAIL from a was not counted: lost=%d", got)
	}
}
