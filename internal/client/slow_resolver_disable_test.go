package client

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func slowTestPacket(id uint16) []byte {
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p, id)
	return p
}

// A 50 ms resolver comes under load - as resolvers do on a national network
// that is throttling - and answers every query 2.5 s late. Its queries are
// counted lost at its own loss timeout, so the balancer moves off it; but
// none has gone unanswered for the request timeout (5 s here), and it must
// not be disabled for answers that are only late.
func TestAResolverThatTurnsSlowIsNotDisabledForLateAnswers(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d", "e")
	c.balancer.SetResolverDownConfirmHandler(func(*Connection, time.Duration) bool { return true })
	const tunnelTimeout = 10 * time.Second
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	stats := c.balancer.statsForKey("a")
	for i := 0; i < 20; i++ {
		stats.observeRTT(50 * time.Millisecond)
	}

	start := time.Now()
	sentAt := func(i int) time.Time { return start.Add(time.Duration(i) * 10 * time.Millisecond) }
	// Two hundred queries in two seconds - well over the window's 96.
	for i := 0; i < 200; i++ {
		c.balancer.TrackResolverSend(slowTestPacket(uint16(i)), addr.String(), "", "a", sentAt(i), tunnelTimeout)
	}
	for at := start; !at.After(start.Add(3 * time.Second)); at = at.Add(250 * time.Millisecond) {
		c.balancer.CollectExpiredResolverTimeouts(at, tunnelTimeout)
	}
	if got := stats.lost.Load(); got < 150 {
		t.Fatalf("only %d queries counted lost three seconds in; the balancer would stay on a resolver this slow", got)
	}
	if got := c.balancer.ActiveCount(); got != 5 {
		t.Fatalf("%d active: a resolver was disabled while every answer was still coming, 2.5 s late", got)
	}

	for i := 0; i < 200; i++ {
		c.balancer.TrackResolverSuccess(slowTestPacket(uint16(i)), addr, "", sentAt(i).Add(2500*time.Millisecond), 0)
	}
	if got := stats.lost.Load(); got != 0 {
		t.Fatalf("the late answers left %d losses counted", got)
	}
	for at := start.Add(3 * time.Second); !at.After(start.Add(8 * time.Second)); at = at.Add(250 * time.Millisecond) {
		c.balancer.CollectExpiredResolverTimeouts(at, tunnelTimeout)
	}
	if got := c.balancer.ActiveCount(); got != 5 {
		t.Fatalf("%d active after every answer came", got)
	}
}

// A resolver that has really gone silent is still disabled, once its queries
// are unanswered past the request timeout.
func TestASilentResolverIsStillDisabledPastTheRequestTimeout(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d", "e")
	c.balancer.SetResolverDownConfirmHandler(func(*Connection, time.Duration) bool { return true })
	const tunnelTimeout = 10 * time.Second
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	stats := c.balancer.statsForKey("a")
	for i := 0; i < 20; i++ {
		stats.observeRTT(50 * time.Millisecond)
	}
	start := time.Now()
	for i := 0; i < 200; i++ {
		c.balancer.TrackResolverSend(slowTestPacket(uint16(i)), addr.String(), "", "a", start.Add(time.Duration(i)*10*time.Millisecond), tunnelTimeout)
	}
	for at := start; !at.After(start.Add(8 * time.Second)); at = at.Add(250 * time.Millisecond) {
		c.balancer.CollectExpiredResolverTimeouts(at, tunnelTimeout)
	}
	if got := c.balancer.ActiveCount(); got != 4 {
		t.Fatalf("%d active: a resolver that answered nothing for eight seconds is still in use", got)
	}
}

// A SERVFAIL for a query already counted lost still counts toward disabling.
func TestAFailureAfterTheLossTimeoutStillReachesTheWindow(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, "a", "b", "c", "d", "e")
	const tunnelTimeout = 10 * time.Second
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	stats := c.balancer.statsForKey("a")
	for i := 0; i < 20; i++ {
		stats.observeRTT(50 * time.Millisecond)
	}
	start := time.Now()
	c.balancer.TrackResolverSend(slowTestPacket(1), addr.String(), "", "a", start, tunnelTimeout)
	c.balancer.CollectExpiredResolverTimeouts(start.Add(time.Second), tunnelTimeout)
	if got := stats.lost.Load(); got != 1 {
		t.Fatalf("lost=%d after the loss timeout", got)
	}
	c.balancer.TrackResolverFailure(slowTestPacket(1), addr, "", start.Add(1500*time.Millisecond))
	if got := stats.lost.Load(); got != 1 {
		t.Fatalf("lost=%d: the failure was counted as a second loss", got)
	}
	if got := stats.windowLost.Load(); got != 1 {
		t.Fatalf("windowLost=%d: the failure never reached the auto-disable window", got)
	}
}

func longListClient(t *testing.T) *Client {
	t.Helper()
	keys := make([]string, 100)
	for i := range keys {
		keys[i] = fmt.Sprintf("r%02d", i)
	}
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 30,
	}, keys...)
	c.balancer.SetResolverDownConfirmHandler(func(*Connection, time.Duration) bool { return true })
	for i := 0; i < 20; i++ {
		c.balancer.statsForKey("r00").observeRTT(300 * time.Millisecond)
	}
	return c
}

// With a long resolver list the request timeout is 1 s. A resolver under
// load answers a burst of twenty queries 2.5 s late each: before the first
// answer came, all twenty had gone unanswered for a second, and it was
// disabled while it answered every one.
func TestALongListKeepsAResolverThatAnswersInSeconds(t *testing.T) {
	c := longListClient(t)
	const tunnelTimeout = 10 * time.Second
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	start := time.Now()
	sentAt := func(i int) time.Time { return start.Add(time.Duration(i) * 50 * time.Millisecond) }
	for i := 0; i < 20; i++ {
		c.balancer.TrackResolverSend(slowTestPacket(uint16(i)), addr.String(), "", "r00", sentAt(i), tunnelTimeout)
	}
	answered := 0
	for at := start; !at.After(start.Add(8 * time.Second)); at = at.Add(100 * time.Millisecond) {
		for answered < 20 && !sentAt(answered).Add(2500*time.Millisecond).After(at) {
			c.balancer.TrackResolverSuccess(slowTestPacket(uint16(answered)), addr, "", sentAt(answered).Add(2500*time.Millisecond), 0)
			answered++
		}
		c.balancer.CollectExpiredResolverTimeouts(at, tunnelTimeout)
	}
	if got := c.balancer.ActiveCount(); got != 100 {
		t.Fatalf("%d active: a resolver answering every query in 2.5 s was disabled", got)
	}
}

// A resolver in the same long list that answers nothing is still disabled.
func TestALongListStillDisablesADeadResolver(t *testing.T) {
	c := longListClient(t)
	const tunnelTimeout = 10 * time.Second
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	start := time.Now()
	for i := 0; i < 20; i++ {
		c.balancer.TrackResolverSend(slowTestPacket(uint16(i)), addr.String(), "", "r00", start.Add(time.Duration(i)*50*time.Millisecond), tunnelTimeout)
	}
	for at := start; !at.After(start.Add(8 * time.Second)); at = at.Add(100 * time.Millisecond) {
		c.balancer.CollectExpiredResolverTimeouts(at, tunnelTimeout)
	}
	if got := c.balancer.ActiveCount(); got != 99 {
		t.Fatalf("%d active: a resolver that answered nothing for eight seconds is still in use", got)
	}
}
