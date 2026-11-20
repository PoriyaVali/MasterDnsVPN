package client

import (
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
)

// A data ACK only answers data the server sent, which counted as traffic when
// it came in. Counted again on the way out, the final ACK a half-closed
// stream repeats every couple of seconds held the pings at 100 ms - ten
// queries a second on a tunnel nobody was using.
func TestAnAckGoingOutDoesNotKeepAnIdleTunnelPollingFast(t *testing.T) {
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
	idle := time.Now().Add(-time.Minute).UnixNano()
	p.lastNonPingSentAt.Store(idle)
	p.lastNonPongReceivedAt.Store(idle)

	c.notifySent(Enums.PACKET_STREAM_DATA_ACK, true)
	c.notifySent(Enums.PACKET_PACKED_CONTROL_BLOCKS, true)
	c.notifySent(Enums.PACKET_PING, false)
	if got := p.nextInterval(time.Now().UnixNano()); got != 15*time.Second {
		t.Fatalf("after ACKs and a ping on an idle tunnel the interval is %v, want the cold 15s", got)
	}

	c.notifySent(Enums.PACKET_PACKED_CONTROL_BLOCKS, false) // ACKs packed with a SYN
	if got := p.nextInterval(time.Now().UnixNano()); got != 100*time.Millisecond {
		t.Fatalf("after a real send the interval is %v, want the aggressive 100ms", got)
	}

	p.lastNonPingSentAt.Store(idle)
	c.notifySent(Enums.PACKET_STREAM_DATA, false)
	if got := p.nextInterval(time.Now().UnixNano()); got != 100*time.Millisecond {
		t.Fatalf("after data went out the interval is %v, want the aggressive 100ms", got)
	}
}
