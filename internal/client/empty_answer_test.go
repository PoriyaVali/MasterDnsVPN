package client

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
)

// A server in a session always answers with a TXT record: queued data or a
// PONG. A NOERROR answer without one is a resolver that stripped, filtered or
// truncated it - a path that carries nothing. It was credited as a success,
// with the short round trip of an answer the resolver never had to fetch, so
// the least-loss strategies (the ones the app uses) ranked it above a
// resolver that really carries the tunnel and loses the odd query: all data
// went to the path that delivers none.
func TestEmptyAnswersDoNotWinTheBalancer(t *testing.T) {
	for _, strategy := range []int{BalancingLeastLoss, BalancingLossThenLatency, BalancingLeastLossTopRoundRobin} {
		c := buildTestClientWithResolvers(config.ClientConfig{
			ResolverBalancingStrategy:       strategy,
			AutoDisableTimeoutServers:       true,
			AutoDisableTimeoutWindowSeconds: 30,
		}, "empty", "carrier", "carrier2")
		emptyAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
		carriers := []struct {
			key  string
			addr *net.UDPAddr
		}{
			{"carrier", &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 53}},
			{"carrier2", &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 53}},
		}
		start := time.Now().Add(-time.Minute)
		const timeout = 2 * time.Second

		send := func(addr *net.UDPAddr, key string, id uint16, at time.Time) []byte {
			query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
			if err != nil {
				t.Fatalf("BuildTXTQuestionPacket: %v", err)
			}
			binary.BigEndian.PutUint16(query[:2], id)
			c.balancer.TrackResolverSend(query, addr.String(), "", key, at, timeout)
			return query
		}

		for i := 0; i < 20; i++ {
			at := start.Add(time.Duration(i) * 100 * time.Millisecond)

			// "empty" answers at once, with nothing in it.
			query := send(emptyAddr, "empty", uint16(1000+i), at)
			response, err := DnsParser.BuildEmptyNoErrorResponse(query)
			if err != nil {
				t.Fatalf("BuildEmptyNoErrorResponse: %v", err)
			}
			c.handleInboundPacket(response, emptyAddr, "")

			// The carriers answer with tunnel data in 80 ms, and each loses two
			// of twenty queries - ordinary working paths.
			for n, carrier := range carriers {
				query = send(carrier.addr, carrier.key, uint16(2000+100*n+i), at)
				if i%10 == 3+n {
					continue
				}
				c.balancer.TrackResolverSuccess(query, carrier.addr, "", at.Add(80*time.Millisecond), 0)
			}
		}
		// The carriers' unanswered queries time out.
		c.balancer.CollectExpiredResolverTimeouts(time.Now().Add(time.Minute), timeout)

		// Strategy 8 rotates over its best tier, two paths here: they must be
		// the two that carry the tunnel.
		for pick := 0; pick < 30; pick++ {
			best, ok := c.balancer.GetBestConnection()
			if !ok {
				t.Fatalf("strategy %d: no connection", strategy)
			}
			if best.Key == "empty" {
				t.Fatalf("strategy %d: picked the path that answers with nothing", strategy)
			}
		}
	}
}

// The empty answer still clears the query, so it does not later count as a
// second, timed-out failure.
func TestEmptyAnswerIsOneFailure(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 10,
	}, "a", "b", "c", "d")
	addr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}

	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	response, err := DnsParser.BuildEmptyNoErrorResponse(query)
	if err != nil {
		t.Fatalf("BuildEmptyNoErrorResponse returned error: %v", err)
	}

	dnsID := binary.BigEndian.Uint16(response[:2])
	c.balancer.pendingStoreForTest(balancerResolverSampleKey{
		resolverAddr: addr.String(),
		dnsID:        dnsID,
	}, balancerResolverSample{
		serverKey: "a",
		sentAt:    time.Now().Add(-200 * time.Millisecond),
	})

	c.handleInboundPacket(response, addr, "")

	if got := c.balancer.pendingCount(); got != 0 {
		t.Fatalf("the empty answer must clear its query, pending=%d", got)
	}
	stats := c.balancer.statsForKey("a")
	if stats == nil {
		t.Fatal("expected stats for resolver a")
	}
	if got := stats.acked.Load(); got != 0 {
		t.Fatalf("an empty answer was counted as a success (acked=%d)", got)
	}
	if got := stats.windowLost.Load(); got != 1 {
		t.Fatalf("an empty answer must count as one failure, windowLost=%d", got)
	}
	c.balancer.CollectExpiredResolverTimeouts(time.Now().Add(time.Minute), time.Second)
	if got := stats.windowLost.Load(); got != 1 {
		t.Fatalf("the query was counted again when it expired, windowLost=%d", got)
	}
}
