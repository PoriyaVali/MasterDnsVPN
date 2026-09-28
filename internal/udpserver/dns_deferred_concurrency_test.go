package udpserver

import (
	"context"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// One slow tunnelled lookup must not hold up the next one - not another
// user's, and not the same user's. Built exactly as New builds the DNS pool.
func TestDeferredDNS_SlowLookupDoesNotBlockOthers(t *testing.T) {
	dnsWorkers, _, dnsQueue, _ := splitDeferredSessionPools(16, 4096)
	p := newDeferredSessionProcessor(dnsWorkers, dnsQueue, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	release := make(chan struct{})
	defer close(release)
	fastDone := make(chan struct{})

	slow := VpnProto.Packet{SessionID: 3, PacketType: Enums.PACKET_DNS_QUERY_REQ, SequenceNum: 10}
	fastSameUser := VpnProto.Packet{SessionID: 3, PacketType: Enums.PACKET_DNS_QUERY_REQ, SequenceNum: 11}
	fastOtherUser := VpnProto.Packet{SessionID: 4, PacketType: Enums.PACKET_DNS_QUERY_REQ, SequenceNum: 1}

	if !p.Enqueue(deferredSessionLaneForPacket(slow), func(context.Context) { <-release }) {
		t.Fatal("slow lookup was not accepted")
	}
	for _, pkt := range []VpnProto.Packet{fastSameUser, fastOtherUser} {
		if !p.Enqueue(deferredSessionLaneForPacket(pkt), func(context.Context) { fastDone <- struct{}{} }) {
			t.Fatalf("lookup %+v was not accepted", pkt)
		}
	}

	for i := 0; i < 2; i++ {
		select {
		case <-fastDone:
		case <-time.After(2 * time.Second):
			t.Fatalf("lookup %d waited behind a slow one", i+1)
		}
	}
}

func TestDeferredDNS_LanesArePerQuery(t *testing.T) {
	a := deferredSessionLaneForPacket(VpnProto.Packet{SessionID: 1, PacketType: Enums.PACKET_DNS_QUERY_REQ, SequenceNum: 5})
	b := deferredSessionLaneForPacket(VpnProto.Packet{SessionID: 1, PacketType: Enums.PACKET_DNS_QUERY_REQ, SequenceNum: 6})
	if a == b {
		t.Fatal("two lookups from one session share a lane")
	}
	// Connect work keeps its per-stream ordering.
	c := deferredSessionLaneForPacket(VpnProto.Packet{SessionID: 1, PacketType: Enums.PACKET_SOCKS5_SYN, StreamID: 9, SequenceNum: 1})
	d := deferredSessionLaneForPacket(VpnProto.Packet{SessionID: 1, PacketType: Enums.PACKET_SOCKS5_SYN, StreamID: 9, SequenceNum: 2})
	if c != d {
		t.Fatal("one stream's connect packets were split across lanes")
	}
}
