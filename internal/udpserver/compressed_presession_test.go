package udpserver

import (
	"encoding/binary"
	"testing"

	"masterdnsvpn-go/internal/compression"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// An MTU probe needs no session, only the node key that every subscriber
// has. One claiming a compressed payload is refused before anything is
// decompressed: an LZ4 header saying 10 MB used to make the node allocate
// 10 MB for a 51-byte query.
func TestCompressedPreSessionFrameIsRefusedUnread(t *testing.T) {
	h := newV2Harness(t, nil)
	bomb := make([]byte, 5)
	binary.LittleEndian.PutUint32(bomb, 10*1024*1024)
	query := h.query(h.v1Encoded(VpnProto.BuildOptions{
		PacketType:      Enums.PACKET_MTU_UP_REQ,
		CompressionType: compression.TypeLZ4,
		Payload:         bomb,
	}))

	allocs := testing.AllocsPerRun(20, func() { _ = h.s.handlePacket(query, "198.51.100.7") })
	if allocs > 100 {
		t.Fatalf("a refused probe cost %.0f allocations", allocs)
	}
	if _, _, _, err := h.s.parseTunnelLabels(tunnelLabelsOf(t, query)); err != errCompressedPreSession {
		t.Fatalf("err = %v, want errCompressedPreSession", err)
	}

	// An ordinary probe still parses.
	plain := h.query(h.v1Encoded(VpnProto.BuildOptions{PacketType: Enums.PACKET_MTU_UP_REQ, Payload: []byte("probe")}))
	if _, _, _, err := h.s.parseTunnelLabels(tunnelLabelsOf(t, plain)); err != nil {
		t.Fatalf("plain probe: %v", err)
	}
}

func tunnelLabelsOf(t *testing.T, query []byte) string {
	t.Helper()
	h := newV2Harness(t, nil)
	parsed, err := DnsParser.ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	decision := h.s.domainMatcher.Match(parsed)
	if decision.Labels == "" {
		t.Fatal("query has no tunnel labels")
	}
	return decision.Labels
}
