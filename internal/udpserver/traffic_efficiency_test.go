package udpserver

import (
	"bytes"
	"fmt"
	"testing"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/sessioncrypto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestV2EmptyPongPreservesFullAuthentication(t *testing.T) {
	for _, base64Mode := range []bool{false, true} {
		t.Run(fmt.Sprint(base64Mode), func(t *testing.T) {
			h := newV2Harness(t, nil)
			h.s.AddUser("alice")
			sig := signatureWith(1)
			if base64Mode {
				sig[0] = 1
			}
			init, keys := v2InitPayload("alice", sig, "phone-alice")
			acceptRaw, sealed, err := DnsParser.ExtractVPNResponseWith(h.init(init), base64Mode, keys.OpenDown)
			if err != nil || !sealed {
				t.Fatalf("session init failed: %v", err)
			}
			accept, err := VpnProto.DecodeSessionAcceptPayload(acceptRaw.Payload)
			if err != nil {
				t.Fatal(err)
			}
			query := h.query(h.sealedEncoded(keys, VpnProto.BuildOptions{SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_PING}))
			response := h.s.handlePacket(query, "198.51.100.7")
			var sealedPong []byte
			pong, authenticated, err := DnsParser.ExtractVPNResponseWith(response, base64Mode, func(b []byte) ([]byte, bool) {
				sealedPong = bytes.Clone(b)
				return keys.OpenDown(b)
			})
			if err != nil || !authenticated || pong.PacketType != Enums.PACKET_PONG || len(pong.Payload) != 0 {
				t.Fatalf("compact pong invalid: authenticated=%v type=%d payload=%d err=%v", authenticated, pong.PacketType, len(pong.Payload), err)
			}
			if len(sealedPong) != VpnProto.HeaderRawSize(Enums.PACKET_PONG)+sessioncrypto.DownOverhead {
				t.Fatal("compact pong changed the AEAD overhead")
			}
			for pos := range sealedPong {
				corrupt := bytes.Clone(sealedPong)
				corrupt[pos] ^= 1
				if _, ok := keys.OpenDown(corrupt); ok {
					t.Fatalf("tampering with byte %d was accepted", pos)
				}
			}
			parsed, err := DnsParser.ParseDNSRequestLite(query)
			if err != nil {
				t.Fatal(err)
			}
			legacy := buildSealedResponse(query, parsed.FirstQuestion.Name, keys, VpnProto.Packet{
				SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_PONG, Payload: []byte("PO:1234"),
			}, base64Mode)
			wantSaving := 7
			if base64Mode {
				wantSaving = 9
			}
			if got := len(legacy) - len(response); got != wantSaving {
				t.Fatalf("pong saving = %d bytes, want %d", got, wantSaving)
			}
			// Compare a complete old/new poll, including the encrypted query
			// name repeated in the DNS response's question section.
			oldQuery := h.query(h.sealedEncoded(keys, VpnProto.BuildOptions{
				SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_PING, Payload: []byte("PO:1234"),
			}))
			oldParsed, err := DnsParser.ParseDNSRequestLite(oldQuery)
			if err != nil {
				t.Fatal(err)
			}
			oldResponse := buildSealedResponse(oldQuery, oldParsed.FirstQuestion.Name, keys, VpnProto.Packet{
				SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_PONG, Payload: []byte("PO:1234"),
			}, base64Mode)
			if got := len(oldQuery) - len(query); got != 11 {
				t.Fatalf("DNS query saving = %d bytes, want 11", got)
			}
			if got := len(oldQuery) + len(oldResponse) - len(query) - len(response); got != 22+wantSaving {
				t.Fatalf("DNS poll cycle saving = %d bytes, want %d", got, 22+wantSaving)
			}
			t.Logf("DNS poll bytes: before=%d after=%d saved=%d", len(oldQuery)+len(oldResponse), len(query)+len(response), 22+wantSaving)
		})
	}
}

func TestLegacyPongBodyStaysCompatible(t *testing.T) {
	h := newV2Harness(t, nil)
	h.s.AddUser("alice")
	response := h.init(v1InitPayload("alice", signatureWith(1)))
	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatal(err)
	}
	accept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	query := h.query(h.v1Encoded(VpnProto.BuildOptions{SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_PING, Payload: []byte("PO:1234")}))
	pong, err := DnsParser.ExtractVPNResponse(h.s.handlePacket(query, "198.51.100.7"), false)
	if err != nil || pong.PacketType != Enums.PACKET_PONG || len(pong.Payload) != 7 || string(pong.Payload[:3]) != "PO:" {
		t.Fatalf("legacy pong format changed: type=%d payload=%d err=%v", pong.PacketType, len(pong.Payload), err)
	}
}
