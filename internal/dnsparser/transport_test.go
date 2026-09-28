// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"masterdnsvpn-go/internal/compression"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestBuildTunnelQuestionNameSplitsLabels(t *testing.T) {
	name, err := BuildTunnelQuestionName("v.example.com", stringsOf('a', 130))
	if err != nil {
		t.Fatalf("BuildTunnelQuestionName returned error: %v", err)
	}
	if len(name) > maxDNSNameLen {
		t.Fatalf("name exceeds max length: %d", len(name))
	}
}

func TestBuildAndExtractVPNResponsePacketSingleAnswer(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	response, err := BuildVPNResponsePacket(query, "x.v.example.com", VpnProto.Packet{
		SessionID:  9,
		PacketType: Enums.PACKET_MTU_UP_RES,
		Payload:    []byte("challenge"),
	}, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
	}

	packet, err := ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_UP_RES)
	}
	if !bytes.Equal(packet.Payload, []byte("challenge")) {
		t.Fatalf("unexpected payload: got=%q", packet.Payload)
	}
}

func TestBuildAndExtractVPNResponsePacketChunked(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	payload := bytes.Repeat([]byte{0xAB}, 700)
	response, err := BuildVPNResponsePacket(query, "x.v.example.com", VpnProto.Packet{
		SessionID:   7,
		PacketType:  Enums.PACKET_MTU_DOWN_RES,
		StreamID:    1,
		SequenceNum: 2,
		Payload:     payload,
	}, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
	}

	packet, err := ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_DOWN_RES)
	}
	if !bytes.Equal(packet.Payload, payload) {
		t.Fatalf("unexpected chunked payload size: got=%d want=%d", len(packet.Payload), len(payload))
	}
}

func TestBuildAndExtractVPNResponsePacketSingleAnswerBaseEncoded(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	response, err := BuildVPNResponsePacket(query, "x.v.example.com", VpnProto.Packet{
		SessionID:  9,
		PacketType: Enums.PACKET_MTU_UP_RES,
		Payload:    []byte("challenge"),
	}, true)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
	}

	packet, err := ExtractVPNResponse(response, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_UP_RES)
	}
	if !bytes.Equal(packet.Payload, []byte("challenge")) {
		t.Fatalf("unexpected payload: got=%q", packet.Payload)
	}
}

func TestBuildAndExtractVPNResponsePacketChunkedBaseEncoded(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	payload := bytes.Repeat([]byte{0xAB}, 700)
	response, err := BuildVPNResponsePacket(query, "x.v.example.com", VpnProto.Packet{
		SessionID:   7,
		PacketType:  Enums.PACKET_MTU_DOWN_RES,
		StreamID:    1,
		SequenceNum: 2,
		Payload:     payload,
	}, true)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
	}

	packet, err := ExtractVPNResponse(response, true)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_DOWN_RES)
	}
	if !bytes.Equal(packet.Payload, payload) {
		t.Fatalf("unexpected chunked payload size: got=%d want=%d", len(packet.Payload), len(payload))
	}
}

func TestBuildAndExtractVPNResponsePacketCompressed(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	payload := bytes.Repeat([]byte("abcdabcdabcdabcd"), 16)
	response, err := BuildVPNResponsePacket(query, "x.v.example.com", VpnProto.Packet{
		SessionID:       7,
		PacketType:      Enums.PACKET_STREAM_DATA,
		SessionCookie:   9,
		StreamID:        1,
		SequenceNum:     2,
		FragmentID:      0,
		TotalFragments:  1,
		CompressionType: compression.TypeZLIB,
		Payload:         payload,
	}, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
	}

	packet, err := ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_STREAM_DATA {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_STREAM_DATA)
	}
	if !bytes.Equal(packet.Payload, payload) {
		t.Fatal("unexpected inflated payload")
	}
}

func TestBuildVPNResponsePacketPreservesOriginalQuestionCaseInAnswerName(t *testing.T) {
	query, err := BuildTXTQuestionPacket("ANHfwjAU21.aa.CoM", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	response, err := BuildVPNResponsePacket(query, "anhfwjau21.aa.com", VpnProto.Packet{
		SessionID:  9,
		PacketType: Enums.PACKET_MTU_UP_RES,
		Payload:    []byte("challenge"),
	}, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
	}

	parsed, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket(response) returned error: %v", err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("unexpected answer count: got=%d want=1", len(parsed.Answers))
	}
	if parsed.Answers[0].Name != "anhfwjau21.aa.com" {
		t.Fatalf("unexpected parsed answer name: got=%q want=%q", parsed.Answers[0].Name, "anhfwjau21.aa.com")
	}

	// The answer names the question by pointer, so it carries the question's
	// exact casing, which a 0x20 resolver checks it against.
	rawMixedCase := encodeDNSName("ANHfwjAU21.aa.CoM")
	questionEnd := dnsHeaderSize + len(rawMixedCase) + 4
	if !bytes.Equal(response[dnsHeaderSize:dnsHeaderSize+len(rawMixedCase)], rawMixedCase) {
		t.Fatal("question must keep its original wire casing")
	}
	if !bytes.Equal(response[questionEnd:questionEnd+2], []byte{0xC0, dnsHeaderSize}) {
		t.Fatalf("answer owner name must point at the question, got % x", response[questionEnd:questionEnd+2])
	}
}

func TestBuildVPNResponsePacketNamesOtherOwnerInFull(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	response, err := BuildVPNResponsePacket(query, "y.v.example.com", VpnProto.Packet{
		SessionID:  9,
		PacketType: Enums.PACKET_MTU_UP_RES,
		Payload:    []byte("challenge"),
	}, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
	}
	parsed, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket(response) returned error: %v", err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].Name != "y.v.example.com" {
		t.Fatalf("unexpected answers: %+v", parsed.Answers)
	}
}

// What a resolver checks before it passes an answer on: the tunnel server is
// the zone's authority, so its answers carry AA and never RA.
func TestBuildVPNResponsePacketIsAuthoritative(t *testing.T) {
	for _, size := range []int{9, 700} {
		for _, baseEncode := range []bool{false, true} {
			query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
			if err != nil {
				t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
			}
			query[3] |= 0x10 // CD
			response, err := BuildVPNResponsePacket(query, "x.v.example.com", VpnProto.Packet{
				SessionID:  9,
				PacketType: Enums.PACKET_MTU_DOWN_RES,
				Payload:    bytes.Repeat([]byte{0xAB}, size),
			}, baseEncode)
			if err != nil {
				t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
			}
			flags := binary.BigEndian.Uint16(response[2:4])
			if flags&(1<<15) == 0 || flags&(1<<10) == 0 {
				t.Fatalf("size=%d base=%v: QR and AA must be set, flags=%#04x", size, baseEncode, flags)
			}
			if flags&(1<<7) != 0 || flags&(1<<9) != 0 {
				t.Fatalf("size=%d base=%v: RA and TC must be clear, flags=%#04x", size, baseEncode, flags)
			}
			if flags&(1<<8) == 0 || flags&(1<<4) == 0 {
				t.Fatalf("size=%d base=%v: RD and CD must be copied, flags=%#04x", size, baseEncode, flags)
			}
		}
	}
}

// A frame over 255 bytes goes in one TXT record of several strings, which
// clients read by joining the strings; it is smaller than the chunked form.
func TestBuildVPNResponsePacketUsesOneRecordForLargeFrames(t *testing.T) {
	for _, baseEncode := range []bool{false, true} {
		query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
		if err != nil {
			t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
		}
		payload := make([]byte, 900)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		packet := VpnProto.Packet{
			SessionID:   7,
			PacketType:  Enums.PACKET_MTU_DOWN_RES,
			StreamID:    1,
			SequenceNum: 2,
			Payload:     payload,
		}
		response, err := BuildVPNResponsePacket(query, "x.v.example.com", packet, baseEncode)
		if err != nil {
			t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
		}
		parsed, err := ParsePacket(response)
		if err != nil {
			t.Fatalf("ParsePacket(response) returned error: %v", err)
		}
		if len(parsed.Answers) != 1 {
			t.Fatalf("base=%v: answers = %d, want 1", baseEncode, len(parsed.Answers))
		}
		rdata := parsed.Answers[0].RData
		strs := 0
		for off := 0; off < len(rdata); off += 1 + int(rdata[off]) {
			strs++
		}
		if strs < 4 {
			t.Fatalf("base=%v: %d character-strings, want the frame split over several", baseEncode, strs)
		}

		got, err := ExtractVPNResponse(response, baseEncode)
		if err != nil {
			t.Fatalf("base=%v: ExtractVPNResponse returned error: %v", baseEncode, err)
		}
		if !bytes.Equal(got.Payload, payload) || got.SequenceNum != 2 || got.StreamID != 1 {
			t.Fatalf("base=%v: frame did not survive the round trip", baseEncode)
		}

		rawFrame, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
			SessionID: 7, PacketType: Enums.PACKET_MTU_DOWN_RES, StreamID: 1, SequenceNum: 2, Payload: payload,
		})
		if err != nil {
			t.Fatalf("BuildRaw returned error: %v", err)
		}
		chunks, err := buildTXTAnswerChunks(rawFrame, baseEncode)
		if err != nil {
			t.Fatalf("buildTXTAnswerChunks returned error: %v", err)
		}
		legacy, err := BuildTXTResponsePacket(query, "x.v.example.com", chunks)
		if err != nil {
			t.Fatalf("BuildTXTResponsePacket returned error: %v", err)
		}
		if len(response) >= len(legacy) {
			t.Fatalf("base=%v: one record is %d bytes, chunked %d", baseEncode, len(response), len(legacy))
		}
	}
}

func TestBuildVPNResponsePacketRejectsOversizedFrame(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	payload := make([]byte, 70000)
	for i := range payload {
		payload[i] = byte(i*31 + i>>8)
	}
	_, err = BuildVPNResponsePacket(query, "x.v.example.com", VpnProto.Packet{
		SessionID:  7,
		PacketType: Enums.PACKET_MTU_DOWN_RES,
		Payload:    payload,
	}, false)
	if !errors.Is(err, ErrTXTAnswerTooLarge) {
		t.Fatalf("err = %v, want ErrTXTAnswerTooLarge", err)
	}
}

func TestExtractVPNResponseReordersChunkedAnswers(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	rawFrame, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		SessionID:   7,
		PacketType:  Enums.PACKET_MTU_DOWN_RES,
		StreamID:    1,
		SequenceNum: 2,
		Payload:     bytes.Repeat([]byte{0xCD}, 700),
	})
	if err != nil {
		t.Fatalf("BuildRaw returned error: %v", err)
	}

	chunks, err := buildTXTAnswerChunks(rawFrame, false)
	if err != nil {
		t.Fatalf("buildTXTAnswerChunks returned error: %v", err)
	}
	if len(chunks) < 3 {
		t.Fatalf("expected chunked answers, got=%d", len(chunks))
	}

	reordered := make([][]byte, len(chunks))
	copy(reordered, chunks)
	reordered[1], reordered[2] = reordered[2], reordered[1]

	response, err := BuildTXTResponsePacket(query, "x.v.example.com", reordered)
	if err != nil {
		t.Fatalf("BuildTXTResponsePacket returned error: %v", err)
	}

	packet, err := ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_DOWN_RES)
	}
	if len(packet.Payload) != 700 {
		t.Fatalf("unexpected payload len: got=%d want=%d", len(packet.Payload), 700)
	}
}

func TestBuildTXTAnswerChunksRejectsTooManyChunks(t *testing.T) {
	rawFrame, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		SessionID:   7,
		PacketType:  Enums.PACKET_MTU_DOWN_RES,
		StreamID:    1,
		SequenceNum: 2,
		Payload:     bytes.Repeat([]byte{0xEF}, 70000),
	})
	if err != nil {
		t.Fatalf("BuildRaw returned error: %v", err)
	}

	_, err = buildTXTAnswerChunks(rawFrame, false)
	if err == nil {
		t.Fatal("expected chunk overflow error, got nil")
	}
	if !errors.Is(err, ErrTXTAnswerTooLarge) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func stringsOf(ch byte, count int) string {
	buf := make([]byte, count)
	for i := range buf {
		buf[i] = ch
	}
	return string(buf)
}

func TestDescribeResponseWithoutTunnelPayloadEmptyNoError(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	response, err := BuildEmptyNoErrorResponse(query)
	if err != nil {
		t.Fatalf("BuildEmptyNoErrorResponse returned error: %v", err)
	}

	summary := DescribeResponseWithoutTunnelPayload(response)
	for _, want := range []string{
		"RCODE=0",
		"QD=1",
		"AN=0",
		"QName=x.v.example.com",
		"Answers=none",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q: %s", want, summary)
		}
	}
}

func TestBuildTunnelTXTQuestionPacketMatchesLegacyQuestionBuilder(t *testing.T) {
	encoded := []byte(stringsOf('a', 130))

	name, err := BuildTunnelQuestionName("v.example.com", string(encoded))
	if err != nil {
		t.Fatalf("BuildTunnelQuestionName returned error: %v", err)
	}

	legacy, err := BuildTXTQuestionPacket(name, Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	direct, err := BuildTunnelTXTQuestionPacket("v.example.com", encoded, Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTunnelTXTQuestionPacket returned error: %v", err)
	}

	if len(legacy) != len(direct) {
		t.Fatalf("packet length mismatch: legacy=%d direct=%d", len(legacy), len(direct))
	}
	if !bytes.Equal(legacy[2:], direct[2:]) {
		t.Fatal("direct tunnel question packet differs from legacy builder output")
	}
}

func TestBuildTunnelTXTQuestionPacketPreparedMatchesDirectBuilder(t *testing.T) {
	encoded := []byte(stringsOf('b', 130))

	normalized, qname, err := PrepareTunnelDomainQname("V.Example.com.")
	if err != nil {
		t.Fatalf("PrepareTunnelDomainQname returned error: %v", err)
	}
	if normalized != "v.example.com" {
		t.Fatalf("unexpected normalized domain: %q", normalized)
	}

	direct, err := BuildTunnelTXTQuestionPacket("v.example.com", encoded, Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTunnelTXTQuestionPacket returned error: %v", err)
	}

	prepared, err := BuildTunnelTXTQuestionPacketPrepared(normalized, qname, encoded, Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTunnelTXTQuestionPacketPrepared returned error: %v", err)
	}

	if len(direct) != len(prepared) {
		t.Fatalf("packet length mismatch: direct=%d prepared=%d", len(direct), len(prepared))
	}
	if !bytes.Equal(direct[2:], prepared[2:]) {
		t.Fatal("prepared tunnel question packet differs from direct builder output")
	}
}

func TestBuildTXTQuestionPacketUsesDistinctRequestIDs(t *testing.T) {
	first, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	second, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	firstID := binary.BigEndian.Uint16(first[0:2])
	secondID := binary.BigEndian.Uint16(second[0:2])
	if firstID == secondID {
		t.Fatalf("expected distinct request ids, got identical id %d", firstID)
	}
}
