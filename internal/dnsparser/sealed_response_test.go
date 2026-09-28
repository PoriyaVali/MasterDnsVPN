package dnsparser

import (
	"bytes"
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// An "encryption" that is trivially reversible, so the test is about framing.
func xorSeal(b []byte) []byte {
	out := make([]byte, len(b)+1)
	out[0] = 0xEE
	for i, v := range b {
		out[i+1] = v ^ 0x5C
	}
	return out
}

func xorOpen(b []byte) ([]byte, bool) {
	if len(b) < 1 || b[0] != 0xEE {
		return nil, false
	}
	out := make([]byte, len(b)-1)
	for i := range out {
		out[i] = b[i+1] ^ 0x5C
	}
	return out, true
}

func TestSealedResponseRoundTripsAtEverySize(t *testing.T) {
	q, err := BuildTunnelTXTQuestionPacket("t.example.com", []byte("abcdefgh"), Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for _, base64 := range []bool{false, true} {
		for _, size := range []int{0, 1, 100, 190, 191, 192, 254, 255, 256, 600, 1400, 3000} {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i * 13)
			}
			raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
				SessionID: 9, SessionCookie: 4, PacketType: Enums.PACKET_STREAM_DATA,
				StreamID: 2, SequenceNum: 77, Payload: payload,
			})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := BuildSealedVPNResponsePacket(q, "abcdefgh.t.example.com", xorSeal(raw), base64)
			if err != nil {
				t.Fatalf("size %d base64=%v: %v", size, base64, err)
			}
			got, sealed, err := ExtractVPNResponseWith(resp, base64, xorOpen)
			if err != nil || !sealed {
				t.Fatalf("size %d base64=%v: sealed=%v err=%v", size, base64, sealed, err)
			}
			if got.SequenceNum != 77 || got.StreamID != 2 || !bytes.Equal(got.Payload, payload) {
				t.Fatalf("size %d base64=%v: frame did not survive", size, base64)
			}
		}
	}
}

// A v1 answer offered to a client holding keys still parses - unsealed - so
// the caller can apply its own rule to it.
func TestUnsealedAnswerFallsThroughAsV1(t *testing.T) {
	q, _ := BuildTunnelTXTQuestionPacket("t.example.com", []byte("abcdefgh"), Enums.DNS_RECORD_TYPE_TXT, 4096)
	resp, err := BuildVPNResponsePacket(q, "abcdefgh.t.example.com", VpnProto.Packet{
		SessionID: 9, PacketType: Enums.PACKET_ERROR_DROP, Payload: []byte("INV12345"),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	got, sealed, err := ExtractVPNResponseWith(resp, false, xorOpen)
	if err != nil || sealed || got.PacketType != Enums.PACKET_ERROR_DROP {
		t.Fatalf("v1 answer: type=%d sealed=%v err=%v", got.PacketType, sealed, err)
	}
}
