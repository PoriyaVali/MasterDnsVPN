package dnsparser

import (
	"bytes"
	"testing"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// The one-buffer builder must put exactly the bytes the two-step builder
// did on the wire: the same RDATA, split into the same strings.
func TestBuildTXTResponseMatchesTheTwoStepBuilder(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, 190, 191, 254, 255, 256, 509, 510, 511, 900, 4000} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i*7 + size)
		}
		for _, base := range []bool{false, true} {
			text := data
			if base {
				text = make([]byte, baseCodec.EncodedRawBase64Len(len(data)))
				baseCodec.EncodeRawBase64Into(text, data)
			}
			want, err := buildSingleTXTResponsePacket(query, "x.v.example.com", appendLengthPrefixedTXT(text))
			if err != nil {
				t.Fatal(err)
			}
			got, err := buildTXTResponse(query, "x.v.example.com", data, base)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("size=%d base=%v: responses differ", size, base)
			}
		}
	}
}

// Building an answer allocates the answer, not a frame, an RDATA and a
// packet besides.
func TestBuildVPNResponsePacketAllocations(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0xAB}, 800)
	packet := VpnProto.Packet{SessionID: 3, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 9, Payload: payload}
	for _, base := range []bool{false, true} {
		_, _ = BuildVPNResponsePacket(query, "x.v.example.com", packet, base)
		allocs := testing.AllocsPerRun(200, func() {
			if _, err := BuildVPNResponsePacket(query, "x.v.example.com", packet, base); err != nil {
				t.Fatal(err)
			}
		})
		if allocs > 3 {
			t.Fatalf("base=%v: %.0f allocations per answer", base, allocs)
		}
		t.Logf("base=%v: %.0f allocations per answer", base, allocs)
	}
}
