package vpnproto

import (
	"bytes"
	"testing"
)

func TestBuildRawIntoReusesTheBufferAndMatchesBuildRaw(t *testing.T) {
	opts := BuildOptions{SessionID: 4, PacketType: 0x05, SessionCookie: 7, StreamID: 3, SequenceNum: 99, Payload: bytes.Repeat([]byte("x"), 300)}
	want, err := BuildRaw(opts)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 0, 1024)
	got, err := BuildRawInto(buf, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("BuildRawInto and BuildRaw disagree")
	}
	if &got[0] != &buf[:1][0] {
		t.Fatal("a large enough buffer was not reused")
	}
	if allocs := testing.AllocsPerRun(100, func() { _, _ = BuildRawInto(buf, opts) }); allocs != 0 {
		t.Fatalf("%.0f allocations building into a large enough buffer", allocs)
	}
	small := make([]byte, 0, 8)
	if got, _ := BuildRawInto(small, opts); !bytes.Equal(got, want) {
		t.Fatal("a too-small buffer must still give the right frame")
	}
}
