package udpserver

import (
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestEarlyDataBufferHoldsAndHandsOver(t *testing.T) {
	var b earlyDataBuffer
	now := time.Unix(1_700_000_000, 0)

	b.hold(7, Enums.PACKET_STREAM_DATA, 0, 0, []byte("hello"), now)
	b.hold(7, Enums.PACKET_STREAM_DATA, 1, 0, []byte("world"), now)
	// The same packet through a second resolver is kept once.
	b.hold(7, Enums.PACKET_STREAM_DATA, 0, 0, []byte("hello"), now)

	got := b.take(7)
	if len(got) != 2 || string(got[0].payload) != "hello" || got[1].sequenceNum != 1 {
		t.Fatalf("held packets = %+v", got)
	}
	if again := b.take(7); again != nil {
		t.Fatal("take returned the same packets twice")
	}
}

func TestEarlyDataBufferCopiesPayload(t *testing.T) {
	var b earlyDataBuffer
	buf := []byte("abc")
	b.hold(1, Enums.PACKET_STREAM_DATA, 0, 0, buf, time.Now())
	buf[0] = 'X'
	if got := b.take(1); string(got[0].payload) != "abc" {
		t.Fatalf("held payload aliases the caller's buffer: %q", got[0].payload)
	}
}

func TestEarlyDataBufferExpiresUnclaimedStreams(t *testing.T) {
	var b earlyDataBuffer
	now := time.Unix(1_700_000_000, 0)
	b.hold(5, Enums.PACKET_STREAM_DATA, 0, 0, []byte("x"), now)
	expired := b.hold(6, Enums.PACKET_STREAM_DATA, 0, 0, []byte("y"), now.Add(earlyDataHoldTTL+time.Second))
	if len(expired) != 1 || expired[0] != 5 {
		t.Fatalf("expired = %v, want [5]", expired)
	}
	if b.take(5) != nil {
		t.Fatal("an expired stream's data was still held")
	}
}

func TestEarlyDataBufferIsBounded(t *testing.T) {
	var b earlyDataBuffer
	now := time.Now()
	for id := uint16(1); id <= earlyDataMaxStreams+10; id++ {
		b.hold(id, Enums.PACKET_STREAM_DATA, 0, 0, []byte("x"), now)
	}
	if len(b.streams) != earlyDataMaxStreams {
		t.Fatalf("held %d streams, cap is %d", len(b.streams), earlyDataMaxStreams)
	}
	big := make([]byte, 1024)
	for seq := uint16(0); seq < earlyDataMaxPacketsStream*2; seq++ {
		b.hold(1, Enums.PACKET_STREAM_DATA, seq, 0, big, now)
	}
	entry := b.streams[1]
	if len(entry.packets) > earlyDataMaxPacketsStream || entry.bytes > earlyDataMaxBytesStream {
		t.Fatalf("one stream holds %d packets / %d bytes", len(entry.packets), entry.bytes)
	}
}

func TestEarlyDataBufferSessionTotalIsBounded(t *testing.T) {
	var b earlyDataBuffer
	now := time.Now()
	chunk := make([]byte, 1024)
	for id := uint16(1); id <= earlyDataMaxStreams; id++ {
		for seq := uint16(0); seq < earlyDataMaxPacketsStream; seq++ {
			b.hold(id, Enums.PACKET_STREAM_DATA, seq, 0, chunk, now)
		}
	}
	if b.bytes > earlyDataMaxBytesSession {
		t.Fatalf("session holds %d bytes, cap is %d", b.bytes, earlyDataMaxBytesSession)
	}
	// Handing a stream over frees its share.
	before := b.bytes
	got := b.take(1)
	if b.bytes != before-len(got)*len(chunk) {
		t.Fatalf("take did not release bytes: %d -> %d", before, b.bytes)
	}
}
