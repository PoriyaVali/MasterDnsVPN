// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package compression

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCompressPayloadKeepsSmallDataRaw(t *testing.T) {
	data := bytes.Repeat([]byte("a"), DefaultMinSize)
	out, used := CompressPayload(data, TypeZLIB, DefaultMinSize)
	if used != TypeOff {
		t.Fatalf("unexpected compression type: got=%d want=%d", used, TypeOff)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("small payload should stay uncompressed")
	}
}

func TestCompressPayloadRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("abcabcabcabcabcabcabcabc"), 16)
	compressed, used := CompressPayload(data, TypeZLIB, DefaultMinSize)
	if used != TypeZLIB {
		t.Fatalf("unexpected compression type: got=%d want=%d", used, TypeZLIB)
	}
	if len(compressed) >= len(data) {
		t.Fatalf("compressed payload should be smaller: got=%d raw=%d", len(compressed), len(data))
	}

	decoded, ok := TryDecompressPayload(compressed, used)
	if !ok {
		t.Fatal("TryDecompressPayload returned false")
	}
	if !bytes.Equal(decoded, data) {
		t.Fatal("decompressed payload mismatch")
	}
}

func TestUnavailableCompressionFallsBackToOff(t *testing.T) {
	data := bytes.Repeat([]byte("abcabcabcabcabcabcabcabc"), 16)
	out, used := CompressPayload(data, 255, DefaultMinSize)
	if used != TypeOff {
		t.Fatalf("unexpected compression type: got=%d want=%d", used, TypeOff)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("unsupported compression must return original data")
	}
}

func TestDecompressZSTDDecoderCanBeReusedFromPool(t *testing.T) {
	data := bytes.Repeat([]byte("zstd-roundtrip-"), 128)

	compressed, err := compressZSTD(data)
	if err != nil {
		t.Fatalf("compressZSTD failed: %v", err)
	}

	for i := 0; i < 2; i++ {
		decoded, err := decompressZSTD(compressed)
		if err != nil {
			t.Fatalf("decompressZSTD failed on pass %d: %v", i+1, err)
		}
		if !bytes.Equal(decoded, data) {
			t.Fatalf("decoded payload mismatch on pass %d", i+1)
		}
	}
}

// A compressed payload is one frame's; nothing legitimate expands past a DNS
// message. A header claiming more must be refused before anything is
// allocated for it - it used to cost 10 MB per 5-byte payload.
func TestDecompressRefusesBombs(t *testing.T) {
	lz4Header := make([]byte, 5)
	binary.LittleEndian.PutUint32(lz4Header, 10*1024*1024)
	allocs := testing.AllocsPerRun(20, func() {
		if _, ok := TryDecompressPayload(lz4Header, TypeLZ4); ok {
			t.Fatal("LZ4 claiming 10 MB was accepted")
		}
	})
	if allocs > 2 {
		t.Fatalf("refusing an LZ4 bomb allocated %.0f times", allocs)
	}

	zeros := make([]byte, 10*1024*1024)
	for _, typ := range []uint8{TypeZSTD, TypeZLIB} {
		var bomb []byte
		var err error
		if typ == TypeZSTD {
			bomb, err = compressZSTD(zeros)
		} else {
			bomb, err = compressZLIB(zeros)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := TryDecompressPayload(bomb, typ); ok {
			t.Fatalf("type %d: %d bytes expanding to 10 MB were accepted", typ, len(bomb))
		}
	}
}

func TestDecompressKeepsTheLargestRealPayload(t *testing.T) {
	msg := make([]byte, 65535)
	for i := range msg {
		msg[i] = byte(i % 251)
	}
	for _, typ := range []uint8{TypeZSTD, TypeLZ4, TypeZLIB} {
		packed, got := CompressPayload(msg, typ, 1)
		if got != typ {
			t.Fatalf("type %d: payload was not compressed", typ)
		}
		out, ok := TryDecompressPayload(packed, typ)
		if !ok || len(out) != len(msg) {
			t.Fatalf("type %d: a 65535-byte payload did not round-trip", typ)
		}
	}
}
