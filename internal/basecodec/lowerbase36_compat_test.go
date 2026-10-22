package basecodec

import (
	"bytes"
	"math/big"
	"math/rand/v2"
	"strings"
	"testing"
)

// A separate big-integer reference locks down the existing seven-byte wire
// format, including partial blocks and leading zero bytes.
func TestLowerBase36WireCompatibility(t *testing.T) {
	rng := rand.New(rand.NewPCG(17, 29))
	for size := 0; size <= 513; size++ {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(rng.Uint32())
		}
		if size > 0 {
			data[0] = 0
		}
		var reference strings.Builder
		for remaining := data; len(remaining) > 0; {
			n := min(7, len(remaining))
			block := new(big.Int).SetBytes(remaining[:n]).Text(36)
			width := lowerBase36EncodedCharsByBytes[n]
			reference.WriteString(strings.Repeat("0", width-len(block)))
			reference.WriteString(block)
			remaining = remaining[n:]
		}
		want := reference.String()
		if got := EncodeLowerBase36(data); got != want {
			t.Fatalf("size %d: encoded wire bytes changed", size)
		}
		for _, encoded := range []string{want, strings.ToUpper(want)} {
			decoded, err := DecodeLowerBase36([]byte(encoded))
			if err != nil || !bytes.Equal(decoded, data) {
				t.Fatalf("size %d: byte decode mismatch: %v", size, err)
			}
			decoded, err = DecodeLowerBase36String(encoded)
			if err != nil || !bytes.Equal(decoded, data) {
				t.Fatalf("size %d: string decode mismatch: %v", size, err)
			}
		}
	}
}

func TestLowerBase36RejectsInvalidDigitAtEveryPosition(t *testing.T) {
	for _, size := range []int{1, 2, 3, 4, 5, 6, 7, 14} {
		valid := EncodeLowerBase36Bytes(make([]byte, size))
		for pos := range valid {
			for _, invalid := range []byte{'-', '=', 0, 0x80, 0xff} {
				input := bytes.Clone(valid)
				input[pos] = invalid
				if _, err := DecodeLowerBase36(input); err == nil {
					t.Fatalf("accepted invalid byte %x at %d", invalid, pos)
				}
				if _, err := DecodeLowerBase36String(string(input)); err == nil {
					t.Fatalf("accepted invalid string byte %x at %d", invalid, pos)
				}
			}
		}
	}
}
