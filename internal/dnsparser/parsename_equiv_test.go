package dnsparser

import (
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"
)

// referenceParseName is parseName as it was before it measured names first.
// The rewrite must agree with it on every input: name, offset and error.
func referenceParseName(data []byte, offset int) (string, int, error) {
	dataLen := len(data)
	if offset >= dataLen {
		return "", offset, ErrInvalidName
	}
	var (
		jumped   bool
		jumps    int
		origNext = offset
		name     strings.Builder
		hasLabel bool
	)
	for {
		if offset >= dataLen {
			return "", origNext, ErrInvalidName
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			if !jumped {
				origNext = offset
			}
			break
		}
		if length >= 192 {
			if offset+1 >= dataLen || jumps >= maxNameJumps {
				return "", origNext, ErrInvalidName
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if ptr >= dataLen {
				return "", origNext, ErrInvalidName
			}
			if !jumped {
				origNext = offset + 2
				jumped = true
			}
			offset = ptr
			jumps++
			continue
		}
		if length > 63 {
			return "", origNext, ErrInvalidName
		}
		offset++
		end := offset + length
		if end > dataLen {
			return "", origNext, ErrInvalidName
		}
		if name.Len() != 0 {
			name.WriteByte('.')
		}
		for _, ch := range data[offset:end] {
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			name.WriteByte(ch)
		}
		hasLabel = true
		offset = end
		if !jumped {
			origNext = offset
		}
	}
	if !hasLabel {
		return ".", origNext, nil
	}
	return name.String(), origNext, nil
}

func randomName(r *rand.Rand, msg []byte) []byte {
	for labels := r.Intn(6); labels > 0; labels-- {
		n := 1 + r.Intn(63)
		if r.Intn(8) == 0 {
			n = 64 + r.Intn(128) // an invalid length
		}
		msg = append(msg, byte(n))
		for i := 0; i < n && len(msg) < 600; i++ {
			const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.\x00\xc3\xff"
			msg = append(msg, alphabet[r.Intn(len(alphabet))])
		}
		if r.Intn(5) == 0 {
			// A compression pointer, sometimes looping or out of range.
			msg = append(msg, 0xC0|byte(r.Intn(4)), byte(r.Intn(256)))
			return msg
		}
	}
	return append(msg, 0)
}

func TestParseNameMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 200000; i++ {
		msg := make([]byte, dnsHeaderSize)
		msg = randomName(r, msg)
		msg = randomName(r, msg)
		if r.Intn(4) == 0 && len(msg) > dnsHeaderSize {
			msg = msg[:dnsHeaderSize+r.Intn(len(msg)-dnsHeaderSize)] // truncated
		}
		if r.Intn(3) == 0 && len(msg) > dnsHeaderSize {
			// Corrupt a byte, often into a capital or a pointer.
			msg[dnsHeaderSize+r.Intn(len(msg)-dnsHeaderSize)] = []byte{'A', 'Z', 0xC0, 0x3F, 0, 0x40}[r.Intn(6)]
		}
		for _, offset := range []int{dnsHeaderSize, r.Intn(len(msg) + 2)} {
			want, wantNext, wantErr := referenceParseName(msg, offset)
			got, gotNext, gotErr := parseName(msg, offset)
			if got != want || gotNext != wantNext || gotErr != wantErr {
				t.Fatalf("message %x offset %d: got (%q, %d, %v), want (%q, %d, %v)", msg, offset, got, gotNext, gotErr, want, wantNext, wantErr)
			}
		}
	}
}

func TestParseNameAllocatesOnce(t *testing.T) {
	msg := make([]byte, dnsHeaderSize)
	for _, label := range []string{strings.Repeat("Ab0", 21), strings.Repeat("x", 63), strings.Repeat("Q9", 31), strings.Repeat("z", 40), "t", "e2e", "test"} {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	allocs := testing.AllocsPerRun(200, func() {
		if _, _, err := parseName(msg, dnsHeaderSize); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 1 {
		t.Fatalf("parseName of a %d-byte name made %v allocations, want 1", len(msg), allocs)
	}
}

// referenceResponseAnswerNameBytes is responseAnswerNameBytes as it was before
// it compared names in place.
func referenceResponseAnswerNameBytes(questionPacket []byte, questionBytes []byte, answerName string) ([]byte, error) {
	_, parsedName, ok := extractFirstQuestionNameWire(questionPacket)
	if ok && len(questionBytes) > 0 && sameDNSName(parsedName, answerName) {
		return questionNamePointer, nil
	}
	return encodeDNSNameStrict(answerName)
}

func TestResponseAnswerNameMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 200000; i++ {
		msg := make([]byte, dnsHeaderSize)
		binary.BigEndian.PutUint16(msg[4:6], uint16(r.Intn(3)))
		msg = randomName(r, msg)
		name, _, err := referenceParseName(msg, dnsHeaderSize)
		answer := "t.e2e.test"
		switch r.Intn(6) {
		case 0, 1:
			if err == nil {
				answer = name // the question's own name, as the server answers
				if r.Intn(2) == 0 {
					answer = strings.ToUpper(answer)
				}
				if r.Intn(3) == 0 {
					answer += "."
				}
			}
		case 2:
			if err == nil && len(name) > 1 {
				answer = name[:len(name)-1] // one character short
			}
		case 3:
			answer = "x\xc3\xa9.e2e.test"
		case 4:
			answer = "."
		}
		questionBytes := msg[dnsHeaderSize:]
		if r.Intn(10) == 0 {
			questionBytes = nil
		}
		want, wantErr := referenceResponseAnswerNameBytes(msg, questionBytes, answer)
		got, gotErr := responseAnswerNameBytes(msg, questionBytes, answer)
		if string(got) != string(want) || (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("question %x answer %q: got (%x, %v), want (%x, %v)", msg, answer, got, gotErr, want, wantErr)
		}
	}
}
