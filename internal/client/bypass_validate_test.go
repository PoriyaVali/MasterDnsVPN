package client

import "testing"

// A minimal DNS header, so each field can be corrupted one at a time.
func hdr(id uint16, qr bool, rcode byte, ancount uint16) []byte {
	b := make([]byte, 12)
	b[0] = byte(id >> 8)
	b[1] = byte(id)
	if qr {
		b[2] |= 0x80
	}
	b[3] = rcode & 0x0F
	b[6] = byte(ancount >> 8)
	b[7] = byte(ancount)
	return b
}

func TestUsableDNSReplyAcceptsARealAnswer(t *testing.T) {
	q := hdr(0x4242, false, 0, 0)
	if !usableDNSReply(hdr(0x4242, true, 0, 1), q) {
		t.Fatal("a NOERROR response with an answer must be accepted")
	}
}

// 🔑 The one that matters. Racing takes whichever reply lands first, so an
// instant hijacked answer beats an honest resolver that is still working -
// unless each reply is checked. These are the shapes that arrive fastest on a
// censored network.
func TestUsableDNSReplyRejectsTheFastLiars(t *testing.T) {
	q := hdr(0x4242, false, 0, 0)
	cases := []struct {
		name string
		resp []byte
	}{
		{"wrong transaction id", hdr(0x1111, true, 0, 1)},
		{"not a response at all", hdr(0x4242, false, 0, 1)},
		{"NXDOMAIN", hdr(0x4242, true, 3, 0)},
		{"SERVFAIL", hdr(0x4242, true, 2, 0)},
		{"NOERROR but empty", hdr(0x4242, true, 0, 0)},
		{"truncated to nothing", []byte{0x42, 0x42}},
		{"empty", nil},
	}
	for _, c := range cases {
		if usableDNSReply(c.resp, q) {
			t.Fatalf("%s should not be accepted as an answer", c.name)
		}
	}
}

func TestUsableDNSReplyNeedsAQueryToCompareAgainst(t *testing.T) {
	// A caller with no query cannot have its transaction matched, so nothing is
	// usable - failing closed rather than accepting anything.
	if usableDNSReply(hdr(0x4242, true, 0, 1), []byte{0x42}) {
		t.Fatal("a short query must not validate anything")
	}
}
