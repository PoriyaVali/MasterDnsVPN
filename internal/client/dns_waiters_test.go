package client

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// A minimal DNS message: header + one question for example.com A/IN.
// Only the transaction ID and the question section matter here.
func dnsMessage(txid uint16, answer bool) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], txid)
	if answer {
		msg[2] = 0x81 // QR=1, RD=1
		msg[3] = 0x80 // RA=1
	} else {
		msg[2] = 0x01 // RD=1
	}
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT
	msg = append(msg, 7)
	msg = append(msg, []byte("example")...)
	msg = append(msg, 3)
	msg = append(msg, []byte("com")...)
	msg = append(msg, 0)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A, IN
	return msg
}

// The behaviour this whole change exists for: a name whose answer is still in
// the tunnel must be answered when it arrives, not met with silence.
//
// Before this, a miss was "fire and forget" - the query went out, the reply was
// stored, and nobody was told. The client had to time out and ask again, which
// cost a resolver timeout for the FIRST lookup of every name. A page pulling in
// a dozen hosts paid that a dozen times, which is why browsers looked broken on
// this core while Telegram and WhatsApp, which dial fixed IPs and resolve
// nothing, were fine.
func TestDNSWaiterIsAnsweredWhenTheTunnelReplies(t *testing.T) {
	c := &Client{}
	const key = "example.com|1|1"

	var mu sync.Mutex
	var got [][]byte
	c.waitForDNSAnswer(key, dnsMessage(0xAAAA, false), func(resp []byte) {
		mu.Lock()
		got = append(got, resp)
		mu.Unlock()
	})

	c.deliverDNSAnswer(key, dnsMessage(0xBBBB, true))

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("waiter was not answered: got %d responses, want 1", len(got))
	}
	// The answer must carry the transaction ID the caller used. A reply under
	// the tunnel's own ID is unsolicited as far as the resolver is concerned
	// and gets dropped - which would look exactly like the bug being fixed.
	if id := binary.BigEndian.Uint16(got[0][0:2]); id != 0xAAAA {
		t.Fatalf("response carries txid %#04x, want the caller's %#04x", id, 0xAAAA)
	}
}

// Several callers asking for the same name share one lookup, and all of them
// have to be answered - on a page loading a dozen assets from one host this is
// the common case, not an edge one.
func TestDNSWaitersAllGetTheirOwnTransactionID(t *testing.T) {
	c := &Client{}
	const key = "example.com|1|1"
	ids := []uint16{0x1111, 0x2222, 0x3333}

	var mu sync.Mutex
	seen := map[uint16]int{}
	for _, id := range ids {
		c.waitForDNSAnswer(key, dnsMessage(id, false), func(resp []byte) {
			mu.Lock()
			seen[binary.BigEndian.Uint16(resp[0:2])]++
			mu.Unlock()
		})
	}

	c.deliverDNSAnswer(key, dnsMessage(0x9999, true))

	mu.Lock()
	defer mu.Unlock()
	for _, id := range ids {
		if seen[id] != 1 {
			t.Fatalf("caller %#04x got %d answers, want exactly 1 (all: %v)", id, seen[id], seen)
		}
	}
}

// A name the tunnel never answers must not pin memory, and must fall back to
// exactly the old behaviour - silence, then the client's own retry.
func TestDNSWaitersExpire(t *testing.T) {
	c := &Client{}
	const key = "example.com|1|1"

	answered := false
	c.waitForDNSAnswer(key, dnsMessage(0xAAAA, false), func([]byte) { answered = true })

	// Age the waiter past its deadline rather than sleeping for it.
	c.dnsWaitersMu.Lock()
	for k, waiting := range c.dnsWaiters {
		for i := range waiting {
			waiting[i].deadline = time.Now().Add(-time.Second)
		}
		c.dnsWaiters[k] = waiting
	}
	c.dnsWaitersMu.Unlock()

	c.deliverDNSAnswer(key, dnsMessage(0xBBBB, true))
	if answered {
		t.Fatal("an expired waiter was answered; its caller has long since given up")
	}

	// Registering anything at all sweeps the map - there is no ticker doing it,
	// because the cache's flush loop does not run when persistence is off and
	// the Android app turns persistence off.
	c.waitForDNSAnswer("other.com|1|1", dnsMessage(0xCCCC, false), func([]byte) {})
	c.dnsWaitersMu.Lock()
	_, stillThere := c.dnsWaiters[key]
	c.dnsWaitersMu.Unlock()
	if stillThere {
		t.Fatal("expired waiters were not swept; they would accumulate for every unanswered name")
	}
}

// Registering must not alias the caller's read buffer: by the time the answer
// comes back the caller has read another packet into it.
func TestDNSWaiterCopiesTheQuery(t *testing.T) {
	c := &Client{}
	const key = "example.com|1|1"

	query := dnsMessage(0xAAAA, false)
	var got []byte
	c.waitForDNSAnswer(key, query, func(resp []byte) { got = resp })

	// Simulate the buffer being reused for the next packet.
	binary.BigEndian.PutUint16(query[0:2], 0xFFFF)

	c.deliverDNSAnswer(key, dnsMessage(0xBBBB, true))
	if got == nil {
		t.Fatal("waiter was not answered")
	}
	if id := binary.BigEndian.Uint16(got[0:2]); id != 0xAAAA {
		t.Fatalf("response carries txid %#04x, want %#04x - the query was aliased, not copied", id, 0xAAAA)
	}
}
