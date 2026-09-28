package dnscache

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// dnsAnswer builds a minimal response: one question for www.example.com and,
// when ttl >= 0, one A record with that TTL. rcode and flags as given.
func dnsAnswer(rcode byte, truncated bool, ttl int, soaMin int) []byte {
	msg := []byte{0x12, 0x34, 0x81, 0x80 | rcode, 0, 1, 0, 0, 0, 0, 0, 0}
	if truncated {
		msg[2] |= 0x02
	}
	name := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	msg = append(msg, name...)
	msg = append(msg, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	if ttl >= 0 {
		binary.BigEndian.PutUint16(msg[6:8], 1)
		rr := []byte{0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 93, 184, 216, 34}
		binary.BigEndian.PutUint32(rr[6:10], uint32(ttl))
		msg = append(msg, rr...)
	}
	if soaMin >= 0 {
		binary.BigEndian.PutUint16(msg[8:10], 1)
		// SOA with owner example.com (pointer to offset 16), TTL 3600.
		rdata := []byte{0xC0, 16, 0xC0, 16, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
		rdata = binary.BigEndian.AppendUint32(rdata, uint32(soaMin))
		rr := []byte{0xC0, 16, 0, 6, 0, 1, 0, 0, 0x0E, 0x10, 0, 0}
		binary.BigEndian.PutUint16(rr[10:12], uint16(len(rdata)))
		msg = append(msg, rr...)
		msg = append(msg, rdata...)
	}
	return msg
}

func TestStore_ReadsDoNotKeepAnEntryAlive(t *testing.T) {
	s := New(100, 5*time.Minute, time.Second)
	t0 := time.Unix(1_000_000, 0)
	key := BuildKey("www.example.com", 1, 1)
	s.SetReady(key, "www.example.com", 1, 1, dnsAnswer(0, false, 3600, -1), t0)

	for m := 4; m < 5; m++ {
		if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(time.Duration(m)*time.Minute)); !ok {
			t.Fatalf("expired early at minute %d", m)
		}
	}
	// Read at minute 4, which used to push expiry to minute 9.
	if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(5*time.Minute)); ok {
		t.Fatal("entry outlived the store TTL because it was read")
	}
}

func TestStore_RecordTTLCapsLifetime(t *testing.T) {
	s := New(100, 5*time.Minute, time.Second)
	t0 := time.Unix(1_000_000, 0)
	key := BuildKey("www.example.com", 1, 1)
	s.SetReady(key, "www.example.com", 1, 1, dnsAnswer(0, false, 90, -1), t0)

	if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(89*time.Second)); !ok {
		t.Fatal("entry expired before its 90s record TTL")
	}
	if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(91*time.Second)); ok {
		t.Fatal("entry served past its 90s record TTL")
	}
}

func TestStore_TinyTTLIsFloored(t *testing.T) {
	s := New(100, 5*time.Minute, time.Second)
	t0 := time.Unix(1_000_000, 0)
	key := BuildKey("www.example.com", 1, 1)
	s.SetReady(key, "www.example.com", 1, 1, dnsAnswer(0, false, 0, -1), t0)
	if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(20*time.Second)); !ok {
		t.Fatal("a TTL-0 answer should still absorb a burst of identical lookups")
	}
	if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(minPositiveLifetime)); ok {
		t.Fatal("floor exceeded")
	}
}

func TestStore_ErrorAnswersAreNotStored(t *testing.T) {
	s := New(100, 5*time.Minute, time.Second)
	t0 := time.Unix(1_000_000, 0)
	for _, tc := range []struct {
		name string
		resp []byte
	}{
		{"servfail", dnsAnswer(2, false, -1, -1)},
		{"refused", dnsAnswer(5, false, -1, -1)},
		{"truncated", dnsAnswer(0, true, -1, -1)},
	} {
		key := BuildKey(tc.name+".example.com", 1, 1)
		// A pending lookup exists, as it does on the client when the tunnel answers.
		s.LookupOrCreatePending(key, tc.name, 1, 1, t0)
		s.SetReady(key, tc.name, 1, 1, tc.resp, t0)
		if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(time.Second)); ok {
			t.Fatalf("%s was stored", tc.name)
		}
		// And the next caller must be told to ask again, not park on a pending
		// entry that nothing will ever complete.
		if res := s.LookupOrCreatePending(key, tc.name, 1, 1, t0.Add(time.Second)); !res.DispatchNeeded {
			t.Fatalf("%s left a pending entry behind", tc.name)
		}
	}
}

func TestStore_NegativeAnswerUsesSOAMinimum(t *testing.T) {
	s := New(100, 5*time.Minute, time.Second)
	t0 := time.Unix(1_000_000, 0)
	key := BuildKey("nx.example.com", 1, 1)
	s.SetReady(key, "nx.example.com", 1, 1, dnsAnswer(3, false, -1, 20), t0)
	if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(19*time.Second)); !ok {
		t.Fatal("NXDOMAIN should be cached for its SOA minimum")
	}
	if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(21*time.Second)); ok {
		t.Fatal("NXDOMAIN served past its SOA minimum")
	}

	// Without an SOA the default negative lifetime applies.
	key2 := BuildKey("nodata.example.com", 28, 1)
	s.SetReady(key2, "nodata.example.com", 28, 1, dnsAnswer(0, false, -1, -1), t0)
	if _, ok := s.GetReady(key2, []byte{0, 1}, t0.Add(defaultNegativeLifetime-time.Second)); !ok {
		t.Fatal("NODATA without SOA should use the default negative lifetime")
	}
	if _, ok := s.GetReady(key2, []byte{0, 1}, t0.Add(defaultNegativeLifetime)); ok {
		t.Fatal("NODATA served past the default negative lifetime")
	}
}

func TestStore_RefreshRestartsTheClock(t *testing.T) {
	s := New(100, 5*time.Minute, time.Second)
	t0 := time.Unix(1_000_000, 0)
	key := BuildKey("www.example.com", 1, 1)
	s.SetReady(key, "www.example.com", 1, 1, dnsAnswer(0, false, 60, -1), t0)
	s.SetReady(key, "www.example.com", 1, 1, dnsAnswer(0, false, 60, -1), t0.Add(50*time.Second))
	if _, ok := s.GetReady(key, []byte{0, 1}, t0.Add(100*time.Second)); !ok {
		t.Fatal("a refreshed answer expired at the previous answer's deadline")
	}
}

func TestStore_LoadedEntriesObeyRecordTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.bin")
	t0 := time.Unix(1_000_000, 0)
	s := New(100, time.Hour, time.Second)
	key := BuildKey("www.example.com", 1, 1)
	s.SetReady(key, "www.example.com", 1, 1, dnsAnswer(0, false, 120, -1), t0)
	if _, err := s.SaveToFile(path, t0); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	s2 := New(100, time.Hour, time.Second)
	if n, err := s2.LoadFromFile(path, t0.Add(time.Minute)); err != nil || n != 1 {
		t.Fatalf("load: n=%d err=%v", n, err)
	}
	if _, ok := s2.GetReady(key, []byte{0, 1}, t0.Add(119*time.Second)); !ok {
		t.Fatal("loaded entry expired early")
	}
	if _, ok := s2.GetReady(key, []byte{0, 1}, t0.Add(121*time.Second)); ok {
		t.Fatal("loaded entry ignored its record TTL")
	}
}

func TestResponseLifetime_SurvivesHostilePointers(t *testing.T) {
	msg := dnsAnswer(0, false, 60, -1)
	// Point the answer's owner name at itself.
	ansOff := len(msg) - 16
	msg[ansOff], msg[ansOff+1] = 0xC0, byte(ansOff)
	if _, _, cacheable := responseLifetime(msg); !cacheable {
		t.Fatal("a looped pointer should fall back, not refuse")
	}
	// Truncated mid-record.
	if _, known, _ := responseLifetime(msg[:len(msg)-3]); known {
		t.Fatal("a cut record cannot have a known lifetime")
	}
}
