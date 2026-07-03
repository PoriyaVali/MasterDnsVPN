package udpserver

import "testing"

func TestUserRegistry_TellsUsersApart(t *testing.T) {
	secret := []byte("node-secret-abc")
	r := newUserRegistry(secret)

	uuidA := "11111111-1111-1111-1111-111111111111"
	uuidB := "22222222-2222-2222-2222-222222222222"

	tokA := r.add(uuidA)
	tokB := r.add(uuidB)

	if tokA == tokB {
		t.Fatalf("distinct UUIDs must yield distinct tokens")
	}
	// Tokens are deterministic and reproducible by a client with the same secret.
	if tokA != DeriveUserToken(secret, uuidA) {
		t.Fatalf("token derivation not reproducible")
	}

	if a := r.lookup(tokA); a == nil || a.uuid != uuidA {
		t.Fatalf("lookup(tokA) should resolve to user A")
	}
	if a := r.lookup(tokB); a == nil || a.uuid != uuidB {
		t.Fatalf("lookup(tokB) should resolve to user B")
	}
	// An unknown token (a scanner / wrong secret) must not resolve.
	if r.lookup(UserToken{9, 9, 9, 9, 9, 9, 9, 9}) != nil {
		t.Fatalf("unknown token must be rejected")
	}
}

func TestUserRegistry_PerUserTrafficAndReset(t *testing.T) {
	r := newUserRegistry([]byte("s"))
	r.add("A")
	r.add("B")
	a := r.lookup(DeriveUserToken(r.secret, "A"))
	b := r.lookup(DeriveUserToken(r.secret, "B"))

	a.up.Add(100)
	a.down.Add(400)
	b.up.Add(7)
	b.down.Add(0)

	got := map[string][2]int64{}
	for _, s := range r.sample(true) { // reset = true
		got[s.UUID] = [2]int64{s.Upload, s.Download}
	}
	if got["A"] != [2]int64{100, 400} {
		t.Fatalf("user A traffic wrong: %v", got["A"])
	}
	if got["B"] != [2]int64{7, 0} {
		t.Fatalf("user B traffic wrong: %v", got["B"])
	}
	// After reset, a fresh sample must be empty (all counters back to zero).
	if s := r.sample(false); len(s) != 0 {
		t.Fatalf("counters should be zero after reset, got %v", s)
	}
}

func TestUserRegistry_DelStopsAuth(t *testing.T) {
	r := newUserRegistry([]byte("s"))
	tok := r.add("A")
	if r.lookup(tok) == nil {
		t.Fatalf("A should authenticate before deletion")
	}
	r.del("A")
	if r.lookup(tok) != nil {
		t.Fatalf("A must be rejected after deletion")
	}
	if r.count() != 0 {
		t.Fatalf("registry should be empty")
	}
}
