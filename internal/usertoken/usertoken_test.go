package usertoken

import "testing"

func TestDerive_DeterministicAndDistinct(t *testing.T) {
	secret := []byte("node-secret")
	a1 := Derive(secret, "user-A")
	a2 := Derive(secret, "user-A")
	b := Derive(secret, "user-B")

	if a1 != a2 {
		t.Fatalf("same secret+uuid must give the same token")
	}
	if a1 == b {
		t.Fatalf("different uuids must give different tokens")
	}
	// A different node secret must change the token (per-node isolation).
	if Derive([]byte("other-secret"), "user-A") == a1 {
		t.Fatalf("different secret must change the token")
	}
	if len(a1) != Len {
		t.Fatalf("token length = %d, want %d", len(a1), Len)
	}
}
