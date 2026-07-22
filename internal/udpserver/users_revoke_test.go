package udpserver

import (
	"testing"
	"time"
)

// A revoked user's live sessions must go, and only theirs.
//
// The session is deliberately given fresh activity: an idle one would be
// collected by the normal cleanup anyway, so it proves nothing. The case that
// matters is the customer actively using the service when their credit runs
// out - that session refreshes its own idle timer and, before this, stayed up
// for as long as they kept using it.
func TestCloseUserSessionsClosesOnlyTheRevokedUser(t *testing.T) {
	reg := newUserRegistry([]byte("node-secret"))
	reg.add("revoked-uuid")
	reg.add("paying-uuid")
	revoked := reg.lookup(DeriveUserToken(reg.secret, "revoked-uuid"))
	paying := reg.lookup(DeriveUserToken(reg.secret, "paying-uuid"))
	if revoked == nil || paying == nil {
		t.Fatal("registry did not return both accounts")
	}

	store := newSessionStore(8, 32)

	theirs := newTestSessionRecord(11)
	theirs.Signature[0] = 11
	theirs.user = revoked
	theirs.setLastActivity(time.Now()) // actively in use
	store.byID[theirs.ID] = theirs
	store.bySig[theirs.Signature] = theirs.ID

	other := newTestSessionRecord(12)
	other.Signature[0] = 12
	other.user = paying
	other.setLastActivity(time.Now())
	store.byID[other.ID] = other
	store.bySig[other.Signature] = other.ID

	store.activeCount = 2

	closed := store.CloseUserSessions(revoked, time.Now(), 10*time.Minute)

	if len(closed) != 1 {
		t.Fatalf("closed %d sessions, want exactly 1", len(closed))
	}
	if closed[0].ID != theirs.ID {
		t.Fatalf("closed session %d, want %d", closed[0].ID, theirs.ID)
	}
	if closed[0].record != theirs {
		t.Fatal("cleanup payload must carry the original record, as Cleanup does")
	}
	if store.byID[theirs.ID] != nil {
		t.Fatal("revoked session still in the active store")
	}
	if _, ok := store.bySig[theirs.Signature]; ok {
		t.Fatal("revoked session still resolvable by signature")
	}
	if !theirs.isClosed() {
		t.Fatal("revoked record not marked closed")
	}
	// The client will retry on the same signature; recentClosed is what tells
	// it the session is gone rather than leaving it to guess.
	if _, ok := store.recentClosed[theirs.ID]; !ok {
		t.Fatal("revoked session missing from recentClosed")
	}

	// The paying customer must not notice any of this.
	if store.byID[other.ID] != other {
		t.Fatal("a different user's session was torn down")
	}
	if other.isClosed() {
		t.Fatal("a different user's session was marked closed")
	}
	if store.activeCount != 1 {
		t.Fatalf("activeCount = %d, want 1", store.activeCount)
	}
}

// A standalone node has no users and every session carries a nil account.
// Passing nil must not be read as "match the sessions that have no user" and
// take the whole node down.
func TestCloseUserSessionsIgnoresNilAccount(t *testing.T) {
	store := newSessionStore(8, 32)
	record := newTestSessionRecord(13)
	record.Signature[0] = 13
	record.setLastActivity(time.Now())
	store.byID[record.ID] = record
	store.bySig[record.Signature] = record.ID
	store.activeCount = 1

	if closed := store.CloseUserSessions(nil, time.Now(), time.Minute); len(closed) != 0 {
		t.Fatalf("closed %d sessions for a nil account, want 0", len(closed))
	}
	if store.byID[record.ID] == nil || record.isClosed() {
		t.Fatal("standalone session was torn down by a nil account")
	}
}

// del has to hand back the account it removed, otherwise DelUser has nothing to
// match sessions against and the revocation silently reaches nobody.
func TestRegistryDelReturnsRemovedAccount(t *testing.T) {
	reg := newUserRegistry([]byte("node-secret"))
	reg.add("uuid-a")
	want := reg.lookup(DeriveUserToken(reg.secret, "uuid-a"))

	got := reg.del("uuid-a")
	if got == nil {
		t.Fatal("del returned nil for a registered user")
	}
	if got != want {
		t.Fatal("del returned a different account than the one registered")
	}
	if reg.lookup(DeriveUserToken(reg.secret, "uuid-a")) != nil {
		t.Fatal("user still resolvable after del")
	}
	if reg.del("uuid-a") != nil {
		t.Fatal("second del should return nil")
	}
	if reg.del("never-existed") != nil {
		t.Fatal("del of an unknown user should return nil")
	}
}
