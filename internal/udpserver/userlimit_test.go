package udpserver

import (
	"testing"
	"time"
)

// A limited user must actually be slowed. The bucket allows one second of burst,
// so the delay only shows once more than that has been charged.
func TestTokenBucketPacesBeyondTheBurst(t *testing.T) {
	const rate = 100_000 // bytes/sec
	b := newTokenBucket(rate)

	start := time.Now()
	b.wait(rate) // the burst - should not block
	if burst := time.Since(start); burst > 50*time.Millisecond {
		t.Errorf("the initial burst blocked for %v; an idle user should not be punished for arriving", burst)
	}

	start = time.Now()
	b.wait(rate / 2) // half a second of debt
	got := time.Since(start)
	if got < 300*time.Millisecond {
		t.Errorf("charging half a second of data slept %v, want at least ~300ms - the limit is not being applied", got)
	}
	if got > 2*time.Second {
		t.Errorf("slept %v for half a second of data - far more than the debt", got)
	}
}

// Zero or negative means unlimited, and must cost nothing at all: this is the
// path almost every user takes, so it cannot be allowed to allocate or lock.
func TestNoLimitMeansNoBucketAndNoDelay(t *testing.T) {
	for _, rate := range []int64{0, -1} {
		if b := newTokenBucket(rate); b != nil {
			t.Errorf("rate %d produced a bucket; unlimited must be nil", rate)
		}
	}
	var nilBucket *tokenBucket
	start := time.Now()
	nilBucket.wait(1 << 20) // must be safe on a nil receiver
	if d := time.Since(start); d > 20*time.Millisecond {
		t.Errorf("an unlimited user waited %v", d)
	}
}

// A limit is a property of the subscriber, so changing it must take effect on
// the sessions they already hold - not only the next one.
func TestSpeedLimitCanBeChangedAndRemoved(t *testing.T) {
	a := &userAccount{uuid: "u1"}
	if a.limiter() != nil {
		t.Fatal("a new account must start unlimited")
	}
	a.setSpeedLimit(50_000)
	if a.limiter() == nil {
		t.Fatal("setting a limit did not attach a bucket")
	}
	a.setSpeedLimit(0)
	if a.limiter() != nil {
		t.Error("setting 0 must remove the limit, not keep the old one")
	}
}

// Device counting: addresses are remembered per user and age out, so a user who
// moved networks is not counted twice forever.
func TestOnlineAddressesAreRememberedAndExpire(t *testing.T) {
	var o onlineAddrs
	now := time.Now()
	o.note("5.127.1.1", now, 1000)
	o.note("5.127.1.2", now, 1000)
	o.note("5.127.1.1", now, 1000) // same address again is still one device

	if got := o.list(now); len(got) != 2 {
		t.Fatalf("expected 2 distinct addresses, got %v", got)
	}
	if got := o.list(now.Add(onlineAddrTTL + time.Second)); len(got) != 0 {
		t.Errorf("addresses should expire; still saw %v", got)
	}
}

// 🔴 A carrier that hands out a different egress address per connection would
// otherwise grow this map without bound. The cap is what stops one client
// costing memory forever.
func TestOnlineAddressesAreBounded(t *testing.T) {
	var o onlineAddrs
	now := time.Now()
	for i := 0; i < onlineAddrCap*3; i++ {
		o.note(string(rune('a'+i%26))+"."+time.Duration(i).String(), now.Add(time.Duration(i)*time.Millisecond), int64(i))
	}
	o.mu.Lock()
	n := len(o.seen)
	o.mu.Unlock()
	if n > onlineAddrCap {
		t.Errorf("kept %d addresses, cap is %d", n, onlineAddrCap)
	}
}

// An empty address must never be recorded - it would show up as a phantom
// device with no way to tell where it came from.
func TestEmptyAddressIsIgnored(t *testing.T) {
	var o onlineAddrs
	o.note("", time.Now(), 100)
	if got := o.list(time.Now()); len(got) != 0 {
		t.Errorf("an empty address was recorded: %v", got)
	}
}

// The registry surfaces only users that actually have a live address.
func TestOnlineIPsReportsOnlyUsersWithAddresses(t *testing.T) {
	r := newUserRegistry([]byte("secret"))
	r.add("with-addr")
	r.add("without-addr")
	now := time.Now()
	r.byUUIDAccount("with-addr").addrs.note("1.2.3.4", now, 500)

	got := r.onlineIPs(now)
	if len(got) != 1 || len(got["with-addr"]) != 1 {
		t.Fatalf("expected only the user with an address, got %v", got)
	}
	if _, present := got["without-addr"]; present {
		t.Error("a user with no address must not be reported as online")
	}
}

// Unknown users must be ignored rather than panic, so a caller can push the
// panel's whole list without filtering it first.
func TestSpeedLimitOnUnknownUserIsIgnored(t *testing.T) {
	r := newUserRegistry([]byte("secret"))
	r.byUUIDAccount("never-registered").setSpeedLimit(1000) // must not panic
}

// The whole point of the byte count: a caller must be able to tell the address
// that carried a session from the ones a rotating carrier handed out in passing.
func TestPerAddressTrafficIsRecordedAndResets(t *testing.T) {
	var o onlineAddrs
	now := time.Now()
	o.note("real-device", now, 5_000_000)
	o.note("real-device", now, 3_000_000)
	o.note("rotation-artefact", now, 400)

	got := o.traffic(now, true)
	if got["real-device"] != 8_000_000 {
		t.Errorf("the busy address recorded %d bytes, want 8000000", got["real-device"])
	}
	if got["rotation-artefact"] != 400 {
		t.Errorf("the idle address recorded %d bytes, want 400", got["rotation-artefact"])
	}

	// Reset means each report covers one interval, like the per-user counters.
	after := o.traffic(now, false)
	if after["real-device"] != 0 || after["rotation-artefact"] != 0 {
		t.Errorf("counters survived the reset: %v", after)
	}
	if len(after) != 2 {
		t.Errorf("a reset must not drop the addresses themselves: %v", after)
	}
}

// 🔴 Eviction must never throw away the device that is actually in use. Evicting
// the oldest entry would do exactly that under per-query address rotation: the
// one real device is the oldest precisely because it has been there all along.
func TestEvictionDropsTheLeastUsedAddressNotTheOldest(t *testing.T) {
	var o onlineAddrs
	start := time.Now()
	o.note("real-device", start, 50_000_000) // oldest, and the one that matters

	for i := 0; i < onlineAddrCap*2; i++ {
		o.note("churn-"+time.Duration(i).String(), start.Add(time.Duration(i+1)*time.Millisecond), 100)
	}

	got := o.traffic(start, false)
	if len(got) > onlineAddrCap {
		t.Errorf("kept %d addresses, cap is %d", len(got), onlineAddrCap)
	}
	if _, alive := got["real-device"]; !alive {
		t.Error("the busiest address was evicted; a customer's real device would stop being counted")
	}
}

// Traffic is reported per user as well as per address, and only for users who
// have live addresses.
func TestOnlineTrafficIsGroupedByUser(t *testing.T) {
	r := newUserRegistry([]byte("secret"))
	r.add("busy")
	r.add("idle")
	now := time.Now()
	r.byUUIDAccount("busy").noteAddr("1.1.1.1", now, 900)
	r.byUUIDAccount("busy").noteAddr("2.2.2.2", now, 100)

	got := r.onlineTraffic(now, false)
	if len(got) != 1 {
		t.Fatalf("expected only the user with addresses, got %v", got)
	}
	if got["busy"]["1.1.1.1"] != 900 || got["busy"]["2.2.2.2"] != 100 {
		t.Errorf("per-address totals came through wrong: %v", got["busy"])
	}
}

// A standalone session has no account, and the packet path calls this for every
// packet - it must not panic on the way.
func TestNoteAddrIsSafeWithoutAnAccount(t *testing.T) {
	var missing *userAccount
	missing.noteAddr("1.2.3.4", time.Now(), 100)
}
