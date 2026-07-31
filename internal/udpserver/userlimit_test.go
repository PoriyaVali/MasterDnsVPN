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
	o.note("5.127.1.1", now)
	o.note("5.127.1.2", now)
	o.note("5.127.1.1", now) // same address again is still one device

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
		o.note(string(rune('a'+i%26))+"."+time.Duration(i).String(), now.Add(time.Duration(i)*time.Millisecond))
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
	o.note("", time.Now())
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
	r.byUUIDAccount("with-addr").addrs.note("1.2.3.4", now)

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
