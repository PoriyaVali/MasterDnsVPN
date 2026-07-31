package udpserver

import (
	"sync"
	"time"
)

// Per-user speed limiting and online-address tracking.
//
// Both exist because a node running this core was invisible to the panel's
// limits: every other protocol in the fleet enforces a speed limit and counts a
// user's devices, and an mdns node enforced neither. A subscriber moved to mdns
// therefore got unmetered speed and unlimited devices, which is not a policy
// anyone chose - it is just the half that was never wired.
//
// Kept dependency-free on purpose: this module builds on the standard library
// plus three codecs, and a token bucket is twenty lines.

// tokenBucket paces a byte stream to a steady rate, allowing a burst of up to
// one second's worth so an idle user is not punished for arriving.
//
// Deliberately NOT a leaky bucket over a timer: a DNS tunnel already moves data
// in query/response bursts, and pacing every packet through a ticker would add
// latency to traffic that is latency-sensitive by construction. Charging tokens
// and only sleeping when the balance goes negative leaves normal use untouched.
type tokenBucket struct {
	mu       sync.Mutex
	rate     float64 // bytes per second; <= 0 means unlimited
	capacity float64
	tokens   float64
	last     time.Time
}

func newTokenBucket(bytesPerSecond int64) *tokenBucket {
	if bytesPerSecond <= 0 {
		return nil
	}
	r := float64(bytesPerSecond)
	return &tokenBucket{
		rate:     r,
		capacity: r,
		tokens:   r,
		last:     time.Now(),
	}
}

// wait charges n bytes, blocking only for as long as the debt requires.
func (b *tokenBucket) wait(n int) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	if b.rate <= 0 {
		b.mu.Unlock()
		return
	}
	now := time.Now()
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	b.tokens -= float64(n)
	var sleep time.Duration
	if b.tokens < 0 {
		sleep = time.Duration(-b.tokens / b.rate * float64(time.Second))
	}
	b.mu.Unlock()

	// Slept outside the lock so one throttled user cannot stall the others.
	if sleep > 0 {
		time.Sleep(sleep)
	}
}

// onlineAddrs remembers which source addresses a user has been seen from - when
// each was last seen and how much it has carried - so the panel can count
// devices and tell a real one from an artefact.
//
// The byte count is the part that keeps this honest. A carrier that hands a
// phone a different egress address per query makes one device look like dozens,
// and a device limit then locks the customer out of the service they paid for -
// this is not hypothetical, it was measured at 22 "devices" for a single phone.
// Recording traffic per address lets the caller drop the addresses that carried
// almost nothing and keep the one or two doing real work.
//
// Bounded and self-pruning: entries older than the TTL are dropped on every
// read, and the map is capped - past the cap the address that has carried the
// least is evicted, so a pathological client costs memory once, not forever,
// and evicting never throws away the device that is actually in use.
type onlineAddrs struct {
	mu   sync.Mutex
	seen map[string]*addrUse
}

type addrUse struct {
	last  time.Time
	bytes int64
}

const (
	onlineAddrTTL = 2 * time.Minute
	onlineAddrCap = 64
)

// note records a sighting of ip carrying n bytes. n may be zero for a sighting
// with no payload of its own (a handshake).
func (o *onlineAddrs) note(ip string, now time.Time, n int64) {
	if o == nil || ip == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen == nil {
		o.seen = make(map[string]*addrUse, 4)
	}
	if use, known := o.seen[ip]; known {
		use.last = now
		use.bytes += n
		return
	}
	if len(o.seen) >= onlineAddrCap {
		// Evict the least-used address rather than the oldest: under per-query
		// address rotation the oldest entry can easily be the one real device,
		// simply because it has been there longest.
		var victim string
		var least int64
		for k, u := range o.seen {
			if victim == "" || u.bytes < least {
				victim, least = k, u.bytes
			}
		}
		delete(o.seen, victim)
	}
	o.seen[ip] = &addrUse{last: now, bytes: n}
}

// list returns the addresses seen within the TTL, pruning the rest.
func (o *onlineAddrs) list(now time.Time) []string {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(o.seen))
	for ip, use := range o.seen {
		if now.Sub(use.last) > onlineAddrTTL {
			delete(o.seen, ip)
			continue
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// traffic returns bytes carried per live address, clearing the counters when
// reset is true so each report covers one interval - the same contract the
// per-user counters use, and what the caller's threshold assumes.
func (o *onlineAddrs) traffic(now time.Time, reset bool) map[string]int64 {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.seen) == 0 {
		return nil
	}
	out := make(map[string]int64, len(o.seen))
	for ip, use := range o.seen {
		if now.Sub(use.last) > onlineAddrTTL {
			delete(o.seen, ip)
			continue
		}
		out[ip] = use.bytes
		if reset {
			use.bytes = 0
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
