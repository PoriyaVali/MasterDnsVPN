package dnscache

import (
	"encoding/binary"
	"time"
)

// How long a stored answer stays valid is decided by the answer itself, capped
// by the store's own TTL.
//
// 🔴 Why this exists. Expiry used to be measured from the last *read*, so an
// entry that was asked for at least once per TTL never expired at all. On a
// server that is every popular name, for every user of the node, until the
// process restarts: a CDN that moves an address, or a transient SERVFAIL that
// got stored, is served forever - the busier the name, the more certainly it
// sticks. Measured: a 5-minute TTL, read every 4 minutes, still answered after
// an hour.

const (
	// A positive answer is kept at least this long even when its records say
	// less. Every lookup a stub makes here can cost a round trip through a DNS
	// tunnel, and CDNs publish 20-60s TTLs for addresses that stay valid for
	// minutes; honouring a 0-5s TTL literally would turn one page load into a
	// stampede of identical tunnel queries.
	minPositiveLifetime = 30 * time.Second

	// A negative answer (NXDOMAIN / NODATA) without an SOA to say otherwise.
	defaultNegativeLifetime = 60 * time.Second

	dnsTypeSOA = 6
	dnsTypeOPT = 41

	rcodeNoError  = 0
	rcodeNXDomain = 3
)

// responseLifetime reports whether a raw DNS response may be stored and, when
// its records say, for how long. known=false means the response could not be
// read far enough to tell; the caller then falls back to its configured TTL,
// which is what every response got before this existed.
//
// Not cacheable:
//   - any error rcode other than NXDOMAIN. SERVFAIL and REFUSED describe the
//     resolver's moment, not the name; stored, one bad second becomes minutes
//     of failure for every user who asks.
//   - a truncated reply (TC). It is a prompt to retry over TCP, not an answer.
func responseLifetime(resp []byte) (lifetime time.Duration, known bool, cacheable bool) {
	if len(resp) < 12 {
		return 0, false, true
	}
	if resp[2]&0x02 != 0 { // TC
		return 0, false, false
	}
	rcode := resp[3] & 0x0F
	if rcode != rcodeNoError && rcode != rcodeNXDomain {
		return 0, false, false
	}

	qdCount := int(binary.BigEndian.Uint16(resp[4:6]))
	anCount := int(binary.BigEndian.Uint16(resp[6:8]))
	nsCount := int(binary.BigEndian.Uint16(resp[8:10]))

	off := 12
	for i := 0; i < qdCount; i++ {
		next, ok := skipDNSName(resp, off)
		if !ok || next+4 > len(resp) {
			return 0, false, true
		}
		off = next + 4
	}

	// Positive answer: the smallest TTL in the answer section.
	if rcode == rcodeNoError && anCount > 0 {
		minTTL := uint32(0)
		found := false
		for i := 0; i < anCount; i++ {
			rrType, ttl, _, next, ok := readRR(resp, off)
			if !ok {
				break
			}
			off = next
			if rrType == dnsTypeOPT {
				continue
			}
			if !found || ttl < minTTL {
				minTTL = ttl
				found = true
			}
		}
		if !found {
			return 0, false, true
		}
		lifetime = time.Duration(minTTL) * time.Second
		if lifetime < minPositiveLifetime {
			lifetime = minPositiveLifetime
		}
		return lifetime, true, true
	}

	// Negative answer: RFC 2308 - min(SOA TTL, SOA MINIMUM) from authority.
	for i := 0; i < anCount; i++ {
		_, _, _, next, ok := readRR(resp, off)
		if !ok {
			return defaultNegativeLifetime, true, true
		}
		off = next
	}
	for i := 0; i < nsCount; i++ {
		rrType, ttl, rdata, next, ok := readRR(resp, off)
		if !ok {
			break
		}
		off = next
		if rrType != dnsTypeSOA || len(rdata) < 4 {
			continue
		}
		negTTL := binary.BigEndian.Uint32(rdata[len(rdata)-4:])
		if ttl < negTTL {
			negTTL = ttl
		}
		return time.Duration(negTTL) * time.Second, true, true
	}
	return defaultNegativeLifetime, true, true
}

// skipDNSName returns the offset just past the name starting at off. A
// compression pointer ends the name in two bytes; nothing is followed, so a
// hostile pointer loop cannot make this spin.
func skipDNSName(msg []byte, off int) (int, bool) {
	for steps := 0; steps < 128; steps++ {
		if off >= len(msg) {
			return 0, false
		}
		labelLen := int(msg[off])
		switch {
		case labelLen == 0:
			return off + 1, true
		case labelLen&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		case labelLen&0xC0 != 0:
			return 0, false
		default:
			off += 1 + labelLen
		}
	}
	return 0, false
}

func readRR(msg []byte, off int) (rrType uint16, ttl uint32, rdata []byte, next int, ok bool) {
	off, ok = skipDNSName(msg, off)
	if !ok || off+10 > len(msg) {
		return 0, 0, nil, 0, false
	}
	rrType = binary.BigEndian.Uint16(msg[off : off+2])
	ttl = binary.BigEndian.Uint32(msg[off+4 : off+8])
	rdLen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	start := off + 10
	if start+rdLen > len(msg) {
		return 0, 0, nil, 0, false
	}
	return rrType, ttl, msg[start : start+rdLen], start + rdLen, true
}

// expiryFor is when an entry stored at `stored` stops being served.
func (s *Store) expiryFor(resp []byte, stored time.Time) (time.Time, bool) {
	lifetime, known, cacheable := responseLifetime(resp)
	if !cacheable {
		return time.Time{}, false
	}
	if !known || lifetime > s.cacheTTL {
		lifetime = s.cacheTTL
	}
	return stored.Add(lifetime), true
}
