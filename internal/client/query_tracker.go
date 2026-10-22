package client

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	queryTrackerMinExpiry     = 300 * time.Millisecond
	queryTrackerInitialExpiry = 3 * time.Second
	queryTrackerMaxExpiry     = 30 * time.Second
	queryTrackerSweepGap      = 50 * time.Millisecond
	queryTrackerMaxEntries    = 4096
)

type queryKey struct {
	id        uint16
	resolver  netip.AddrPort
	localAddr string
}

type queryEntry struct {
	sentAt    int64 // UnixNano
	expiresAt int64
	copies    int
	ambiguous bool
}

type queryTiming struct {
	srtt   time.Duration
	rttvar time.Duration
}

func (p *queryTiming) observe(rtt time.Duration) {
	if rtt > queryTrackerMaxExpiry {
		rtt = queryTrackerMaxExpiry
	}
	if p.srtt == 0 {
		p.srtt, p.rttvar = rtt, rtt/2
		return
	}
	delta := p.srtt - rtt
	if delta < 0 {
		delta = -delta
	}
	p.rttvar += (delta - p.rttvar) / 4
	p.srtt += (rtt - p.srtt) / 8
}

func (p queryTiming) expiry() time.Duration {
	if p.srtt == 0 {
		return queryTrackerInitialExpiry
	}
	expiry := p.srtt + 4*p.rttvar
	if expiry < queryTrackerMinExpiry {
		expiry = queryTrackerMinExpiry
	}
	if expiry > queryTrackerMaxExpiry {
		expiry = queryTrackerMaxExpiry
	}
	return expiry
}

func queryResolverEndpoint(addr *net.UDPAddr) netip.AddrPort {
	endpoint := addr.AddrPort()
	// ParseIP and UDP reads can represent the same IPv4 address differently.
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
}

// queryTracker bounds the download polls in flight. Responses are matched to
// their resolver and local socket as well as their DNS ID: duplicated replies
// on one path must not consume another path's outstanding queries.
type queryTracker struct {
	mu          sync.Mutex
	pending     map[queryKey]queryEntry
	paths       map[netip.AddrPort]queryTiming
	outstanding int
	nextSweep   int64
}

func newQueryTracker() *queryTracker {
	return &queryTracker{
		pending: make(map[queryKey]queryEntry, 64),
		paths:   make(map[netip.AddrPort]queryTiming),
	}
}

func (q *queryTracker) sent(packet []byte, resolver *net.UDPAddr, localAddr string, now time.Time) {
	if q == nil || len(packet) < 2 || resolver == nil {
		return
	}
	key := queryKey{binary.BigEndian.Uint16(packet[:2]), queryResolverEndpoint(resolver), localAddr}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.outstanding >= queryTrackerMaxEntries {
		// Throttle full-table scans too: an outage must not make each new
		// packet scan thousands of entries. This only limits accounting,
		// never the ARQ sends needed to recover the connection.
		q.sweepLocked(now.UnixNano())
		if q.outstanding >= queryTrackerMaxEntries {
			return
		}
	}
	e, exists := q.pending[key]
	if exists {
		e.copies++
		// Repeated IDs on the same path have ambiguous RTTs. Preserve the
		// first expiry so repeated sends cannot pin an entry indefinitely.
		e.ambiguous = true
	} else {
		e = queryEntry{
			sentAt:    now.UnixNano(),
			expiresAt: now.Add(q.paths[key.resolver].expiry()).UnixNano(),
			copies:    1,
		}
	}
	q.pending[key] = e
	q.outstanding++
}

func (q *queryTracker) answered(packet []byte, resolver *net.UDPAddr, localAddr string, now time.Time) {
	if q == nil || len(packet) < 2 || resolver == nil {
		return
	}
	key := queryKey{binary.BigEndian.Uint16(packet[:2]), queryResolverEndpoint(resolver), localAddr}
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.pending[key]
	if !ok {
		return
	}
	if rtt := time.Duration(now.UnixNano() - e.sentAt); rtt > 0 && !e.ambiguous {
		path, known := q.paths[key.resolver]
		if known || len(q.paths) < queryTrackerMaxEntries {
			path.observe(rtt)
			q.paths[key.resolver] = path
		}
	}
	e.copies--
	q.outstanding--
	if e.copies <= 0 {
		delete(q.pending, key)
	} else {
		q.pending[key] = e
	}
}

func (q *queryTracker) inFlight(now time.Time) int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sweepLocked(now.UnixNano())
	return q.outstanding
}

func (q *queryTracker) sweepLocked(nowNano int64) {
	if nowNano < q.nextSweep {
		return
	}
	q.nextSweep = nowNano + int64(queryTrackerSweepGap)
	for key, e := range q.pending {
		if e.expiresAt < nowNano {
			q.outstanding -= e.copies
			delete(q.pending, key)
		}
	}
}

func (q *queryTracker) reset() {
	if q == nil {
		return
	}
	q.mu.Lock()
	clear(q.pending)
	clear(q.paths)
	q.outstanding = 0
	q.nextSweep = 0
	q.mu.Unlock()
}
