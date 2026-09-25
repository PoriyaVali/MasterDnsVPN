package client

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
)

// CIDRMatcher decides which destination addresses leave directly instead of
// going into the tunnel.
//
// Why this exists (2026-09-25): on Android the home country's ranges used to
// be subtracted from the VPN's routes. Iran's 2,782 ranges became thousands of
// routes, and Android hands a VPN's whole route table to every app that
// watches the network - measured on a phone at 1.4 MB for 10,153 routes, past
// binder's 1 MB limit. The system lost track of the VPN: no key icon, never
// validated, apps' network callbacks failing. sing-box's documentation says
// the same of its Android client ("VpnService not being able to handle a large
// number of routes"). So the list is matched here instead, and the TUN keeps a
// single default route.
//
// The connection leaves from this process, which the app has already kept out
// of its own VPN; the protect control is the second safety net, exactly as for
// the resolver sockets.
//
// 🔑 Ranges are merged and searched with a binary search, so a lookup costs
// log2(n) comparisons however long the list is - it runs on every CONNECT.
type CIDRMatcher struct {
	mu     sync.RWMutex
	ranges []addrRange // sorted by start, non-overlapping
}

type addrRange struct{ start, end netip.Addr }

// NewCIDRMatcher builds an empty matcher. Empty matches nothing: bypassing is
// an explicit choice, as with names.
func NewCIDRMatcher() *CIDRMatcher { return &CIDRMatcher{} }

// LoadFile replaces the ranges from a newline-separated file of CIDRs.
//
// ⚠️ Same rule as the name list: an unreadable file empties the matcher rather
// than failing, because tunnelling everything is a safe fallback and refusing
// to start is not. Malformed lines are skipped, not fatal - one bad line in a
// list of thousands must not cost the user the rest.
func (m *CIDRMatcher) LoadFile(path string) (int, error) {
	if m == nil || path == "" {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		m.replace(nil)
		return 0, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		m.replace(nil)
		return 0, err
	}
	return m.Load(lines), nil
}

// Load replaces the ranges from an in-memory list. Returns how many entries
// parsed; overlapping entries still count once each here.
func (m *CIDRMatcher) Load(lines []string) int {
	if m == nil {
		return 0
	}
	var rs []addrRange
	for _, line := range lines {
		if r, ok := parseBypassCIDR(line); ok {
			rs = append(rs, r)
		}
	}
	n := len(rs)
	m.replace(mergeRanges(rs))
	return n
}

// Contains reports whether ip falls in one of the ranges. An IPv4-mapped IPv6
// address is looked up as the IPv4 address it carries.
func (m *CIDRMatcher) Contains(ip net.IP) bool {
	if m == nil || ip == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return m.ContainsAddr(addr)
}

// ContainsAddr is Contains for a netip.Addr.
func (m *CIDRMatcher) ContainsAddr(addr netip.Addr) bool {
	if m == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	m.mu.RLock()
	rs := m.ranges
	m.mu.RUnlock()
	// First range whose end is not below addr; it holds addr iff it starts at
	// or before it. Ranges never overlap, so no other range can.
	i := sort.Search(len(rs), func(i int) bool { return rs[i].end.Compare(addr) >= 0 })
	return i < len(rs) && rs[i].start.Compare(addr) <= 0
}

// Len is the number of merged ranges.
func (m *CIDRMatcher) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ranges)
}

func (m *CIDRMatcher) replace(rs []addrRange) {
	m.mu.Lock()
	m.ranges = rs
	m.mu.Unlock()
}

// parseBypassCIDR accepts "a.b.c.d/n", "x::/n" and a bare address (a single
// host). Comments start with '#'.
func parseBypassCIDR(line string) (addrRange, bool) {
	s := strings.TrimSpace(line)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return addrRange{}, false
	}
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return addrRange{}, false
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return addrRange{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		// "::ffff:1.2.3.0/120" is 1.2.3.0/24; keep one representation.
		bits := p.Bits() - 96
		if bits < 0 {
			return addrRange{}, false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), bits)
	}
	p = p.Masked()
	return addrRange{start: p.Addr(), end: lastAddr(p)}, true
}

// lastAddr is the highest address in p: the network address with every host
// bit set.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		for bit := 0; bit < 8; bit++ {
			if i*8+bit >= bits {
				b[i] |= 0x80 >> bit
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// mergeRanges sorts and joins overlapping or touching ranges, so the search
// can assume they are disjoint. IPv4 sorts before IPv6 (netip's order), and a
// range never spans the two families, so they never merge with each other.
func mergeRanges(rs []addrRange) []addrRange {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].start.Compare(rs[j].start) < 0 })
	out := make([]addrRange, 0, len(rs))
	cur := rs[0]
	for _, r := range rs[1:] {
		next := cur.end.Next()
		sameFamily := r.start.Is4() == cur.start.Is4()
		if sameFamily && (r.start.Compare(cur.end) <= 0 || (next.IsValid() && r.start == next)) {
			if r.end.Compare(cur.end) > 0 {
				cur.end = r.end
			}
			continue
		}
		out = append(out, cur)
		cur = r
	}
	return append(out, cur)
}
