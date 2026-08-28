package client

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// BypassMatcher decides which names must not be resolved through the tunnel.
//
// Why this exists: the tunnel carries DNS inside DNS, which is the slowest and
// most fragile path this client has. Sending a domestic name through it costs a
// round trip over that path and answers from wherever the tunnel exits - so a
// site with regional CDNs hands back an address on the far side of the world,
// and the connection that follows is slow even when it is not tunnelled.
//
// 🔑 Matching is by suffix on label boundaries, not by substring. "digikala.com"
// must match "www.digikala.com" and must *not* match "notdigikala.com" - the
// second is a different owner, and a substring match would quietly route
// someone else's traffic around the tunnel.
type BypassMatcher struct {
	mu sync.RWMutex
	// Exact names and the suffixes they imply, lowercased and dot-trimmed.
	set map[string]struct{}
}

// NewBypassMatcher builds an empty matcher. An empty matcher matches nothing,
// which is the right default: bypassing is an explicit choice.
func NewBypassMatcher() *BypassMatcher {
	return &BypassMatcher{set: make(map[string]struct{})}
}

// LoadFile replaces the rule set from a newline-separated file.
//
// ⚠️ A missing or unreadable file empties the matcher rather than failing.
// Bypass is an optimisation; losing it must not stop the tunnel from starting,
// and a client that refuses to run because a hint file is absent is worse than
// one that tunnels everything.
func (m *BypassMatcher) LoadFile(path string) (int, error) {
	if m == nil || path == "" {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		m.replace(nil)
		return 0, err
	}
	defer func() { _ = f.Close() }()

	set := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	// Rule files are lists of names; a very long line is malformed, not a name.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if name := normalizeBypassRule(sc.Text()); name != "" {
			set[name] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		m.replace(nil)
		return 0, err
	}
	m.replace(set)
	return len(set), nil
}

// Load replaces the rule set from an in-memory list, for config-inline rules.
func (m *BypassMatcher) Load(rules []string) int {
	if m == nil {
		return 0
	}
	set := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if name := normalizeBypassRule(r); name != "" {
			set[name] = struct{}{}
		}
	}
	m.replace(set)
	return len(set)
}

func (m *BypassMatcher) replace(set map[string]struct{}) {
	if set == nil {
		set = make(map[string]struct{})
	}
	m.mu.Lock()
	m.set = set
	m.mu.Unlock()
}

// Len reports how many rules are loaded.
func (m *BypassMatcher) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.set)
}

// Match reports whether a queried name should skip the tunnel.
//
// Walks the name's own suffixes rather than every rule, so the cost is the
// number of labels in the query - a handful - instead of the size of the rule
// set, which is thousands.
func (m *BypassMatcher) Match(name string) bool {
	if m == nil {
		return false
	}
	n := normalizeBypassRule(name)
	if n == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.set) == 0 {
		return false
	}
	for {
		if _, ok := m.set[n]; ok {
			return true
		}
		// Next label boundary. Stopping at the last dot rather than trying the
		// bare TLD keeps a rule like "com" from being reachable by accident;
		// a genuine TLD rule still matches because it is tried on the way past.
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return false
		}
		n = n[i+1:]
	}
}

// normalizeBypassRule turns a written rule or a queried name into the form the
// set stores: lowercase, no trailing dot, no clash-style "+." prefix, no
// comment, no surrounding space.
func normalizeBypassRule(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return ""
	}
	// Rule sets in this project come from mihomo's lists, which write a suffix
	// rule as "+.example.com". The leading marker means the same thing this
	// matcher already does with every rule, so it is dropped rather than being
	// treated as part of the name.
	s = strings.TrimPrefix(s, "+.")
	s = strings.TrimPrefix(s, "*.")
	s = strings.Trim(s, ".")
	if s == "" {
		return ""
	}
	return strings.ToLower(s)
}
