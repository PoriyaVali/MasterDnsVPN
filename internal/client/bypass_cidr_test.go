package client

import (
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestCIDRMatcherBoundaries(t *testing.T) {
	m := NewCIDRMatcher()
	if n := m.Load([]string{"5.160.0.0/16", "2a01:5ec0::/29", "1.2.3.4"}); n != 3 {
		t.Fatalf("loaded %d, want 3", n)
	}
	cases := map[string]bool{
		"5.160.0.0":        true,
		"5.160.255.255":    true,
		"5.159.255.255":    false,
		"5.161.0.0":        false,
		"1.2.3.4":          true,
		"1.2.3.5":          false,
		"2a01:5ec0::1":     true,
		"2a01:5ec7:ffff::": true,
		"2a01:5ec8::":      false,
		// net.ParseIP gives IPv4 in its 16-byte mapped form; that must still
		// be looked up as IPv4.
		"::ffff:5.160.1.1": true,
	}
	for ip, want := range cases {
		if got := m.Contains(net.ParseIP(ip)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestCIDRMatcherKeepsFamiliesApart(t *testing.T) {
	m := NewCIDRMatcher()
	m.Load([]string{"0.0.0.0/0"})
	if m.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("an IPv4 range matched an IPv6 address")
	}
	if !m.Contains(net.ParseIP("255.255.255.255")) {
		t.Fatal("0.0.0.0/0 must contain the last IPv4 address")
	}
}

func TestCIDRMatcherMergesAndSkipsJunk(t *testing.T) {
	m := NewCIDRMatcher()
	n := m.Load([]string{
		"# a comment",
		"",
		"10.0.0.0/25",
		"10.0.0.128/25", // touching: one range
		"10.0.0.0/8",
		"10.1.0.0/16", // inside: one range
		"not-a-cidr",
		"300.1.1.1/8",
		"  192.168.0.0/24  # trailing comment",
	})
	if n != 5 {
		t.Fatalf("parsed %d entries, want 5", n)
	}
	if m.Len() != 2 {
		t.Fatalf("merged into %d ranges, want 2 (10/8 and 192.168.0/24)", m.Len())
	}
	if !m.Contains(net.ParseIP("192.168.0.200")) || m.Contains(net.ParseIP("192.168.1.1")) {
		t.Fatal("trailing comment broke the entry before it")
	}
}

// The binary search must agree with the obvious linear answer on any list.
func TestCIDRMatcherAgreesWithLinearScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var prefixes []netip.Prefix
	var lines []string
	for i := 0; i < 3000; i++ {
		var b [4]byte
		rng.Read(b[:])
		p := netip.PrefixFrom(netip.AddrFrom4(b), 8+rng.Intn(25)).Masked()
		prefixes = append(prefixes, p)
		lines = append(lines, p.String())
	}
	m := NewCIDRMatcher()
	m.Load(lines)
	for i := 0; i < 200000; i++ {
		var b [4]byte
		rng.Read(b[:])
		a := netip.AddrFrom4(b)
		want := false
		for _, p := range prefixes {
			if p.Contains(a) {
				want = true
				break
			}
		}
		if got := m.ContainsAddr(a); got != want {
			t.Fatalf("ContainsAddr(%s) = %v, linear scan says %v", a, got, want)
		}
	}
}

func TestCIDRMatcherLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ranges.txt")
	if err := os.WriteFile(path, []byte("5.160.0.0/16\n2a01:5ec0::/29\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewCIDRMatcher()
	if n, err := m.LoadFile(path); err != nil || n != 2 {
		t.Fatalf("LoadFile = %d, %v", n, err)
	}
	// A missing file empties the matcher: tunnel everything, never refuse to run.
	if _, err := m.LoadFile(path + ".missing"); err == nil {
		t.Fatal("missing file reported no error")
	}
	if m.Len() != 0 || m.Contains(net.ParseIP("5.160.1.1")) {
		t.Fatal("a failed load left old ranges in place")
	}
}

func TestNilAndEmptyMatcherMatchNothing(t *testing.T) {
	var m *CIDRMatcher
	if m.Contains(net.ParseIP("1.1.1.1")) || m.Len() != 0 {
		t.Fatal("nil matcher matched")
	}
	if NewCIDRMatcher().Contains(net.ParseIP("1.1.1.1")) {
		t.Fatal("empty matcher matched")
	}
}
