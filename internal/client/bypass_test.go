package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBypassMatchesOnLabelBoundaries(t *testing.T) {
	m := NewBypassMatcher()
	m.Load([]string{"digikala.com", "ir"})

	for _, name := range []string{
		"digikala.com",
		"www.digikala.com",
		"a.b.digikala.com",
		"example.ir",
		"deep.sub.example.ir",
	} {
		if !m.Match(name) {
			t.Fatalf("expected %q to match", name)
		}
	}

	// The one that matters: a substring match would route a different owner's
	// traffic around the tunnel.
	for _, name := range []string{
		"notdigikala.com",
		"digikala.com.evil.net",
		"xdigikala.com",
		"example.com",
	} {
		if m.Match(name) {
			t.Fatalf("expected %q NOT to match", name)
		}
	}
}

func TestBypassNormalisesWrittenRules(t *testing.T) {
	m := NewBypassMatcher()
	// mihomo writes suffix rules as "+.example.com"; a trailing dot is how a
	// name arrives from the wire; case is not significant in DNS.
	m.Load([]string{"+.Example.COM", "  aparat.com.  ", "*.snapp.ir", "# comment", ""})

	if got := m.Len(); got != 3 {
		t.Fatalf("expected 3 rules, got %d", got)
	}
	for _, name := range []string{"www.example.com", "APARAT.COM", "x.snapp.ir"} {
		if !m.Match(name) {
			t.Fatalf("expected %q to match", name)
		}
	}
}

func TestBypassEmptyMatcherMatchesNothing(t *testing.T) {
	// Bypassing is an explicit choice: an empty rule set must tunnel
	// everything rather than fall open.
	m := NewBypassMatcher()
	if m.Match("digikala.com") {
		t.Fatal("empty matcher must not match")
	}
	var nilMatcher *BypassMatcher
	if nilMatcher.Match("digikala.com") {
		t.Fatal("nil matcher must not match")
	}
}

func TestBypassMissingFileEmptiesRatherThanKeepingStale(t *testing.T) {
	m := NewBypassMatcher()
	m.Load([]string{"digikala.com"})

	// ⚠️ A file that has gone away must clear the rules, not leave the previous
	// ones in force - otherwise turning bypass off in the app would appear to
	// do nothing until the process restarted.
	if _, err := m.LoadFile(filepath.Join(t.TempDir(), "absent.txt")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if m.Match("digikala.com") {
		t.Fatal("rules survived a failed load")
	}
}

func TestBypassLoadsFromFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bypass.txt")
	body := "# domestic\n+.digikala.com\naparat.com\n\n   \nsnapp.ir # inline comment\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewBypassMatcher()
	n, err := m.LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected 3 rules, got %d", n)
	}
	if !m.Match("cdn.digikala.com") || !m.Match("snapp.ir") {
		t.Fatal("expected file rules to match")
	}
	if m.Match("google.com") {
		t.Fatal("unrelated name matched")
	}
}
