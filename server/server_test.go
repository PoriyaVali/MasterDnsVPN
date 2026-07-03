package server

import (
	"strings"
	"testing"
)

func TestBridge_BuildAndManageUsers(t *testing.T) {
	s, err := New(Options{
		Domains:          []string{"tun.example.com"},
		UDPPort:          5599,
		EncryptionMethod: 2, // ChaCha20 -> 32-byte key
		EncryptionKey:    strings.Repeat("a", 32),
		NodeSecret:       "node-secret",
		LogLevel:         "error",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	s.AddUser("A")
	s.AddUser("B")
	s.AddUser("A") // idempotent
	if n := s.UserCount(); n != 2 {
		t.Fatalf("UserCount = %d, want 2", n)
	}
	s.DelUser("A")
	if n := s.UserCount(); n != 1 {
		t.Fatalf("UserCount after del = %d, want 1", n)
	}
	if tr := s.Traffic(false); len(tr) != 0 {
		t.Fatalf("no traffic expected yet, got %v", tr)
	}
}

func TestBridge_RejectsBadOptions(t *testing.T) {
	if _, err := New(Options{UDPPort: 5599, EncryptionKey: strings.Repeat("a", 32)}); err == nil {
		t.Fatalf("missing domain must error")
	}
	if _, err := New(Options{Domains: []string{"x.com"}, EncryptionKey: strings.Repeat("a", 32)}); err == nil {
		t.Fatalf("missing UDP port must error")
	}
}
