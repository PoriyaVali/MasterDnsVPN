package udpserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// A name that resolves to this node's own loopback or private network must be
// refused exactly as the literal address is - the check has to judge what the
// name points at, not how it is spelled.
func TestDialDirectSOCKSTarget_RefusesNamesPointingInside(t *testing.T) {
	for _, inside := range []string{
		"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "0.1.2.3", "::1", "fe80::1", "::ffff:127.0.0.1",
	} {
		s := newTestServerForStreamSyn("SOCKS5")
		s.lookupTargetIPsFn = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(inside)}, nil
		}
		dialled := ""
		s.dialStreamUpstreamFn = func(network, address string, timeout time.Duration) (net.Conn, error) {
			dialled = address
			return nil, errors.New("must not dial")
		}

		_, err := s.dialSOCKSStreamTargetContext(context.Background(), "rebind.attacker.example", 80, []byte{0x03})
		var blocked *blockedSOCKSTargetError
		if !errors.As(err, &blocked) {
			t.Fatalf("%s: expected a blocked-target error, got %v", inside, err)
		}
		if dialled != "" {
			t.Fatalf("%s: dialled %s", inside, dialled)
		}
		if got := s.mapSOCKSConnectError(err); got == 0 {
			t.Fatalf("%s: no packet type for the refusal", inside)
		}
	}
}

// Only the addresses that passed the check are dialled, in order, and a dead
// first address does not stop the next one from being tried.
func TestDialDirectSOCKSTarget_DialsOnlyCheckedAddresses(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.lookupTargetIPsFn = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("10.0.0.5"),    // inside: skipped
			netip.MustParseAddr("203.0.113.7"), // dead
			netip.MustParseAddr("198.51.100.9"),
		}, nil
	}
	var dialled []string
	want := &net.TCPConn{}
	s.dialStreamUpstreamFn = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialled = append(dialled, address)
		if address == "203.0.113.7:443" {
			return nil, errors.New("connection refused")
		}
		return want, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := s.dialSOCKSStreamTargetContext(ctx, "cdn.example", 443, []byte{0x03})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn != want {
		t.Fatal("wrong connection returned")
	}
	if len(dialled) != 2 || dialled[0] != "203.0.113.7:443" || dialled[1] != "198.51.100.9:443" {
		t.Fatalf("dialled %v", dialled)
	}
}

func TestIsBlockedSOCKSTargetIP_PublicAddressesPass(t *testing.T) {
	for _, public := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if isBlockedSOCKSTargetIP(netip.MustParseAddr(public)) {
			t.Fatalf("%s was blocked", public)
		}
	}
}
