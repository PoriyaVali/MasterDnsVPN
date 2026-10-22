package udpserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
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

type closeRecorder struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeRecorder) Close() error {
	c.closed.Store(true)
	return nil
}

func lookupGives(addrs ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) {
		parsed := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			parsed = append(parsed, netip.MustParseAddr(a))
		}
		return parsed, nil
	}
}

// 🔴 The UK node's case, measured 2026-10-22: the lookup sorts IPv6 first and
// IPv6 never answers there, so a new connection to speed.cloudflare.com waited
// 7.5 s for two IPv6 attempts to time out before IPv4 was tried.
func TestDialDirectSOCKSTarget_IPv4DoesNotWaitForIPv6ThatNeverAnswers(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.lookupTargetIPsFn = lookupGives("2606:4700:7::da", "2a06:98c1:58::da", "162.159.140.220", "172.66.0.218")
	silent := make(chan struct{})
	defer close(silent)
	want := &net.TCPConn{}
	s.dialStreamUpstreamFn = func(network, address string, timeout time.Duration) (net.Conn, error) {
		if strings.HasPrefix(address, "[") {
			<-silent
			return nil, errors.New("i/o timeout")
		}
		return want, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := s.dialSOCKSStreamTargetContext(ctx, "speed.cloudflare.com", 80, []byte{0x03})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn != want {
		t.Fatal("wrong connection returned")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("connected after %s; IPv4 waited for IPv6", took)
	}
}

// The same with the families the other way round: whichever address goes
// first, one that never answers holds the next back by the fallback delay and
// no more.
func TestDialDirectSOCKSTarget_RacesPastAnAddressThatNeverAnswers(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.lookupTargetIPsFn = lookupGives("198.51.100.9", "2606:4700:7::da")
	silent := make(chan struct{})
	defer close(silent)
	want := &net.TCPConn{}
	s.dialStreamUpstreamFn = func(network, address string, timeout time.Duration) (net.Conn, error) {
		if address == "198.51.100.9:443" {
			<-silent
			return nil, errors.New("i/o timeout")
		}
		return want, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := s.dialSOCKSStreamTargetContext(ctx, "cdn.example", 443, []byte{0x03})
	took := time.Since(start)
	if err != nil || conn != want {
		t.Fatalf("conn=%v err=%v", conn, err)
	}
	if took < directTargetFallbackDelay || took > 2*time.Second {
		t.Fatalf("connected after %s; want the fallback delay (%s) and little more", took, directTargetFallbackDelay)
	}
}

// www.google.com from the UK node: more IPv6 addresses than attempts. IPv4
// must still get one.
func TestIPv4FirstInterleavedKeepsIPv4WithinTheAttempts(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("2a00:1450:4009:81f::2004"),
		netip.MustParseAddr("2a00:1450:4009:820::2004"),
		netip.MustParseAddr("2a00:1450:4009:821::2004"),
		netip.MustParseAddr("2a00:1450:4009:822::2004"),
		netip.MustParseAddr("142.250.200.4"),
		netip.MustParseAddr("142.250.200.36"),
	}
	got := ipv4FirstInterleaved(in)
	want := []string{
		"142.250.200.4", "2a00:1450:4009:81f::2004",
		"142.250.200.36", "2a00:1450:4009:820::2004",
		"2a00:1450:4009:821::2004", "2a00:1450:4009:822::2004",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// A slower address that connects after another one already won is closed, not
// leaked.
func TestDialDirectSOCKSTarget_ClosesALoserThatConnectsLate(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.lookupTargetIPsFn = lookupGives("198.51.100.9", "2606:4700:7::da")
	late := &closeRecorder{}
	want := &net.TCPConn{}
	s.dialStreamUpstreamFn = func(network, address string, timeout time.Duration) (net.Conn, error) {
		if address == "198.51.100.9:443" {
			time.Sleep(3 * directTargetFallbackDelay)
			return late, nil
		}
		return want, nil
	}

	conn, err := s.dialSOCKSStreamTargetContext(context.Background(), "cdn.example", 443, []byte{0x03})
	if err != nil || conn != want {
		t.Fatalf("conn=%v err=%v", conn, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !late.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the losing connection was never closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDialDirectSOCKSTarget_ReportsAFailureWhenNoAddressConnects(t *testing.T) {
	s := newTestServerForStreamSyn("SOCKS5")
	s.lookupTargetIPsFn = lookupGives("198.51.100.9", "203.0.113.7", "2606:4700:7::da")
	var mu sync.Mutex
	var dialled []string
	s.dialStreamUpstreamFn = func(network, address string, timeout time.Duration) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, address)
		mu.Unlock()
		return nil, errors.New("connection refused")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := s.dialSOCKSStreamTargetContext(ctx, "cdn.example", 443, []byte{0x03}); err == nil {
		t.Fatal("expected an error")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("refusals took %s; each one should start the next at once", took)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialled) != 3 {
		t.Fatalf("dialled %v, want all three", dialled)
	}
}
