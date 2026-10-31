package udpserver

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// Device accounting is keyed on the client's IP text, which used to come from
// net.IP.String. It must not change under a subscriber's feet.
func TestClientAddrTextMatchesNetIP(t *testing.T) {
	for _, s := range []string{
		"198.51.100.7", "::ffff:198.51.100.7", "0.0.0.0", "::", "::1",
		"2001:db8::1", "2001:db8:0:0:1:0:0:1", "2001:0db8:0000:0000:0000:ff00:0042:8329",
		"::1.2.3.4", "64:ff9b::192.0.2.33", "fe80::1%eth0",
	} {
		a := netip.MustParseAddr(s)
		want := net.IP(a.AsSlice()).String()
		if got := (clientAddr{addr: a}).String(); got != want {
			t.Errorf("%s: clientAddr gives %q, net.IP gave %q", s, got, want)
		}
	}
	if got := (clientAddr{}).String(); got != "" {
		t.Errorf("no address gives %q, want empty", got)
	}
	if got := (clientAddr{addr: netip.MustParseAddr("192.0.2.1"), text: "203.0.113.9"}).String(); got != "203.0.113.9" {
		t.Errorf("given text is replaced: %q", got)
	}
}

// An IPv4 client of a dual-stack socket, as a node listening on 0.0.0.0 has:
// its address reads IPv4-mapped, names the client as plain IPv4, and the
// answer written to it as read arrives.
func TestDualStackClientAddressRoundTrip(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Skip("no UDP:", err)
	}
	defer server.Close()
	port := server.LocalAddr().(*net.UDPAddr).Port
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, from, err := server.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "query" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}
	if got := (clientAddr{addr: from.Addr()}).String(); got != "127.0.0.1" {
		t.Fatalf("client named %q, want 127.0.0.1", got)
	}
	if _, err := server.WriteToUDPAddrPort([]byte("answer"), from); err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err = client.Read(buf); err != nil || string(buf[:n]) != "answer" {
		t.Fatalf("client got %q, %v", buf[:n], err)
	}
}
