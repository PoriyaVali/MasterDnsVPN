package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	dnsCache "masterdnsvpn-go/internal/dnscache"
)

func TestSocksUDPPeerMatchesMappedIPv4AndPinsPort(t *testing.T) {
	peer, err := newSocksUDPPeer(&net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 1234}, 0)
	if err != nil {
		t.Fatal(err)
	}
	first := &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 5678}
	if !peer.allowed(first) {
		t.Fatal("a mapped TCP peer must allow its IPv4 UDP socket, whose port differs from TCP")
	}
	if peer.allowed(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 5678}) {
		t.Fatal("another IP was allowed before the UDP port was known")
	}
	peer.pin(first)
	if !peer.allowed(&net.UDPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 5678}) {
		t.Fatal("mapped and ordinary IPv4 representations must keep matching after pinning")
	}
	if peer.allowed(&net.UDPAddr{IP: first.IP, Port: 5679}) {
		t.Fatal("an established association moved to another UDP socket")
	}
	declared, err := newSocksUDPPeer(&net.TCPAddr{IP: first.IP, Port: 1234}, 7777)
	if err != nil {
		t.Fatal(err)
	}
	if declared.allowed(first) || !declared.allowed(&net.UDPAddr{IP: first.IP, Port: 7777}) {
		t.Fatal("the request's declared UDP port was not enforced")
	}
}

func TestSocksUDPPeerRejectsUnverifiedAddress(t *testing.T) {
	for _, addr := range []net.Addr{nil, &net.TCPAddr{}, &net.TCPAddr{IP: net.IPv4zero}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}} {
		if _, err := newSocksUDPPeer(addr, 0); err == nil {
			t.Fatalf("unverified control peer %v was accepted", addr)
		}
	}
}

// A real SOCKS handshake and UDP association, with no resolver traffic or VPN.
func openTestUDPAssociation(t *testing.T, c *Client, declaredPort int) (net.Conn, *net.UDPAddr, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			c.HandleSOCKS5(ctx, conn)
		}
	}()
	control, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = control.Close()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("UDP association did not retire its control reader")
		}
	})
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(control, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatalf("SOCKS greeting %v: %v", greeting, err)
	}
	if _, err := control.Write(socksRequest(SOCKS5_CMD_UDP_ASSOCIATE, &net.TCPAddr{IP: net.IPv4zero, Port: declaredPort})); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(control, reply); err != nil || reply[1] != SOCKS5_REPLY_SUCCESS || reply[3] != SOCKS5_ATYP_IPV4 {
		t.Fatalf("SOCKS UDP reply %v: %v", reply, err)
	}
	_ = control.SetDeadline(time.Time{})
	return control, &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}, cancel, done
}

func udpTestSocket(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// needLoopbackAlias skips a test that needs a second loopback address. Linux
// and Windows answer on all of 127.0.0.0/8; macOS only on 127.0.0.1 unless
// lo0 has an alias, and there the test would fail on the host, not the code.
func needLoopbackAlias(t *testing.T, ip string) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Skipf("loopback address %s is not usable on this host: %v", ip, err)
	}
	_ = conn.Close()
}

func udpTestEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	echo := udpTestSocket(t, "127.0.0.1")
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], peer)
		}
	}()
	return echo.LocalAddr().(*net.UDPAddr)
}

func udpTestFrame(target *net.UDPAddr, payload []byte) []byte {
	packet := []byte{0, 0, 0, SOCKS5_ATYP_IPV4}
	packet = append(packet, target.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(target.Port))
	return append(packet, payload...)
}

func expectUDPReply(t *testing.T, client *net.UDPConn, relay *net.UDPAddr, packet []byte) []byte {
	t.Helper()
	if _, err := client.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("legitimate UDP peer received no reply: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
}

func expectNoUDPReply(t *testing.T, client *net.UDPConn, relay *net.UDPAddr, packet []byte) {
	t.Helper()
	if _, err := client.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n, _, err := client.ReadFromUDP(make([]byte, 4096)); err == nil {
		t.Fatalf("unowned UDP endpoint received %d response bytes", n)
	}
}

func TestUDPAssociationIsBoundToTCPInterface(t *testing.T) {
	needLoopbackAlias(t, "127.0.0.2")
	_, relay, _, _ := openTestUDPAssociation(t, newBypassTestClient("127.0.0.0/8"), 0)
	client := udpTestSocket(t, "127.0.0.1")
	packet := udpTestFrame(udpTestEcho(t), []byte("local-only"))
	otherInterface := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: relay.Port}
	expectNoUDPReply(t, client, otherInterface, packet)
	if got := expectUDPReply(t, client, relay, packet); !bytes.Equal(got, packet) {
		t.Fatalf("loopback relay changed direct UDP reply: %v", got)
	}
}

func TestUDPAssociationEnforcesDeclaredClientPort(t *testing.T) {
	client := udpTestSocket(t, "127.0.0.1")
	attacker := udpTestSocket(t, "127.0.0.1")
	_, relay, _, _ := openTestUDPAssociation(t, newBypassTestClient("127.0.0.0/8"), client.LocalAddr().(*net.UDPAddr).Port)
	packet := udpTestFrame(udpTestEcho(t), []byte("declared-port"))
	expectNoUDPReply(t, attacker, relay, packet)
	if got := expectUDPReply(t, client, relay, packet); !bytes.Equal(got, packet) {
		t.Fatal("declared UDP client could not use its association")
	}
}

func TestUDPAssociationPinsFirstValidPortAndRejectsMalformedClaim(t *testing.T) {
	_, relay, _, _ := openTestUDPAssociation(t, newBypassTestClient("127.0.0.0/8"), 0)
	client, attacker := udpTestSocket(t, "127.0.0.1"), udpTestSocket(t, "127.0.0.1")
	packet := udpTestFrame(udpTestEcho(t), []byte("first-valid-port"))
	for _, malformed := range [][]byte{
		{0, 0, 0, SOCKS5_ATYP_IPV4},
		{1, 0, 0, SOCKS5_ATYP_IPV4, 127, 0, 0, 1, 0, 53},
		{0, 1, 0, SOCKS5_ATYP_IPV4, 127, 0, 0, 1, 0, 53},
		{0, 0, 1, SOCKS5_ATYP_IPV4, 127, 0, 0, 1, 0, 53},
		{0, 0, 0, SOCKS5_ATYP_DOMAIN, 0, 0, 53},
	} {
		if _, err := attacker.WriteToUDP(malformed, relay); err != nil {
			t.Fatal(err)
		}
	}
	if got := expectUDPReply(t, client, relay, packet); !bytes.Equal(got, packet) {
		t.Fatal("malformed datagram claimed the unspecified client port")
	}
	expectNoUDPReply(t, attacker, relay, packet)
	if got := expectUDPReply(t, client, relay, packet); !bytes.Equal(got, packet) {
		t.Fatal("a second socket hijacked the established association")
	}
}

func TestUDPAssociationRejectsAnotherTCPPeerAddress(t *testing.T) {
	needLoopbackAlias(t, "127.0.0.2")
	_, relay, _, _ := openTestUDPAssociation(t, newBypassTestClient("127.0.0.0/8"), 0)
	attacker := udpTestSocket(t, "127.0.0.2")
	client := udpTestSocket(t, "127.0.0.1")
	packet := udpTestFrame(udpTestEcho(t), []byte("authenticated-ip"))
	expectNoUDPReply(t, attacker, relay, packet)
	if got := expectUDPReply(t, client, relay, packet); !bytes.Equal(got, packet) {
		t.Fatal("the TCP peer was denied after another IP tried to claim the relay")
	}
}

func TestUDPAssociationsDoNotStealEachOthersPeer(t *testing.T) {
	c := newBypassTestClient("127.0.0.0/8")
	_, relayA, _, _ := openTestUDPAssociation(t, c, 0)
	_, relayB, _, _ := openTestUDPAssociation(t, c, 0)
	a, b := udpTestSocket(t, "127.0.0.1"), udpTestSocket(t, "127.0.0.1")
	packet := udpTestFrame(udpTestEcho(t), []byte("independent-associations"))
	if !bytes.Equal(expectUDPReply(t, a, relayA, packet), packet) || !bytes.Equal(expectUDPReply(t, b, relayB, packet), packet) {
		t.Fatal("independent UDP associations could not relay")
	}
	expectNoUDPReply(t, b, relayA, packet)
	expectNoUDPReply(t, a, relayB, packet)
	if !bytes.Equal(expectUDPReply(t, a, relayA, packet), packet) || !bytes.Equal(expectUDPReply(t, b, relayB, packet), packet) {
		t.Fatal("cross-association traffic stole the legitimate UDP sockets")
	}
}

func TestUDPAssociationPreservesCachedDNS(t *testing.T) {
	c := createTestClient(t)
	c.sessionReady = true
	c.cfg.SOCKSUDPAssociateReadTimeoutSeconds = 5
	query := buildDNSListenerTestQuery(0x4242, "cached-association.example.org")
	answer := append([]byte(nil), query...)
	answer[2] |= 0x80
	answer[7] = 1 // A real cacheable A answer, with a 60-second TTL.
	answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 5)
	c.localDNSCache.SetReady(dnsCache.BuildKey("cached-association.example.org", 1, 1), "cached-association.example.org", 1, 1, answer, time.Now())
	_, relay, _, _ := openTestUDPAssociation(t, c, 0)
	client := udpTestSocket(t, "127.0.0.1")
	target := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	got := expectUDPReply(t, client, relay, udpTestFrame(target, query))
	if !bytes.Equal(got, udpTestFrame(target, answer)) {
		t.Fatalf("DNS reply header or transaction ID changed: % x", got)
	}
}

func TestUDPAssociationEndsWithControlConnectionOrContext(t *testing.T) {
	for _, cause := range []string{"tcp-close", "context-cancel"} {
		t.Run(cause, func(t *testing.T) {
			control, _, cancel, done := openTestUDPAssociation(t, newBypassTestClient("127.0.0.0/8"), 0)
			if cause == "tcp-close" {
				_ = control.Close()
			} else {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("association survived its TCP/context owner, waiting for the idle timeout")
			}
		})
	}
}
