package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

// newBypassTestClient is a client with nothing but the SOCKS front and a
// bypass list. It has no session and no streams, so anything that reached
// the tunnel path would fail - the tests below passing is itself the proof
// that a bypassed address never did.
func newBypassTestClient(ranges ...string) *Client {
	m := NewCIDRMatcher()
	m.Load(ranges)
	return &Client{
		cfg:         config.ClientConfig{SOCKSUDPAssociateReadTimeoutSeconds: 5},
		log:         logger.New("TestLogger", "debug"),
		bypassCIDRs: m,
	}
}

// socksPair returns both ends of a real loopback TCP connection, the second
// being served by c's SOCKS front.
func socksPair(t *testing.T, ctx context.Context, c *Client) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		srv, err := ln.Accept()
		if err == nil {
			c.HandleSOCKS5(ctx, srv)
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := cli.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(cli, greet); err != nil || greet[1] != 0 {
		t.Fatalf("greeting: %v %v", greet, err)
	}
	return cli
}

func socksRequest(cmd byte, addr *net.TCPAddr) []byte {
	req := []byte{5, cmd, 0, SOCKS5_ATYP_IPV4}
	req = append(req, addr.IP.To4()...)
	return binary.BigEndian.AppendUint16(req, uint16(addr.Port))
}

func TestDirectConnectRelaysBypassedAddress(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(conn, conn); _ = conn.Close() }()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newBypassTestClient("127.0.0.0/8")
	cli := socksPair(t, ctx, c)

	if _, err := cli.Write(socksRequest(SOCKS5_CMD_CONNECT, echo.Addr().(*net.TCPAddr))); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(cli, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != SOCKS5_REPLY_SUCCESS {
		t.Fatalf("reply code %d, want success", reply[1])
	}
	if _, err := cli.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(cli, got); err != nil || string(got) != "hello" {
		t.Fatalf("echo = %q, %v", got, err)
	}
}

func TestDirectConnectReportsAFailedDial(t *testing.T) {
	// A port nothing listens on: bind one, then close it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().(*net.TCPAddr)
	_ = l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := socksPair(t, ctx, newBypassTestClient("127.0.0.0/8"))
	if _, err := cli.Write(socksRequest(SOCKS5_CMD_CONNECT, dead)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(cli, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] == SOCKS5_REPLY_SUCCESS {
		t.Fatal("a refused dial was reported as success")
	}
}

func TestBypassTargetIgnoresDomainsAndOtherAddresses(t *testing.T) {
	c := newBypassTestClient("5.160.0.0/16")
	if _, ok := c.bypassTarget(SOCKS5_ATYP_DOMAIN, "5.160.1.1"); ok {
		t.Fatal("a domain-typed target must never be treated as an address")
	}
	if _, ok := c.bypassTarget(SOCKS5_ATYP_IPV4, "8.8.8.8"); ok {
		t.Fatal("an address outside the ranges was bypassed")
	}
	if _, ok := c.bypassTarget(SOCKS5_ATYP_IPV4, "5.160.1.1"); !ok {
		t.Fatal("an address inside the ranges was not bypassed")
	}
	if _, ok := (&Client{}).bypassTarget(SOCKS5_ATYP_IPV4, "5.160.1.1"); ok {
		t.Fatal("a client with no ranges bypassed something")
	}
}

// UDP to a bypassed address is relayed directly, and the reply comes back
// wrapped with the address it came from (RFC 1928 §7) - the association used
// to drop anything that was not DNS.
func TestUDPAssociateRelaysBypassedDatagrams(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], from)
		}
	}()
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := socksPair(t, ctx, newBypassTestClient("127.0.0.0/8"))
	if _, err := cli.Write(socksRequest(SOCKS5_CMD_UDP_ASSOCIATE, &net.TCPAddr{IP: net.IPv4zero})); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(cli, reply); err != nil || reply[1] != SOCKS5_REPLY_SUCCESS {
		t.Fatalf("associate reply %v, %v", reply, err)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}

	u, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	hdr := []byte{0, 0, 0, SOCKS5_ATYP_IPV4}
	hdr = append(hdr, echoAddr.IP.To4()...)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(echoAddr.Port))
	if _, err := u.Write(append(append([]byte{}, hdr...), []byte("ping")...)); err != nil {
		t.Fatal(err)
	}
	_ = u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatalf("no reply through the direct relay: %v", err)
	}
	if !bytes.Equal(buf[:len(hdr)], hdr) || string(buf[len(hdr):n]) != "ping" {
		t.Fatalf("reply = % x, want header % x + ping", buf[:n], hdr)
	}
}
