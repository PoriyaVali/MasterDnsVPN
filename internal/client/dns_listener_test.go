package client

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	dnsCache "masterdnsvpn-go/internal/dnscache"
	"masterdnsvpn-go/internal/dnstcp"
)

type dnsTempError struct {
	timeout   bool
	temporary bool
}

func (e dnsTempError) Error() string   { return "dns temp error" }
func (e dnsTempError) Timeout() bool   { return e.timeout }
func (e dnsTempError) Temporary() bool { return e.temporary }

func TestDNSListenerShouldRetryRead(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "closed", err: net.ErrClosed, want: false},
		{name: "timeout", err: dnsTempError{timeout: true}, want: true},
		{name: "temporary", err: dnsTempError{temporary: true}, want: true},
		{name: "permanent", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		if got := dnsListenerShouldRetryRead(tt.err); got != tt.want {
			t.Fatalf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}

// An application that retries over TCP (after a truncated answer, or because
// it only uses TCP) is answered on the same address as UDP.
func TestDNSListenerAnswersOverTCP(t *testing.T) {
	c := createTestClient(t)
	c.sessionReady = true

	query := buildDNSListenerTestQuery(0x4141, "cached.example.org")
	answer := append([]byte(nil), query...)
	answer[2] |= 0x80 // QR
	binary.BigEndian.PutUint16(answer[0:2], 0x9999)
	c.localDNSCache.SetReady(dnsCache.BuildKey("cached.example.org", 1, 1), "cached.example.org", 1, 1, answer, time.Now())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := NewDNSListener(c)
	if err := l.Start(ctx, "127.0.0.1", 0); err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	if l.tcp == nil {
		t.Fatal("no TCP listener")
	}

	conn, err := net.Dial("tcp", l.tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	framed, _ := dnstcp.Frame(query)
	if _, err := conn.Write(framed); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := dnstcp.ReadMessage(conn, buf)
	if err != nil {
		t.Fatalf("no answer over TCP: %v", err)
	}
	if n != len(answer) || binary.BigEndian.Uint16(buf[0:2]) != 0x4141 || buf[2]&0x80 == 0 {
		t.Fatalf("unexpected answer % x", buf[:n])
	}

	// Same port as UDP.
	if l.tcp.Addr().(*net.TCPAddr).Port != l.conn.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal("TCP and UDP listen on different ports")
	}
}

func buildDNSListenerTestQuery(id uint16, name string) []byte {
	q := []byte{0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(q[0:2], id)
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}
