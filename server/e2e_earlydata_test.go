package server_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	mdns "masterdnsvpn-go/server"
)

// startNodeTo runs a node whose every connection goes to target.
func startNodeTo(t *testing.T, target string, disableEarlyData bool) *net.UDPAddr {
	t.Helper()
	egress := startEgressProxy(t, target)
	port := freeUDPPort(t)
	srv, err := mdns.New(mdns.Options{
		Domains:           []string{e2eDomain},
		UDPHost:           "127.0.0.1",
		UDPPort:           port,
		EncryptionMethod:  2,
		EncryptionKey:     e2eKey,
		NodeSecret:        e2eSecret,
		LogLevel:          "error",
		UseExternalSOCKS5: true,
		ForwardIP:         "127.0.0.1",
		ForwardPort:       egress,
		DisableEarlyData:  disableEarlyData,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.AddUser(e2eUUID)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return startRelay(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, &wireRecorder{})
}

// A node that does not offer early data (or predates it) is used exactly as
// before: the client answers the app's CONNECT only once the node has.
func TestE2E_EarlyDataOffNodeStillWorks(t *testing.T) {
	body := e2eBody(t)
	relay := startNodeTo(t, startTarget(t, body), true)
	port := startClient(t, relay, "")
	if got := fetch(t, port); !bytes.Equal(got, body) {
		t.Fatal("body differs")
	}
}

// With early data the app is told "connected" at once; a target that then
// cannot be reached must close the connection promptly - not leave the app
// waiting, and not write a SOCKS error into what it reads as data.
func TestE2E_EarlyDataFailedConnectClosesTheConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close() // nothing listens here any more

	relay := startNodeTo(t, closed, false)
	port := startClient(t, relay, "")

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		t.Fatal(err)
	}
	host := "gone.e2e.example"
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = binary.BigEndian.AppendUint16(req, 80)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("no SOCKS reply: %v", err)
	}
	if reply[1] != 0 {
		t.Fatalf("early data is on, so the reply should be an early success; got %v", reply)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: gone\r\n\r\n"))

	start := time.Now()
	rest, err := io.ReadAll(c)
	if len(rest) != 0 {
		t.Fatalf("the app read %d bytes from a connection that never opened: %q", len(rest), rest)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection to an unreachable target was left open for %v", time.Since(start))
	}
}
