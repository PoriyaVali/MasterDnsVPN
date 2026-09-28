package udpserver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
)

// runTestServer starts a full server on a free loopback port and returns the
// port. tweak adjusts the config before it is finalized.
func runTestServer(t *testing.T, tweak func(*config.ServerConfig)) int {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	cfg := config.DefaultServerConfig()
	cfg.Domain = []string{"vpn.example.com"}
	cfg.UDPHost = "127.0.0.1"
	cfg.UDPPort = port
	cfg.UDPReaders = 1
	cfg.LogLevel = "ERROR"
	if tweak != nil {
		tweak(&cfg)
	}
	cfg, err = config.FinalizeServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	port = cfg.UDPPort
	codec, err := security.NewCodec(cfg.DataEncryptionMethod, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, logger.New("test", "ERROR"), codec)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})

	// Wait for the UDP side, which is always up.
	query := buildTestDNSQuery(1, "vpn.example.com", Enums.DNS_RECORD_TYPE_A)
	for i := 0; i < 100; i++ {
		if _, err := udpExchange(port, query); err == nil {
			return port
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server never answered over UDP")
	return 0
}

func udpExchange(port int, query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	return buf[:n], err
}

func writeTCPQuery(t *testing.T, conn net.Conn, query []byte) {
	t.Helper()
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		t.Fatal(err)
	}
}

func readTCPResponse(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		t.Fatalf("reading length: %v", err)
	}
	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		t.Fatalf("reading message: %v", err)
	}
	return msg
}

// A resolver that falls back to TCP gets the same answers as over UDP, and
// may pipeline queries on one connection.
func TestServerAnswersPipelinedQueriesOverTCP(t *testing.T) {
	port := runTestServer(t, nil)

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("no TCP listener: %v", err)
	}
	defer conn.Close()

	want := map[uint16]uint16{
		0x1001: Enums.DNSR_CODE_NAME_ERROR, // below the tunnel domain
		0x1002: Enums.DNSR_CODE_NO_ERROR,   // the tunnel domain itself
		0x1003: Enums.DNSR_CODE_NAME_ERROR, // not our domain
	}
	writeTCPQuery(t, conn, buildTestDNSQuery(0x1001, "probe.vpn.example.com", Enums.DNS_RECORD_TYPE_A))
	writeTCPQuery(t, conn, buildTestDNSQuery(0x1002, "vpn.example.com", Enums.DNS_RECORD_TYPE_A))
	writeTCPQuery(t, conn, buildTestDNSQuery(0x1003, "example.org", Enums.DNS_RECORD_TYPE_A))

	for range want {
		msg := readTCPResponse(t, conn)
		id := binary.BigEndian.Uint16(msg[0:2])
		rcode, ok := want[id]
		if !ok {
			t.Fatalf("unexpected or repeated answer id %#x", id)
		}
		delete(want, id)
		flags := binary.BigEndian.Uint16(msg[2:4])
		if flags&0x000F != rcode || flags&(1<<10) == 0 {
			t.Fatalf("id %#x: flags=%#04x, want rcode %d with AA", id, flags, rcode)
		}
	}
}

// A client that sends its query and half-closes still gets the answer.
func TestServerAnswersTCPQueryAfterHalfClose(t *testing.T) {
	port := runTestServer(t, nil)
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writeTCPQuery(t, conn, buildTestDNSQuery(0x2001, "vpn.example.com", Enums.DNS_RECORD_TYPE_A))
	_ = conn.(*net.TCPConn).CloseWrite()
	msg := readTCPResponse(t, conn)
	if binary.BigEndian.Uint16(msg[0:2]) != 0x2001 {
		t.Fatal("wrong answer")
	}
}

func TestServerTCPCanBeDisabled(t *testing.T) {
	port := runTestServer(t, func(cfg *config.ServerConfig) { cfg.TCPEnabled = false })
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("TCP listener is up although TCP_ENABLED = false")
	}
}

// Someone else holding the TCP port must not take the UDP tunnel down.
func TestServerKeepsUDPWhenTCPPortIsTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := taken.Addr().(*net.TCPAddr).Port

	runTestServer(t, func(cfg *config.ServerConfig) { cfg.UDPPort = port })
}
