package udpserver

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeUpstream answers UDP with udpFlags and, if tcpAnswer is set, TCP with
// the full answer, on one loopback port.
func fakeUpstream(t *testing.T, udpFlags uint16, tcpAnswer []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	port := pc.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := append([]byte(nil), buf[:n]...)
			binary.BigEndian.PutUint16(resp[2:4], udpFlags)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	if tcpAnswer != nil {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					var size [2]byte
					if _, err := io.ReadFull(conn, size[:]); err != nil {
						return
					}
					query := make([]byte, binary.BigEndian.Uint16(size[:]))
					if _, err := io.ReadFull(conn, query); err != nil {
						return
					}
					resp := append([]byte(nil), tcpAnswer...)
					copy(resp[0:2], query[0:2])
					framed := make([]byte, 2+len(resp))
					binary.BigEndian.PutUint16(framed, uint16(len(resp)))
					copy(framed[2:], resp)
					_, _ = conn.Write(framed)
				}(conn)
			}
		}()
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func upstreamTestServer() *Server {
	s := &Server{}
	s.dnsUpstreamBufferPool.New = func() any {
		buf := make([]byte, 65535)
		return &buf
	}
	return s
}

func TestQueryOneUpstreamRetriesTruncatedAnswerOverTCP(t *testing.T) {
	full := make([]byte, 1400)
	binary.BigEndian.PutUint16(full[2:4], 0x8180)
	full[100] = 0x5A
	upstream := fakeUpstream(t, 0x8380, full) // QR RD TC RA
	query := buildTestDNSQuery(0x3131, "big.example.org", 16)

	got, err := upstreamTestServer().queryOneUpstream(upstream, query, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(full) || got[100] != 0x5A || got[2]&dnsFlagTC != 0 {
		t.Fatalf("got a %d-byte answer, want the full %d-byte TCP answer", len(got), len(full))
	}
	if binary.BigEndian.Uint16(got[0:2]) != 0x3131 {
		t.Fatal("answer id does not match the query")
	}
}

func TestQueryOneUpstreamKeepsTruncatedAnswerWithoutTCP(t *testing.T) {
	upstream := fakeUpstream(t, 0x8380, nil)
	query := buildTestDNSQuery(0x3232, "big.example.org", 16)

	got, err := upstreamTestServer().queryOneUpstream(upstream, query, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got[2]&dnsFlagTC == 0 || !bytes.Equal(got[4:], query[4:]) {
		t.Fatal("want the truncated UDP answer, TC bit intact")
	}
}

func TestQueryOneUpstreamUsesUDPAnswerWhenComplete(t *testing.T) {
	upstream := fakeUpstream(t, 0x8180, []byte("must not be asked"))
	query := buildTestDNSQuery(0x3333, "small.example.org", 1)

	got, err := upstreamTestServer().queryOneUpstream(upstream, query, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(query) || got[2]&dnsFlagTC != 0 {
		t.Fatal("a complete UDP answer must be returned as is")
	}
}
