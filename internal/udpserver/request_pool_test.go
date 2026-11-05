package udpserver

import (
	"net"
	"net/netip"
	"testing"
)

func newRequestPoolServer() *Server {
	s := &Server{}
	s.requestPool.New = func() any { return &request{buf: make([]byte, 512)} }
	return s
}

// A pooled request keeps its buffer and nothing else: not the socket, the TCP
// connection's reply or the address of the query it last carried.
func TestPutRequestKeepsOnlyTheBuffer(t *testing.T) {
	s := newRequestPoolServer()
	req := s.getRequest()
	buf := req.buf
	req.size = 64
	req.addr = netip.MustParseAddrPort("198.51.100.7:53")
	req.conn = &net.UDPConn{}
	req.reply = func([]byte) {}
	s.putRequest(req)
	if req.size != 0 || req.addr.IsValid() || req.conn != nil || req.reply != nil {
		t.Fatalf("pooled request keeps size %d, addr %v, conn %v, reply set %v", req.size, req.addr, req.conn, req.reply != nil)
	}
	if len(req.buf) != len(buf) || &req.buf[0] != &buf[0] {
		t.Fatal("pooled request lost its buffer")
	}
}

// Recycling a request allocates nothing. A []byte pooled by value allocated
// its slice header on every Put, once per packet.
func TestRequestRecyclingDoesNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector makes sync.Pool drop items on purpose")
	}
	s := newRequestPoolServer()
	s.putRequest(s.getRequest())
	if allocs := testing.AllocsPerRun(1000, func() { s.putRequest(s.getRequest()) }); allocs != 0 {
		t.Fatalf("a get/put cycle made %v allocations", allocs)
	}
}
