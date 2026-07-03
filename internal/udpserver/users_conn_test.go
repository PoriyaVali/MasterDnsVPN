package udpserver

import (
	"io"
	"net"
	"testing"
)

// fakeConn is a minimal net.Conn: Read drains a buffer, Write counts bytes.
type fakeConn struct {
	net.Conn
	readData []byte
	written  int
}

func (f *fakeConn) Read(p []byte) (int, error) {
	if len(f.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(p, f.readData)
	f.readData = f.readData[n:]
	return n, nil
}

func (f *fakeConn) Write(p []byte) (int, error) {
	f.written += len(p)
	return len(p), nil
}

func TestCountingConn_MetersPerUser(t *testing.T) {
	r := newUserRegistry([]byte("s"))
	r.add("A")
	acc := r.lookup(DeriveUserToken(r.secret, "A"))

	fc := &fakeConn{readData: []byte("hello-download")} // 14 bytes down
	wrapped := wrapUserCounting(fc, acc)

	buf := make([]byte, 64)
	n, _ := wrapped.Read(buf) // download
	if n != 14 {
		t.Fatalf("read n = %d, want 14", n)
	}
	upPayload := []byte("client-upload") // 13 bytes up
	if _, err := wrapped.Write(upPayload); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := acc.down.Load(); got != 14 {
		t.Fatalf("download counted = %d, want 14", got)
	}
	if got := acc.up.Load(); got != 13 {
		t.Fatalf("upload counted = %d, want 13", got)
	}

	// The metered bytes surface through Traffic().
	samples := r.sample(false)
	if len(samples) != 1 || samples[0].UUID != "A" || samples[0].Upload != 13 || samples[0].Download != 14 {
		t.Fatalf("Traffic() sample wrong: %+v", samples)
	}
}

func TestWrapUserCounting_NilUserPassesThrough(t *testing.T) {
	fc := &fakeConn{}
	if got := wrapUserCounting(fc, nil); got != net.Conn(fc) {
		t.Fatalf("nil user must return the original conn unwrapped")
	}
}
