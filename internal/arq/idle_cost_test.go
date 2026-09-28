package arq

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

// deadlineCountingConn counts how often ioLoop touches the local connection.
type deadlineCountingConn struct {
	net.Conn
	deadlines atomic.Int32
	reads     atomic.Int32
}

func (c *deadlineCountingConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

func (c *deadlineCountingConn) SetReadDeadline(t time.Time) error {
	c.deadlines.Add(1)
	return c.Conn.SetReadDeadline(t)
}

// An idle stream waits in one blocking read. It used to re-arm a 500 ms read
// deadline and read again, two syscalls a second on every idle stream.
func TestARQ_IdleStreamDoesNotPollItsLocalConnection(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	conn := &deadlineCountingConn{Conn: local}
	a := NewARQ(1, 1, NewMockPacketEnqueuer(), conn, 1000, &testLogger{t}, Config{WindowSize: 100, RTO: 0.2, MaxRTO: 1})
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	time.Sleep(1200 * time.Millisecond)
	if n := conn.reads.Load(); n != 1 {
		t.Fatalf("%d reads on an idle stream, want 1 blocking read", n)
	}
	if n := conn.deadlines.Load(); n != 0 {
		t.Fatalf("%d read deadlines set on an idle stream, want 0", n)
	}

	// Stopping local reads still ends that read at once.
	a.MarkCloseWriteReceived()
	deadline := time.Now().Add(time.Second)
	for conn.deadlines.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if conn.deadlines.Load() == 0 {
		t.Fatal("stopping local reads did not interrupt the blocked read")
	}
}

// A stream silent long enough checks its timers every couple of seconds, but
// data sent after the silence is still retransmitted on its RTO, not on the
// quiet tick.
func TestARQ_QuietStreamWakesForNewData(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	enq := NewMockPacketEnqueuer()
	a := NewARQ(1, 1, enq, local, 1000, &testLogger{t}, Config{WindowSize: 100, RTO: 0.1, MaxRTO: 0.2})
	a.Start()
	defer a.Close("test end", CloseOptions{Force: true})

	a.mu.Lock()
	a.lastActivity = time.Now().Add(-time.Minute)
	a.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for !a.rtxQuiet.Load() {
		if time.Now().After(deadline) {
			t.Fatal("an idle stream never entered quiet mode")
		}
		time.Sleep(10 * time.Millisecond)
	}

	go func() { _, _ = peer.Write([]byte("after the silence")) }()
	var sent time.Time
	for {
		select {
		case p := <-enq.Packets:
			if p.packetType != Enums.PACKET_STREAM_DATA && p.packetType != Enums.PACKET_STREAM_RESEND {
				continue
			}
			if sent.IsZero() {
				// The dispatcher would note the send; the mock does not.
				a.NoteTXPacketDequeued(p.packetType, p.sequenceNum, 0)
				sent = time.Now()
				continue
			}
			if took := time.Since(sent); took >= arqQuietCheckInterval {
				t.Fatalf("first retransmission after %v: it waited for the quiet tick", took)
			}
			return
		case <-time.After(1500 * time.Millisecond):
			t.Fatalf("no retransmission 1.5s after the send; the quiet tick is %v", arqQuietCheckInterval)
		}
	}
}
