package arq

import (
	"net"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

func countDataAcks(enq *MockPacketEnqueuer) int {
	n := 0
	for {
		select {
		case p := <-enq.Packets:
			if p.packetType == Enums.PACKET_STREAM_DATA_ACK {
				n++
			}
		default:
			return n
		}
	}
}

// The client closed its read side and the server acknowledged it, but the
// server keeps its own side open - a keep-alive connection the local app has
// already closed, which servers hold for minutes. The final ACK is repeated
// so that a lost one is recovered; it was repeated every 2 s for as long as
// the server stayed open, and each one counted as traffic, which kept the
// whole tunnel polling at its fastest rate while nothing was being used.
func TestARQ_FinalAckIsRepeatedForAWhileNotForever(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	enq := NewMockPacketEnqueuer()
	a := NewARQ(1, 1, enq, local, 1000, &testLogger{t}, Config{WindowSize: 100, RTO: 0.2, MaxRTO: 1, IsClient: true})

	start := time.Now()
	halfClosed := func(lastActivity time.Time) {
		a.mu.Lock()
		a.closeReadSent = true
		a.closeReadAcked = true
		a.rcvNxt = 5
		a.lastActivity = lastActivity
		a.lastDuplicateAckAt = time.Time{}
		a.mu.Unlock()
	}
	halfClosed(start)

	tick := func(from, to time.Duration) int {
		for at := from; at <= to; at += 500 * time.Millisecond {
			a.runFinalAckWatchdog(start.Add(at))
		}
		return countDataAcks(enq)
	}

	early := tick(0, 9*time.Second)
	if early < 3 {
		t.Fatalf("%d final ACKs in the first 9 s of silence, want it repeated (a lost one must be recovered)", early)
	}
	late := tick(9*time.Second+500*time.Millisecond, 10*time.Minute)
	if late > 2 {
		t.Fatalf("%d more final ACKs over the next ten minutes of silence; it must stop", late)
	}

	// New activity on the stream starts the repeats again.
	restart := start.Add(10 * time.Minute)
	halfClosed(restart)
	start = restart
	if again := tick(0, 9*time.Second); again < 3 {
		t.Fatalf("%d final ACKs after new activity, want them repeated again", again)
	}
}
