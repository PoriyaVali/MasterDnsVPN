package client

import (
	"context"
	"testing"
	"time"

	"masterdnsvpn-go/internal/mlq"
)

// The dispatcher's safety timer, at 20 ms, woke the process 50 times a
// second on a tunnel with nothing to send. It backs off while nothing arrives.
func TestDispatcherSafetyTimerBacksOffToASecond(t *testing.T) {
	base := 20 * time.Millisecond
	wait := base
	var steps []time.Duration
	for i := 0; i < 8; i++ {
		wait = nextDispatcherIdleWait(wait, base)
		steps = append(steps, wait)
	}
	want := []time.Duration{40, 80, 160, 320, 640, 1000, 1000, 1000}
	for i, ms := range want {
		if steps[i] != ms*time.Millisecond {
			t.Fatalf("backoff steps %v, want %v ms", steps, want)
		}
	}
	if got := nextDispatcherIdleWait(time.Second, 2*time.Second); got != 2*time.Second {
		t.Fatalf("a configured poll above the cap became %v; it must be kept", got)
	}
}

// A stream starts its loops before it joins the set: its first packet can be
// queued, and signalled, while the dispatcher cannot see the stream yet. The
// dispatcher woke, found nothing, and only its safety timer brought it back -
// harmless at 20 ms, up to a second once that timer backs off. Joining the
// set now wakes it.
func TestAPacketQueuedBeforeItsStreamJoinedGoesOutAtOnce(t *testing.T) {
	c := createTestClient(t)
	c.cfg.DispatcherIdlePollIntervalSeconds = 1.0
	c.dispatchSignal = make(chan struct{}, 1)
	c.plannerQueueSpaceSignal = make(chan struct{}, 1)
	c.plannerQueue = make(chan plannerTask, 4)
	c.active_streams = make(map[uint16]*Stream_client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.asyncWG.Add(1)
	go c.asyncStreamDispatcher(ctx)
	time.Sleep(50 * time.Millisecond) // waiting, with nothing to do

	stream := &Stream_client{client: c, StreamID: 1, txQueue: mlq.New[*clientStreamTXPacket](8)}
	if !stream.PushTXPacket(0, 0x99, 1, 0, 0, 0, 0, []byte("syn")) {
		t.Fatal("expected the packet to enqueue")
	}
	time.Sleep(50 * time.Millisecond) // the dispatcher looked and saw no stream

	c.streamsMu.Lock()
	c.active_streams[stream.StreamID] = stream
	c.streamsMu.Unlock()
	c.bumpStreamSetVersion()

	waitForCondition(t, 300*time.Millisecond, func() bool {
		return len(c.plannerQueue) == 1
	}, "the stream's first packet waited for the dispatcher's safety timer")

	cancel()
	c.asyncWG.Wait()
}
