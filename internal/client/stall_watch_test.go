package client

import (
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func silentSingleClient(t *testing.T) *Client {
	t.Helper()
	c := buildTestClientWithResolvers(config.ClientConfig{}, "r")
	c.runtimeReady.Store(true)
	c.successMTUChecks = true
	return c
}

func resetRequested(c *Client) bool {
	select {
	case <-c.sessionResetSignal:
		c.clearRuntimeResetRequest()
		return true
	default:
		return false
	}
}

// bringUpRuntime does what Client.Run does once a new session is up: no
// answer has been heard on it yet, and nothing has been sent either.
func bringUpRuntime(c *Client) {
	c.awaitingReplySince.Store(0)
	c.runtimeReady.Store(true)
}

// sendUnanswered makes the oldest unanswered send [age] old at [now].
func sendUnanswered(c *Client, now time.Time, age time.Duration) {
	c.awaitingReplySince.Store(now.Add(-age).UnixNano())
}

func TestSingleServerRestartsASessionThatWentSilent(t *testing.T) {
	c := silentSingleClient(t)
	now := time.Unix(1_700_000_000, 0)
	var w stallWatch

	sendUnanswered(c, now, 30*time.Second)
	c.watchStall(now, &w)
	if resetRequested(c) {
		t.Fatal("restarted 30s into a wait; the threshold is 45s")
	}

	sendUnanswered(c, now, time.Minute)
	c.watchStall(now, &w)
	if !resetRequested(c) {
		t.Fatal("a session silent for a minute was not restarted")
	}
	if !c.successMTUChecks {
		t.Fatal("the first recovery must not throw away the resolver scan")
	}

	c.watchStall(now.Add(30*time.Second), &w)
	if resetRequested(c) {
		t.Fatal("recovered again inside the gap")
	}
}

// The lifecycle Codex's review pointed at: the new session comes up (which
// stores awaitingReplySince=0), sends, and hears nothing again.
func TestASecondSilentSessionMeasuresTheResolversAgain(t *testing.T) {
	c := silentSingleClient(t)
	now := time.Unix(1_700_000_000, 0)
	var w stallWatch

	sendUnanswered(c, now, time.Minute)
	c.watchStall(now, &w)
	resetRequested(c)

	// Run brings the replacement up: nothing sent, nothing answered yet.
	bringUpRuntime(c)
	c.watchStall(now.Add(5*time.Second), &w)
	if resetRequested(c) {
		t.Fatal("recovered a session that has not sent anything yet")
	}

	// It sends, and the server stays silent past the gap.
	later := now.Add(singleStallRestartGap + time.Second)
	sendUnanswered(c, later, time.Minute)
	c.watchStall(later, &w)
	if !resetRequested(c) {
		t.Fatal("the second silent session was not recovered")
	}
	if c.successMTUChecks {
		t.Fatal("the second recovery in a row must measure the resolvers again; " +
			"bringing the runtime up must not count as an answer")
	}
}

func TestAnAnswerAfterARecoveryStartsTheCountAgain(t *testing.T) {
	c := silentSingleClient(t)
	now := time.Unix(1_700_000_000, 0)
	var w stallWatch

	sendUnanswered(c, now, time.Minute)
	c.watchStall(now, &w)
	resetRequested(c)

	// The new session works: the server answers.
	bringUpRuntime(c)
	c.lastInboundAt.Store(now.Add(3 * time.Second).UnixNano())
	c.watchStall(now.Add(4*time.Second), &w)

	// Much later it goes quiet once: a first recovery again, not a second.
	later := now.Add(10 * time.Minute)
	sendUnanswered(c, later, time.Minute)
	c.watchStall(later, &w)
	if !resetRequested(c) {
		t.Fatal("a later stall was not recovered")
	}
	if !c.successMTUChecks {
		t.Fatal("a stall after a working stretch rescanned as if recoveries had failed")
	}
}

func TestRecoveriesThatChangeNothingBackOff(t *testing.T) {
	c := silentSingleClient(t)
	t0 := time.Unix(1_700_000_000, 0)
	var w stallWatch

	at := t0
	var gaps []time.Duration
	for i := 0; i < 6; i++ {
		// Step a second at a time until the watch recovers again.
		for step := 0; step < 1000; step++ {
			sendUnanswered(c, at, time.Minute)
			c.watchStall(at, &w)
			if resetRequested(c) {
				break
			}
			at = at.Add(time.Second)
		}
		gaps = append(gaps, w.gap)
		bringUpRuntime(c)
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i := range want {
		if gaps[i] != want[i] {
			t.Fatalf("gap after recovery %d = %s, want %s (all: %v)", i+1, gaps[i], want[i], gaps)
		}
	}
}

func TestStallWatchLeavesPoolMembersToThePool(t *testing.T) {
	p := testPool(t, config.LoadBalancerLeastLoad, false, 1)
	c := p.members[0].client
	now := time.Unix(1_700_000_000, 0)
	var w stallWatch

	sendUnanswered(c, now, time.Minute)
	c.watchStall(now, &w)
	if resetRequested(c) {
		t.Fatal("a pool member was restarted by its own watch; the pool supervises it")
	}
}

func TestStallWatchIgnoresAClientThatIsNotRunning(t *testing.T) {
	c := silentSingleClient(t)
	c.runtimeReady.Store(false)
	now := time.Unix(1_700_000_000, 0)
	var w stallWatch

	sendUnanswered(c, now, time.Minute)
	c.watchStall(now, &w)
	if resetRequested(c) {
		t.Fatal("restarted a client whose runtime is not up")
	}
}

func TestAnInboundPacketIsTheEvidence(t *testing.T) {
	c := silentSingleClient(t)
	before := time.Now().UnixNano()
	c.NotifyPacket(0, true)
	if got := c.lastInboundAt.Load(); got < before {
		t.Fatalf("an inbound packet did not record lastInboundAt (got %d, before %d)", got, before)
	}
	last := c.lastInboundAt.Load()
	c.NotifyPacket(0, false)
	if c.lastInboundAt.Load() != last {
		t.Fatal("an outbound packet moved lastInboundAt")
	}
}
