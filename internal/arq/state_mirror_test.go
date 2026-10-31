package arq

import "testing"

// IsClosed and IsReset read atomic mirrors instead of taking a.mu. Through
// every transition that sets their fields they must still say what the
// fields say.
func TestClosedAndResetMirrorTheirFields(t *testing.T) {
	check := func(t *testing.T, a *ARQ, step string) {
		t.Helper()
		a.mu.RLock()
		closed := a.closed
		reset := a.state == StateReset || a.rstReceived || a.rstSent
		a.mu.RUnlock()
		if a.IsClosed() != closed || a.IsReset() != reset {
			t.Fatalf("%s: IsClosed %v IsReset %v, fields say %v %v", step, a.IsClosed(), a.IsReset(), closed, reset)
		}
	}
	for _, path := range []string{"rst-sent", "rst-received", "rst-acked", "close", "half-close-then-close"} {
		t.Run(path, func(t *testing.T) {
			a := NewARQ(1, 1, NewMockPacketEnqueuer(), nil, 1000, &testLogger{t}, Config{})
			check(t, a, "new")
			switch path {
			case "rst-sent":
				a.MarkRstSent()
			case "rst-received":
				a.MarkRstReceived()
			case "rst-acked":
				a.markRstAcked()
			case "half-close-then-close":
				a.mu.Lock()
				a.setState(StateHalfClosedLocal)
				a.mu.Unlock()
				check(t, a, "half-closed")
			}
			check(t, a, path)
			a.Close("test", CloseOptions{})
			check(t, a, path+" then close")
			if !a.IsClosed() {
				t.Fatal("not closed after Close")
			}
		})
	}
}
