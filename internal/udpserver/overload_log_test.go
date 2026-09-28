package udpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"masterdnsvpn-go/internal/logger"
)

// A full table refuses every SESSION_INIT; the log reports that once per
// interval with a count, instead of one error line per refusal.
func TestSessionTableFullIsLoggedOncePerInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.log")
	s := &Server{log: logger.NewWithFile("test", "ERROR", path)}

	for i := 0; i < 1000; i++ {
		s.logSessionTableFull()
	}
	time.Sleep(50 * time.Millisecond)
	body, _ := os.ReadFile(path)
	lines := strings.Count(string(body), "Session Table Full")
	if lines != 1 {
		t.Fatalf("%d log lines for 1000 refusals, want 1", lines)
	}
	if !strings.Contains(string(body), "refused 1 ") {
		t.Fatalf("first report should count the refusal that triggered it: %q", body)
	}

	// The next report, one interval later, carries the refusals in between.
	s.sessionTableFullLastLog.Store(time.Now().Add(-sessionTableFullLogInterval).UnixNano())
	s.logSessionTableFull()
	time.Sleep(50 * time.Millisecond)
	body, _ = os.ReadFile(path)
	if !strings.Contains(string(body), "refused 1000 ") {
		t.Fatalf("second report should count the 999 held back plus this one: %q", body)
	}
}
