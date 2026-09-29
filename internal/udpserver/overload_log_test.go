package udpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"masterdnsvpn-go/internal/logger"
)

func refusalLines(t *testing.T, path string) []string {
	t.Helper()
	body, _ := os.ReadFile(path)
	var lines []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, "SESSION_INIT Refused") {
			lines = append(lines, line)
		}
	}
	return lines
}

func waitForRefusalLines(t *testing.T, path string, want int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		lines := refusalLines(t, path)
		if len(lines) >= want || time.Now().After(deadline) {
			return lines
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Refused SESSION_INITs are reported once per interval with counts, naming
// the limit that refused each, instead of one error line per refusal. A burst
// that stops is still reported in full at the end of its interval.
func TestRefusedSessionInitsAreReportedOncePerIntervalInFull(t *testing.T) {
	old := sessionInitRefusalLogInterval
	sessionInitRefusalLogInterval = 100 * time.Millisecond
	defer func() { sessionInitRefusalLogInterval = old }()

	path := filepath.Join(t.TempDir(), "node.log")
	store := newSessionStore(8, 32)
	store.maxActiveSessions = 100
	store.maxSessionsPerUser = 8
	s := &Server{log: logger.NewWithFile("test", "ERROR", path), sessions: store}
	t.Cleanup(func() { _ = s.log.Close() }) // before TempDir's cleanup removes the file

	for i := 0; i < 1000; i++ {
		s.noteRefusedSessionInit(i%4 == 0)
	}
	lines := waitForRefusalLines(t, path, 1)
	if len(lines) != 1 || !strings.Contains(lines[0], "Refused: 0 for a full session table (limit 100), 1 for a subscriber at their session limit (8)") {
		t.Fatalf("first report should be the one refusal that started the burst: %q", lines)
	}

	// The burst stopped; the rest must still be reported, once.
	lines = waitForRefusalLines(t, path, 2)
	if len(lines) != 2 || !strings.Contains(lines[1], "Refused: 750 for a full session table (limit 100), 249 for a subscriber at their session limit (8)") {
		t.Fatalf("held-back refusals were not reported in full: %q", lines)
	}
	time.Sleep(3 * sessionInitRefusalLogInterval)
	if n := len(refusalLines(t, path)); n != 2 {
		t.Fatalf("%d reports after the burst ended, want 2", n)
	}

	// After a quiet spell the next refusal is reported at once again.
	s.noteRefusedSessionInit(false)
	if lines := waitForRefusalLines(t, path, 3); len(lines) != 3 {
		t.Fatal("a refusal after a quiet spell was not reported")
	}
}
