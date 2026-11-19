package client

import (
	"fmt"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
)

func TestPatientProbeTimeoutIsThreeTimesTheConfiguredWithinBounds(t *testing.T) {
	for _, tc := range []struct{ base, want time.Duration }{
		{500 * time.Millisecond, patientProbeTimeoutMin},
		{1500 * time.Millisecond, 4500 * time.Millisecond},
		{2 * time.Second, 6 * time.Second},
		{5 * time.Second, patientProbeTimeoutMax},
	} {
		if got := patientProbeTimeout(tc.base); got != tc.want {
			t.Fatalf("patientProbeTimeout(%v) = %v, want %v", tc.base, got, tc.want)
		}
	}
}

// A long list kept MTU_TEST_TIMEOUT - 1.5 s from the app - for rechecks, so a
// resolver answering in two seconds could never come back.
func TestRechecksOfALongListWaitLongEnoughForASlowResolver(t *testing.T) {
	keys := make([]string, 40)
	for i := range keys {
		keys[i] = fmt.Sprintf("r%02d", i)
	}
	c := buildTestClientWithResolvers(config.ClientConfig{MTUTestTimeout: 1.5}, keys...)
	if got := c.resolverHealthProbeTimeout(); got < 4*time.Second {
		t.Fatalf("recheck probe timeout with 40 active resolvers: %v, want at least 4s", got)
	}
}

func TestTheScanUsesThePatientTimeoutOnlyDuringThePatientPass(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{MTUTestTimeout: 1.5}, "a", "b")
	if got := c.mtuProbeTimeout(); got != 1500*time.Millisecond {
		t.Fatalf("scan probe timeout %v, want the configured 1.5s", got)
	}
	c.mtuPatientTimeout.Store(int64(4500 * time.Millisecond))
	if got := c.mtuProbeTimeout(); got != 4500*time.Millisecond {
		t.Fatalf("scan probe timeout during the patient pass %v, want 4.5s", got)
	}
}
