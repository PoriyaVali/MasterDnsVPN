//go:build linux || benchcheck

package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"masterdnsvpn-go/internal/config"
)

// The production resolver loader deduplicates by IP, not by port. Give each
// simulated path a distinct loopback IP rather than changing that policy.
func relayIP(index int) net.IP { return net.IPv4(127, 0, 0, byte(index+2)) }

func validateResolverFixture(lines []string, want int) error {
	parsed, _, err := config.ParseClientResolvers(lines, "CPU benchmark fixture")
	if err != nil {
		return err
	}
	if len(parsed) != want {
		return fmt.Errorf("resolver fixture retained %d paths, want %d", len(parsed), want)
	}
	return nil
}

var (
	consoleEscapes = regexp.MustCompile(`\x1b\[[0-9;]*m|</?[a-z]+>`)
	activeSummary  = regexp.MustCompile(`Total valid resolvers after MTU testing:\s*(\d+)\s+of\s+(\d+)`)
)

// Reuse the real client's startup summary instead of assuming parsed paths
// passed MTU discovery. Refuse to measure an older binary with no summary.
func validateActiveResolvers(output string, want int) error {
	matches := activeSummary.FindAllStringSubmatch(consoleEscapes.ReplaceAllString(output, ""), -1)
	if len(matches) == 0 {
		return fmt.Errorf("client has no active-resolver summary; keep LOG_LEVEL=INFO")
	}
	last := matches[len(matches)-1]
	valid, _ := strconv.Atoi(last[1])
	total, _ := strconv.Atoi(last[2])
	if valid != want || total != want {
		return fmt.Errorf("client MTU discovery retained %d of %d paths, want %d of %d", valid, total, want, want)
	}
	return nil
}

type phaseResult struct {
	Phase      string        `json:"phase"`
	Wall       float64       `json:"wall_s"`
	NodeCPU    float64       `json:"node_cpu_s"`
	ClientCPU  float64       `json:"client_cpu_s"`
	Bytes      int64         `json:"bytes,omitempty"`
	MiBps      float64       `json:"mib_per_s,omitempty"`
	CPUmsPerMB float64       `json:"node_cpu_ms_per_mib,omitempty"`
	P50ms      float64       `json:"p50_ms,omitempty"`
	P95ms      float64       `json:"p95_ms,omitempty"`
	P99ms      float64       `json:"p99_ms,omitempty"`
	PktUp      int64         `json:"packets_up"`
	PktDown    int64         `json:"packets_down"`
	USPerPkt   float64       `json:"node_us_per_packet"`
	Errors     int64         `json:"errors"`
	Corrupt    int64         `json:"corrupt"`
	Samples    int           `json:"latency_samples,omitempty"`
	Paths      []pathTraffic `json:"paths"`
}

type pathTraffic struct {
	Address string `json:"address"`
	Up      int64  `json:"packets_up"`
	Down    int64  `json:"packets_down"`
}

func validatePhase(res phaseResult, expectedBytes int64, expectedSamples int) error {
	if res.Errors != 0 || res.Corrupt != 0 {
		return fmt.Errorf("%s: %d transfer errors, %d corrupt/incomplete transfers", res.Phase, res.Errors, res.Corrupt)
	}
	if res.Bytes != expectedBytes {
		return fmt.Errorf("%s: verified %d bytes, want %d", res.Phase, res.Bytes, expectedBytes)
	}
	if res.Samples != expectedSamples {
		return fmt.Errorf("%s: completed %d latency samples, want %d", res.Phase, res.Samples, expectedSamples)
	}
	return nil
}

func parseCPUSeconds(stat string) (float64, error) {
	// comm may itself contain spaces and parentheses. Fields after its final
	// ')' start at state (field 3); utime/stime are fields 14 and 15.
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, fmt.Errorf("missing process name terminator in /proc stat")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("short /proc stat: %d fields after process name", len(fields))
	}
	user, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid utime: %w", err)
	}
	system, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid stime: %w", err)
	}
	// Linux /proc reports these values in USER_HZ ticks (100 per second).
	return (float64(user) + float64(system)) / 100, nil
}
