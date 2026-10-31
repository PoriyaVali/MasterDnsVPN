//go:build linux || benchcheck

package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestResolverFixturePreservesEveryPath(t *testing.T) {
	var distinct, sameIP []string
	for i := 0; i < 4; i++ {
		distinct = append(distinct, fmt.Sprintf("%s:%d", relayIP(i), 5300+i))
		sameIP = append(sameIP, fmt.Sprintf("127.0.0.1:%d", 5300+i))
	}
	if err := validateResolverFixture(distinct, 4); err != nil {
		t.Fatal(err)
	}
	if err := validateResolverFixture(sameIP, 4); err == nil {
		t.Fatal("accepted the old fixture whose four ports collapse to one IP")
	}
}

func TestActiveResolverSummaryIsRequiredAndComplete(t *testing.T) {
	good := "Total valid resolvers after MTU testing: <cyan>4</cyan> of <cyan>4</cyan>"
	if err := validateActiveResolvers(good, 4); err != nil {
		t.Fatal(err)
	}
	colored := "Total valid resolvers after MTU testing: \x1b[36m4\x1b[0m of \x1b[36m4\x1b[0m"
	if err := validateActiveResolvers(colored, 4); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"", "Total valid resolvers after MTU testing: 1 of 1", good + "\nTotal valid resolvers after MTU testing: 3 of 4"} {
		if err := validateActiveResolvers(output, 4); err == nil {
			t.Fatalf("accepted missing or incomplete active paths: %q", output)
		}
	}
}

func TestPhaseValidationRejectsFailedOrIncompleteWork(t *testing.T) {
	good := phaseResult{Phase: "download", Bytes: 4096}
	if err := validatePhase(good, 4096, 0); err != nil {
		t.Fatal(err)
	}
	for _, result := range []phaseResult{
		{Phase: "download", Bytes: 4096, Errors: 1},
		{Phase: "download", Bytes: 4096, Corrupt: 1},
		{Phase: "download", Bytes: 4095},
		{Phase: "rtt", Samples: 9},
	} {
		bytes, samples := int64(4096), 0
		if result.Phase == "rtt" {
			bytes, samples = 0, 10
		}
		if err := validatePhase(result, bytes, samples); err == nil {
			t.Fatalf("accepted invalid phase: %+v", result)
		}
	}
}

func TestCPUCounterParsingRejectsUnavailableMeasurements(t *testing.T) {
	stat := func(user, system string) string {
		fields := []string{"S", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", user, system}
		return "123 (node (bench)) " + strings.Join(fields, " ")
	}
	for _, tc := range []struct {
		user, system string
		want         float64
	}{{"125", "75", 2}, {"0", "0", 0}} {
		got, err := parseCPUSeconds(stat(tc.user, tc.system))
		if err != nil || got != tc.want {
			t.Fatalf("CPU counters %s/%s: got %v, %v, want %v", tc.user, tc.system, got, err, tc.want)
		}
	}
	for _, input := range []string{"", "123 (missing close", "123 (short) S 0", stat("invalid", "0"), stat("0", "-1"), stat("18446744073709551616", "0")} {
		if _, err := parseCPUSeconds(input); err == nil {
			t.Fatalf("accepted malformed CPU measurement: %q", input)
		}
	}
}
