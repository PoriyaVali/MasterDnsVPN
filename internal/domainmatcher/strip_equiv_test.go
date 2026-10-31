package domainmatcher

import (
	"math/rand"
	"strings"
	"testing"
)

func TestStripLabelDotsDropsEveryDot(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := r.Intn(300); n > 0; n-- {
			b.WriteByte(".ab9Z."[r.Intn(6)])
		}
		in := b.String()
		if got, want := stripLabelDots(in), strings.ReplaceAll(in, ".", ""); got != want {
			t.Fatalf("stripLabelDots(%q) = %q, want %q", in, got, want)
		}
	}
}
