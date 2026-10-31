package arq

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

// nackRecorder keeps the NACKs an ARQ queued, in order.
type nackRecorder struct{ nacks []uint16 }

func (r *nackRecorder) PushTXPacket(_ int, packetType uint8, sn uint16, _ uint8, _ uint8, _ uint8, _ time.Duration, _ []byte) bool {
	if packetType == Enums.PACKET_STREAM_DATA_NACK {
		r.nacks = append(r.nacks, sn)
	}
	return true
}

// referenceMaybeSendDataNacks is maybeSendDataNacks as it was before it took
// the lock once and skipped prunes that delete nothing.
func referenceMaybeSendDataNacks(a *ARQ, sn uint16, now time.Time) {
	if a == nil || a.dataNackMaxGap <= 0 {
		return
	}
	a.mu.RLock()
	rcvNxt := a.rcvNxt
	closed := a.closed
	a.mu.RUnlock()
	if closed {
		return
	}
	diff := sn - rcvNxt
	if diff == 0 || diff >= 32768 {
		return
	}
	a.mu.Lock()
	referencePrune(a, rcvNxt)
	a.mu.Unlock()

	windowSpan := uint16(a.dataNackMaxGap)
	a.mu.RLock()
	missingSeqs := make([]uint16, 0, a.dataNackMaxGap)
	if diff <= windowSpan {
		for missing := rcvNxt; missing != sn; missing++ {
			if _, buffered := a.rcvBuf[missing]; buffered {
				continue
			}
			missingSeqs = append(missingSeqs, missing)
		}
	} else {
		seen := make(map[uint16]struct{}, maxI(2, a.dataNackMaxGap/20+1))
		sampleCount := maxI(1, (a.dataNackMaxGap+19)/20)
		for missing, added := rcvNxt, 0; missing != sn && added < sampleCount; missing++ {
			if _, buffered := a.rcvBuf[missing]; buffered {
				continue
			}
			missingSeqs = append(missingSeqs, missing)
			seen[missing] = struct{}{}
			added++
		}
		frontier := uint16(uint32(rcvNxt) + uint32(windowSpan) - 1)
		for candidate := frontier; ; candidate-- {
			if _, buffered := a.rcvBuf[candidate]; !buffered {
				if _, exists := seen[candidate]; !exists {
					missingSeqs = append(missingSeqs, candidate)
				}
				break
			}
			if candidate == rcvNxt {
				break
			}
		}
	}
	a.mu.RUnlock()

	for _, missing := range missingSeqs {
		if !referenceShouldSendDataNack(a, missing, now) {
			continue
		}
		if !a.enqueuer.PushTXPacket(Enums.DefaultPacketPriority(Enums.PACKET_STREAM_DATA_NACK), Enums.PACKET_STREAM_DATA_NACK, missing, 0, 0, 0, 0, nil) {
			continue
		}
		a.mu.Lock()
		a.lastDataNackSent[missing] = now
		a.mu.Unlock()
	}
}

func referenceShouldSendDataNack(a *ARQ, sn uint16, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	firstSeenAt, exists := a.firstDataNackSeen[sn]
	if !exists {
		a.firstDataNackSeen[sn] = now
		return a.dataNackInitialDelay <= 0
	}
	if a.dataNackInitialDelay > 0 && now.Sub(firstSeenAt) < a.dataNackInitialDelay {
		return false
	}
	lastSentAt, exists := a.lastDataNackSent[sn]
	if !exists {
		return true
	}
	return now.Sub(lastSentAt) >= a.dataNackRepeatInterval
}

func referencePrune(a *ARQ, rcvNxt uint16) {
	for sn := range a.firstDataNackSeen {
		if seqBehind(rcvNxt, sn) {
			delete(a.firstDataNackSeen, sn)
		}
	}
	for sn := range a.lastDataNackSent {
		if seqBehind(rcvNxt, sn) {
			delete(a.lastDataNackSent, sn)
		}
	}
}

func nackTestARQ(maxGap int, initialDelay, repeat time.Duration, start uint16) (*ARQ, *nackRecorder) {
	rec := &nackRecorder{}
	return &ARQ{
		enqueuer:               rec,
		dataNackMaxGap:         maxGap,
		dataNackInitialDelay:   initialDelay,
		dataNackRepeatInterval: repeat,
		rcvNxt:                 start,
		rcvBuf:                 map[uint16][]byte{},
		firstDataNackSeen:      map[uint16]time.Time{},
		lastDataNackSent:       map[uint16]time.Time{},
	}, rec
}

// The rewrite must queue the same NACKs, in the same order, and keep the same
// NACK state as the code it replaced, under reordering, loss, wrap-around,
// gaps beyond the NACK window and entries a racing watchdog adds.
func TestDataNacksMatchReference(t *testing.T) {
	for _, cfg := range []struct {
		maxGap         int
		initial, every time.Duration
		start          uint16
	}{
		{64, 0, 40 * time.Millisecond, 0},
		{64, 20 * time.Millisecond, 60 * time.Millisecond, 65500},
		{8, 5 * time.Millisecond, 30 * time.Millisecond, 32760},
		{256, 0, 0, 100},
	} {
		t.Run(fmt.Sprintf("gap%d", cfg.maxGap), func(t *testing.T) {
			r := rand.New(rand.NewSource(int64(cfg.maxGap) + int64(cfg.start)))
			got, gotRec := nackTestARQ(cfg.maxGap, cfg.initial, cfg.every, cfg.start)
			want, wantRec := nackTestARQ(cfg.maxGap, cfg.initial, cfg.every, cfg.start)
			now := time.Unix(1_700_000_000, 0)
			sent := 0
			for step := 0; step < 30000; step++ {
				now = now.Add(time.Duration(r.Intn(15)) * time.Millisecond)
				switch e := r.Intn(20); {
				case e < 14: // a data packet arrives, often out of order
					sn := got.rcvNxt + uint16(r.Intn(cfg.maxGap*2+3))
					for _, a := range []*ARQ{got, want} {
						if _, ok := a.rcvBuf[sn]; !ok {
							a.rcvBuf[sn] = []byte{1}
							delete(a.firstDataNackSeen, sn)
							delete(a.lastDataNackSent, sn)
						}
					}
					got.maybeSendDataNacksAt(sn, now)
					referenceMaybeSendDataNacks(want, sn, now)
				case e < 18: // in-order data is delivered
					for _, a := range []*ARQ{got, want} {
						for {
							if _, ok := a.rcvBuf[a.rcvNxt]; !ok {
								break
							}
							delete(a.rcvBuf, a.rcvNxt)
							a.rcvNxt++
						}
					}
				default: // the gap watchdog notes a number already behind
					sn := got.rcvNxt - uint16(1+r.Intn(4))
					got.shouldSendDataNack(sn, now)
					referenceShouldSendDataNack(want, sn, now)
				}
				if !reflect.DeepEqual(gotRec.nacks, wantRec.nacks) {
					t.Fatalf("step %d: NACKs %v, want %v", step, gotRec.nacks, wantRec.nacks)
				}
				sent += len(gotRec.nacks)
				gotRec.nacks, wantRec.nacks = gotRec.nacks[:0], wantRec.nacks[:0]
			}
			// One last full prune on both: the state must agree.
			got.nackStaleAdded = true
			got.pruneDataNackStateLocked(got.rcvNxt)
			referencePrune(want, want.rcvNxt)
			if !reflect.DeepEqual(got.firstDataNackSeen, want.firstDataNackSeen) || !reflect.DeepEqual(got.lastDataNackSent, want.lastDataNackSent) {
				t.Fatalf("NACK state differs after %d NACKs", sent)
			}
			if sent == 0 {
				t.Fatal("the scenario sent no NACKs; it tests nothing")
			}
		})
	}
}
