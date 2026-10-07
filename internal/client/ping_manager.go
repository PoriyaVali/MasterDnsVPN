// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
)

type PingManager struct {
	client                *Client
	lastPingSentAt        atomic.Int64
	lastPongReceivedAt    atomic.Int64
	lastNonPingSentAt     atomic.Int64
	lastNonPongReceivedAt atomic.Int64
	nextPingSeq           atomic.Uint32

	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	wakeCh     chan struct{}
	lastWokeAt atomic.Int64

	// idle: the current interval is a quiet-tunnel one (cooldown or longer).
	// Those pings only keep the session alive and poll for pushes, so they
	// go out once instead of duplicated (see runtimePacketDuplicationCount).
	idle atomic.Bool
}

// pingMinWait is the shortest the loop sleeps. Pings themselves are paced
// by the interval; this only bounds how often the loop wakes to check.
const pingMinWait = 10 * time.Millisecond

// pingMaxWait: tiers depend on how long the tunnel has been quiet, so the
// loop looks again at least this often even when the next ping is far off.
const pingMaxWait = time.Second

func newPingManager(client *Client) *PingManager {
	now := time.Now().UnixNano()
	p := &PingManager{
		client: client,
		wakeCh: make(chan struct{}, 1),
	}
	p.lastPingSentAt.Store(now)
	p.lastPongReceivedAt.Store(now)
	p.lastNonPingSentAt.Store(now)
	p.lastNonPongReceivedAt.Store(now)
	p.lastWokeAt.Store(now)
	return p
}

// Start starts the autonomous ping loop.
func (p *PingManager) Start(parentCtx context.Context) {
	p.Stop() // Ensure old one is stopped

	p.ctx, p.cancel = context.WithCancel(parentCtx)
	p.wg.Add(1)
	go p.pingLoop()
}

// Stop stops the ping loop.
func (p *PingManager) Stop() {
	if p.cancel != nil {
		p.cancel()
		p.wg.Wait()
		p.cancel = nil
	}
}

func (p *PingManager) NotifyPacket(packetType uint8, isInbound bool) {
	if p == nil {
		return
	}

	isPing := packetType == Enums.PACKET_PING
	isPong := packetType == Enums.PACKET_PONG

	now := time.Now().UnixNano()

	if isInbound {
		if isPong {
			p.lastPongReceivedAt.Store(now)
		} else {
			p.lastNonPongReceivedAt.Store(now)
			p.wake(now)
		}
	} else {
		if isPing {
			p.lastPingSentAt.Store(now)
		} else {
			p.lastNonPingSentAt.Store(now)
			p.wake(now)
		}
	}
}

func (p *PingManager) wake(now int64) {
	// Throttle wakeups to at most once per 100ms to reduce CPU overhead in high traffic
	if now-p.lastWokeAt.Load() < int64(100*time.Millisecond) {
		return
	}
	p.lastWokeAt.Store(now)
	select {
	case p.wakeCh <- struct{}{}:
	default:
	}
}

func (p *PingManager) nextInterval(nowNano int64) time.Duration {
	lastNonPingSent := p.lastNonPingSentAt.Load()
	lastNonPongRecv := p.lastNonPongReceivedAt.Load()

	// Use fast int64 comparisons for intervals
	warmThresholdNano := int64(p.client.cfg.PingWarmThreshold())

	if nowNano-lastNonPingSent < warmThresholdNano || nowNano-lastNonPongRecv < warmThresholdNano {
		return p.client.cfg.PingAggressiveInterval()
	}

	idleSent := nowNano - lastNonPingSent
	idleRecv := nowNano - lastNonPongRecv
	minIdle := idleSent
	if idleRecv < minIdle {
		minIdle = idleRecv
	}

	coolThresholdNano := int64(p.client.cfg.PingCoolThreshold())
	coldThresholdNano := int64(p.client.cfg.PingColdThreshold())
	switch {
	case minIdle < coolThresholdNano:
		return p.client.cfg.PingLazyInterval()
	case minIdle < coldThresholdNano:
		return p.client.cfg.PingCooldownInterval()
	case minIdle < int64(p.client.cfg.PingStreamIdleWindow()) && p.client.ActiveStreamCount() > 0:
		// 🔑 A chat app's connection sits open and silent until a message
		// comes in, and the server cannot send it until this client asks.
		// At the cold interval that is up to 15 s late; here, a few.
		return p.client.cfg.PingStreamIdleInterval()
	default:
		return p.client.cfg.PingColdInterval()
	}
}

func (p *PingManager) pingLoop() {
	defer p.wg.Done()

	p.client.log.Debugf("\U0001F3D3 <cyan>Ping Manager loop started</cyan>")
	timer := time.NewTimer(p.client.cfg.PingAggressiveInterval())
	defer timer.Stop()

	// When this loop last queued a ping. lastPingSentAt is only stamped once
	// the dispatcher sends it, and judging by that alone, a loop that wakes
	// sooner than the send would queue the same ping twice.
	var lastQueued int64

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.wakeCh:
		case <-timer.C:
		}

		nowNano := time.Now().UnixNano()
		interval := p.nextInterval(nowNano)
		p.idle.Store(interval >= p.client.cfg.PingCooldownInterval())
		lastPing := max64(p.lastPingSentAt.Load(), lastQueued)

		if nowNano-lastPing >= int64(interval) && p.client.SessionReady() {
			if p.queuePing() {
				lastQueued = nowNano
				lastPing = nowNano
			}
		}

		// ⚠️ Sleep until the next ping is due, not a fixed fraction of the
		// interval. This used to wake every interval/2 but never sooner than
		// 100 ms, so the 100 ms aggressive interval came out at 100-200 ms -
		// and a reply waiting at the server waits for the next ping.
		wait := time.Duration(lastPing + int64(interval) - nowNano)
		if wait < pingMinWait {
			wait = pingMinWait
		}
		if wait > pingMaxWait {
			wait = pingMaxWait
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
	}
}

// queuePing puts one PING on stream 0. Every answer to a query carries
// whatever the server has queued, so a ping also pulls data down.
func (p *PingManager) queuePing() bool {
	payload, err := buildClientPingPayload()
	if err != nil {
		return false
	}
	p.client.streamsMu.RLock()
	s0 := p.client.active_streams[0]
	p.client.streamsMu.RUnlock()
	if s0 == nil {
		return false
	}
	return s0.PushTXPacket(
		Enums.DefaultPacketPriority(Enums.PACKET_PING),
		Enums.PACKET_PING,
		p.nextPingSequence(),
		0,
		0,
		0,
		0,
		payload,
	)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (p *PingManager) nextPingSequence() uint16 {
	if p == nil {
		return 0
	}
	return uint16(p.nextPingSeq.Add(1))
}

func buildClientPingPayload() ([]byte, error) {
	// Pre-allocate the fixed size payload to avoid multiple allocations and appends
	payload := make([]byte, 7)
	payload[0] = 'P'
	payload[1] = 'O'
	payload[2] = ':'

	// Use rand.Read directly into the pre-allocated buffer starting at index 3
	if _, err := rand.Read(payload[3:]); err != nil {
		return nil, err
	}
	return payload, nil
}
