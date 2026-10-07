// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (pull.go) keeps queries in flight while the server has data.
// ==============================================================================
package client

import (
	"encoding/binary"
	"sync"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// 🔑 Why downloads need this: a DNS server can only answer, and every answer
// carries one packet. Download speed is therefore (queries in flight) / RTT x
// packet size. Without help the number in flight is whatever the client's
// ACKs and pings happen to add up to. Each data packet that arrives here adds
// one more query while the total is under PULL_PIPELINE_DEPTH: a bulk transfer
// ramps up like TCP slow start, a single chat message costs one extra query,
// and when the server has nothing left its answers are PONGs, data stops
// arriving and so does this.
//
// It does not cost traffic: a transfer still takes about one query per packet
// - measured, the same ~2400 datagrams for 512 KiB at every depth - they are
// just sent sooner. On a 120 ms path with 2% loss, depth 128 took the same
// download from ~45 to ~92 KiB/s.

const (
	queryTrackerMinExpiry = 300 * time.Millisecond
	queryTrackerMaxExpiry = 5 * time.Second
	queryTrackerSweepGap  = 50 * time.Millisecond
	// queryTrackerMaxEntries bounds the table on a path that loses everything.
	queryTrackerMaxEntries = 4096
)

type queryEntry struct {
	sentAt int64 // UnixNano
	copies int   // one built query can go to several resolvers
}

// queryTracker counts tunnel queries that have not been answered yet. A query
// unanswered for a few round trips is taken as lost and stops counting.
type queryTracker struct {
	mu          sync.Mutex
	pending     map[uint16]queryEntry
	outstanding int
	srtt        time.Duration
	nextSweep   int64
}

func newQueryTracker() *queryTracker {
	return &queryTracker{pending: make(map[uint16]queryEntry, 64)}
}

func (q *queryTracker) sent(packet []byte, now time.Time) {
	if q == nil || len(packet) < 2 {
		return
	}
	id := binary.BigEndian.Uint16(packet[:2])
	q.mu.Lock()
	if len(q.pending) >= queryTrackerMaxEntries {
		q.sweepLocked(now.UnixNano(), true)
	}
	e := q.pending[id]
	e.sentAt = now.UnixNano()
	e.copies++
	q.pending[id] = e
	q.outstanding++
	q.mu.Unlock()
}

func (q *queryTracker) answered(packet []byte, now time.Time) {
	if q == nil || len(packet) < 2 {
		return
	}
	id := binary.BigEndian.Uint16(packet[:2])
	q.mu.Lock()
	e, ok := q.pending[id]
	if ok {
		if rtt := time.Duration(now.UnixNano() - e.sentAt); rtt > 0 {
			if q.srtt == 0 {
				q.srtt = rtt
			} else {
				q.srtt += (rtt - q.srtt) / 8
			}
		}
		e.copies--
		q.outstanding--
		if e.copies <= 0 {
			delete(q.pending, id)
		} else {
			q.pending[id] = e
		}
	}
	q.mu.Unlock()
}

// inFlight is the number of queries sent and not yet answered or given up on.
func (q *queryTracker) inFlight(now time.Time) int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sweepLocked(now.UnixNano(), false)
	return q.outstanding
}

func (q *queryTracker) expiryLocked() time.Duration {
	expiry := 3 * q.srtt
	if expiry < queryTrackerMinExpiry {
		expiry = queryTrackerMinExpiry
	}
	if expiry > queryTrackerMaxExpiry {
		expiry = queryTrackerMaxExpiry
	}
	return expiry
}

func (q *queryTracker) sweepLocked(nowNano int64, force bool) {
	if !force && nowNano < q.nextSweep {
		return
	}
	q.nextSweep = nowNano + int64(queryTrackerSweepGap)
	cutoff := nowNano - int64(q.expiryLocked())
	for id, e := range q.pending {
		if e.sentAt < cutoff {
			q.outstanding -= e.copies
			delete(q.pending, id)
		}
	}
	if q.outstanding < 0 {
		q.outstanding = 0
	}
}

func (q *queryTracker) reset() {
	if q == nil {
		return
	}
	q.mu.Lock()
	clear(q.pending)
	q.outstanding = 0
	q.srtt = 0
	q.nextSweep = 0
	q.mu.Unlock()
}

// pullDepth is the number of queries to keep in flight while data flows; <= 0
// turns pulling off.
func (c *Client) pullDepth() int {
	return c.cfg.PullPipelineDepth
}

// notePulledData runs for every data packet the server sent. It sends one
// more poll while fewer than pullDepth queries are in flight, counting polls
// handed to the encoder but not yet on the wire.
func (c *Client) notePulledData(packetType uint8, now time.Time) {
	if packetType != Enums.PACKET_STREAM_DATA && packetType != Enums.PACKET_STREAM_RESEND {
		return
	}
	depth := c.pullDepth()
	if depth <= 0 || c.queries == nil || !c.SessionReady() {
		return
	}
	if int64(c.queries.inFlight(now))+c.pullsQueued.Load() >= int64(depth) {
		return
	}
	c.sendPull()
}

// sendPull hands one PING straight to the encoder.
//
// ⚠️ Not through stream 0's queue like a keepalive. The dispatcher serves
// streams in turn and holds a stream-0 PING back while any other stream has
// something queued - right for a keepalive, since that other packet polls
// too, but with eight downloads running there always is something, and the
// pulls sat in the queue. A pull has no stream state to keep in order.
//
// One query, not duplicated: a pull only has to reach the server, and a lost
// one is replaced by the next data packet's.
func (c *Client) sendPull() {
	payload, err := buildClientPingPayload()
	if err != nil {
		return
	}
	var seq uint16
	if c.pingManager != nil {
		seq = c.pingManager.nextPingSequence()
	}
	task := plannerTask{
		opts: VpnProto.BuildOptions{
			SessionID:     c.sessionID,
			SessionCookie: c.sessionCookie,
			PacketType:    Enums.PACKET_PING,
			SequenceNum:   seq,
			Payload:       payload,
		},
		dupCount: 1,
		pull:     true,
	}
	c.pullsQueued.Add(1)
	select {
	case c.plannerQueue <- task:
		c.NotifyPacket(Enums.PACKET_PING, false)
	default:
		// The encoder is busy: queries are going out anyway.
		c.notePullSent()
	}
}

// notePullSent settles pullsQueued once a pull is on the wire, or dropped.
func (c *Client) notePullSent() {
	for {
		cur := c.pullsQueued.Load()
		if cur <= 0 {
			return
		}
		if c.pullsQueued.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}
