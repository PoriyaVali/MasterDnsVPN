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
	payload, err := c.sessionPingPayload()
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
