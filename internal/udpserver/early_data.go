// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"sync"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// Early data (VpnProto.SessionCapEarlyData).
//
// 🔑 A client that knows this node holds early data answers the app's SOCKS
// CONNECT at once and sends the connection's first bytes - a TLS ClientHello,
// an HTTP request - right behind the SYN, instead of waiting a whole tunnel
// round trip for CONNECTED first. Each new connection is one round trip faster.
//
// Two things make that safe here. Data that arrives after the SYN but before
// the upstream connect finishes already waits in the stream's ARQ, which only
// starts writing once the connection is attached. And data that overtakes its
// SYN - the copies travel through different resolvers, and any of them can be
// the slow one - is held below until the SYN creates the stream, instead of
// being answered with a reset that would kill the connection. Held data that
// no SYN claims within earlyDataHoldTTL gets the reset it used to get at once.

// Early data is a TLS ClientHello or an HTTP request - a few KB - and it is
// only held for the moment its SYN is overtaken, so the bounds are small: at
// most 128 KB per session whatever a client sends.
const (
	earlyDataHoldTTL          = 10 * time.Second
	earlyDataMaxStreams       = 64
	earlyDataMaxPacketsStream = 32
	earlyDataMaxBytesStream   = 16 * 1024
	earlyDataMaxBytesSession  = 128 * 1024
)

type earlyDataPacket struct {
	packetType  uint8
	sequenceNum uint16
	fragmentID  uint8
	payload     []byte
}

type earlyDataStream struct {
	firstSeen time.Time
	bytes     int
	packets   []earlyDataPacket
}

// earlyDataBuffer holds, per session, data for streams whose SYN has not
// arrived yet.
type earlyDataBuffer struct {
	mu      sync.Mutex
	streams map[uint16]*earlyDataStream
	bytes   int
}

// hold keeps a data packet for a stream the session does not have yet, and
// returns the streams whose hold expired, which the caller resets. A packet
// that does not fit is dropped without a reset: the client resends it after
// its RTO, by which time the SYN has almost always arrived.
func (b *earlyDataBuffer) hold(streamID uint16, packetType uint8, sequenceNum uint16, fragmentID uint8, payload []byte, now time.Time) (expired []uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()

	expired = b.sweepLocked(now)

	if b.streams == nil {
		b.streams = make(map[uint16]*earlyDataStream)
	}
	entry := b.streams[streamID]
	if entry == nil {
		if len(b.streams) >= earlyDataMaxStreams {
			return expired
		}
		entry = &earlyDataStream{firstSeen: now}
		b.streams[streamID] = entry
	}
	if len(entry.packets) >= earlyDataMaxPacketsStream ||
		entry.bytes+len(payload) > earlyDataMaxBytesStream ||
		b.bytes+len(payload) > earlyDataMaxBytesSession {
		if len(entry.packets) == 0 {
			delete(b.streams, streamID)
		}
		return expired
	}
	for _, p := range entry.packets {
		if p.sequenceNum == sequenceNum && p.packetType == packetType && p.fragmentID == fragmentID {
			// A duplicate copy through another resolver.
			return expired
		}
	}
	entry.packets = append(entry.packets, earlyDataPacket{
		packetType:  packetType,
		sequenceNum: sequenceNum,
		fragmentID:  fragmentID,
		payload:     append([]byte(nil), payload...),
	})
	entry.bytes += len(payload)
	b.bytes += len(payload)
	return expired
}

// take removes and returns what is held for streamID.
func (b *earlyDataBuffer) take(streamID uint16) []earlyDataPacket {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry := b.streams[streamID]
	if entry == nil {
		return nil
	}
	b.removeLocked(streamID, entry)
	return entry.packets
}

func (b *earlyDataBuffer) drop(streamID uint16) {
	b.mu.Lock()
	if entry := b.streams[streamID]; entry != nil {
		b.removeLocked(streamID, entry)
	}
	b.mu.Unlock()
}

func (b *earlyDataBuffer) removeLocked(streamID uint16, entry *earlyDataStream) {
	delete(b.streams, streamID)
	b.bytes -= entry.bytes
	if b.bytes < 0 {
		b.bytes = 0
	}
}

func (b *earlyDataBuffer) sweepLocked(now time.Time) []uint16 {
	var expired []uint16
	for id, entry := range b.streams {
		if now.Sub(entry.firstSeen) >= earlyDataHoldTTL {
			expired = append(expired, id)
			b.removeLocked(id, entry)
		}
	}
	return expired
}

// holdEarlyStreamData keeps data that reached the node before its stream's
// SYN. false means the caller should answer the old way (a reset).
func (s *Server) holdEarlyStreamData(record *sessionRecord, packetType uint8, streamID uint16, sequenceNum uint16, fragmentID uint8, payload []byte) bool {
	if s == nil || record == nil || !s.earlyData || streamID == 0 {
		return false
	}
	if packetType != Enums.PACKET_STREAM_DATA && packetType != Enums.PACKET_STREAM_RESEND {
		return false
	}
	for _, id := range record.early.hold(streamID, packetType, sequenceNum, fragmentID, payload, time.Now()) {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, id, 0)
	}
	return true
}

// replayEarlyStreamData hands held data to the stream its SYN just created.
func (s *Server) replayEarlyStreamData(record *sessionRecord, streamID uint16) {
	if s == nil || record == nil || !s.earlyData {
		return
	}
	packets := record.early.take(streamID)
	if len(packets) == 0 {
		return
	}
	stream, ok := record.getStream(streamID)
	if !ok || stream == nil || stream.ARQ == nil || stream.ARQ.IsClosed() || stream.ARQ.IsReset() {
		return
	}
	for _, p := range packets {
		stream.enqueueInboundData(p.packetType, p.sequenceNum, p.fragmentID, p.payload)
	}
}

// sessionCaps is what this node tells each new session it supports.
func (s *Server) sessionCaps() uint8 {
	var caps uint8
	if s.earlyData {
		caps |= VpnProto.SessionCapEarlyData
	}
	return caps
}
