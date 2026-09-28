// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/compression"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/sessioncrypto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (s *Server) validatePostSessionPacket(questionPacket []byte, requestName string, vpnPacket VpnProto.Packet, sealed bool) postSessionValidation {
	now := time.Now()
	validation := s.sessions.ValidateAndTouchAuth(vpnPacket.SessionID, vpnPacket.SessionCookie, sealed, now)
	if validation.Valid {
		return postSessionValidation{
			record: validation.Active,
			ok:     true,
		}
	}

	if validation.Unsealed {
		// Someone without this v2 session's keys naming its ID and cookie.
		// Answered with nothing: not the session's queued data, not even an
		// error that would confirm the guess.
		s.logInvalidSessionDrop("unsealed packet for sealed session", vpnPacket.SessionID, vpnPacket.SessionCookie, 0, 0)
		return postSessionValidation{}
	}

	if !validation.Known {
		mode := s.nextUnknownInvalidDropMode()
		s.logInvalidSessionDrop("unknown session", vpnPacket.SessionID, vpnPacket.SessionCookie, 0, mode)
		return postSessionValidation{
			response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, mode),
		}
	}

	if validation.Lookup.State == sessionLookupClosed {
		s.logInvalidSessionDrop("recently closed session", vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup.Cookie, validation.Lookup.ResponseMode)
		return postSessionValidation{
			response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, validation.Lookup.ResponseMode),
		}
	}

	if !s.invalidCookieTracker.Note(
		vpnPacket.SessionID,
		validation.Lookup,
		validation.Known,
		vpnPacket.SessionCookie,
		now.UnixNano(),
		s.invalidCookieWindowNanos,
		s.invalidCookieThreshold,
	) {
		return postSessionValidation{}
	}

	s.logInvalidSessionDrop("invalid cookie threshold", vpnPacket.SessionID, vpnPacket.SessionCookie, validation.Lookup.Cookie, validation.Lookup.ResponseMode)

	return postSessionValidation{
		response: s.buildInvalidSessionErrorResponse(questionPacket, requestName, vpnPacket.SessionID, validation.Lookup.ResponseMode),
	}
}

func (s *Server) handleSessionCloseNotice(vpnPacket VpnProto.Packet, sealed bool, now time.Time) {
	if s == nil || vpnPacket.SessionID == 0 {
		return
	}

	lookup, known := s.sessions.Lookup(vpnPacket.SessionID)
	if !known || lookup.State != sessionLookupActive || lookup.Cookie != vpnPacket.SessionCookie {
		return
	}
	// 🔴 A v1 close is an 8-bit ID and an 8-bit cookie under the node key every
	// subscriber holds: at most 65536 guesses closed anyone's session. A v2
	// session is only closed by a close sealed under its own keys.
	if record, ok := s.sessions.Get(vpnPacket.SessionID); ok && record.v2 != sealed {
		return
	}

	record, ok := s.sessions.Close(vpnPacket.SessionID, now, s.cfg.ClosedSessionRetention())
	if !ok {
		return
	}

	s.cleanupClosedSession(vpnPacket.SessionID, record)
	if s.log != nil {
		s.log.Infof(
			"\U0001F6AA <green>Session Closed By Client, Session: <cyan>%d</cyan></green>",
			vpnPacket.SessionID,
		)
	}
}

func (s *Server) logInvalidSessionDrop(reason string, sessionID uint8, receivedCookie uint8, expectedCookie uint8, responseMode uint8) {
	if !s.debugLoggingEnabled() {
		return
	}
	now := time.Now()
	logKey, interval := invalidSessionDropLogConfig(reason, sessionID, receivedCookie, expectedCookie, responseMode)
	if !s.invalidSessionDropLog.allow(logKey, now, interval) {
		return
	}
	if expectedCookie == 0 {
		s.log.Debugf(
			"\U0001F44B <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
			reason,
			sessionID,
			receivedCookie,
			sessionResponseModeName(responseMode),
		)
		return
	}
	s.log.Debugf(
		"\U0001F44B <yellow>Sending Session Drop</yellow> <magenta>|</magenta> <blue>Reason</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Expected</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Received</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan>",
		reason,
		sessionID,
		expectedCookie,
		receivedCookie,
		sessionResponseModeName(responseMode),
	)
}

func invalidSessionDropLogConfig(reason string, sessionID uint8, receivedCookie uint8, expectedCookie uint8, responseMode uint8) (string, time.Duration) {
	switch reason {
	case "recently closed session":
		return fmt.Sprintf("recently-closed:%d:%d:%d", sessionID, expectedCookie, responseMode), 3 * time.Second
	case "invalid cookie threshold":
		return fmt.Sprintf("invalid-cookie:%d:%d:%d", sessionID, expectedCookie, responseMode), 1500 * time.Millisecond
	case "unknown session":
		return fmt.Sprintf("unknown-session:%d:%d", sessionID, responseMode), 1500 * time.Millisecond
	default:
		return fmt.Sprintf("%s:%d:%d:%d", reason, sessionID, expectedCookie, responseMode), time.Second
	}
}

func (s *Server) buildInvalidSessionErrorResponse(questionPacket []byte, requestName string, sessionID uint8, responseMode uint8) []byte {
	payload := s.nextInvalidDropPayload()
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, VpnProto.Packet{
		SessionID:  sessionID,
		PacketType: Enums.PACKET_ERROR_DROP,
		Payload:    payload[:],
	}, responseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildSessionBusyResponse(questionPacket []byte, requestName string, responseMode uint8, verifyCode []byte) []byte {
	if len(verifyCode) < mtuProbeCodeLength {
		return nil
	}
	var payload [mtuProbeCodeLength]byte
	copy(payload[:], verifyCode[:mtuProbeCodeLength])
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_BUSY,
		Payload:    payload[:],
	}, responseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildSessionVPNResponse(questionPacket []byte, requestName string, record *sessionRuntimeView, packet VpnProto.Packet) []byte {
	if record == nil {
		return nil
	}
	packet.SessionID = record.ID
	packet.SessionCookie = record.Cookie
	if record.v2 {
		return buildSealedResponse(questionPacket, requestName, record.keys, packet, record.ResponseBase64)
	}
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, requestName, packet, record.ResponseBase64)
	if err != nil {
		return nil
	}
	return response
}

// buildSealedResponse answers a v2 session: the frame is built exactly as v1
// builds it, then sealed under the session's downstream key - so neither its
// header nor its payload (the user's traffic, and every name they resolve
// through the tunnel) is readable on the wire, by the censor or by another
// subscriber holding the node key.
func buildSealedResponse(questionPacket []byte, requestName string, keys *sessioncrypto.Keys, packet VpnProto.Packet, base64 bool) []byte {
	frameBuf, sealBuf := sealScratch.Get().(*[]byte), sealScratch.Get().(*[]byte)
	defer putSealScratch(frameBuf)
	defer putSealScratch(sealBuf)
	raw, err := VpnProto.BuildRawAutoInto(*frameBuf, VpnProto.BuildOptions{
		SessionID:       packet.SessionID,
		PacketType:      packet.PacketType,
		SessionCookie:   packet.SessionCookie,
		StreamID:        packet.StreamID,
		SequenceNum:     packet.SequenceNum,
		FragmentID:      packet.FragmentID,
		TotalFragments:  packet.TotalFragments,
		CompressionType: packet.CompressionType,
		Payload:         packet.Payload,
	}, compression.DefaultMinSize)
	if err != nil {
		return nil
	}
	*frameBuf = raw[:0]
	sealed, err := keys.SealDownTo(*sealBuf, raw)
	if err != nil {
		return nil
	}
	*sealBuf = sealed[:0]
	response, err := DnsParser.BuildSealedVPNResponsePacket(questionPacket, requestName, sealed, base64)
	if err != nil {
		return nil
	}
	return response
}

// sealScratch holds the frame and its sealed form while a v2 answer is
// built; only the answer itself is allocated.
var sealScratch = sync.Pool{New: func() any {
	b := make([]byte, 0, 2048)
	return &b
}}

func putSealScratch(b *[]byte) {
	if cap(*b) > 64*1024 {
		return
	}
	*b = (*b)[:0]
	sealScratch.Put(b)
}

func (s *Server) queueSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	record, ok := s.sessions.Get(sessionID)
	if !ok {
		return false
	}

	if packet.StreamID == 0 {
		record.ensureStream0(s.log)
		stream, exists := record.getStream(0)
		if !exists || stream == nil {
			return false
		}

		return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, packet.CompressionType, 0, packet.Payload)
	}

	stream, exists := record.getStream(packet.StreamID)
	if !exists || stream == nil {
		return false
	}

	return stream.PushTXPacket(getEffectivePriority(packet.PacketType, 3), packet.PacketType, packet.SequenceNum, packet.FragmentID, packet.TotalFragments, packet.CompressionType, 0, packet.Payload)
}

func (s *Server) streamARQConfig(compressionType uint8) arq.Config {
	return arq.Config{
		WindowSize:                  s.cfg.ARQWindowSize,
		RTO:                         s.cfg.ARQInitialRTOSeconds,
		MaxRTO:                      s.cfg.ARQMaxRTOSeconds,
		EnableControlReliability:    true,
		ControlRTO:                  s.cfg.ARQControlInitialRTOSeconds,
		ControlMaxRTO:               s.cfg.ARQControlMaxRTOSeconds,
		ControlMaxRetries:           s.cfg.ARQMaxControlRetries,
		InactivityTimeout:           s.cfg.ARQInactivityTimeoutSeconds,
		DataPacketTTL:               s.cfg.ARQDataPacketTTLSeconds,
		MaxDataRetries:              s.cfg.ARQMaxDataRetries,
		DataNackMaxGap:              s.cfg.ARQDataNackMaxGap,
		DataNackInitialDelaySeconds: s.cfg.ARQDataNackInitialDelaySeconds,
		DataNackRepeatSeconds:       s.cfg.ARQDataNackRepeatSeconds,
		ControlPacketTTL:            s.cfg.ARQControlPacketTTLSeconds,
		TerminalDrainTimeout:        s.cfg.ARQTerminalDrainTimeoutSec,
		TerminalAckWaitTimeout:      s.cfg.ARQTerminalAckWaitTimeoutSec,
		CompressionType:             compressionType,
		// Left at 0 the ARQ sizes its inbound hand-off queue from the window -
		// 1600 slots for the default window of 800, allocated up front: ~48KB of
		// a stream's ~59KB, on every stream of every user. That queue only
		// bridges the packet worker to the stream's own reader, which drains it
		// immediately, and upload arrives a query at a time; a full queue drops
		// the packet, which the client retransmits.
		InboundQueueSize: serverStreamInboundQueueSize,
	}
}

const serverStreamInboundQueueSize = 512

func (s *Server) queueMainSessionPacket(sessionID uint8, packet VpnProto.Packet) bool {
	packet.StreamID = 0
	return s.queueSessionPacket(sessionID, packet)
}

func (s *Server) cleanupClosedSession(sessionID uint8, record *sessionRecord) {
	if s == nil || sessionID == 0 {
		return
	}
	s.clearDeferredPacketsForSession(sessionID)
	s.removeSOCKS5SynFragmentsForSession(sessionID)
	if record != nil {
		record.closeAllStreams("session closed cleanup")
	}
	s.cleanupDeferredSessionState(sessionID)
}

func (s *Server) cleanupDeferredSessionState(sessionID uint8) {
	if s == nil || sessionID == 0 {
		return
	}
	if s.deferredDNSSession != nil {
		s.deferredDNSSession.RemoveSession(sessionID)
	}
	if s.deferredConnectSession != nil {
		s.deferredConnectSession.RemoveSession(sessionID)
	}
	s.removeDNSQueryFragmentsForSession(sessionID)
}

func (s *Server) cleanupIdleDeferredSession(sessionID uint8, lastActivityNano int64, now time.Time) {
	if s == nil || sessionID == 0 {
		return
	}

	s.clearDeferredPacketsForSession(sessionID)
	s.removeSOCKS5SynFragmentsForSession(sessionID)
	s.cleanupDeferredSessionState(sessionID)
}

func (s *Server) cleanupStreamArtifacts(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.clearDeferredPacketsForStream(sessionID, streamID)
	s.removeSOCKS5SynFragmentsForStream(sessionID, streamID)
}

func (s *Server) finalizeStreamArtifacts(sessionID uint8, streamID uint16) {
	if s == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.finalizeDeferredPacketsForStream(sessionID, streamID)
	s.removeSOCKS5SynFragmentsForStream(sessionID, streamID)
}

func (s *Server) serveQueuedOrPong(questionPacket []byte, requestName string, record *sessionRuntimeView, now time.Time) []byte {
	if record == nil {
		return nil
	}

	sessionID := record.ID

	if pkt, ok := s.dequeueSessionResponse(sessionID, now); ok {
		return s.buildSessionVPNResponse(questionPacket, requestName, record, *pkt)
	}

	payload := s.nextPongPayload()
	return s.buildSessionVPNResponse(questionPacket, requestName, record, VpnProto.Packet{
		PacketType: Enums.PACKET_PONG,
		Payload:    payload[:],
	})
}

func (s *Server) dequeueSessionResponse(sessionID uint8, now time.Time) (*VpnProto.Packet, bool) {
	record, ok := s.sessions.Get(sessionID)
	if !ok {
		return nil, false
	}

	record.mu.Lock()
	if pkt, ok := s.dequeueDuplicatedPackedControlBlock(record); ok {
		record.mu.Unlock()
		return pkt, true
	}
	rrStreamID := record.RRStreamID
	record.mu.Unlock()

	readyIDs, readyStreams := record.activeStreamSnapshot()
	hasOrphan := record.OrphanQueue != nil && record.OrphanQueue.FastSize() > 0
	totalCandidates := len(readyIDs)

	if hasOrphan {
		totalCandidates++
	}

	if totalCandidates == 0 {
		return nil, false
	}

	startIdx := 0
	candidateAt := func(idx int) (int32, *Stream_server) {
		if hasOrphan {
			if idx == 0 {
				return -1, nil
			}
			idx--
		}
		if idx < 0 || idx >= len(readyIDs) {
			return 0, nil
		}
		return readyIDs[idx], readyStreams[idx]
	}

	for i := 0; i < totalCandidates; i++ {
		id, _ := candidateAt(i)
		if id >= rrStreamID {
			startIdx = i
			break
		}
	}

	for i := 0; i < totalCandidates; i++ {
		idx := (startIdx + i) % totalCandidates
		id, stream := candidateAt(idx)

		var item *serverStreamTXPacket
		var ok bool
		var selectedStreamID uint16

		if id == -1 {
			p, _, popOk := record.OrphanQueue.Pop()
			if popOk {
				item = &serverStreamTXPacket{
					PacketType:     p.PacketType,
					SequenceNum:    p.SequenceNum,
					FragmentID:     p.FragmentID,
					TotalFragments: p.TotalFragments,
					Payload:        p.Payload,
				}
				selectedStreamID = p.StreamID
				ok = true
			}
		} else {
			if stream == nil || stream.TXQueue == nil || stream.FastTXQueueSize() == 0 {
				continue
			}
			if stream.ARQ != nil && stream.ARQ.IsClosed() {
				stream.ClearTXQueue()
				record.deactivateStream(uint16(id))
				continue
			}
			var popped *serverStreamTXPacket
			popped, _, ok = stream.PopNextTXPacket()
			if ok {
				stream.NoteTXPacketDequeued(popped)
				if (popped.PacketType == Enums.PACKET_STREAM_DATA || popped.PacketType == Enums.PACKET_STREAM_RESEND) &&
					stream.ARQ != nil && !stream.ARQ.HasPendingSequence(popped.SequenceNum) {
					putTXPacketToPool(popped)
					continue
				}
				item = popped
				selectedStreamID = uint16(id)
			}
		}

		if ok && item != nil {
			record.mu.Lock()
			record.RRStreamID = id + 1
			if VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) && record.MaxPackedBlocks > 1 {
				pkt := s.packControlBlocks(record, item, id, selectedStreamID)
				s.cachePackedControlBlockDuplicate(record, pkt)
				record.mu.Unlock()
				return pkt, true
			}
			record.mu.Unlock()
			pkt := vpnPacketFromTX(item, selectedStreamID)
			if id != -1 {
				putTXPacketToPool(item)
			}
			return &pkt, true
		}
	}

	return nil, false
}

func cloneVPNPacket(packet *VpnProto.Packet) *VpnProto.Packet {
	if packet == nil {
		return nil
	}
	cloned := *packet
	if len(packet.Payload) > 0 {
		cloned.Payload = append([]byte(nil), packet.Payload...)
	}
	return &cloned
}

func (s *Server) dequeueDuplicatedPackedControlBlock(record *sessionRecord) (*VpnProto.Packet, bool) {
	if s == nil || record == nil || record.LastPackedControlBlock == nil || record.LastPackedControlBlockRemaining <= 0 {
		return nil, false
	}
	packet := cloneVPNPacket(record.LastPackedControlBlock)
	record.LastPackedControlBlockRemaining--
	if record.LastPackedControlBlockRemaining <= 0 {
		record.LastPackedControlBlock = nil
		record.LastPackedControlBlockRemaining = 0
	}
	return packet, packet != nil
}

func (s *Server) cachePackedControlBlockDuplicate(record *sessionRecord, packet *VpnProto.Packet) {
	if s == nil || record == nil {
		return
	}
	duplication := s.cfg.PacketBlockControlDuplication
	if duplication <= 1 || packet == nil || packet.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS {
		record.LastPackedControlBlock = nil
		record.LastPackedControlBlockRemaining = 0
		return
	}
	record.LastPackedControlBlock = cloneVPNPacket(packet)
	record.LastPackedControlBlockRemaining = duplication - 1
}

func (s *Server) packControlBlocks(record *sessionRecord, first *serverStreamTXPacket, initialID int32, initialStreamID uint16) *VpnProto.Packet {
	limit := record.MaxPackedBlocks
	if limit <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)
		return &pkt
	}

	payload := make([]byte, 0, limit*VpnProto.PackedControlBlockSize)
	payload = VpnProto.AppendPackedControlBlock(payload, first.PacketType, initialStreamID, first.SequenceNum, first.FragmentID, first.TotalFragments)
	blocks := 1

	readyIDs, readyStreams := record.activeStreamSnapshot()
	hasOrphan := record.OrphanQueue != nil && record.OrphanQueue.FastSize() > 0

	processID := func(id int32, stream *Stream_server) bool {
		if blocks >= limit {
			return true
		}

		if id == -1 {
			for blocks < limit {
				if record.OrphanQueue == nil || record.OrphanQueue.FastSize() == 0 {
					return false
				}
				popped, ok := record.OrphanQueue.PopAnyIf(2, func(p VpnProto.Packet) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, 0)
				}, func(p VpnProto.Packet) uint64 {
					return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
				})
				if !ok {
					return false
				}
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
			}
			return false
		}

		if stream == nil || stream.TXQueue == nil {
			return false
		}

		for blocks < limit {
			if stream.FastTXQueueSize() == 0 {
				return false
			}
			popped, ok := stream.PopAnyTXPacket(2, func(p *serverStreamTXPacket) bool {
				return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
			})
			if !ok {
				return false
			}
			stream.NoteTXPacketDequeued(popped)
			payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, uint16(id), popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
			blocks++
			putTXPacketToPool(popped)
		}
		return false
	}

	var initialStream *Stream_server
	var initialIndex int = -1
	if initialID != -1 {
		for i, id := range readyIDs {
			if id == initialID {
				initialIndex = i
				initialStream = readyStreams[i]
				break
			}
		}
	}
	if processID(initialID, initialStream) {
		goto buildResult
	}

	if hasOrphan && initialID != -1 {
		if processID(-1, nil) {
			goto buildResult
		}
	}

	if initialIndex >= 0 {
		for i := initialIndex + 1; i < len(readyIDs); i++ {
			if processID(readyIDs[i], readyStreams[i]) {
				goto buildResult
			}
		}
		for i := 0; i < initialIndex; i++ {
			if processID(readyIDs[i], readyStreams[i]) {
				goto buildResult
			}
		}
	} else {
		for i, id := range readyIDs {
			if processID(id, readyStreams[i]) {
				goto buildResult
			}
		}
	}

	if initialID == -1 && hasOrphan {
		for i, id := range readyIDs {
			if processID(id, readyStreams[i]) {
				goto buildResult
			}
		}
	}

buildResult:
	if blocks <= 1 {
		pkt := vpnPacketFromTX(first, initialStreamID)

		if initialID != -1 {
			putTXPacketToPool(first)
		}
		return &pkt
	}

	if initialID != -1 {
		putTXPacketToPool(first)
	}

	return &VpnProto.Packet{
		PacketType:  Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Payload:     payload,
		StreamID:    0,
		HasStreamID: true,
	}
}

func vpnPacketFromTX(p *serverStreamTXPacket, streamID uint16) VpnProto.Packet {
	return VpnProto.Packet{
		PacketType:         p.PacketType,
		StreamID:           streamID,
		SequenceNum:        p.SequenceNum,
		FragmentID:         p.FragmentID,
		TotalFragments:     p.TotalFragments,
		CompressionType:    p.CompressionType,
		HasCompressionType: p.CompressionType != compression.TypeOff,
		Payload:            p.Payload,
		HasSequenceNum:     p.SequenceNum != 0,
		HasFragmentInfo:    p.FragmentID != 0 || p.TotalFragments != 0,
		HasStreamID:        true,
	}
}

func (s *Server) nextPongPayload() [7]byte {
	var payload [7]byte
	payload[0] = 'P'
	payload[1] = 'O'
	payload[2] = ':'

	nonce := s.pongNonce.Add(1)
	nonce ^= nonce << 13
	nonce ^= nonce >> 17
	nonce ^= nonce << 5
	binary.BigEndian.PutUint32(payload[3:], nonce)
	return payload
}

func (s *Server) nextInvalidDropPayload() [8]byte {
	var payload [8]byte
	payload[0] = 'I'
	payload[1] = 'N'
	payload[2] = 'V'

	nonce := s.pongNonce.Add(1)
	nonce ^= nonce << 13
	nonce ^= nonce >> 17
	nonce ^= nonce << 5
	binary.BigEndian.PutUint32(payload[3:7], nonce)
	payload[7] = byte(nonce)
	return payload
}

func (s *Server) nextUnknownInvalidDropMode() uint8 {
	if s == nil {
		return mtuProbeModeRaw
	}

	if s.invalidDropMode.Add(1)&1 == 0 {
		return mtuProbeModeRaw
	}

	return mtuProbeModeBase64
}

func deferredSessionLaneForPacket(packet VpnProto.Packet) deferredSessionLane {
	if packet.PacketType == Enums.PACKET_DNS_QUERY_REQ {
		// A lane is a unit of ordering: everything in one lane runs on one
		// worker, in turn. Lookups arrive on stream 0, so keyed by stream they
		// all shared a single lane per session and one slow name held up every
		// other lookup that user made. They have no order to keep - each is
		// answered under its own sequence number - so each gets its own lane.
		// (The DNS pool is separate from the connect pool, so these lanes can
		// never be mistaken for a stream's.)
		return deferredSessionLane{
			sessionID: packet.SessionID,
			streamID:  packet.SequenceNum,
		}
	}
	return deferredSessionLane{
		sessionID: packet.SessionID,
		streamID:  packet.StreamID,
	}
}

func isDeferredPostSessionPacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_DNS_QUERY_REQ,
		Enums.PACKET_STREAM_SYN,
		Enums.PACKET_SOCKS5_SYN:
		return true
	default:
		return false
	}
}

func (s *Server) dispatchDeferredSessionPacket(packet VpnProto.Packet, run func(context.Context)) bool {
	if s == nil || !isDeferredPostSessionPacketType(packet.PacketType) {
		return false
	}
	var processor *deferredSessionProcessor
	switch packet.PacketType {
	case Enums.PACKET_DNS_QUERY_REQ:
		processor = s.deferredDNSSession
	case Enums.PACKET_STREAM_SYN, Enums.PACKET_SOCKS5_SYN:
		processor = s.deferredConnectSession
	default:
		return false
	}
	if processor == nil {
		return false
	}
	return processor.Enqueue(deferredSessionLaneForPacket(packet), run)
}

func isPreSessionRequestType(packetType uint8) bool {
	return preSessionPacketTypes[packetType]
}

func buildPreSessionPacketTypes() [256]bool {
	var values [256]bool
	values[Enums.PACKET_SESSION_INIT] = true
	values[Enums.PACKET_MTU_UP_REQ] = true
	values[Enums.PACKET_MTU_DOWN_REQ] = true
	return values
}

func (s *Server) handleSessionInitRequest(questionPacket []byte, decision domainMatcher.Decision, vpnPacket VpnProto.Packet, clientIP string) []byte {
	if vpnPacket.SessionID != 0 {
		return nil
	}

	// Three forms, all starting with the unchanged 10-byte signature:
	//   signature                            standalone node (no users), v1
	//   signature | token                    multi-user, v1
	//   signature | token | v2 | device | proof   multi-user, session v2
	// A node with registered users requires a token. v2 additionally proves the
	// client holds the subscriber's own key (not just the token, which crosses
	// the wire under the node key every subscriber has), and seals the session.
	payload := vpnPacket.Payload
	var account *userAccount
	var owner sessionOwner
	switch len(payload) {
	case sessionInitDataSize:
		if s.users != nil && s.users.count() > 0 {
			return nil // token required but missing -> reject
		}
	case sessionInitDataSize + UserTokenLen, sessionInitDataSize + UserTokenLen + sessioncrypto.InitTailLen:
		if s.users == nil {
			return nil
		}
		var tok UserToken
		copy(tok[:], payload[sessionInitDataSize:sessionInitDataSize+UserTokenLen])
		if account = s.users.lookup(tok); account == nil {
			return nil // unknown / revoked user -> reject
		}
		owner.user = account

		if len(payload) > sessionInitDataSize+UserTokenLen {
			tail := payload[sessionInitDataSize+UserTokenLen:]
			version := tail[0]
			var device [sessioncrypto.DeviceLen]byte
			copy(device[:], tail[1:1+sessioncrypto.DeviceLen])
			proof := tail[1+sessioncrypto.DeviceLen:]
			if version != sessioncrypto.Version ||
				!sessioncrypto.VerifyInitProof(account.key, payload[:sessionInitDataSize], version, device, proof) {
				return nil
			}
			keys, err := sessioncrypto.DeriveKeys(account.key, payload[:sessionInitDataSize], device)
			if err != nil {
				return nil
			}
			owner.v2 = true
			owner.keys = keys
			owner.deviceAddr = sessioncrypto.DeviceAddr(device)
		} else if s.cfg.RequireSessionV2 {
			// Once every client speaks v2, a v1 init is only ever someone
			// replaying or forging a token they were not given.
			return nil
		}

		// Authorisation is separate from authentication: the token proves who the
		// subscriber is, the embedder decides whether this device may open a
		// session. Only a NEW device is put to the hook - one already counted for
		// this user is the same device coming back, and a session re-init is
		// routine, so asking again would refuse a subscriber whose single allowed
		// device is the one already holding the slot.
		//
		// The device is the one the client declared (v2) when it declared one,
		// otherwise the source address - which for a DNS tunnel is a resolver's,
		// so v1 counts resolvers, not phones.
		//
		// Asked before the device is recorded, so a refused session never leaves
		// a sighting behind to be reported as a device that is not really there.
		device := clientIP
		if owner.deviceAddr != "" {
			device = owner.deviceAddr
		}
		now := time.Now()
		if !account.addrs.has(device, now) && !s.authorizeSession(account.uuid, device) {
			return nil
		}
		// Authenticated: recorded after the token (and v2 proof) check, so an
		// unauthenticated packet cannot inflate someone's device count.
		account.noteAddr(device, now, 0)
	default:
		return nil
	}
	// findOrCreate keys sessions on the 10-byte signature only.
	initSignature := payload[:sessionInitDataSize]

	requestedUpload, requestedDownload := compression.SplitPair(initSignature[1])
	resolvedUpload := resolveCompressionType(requestedUpload, s.uploadCompressionMask)
	resolvedDownload := resolveCompressionType(requestedDownload, s.downloadCompressionMask)

	record, reused, evicted, err := s.sessions.findOrCreateFor(
		owner,
		initSignature,
		resolvedUpload,
		resolvedDownload,
		s.cfg.EffectiveMaxPacketsPerBatch(),
		s.cfg.ClientMaxUploadMTU,
		s.cfg.ClientMaxDownloadMTU,
	)
	for _, gone := range evicted {
		s.cleanupClosedSession(gone.ID, gone.record)
	}
	if len(evicted) > 0 && s.log != nil {
		s.log.Infof(
			"\U0001F9F9 <yellow>Evicted <cyan>%d</cyan> silent session(s) to make room</yellow>",
			len(evicted),
		)
	}
	if err != nil {
		if err == ErrSessionTableFull {
			s.logSessionTableFull()
			return s.buildSessionBusyResponse(questionPacket, decision.RequestName, initSignature[0], initSignature[6:10])
		}
		return nil
	}
	if record == nil {
		return nil
	}

	if !reused && s.log != nil {
		s.log.Infof(
			"\U0001F9DD <green>Session Created, ID: <cyan>%d</cyan>, Mode: <cyan>%s</cyan>, Upload Compression: <cyan>%s</cyan>, Download Compression: <cyan>%s</cyan>, Client Upload MTU: <cyan>%d</cyan>, Client Download MTU: <cyan>%d</cyan>, Max Packed Blocks: <cyan>%d</cyan></green>",
			record.ID,
			sessionResponseModeName(record.ResponseMode),
			compression.TypeName(record.UploadCompression),
			compression.TypeName(record.DownloadCompression),
			record.UploadMTU,
			record.DownloadMTU,
			record.MaxPackedBlocks,
		)
	}

	responsePayload := VpnProto.EncodeSessionAcceptPayload(VpnProto.SessionAcceptPayload{
		SessionID:       record.ID,
		SessionCookie:   record.Cookie,
		CompressionPair: compression.PackPair(record.UploadCompression, record.DownloadCompression),
		VerifyCode:      record.VerifyCode,
		ClientPolicy: VpnProto.SessionAcceptClientPolicy{
			MaxPacketDuplicationCount: s.cfg.ClientMaxPacketDuplicationCount,
			MaxSetupDuplicationCount:  s.cfg.ClientMaxSetupDuplicationCount,
			MaxUploadMTU:              s.cfg.ClientMaxUploadMTU,
			MaxDownloadMTU:            s.cfg.ClientMaxDownloadMTU,
			MaxRxTxWorkers:            s.cfg.ClientMaxRxTxWorkers,
			MinPingAggressiveInterval: s.cfg.ClientMinPingAggressiveInterval,
			MaxPacketsPerBatch:        s.cfg.ClientMaxPacketsPerBatch,
			MaxARQWindowSize:          s.cfg.ClientMaxARQWindowSize,
			MaxARQDataNackMaxGap:      s.cfg.ClientMaxARQDataNackMaxGap,
			MinCompressionMinSize:     s.cfg.ClientMinCompressionMinSize,
			MinARQInitialRTOSeconds:   s.cfg.ClientMinARQInitialRTOSeconds,
		},
		HasClientPolicySync: true,
	})

	acceptPacket := VpnProto.Packet{
		SessionID:  0,
		PacketType: Enums.PACKET_SESSION_ACCEPT,
		Payload:    responsePayload,
	}
	if record.v2 {
		// Sealed like everything else in the session: the ID and cookie it
		// hands out are the session's handle, and only its owner may see them.
		return buildSealedResponse(questionPacket, decision.RequestName, record.keys, acceptPacket, record.ResponseMode == mtuProbeModeBase64)
	}
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, acceptPacket, record.ResponseMode == mtuProbeModeBase64)
	if err != nil {
		return nil
	}

	return response
}

func resolveCompressionType(requested uint8, allowedMask uint8) uint8 {
	if requested <= compression.TypeZLIB && allowedMask&(1<<requested) != 0 {
		return requested
	}
	return compression.TypeOff
}

func (s *Server) handleMTUUpRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < mtuProbeUpMinSize {
		return nil
	}

	baseEncode, ok := parseMTUProbeBaseEncoding(vpnPacket.Payload[0])
	if !ok {
		return nil
	}

	responsePayload := buildMTUProbeMetaPayload(vpnPacket.Payload[1:mtuProbeUpMinSize], len(vpnPacket.Payload))
	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:  vpnPacket.SessionID,
		PacketType: Enums.PACKET_MTU_UP_RES,
		Payload:    responsePayload[:],
	}, baseEncode)

	if err != nil {
		return nil
	}

	return response
}

func (s *Server) handleMTUDownRequest(questionPacket []byte, _ DnsParser.LitePacket, decision domainMatcher.Decision, vpnPacket VpnProto.Packet) []byte {
	if len(vpnPacket.Payload) < mtuProbeDownMinSize {
		return nil
	}

	baseEncode, ok := parseMTUProbeBaseEncoding(vpnPacket.Payload[0])
	if !ok {
		return nil
	}
	downloadSize := int(binary.BigEndian.Uint16(vpnPacket.Payload[mtuProbeUpMinSize:mtuProbeDownMinSize]))
	if downloadSize < mtuProbeMinDownSize || downloadSize > mtuProbeMaxDownSize {
		return nil
	}

	payloadBuffer := s.mtuProbePayloadPool.Get().([]byte)
	defer s.mtuProbePayloadPool.Put(payloadBuffer)
	payload := payloadBuffer[:downloadSize]
	copy(payload[:mtuProbeCodeLength], vpnPacket.Payload[1:mtuProbeUpMinSize])
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(downloadSize))
	if downloadSize > mtuProbeMetaLength {
		fillMTUProbeBytes(payload[mtuProbeMetaLength:])
	}

	response, err := DnsParser.BuildVPNResponsePacket(questionPacket, decision.RequestName, VpnProto.Packet{
		SessionID:      vpnPacket.SessionID,
		PacketType:     Enums.PACKET_MTU_DOWN_RES,
		StreamID:       vpnPacket.StreamID,
		SequenceNum:    vpnPacket.SequenceNum,
		FragmentID:     vpnPacket.FragmentID,
		TotalFragments: vpnPacket.TotalFragments,
		Payload:        payload,
	}, baseEncode)
	if err != nil {
		return nil
	}

	return response
}

// sessionTableFullLogInterval is how often a full session table is reported.
const sessionTableFullLogInterval = 10 * time.Second

// logSessionTableFull reports refused SESSION_INITs at most once per
// interval, with how many were refused since the last report. Each refusal
// used to write its own error line: 45 clients over capacity wrote 2,814
// lines in two and a half minutes, and anyone holding the node key could
// fill the disk that way on purpose.
func (s *Server) logSessionTableFull() {
	refused := s.sessionTableFullRefused.Add(1)
	if s.log == nil {
		return
	}
	now := time.Now().UnixNano()
	last := s.sessionTableFullLastLog.Load()
	if now-last < int64(sessionTableFullLogInterval) || !s.sessionTableFullLastLog.CompareAndSwap(last, now) {
		return
	}
	s.sessionTableFullRefused.Add(-refused)
	s.log.Errorf(
		"\U0001F6AB <red>Session Table Full: refused <cyan>%d</cyan> SESSION_INIT(s) in the last %s; a node holds at most %d sessions</red>",
		refused, sessionTableFullLogInterval, maxServerSessionSlots,
	)
}
