// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"fmt"
	"time"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/sessioncrypto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (s *Server) handlePacket(packet []byte, clientIP string) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return s.buildNoDataResponseLogged(packet, "request-parse-failed")
	}

	if !parsed.HasQuestion {
		return s.buildNoDataResponseLogged(packet, "request-has-no-question")
	}

	decision := s.domainMatcher.Match(parsed)
	switch decision.Action {
	case domainMatcher.ActionProcess:
		response := s.handleTunnelCandidate(packet, parsed, decision, clientIP)
		if response != nil {
			return response
		}

		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-process-failed")
	case domainMatcher.ActionFormatError:
		return s.buildFormatErrorResponseLiteLogged(packet, parsed, decision.Reason)
	case domainMatcher.ActionNoData:
		if decision.Reason == "unauthorized-domain" {
			return s.buildNameErrorResponseLiteLogged(packet, parsed, decision.Reason)
		}
		return s.buildNoDataResponseLiteLogged(packet, parsed, decision.Reason)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-unknown-action")
	}
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision, clientIP string) []byte {
	vpnPacket, sealed, orphan, err := s.parseTunnelLabels(decision.Labels)
	if err != nil {
		if orphan >= 0 {
			// 🔴 A sealed frame for a session this node cannot open: it was
			// evicted, timed out, or the node restarted and the ID now belongs
			// to someone else. A v1 client in that spot is told "unknown
			// session" and starts over; without the same answer a v2 client
			// would keep sending into a session that no longer exists, for
			// ever. Nothing here needs the keys, and the answer only reaches
			// whoever sent this query.
			return s.buildOrphanSealedDropResponse(packet, decision.RequestName, uint8(orphan))
		}
		return s.buildNoDataResponseLiteLogged(packet, parsed, "vpn-proto-parse-failed")
	}

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, sealed, time.Now())
		return s.buildNoDataResponseLiteLogged(packet, parsed, "session-close-notice")
	}

	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket, sealed)
		if !validation.ok {
			return validation.response
		}

		if !s.handlePostSessionPacket(vpnPacket, validation.record) {
			return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("post-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
		}

		now := time.Now()
		response := s.serveQueuedOrPong(packet, decision.RequestName, validation.record, now)

		// Every authenticated data packet re-notes the address, not just the
		// handshake. Recording it only at SESSION_INIT left the sighting to age
		// out of its TTL while the session was still busy, so a user connected
		// for an hour reported no devices at all after the first two minutes.
		// The byte count is what lets the caller separate a real device from one
		// address out of a carrier's rotating pool.
		if validation.record != nil {
			validation.record.user.noteAddr(validation.record.deviceKey(clientIP), now, int64(len(packet)+len(response)))
		}
		return response
	}

	if sealed {
		// Pre-session requests are never sealed: there is no session yet.
		return s.buildNoDataResponseLiteLogged(packet, parsed, "sealed-pre-session-request")
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket, clientIP)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("pre-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
	}
}

// parseTunnelLabels decodes a query's tunnel payload. sealed reports that it
// was a session v2 frame that opened under its session's own keys - the only
// kind a v2 session accepts. Anything else is read as a v1 frame under the
// node's shared key, exactly as before v2 existed.
//
// When it fails, orphan is the session a sealed-looking frame was routed to
// (else -1), so the caller can tell that client its session is gone.
func (s *Server) parseTunnelLabels(labels string) (vpnPacket VpnProto.Packet, sealed bool, orphan int, err error) {
	orphan = -1
	if labels == "" {
		return VpnProto.Packet{}, false, orphan, VpnProto.ErrInvalidEncodedData
	}
	decoded, err := baseCodec.DecodeString(labels)
	if err != nil {
		return VpnProto.Packet{}, false, orphan, err
	}

	if s.users != nil {
		if sessionID, ok := sessioncrypto.PeekRoute(&s.users.mask, decoded); ok {
			if record, ok := s.sessions.Get(sessionID); ok && record.v2 {
				if frame, ok := record.keys.OpenUp(decoded); ok {
					vpnPacket, err := VpnProto.ParseInflated(frame)
					if err == nil && vpnPacket.SessionID == sessionID {
						return vpnPacket, true, -1, nil
					}
				}
			}
			orphan = int(sessionID)
		}
	}

	if s.codec == nil {
		return VpnProto.Packet{}, false, orphan, VpnProto.ErrCodecUnavailable
	}
	raw := decoded
	if s.codec.Method() != 0 {
		if raw, err = s.codec.Decrypt(decoded); err != nil {
			return VpnProto.Packet{}, false, orphan, err
		}
	}
	// A v1 frame that happened to show the route marker (1 in 256) is still
	// a v1 frame: if it parses, it is not an orphan.
	vpnPacket, err = VpnProto.ParseInflated(raw)
	if err == nil {
		return vpnPacket, false, -1, nil
	}
	return vpnPacket, false, orphan, err
}

// buildOrphanSealedDropResponse answers a sealed frame whose session is gone
// with the same "unknown session" drop a v1 client gets.
func (s *Server) buildOrphanSealedDropResponse(questionPacket []byte, requestName string, sessionID uint8) []byte {
	mode := s.nextUnknownInvalidDropMode()
	if lookup, known := s.sessions.Lookup(sessionID); known {
		mode = lookup.ResponseMode
	}
	s.logInvalidSessionDrop("sealed frame for a gone session", sessionID, 0, 0, mode)
	return s.buildInvalidSessionErrorResponse(questionPacket, requestName, sessionID, mode)
}
