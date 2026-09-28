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

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
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
		if decision.Reason == "unauthorized-domain" || s.nameErrorBelowTunnelDomain(decision) {
			return s.buildNameErrorResponseLiteLogged(packet, parsed, decision.Reason)
		}
		return s.buildNoDataResponseLiteLogged(packet, parsed, decision.Reason)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-unknown-action")
	}
}

// nameErrorBelowTunnelDomain says whether a query for a name under a tunnel
// domain, of a type other than TXT, gets NXDOMAIN instead of NoData.
//
// Those queries come from resolvers doing QNAME minimisation: they walk down
// the tunnel's labels one at a time (A or NS queries for each ancestor) before
// they ask the real TXT query. NoData tells them each ancestor exists, so they
// keep walking, one round trip per label. NXDOMAIN makes Unbound, BIND and
// PowerDNS give up the walk and send the full TXT query at once. It is sent
// without an SOA, so it is not cached (RFC 2308) and cannot hide the TXT name
// that is asked next; resolvers only cut the tree below an NXDOMAIN (RFC 8020)
// when it is DNSSEC-validated. The tunnel domain itself keeps NoData.
func (s *Server) nameErrorBelowTunnelDomain(decision domainMatcher.Decision) bool {
	return s.nxdomainBelowTunnel &&
		decision.Reason == "unsupported-qtype" &&
		decision.Labels != ""
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision, clientIP string) []byte {
	vpnPacket, err := VpnProto.ParseInflatedFromLabels(decision.Labels, s.codec)
	if err != nil {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "vpn-proto-parse-failed")
	}

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, time.Now())
		return s.buildNoDataResponseLiteLogged(packet, parsed, "session-close-notice")
	}

	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
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
			validation.record.user.noteAddr(clientIP, now, int64(len(packet)+len(response)))
		}
		return response
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
