package udpserver

import (
	"encoding/binary"
	"testing"

	"masterdnsvpn-go/internal/compression"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func sessionInitFor(s *Server, uuid string, signature []byte) []byte {
	tok := DeriveUserToken(s.users.secret, uuid)
	return append(append([]byte(nil), signature...), tok[:]...)
}

func acceptedSession(t *testing.T, response []byte) VpnProto.SessionAcceptPayload {
	t.Helper()
	if response == nil {
		t.Fatal("session init was refused")
	}
	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatal(err)
	}
	accept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return accept
}

// A session is found again by its 10-byte signature. Presenting another
// subscriber's signature under one's own valid token must not hand over their
// session - its ID and cookie are all it takes to use it.
func TestSessionInit_SignatureReuseIsPerUser(t *testing.T) {
	s := &Server{
		sessions:                newSessionStore(16, 32),
		users:                   newUserRegistry([]byte("node-secret")),
		uploadCompressionMask:   1 << compression.TypeOff,
		downloadCompressionMask: 1 << compression.TypeOff,
	}
	s.AddUser("alice")
	s.AddUser("mallory")

	query, err := DnsParser.BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, sessionInitDataSize)
	signature[0] = mtuProbeModeRaw
	signature[1] = compression.PackPair(compression.TypeOff, compression.TypeOff)
	binary.BigEndian.PutUint16(signature[2:4], 120)
	binary.BigEndian.PutUint16(signature[4:6], 500)
	copy(signature[6:10], []byte{9, 8, 7, 6})

	init := func(uuid, ip string) []byte {
		return s.handleSessionInitRequest(query, domainMatcher.Decision{RequestName: "x.v.example.com"}, VpnProto.Packet{
			PacketType: Enums.PACKET_SESSION_INIT,
			Payload:    sessionInitFor(s, uuid, signature),
		}, ip)
	}

	alice := acceptedSession(t, init("alice", "198.51.100.1"))

	if resp := init("mallory", "203.0.113.9"); resp != nil {
		stolen := acceptedSession(t, resp)
		if stolen.SessionID == alice.SessionID && stolen.SessionCookie == alice.SessionCookie {
			t.Fatal("another user was handed alice's session")
		}
	}

	// Alice retransmitting her own init still gets her session back.
	again := acceptedSession(t, init("alice", "198.51.100.1"))
	if again.SessionID != alice.SessionID || again.SessionCookie != alice.SessionCookie {
		t.Fatal("alice's own retransmitted init no longer finds her session")
	}

	record, ok := s.sessions.Get(alice.SessionID)
	if !ok || record.user == nil || record.user.uuid != "alice" {
		t.Fatal("session is not attributed to alice")
	}
}
