package client

import (
	"testing"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/sessioncrypto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	testSecret = "node-secret"
	testUUID   = "alice-uuid"
)

func v2Client(t *testing.T, mode string) *Client {
	t.Helper()
	cfg := config.ClientConfig{
		Uuid:                 testUUID,
		NodeSecret:           testSecret,
		DeviceID:             "phone-1",
		SessionV2:            mode,
		DataEncryptionMethod: 2,
	}
	codec, err := security.NewCodec(2, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	c := buildTestClientWithResolvers(cfg, "a")
	c.codec = codec
	c.syncedUploadMTU = 120
	c.syncedDownloadMTU = 600
	return c
}

func TestSessionV2InitPayload(t *testing.T) {
	c := v2Client(t, "auto")
	payload, _, _, keys, err := c.buildSessionInitPayload()
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != sessionInitPayloadSize+8+sessioncrypto.InitTailLen || keys == nil {
		t.Fatalf("v2 init: %d bytes, keys=%v", len(payload), keys != nil)
	}
	tail := payload[sessionInitPayloadSize+8:]
	var device [sessioncrypto.DeviceLen]byte
	copy(device[:], tail[1:9])
	if tail[0] != sessioncrypto.Version || device != sessioncrypto.DeviceHash("phone-1") {
		t.Fatal("v2 init does not carry version and device")
	}
	uk := sessioncrypto.DeriveUserKey([]byte(testSecret), testUUID)
	if !sessioncrypto.VerifyInitProof(uk, payload[:sessionInitPayloadSize], tail[0], device, tail[9:]) {
		t.Fatal("the server-side check rejects the client's proof")
	}
}

func TestSessionV2Off(t *testing.T) {
	c := v2Client(t, "off")
	payload, _, _, keys, err := c.buildSessionInitPayload()
	if err != nil || len(payload) != sessionInitPayloadSize+8 || keys != nil {
		t.Fatalf("SESSION_V2=off still built a v2 init (%d bytes)", len(payload))
	}
}

// An updated client meeting a node that predates v2 must still get in - the
// node never answers the longer init, so "auto" retries in v1.
func TestSessionV2AutoFallsBackToV1(t *testing.T) {
	c := v2Client(t, "auto")
	for i := 0; i < v2InitFallbackRounds; i++ {
		c.noteV2InitRoundFailed()
	}
	payload, _, _, keys, _ := c.buildSessionInitPayload()
	if keys != nil || len(payload) != sessionInitPayloadSize+8 {
		t.Fatal("auto did not fall back to v1 after v2 went unanswered")
	}
}

func TestSessionV2NeverFallsBackOnceProvenOrRequired(t *testing.T) {
	proven := v2Client(t, "auto")
	proven.v2Proven.Store(true)
	required := v2Client(t, "on")
	for _, c := range []*Client{proven, required} {
		for i := 0; i < 5*v2InitFallbackRounds; i++ {
			c.noteV2InitRoundFailed()
		}
		if _, _, _, keys, _ := c.buildSessionInitPayload(); keys == nil {
			t.Fatal("fell back to v1 - anyone able to drop packets could switch encryption off")
		}
	}
}

func TestSessionV2EncodeFrameSealsSessionTrafficOnly(t *testing.T) {
	c := v2Client(t, "auto")
	payload, _, _, keys, _ := c.buildSessionInitPayload()
	c.sessionKeys.Store(keys)
	serverKeys, _ := sessioncrypto.DeriveKeys(sessioncrypto.DeriveUserKey([]byte(testSecret), testUUID), payload[:sessionInitPayloadSize], sessioncrypto.DeviceHash("phone-1"))
	mask := sessioncrypto.DeriveMaskKey([]byte(testSecret))

	raw, _ := VpnProto.BuildRaw(VpnProto.BuildOptions{SessionID: 5, SessionCookie: 9, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 2, Payload: []byte("upload")})
	enc, err := c.encodeFrame(5, Enums.PACKET_STREAM_DATA, raw)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := baseCodec.Decode(enc)
	if sid, ok := sessioncrypto.PeekRoute(&mask, wire); !ok || sid != 5 {
		t.Fatal("session frame was not sealed for session 5")
	}
	if got, ok := serverKeys.OpenUp(wire); !ok || string(got) != string(raw) {
		t.Fatal("the server cannot open the client's sealed frame")
	}

	// Pre-session requests have no session to be sealed for.
	init, _ := VpnProto.BuildRaw(VpnProto.BuildOptions{PacketType: Enums.PACKET_MTU_UP_REQ, Payload: []byte{1, 2, 3, 4, 5}})
	enc, _ = c.encodeFrame(5, Enums.PACKET_MTU_UP_REQ, init)
	wire, _ = baseCodec.Decode(enc)
	if _, ok := sessioncrypto.PeekRoute(&mask, wire); ok {
		if _, opened := serverKeys.OpenUp(wire); opened {
			t.Fatal("an MTU probe was sealed")
		}
	}
}

func TestSessionV2InboundDropsUnsealedSessionTraffic(t *testing.T) {
	c := v2Client(t, "auto")
	sig := make([]byte, sessionInitPayloadSize)
	keys, _ := sessioncrypto.DeriveKeys(sessioncrypto.DeriveUserKey([]byte(testSecret), testUUID), sig, sessioncrypto.DeviceHash("phone-1"))
	c.sessionKeys.Store(keys)
	q, _ := DnsParser.BuildTunnelTXTQuestionPacket("t.example.com", []byte("abcdefgh"), Enums.DNS_RECORD_TYPE_TXT, 4096)

	forged, _ := DnsParser.BuildVPNResponsePacket(q, "abcdefgh.t.example.com", VpnProto.Packet{
		SessionID: 3, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, Payload: []byte("injected"),
	}, false)
	if _, trusted, err := c.decodeInbound(forged); err != nil || trusted {
		t.Fatalf("unsealed stream data accepted in a v2 session (err=%v)", err)
	}

	drop, _ := DnsParser.BuildVPNResponsePacket(q, "abcdefgh.t.example.com", VpnProto.Packet{
		SessionID: 3, PacketType: Enums.PACKET_ERROR_DROP, Payload: []byte("INV12345"),
	}, false)
	if _, trusted, _ := c.decodeInbound(drop); !trusted {
		t.Fatal("the server's unsealed 'session gone' must still be heard")
	}

	raw, _ := VpnProto.BuildRaw(VpnProto.BuildOptions{SessionID: 3, PacketType: Enums.PACKET_STREAM_DATA, StreamID: 1, SequenceNum: 1, Payload: []byte("real")})
	sealedDown, _ := keys.SealDown(raw)
	genuine, _ := DnsParser.BuildSealedVPNResponsePacket(q, "abcdefgh.t.example.com", sealedDown, false)
	p, trusted, err := c.decodeInbound(genuine)
	if err != nil || !trusted || string(p.Payload) != "real" {
		t.Fatalf("genuine sealed data refused (err=%v)", err)
	}
}

func TestErrorDropForAnotherSessionIsIgnored(t *testing.T) {
	c := v2Client(t, "off")
	c.sessionID = 5
	_ = c.HandleErrorDrop(VpnProto.Packet{SessionID: 7, PacketType: Enums.PACKET_ERROR_DROP})
	if c.runtimeResetPending.Load() {
		t.Fatal("a drop about an earlier session tore down the current one")
	}
	_ = c.HandleErrorDrop(VpnProto.Packet{SessionID: 5, PacketType: Enums.PACKET_ERROR_DROP})
	if !c.runtimeResetPending.Load() {
		t.Fatal("a drop about this session was ignored")
	}
}

func TestSessionV2UploadBudget(t *testing.T) {
	c := v2Client(t, "auto")
	c.sessionReady = true
	if got := c.uploadPayloadMTU(); got != 120 {
		t.Fatalf("v1 session budget %d, want the measured 120", got)
	}
	_, _, _, keys, _ := c.buildSessionInitPayload()
	c.sessionKeys.Store(keys)
	// Method 2 already paid 16 bytes in the probe; sealing costs 26.
	if got := c.uploadPayloadMTU(); got != 120-(sessioncrypto.UpOverhead-16) {
		t.Fatalf("v2 session budget %d", got)
	}
}
