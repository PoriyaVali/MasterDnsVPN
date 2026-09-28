package udpserver

import (
	"encoding/binary"
	"testing"
	"time"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/compression"
	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/sessioncrypto"
	"masterdnsvpn-go/internal/usertoken"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	v2Domain = "v.example.com"
	v2Secret = "node-secret"
	v2Key    = "0123456789abcdef0123456789abcdef"
)

type v2Harness struct {
	t     *testing.T
	s     *Server
	codec *security.Codec
	mask  sessioncrypto.MaskKey
}

func newV2Harness(t *testing.T, mutate func(*config.ServerConfig)) *v2Harness {
	t.Helper()
	cfg := config.DefaultServerConfig()
	cfg.Domain = []string{v2Domain}
	cfg.UDPPort = 5353
	cfg.DataEncryptionMethod = 2
	cfg.NodeSecret = v2Secret
	if mutate != nil {
		mutate(&cfg)
	}
	cfg, err := config.FinalizeServerConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := security.NewCodec(2, v2Key)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, logger.New("test", "ERROR"), codec)
	return &v2Harness{t: t, s: s, codec: codec, mask: sessioncrypto.DeriveMaskKey([]byte(v2Secret))}
}

// query wraps already-encoded label bytes in a DNS question for the tunnel.
func (h *v2Harness) query(encoded []byte) []byte {
	h.t.Helper()
	q, err := DnsParser.BuildTunnelTXTQuestionPacket(v2Domain, encoded, Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		h.t.Fatal(err)
	}
	return q
}

func (h *v2Harness) v1Encoded(opts VpnProto.BuildOptions) []byte {
	h.t.Helper()
	raw, err := VpnProto.BuildRaw(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	enc, err := h.codec.EncryptAndEncodeBytes(raw)
	if err != nil {
		h.t.Fatal(err)
	}
	return enc
}

func (h *v2Harness) sealedEncoded(keys *sessioncrypto.Keys, opts VpnProto.BuildOptions) []byte {
	h.t.Helper()
	raw, err := VpnProto.BuildRaw(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	sealed, err := keys.SealUp(&h.mask, opts.SessionID, raw)
	if err != nil {
		h.t.Fatal(err)
	}
	return baseCodec.EncodeToBytes(sealed)
}

func signatureWith(verify byte) []byte {
	sig := make([]byte, sessionInitDataSize)
	sig[1] = compression.PackPair(compression.TypeOff, compression.TypeOff)
	binary.BigEndian.PutUint16(sig[2:4], 150)
	binary.BigEndian.PutUint16(sig[4:6], 700)
	copy(sig[6:10], []byte{verify, 2, 3, 4})
	return sig
}

func v2InitPayload(uuid string, sig []byte, device string) ([]byte, *sessioncrypto.Keys) {
	tok := usertoken.Derive([]byte(v2Secret), uuid)
	uk := sessioncrypto.DeriveUserKey([]byte(v2Secret), uuid)
	dev := sessioncrypto.DeviceHash(device)
	proof := sessioncrypto.InitProof(uk, sig, sessioncrypto.Version, dev)
	keys, _ := sessioncrypto.DeriveKeys(uk, sig, dev)
	p := append(append([]byte(nil), sig...), tok[:]...)
	p = append(p, sessioncrypto.Version)
	p = append(p, dev[:]...)
	p = append(p, proof[:]...)
	return p, keys
}

func v1InitPayload(uuid string, sig []byte) []byte {
	tok := usertoken.Derive([]byte(v2Secret), uuid)
	return append(append([]byte(nil), sig...), tok[:]...)
}

// accepted reports whether a response hands out a session (read as v1 - a
// refusal is an empty DNS answer, not silence).
func accepted(resp []byte) bool {
	p, err := DnsParser.ExtractVPNResponse(resp, false)
	return err == nil && p.PacketType == Enums.PACKET_SESSION_ACCEPT
}

func (h *v2Harness) init(payload []byte) []byte {
	return h.s.handlePacket(h.query(h.v1Encoded(VpnProto.BuildOptions{
		PacketType: Enums.PACKET_SESSION_INIT,
		Payload:    payload,
	})), "198.51.100.7")
}

func (h *v2Harness) openV2Session(uuid string, verify byte) (VpnProto.SessionAcceptPayload, *sessioncrypto.Keys) {
	h.t.Helper()
	payload, keys := v2InitPayload(uuid, signatureWith(verify), "phone-"+uuid)
	resp := h.init(payload)
	if resp == nil {
		h.t.Fatal("v2 init refused")
	}
	packet, sealed, err := DnsParser.ExtractVPNResponseWith(resp, false, keys.OpenDown)
	if err != nil || !sealed || packet.PacketType != Enums.PACKET_SESSION_ACCEPT {
		h.t.Fatalf("v2 accept: type=%d sealed=%v err=%v", packet.PacketType, sealed, err)
	}
	accept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
	if err != nil {
		h.t.Fatal(err)
	}
	return accept, keys
}

func TestSessionV2_AcceptIsSealedAndCarriesTheDevice(t *testing.T) {
	h := newV2Harness(t, nil)
	h.s.AddUser("alice")
	var seen []string
	h.s.SetSessionAuthorizer(func(uuid, device string) bool { seen = append(seen, device); return true })

	payload, _ := v2InitPayload("alice", signatureWith(1), "phone")
	if resp := h.init(payload); accepted(resp) {
		t.Fatal("v2 SESSION_ACCEPT (session ID and cookie) readable in clear")
	}
	seen = nil
	accept, _ := h.openV2Session("alice", 2)
	if accept.SessionID == 0 {
		t.Fatal("no session")
	}
	want := sessioncrypto.DeviceAddr(sessioncrypto.DeviceHash("phone-alice"))
	if len(seen) == 0 || seen[0] != want {
		t.Fatalf("authorizer saw %v, want device %s", seen, want)
	}
	record, _ := h.s.sessions.Get(accept.SessionID)
	if record.DownloadMTUBytes != 700-sessioncrypto.DownOverhead {
		t.Fatalf("download payload %d does not leave room for sealing", record.DownloadMTUBytes)
	}
}

// 🔴 The attack this whole change closes: another subscriber (who has the node
// key, as every subscriber does) guessing a session's ID and cookie and then
// polling it - which under v1 handed them the victim's queued downstream data.
func TestSessionV2_UnsealedPacketsGetNothing(t *testing.T) {
	h := newV2Harness(t, nil)
	h.s.AddUser("victim")
	accept, keys := h.openV2Session("victim", 1)

	secret := []byte("victim's downstream")
	h.s.queueMainSessionPacket(accept.SessionID, VpnProto.Packet{
		PacketType: Enums.PACKET_DNS_QUERY_RES, SequenceNum: 9, TotalFragments: 1, Payload: secret,
	})

	// The attacker knows the right ID and cookie (the worst case).
	poll := VpnProto.BuildOptions{
		SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_PING,
		Payload: []byte("PO:1234"),
	}
	resp := h.s.handlePacket(h.query(h.v1Encoded(poll)), "203.0.113.66")
	if p, err := DnsParser.ExtractVPNResponse(resp, false); err == nil {
		t.Fatalf("unsealed poll got a tunnel answer: type %s", Enums.PacketTypeName(p.PacketType))
	}

	// The owner, sealing, gets its data.
	resp = h.s.handlePacket(h.query(h.sealedEncoded(keys, poll)), "198.51.100.7")
	p, sealed, err := DnsParser.ExtractVPNResponseWith(resp, false, keys.OpenDown)
	if err != nil || !sealed || p.PacketType != Enums.PACKET_DNS_QUERY_RES || string(p.Payload) != string(secret) {
		t.Fatalf("owner's sealed poll: type=%s sealed=%v err=%v", Enums.PacketTypeName(p.PacketType), sealed, err)
	}
}

func TestSessionV2_CloseMustBeSealed(t *testing.T) {
	h := newV2Harness(t, nil)
	h.s.AddUser("alice")
	accept, keys := h.openV2Session("alice", 1)
	closeOpts := VpnProto.BuildOptions{SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_SESSION_CLOSE}

	h.s.handlePacket(h.query(h.v1Encoded(closeOpts)), "203.0.113.66")
	if !h.s.sessions.HasActive(accept.SessionID) {
		t.Fatal("an unsealed close (ID and cookie guessed) closed a v2 session")
	}
	h.s.handlePacket(h.query(h.sealedEncoded(keys, closeOpts)), "198.51.100.7")
	if h.s.sessions.HasActive(accept.SessionID) {
		t.Fatal("the owner's sealed close did not close the session")
	}
}

func TestSessionV2_InitNeedsTheUsersKeyNotJustTheToken(t *testing.T) {
	h := newV2Harness(t, nil)
	h.s.AddUser("alice")
	payload, _ := v2InitPayload("alice", signatureWith(1), "phone")
	// Proof made by someone who has alice's token but not her UUID.
	forged := append([]byte(nil), payload...)
	wrong := sessioncrypto.InitProof(sessioncrypto.DeriveUserKey([]byte(v2Secret), "guess"), forged[:sessionInitDataSize], sessioncrypto.Version, sessioncrypto.DeviceHash("phone"))
	copy(forged[len(forged)-sessioncrypto.ProofLen:], wrong[:])
	if resp := h.init(forged); accepted(resp) || len(resp) == 0 {
		t.Fatal("a v2 init with a wrong proof was accepted")
	}
	if _, keys := v2InitPayload("alice", signatureWith(1), "phone"); keys != nil {
		if _, sealed, _ := DnsParser.ExtractVPNResponseWith(h.init(forged), false, keys.OpenDown); sealed {
			t.Fatal("a v2 init with a wrong proof got a sealed answer")
		}
	}
}

func TestSessionV2_V1InitCannotReachAV2Session(t *testing.T) {
	h := newV2Harness(t, nil)
	h.s.AddUser("alice")
	sig := signatureWith(1)
	h.openV2Session("alice", 1)
	if accepted(h.init(v1InitPayload("alice", sig))) {
		t.Fatal("a v1 init with a v2 session's signature was handed the session")
	}
}

func TestSessionV2_RequireRefusesV1(t *testing.T) {
	h := newV2Harness(t, func(c *config.ServerConfig) { c.RequireSessionV2 = true })
	h.s.AddUser("alice")
	if accepted(h.init(v1InitPayload("alice", signatureWith(1)))) {
		t.Fatal("REQUIRE_SESSION_V2 still accepted a v1 init")
	}
	h.openV2Session("alice", 2)
}

func TestSessionV1_StillServedByDefault(t *testing.T) {
	h := newV2Harness(t, nil)
	h.s.AddUser("alice")
	resp := h.init(v1InitPayload("alice", signatureWith(1)))
	p, err := DnsParser.ExtractVPNResponse(resp, false)
	if err != nil || p.PacketType != Enums.PACKET_SESSION_ACCEPT {
		t.Fatalf("v1 client refused: type=%d err=%v", p.PacketType, err)
	}
}

func TestSessionStore_PerUserCapReplacesTheQuietest(t *testing.T) {
	store := newSessionStore(8, 32)
	store.maxSessionsPerUser = 2
	alice := &userAccount{uuid: "alice"}
	owner := sessionOwner{user: alice}

	a, _, _, err := store.findOrCreateFor(owner, signatureWith(1), 0, 0, 8, 150, 700)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := store.findOrCreateFor(owner, signatureWith(2), 0, 0, 8, 150, 700)
	if err != nil {
		t.Fatal(err)
	}
	// Both busy: a third is refused rather than cutting a live session.
	if _, _, _, err := store.findOrCreateFor(owner, signatureWith(3), 0, 0, 8, 150, 700); err != ErrUserSessionLimit {
		t.Fatalf("third session while both are busy: %v", err)
	}
	// a goes quiet: the next one replaces it.
	a.setLastActivity(time.Now().Add(-perUserEvictIdle - time.Second))
	c, _, evicted, err := store.findOrCreateFor(owner, signatureWith(3), 0, 0, 8, 150, 700)
	if err != nil || c == nil {
		t.Fatalf("replacement refused: %v", err)
	}
	if len(evicted) != 1 || evicted[0].record != a {
		t.Fatal("the quiet session was not the one replaced")
	}
	if !store.HasActive(b.ID) {
		t.Fatal("a busy session was evicted")
	}
	if lookup, ok := store.Lookup(a.ID); !ok || lookup.State != sessionLookupClosed {
		t.Fatal("the evicted session does not answer 'closed', so its client would not re-init")
	}
}

func TestSessionStore_FullTableEvictsOnlySilentSessions(t *testing.T) {
	store := newSessionStore(8, 32)
	store.maxActiveSessions = 2
	a, _, _, _ := store.findOrCreateFor(sessionOwner{}, signatureWith(1), 0, 0, 8, 150, 700)
	store.findOrCreateFor(sessionOwner{}, signatureWith(2), 0, 0, 8, 150, 700)
	if _, _, _, err := store.findOrCreateFor(sessionOwner{}, signatureWith(3), 0, 0, 8, 150, 700); err != ErrSessionTableFull {
		t.Fatalf("full table with live sessions: %v", err)
	}
	a.setLastActivity(time.Now().Add(-tableEvictIdle - time.Second))
	c, _, evicted, err := store.findOrCreateFor(sessionOwner{}, signatureWith(3), 0, 0, 8, 150, 700)
	if err != nil || c == nil || len(evicted) != 1 || evicted[0].record != a {
		t.Fatalf("silent session not evicted for room: err=%v evicted=%d", err, len(evicted))
	}
}

// The control for TestSessionV2_UnsealedPacketsGetNothing: the same poll on a
// v1 session does hand over the queued data. This is the hole v2 closes, and
// it shows the probe above is able to see a leak when there is one.
func TestSessionV1_ControlGuessedCookieReadsQueuedData(t *testing.T) {
	h := newV2Harness(t, nil)
	h.s.AddUser("victim")
	p, err := DnsParser.ExtractVPNResponse(h.init(v1InitPayload("victim", signatureWith(1))), false)
	if err != nil {
		t.Fatal(err)
	}
	accept, _ := VpnProto.DecodeSessionAcceptPayload(p.Payload)
	h.s.queueMainSessionPacket(accept.SessionID, VpnProto.Packet{
		PacketType: Enums.PACKET_DNS_QUERY_RES, SequenceNum: 9, TotalFragments: 1, Payload: []byte("victim's downstream"),
	})
	resp := h.s.handlePacket(h.query(h.v1Encoded(VpnProto.BuildOptions{
		SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_PING, Payload: []byte("PO:1234"),
	})), "203.0.113.66")
	got, err := DnsParser.ExtractVPNResponse(resp, false)
	if err != nil || string(got.Payload) != "victim's downstream" {
		t.Fatalf("control failed: v1 poll did not return the queued data (err=%v)", err)
	}
}

// A v2 client whose session is gone (evicted, expired, node restarted) must be
// told so, as a v1 client is - otherwise it sends into the void for ever.
func TestSessionV2_GoneSessionAnswersDrop(t *testing.T) {
	h := newV2Harness(t, nil)
	h.s.AddUser("alice")
	accept, keys := h.openV2Session("alice", 1)
	record, _ := h.s.sessions.Get(accept.SessionID)
	h.s.sessions.Close(accept.SessionID, time.Now(), time.Minute)
	h.s.cleanupClosedSession(accept.SessionID, record)

	resp := h.s.handlePacket(h.query(h.sealedEncoded(keys, VpnProto.BuildOptions{
		SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_PING, Payload: []byte("PO:1234"),
	})), "198.51.100.7")
	p, err := DnsParser.ExtractVPNResponse(resp, false)
	if err != nil || p.PacketType != Enums.PACKET_ERROR_DROP || p.SessionID != accept.SessionID {
		t.Fatalf("gone v2 session: type=%s sid=%d err=%v, want ERROR_DROP for sid %d",
			Enums.PacketTypeName(p.PacketType), p.SessionID, err, accept.SessionID)
	}

	// Same after a restart, when the node has never heard of the session.
	fresh := newV2Harness(t, nil)
	fresh.s.AddUser("alice")
	resp = fresh.s.handlePacket(fresh.query(fresh.sealedEncoded(keys, VpnProto.BuildOptions{
		SessionID: accept.SessionID, SessionCookie: accept.SessionCookie, PacketType: Enums.PACKET_PING, Payload: []byte("PO:1234"),
	})), "198.51.100.7")
	// A node that has never seen the session does not know how the client
	// reads answers, so (as for v1) it alternates raw and base64; the client
	// reads the one in its own mode.
	p, err = DnsParser.ExtractVPNResponse(resp, false)
	if err != nil {
		p, err = DnsParser.ExtractVPNResponse(resp, true)
	}
	if err != nil || p.PacketType != Enums.PACKET_ERROR_DROP || p.SessionID != accept.SessionID {
		t.Fatalf("restarted node: type=%s err=%v, want ERROR_DROP", Enums.PacketTypeName(p.PacketType), err)
	}
}
