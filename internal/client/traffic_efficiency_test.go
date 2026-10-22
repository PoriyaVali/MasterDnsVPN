package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/mlq"
	"masterdnsvpn-go/internal/sessioncrypto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func compactV2Client(t *testing.T) *Client {
	t.Helper()
	c := v2Client(t, "on")
	_, _, _, keys, err := c.buildSessionInitPayload()
	if err != nil {
		t.Fatal(err)
	}
	c.sessionKeys.Store(keys)
	c.sessionID, c.sessionCookie = 5, 9
	c.cfg.PacketDuplicationCount, c.cfg.SetupPacketDuplicationCount = 3, 5
	return c
}

func TestV2PingDropsOnlyUnusedBody(t *testing.T) {
	c := compactV2Client(t)
	payload, err := c.sessionPingPayload()
	if err != nil || len(payload) != 0 {
		t.Fatalf("v2 ping body: len=%d err=%v", len(payload), err)
	}
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		raw, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
			SessionID: c.sessionID, SessionCookie: c.sessionCookie, PacketType: Enums.PACKET_PING, Payload: payload,
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := c.encodeFrame(c.sessionID, Enums.PACKET_PING, raw)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(encoded)] {
			t.Fatal("compact ping reused its encrypted query name")
		}
		seen[string(encoded)] = true
		wire, err := baseCodec.Decode(encoded)
		if err != nil || len(wire) != len(raw)+sessioncrypto.UpOverhead {
			t.Fatalf("AEAD overhead changed: sealed=%d raw=%d err=%v", len(wire), len(raw), err)
		}
		opened, ok := c.sessionKeys.Load().OpenUp(wire)
		if !ok || !bytes.Equal(opened, raw) {
			t.Fatal("compact ping did not authenticate and round trip")
		}
		for pos := range wire {
			corrupt := bytes.Clone(wire)
			corrupt[pos] ^= 1
			if _, ok := c.sessionKeys.Load().OpenUp(corrupt); ok {
				t.Fatalf("tampering with byte %d was accepted", pos)
			}
		}
	}
	legacyRaw, _ := VpnProto.BuildRaw(VpnProto.BuildOptions{SessionID: c.sessionID, SessionCookie: c.sessionCookie, PacketType: Enums.PACKET_PING, Payload: []byte("PO:1234")})
	legacyEncoded, err := c.encodeFrame(c.sessionID, Enums.PACKET_PING, legacyRaw)
	if err != nil {
		t.Fatal(err)
	}
	for compact := range seen {
		if got := len(legacyEncoded) - len(compact); got != 11 {
			t.Fatalf("query-label saving = %d bytes, want 11", got)
		}
	}
}

func TestLegacyPingRetainsCacheBustingBody(t *testing.T) {
	c := &Client{}
	first, err := c.sessionPingPayload()
	if err != nil || len(first) != 7 || string(first[:3]) != "PO:" {
		t.Fatalf("legacy ping format changed: len=%d err=%v", len(first), err)
	}
	second, err := c.sessionPingPayload()
	if err != nil || bytes.Equal(first, second) {
		t.Fatal("legacy ping lost its random cache-busting suffix")
	}
}

func TestDispatcherPreservesPackedACKCopies(t *testing.T) {
	c := compactV2Client(t)
	c.maxPackedBlocks = 8
	c.plannerQueue = make(chan plannerTask, 4)
	s := &Stream_client{client: c, StreamID: 1, txQueue: mlq.New[*clientStreamTXPacket](8)}
	c.active_streams = map[uint16]*Stream_client{1: s}
	c.bumpStreamSetVersion()
	for seq := uint16(1); seq <= 2; seq++ {
		if !s.PushTXPacket(0, Enums.PACKET_STREAM_DATA_ACK, seq, 0, 0, 0, 0, nil) {
			t.Fatal("failed to queue ACK")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.asyncWG.Add(1)
	go c.asyncStreamDispatcher(ctx)
	defer func() { cancel(); c.asyncWG.Wait() }()
	select {
	case task := <-c.plannerQueue:
		if task.opts.PacketType != Enums.PACKET_PACKED_CONTROL_BLOCKS || task.dupCount != 5 || len(task.opts.Payload) != 2*VpnProto.PackedControlBlockSize {
			t.Fatalf("unexpected packed ACK task: type=%d copies=%d payload=%d", task.opts.PacketType, task.dupCount, len(task.opts.Payload))
		}
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not emit the ACK batch")
	}
}
