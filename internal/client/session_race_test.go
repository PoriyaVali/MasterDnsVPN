package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	"masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	initSilent = iota
	initAccept
	initWrongVerify
)

// These peers speak the real v1 DNS init format, including a policy that
// changes the configuration read by resolver-pool creation. The real V2 E2E
// suite independently covers sealed acceptance and older-node compatibility.
func newInitRaceClient(t *testing.T, behaviors ...int) (*Client, []*atomic.Int32) {
	t.Helper()
	codec, err := security.NewCodec(2, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	c := New(config.ClientConfig{
		SessionV2: "off", SessionInitRacingCount: len(behaviors), MTUTestTimeout: 1,
		PacketDuplicationCount: 7, SetupPacketDuplicationCount: 9, RX_TX_Workers: 4,
		MaxUploadMTU: 200, MaxDownloadMTU: 4000,
	}, logger.New("session-init-test", "error"), codec)
	c.syncedUploadMTU, c.syncedDownloadMTU = 120, 400
	matcher := domainmatcher.New([]string{"v.example.com"}, 1)
	var sockets []*net.UDPConn
	var wg sync.WaitGroup
	counts := make([]*atomic.Int32, 0, len(behaviors))
	connections := make([]*Connection, 0, len(behaviors))
	t.Cleanup(func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
		wg.Wait()
		c.closeResolverConnPools()
	})
	for i, behavior := range behaviors {
		socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		sockets = append(sockets, socket)
		addr := socket.LocalAddr().(*net.UDPAddr)
		connections = append(connections, &Connection{
			Key: fmt.Sprint(i), Domain: "v.example.com", Resolver: "127.0.0.1",
			ResolverPort: addr.Port, ResolverLabel: addr.String(),
		})
		count := &atomic.Int32{}
		counts = append(counts, count)
		wg.Add(1)
		go func(socket *net.UDPConn, behavior int, count *atomic.Int32) {
			defer wg.Done()
			buf := make([]byte, 4096)
			for {
				n, peer, err := socket.ReadFromUDP(buf)
				if err != nil {
					return
				}
				count.Add(1)
				if behavior == initSilent {
					continue
				}
				parsed, err := DnsParser.ParsePacketLite(buf[:n])
				if err != nil {
					t.Errorf("parse init query: %v", err)
					return
				}
				decision := matcher.Match(parsed)
				packet, err := VpnProto.ParseFromLabels(decision.Labels, codec)
				if err != nil || len(packet.Payload) < sessionInitPayloadSize {
					t.Errorf("decode init query: %v", err)
					return
				}
				payload := make([]byte, VpnProto.SessionAcceptPayloadSize)
				payload[0], payload[1] = 7, 9
				copy(payload[3:7], packet.Payload[6:10])
				if behavior == initWrongVerify {
					payload[3] ^= 1
				}
				policy := VpnProto.EncodeSessionAcceptClientPolicy(VpnProto.SessionAcceptClientPolicy{
					MaxPacketDuplicationCount: 2, MaxSetupDuplicationCount: 3,
					MaxUploadMTU: 150, MaxDownloadMTU: 1000, MaxRxTxWorkers: 2,
				})
				copy(payload[VpnProto.SessionAcceptBasePayloadSize:], policy[:])
				response, err := DnsParser.BuildVPNResponsePacket(buf[:n], decision.RequestName,
					VpnProto.Packet{PacketType: Enums.PACKET_SESSION_ACCEPT, Payload: payload},
					packet.Payload[0] == mtuProbeBase64Reply)
				if err != nil {
					t.Errorf("build init reply: %v", err)
					return
				}
				_, _ = socket.WriteToUDP(response, peer)
			}
		}(socket, behavior, count)
	}
	c.balancer.SetConnections(connections)
	for _, conn := range connections {
		c.balancer.SetConnectionMTU(conn.Key, 120, 180, 400)
		c.balancer.SetConnectionValidity(conn.Key, true)
	}
	return c, counts
}

func TestSessionInitReturnsOnFirstVerifiedAnswer(t *testing.T) {
	c, counts := newInitRaceClient(t, initAccept, initSilent, initSilent, initSilent, initSilent)
	started := time.Now()
	if err := c.initializeSessionRequest(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= 3*sessionInitStagger {
		t.Fatalf("verified first answer waited for later launches: %v", elapsed)
	}
	if !c.SessionReady() || c.cfg.PacketDuplicationCount != 2 {
		t.Fatal("winning response did not install its session policy")
	}
	if counts[0].Load() != 1 {
		t.Fatal("first resolver did not receive the init")
	}
}

func TestSessionInitCancelsSilentLoserBeforeApplyingPolicy(t *testing.T) {
	c, counts := newInitRaceClient(t, initSilent, initAccept)
	started := time.Now()
	if err := c.initializeSessionRequest(); err != nil {
		t.Fatal(err)
	}
	if counts[0].Load() != 1 || counts[1].Load() != 1 {
		t.Fatal("test did not run both init attempts")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("silent loser was not canceled promptly: %v", elapsed)
	}
	if c.cfg.PacketDuplicationCount != 2 || c.cfg.RX_TX_Workers != 2 {
		t.Fatal("acceptance did not apply the server policy")
	}
	c.resolverConnsMu.Lock()
	defer c.resolverConnsMu.Unlock()
	if len(c.resolverConns) != 0 {
		t.Fatal("an init racer retained a pool after policy replaced the pools")
	}
}

func TestSessionInitInvalidAnswerKeepsLaterResolverAlive(t *testing.T) {
	c, counts := newInitRaceClient(t, initWrongVerify, initAccept)
	if err := c.initializeSessionRequest(); err != nil {
		t.Fatalf("invalid early reply prevented the valid later reply: %v", err)
	}
	if counts[0].Load() != 1 || counts[1].Load() != 1 || !c.SessionReady() {
		t.Fatal("both paths and a valid acceptance were not exercised")
	}
}

func TestInitExchangeCancellationClosesInflightSocket(t *testing.T) {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	c := New(config.ClientConfig{}, nil, nil)
	defer c.closeResolverConnPools()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := c.exchangeDNSOverConnectionWith(ctx, Connection{ResolverLabel: socket.LocalAddr().String()},
			[]byte{0x12, 0x34}, 5*time.Second, false, nil, 8)
		done <- err
	}()
	_ = socket.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := socket.ReadFromUDP(make([]byte, 512)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled exchange returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled exchange kept waiting on its socket")
	}
	c.resolverConnsMu.Lock()
	defer c.resolverConnsMu.Unlock()
	for _, pool := range c.resolverConns {
		if len(pool) != 0 {
			t.Fatal("canceled socket was returned to the pool")
		}
	}
}
