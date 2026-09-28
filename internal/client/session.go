// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (session.go) handles session states and initialization requests.
// ==============================================================================
package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"masterdnsvpn-go/internal/compression"
	Enums "masterdnsvpn-go/internal/enums"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/mlq"
	"masterdnsvpn-go/internal/sessioncrypto"
	"masterdnsvpn-go/internal/usertoken"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var (
	ErrSessionInitFailed = errors.New("session init failed")
	ErrSessionInitBusy   = errors.New("session init busy: server is at capacity or rejected the request")
)

const (
	sessionInitPayloadSize      = 10
	sessionAcceptPayloadSize    = VpnProto.SessionAcceptPayloadSize
	sessionBusyPayloadSize      = 4
	sessionCloseBurstMaxTargets = 10
	sessionCloseBurstRounds     = 3
)

func (c *Client) InitializeSession(maxAttempts int) error {
	if c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {
		return ErrSessionInitFailed
	}

	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.initializeSessionRequest(); err == nil {
			return nil
		} else if errors.Is(err, ErrNoValidConnections) || errors.Is(err, ErrSessionInitBusy) {
			return err
		}
	}

	c.noteV2InitRoundFailed()
	return ErrSessionInitFailed
}

// v2InitFallbackRounds is how many whole init rounds a v2 SESSION_INIT may go
// unanswered before "auto" retries in v1. A node that predates v2 does not
// answer the longer init at all, so without this an updated client could never
// reach an old node.
const v2InitFallbackRounds = 2

func (c *Client) usingSessionV2() bool {
	return c.v2Capable && !c.v2Fallback.Load()
}

func (c *Client) noteV2InitRoundFailed() {
	if !c.usingSessionV2() || c.v2Required || c.v2Proven.Load() {
		return
	}
	c.v2InitFailures++
	if c.v2InitFailures < v2InitFallbackRounds {
		return
	}
	// ⚠️ Once any node has accepted v2 this run never falls back: a v2 node
	// that stops answering is a network problem, and retrying in v1 would hand
	// anyone able to drop packets a way to switch the encryption off.
	c.v2Fallback.Store(true)
	c.resetSessionInitState()
	if c.log != nil {
		c.log.Warnf("<yellow>Session v2 was not answered; this node looks older than v2 - retrying with v1 (downstream unencrypted)</yellow>")
	}
}

func (c *Client) initializeSessionRequest() error {
	conn, initPayload, verifyCode, initKeys, err := c.nextSessionInitAttempt()
	if err != nil {
		return err
	}

	c.log.Infof("<green>Session init attempt with <cyan>%s</cyan> and resolver <cyan>%s</cyan>", conn.Domain, conn.Resolver)

	query, err := c.buildSessionQuery(conn.Domain, Enums.PACKET_SESSION_INIT, initPayload)
	if err != nil {
		return ErrSessionInitFailed
	}

	// Intra-Resolver Racing: Send 3 parallel requests to the same selected resolver.
	// We staggered each attempt by 100ms.
	const racingCount = 3
	const staggerDelay = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		err    error
		packet VpnProto.Packet
		sealed bool
	}

	resChan := make(chan result, racingCount)

	for i := range racingCount {
		if i > 0 {
			select {
			case <-time.After(staggerDelay):
			case <-ctx.Done():
				goto waitPhase
			}
		}

		go func() {
			// The answer is decoded the way this init asked for it, not by
			// c.responseMode: a session reset zeroes that, which made every
			// re-init in base64 mode unreadable.
			packet, sealed, err := c.exchangeDNSOverConnectionWith(conn, query, c.mtuTestTimeout*3, initPayload[0] == mtuProbeBase64Reply, initKeys)
			select {
			case resChan <- result{err: err, packet: packet, sealed: sealed}:
			case <-ctx.Done():
			}
		}()
	}

waitPhase:
	var lastErr error
	responsesReceived := 0
	for {
		select {
		case res := <-resChan:
			responsesReceived++
			if res.err == nil {
				if err := c.applySessionInitPacket(res.packet, res.sealed, initPayload, verifyCode, initKeys); err == nil {
					cancel()
					return nil
				} else if errors.Is(err, ErrSessionInitBusy) {
					cancel()
					return err
				}
				lastErr = res.err
			} else {
				lastErr = res.err
			}

			if responsesReceived >= racingCount {
				if lastErr == nil {
					return ErrSessionInitFailed
				}
				return lastErr
			}
		case <-time.After(30 * time.Second): // Hard safety timeout
			return ErrSessionInitFailed
		}
	}
}

func (c *Client) applySessionInitPacket(packet VpnProto.Packet, sealed bool, initPayload []byte, verifyCode [4]byte, initKeys *sessioncrypto.Keys) error {
	if c.SessionReady() {
		return nil
	}

	switch packet.PacketType {
	case Enums.PACKET_SESSION_BUSY:
		if len(packet.Payload) < sessionBusyPayloadSize || !bytes.Equal(packet.Payload[:sessionBusyPayloadSize], verifyCode[:]) {
			return ErrSessionInitFailed
		}
		c.setSessionInitBusyUntil(time.Now().Add(c.cfg.SessionInitBusyRetryInterval()))
		return ErrSessionInitBusy
	case Enums.PACKET_SESSION_ACCEPT:
		// A v2 init is only ever accepted sealed under the keys it committed
		// to, and a v1 init only in clear. Anything else is not this node
		// answering this init.
		if sealed != (initKeys != nil) {
			return ErrSessionInitFailed
		}
		sessionAccept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
		if err != nil || !bytes.Equal(sessionAccept.VerifyCode[:], verifyCode[:]) {
			return ErrSessionInitFailed
		}

		c.initStateMu.Lock()
		defer c.initStateMu.Unlock()

		if c.sessionReady {
			return nil
		}

		c.sessionID = sessionAccept.SessionID
		c.sessionCookie = sessionAccept.SessionCookie
		c.responseMode = initPayload[0]
		c.sessionKeys.Store(initKeys)
		if initKeys != nil {
			c.v2Proven.Store(true)
			c.v2InitFailures = 0
		}
		c.uploadCompression, c.downloadCompression = compression.SplitPair(sessionAccept.CompressionPair)
		if sessionAccept.HasClientPolicySync {
			c.applySessionClientPolicy(sessionAccept.ClientPolicy)
		}
		c.sessionReady = true
		c.applySessionCompressionPolicy()
		c.clearSessionInitBusyUntil()
		c.resetSessionInitStateLocked()
		c.clearSessionResetPending()
		return nil
	default:
		return ErrSessionInitFailed
	}
}

func (c *Client) applySessionClientPolicy(policy VpnProto.SessionAcceptClientPolicy) {
	if c == nil {
		return
	}

	before := VpnProto.SessionAcceptClientSettings{
		PacketDuplicationCount:      c.cfg.PacketDuplicationCount,
		SetupPacketDuplicationCount: c.cfg.SetupPacketDuplicationCount,
		MaxUploadMTU:                c.cfg.MaxUploadMTU,
		MaxDownloadMTU:              c.cfg.MaxDownloadMTU,
		RXTXWorkers:                 c.cfg.RX_TX_Workers,
		PingAggressiveInterval:      c.cfg.PingAggressiveIntervalSeconds,
		MaxPacketsPerBatch:          c.cfg.MaxPacketsPerBatch,
		ARQWindowSize:               c.cfg.ARQWindowSize,
		ARQDataNackMaxGap:           c.cfg.ARQDataNackMaxGap,
		CompressionMinSize:          c.cfg.CompressionMinSize,
		ARQInitialRTOSeconds:        c.cfg.ARQInitialRTOSeconds,
		ARQControlInitialRTOSeconds: c.cfg.ARQControlInitialRTOSeconds,
		ARQMaxRTOSeconds:            c.cfg.ARQMaxRTOSeconds,
		ARQControlMaxRTOSeconds:     c.cfg.ARQControlMaxRTOSeconds,
	}

	settings := VpnProto.ApplySessionAcceptClientPolicy(VpnProto.SessionAcceptClientSettings{
		PacketDuplicationCount:      before.PacketDuplicationCount,
		SetupPacketDuplicationCount: before.SetupPacketDuplicationCount,
		MaxUploadMTU:                before.MaxUploadMTU,
		MaxDownloadMTU:              before.MaxDownloadMTU,
		RXTXWorkers:                 before.RXTXWorkers,
		PingAggressiveInterval:      before.PingAggressiveInterval,
		MaxPacketsPerBatch:          before.MaxPacketsPerBatch,
		ARQWindowSize:               before.ARQWindowSize,
		ARQDataNackMaxGap:           before.ARQDataNackMaxGap,
		CompressionMinSize:          before.CompressionMinSize,
		ARQInitialRTOSeconds:        before.ARQInitialRTOSeconds,
		ARQControlInitialRTOSeconds: before.ARQControlInitialRTOSeconds,
		ARQMaxRTOSeconds:            before.ARQMaxRTOSeconds,
		ARQControlMaxRTOSeconds:     before.ARQControlMaxRTOSeconds,
	}, policy)

	c.cfg.PacketDuplicationCount = settings.PacketDuplicationCount
	c.cfg.SetupPacketDuplicationCount = settings.SetupPacketDuplicationCount
	c.cfg.MaxUploadMTU = settings.MaxUploadMTU
	c.cfg.MaxDownloadMTU = settings.MaxDownloadMTU
	c.cfg.RX_TX_Workers = settings.RXTXWorkers
	c.tunnelRX_TX_Workers = settings.RXTXWorkers
	c.cfg.PingAggressiveIntervalSeconds = settings.PingAggressiveInterval
	c.cfg.MaxPacketsPerBatch = settings.MaxPacketsPerBatch
	c.cfg.ARQWindowSize = settings.ARQWindowSize
	c.cfg.ARQDataNackMaxGap = settings.ARQDataNackMaxGap
	c.cfg.CompressionMinSize = settings.CompressionMinSize
	c.cfg.ARQInitialRTOSeconds = settings.ARQInitialRTOSeconds
	c.cfg.ARQControlInitialRTOSeconds = settings.ARQControlInitialRTOSeconds
	c.cfg.TunnelProcessWorkers = deriveSessionPolicyTunnelProcessWorkers(c.cfg.TunnelProcessWorkers, c.cfg.RX_TX_Workers)
	c.tunnelProcessWorkers = c.cfg.TunnelProcessWorkers

	c.syncSessionPolicyDerivedState()

	c.logSessionClientPolicyChanges(before, settings, policy)
}

func (c *Client) syncSessionPolicyDerivedState() {
	if c == nil {
		return
	}

	if c.syncedUploadMTU > 0 {
		c.syncedUploadMTU = min(c.syncedUploadMTU, c.cfg.MaxUploadMTU)
		c.syncedUploadChars = c.encodedCharsForPayload(c.syncedUploadMTU)
		c.safeUploadMTU = computeSafeUploadMTU(c.syncedUploadMTU, c.mtuCryptoOverhead)
		c.maxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(c.uploadPayloadMTU(), 80, c.cfg.MaxPacketsPerBatch)
	} else {
		c.syncedUploadChars = 0
		c.safeUploadMTU = 0
		c.maxPackedBlocks = 1
	}

	if c.syncedDownloadMTU > 0 {
		c.syncedDownloadMTU = min(c.syncedDownloadMTU, c.cfg.MaxDownloadMTU)
	}

	c.closeResolverConnPools()

	if c.asyncCancel != nil {
		return
	}

	c.plannerQueue = make(chan plannerTask, max(24, c.cfg.RX_TX_Workers*24))
	c.encodedTXChannel = make(chan writerTask, max(24, c.cfg.RX_TX_Workers*24))
	c.rxChannel = make(chan asyncReadPacket, c.cfg.EffectiveRXChannelSize())
	c.orphanQueue = mlq.New[VpnProto.Packet](c.cfg.EffectiveOrphanQueueInitialCapacity())
	c.dnsResponses = fragmentStore.New[dnsFragmentKey](c.cfg.EffectiveDNSResponseFragmentStoreCap())
}

func deriveSessionPolicyTunnelProcessWorkers(current int, rxWorkers int) int {
	if rxWorkers < 1 {
		rxWorkers = 1
	}

	recommended := max(4, rxWorkers+1)
	if recommended > 256 {
		recommended = 256
	}

	if current < recommended {
		current = recommended
	}

	if current < rxWorkers {
		return rxWorkers
	}

	if current > 256 {
		return 256
	}
	return current
}

func (c *Client) logSessionClientPolicyChanges(before VpnProto.SessionAcceptClientSettings, after VpnProto.SessionAcceptClientSettings, policy VpnProto.SessionAcceptClientPolicy) {
	if c == nil || c.log == nil {
		return
	}

	logInt := func(label string, oldValue int, newValue int, accepted string) {
		if oldValue == newValue {
			return
		}
		c.log.Warnf(
			"<yellow>Session policy adjusted %s because this server does not accept the requested value</yellow> <magenta>|</magenta> <blue>Requested</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Effective</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Server Rule</blue>: <cyan>%s</cyan>",
			label,
			oldValue,
			newValue,
			accepted,
		)
	}

	logFloat := func(label string, oldValue float64, newValue float64, accepted string) {
		if oldValue == newValue {
			return
		}
		c.log.Warnf(
			"<yellow>Session policy adjusted %s because this server does not accept the requested value</yellow> <magenta>|</magenta> <blue>Requested</blue>: <cyan>%.3f</cyan> <magenta>|</magenta> <blue>Effective</blue>: <cyan>%.3f</cyan> <magenta>|</magenta> <blue>Server Rule</blue>: <cyan>%s</cyan>",
			label,
			oldValue,
			newValue,
			accepted,
		)
	}

	logInt("PACKET_DUPLICATION_COUNT", before.PacketDuplicationCount, after.PacketDuplicationCount, "max="+itoaSafe(policy.MaxPacketDuplicationCount))
	logInt("SETUP_PACKET_DUPLICATION_COUNT", before.SetupPacketDuplicationCount, after.SetupPacketDuplicationCount, "max="+itoaSafe(policy.MaxSetupDuplicationCount))
	logInt("MAX_UPLOAD_MTU", before.MaxUploadMTU, after.MaxUploadMTU, "max="+itoaSafe(policy.MaxUploadMTU))
	logInt("MAX_DOWNLOAD_MTU", before.MaxDownloadMTU, after.MaxDownloadMTU, "max="+itoaSafe(policy.MaxDownloadMTU))
	logInt("RX_TX_WORKERS", before.RXTXWorkers, after.RXTXWorkers, "max="+itoaSafe(policy.MaxRxTxWorkers))
	logFloat("PING_AGGRESSIVE_INTERVAL_SECONDS", before.PingAggressiveInterval, after.PingAggressiveInterval, "min="+formatPolicyFloat(policy.MinPingAggressiveInterval))
	logInt("MAX_PACKETS_PER_BATCH", before.MaxPacketsPerBatch, after.MaxPacketsPerBatch, "max="+itoaSafe(policy.MaxPacketsPerBatch))
	logInt("ARQ_WINDOW_SIZE", before.ARQWindowSize, after.ARQWindowSize, "max="+itoaSafe(policy.MaxARQWindowSize))
	logInt("ARQ_DATA_NACK_MAX_GAP", before.ARQDataNackMaxGap, after.ARQDataNackMaxGap, "max="+itoaSafe(policy.MaxARQDataNackMaxGap))
	logInt("COMPRESSION_MIN_SIZE", before.CompressionMinSize, after.CompressionMinSize, "min="+itoaSafe(policy.MinCompressionMinSize))
	logFloat("ARQ_INITIAL_RTO_SECONDS", before.ARQInitialRTOSeconds, after.ARQInitialRTOSeconds, "min="+formatPolicyFloat(policy.MinARQInitialRTOSeconds))
	logFloat("ARQ_CONTROL_INITIAL_RTO_SECONDS", before.ARQControlInitialRTOSeconds, after.ARQControlInitialRTOSeconds, "min="+formatPolicyFloat(policy.MinARQInitialRTOSeconds))
}

func itoaSafe(value int) string {
	return fmt.Sprintf("%d", value)
}

func formatPolicyFloat(value float64) string {
	return fmt.Sprintf("%.3f", value)
}

func (c *Client) buildSessionInitPayload() ([]byte, bool, [4]byte, *sessioncrypto.Keys, error) {
	var verifyCode [4]byte
	randomPart, err := randomBytes(len(verifyCode))
	if err != nil {
		return nil, false, verifyCode, nil, err
	}
	copy(verifyCode[:], randomPart)

	payload := make([]byte, sessionInitPayloadSize)
	if c.cfg.BaseEncodeData {
		payload[0] = mtuProbeBase64Reply
	}
	payload[1] = compression.PackPair(c.uploadCompression, c.downloadCompression)
	binary.BigEndian.PutUint16(payload[2:4], uint16(c.syncedUploadMTU))
	binary.BigEndian.PutUint16(payload[4:6], uint16(c.syncedDownloadMTU))
	copy(payload[6:10], verifyCode[:])

	// Multi-user: when a UUID + node secret are configured, append the 8-byte
	// identity token so the node can authenticate and meter this user. Nodes
	// without registered users still accept the bare 10-byte form.
	if c.cfg.Uuid != "" && c.cfg.NodeSecret != "" {
		tok := usertoken.Derive([]byte(c.cfg.NodeSecret), c.cfg.Uuid)
		payload = append(payload, tok[:]...)
	}

	// Session v2: version, device, and a proof made with the subscriber's own
	// key, from which this session's keys are also derived.
	var keys *sessioncrypto.Keys
	if c.usingSessionV2() {
		signature := payload[:sessionInitPayloadSize]
		keys, err = sessioncrypto.DeriveKeys(c.v2UserKey, signature, c.v2Device)
		if err != nil {
			return nil, false, verifyCode, nil, err
		}
		proof := sessioncrypto.InitProof(c.v2UserKey, signature, sessioncrypto.Version, c.v2Device)
		payload = append(payload, sessioncrypto.Version)
		payload = append(payload, c.v2Device[:]...)
		payload = append(payload, proof[:]...)
	}

	return payload, payload[0] == mtuProbeBase64Reply, verifyCode, keys, nil
}

func (c *Client) nextSessionInitAttempt() (Connection, []byte, [4]byte, *sessioncrypto.Keys, error) {
	var empty [4]byte
	if c == nil {
		return Connection{}, nil, empty, nil, ErrSessionInitFailed
	}

	c.initStateMu.Lock()
	defer c.initStateMu.Unlock()

	// Persistence Check: reuse existing token/payload if already ready
	if !c.sessionInitReady {
		payload, responseBase64, verifyCode, keys, err := c.buildSessionInitPayload()
		if err != nil {
			return Connection{}, nil, empty, nil, err
		}
		c.sessionInitPayload = payload
		c.sessionInitBase64 = responseBase64
		c.sessionInitVerify = verifyCode
		c.sessionInitKeys = keys
		c.sessionInitReady = true
		c.sessionInitCursor = 0
	}

	active := c.balancer.ActiveConnections()
	if len(active) == 0 {
		return Connection{}, nil, empty, nil, ErrNoValidConnections
	}

	// Use the cursor to rotate between valid resolvers in a Round-Robin fashion.
	validLen := len(active)
	start := c.sessionInitCursor
	for checked := 0; checked < validLen; checked++ {
		idxInValid := (start + checked) % validLen
		conn := active[idxInValid]
		if !conn.IsValid || conn.Key == "" {
			continue
		}

		c.sessionInitCursor = (idxInValid + 1) % validLen
		return conn, c.sessionInitPayload, c.sessionInitVerify, c.sessionInitKeys, nil
	}

	return Connection{}, nil, empty, nil, ErrNoValidConnections
}

func (c *Client) resetSessionInitState() {
	if c == nil {
		return
	}
	c.initStateMu.Lock()
	c.resetSessionInitStateLocked()
	c.initStateMu.Unlock()
}

func (c *Client) resetSessionInitStateLocked() {
	c.sessionInitPayload = nil
	c.sessionInitVerify = [4]byte{}
	c.sessionInitKeys = nil
	c.sessionInitBase64 = false
	c.sessionInitReady = false
	c.sessionInitCursor = 0
}

func (c *Client) setSessionInitBusyUntil(deadline time.Time) {
	if c == nil {
		return
	}
	c.sessionInitBusyUnix.Store(deadline.UnixNano())
}

func (c *Client) clearSessionInitBusyUntil() {
	if c == nil {
		return
	}
	c.sessionInitBusyUnix.Store(0)
}

func (c *Client) sessionInitBusyUntil() time.Time {
	if c == nil {
		return time.Time{}
	}
	unixNano := c.sessionInitBusyUnix.Load()
	if unixNano <= 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano)
}

func (c *Client) buildSessionQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelQuery(domain, 0, packetType, payload)
}

func (c *Client) buildTunnelQuery(domain string, sessionID uint8, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQueryRaw(domain, VpnProto.BuildOptions{
		SessionID:  sessionID,
		PacketType: packetType,
		Payload:    payload,
	})
}

func (c *Client) clearSessionResetPending() {
	if c != nil {
		c.sessionResetPending.Store(false)
	}
}

func (c *Client) notifySessionCloseBurst(timeout time.Duration) {
	if c == nil || !c.SessionReady() || c.sessionID == 0 {
		return
	}
	if !c.sessionResetPending.CompareAndSwap(false, true) {
		return
	}

	targets := c.selectSessionCloseTargets(sessionCloseBurstMaxTargets)
	if len(targets) == 0 {
		c.sessionResetPending.Store(false)
		return
	}

	timeout = normalizeTimeout(timeout, time.Second)
	deadline := time.Now().Add(timeout)

	rounds := sessionCloseBurstRounds
	if rounds < 1 {
		rounds = 1
	}
	interval := timeout / time.Duration(rounds)
	if interval <= 0 {
		interval = timeout
	}

	for round := 0; round < rounds; round++ {
		c.sendSessionCloseRound(targets, deadline)
		if round == rounds-1 {
			break
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		sleepFor := interval
		if sleepFor > remaining {
			sleepFor = remaining
		}
		time.Sleep(sleepFor)
	}

	if c.log != nil {
		c.log.Debugf(
			"\U0001F6AA <yellow>Client Session Close Burst Sent</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Targets</blue>: <cyan>%d</cyan>",
			c.sessionID,
			len(targets),
		)
	}
}

func (c *Client) selectSessionCloseTargets(maxTargets int) []Connection {
	if c == nil {
		return nil
	}

	if maxTargets < 1 {
		maxTargets = 1
	}

	targets := c.balancer.GetUniqueConnections(maxTargets)
	if len(targets) > 0 {
		return targets
	}

	if best, ok := c.balancer.GetBestConnection(); ok {
		return []Connection{best}
	}
	return nil
}

func (c *Client) sendSessionCloseRound(targets []Connection, deadline time.Time) {
	if c == nil || len(targets) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, conn := range targets {
		conn := conn
		wg.Add(1)
		go func() {
			defer wg.Done()
			query, err := c.buildTunnelTXTQueryRaw(conn.Domain, VpnProto.BuildOptions{
				SessionID:     c.sessionID,
				SessionCookie: c.sessionCookie,
				PacketType:    Enums.PACKET_SESSION_CLOSE,
			})
			if err != nil {
				return
			}
			c.sendOneWayDNSQuery(conn, query, deadline)
		}()
	}
	wg.Wait()
}

// applySyncedMTUState updates the client's internal MTU state after successful probing.
func (c *Client) applySyncedMTUState(uploadMTU int, downloadMTU int, uploadChars int) {
	if c == nil {
		return
	}
	c.syncedUploadMTU = uploadMTU
	c.syncedDownloadMTU = downloadMTU
	c.syncedUploadChars = uploadChars
	c.safeUploadMTU = computeSafeUploadMTU(uploadMTU, c.mtuCryptoOverhead)
	c.maxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(c.uploadPayloadMTU(), 80, c.cfg.MaxPacketsPerBatch)
	c.applySessionCompressionPolicy()
	if c.log != nil && c.successMTUChecks {
		c.log.Infof("\U0001F4CF <green>MTU state applied: UP=%d, DOWN=%d</green>", uploadMTU, downloadMTU)
	}
}

func (c *Client) applySessionCompressionPolicy() {
	if c == nil {
		return
	}

	minSize := c.cfg.CompressionMinSize
	if minSize <= 0 {
		minSize = compression.DefaultMinSize
	}

	uploadCompression := compression.NormalizeAvailableType(c.uploadCompression)
	downloadCompression := compression.NormalizeAvailableType(c.downloadCompression)

	const mtuWarningThreshold = 100

	if c.syncedUploadMTU > 0 && c.syncedUploadMTU < mtuWarningThreshold {
		if uploadCompression != compression.TypeOff && c.log != nil {
			c.log.Warnf(
				"⚠️ <red>Session Compression Upload: <cyan>%s</cyan> (Disabled due to low MTU: <cyan>%d</cyan>)</red>",
				compression.TypeName(uploadCompression),
				c.syncedUploadMTU,
			)
		}
		uploadCompression = compression.TypeOff
		c.cfg.UploadCompressionType = int(compression.TypeOff)
	} else if c.syncedUploadMTU > 0 && c.syncedUploadMTU <= minSize {
		if uploadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Upload: <cyan>%s</cyan> (Disabled due to MinSize MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(uploadCompression),
				c.syncedUploadMTU,
			)
		}
		uploadCompression = compression.TypeOff
	}

	if c.syncedDownloadMTU > 0 && c.syncedDownloadMTU < mtuWarningThreshold {
		if downloadCompression != compression.TypeOff && c.log != nil {
			c.log.Warnf(
				"⚠️ <red>Session Compression Download: <cyan>%s</cyan> (Disabled due to low MTU: <cyan>%d</cyan>)</red>",
				compression.TypeName(downloadCompression),
				c.syncedDownloadMTU,
			)
		}
		downloadCompression = compression.TypeOff
		c.cfg.DownloadCompressionType = int(compression.TypeOff)
	} else if c.syncedDownloadMTU > 0 && c.syncedDownloadMTU <= minSize {
		if downloadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Download: <cyan>%s</cyan> (Disabled due to MinSize MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(downloadCompression),
				c.syncedDownloadMTU,
			)
		}
		downloadCompression = compression.TypeOff
	}

	c.uploadCompression = uploadCompression
	c.downloadCompression = downloadCompression

	if c.log != nil {
		c.log.Infof(
			"\U0001F9E9 <green>Effective Compression Upload: <cyan>%s</cyan> Download: <cyan>%s</cyan></green>",
			compression.TypeName(c.uploadCompression),
			compression.TypeName(c.downloadCompression),
		)
	}
}

// uploadPayloadMTU is the most payload one upstream frame may carry.
//
// The measured upload MTU already paid for the node codec's own overhead (the
// probe travels under it). A v2 frame is sealed instead of encoded with that
// codec, so the budget moves by the difference - smaller than v1 under
// ChaCha20 or no encryption, slightly larger under AES-GCM.
func (c *Client) uploadPayloadMTU() int {
	mtu := c.syncedUploadMTU
	if mtu <= 0 {
		return mtu
	}
	if c.sessionKeys.Load() != nil || (c.usingSessionV2() && !c.sessionReady) {
		mtu -= sessioncrypto.UpOverhead - c.mtuCryptoOverhead
	}
	return max(mtu, minSealedUploadPayload)
}

const minSealedUploadPayload = 16
