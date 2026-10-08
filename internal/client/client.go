// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic and initialization for the MasterDnsVPN client.
// This file (client.go) defines the main Client struct and bootstrapping process.
// ==============================================================================
package client

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/config"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	Enums "masterdnsvpn-go/internal/enums"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/mlq"
	"masterdnsvpn-go/internal/netutil"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/sessioncrypto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	EDnsSafeUDPSize = 4096
)

type Client struct {
	cfg      config.ClientConfig
	log      *logger.Logger
	codec    *security.Codec
	balancer *Balancer

	successMTUChecks  bool
	udpBufferPool     sync.Pool
	resolverConnsMu   sync.Mutex
	resolverConns     map[string]chan pooledUDPConn
	resolverAddrMu    sync.RWMutex
	resolverAddrCache map[string]*net.UDPAddr
	nowFn             func() time.Time

	// MTU States
	syncedUploadMTU                       int
	syncedDownloadMTU                     int
	syncedUploadChars                     int
	safeUploadMTU                         int
	maxPackedBlocks                       int
	uploadCompression                     uint8
	downloadCompression                   uint8
	mtuCryptoOverhead                     int
	mtuProbeCounter                       atomic.Uint32
	mtuTestRetries                        int
	mtuTestTimeout                        time.Duration
	mtuSaveToFile                         bool
	mtuServersFileName                    string
	mtuServersFileFormat                  string
	mtuSuccessOutputPath                  string
	mtuOutputMu                           sync.Mutex
	mtuUsageSeparatorWritten              bool
	mtuUsingSeparatorText                 string
	mtuRemovedServerLogFormat             string
	mtuAddedServerLogFormat               string
	mtuReactiveAddedServerLogFormat       string
	streamResolverFailoverResendThreshold int
	streamResolverFailoverCooldown        time.Duration

	// Session States
	sessionID          uint8
	sessionCookie      uint8
	responseMode       uint8
	sessionReady       bool
	initStateMu        sync.Mutex
	sessionInitReady   bool
	sessionInitBase64  bool
	sessionInitPayload []byte
	sessionInitVerify  [4]byte
	// Keys the pending SESSION_INIT will be sealed under if the node accepts
	// it as v2; nil for a v1 init.
	sessionInitKeys *sessioncrypto.Keys

	// Session protocol v2 (package sessioncrypto).
	v2Capable      bool // UUID + node secret configured and SESSION_V2 != off
	v2Required     bool // SESSION_V2 = on: never fall back to v1
	v2UserKey      sessioncrypto.UserKey
	v2Mask         sessioncrypto.MaskKey
	v2Device       [sessioncrypto.DeviceLen]byte
	v2Fallback     atomic.Bool // auto mode gave up on v2 for this run
	v2Proven       atomic.Bool // a node accepted v2 once: never fall back
	v2InitFailures int
	// sessionKeys are the live session's keys; nil for a v1 session.
	sessionKeys           atomic.Pointer[sessioncrypto.Keys]
	sessionInitCursor     int
	sessionInitBusyUnix   atomic.Int64
	sessionResetPending   atomic.Bool
	runtimeResetPending   atomic.Bool
	resolverHealthStarted atomic.Bool
	sessionResetSignal    chan struct{}
	rxDroppedPackets      atomic.Uint64
	lastRXDropLogUnix     atomic.Int64

	// Async Runtime Workers & Channels
	asyncWG              sync.WaitGroup
	asyncCancel          context.CancelFunc
	tunnelConns          []*net.UDPConn
	plannerQueue         chan plannerTask
	encodedTXChannel     chan writerTask
	rxChannel            chan asyncReadPacket
	tunnelRX_TX_Workers  int
	tunnelProcessWorkers int
	tunnelPacketTimeout  time.Duration

	// Local Proxy Daemons
	tcpListener *TCPListener
	dnsListener *DNSListener

	// Stream Management
	streamsMu             sync.RWMutex
	active_streams        map[uint16]*Stream_client
	last_stream_id        uint16
	streamSetVersion      atomic.Uint64
	orphanQueue           *mlq.MultiLevelQueue[VpnProto.Packet]
	recentlyClosedMu      sync.Mutex
	recentlyClosedStreams map[uint16]time.Time
	recentlyClosedHeap    recentlyClosedHeap

	// Signals to wake up dispatcher and downstream stages.
	dispatchSignal          chan struct{}
	plannerQueueSpaceSignal chan struct{}
	writerQueueSpaceSignal  chan struct{}

	// Autonomous Ping Manager
	pingManager *PingManager

	// DNS Management
	// Names answered directly instead of through the tunnel. Nil until the
	// config names a rule file, and empty means "tunnel everything", which is
	// the behaviour this client had before the matcher existed.
	bypass                 *BypassMatcher
	bypassCIDRs            *CIDRMatcher
	localDNSCache          *dnsCache.Store
	dnsResponses           *fragmentStore.Store[dnsFragmentKey]
	localDNSCachePersist   bool
	localDNSCachePath      string
	localDNSCacheFlushTick time.Duration
	localDNSCacheLoadOnce  sync.Once
	localDNSCacheFlushOnce sync.Once

	// Callers waiting for an answer that is still in the tunnel, keyed the same
	// way the cache is. See answerWhenReady: a miss used to be answered with
	// silence and the client's own retry, which costs a resolver timeout per
	// name and is why a browser could not load a page while fixed-IP apps were
	// fine.
	dnsWaitersMu sync.Mutex
	dnsWaiters   map[string][]dnsWaiter

	// SOCKS5 brute-force rate limiter
	socksRateLimit *socksRateLimiter

	// Load balancing (pool.go). pool is nil for a client running on its own;
	// a pool member opens no local listeners - the pool owns them - and may
	// hand a new connection to another member.
	pool *Pool
	// runtimeReady: a session is open and the async runtime is running, so a
	// new stream started on this client will be carried.
	runtimeReady atomic.Bool
	// startFailures counts failed attempts to come up since start: MTU scans
	// that found nothing usable and session inits that were not answered.
	// The pool reports a failed start only once every server has some.
	startFailures atomic.Uint64
	// awaitingReplySince is when the oldest send still without any answer
	// went out (UnixNano), 0 when every send has been answered.
	awaitingReplySince atomic.Int64

	// Download pipelining (pull.go): queries in flight, and PING frames queued
	// to pull data but not yet sent.
	queries     *queryTracker
	pullsQueued atomic.Int64

	// serverCaps: the live session's SESSION_ACCEPT capabilities.
	serverCaps atomic.Uint32
}

// clientStreamTXPacket represents a queued packet pending transmission or retransmission.
type clientStreamTXPacket struct {
	PacketType       uint8
	SequenceNum      uint16
	FragmentID       uint8
	TotalFragments   uint8
	CompressionType  uint8
	Payload          []byte
	CreatedAt        time.Time
	TTL              time.Duration
	LastSentAt       time.Time
	RetryDelay       time.Duration
	RetryAt          time.Time
	RetryCount       int
	Scheduled        bool
	isControlCounted atomic.Bool
}

type recentlyClosedEntry struct {
	streamID uint16
	expires  time.Time
}

type recentlyClosedHeap []recentlyClosedEntry

func (h recentlyClosedHeap) Len() int { return len(h) }

func (h recentlyClosedHeap) Less(i, j int) bool {
	return h[i].expires.Before(h[j].expires)
}

func (h recentlyClosedHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *recentlyClosedHeap) Push(x any) {
	*h = append(*h, x.(recentlyClosedEntry))
}

func (h *recentlyClosedHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// plannerTask is the handoff between dispatcher and the planner/encoder stage.
// The dispatcher only decides fairness/dequeue/packing. Resolver selection and
// fan-out happen later in the encode stage.
type plannerTask struct {
	opts      VpnProto.BuildOptions
	dupCount  int
	wasPacked bool
	item      *clientStreamTXPacket
	selected  *Stream_client
	// pull: a poll from pull.go, queued here directly rather than through
	// a stream, so it carries no item.
	pull bool
}

type encodedOutboundDatagram struct {
	addr      *net.UDPAddr
	serverKey string
	packet    []byte
}

type writerTask struct {
	wasPacked bool
	item      *clientStreamTXPacket
	selected  *Stream_client
	frames    []encodedOutboundDatagram
	pull      bool
}

// Bootstrap initializes a new Client by loading configuration, setting up logging,
// and preparing the connection map.
func Bootstrap(configPath string, logPath string, overrides config.ClientConfigOverrides) (*Client, error) {
	cfg, err := config.LoadClientConfigWithOverrides(configPath, overrides)
	if err != nil {
		return nil, err
	}
	return BootstrapLoadedConfig(cfg, logPath)
}

func BootstrapLoadedConfig(cfg config.ClientConfig, logPath string) (*Client, error) {
	var log *logger.Logger
	if logPath != "" {
		log = logger.NewWithFile("MasterDnsVPN Client", cfg.LogLevel, logPath)
	} else {
		log = logger.New("MasterDnsVPN Client", cfg.LogLevel)
	}

	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("client codec setup failed: %w", err)
	}

	c := New(cfg, log, codec)
	if err := c.BuildConnectionMap(); err != nil {
		if c.log != nil {
			c.log.Errorf("<red>%v</red>", err)
		}
		return nil, err
	}
	return c, nil
}

func New(cfg config.ClientConfig, log *logger.Logger, codec *security.Codec) *Client {
	// Before any socket exists, so every resolver dial can ask the app to keep
	// itself off the tunnel this client is about to provide.
	SetProtectPath(cfg.ProtectPath)

	// Rules are loaded once, here, rather than re-read per query: the file is
	// written by the launcher before the process starts, and a lookup on the
	// DNS path must not touch the disk.
	bypass := NewBypassMatcher()
	if cfg.BypassDomainsFile != "" {
		// ⚠️ Relative names resolve against the config's own directory, not the
		// process's working directory. The launcher writes this file beside
		// client.toml and cannot know the absolute path at the time it writes
		// the config, and "next to the config" is what a config referring to a
		// sibling file should mean anyway.
		path := cfg.BypassDomainsFile
		if !filepath.IsAbs(path) && cfg.ConfigDir != "" {
			path = filepath.Join(cfg.ConfigDir, path)
		}
		if n, err := bypass.LoadFile(path); err != nil {
			log.Warnf("↩️ <yellow>Bypass list unreadable (%s): %v — tunnelling everything</yellow>",
				path, err)
		} else {
			log.Infof("↩️ <green>Bypass list loaded: <cyan>%d</cyan> rules</green>", n)
		}
	}

	// Same loading rules as the name list: once, at startup, relative to the
	// config, and a missing file means "tunnel everything", never "do not run".
	bypassCIDRs := NewCIDRMatcher()
	if cfg.BypassCIDRsFile != "" {
		path := cfg.BypassCIDRsFile
		if !filepath.IsAbs(path) && cfg.ConfigDir != "" {
			path = filepath.Join(cfg.ConfigDir, path)
		}
		if n, err := bypassCIDRs.LoadFile(path); err != nil {
			log.Warnf("↩️ <yellow>Bypass ranges unreadable (%s): %v — tunnelling everything</yellow>",
				path, err)
		} else {
			log.Infof("↩️ <green>Bypass ranges loaded: <cyan>%d</cyan> entries, <cyan>%d</cyan> merged ranges</green>",
				n, bypassCIDRs.Len())
		}
	}

	// Session v2 needs the subscriber's identity to key sessions from; without
	// it (a standalone node) the client speaks v1 exactly as before.
	v2Capable := cfg.Uuid != "" && cfg.NodeSecret != "" && cfg.SessionV2 != "off"
	var v2UserKey sessioncrypto.UserKey
	var v2Mask sessioncrypto.MaskKey
	if v2Capable {
		v2UserKey = sessioncrypto.DeriveUserKey([]byte(cfg.NodeSecret), cfg.Uuid)
		v2Mask = sessioncrypto.DeriveMaskKey([]byte(cfg.NodeSecret))
	}

	var responseMode uint8
	if cfg.BaseEncodeData {
		responseMode = mtuProbeBase64Reply
	}

	c := &Client{
		cfg:                 cfg,
		log:                 log,
		codec:               codec,
		balancer:            NewBalancer(cfg.ResolverBalancingStrategy, log),
		uploadCompression:   uint8(cfg.UploadCompressionType),
		downloadCompression: uint8(cfg.DownloadCompressionType),
		mtuCryptoOverhead:   mtuCryptoOverhead(cfg.DataEncryptionMethod),
		maxPackedBlocks:     1,
		responseMode:        responseMode,
		udpBufferPool: sync.Pool{
			New: func() any {
				buf := make([]byte, RuntimeUDPReadBufferSize)
				return &buf
			},
		},
		resolverConns:                         make(map[string]chan pooledUDPConn),
		resolverAddrCache:                     make(map[string]*net.UDPAddr),
		mtuTestRetries:                        cfg.MTUTestRetries,
		mtuTestTimeout:                        time.Duration(cfg.MTUTestTimeout * float64(time.Second)),
		mtuSaveToFile:                         cfg.SaveMTUServersToFile,
		mtuServersFileName:                    cfg.MTUServersFileName,
		mtuServersFileFormat:                  cfg.MTUServersFileFormat,
		mtuUsingSeparatorText:                 cfg.MTUUsingSeparatorText,
		mtuRemovedServerLogFormat:             cfg.MTURemovedServerLogFormat,
		mtuAddedServerLogFormat:               cfg.MTUAddedServerLogFormat,
		mtuReactiveAddedServerLogFormat:       cfg.MTUReactiveAddedServerLogFormat,
		streamResolverFailoverResendThreshold: cfg.StreamResolverFailoverResendThreshold,
		streamResolverFailoverCooldown:        time.Duration(cfg.StreamResolverFailoverCooldownSec * float64(time.Second)),

		// Workers config
		tunnelRX_TX_Workers:     cfg.RX_TX_Workers,
		tunnelProcessWorkers:    cfg.TunnelProcessWorkers,
		tunnelPacketTimeout:     time.Duration(cfg.TunnelPacketTimeoutSec * float64(time.Second)),
		plannerQueue:            make(chan plannerTask, max(24, cfg.RX_TX_Workers*24)),
		encodedTXChannel:        make(chan writerTask, max(24, cfg.RX_TX_Workers*24)),
		rxChannel:               make(chan asyncReadPacket, cfg.EffectiveRXChannelSize()),
		active_streams:          make(map[uint16]*Stream_client),
		recentlyClosedStreams:   make(map[uint16]time.Time),
		recentlyClosedHeap:      make(recentlyClosedHeap, 0, 128),
		dispatchSignal:          make(chan struct{}, 1),
		plannerQueueSpaceSignal: make(chan struct{}, 1),
		writerQueueSpaceSignal:  make(chan struct{}, 1),

		bypass:      bypass,
		bypassCIDRs: bypassCIDRs,

		v2Capable:  v2Capable,
		v2Required: v2Capable && cfg.SessionV2 == "on",
		v2UserKey:  v2UserKey,
		v2Mask:     v2Mask,
		v2Device:   sessioncrypto.DeviceHash(cfg.DeviceID),

		// DNS Management
		// Recorded before any socket is made, so every resolver dial can ask
		// the app to keep itself off the tunnel we are about to provide.
		localDNSCache: dnsCache.New(
			cfg.LocalDNSCacheMaxRecords,
			time.Duration(cfg.LocalDNSCacheTTLSeconds)*time.Second,
			time.Duration(cfg.LocalDNSPendingTimeoutSec)*time.Second,
		),
		dnsResponses:           fragmentStore.New[dnsFragmentKey](cfg.EffectiveDNSResponseFragmentStoreCap()),
		localDNSCachePersist:   cfg.LocalDNSCachePersist,
		localDNSCachePath:      cfg.LocalDNSCachePath(),
		localDNSCacheFlushTick: time.Duration(cfg.LocalDNSCacheFlushSec) * time.Second,
		orphanQueue:            mlq.New[VpnProto.Packet](cfg.EffectiveOrphanQueueInitialCapacity()),
		sessionResetSignal:     make(chan struct{}, 1),
		socksRateLimit:         newSocksRateLimiter(),
		queries:                newQueryTracker(),
	}

	if c.streamResolverFailoverResendThreshold < 1 {
		c.streamResolverFailoverResendThreshold = 1
	}

	if c.streamResolverFailoverCooldown <= 0 {
		c.streamResolverFailoverCooldown = time.Second
	}

	c.balancer.SetStreamFailoverConfig(c.streamResolverFailoverResendThreshold, c.streamResolverFailoverCooldown)
	c.balancer.SetAutoDisableConfig(
		cfg.AutoDisableTimeoutServers,
		time.Duration(cfg.AutoDisableTimeoutWindowSeconds*float64(time.Second)),
	)

	c.balancer.SetResolverDisabledHandler(func(conn *Connection, cause string) {
		c.appendMTURemovedServerLine(conn, cause)
	})

	c.balancer.SetResolverDownConfirmHandler(func(conn *Connection, window time.Duration) bool {
		return c.confirmResolverDown(conn, window)
	})

	c.pingManager = newPingManager(c)
	return c
}

var protectRefusalWarned atomic.Bool

// warnProtectRefusals says once per process that the VPN app could not
// protect some of our sockets. They still work while the app keeps this
// process off the tunnel by uid; if it ever stops doing that, this line is
// what explains a tunnel that captures its own packets.
func warnProtectRefusals(log *logger.Logger) {
	n := netutil.ProtectRefusals()
	if n == 0 || log == nil || !protectRefusalWarned.CompareAndSwap(false, true) {
		return
	}
	log.Warnf("<yellow>The VPN app could not protect %d socket(s); relying on it keeping this process off the tunnel</yellow>", n)
}

// loadBalancedRescanAfter: a load-balanced server whose session init fails
// this many times in a row measures its resolvers again.
const loadBalancedRescanAfter = 3

// mtuRescanDelay is the pause after an MTU scan that found nothing usable.
//
// On its own a client rescans every 5 s: nothing works until it finds a
// resolver, and the network may have just come back. A load-balanced server
// is different - the others carry the traffic, and a server that a network
// blocks would rescan its whole list every few seconds for as long as the app
// runs - so it backs off, to at most a minute.
func (c *Client) mtuRescanDelay(failures int) time.Duration {
	const base = 5 * time.Second
	if c.pool == nil || failures <= 1 {
		return base
	}
	delay := base << min(failures-1, 4)
	if delay > time.Minute {
		delay = time.Minute
	}
	return delay
}

func (c *Client) nextSessionInitRetryDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}

	delay := c.cfg.SessionInitRetryBase()
	if failures > c.cfg.SessionInitRetryLinearAfter {
		delay += time.Duration(failures-c.cfg.SessionInitRetryLinearAfter) * c.cfg.SessionInitRetryStep()
	}

	if delay > c.cfg.SessionInitRetryMax() {
		return c.cfg.SessionInitRetryMax()
	}

	return delay
}

// Run starts the main execution loop of the client.
func (c *Client) Run(parent context.Context) error {
	// Everything started here - the resolver health loop above all - ends
	// with this call. A load-balanced server whose Run fails is restarted by
	// the pool, and its old health loop must not keep probing meanwhile.
	ctx, cancelRun := context.WithCancel(parent)
	defer c.resolverHealthStarted.Store(false) // runs after cancelRun
	defer cancelRun()

	c.successMTUChecks = false
	c.log.Infof("\U0001F504 <cyan>Starting main runtime loop...</cyan>")
	sessionInitRetryDelay := time.Duration(0)
	sessionInitRetryFailures := 0
	mtuScanFailures := 0

	// Ensure local DNS cache is loaded from file if persistence is enabled
	c.ensureLocalDNSCacheLoaded()

	for {
		select {
		case <-ctx.Done():
			c.notifySessionCloseBurst(time.Second)
			c.StopAsyncRuntime()
			return nil
		default:
			if !c.successMTUChecks {
				scanErr := c.RunInitialMTUTests(ctx)
				if scanErr == nil && (c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0) {
					scanErr = fmt.Errorf("Upload MTU: %d, Download MTU: %d", c.syncedUploadMTU, c.syncedDownloadMTU)
				}
				if scanErr != nil {
					if ctx.Err() != nil {
						c.StopAsyncRuntime()
						return nil
					}
					c.log.Errorf("<red>MTU tests failed: %v</red>", scanErr)
					c.successMTUChecks = false
					mtuScanFailures++
					c.startFailures.Add(1)
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(c.mtuRescanDelay(mtuScanFailures)):
					}
					continue
				}

				mtuScanFailures = 0
				c.successMTUChecks = true
				warnProtectRefusals(c.log)
				if c.resolverHealthStarted.CompareAndSwap(false, true) {
					go c.runResolverHealthLoop(ctx)
				}
				c.ShortPrintBanner()
			}

			if !c.sessionReady {
				retries := c.cfg.MTUTestRetries
				if retries < 1 {
					retries = 3
				}

				if err := c.InitializeSession(retries); err != nil {
					sessionInitRetryFailures++
					sessionInitRetryDelay = c.nextSessionInitRetryDelay(sessionInitRetryFailures)
					if c.pool != nil && sessionInitRetryFailures%loadBalancedRescanAfter == 0 {
						// The resolvers that passed the scan may be the ones
						// that died: a load-balanced server keeps its process
						// alive through the others, so nothing else would
						// ever measure them again.
						c.log.Warnf("<yellow>Session init failed %d times; measuring the resolvers again</yellow>", sessionInitRetryFailures)
						c.successMTUChecks = false
					}
					c.startFailures.Add(1)
					if c.pool != nil {
						// ⚠️ Not the words below. The Android app stops the
						// whole core after three "Session initialization
						// failed" lines, and one dead server must not take the
						// others down with it. The pool says those words
						// itself once every server is failing.
						c.log.Errorf("<red>❌ Server session setup failed: %v</red>", err)
					} else {
						c.log.Errorf("<red>❌ Session initialization failed: %v</red>", err)
					}
					c.log.Warnf("<yellow>Session init retry backoff: %s</yellow>", sessionInitRetryDelay)
					select {
					case <-ctx.Done():
						c.notifySessionCloseBurst(time.Second)
						c.StopAsyncRuntime()
						return nil
					case <-time.After(sessionInitRetryDelay):
					}
					continue
				}
				c.log.Infof("<green>✅ Session Initialized Successfully (ID: <cyan>%d</cyan>)</green>", c.sessionID)

				sessionInitRetryFailures = 0
				sessionInitRetryDelay = 0
				if err := c.StartAsyncRuntime(ctx); err != nil {
					c.log.Errorf("<red>❌ Async Runtime failed to launch: %v</red>", err)
					// The session was opened for a runtime that never ran; a
					// later Run (the pool restarts its servers) must open a
					// new one rather than believe it has one.
					c.resetSessionState(true)
					return err
				}

				c.InitVirtualStream0()

				if c.pingManager != nil {
					c.pingManager.Start(ctx)
				}

				c.ensureLocalDNSCachePersistence(ctx)
				c.awaitingReplySince.Store(0)
				c.runtimeReady.Store(true)
			}

			select {
			case <-ctx.Done():
				c.notifySessionCloseBurst(time.Second)
				c.StopAsyncRuntime()
				return nil
			case <-c.sessionResetSignal:
				c.StopAsyncRuntime()
				c.resetSessionState(true)
				c.clearRuntimeResetRequest()
				sessionInitRetryFailures++
				sessionInitRetryDelay = c.nextSessionInitRetryDelay(sessionInitRetryFailures)
				c.log.Warnf("<yellow>Session reset requested, retrying in %s</yellow>", sessionInitRetryDelay)
				select {
				case <-ctx.Done():
					c.notifySessionCloseBurst(time.Second)
					c.StopAsyncRuntime()
					return nil
				case <-time.After(sessionInitRetryDelay):
				}
				continue
			case <-time.After(1 * time.Second):
			}
		}
	}
}

func (c *Client) HandleStreamPacket(packet VpnProto.Packet) error {
	if !packet.HasStreamID {
		return nil
	}

	c.streamsMu.RLock()
	s, ok := c.active_streams[packet.StreamID]
	c.streamsMu.RUnlock()

	if !ok || s == nil {
		return nil
	}

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		if (packet.PacketType == Enums.PACKET_STREAM_DATA ||
			packet.PacketType == Enums.PACKET_STREAM_RESEND ||
			packet.PacketType == Enums.PACKET_STREAM_DATA_NACK) && !c.isRecentlyClosedStream(packet.StreamID, c.now()) {
			c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
		}
		return nil
	}

	switch packet.PacketType {
	case Enums.PACKET_STREAM_DATA, Enums.PACKET_STREAM_RESEND:
		if arqObj.IsClosed() {
			c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
			return nil
		}

		if !s.TerminalSince().IsZero() {
			c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
			return nil
		}

		if !arqObj.ReceiveData(packet.SequenceNum, packet.Payload) {
			return nil
		}

	case Enums.PACKET_STREAM_DATA_NACK:
		if arqObj.IsClosed() || !s.TerminalSince().IsZero() {
			return nil
		}

		if arqObj.HandleDataNack(packet.SequenceNum) {
			c.balancer.NoteStreamProgress(packet.StreamID)
		}
	case Enums.PACKET_STREAM_CONNECTED:
		return c.handleStreamConnected(packet, s, arqObj)
	case Enums.PACKET_STREAM_CONNECT_FAIL:
		return c.handleStreamConnectFail(packet, s, arqObj)
	case Enums.PACKET_STREAM_CLOSE_READ:
		arqObj.MarkCloseReadReceived()
	case Enums.PACKET_STREAM_CLOSE_WRITE:
		arqObj.MarkCloseWriteReceived()
	case Enums.PACKET_STREAM_RST:
		arqObj.MarkRstReceived()
		arqObj.Close("peer reset received", arq.CloseOptions{Force: true})
		s.MarkTerminal(time.Now())
		if s.StatusValue() != streamStatusCancelled {
			s.SetStatus(streamStatusTimeWait)
		}
	default:
		handledAck := arqObj.HandleAckPacket(packet.PacketType, packet.SequenceNum, packet.FragmentID)
		if handledAck {
			c.balancer.NoteStreamProgress(packet.StreamID)
		}
		if _, ok := Enums.GetPacketCloseStream(packet.PacketType); handledAck && ok {
			if s.StatusValue() == streamStatusCancelled || arqObj.IsClosed() {
				s.MarkTerminal(time.Now())
				if s.StatusValue() != streamStatusCancelled {
					s.SetStatus(streamStatusTimeWait)
				}
			}
		}
	}

	return nil
}

func (c *Client) HandleSessionReject(packet VpnProto.Packet) error {
	c.requestSessionRestart("session reject received")
	return nil
}

func (c *Client) HandleSessionBusy() error {
	c.requestSessionRestart("session busy received")
	return nil
}

func (c *Client) HandleErrorDrop(packet VpnProto.Packet) error {
	// The drop names the session it is about. One about an earlier session -
	// a late answer to a query sent before the last re-init - says nothing
	// about this one, and used to tear it down.
	if packet.SessionID != c.sessionID {
		return nil
	}
	c.requestSessionRestart("error drop received")
	return nil
}

func (c *Client) HandleMTUResponse(packet VpnProto.Packet) error {
	return nil
}
