// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"container/heap"
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/config"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	mtuProbeModeRaw     = 0
	mtuProbeModeBase64  = 1
	mtuProbeCodeLength  = 4
	mtuProbeMetaLength  = mtuProbeCodeLength + 2
	mtuProbeUpMinSize   = 1 + mtuProbeCodeLength
	mtuProbeDownMinSize = mtuProbeUpMinSize + 2
	mtuProbeMinDownSize = VpnProto.SessionAcceptWireSize
	mtuProbeMaxDownSize = 4096
)

var preSessionPacketTypes = buildPreSessionPacketTypes()

type Server struct {
	cfg                      config.ServerConfig
	log                      *logger.Logger
	codec                    *security.Codec
	users                    *userRegistry
	authorizerMu             sync.RWMutex
	authorizer               SessionAuthorizer
	domainMatcher            *domainMatcher.Matcher
	nxdomainBelowTunnel      bool
	sessions                 *sessionStore
	deferredDNSSession       *deferredSessionProcessor
	deferredConnectSession   *deferredSessionProcessor
	invalidCookieTracker     *invalidCookieTracker
	dnsCache                 *dnsCache.Store
	dnsResolveInflight       *dnsResolveInflightManager
	dnsUpstreamServers       []string
	dnsUpstreamBufferPool    sync.Pool
	dnsFragments             *fragmentStore.Store[dnsFragmentKey]
	socks5Fragments          *fragmentStore.Store[socks5FragmentKey]
	dnsFragmentTimeout       time.Duration
	resolveDNSQueryFn        func([]byte) ([]byte, error)
	dialStreamUpstreamFn     func(string, string, time.Duration) (net.Conn, error)
	lookupTargetIPsFn        func(context.Context, string) ([]netip.Addr, error)
	uploadCompressionMask    uint8
	downloadCompressionMask  uint8
	dropLogIntervalNanos     int64
	invalidCookieWindow      time.Duration
	invalidCookieWindowNanos int64
	invalidCookieThreshold   int
	socksConnectTimeout      time.Duration
	useExternalSOCKS5        bool
	externalSOCKS5Address    string
	externalSOCKS5Auth       bool
	externalSOCKS5User       []byte
	externalSOCKS5Pass       []byte
	streamOutboundTTL        time.Duration
	streamOutboundMaxRetry   int
	mtuProbePayloadPool      sync.Pool
	packetPool               sync.Pool
	deferredInflightMu       sync.Mutex
	deferredInflight         map[uint64]struct{}
	deferredInflightIndex    map[uint8]map[uint16]map[uint64]struct{}
	immediateConnectedLog    throttledLogState
	invalidSessionDropLog    throttledLogState
	droppedPackets           atomic.Uint64
	lastDropLogUnix          atomic.Int64
	deferredDroppedPackets   atomic.Uint64
	lastDeferredDropLogUnix  atomic.Int64
	pongNonce                atomic.Uint32
	invalidDropMode          atomic.Uint32
	refusedInitsTableFull    atomic.Int64
	refusedInitsUserLimit    atomic.Int64
	refusedInitsReportArmed  atomic.Bool
	// earlyData: hold stream data that overtakes its SYN (early_data.go).
	earlyData bool
}

type request struct {
	buf  []byte
	size int
	addr *net.UDPAddr
	conn *net.UDPConn
	// reply sends the response back on a TCP connection; nil for UDP.
	reply func([]byte)
}

type postSessionValidation struct {
	record   *sessionRuntimeView
	response []byte
	ok       bool
}

func New(cfg config.ServerConfig, log *logger.Logger, codec *security.Codec) *Server {
	invalidCookieWindow := cfg.InvalidCookieWindow()
	if invalidCookieWindow <= 0 {
		invalidCookieWindow = 2 * time.Second
	}
	dnsFragmentTimeout := cfg.DNSFragmentAssemblyTimeout()
	if dnsFragmentTimeout <= 0 {
		dnsFragmentTimeout = 5 * time.Minute
	}
	dropLogInterval := cfg.DropLogInterval()
	if dropLogInterval <= 0 {
		dropLogInterval = 2 * time.Second
	}
	socksConnectTimeout := cfg.SOCKSConnectTimeout()
	if socksConnectTimeout <= 0 {
		socksConnectTimeout = 8 * time.Second
	}
	dnsDeferredWorkers, connectDeferredWorkers, dnsDeferredQueue, connectDeferredQueue := splitDeferredSessionPools(cfg.EffectiveDeferredSessionWorkers(), cfg.EffectiveDeferredSessionQueueLimit())
	sessions := newSessionStore(cfg.EffectiveSessionOrphanQueueInitialCap(), cfg.EffectiveStreamQueueInitialCapacity(), cfg.SessionInitReuseTTL(), cfg.RecentlyClosedStreamTTL(), cfg.RecentlyClosedStreamCap)
	sessions.maxActiveSessions = cfg.MaxAllowedClientActiveSessions
	sessions.maxActiveStreams = cfg.MaxAllowedClientActiveStreams
	sessions.maxSessionsPerUser = cfg.MaxSessionsPerUser
	if retention := cfg.ClosedSessionRetention(); retention > 0 {
		sessions.closedRetention = retention
	}
	server := &Server{
		cfg:                    cfg,
		log:                    log,
		codec:                  codec,
		users:                  newUserRegistry([]byte(cfg.NodeSecret)),
		domainMatcher:          domainMatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		nxdomainBelowTunnel:    cfg.NXDomainForNonTXTSubdomains,
		sessions:               sessions,
		deferredDNSSession:     newDeferredSessionProcessor(dnsDeferredWorkers, dnsDeferredQueue, log),
		deferredConnectSession: newDeferredSessionProcessor(connectDeferredWorkers, connectDeferredQueue, log),
		invalidCookieTracker:   newInvalidCookieTracker(),
		dnsCache: dnsCache.New(
			cfg.EffectiveDNSCacheMaxRecords(),
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			dnsFragmentTimeout,
		),
		dnsResolveInflight: newDNSResolveInflightManager(dnsFragmentTimeout),
		dnsUpstreamServers: append([]string(nil), cfg.DNSUpstreamServers...),
		dnsFragments:       fragmentStore.New[dnsFragmentKey](cfg.EffectiveDNSFragmentStoreCapacity()),
		socks5Fragments:    fragmentStore.New[socks5FragmentKey](cfg.EffectiveSOCKS5FragmentStoreCapacity()),
		dnsFragmentTimeout: dnsFragmentTimeout,
		dnsUpstreamBufferPool: sync.Pool{
			New: func() any {
				buf := make([]byte, 65535)
				return &buf
			},
		},
		dialStreamUpstreamFn: func(network string, address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		},
		uploadCompressionMask:    buildCompressionMask(cfg.SupportedUploadCompressionTypes),
		downloadCompressionMask:  buildCompressionMask(cfg.SupportedDownloadCompressionTypes),
		dropLogIntervalNanos:     dropLogInterval.Nanoseconds(),
		invalidCookieWindow:      invalidCookieWindow,
		invalidCookieWindowNanos: invalidCookieWindow.Nanoseconds(),
		invalidCookieThreshold:   cfg.InvalidCookieErrorThreshold,
		socksConnectTimeout:      socksConnectTimeout,
		earlyData:                cfg.EarlyDataEnabled,
		useExternalSOCKS5:        cfg.UseExternalSOCKS5,
		externalSOCKS5Address:    net.JoinHostPort(cfg.ForwardIP, strconv.Itoa(cfg.ForwardPort)),
		externalSOCKS5Auth:       cfg.SOCKS5Auth,
		externalSOCKS5User:       []byte(cfg.SOCKS5User),
		externalSOCKS5Pass:       []byte(cfg.SOCKS5Pass),
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				return make([]byte, mtuProbeMaxDownSize)
			},
		},
		deferredInflight:      make(map[uint64]struct{}, 128),
		deferredInflightIndex: make(map[uint8]map[uint16]map[uint64]struct{}, 64),
		packetPool: sync.Pool{
			New: func() any {
				return make([]byte, udpReadBufferSize(cfg.MaxPacketSize))
			},
		},
	}
	// Set here, before any session exists, rather than on every SESSION_INIT:
	// retransmitted inits for one session reach several workers at once, and
	// each used to write the record's callback while another could read it.
	server.sessions.streamCleanup = server.cleanupStreamArtifacts
	return server
}

// maxDNSQueryDatagram bounds the per-read buffer. Every request is a DNS query
// whose payload rides in a <=255-byte name, so real ones are a few hundred
// bytes; a larger datagram is truncated, fails to parse and is dropped, as a
// junk one should be.
//
// ⚠️ Each queued request holds its buffer until a worker answers it. At the old
// 64KB per buffer a full request queue (16384 by default) pinned a gigabyte of
// memory - reachable by anyone able to send this port a flood of datagrams.
const maxDNSQueryDatagram = 4096

func udpReadBufferSize(configured int) int {
	if configured <= 0 || configured > maxDNSQueryDatagram {
		return maxDNSQueryDatagram
	}
	return configured
}

type throttledLogState struct {
	mu   sync.Mutex
	last map[string]int64
	heap throttledLogHeap
}

type throttledLogEntry struct {
	key  string
	seen int64
}

type throttledLogHeap []throttledLogEntry

func (h throttledLogHeap) Len() int { return len(h) }

func (h throttledLogHeap) Less(i, j int) bool {
	return h[i].seen < h[j].seen
}

func (h throttledLogHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *throttledLogHeap) Push(x any) {
	*h = append(*h, x.(throttledLogEntry))
}

func (h *throttledLogHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

const (
	throttledLogSoftCap = 1024
	throttledLogHardCap = 1536
)

func (s *throttledLogState) allow(key string, now time.Time, interval time.Duration) bool {
	if s == nil {
		return true
	}
	if interval <= 0 {
		interval = time.Second
	}

	nowUnixNano := now.UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.last == nil {
		s.last = make(map[string]int64, 64)
	}

	last := s.last[key]

	if last != 0 && nowUnixNano-last < interval.Nanoseconds() {
		return false
	}

	s.last[key] = nowUnixNano
	heap.Push(&s.heap, throttledLogEntry{key: key, seen: nowUnixNano})

	if len(s.last) > 0 {
		s.pruneLocked(nowUnixNano, interval)
	}

	return true
}

func (s *throttledLogState) pruneLocked(nowUnixNano int64, interval time.Duration) {
	if s == nil || len(s.last) == 0 {
		return
	}

	cutoff := nowUnixNano - interval.Nanoseconds()
	for len(s.heap) > 0 {
		entry := s.heap[0]
		last, ok := s.last[entry.key]
		if !ok || last != entry.seen {
			heap.Pop(&s.heap)
			continue
		}
		if entry.seen > cutoff && len(s.last) <= throttledLogHardCap {
			break
		}
		delete(s.last, entry.key)
		heap.Pop(&s.heap)
	}

	for len(s.last) > throttledLogSoftCap && len(s.heap) > 0 {
		entry := heap.Pop(&s.heap).(throttledLogEntry)
		last, ok := s.last[entry.key]
		if !ok || last != entry.seen {
			continue
		}
		delete(s.last, entry.key)
	}
}

const (
	minDNSDeferredWorkers = 4
	maxDNSDeferredWorkers = 32
)

func splitDeferredSessionPools(totalWorkers int, totalQueue int) (dnsWorkers int, connectWorkers int, dnsQueue int, connectQueue int) {
	if totalWorkers <= 0 {
		totalWorkers = 1
	}
	if totalQueue <= 0 {
		totalQueue = 256
	}

	// DNS queries use a dedicated pool so connect-heavy work keeps the full
	// user-configured deferred capacity.
	//
	// 🔴 It used to be ONE worker for the whole node. A tunnelled lookup blocks
	// its worker for the upstream round trip - up to DNS_UPSTREAM_TIMEOUT, twice
	// over when the host-resolver fallback runs, and up to
	// DNS_INFLIGHT_WAIT_TIMEOUT when it waits on someone else's lookup - so one
	// slow or dead name stalled DNS for every user on the node, and throughput
	// was capped at one upstream round trip at a time. The work is waiting, not
	// computing, so it takes as many workers as the connect pool.
	dnsWorkers = min(max(totalWorkers, minDNSDeferredWorkers), maxDNSDeferredWorkers)
	connectWorkers = totalWorkers

	connectQueue = totalQueue
	dnsQueue = min(max(totalQueue/4, 64), 256)

	return dnsWorkers, connectWorkers, dnsQueue, connectQueue
}

func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	conns, err := s.openUDPListeners()
	if err != nil {
		return err
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	s.log.Infof(
		"\U0001F4E1 <green>UDP Listener Ready, Addr: <cyan>%s</cyan>, Readers: <cyan>%d</cyan>, Workers: <cyan>%d</cyan>, Queue: <cyan>%d</cyan>, Sockets: <cyan>%d</cyan></green>",
		s.cfg.Address(),
		s.cfg.EffectiveUDPReaders(),
		s.cfg.EffectiveDNSRequestWorkers(),
		s.cfg.EffectiveMaxConcurrentRequests(),
		len(conns),
	)

	reqCh := make(chan request, s.cfg.EffectiveMaxConcurrentRequests())
	var workerWG sync.WaitGroup
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)
		s.sessionCleanupLoop(runCtx)
	}()

	s.deferredDNSSession.Start(runCtx)
	s.deferredConnectSession.Start(runCtx)
	s.startDNSWorkers(runCtx, conns[0], reqCh, &workerWG)

	go func() {
		<-runCtx.Done()
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	readErrCh := make(chan error, max(1, len(conns)))
	var readerWG sync.WaitGroup
	s.startReaders(runCtx, conns, reqCh, readErrCh, &readerWG)

	// TCP feeds the same queue and workers. It stops with the UDP readers,
	// and all its senders are gone before the queue is closed.
	tcpCtx, stopTCP := context.WithCancel(runCtx)
	defer stopTCP()
	var tcpWG sync.WaitGroup
	s.startTCP(tcpCtx, reqCh, &tcpWG)

	readerWG.Wait()
	stopTCP()
	tcpWG.Wait()
	close(reqCh)
	workerWG.Wait()
	cancel()
	<-cleanupDone

	if ctx.Err() != nil {
		return ctx.Err()
	}

	select {
	case err := <-readErrCh:
		return err
	default:
		return nil
	}
}
