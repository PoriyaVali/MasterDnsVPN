// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (pool.go) runs several servers at once behind one local proxy:
// the multi-server load balancer.
// ==============================================================================
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
)

// A Pool is the load balancer: one full client (its own resolvers, MTU scan,
// session and streams) per configured server, behind a single local SOCKS5 /
// TCP / DNS listener.
//
// 🔑 The unit it balances is a connection, not a packet. One TCP stream lives
// on one server from start to end: its bytes are reassembled in order by that
// server's ARQ and leave from that server's address. Splitting a single stream
// across servers would need the servers to rejoin it somewhere, which a DNS
// tunnel - each server answering only its own domain - has no place for. What
// the pool does give is the sum of the servers: many connections (a browser
// opens dozens) run on all of them at once, and a server that goes down only
// takes its own connections with it while new ones go to the others.
//
// Servers need no change for this: each one sees an ordinary client session.
type Pool struct {
	cfg     config.ClientConfig
	log     *logger.Logger
	members []*poolMember

	strategy  string
	sticky    bool
	stickyTTL time.Duration

	rr  atomic.Uint64
	rng atomic.Uint64

	affinityMu sync.Mutex
	affinity   map[string]poolAffinity

	listenMu    sync.Mutex
	tcpListener *TCPListener
	dnsListener *DNSListener

	nowFn func() time.Time
}

type poolMember struct {
	name   string
	weight int
	client *Client
}

type poolAffinity struct {
	member  *poolMember
	expires time.Time
}

const (
	// poolAffinityMaxEntries bounds the destination -> server map.
	poolAffinityMaxEntries = 4096
	// poolReadyWait is how long a new local connection waits for some server
	// to be up (they reopen sessions after a reset) before it is refused.
	poolReadyWait = 15 * time.Second
	// poolSuperviseInterval paces the pool's own health loop.
	poolSuperviseInterval = 200 * time.Millisecond
	// poolUnresponsiveAfter: a server that has been sending this long without
	// any answer gets no new connections while another server is answering.
	// Its session still counts as open - it may be a slow patch, and the
	// server's own client resets the session if it is really gone - but new
	// work should not wait on it.
	poolUnresponsiveAfter = 12 * time.Second
)

// BootstrapPool builds the load balancer from a config with SERVERS.
func BootstrapPool(cfg config.ClientConfig, logPath string) (*Pool, error) {
	if !cfg.IsLoadBalanced() {
		return nil, errors.New("load balancer needs at least one SERVERS entry")
	}

	var log *logger.Logger
	if logPath != "" {
		log = logger.NewWithFile("MasterDnsVPN Client", cfg.LogLevel, logPath)
	} else {
		log = logger.New("MasterDnsVPN Client", cfg.LogLevel)
	}

	p := newPool(cfg, log)
	for i, profile := range cfg.ServerProfiles {
		codec, err := security.NewCodec(profile.DataEncryptionMethod, profile.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("server %s: codec setup failed: %w", profile.ServerName, err)
		}
		if i > 0 {
			// Loaded once and shared: the domestic lists run to thousands of
			// entries, and a phone should not hold one copy per server.
			profile.BypassDomainsFile = ""
			profile.BypassCIDRsFile = ""
			// One cache file in the config directory; two writers would
			// overwrite each other.
			profile.LocalDNSCachePersist = false
		}

		c := New(profile, log.Named(profile.ServerName), codec)
		c.pool = p
		if i > 0 {
			first := p.members[0].client
			c.bypass = first.bypass
			c.bypassCIDRs = first.bypassCIDRs
		}
		if err := c.BuildConnectionMap(); err != nil {
			return nil, fmt.Errorf("server %s: %w", profile.ServerName, err)
		}
		p.members = append(p.members, &poolMember{
			name:   profile.ServerName,
			weight: max(profile.ServerWeight, 1),
			client: c,
		})
	}
	return p, nil
}

func newPool(cfg config.ClientConfig, log *logger.Logger) *Pool {
	p := &Pool{
		cfg:       cfg,
		log:       log,
		strategy:  cfg.LoadBalancerStrategy,
		sticky:    cfg.LoadBalancerSticky,
		stickyTTL: cfg.LoadBalancerStickyTTL(),
		affinity:  make(map[string]poolAffinity),
		nowFn:     time.Now,
	}
	if p.stickyTTL <= 0 {
		p.stickyTTL = 10 * time.Minute
	}
	p.rng.Store(seedRNG())
	return p
}

func (p *Pool) Log() *logger.Logger { return p.log }

// ConnectionCount is the number of domain-resolver pairs across all servers.
func (p *Pool) ConnectionCount() int {
	total := 0
	for _, m := range p.members {
		total += m.client.Balancer().TotalCount()
	}
	return total
}

func (p *Pool) PrintBanner() {
	if p.log == nil {
		return
	}
	printShortBanner(p.log)
	sticky := "off"
	if p.sticky {
		sticky = p.stickyTTL.String()
	}
	p.log.Infof("⚖  <green>Load Balancer: <cyan>%d</cyan> servers</green> <magenta>|</magenta> <blue>Strategy</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Sticky</blue>: <cyan>%s</cyan>",
		len(p.members), p.strategy, sticky)
	for _, m := range p.members {
		cfg := m.client.cfg
		p.log.Infof("   <cyan>%s</cyan> <magenta>|</magenta> <blue>Domains</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Resolvers</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Weight</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Encryption</blue>: <cyan>%d</cyan>",
			m.name, strings.Join(cfg.Domains, ","), len(cfg.Resolvers), m.weight, cfg.DataEncryptionMethod)
	}
}

// Run runs every server and the shared listeners until ctx ends.
func (p *Pool) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	exited := make(chan struct{}, len(p.members))
	for _, m := range p.members {
		wg.Add(1)
		go func(m *poolMember) {
			defer wg.Done()
			defer func() { exited <- struct{}{} }()
			if err := m.client.Run(runCtx); err != nil && p.log != nil {
				p.log.Errorf("<red>❌ Server <cyan>%s</cyan> stopped: %v</red>", m.name, err)
			}
		}(m)
	}

	err := p.supervise(runCtx, exited)
	cancel()
	p.stopListeners()
	wg.Wait()
	return err
}

// supervise opens the shared listeners once the first server is up and
// reports the pool's state as servers come and go.
func (p *Pool) supervise(ctx context.Context, exited <-chan struct{}) error {
	ticker := time.NewTicker(poolSuperviseInterval)
	defer ticker.Stop()

	listening := false
	lastState := ""
	stopped := 0
	failMarks := make([]uint64, len(p.members))

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-exited:
			stopped++
			if stopped >= len(p.members) {
				return errors.New("every load-balanced server stopped")
			}
			continue
		case <-ticker.C:
		}

		ready := p.readyCount()
		if ready > 0 && !listening {
			if err := p.startListeners(ctx); err != nil {
				return err
			}
			listening = true
		}
		if state := p.stateSignature(); state != lastState {
			p.logReadyState(ready)
			lastState = state
		}
		if ready == 0 {
			p.reportAllServersFailing(failMarks)
		}
	}
}

// stateSignature changes whenever any server goes up, stalls or goes down.
func (p *Pool) stateSignature() string {
	now := p.nowFn()
	var b strings.Builder
	for _, m := range p.members {
		switch {
		case p.answering(m, now):
			b.WriteByte('u')
		case m.client.RuntimeReady():
			b.WriteByte('s')
		default:
			b.WriteByte('d')
		}
	}
	return b.String()
}

func (p *Pool) logReadyState(ready int) {
	if p.log == nil {
		return
	}
	now := p.nowFn()
	names := make([]string, 0, len(p.members))
	for _, m := range p.members {
		state := "down"
		if p.answering(m, now) {
			state = "up"
		} else if m.client.RuntimeReady() {
			state = "stalled"
		}
		names = append(names, m.name+"="+state)
	}
	if ready == 0 {
		p.log.Warnf("⚖  <yellow>Load Balancer: no server is up</yellow> <magenta>|</magenta> %s", strings.Join(names, " "))
		return
	}
	p.log.Infof("⚖  <green>Load Balancer: <cyan>%d/%d</cyan> servers up</green> <magenta>|</magenta> %s", ready, len(p.members), strings.Join(names, " "))
}

// reportAllServersFailing says "Session initialization failed" - the words a
// single-server client uses, and the ones the Android app counts to give up on
// a core - only when no server is up and every one of them has failed a
// session init since the last time it was said. One dead server among live
// ones is the load balancer doing its job, not a failed start.
func (p *Pool) reportAllServersFailing(marks []uint64) {
	current := make([]uint64, len(p.members))
	for i, m := range p.members {
		current[i] = m.client.sessionInitFailures.Load()
		if current[i] <= marks[i] {
			return
		}
	}
	copy(marks, current)
	if p.log != nil {
		p.log.Errorf("<red>❌ Session initialization failed: none of the <cyan>%d</cyan> load-balanced servers could open a session</red>", len(p.members))
	}
}

func (p *Pool) startListeners(ctx context.Context) error {
	p.listenMu.Lock()
	defer p.listenMu.Unlock()

	tcp := newTCPListenerWithHandler(p.log, p.cfg.ProtocolType, p.handleConn)
	if err := tcp.Start(ctx, p.cfg.ListenIP, p.cfg.ListenPort); err != nil {
		if p.log != nil {
			p.log.Errorf("<red>❌ Failed to start %s proxy: %v</red>", p.cfg.ProtocolType, err)
		}
		return err
	}
	p.tcpListener = tcp

	if p.cfg.LocalDNSEnabled {
		dns := newDNSListenerWithHandler(p.log, p.processDNSQuery)
		if err := dns.Start(ctx, p.cfg.LocalDNSIP, p.cfg.LocalDNSPort); err != nil {
			if p.log != nil {
				p.log.Errorf("<red>❌ Failed to start DNS resolver: %v</red>", err)
			}
			return err
		}
		p.dnsListener = dns
	}
	return nil
}

func (p *Pool) stopListeners() {
	p.listenMu.Lock()
	defer p.listenMu.Unlock()
	if p.tcpListener != nil {
		p.tcpListener.Stop()
		p.tcpListener = nil
	}
	if p.dnsListener != nil {
		p.dnsListener.Stop()
		p.dnsListener = nil
	}
}

// handleConn hands an accepted local connection to a server.
//
// A SOCKS connection is read by the first server that is up, in config order:
// the destination is only known once the request is read, and the server
// that carries it is picked then (see memberForTarget). Picking the reader by
// strategy as well would spend a round-robin turn per connection on reading
// alone, and with two servers every stream would land on the same one.
func (p *Pool) handleConn(ctx context.Context, conn net.Conn) {
	if p.cfg.ProtocolType == "SOCKS5" {
		m := p.waitForMember(ctx, p.firstReady)
		if m == nil {
			_ = conn.Close()
			return
		}
		m.client.HandleSOCKS5(ctx, conn)
		return
	}

	m := p.waitForMember(ctx, func() *poolMember { return p.pick("") })
	if m == nil {
		_ = conn.Close()
		return
	}
	m.client.HandleTCPConnect(ctx, conn)
}

// waitForMember polls find until it returns a server or poolReadyWait runs out:
// servers reopen their sessions after a reset, and a connection that arrives
// in that gap should not fail when a few seconds' wait would carry it.
func (p *Pool) waitForMember(ctx context.Context, find func() *poolMember) *poolMember {
	if m := find(); m != nil {
		return m
	}
	deadline := time.NewTimer(poolReadyWait)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return nil
		case <-tick.C:
			if m := find(); m != nil {
				return m
			}
		}
	}
}

// processDNSQuery answers the shared local DNS listener from the first server
// that is up, so the DNS cache stays mostly in one place.
func (p *Pool) processDNSQuery(query []byte, addr net.Addr, respond func([]byte)) bool {
	m := p.firstReady()
	if m == nil {
		return false
	}
	return m.client.ProcessDNSQuery(query, addr, respond)
}

// memberForTarget picks the server a new stream to host should run on. nil
// means none is up; the caller then keeps the stream itself.
func (p *Pool) memberForTarget(host string) *Client {
	m := p.pick(host)
	if m == nil {
		return nil
	}
	return m.client
}

// pick chooses a server for a new connection to host ("" = unknown).
//
// With LOAD_BALANCER_STICKY a destination keeps the server it was first given
// for LOAD_BALANCER_STICKY_SECONDS after its last use. Every server leaves the
// internet from its own address, and a site that sees one visitor jump between
// addresses mid-session (logins, banks, captchas, video CDNs) may log them out
// or block them.
func (p *Pool) pick(host string) *poolMember {
	host = normalizePoolHost(host)
	now := p.nowFn()
	if p.sticky && host != "" {
		p.affinityMu.Lock()
		if a, ok := p.affinity[host]; ok && now.Before(a.expires) && p.answering(a.member, now) {
			a.expires = now.Add(p.stickyTTL)
			p.affinity[host] = a
			p.affinityMu.Unlock()
			return a.member
		}
		p.affinityMu.Unlock()
	}

	ready := p.readyMembers(now)
	if len(ready) == 0 {
		return nil
	}
	m := p.choose(ready)

	if p.sticky && host != "" {
		p.affinityMu.Lock()
		if len(p.affinity) >= poolAffinityMaxEntries {
			p.pruneAffinityLocked(now)
		}
		p.affinity[host] = poolAffinity{member: m, expires: now.Add(p.stickyTTL)}
		p.affinityMu.Unlock()
	}
	return m
}

func (p *Pool) choose(ready []*poolMember) *poolMember {
	if len(ready) == 1 {
		return ready[0]
	}
	switch p.strategy {
	case config.LoadBalancerFailover:
		return ready[0]
	case config.LoadBalancerRoundRobin:
		return weightedSlot(ready, p.rr.Add(1)-1)
	case config.LoadBalancerRandom:
		return weightedSlot(ready, p.nextRandom())
	default:
		return p.leastLoaded(ready)
	}
}

// leastLoaded is the server with the fewest streams for its weight. Ties are
// broken by rotation, so equally idle servers take turns instead of the first
// one getting everything.
func (p *Pool) leastLoaded(ready []*poolMember) *poolMember {
	start := int((p.rr.Add(1) - 1) % uint64(len(ready)))
	best := ready[start]
	bestLoad := best.client.ActiveStreamCount()
	for i := 1; i < len(ready); i++ {
		m := ready[(start+i)%len(ready)]
		load := m.client.ActiveStreamCount()
		// load/weight < bestLoad/best.weight, without division.
		if load*best.weight < bestLoad*m.weight {
			best, bestLoad = m, load
		}
	}
	return best
}

// weightedSlot maps n onto the servers, each taking weight consecutive slots.
func weightedSlot(ready []*poolMember, n uint64) *poolMember {
	total := 0
	for _, m := range ready {
		total += m.weight
	}
	slot := int(n % uint64(total))
	for _, m := range ready {
		if slot < m.weight {
			return m
		}
		slot -= m.weight
	}
	return ready[len(ready)-1]
}

func (p *Pool) pruneAffinityLocked(now time.Time) {
	for host, a := range p.affinity {
		if !now.Before(a.expires) {
			delete(p.affinity, host)
		}
	}
	if len(p.affinity) >= poolAffinityMaxEntries {
		// Still full of live entries: start over rather than scan for the
		// oldest on every new destination.
		clear(p.affinity)
	}
}

// answering: the server has a session and is not overdue with its replies.
func (p *Pool) answering(m *poolMember, now time.Time) bool {
	return m.client.RuntimeReady() && m.client.unansweredFor(now) < poolUnresponsiveAfter
}

// readyMembers lists, in config order, the servers that are answering - or,
// when none is, every server that at least has a session, so a network-wide
// stall slows connections down instead of refusing them.
func (p *Pool) readyMembers(now time.Time) []*poolMember {
	ready := make([]*poolMember, 0, len(p.members))
	answering := make([]*poolMember, 0, len(p.members))
	for _, m := range p.members {
		if !m.client.RuntimeReady() {
			continue
		}
		ready = append(ready, m)
		if p.answering(m, now) {
			answering = append(answering, m)
		}
	}
	if len(answering) > 0 {
		return answering
	}
	return ready
}

func (p *Pool) readyCount() int {
	n := 0
	for _, m := range p.members {
		if m.client.RuntimeReady() {
			n++
		}
	}
	return n
}

func (p *Pool) firstReady() *poolMember {
	if ready := p.readyMembers(p.nowFn()); len(ready) > 0 {
		return ready[0]
	}
	return nil
}

func (p *Pool) nextRandom() uint64 {
	for {
		old := p.rng.Load()
		next := xorshift64(old)
		if p.rng.CompareAndSwap(old, next) {
			return next
		}
	}
}

func normalizePoolHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
