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
	"path/filepath"
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

	// scanSlots bounds MTU probes in flight across ALL servers. Each server
	// measures every resolver for itself - a resolver can serve one server's
	// domain and not another's - so N servers are N scans; together they get
	// the budget one client would have, not N times it. Each probe opens a
	// socket that the Android app must protect, one at a time.
	scanSlots chan struct{}

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
	// Its session still counts as open - it may be a slow patch - but new
	// work should not wait on it.
	poolUnresponsiveAfter = 12 * time.Second
	// poolStallRestartAfter: a server silent this long has its session
	// restarted. Its resolvers may all have died; auto-disable keeps the
	// last few active whatever happens to them, so without this the server
	// would keep sending into them for as long as the app runs.
	poolStallRestartAfter = 45 * time.Second
	// poolStallRestartGap spaces those restarts out.
	poolStallRestartGap = 60 * time.Second
	// poolMemberRestartMax caps the backoff for restarting a server whose
	// runtime failed to start.
	poolMemberRestartMax = time.Minute
	// poolHealthyResolvers: a server with this many working resolvers or
	// more gets its full weight; with fewer, proportionally less.
	poolHealthyResolvers = 4
	// poolMinScanSlots is the least the shared scan budget is allowed.
	poolMinScanSlots = 8
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
	p.scanSlots = make(chan struct{}, max(cfg.MTUTestParallelism, poolMinScanSlots))
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
		if profile.SaveMTUServersToFile {
			// Every server would otherwise write - and truncate - the same
			// file in the same config directory.
			profile.MTUServersFileName = perServerFileName(profile.MTUServersFileName, profile.ServerName)
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
	for _, m := range p.members {
		wg.Add(1)
		go func(m *poolMember) {
			defer wg.Done()
			p.runMember(runCtx, m)
		}(m)
	}

	err := p.supervise(runCtx)
	cancel()
	p.stopListeners()
	wg.Wait()
	return err
}

// runMember keeps one server running until ctx ends.
//
// ⚠️ Client.Run returns early only when its runtime could not start - a
// socket that could not be opened, say during another server's scan. On its
// own the process would exit and the app would start it again; here the
// other servers keep the process alive, so the pool restarts it instead of
// carrying on one server short for the rest of the session.
func (p *Pool) runMember(ctx context.Context, m *poolMember) {
	delay := time.Second
	for {
		err := m.client.Run(ctx)
		if ctx.Err() != nil {
			return
		}
		if p.log != nil {
			p.log.Errorf("<red>❌ Server <cyan>%s</cyan> stopped: %v - restarting in %s</red>", m.name, err, delay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay *= 2; delay > poolMemberRestartMax {
			delay = poolMemberRestartMax
		}
	}
}

// supervise opens the shared listeners once the first server is up, reports
// the pool's state as servers come and go, and restarts servers that went
// silent.
func (p *Pool) supervise(ctx context.Context) error {
	ticker := time.NewTicker(poolSuperviseInterval)
	defer ticker.Stop()

	listening := false
	lastState := ""
	failMarks := make([]uint64, len(p.members))
	lastStallRestart := make([]time.Time, len(p.members))

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		p.restartStalledMembers(lastStallRestart)

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

// restartStalledMembers restarts the session of every server that has had no
// answer for poolStallRestartAfter, at most once per poolStallRestartGap.
//
// A restart opens a new session through the server's resolvers; if that
// fails a few times the server measures its resolvers again (Client.Run).
func (p *Pool) restartStalledMembers(last []time.Time) {
	now := p.nowFn()
	for i, m := range p.members {
		if !m.client.RuntimeReady() || m.client.unansweredFor(now) < poolStallRestartAfter {
			continue
		}
		if !last[i].IsZero() && now.Sub(last[i]) < poolStallRestartGap {
			continue
		}
		last[i] = now
		m.client.requestSessionRestart(fmt.Sprintf("no answer from this server for %s", poolStallRestartAfter))
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
		current[i] = m.client.startFailures.Load()
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

// effectiveWeight is a server's WEIGHT scaled by how many of its resolvers
// work. A server that got through on one resolver is as "up" as one with a
// hundred, but every connection on it shares that one resolver and dies
// with it; it should not get the same share.
func (m *poolMember) effectiveWeight() int {
	healthy := poolHealthyResolvers
	if b := m.client.Balancer(); b != nil {
		healthy = min(max(b.ActiveCount(), 1), poolHealthyResolvers)
	}
	return m.weight * healthy
}

// leastLoaded is the server with the fewest streams for its effective
// weight. Ties are broken by rotation, so equally idle servers take turns
// instead of the first one getting everything.
func (p *Pool) leastLoaded(ready []*poolMember) *poolMember {
	start := int((p.rr.Add(1) - 1) % uint64(len(ready)))
	best := ready[start]
	bestLoad, bestWeight := best.client.ActiveStreamCount(), best.effectiveWeight()
	for i := 1; i < len(ready); i++ {
		m := ready[(start+i)%len(ready)]
		load, weight := m.client.ActiveStreamCount(), m.effectiveWeight()
		// load/weight < bestLoad/bestWeight, without division.
		if load*bestWeight < bestLoad*weight {
			best, bestLoad, bestWeight = m, load, weight
		}
	}
	return best
}

// weightedSlot maps n onto the servers, each taking effective-weight
// consecutive slots.
func weightedSlot(ready []*poolMember, n uint64) *poolMember {
	weights := make([]int, len(ready))
	total := 0
	for i, m := range ready {
		weights[i] = m.effectiveWeight()
		total += weights[i]
	}
	slot := int(n % uint64(total))
	for i, m := range ready {
		if slot < weights[i] {
			return m
		}
		slot -= weights[i]
	}
	return ready[len(ready)-1]
}

// acquireScanSlot takes one slot of the pool's shared scan budget, or
// returns false if ctx ends first. A client outside a pool has no budget.
func (c *Client) acquireScanSlot(ctx context.Context) bool {
	if c.pool == nil || c.pool.scanSlots == nil {
		return true
	}
	select {
	case c.pool.scanSlots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Client) releaseScanSlot() {
	if c.pool == nil || c.pool.scanSlots == nil {
		return
	}
	<-c.pool.scanSlots
}

// perServerFileName puts a server's name before a file name's extension:
// "mtu_{time}.log" -> "mtu_{time}_de-1.log".
func perServerFileName(name, server string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, server)
	ext := filepath.Ext(name)
	return strings.TrimSuffix(name, ext) + "_" + safe + ext
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
