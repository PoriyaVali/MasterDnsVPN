// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"masterdnsvpn-go/internal/arq"
	dnsCache "masterdnsvpn-go/internal/dnscache"
	dnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/netutil"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type dnsFragmentKey struct {
	SessionID   uint8
	SequenceNum uint16
}

// How long a caller is kept waiting for an answer still in the tunnel.
//
// Long enough to beat a resolver's own patience - Android gives a server
// several seconds before moving on - and short enough that a name the tunnel
// never answers does not pin memory. Past it the waiter is dropped and the
// caller falls back to exactly the old behaviour: silence, then its own retry.
const dnsWaitTimeout = 6 * time.Second

// Someone waiting on a name whose answer has not come back yet.
//
// `query` is kept because the response has to be patched to the transaction ID
// *this* caller used - two lookups of the same name from different sockets are
// the same cache entry but not the same DNS message.
type dnsWaiter struct {
	query    []byte
	respond  func([]byte)
	deadline time.Time
}

// waitForDNSAnswer parks a caller until the tunnel answers `key`, or until the
// timeout gives up on it.
//
// 🔑 This is what turns "fire and forget" into a forwarder. The core already
// sent the query and already stores the reply; it simply had nobody to hand it
// to, so the first lookup of every name resolved to silence and the client had
// to time out and ask again. On a page pulling in a dozen hosts that is a dozen
// resolver timeouts, which is why browsers looked broken while Telegram and
// WhatsApp - which dial fixed IPs and never resolve anything - were fine.
func (c *Client) waitForDNSAnswer(key string, query []byte, respond func([]byte)) {
	if respond == nil || key == "" {
		return
	}
	now := time.Now()
	c.dnsWaitersMu.Lock()
	defer c.dnsWaitersMu.Unlock()
	if c.dnsWaiters == nil {
		c.dnsWaiters = make(map[string][]dnsWaiter)
	}
	// Sweep here rather than on a ticker: the map only holds names currently in
	// flight, so it is tiny, and registering is the only thing that grows it.
	// ⚠️ The cache's own flush loop would have been the obvious place, but it
	// returns immediately unless the cache persists to disk - and the Android
	// app deliberately turns persistence off, so nothing there ever ticks.
	c.expireDNSWaitersLocked(now)
	c.dnsWaiters[key] = append(c.dnsWaiters[key], dnsWaiter{
		// Copied: `query` is a slice of a reusable read buffer, and by the time
		// the answer arrives the caller has read another packet into it.
		query:    append([]byte(nil), query...),
		respond:  respond,
		deadline: now.Add(dnsWaitTimeout),
	})
}

// deliverDNSAnswer hands `response` to everyone parked on `key` and clears them.
// Expired waiters are dropped on the way past, so a name the tunnel never
// answers cannot accumulate.
func (c *Client) deliverDNSAnswer(key string, response []byte) {
	if key == "" || len(response) == 0 {
		return
	}
	c.dnsWaitersMu.Lock()
	waiting := c.dnsWaiters[key]
	delete(c.dnsWaiters, key)
	c.dnsWaitersMu.Unlock()

	now := time.Now()
	for _, w := range waiting {
		if now.After(w.deadline) {
			continue
		}
		// Each caller gets the answer under its own transaction ID; a reply
		// carrying someone else's is discarded by the resolver as unsolicited.
		w.respond(dnsCache.PatchResponseForQuery(response, w.query))
	}
}

// expireDNSWaitersLocked drops waiters nothing ever answered.
// The caller must hold dnsWaitersMu.
func (c *Client) expireDNSWaitersLocked(now time.Time) {
	for key, waiting := range c.dnsWaiters {
		kept := waiting[:0]
		for _, w := range waiting {
			if now.Before(w.deadline) {
				kept = append(kept, w)
			}
		}
		if len(kept) == 0 {
			delete(c.dnsWaiters, key)
			continue
		}
		c.dnsWaiters[key] = kept
	}
}

type DNSListener struct {
	client   *Client
	conn     *net.UDPConn
	stopChan chan struct{}
	stopOnce sync.Once
}

func NewDNSListener(c *Client) *DNSListener {
	return &DNSListener{
		client:   c,
		stopChan: make(chan struct{}),
	}
}

func (l *DNSListener) Start(ctx context.Context, ip string, port int) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	l.conn = conn

	l.client.log.Infof("🚀 <green>DNS server is listening on <cyan>%s:%d</cyan></green>", ip, port)
	actualPort := port
	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && localAddr != nil && localAddr.Port > 0 {
		actualPort = localAddr.Port
	}

	if hint := netutil.FormatListenHint(ip, actualPort); hint != "" {
		l.client.log.Infof("🌐 <green>DNS Server %s</green>", hint)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, peerAddr, err := l.conn.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case <-l.stopChan:
					return
				case <-ctx.Done():
					return
				default:
					if dnsListenerShouldRetryRead(err) {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					if l.client != nil && l.client.log != nil {
						l.client.log.Warnf("⚠️ <yellow>DNS listener stopped after read error: %v</yellow>", err)
					}
					return
				}
			}
			// Copy data for the handler to prevent overwrite race condition
			dataCopy := make([]byte, n)
			copy(dataCopy, buf[:n])
			go l.handleQuery(ctx, dataCopy, peerAddr)
		}
	}()

	return nil
}

func dnsListenerShouldRetryRead(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
		type temporary interface {
			Temporary() bool
		}
		if tempErr, ok := any(netErr).(temporary); ok && tempErr.Temporary() {
			return true
		}
	}
	return false
}

func (l *DNSListener) Stop() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() {
		close(l.stopChan)
		if l.conn != nil {
			_ = l.conn.Close()
			l.conn = nil
		}
	})
}

// handleQuery manages incoming DNS queries by checking the local cache or redirecting to the tunnel.
func (l *DNSListener) handleQuery(ctx context.Context, data []byte, addr *net.UDPAddr) {
	if l.client == nil {
		return
	}

	l.client.ProcessDNSQuery(data, addr, func(resp []byte) {
		if l.conn != nil {
			_, _ = l.conn.WriteToUDP(resp, addr)
		}
	})
}

// DNS Cache Persistence Methods

func (c *Client) hasPersistableLocalDNSCache() bool {
	return c != nil &&
		c.localDNSCache != nil &&
		c.localDNSCachePersist &&
		c.localDNSCachePath != ""
}

func (c *Client) ensureLocalDNSCacheLoaded() {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	c.localDNSCacheLoadOnce.Do(func() {
		c.loadLocalDNSCache()
	})
}

func (c *Client) ensureLocalDNSCachePersistence(ctx context.Context) {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	c.ensureLocalDNSCacheLoaded()
	c.localDNSCacheFlushOnce.Do(func() {
		go c.runLocalDNSCacheFlushLoop(ctx)
	})
}

func (c *Client) loadLocalDNSCache() {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	loaded, err := c.localDNSCache.LoadFromFile(c.localDNSCachePath, time.Now())
	if err != nil {
		if c.log != nil {
			c.log.Warnf("💾 <yellow>Local DNS Cache <red>Load Failed:</red> %v</yellow>", err)
		}
		if removeErr := os.Remove(c.localDNSCachePath); removeErr != nil && !os.IsNotExist(removeErr) && c.log != nil {
			c.log.Warnf("💾 <yellow>Local DNS Cache <red>Purge Failed:</red> %v</yellow>", removeErr)
		}
		return
	}

	if loaded > 0 && c.log != nil {
		c.log.Infof("💾 <green>Local DNS Cache Loaded: <cyan>%d</cyan> records.</green>", loaded)
	}
}

func (c *Client) flushLocalDNSCache() {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	saved, err := c.localDNSCache.SaveToFile(c.localDNSCachePath, time.Now())
	if err != nil {
		if c.log != nil {
			c.log.Warnf("💾 <yellow>Local DNS Cache <red>Flush Failed:</red> %v</yellow>", err)
		}
		return
	}

	if saved > 0 && c.log != nil {
		c.log.Debugf("💾 <green>Local DNS Cache Flushed: <cyan>%d</cyan> records.</green>", saved)
	}
}

func (c *Client) runLocalDNSCacheFlushLoop(ctx context.Context) {
	if !c.hasPersistableLocalDNSCache() {
		return
	}

	ticker := time.NewTicker(c.localDNSCacheFlushTick)
	defer ticker.Stop()
	defer c.flushLocalDNSCache()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.flushLocalDNSCache()
		}
	}
}

func (c *Client) HandleDNSQueryAck(packet VpnProto.Packet) error {
	c.streamsMu.RLock()
	s0, ok := c.active_streams[0]
	c.streamsMu.RUnlock()

	if ok && s0 != nil {
		if arqObj, ok := s0.Stream.(*arq.ARQ); ok {
			arqObj.HandleAckPacket(packet.PacketType, packet.SequenceNum, packet.FragmentID)
		}
	}
	return nil
}

func (c *Client) HandleDNSQueryRes(packet VpnProto.Packet) error {
	key := dnsFragmentKey{
		SessionID:   c.sessionID,
		SequenceNum: packet.SequenceNum,
	}

	assembled, ready, _ := c.dnsResponses.Collect(key, packet.Payload, packet.FragmentID, packet.TotalFragments, time.Now(), c.cfg.DNSResponseFragmentTimeout())
	if !ready {
		return nil
	}

	if c.localDNSCache != nil {
		lite, err := dnsParser.ParsePacketLite(assembled)
		if err == nil && lite.HasQuestion {
			cacheKey := dnsCache.BuildKey(lite.FirstQuestion.Name, lite.FirstQuestion.Type, lite.FirstQuestion.Class)
			c.localDNSCache.SetReady(cacheKey, lite.FirstQuestion.Name, lite.FirstQuestion.Type, lite.FirstQuestion.Class, assembled, time.Now())
			// Hand it straight to whoever asked. Storing it and waiting for
			// them to ask again is what made the first lookup of every name
			// cost a resolver timeout.
			c.deliverDNSAnswer(cacheKey, assembled)
		}
	}

	return nil
}

// ProcessDNSQuery handles a DNS query by checking the local cache or dispatching to the tunnel.
// It only responds on cache hits and uses "fire-and-forget" for misses.
func (c *Client) ProcessDNSQuery(query []byte, addr net.Addr, respond func([]byte)) bool {
	if c == nil || !c.SessionReady() {
		return false
	}

	// 1. Lite Parse DNS Query
	lite, err := dnsParser.ParseDNSRequestLite(query)
	if err != nil || !lite.HasQuestion {
		return false
	}

	question := lite.FirstQuestion
	now := time.Now()

	// 1b. Bypass: answer domestic names from a domestic resolver.
	//
	// 🔴 Never inline. This function is called straight from the SOCKS5 UDP
	// read loop - `isHit := c.ProcessDNSQuery(...)` with no goroutine - and on
	// Android that loop is the *only* DNS path, because LOCAL_DNS_ENABLED is
	// false. A blocking lookup here does not delay one name, it stops every
	// other query on the device until it returns. The first version of this did
	// exactly that: up to two seconds per resolver, tried in turn.
	//
	// So the cache is consulted inline (free) and anything else is handed to a
	// goroutine that answers when it can. That is the same shape the tunnel
	// path already has - dispatch, return, respond later.
	if c.bypass.Match(question.Name) {
		key := dnsCache.BuildKey(question.Name, question.Type, question.Class)
		if c.localDNSCache != nil {
			if resp, ok := c.localDNSCache.GetReady(key, query, now); ok && len(resp) > 0 {
				if respond != nil {
					respond(resp)
				}
				return true
			}
		}
		// ⚠️ Copied. `query` is a slice of a reusable read buffer, and by the
		// time this goroutine runs the loop has read another packet into it -
		// the same trap the tunnel's own waiters document.
		q := append([]byte(nil), query...)
		name := question.Name
		go func() {
			resp := c.resolveBypassDirect(q)
			if resp == nil {
				// Fall back to the tunnel, as a lookup that was never bypassed
				// would have gone. A domestic resolver being down must not take
				// the name with it.
				if c.log != nil {
					c.log.Warnf("↩️ <yellow>DNS Bypass failed for %s, using the tunnel</yellow>", name)
				}
				// 🔴 Parked first, exactly as the tunnel path parks its callers.
				// Without it the tunnel's answer was stored in the cache and
				// handed to nobody: the caller heard silence and only got an
				// answer on its own retry, seconds later.
				if c.localDNSCache != nil {
					c.waitForDNSAnswer(key, q, respond)
				}
				c.dispatchDNSQueryToTunnel(q)
				return
			}
			// 🔑 Cached. Without this every single lookup of a domestic name is
			// a fresh query - a page with twenty hosts is twenty queries, and
			// the next page is twenty more, all landing on the handful of
			// resolvers that are still up when everything else is cut.
			if c.localDNSCache != nil {
				c.localDNSCache.SetReady(key, name, question.Type, question.Class, resp, time.Now())
			}
			if respond != nil {
				respond(resp)
			}
			if c.log != nil {
				c.log.Infof("↩️ <green>DNS Bypass (direct): %s</green>", name)
			}
		}()
		return true
	}

	// 2. Check Local Cache
	if c.localDNSCache != nil {
		key := dnsCache.BuildKey(question.Name, question.Type, question.Class)
		res := c.localDNSCache.LookupOrCreatePending(key, question.Name, question.Type, question.Class, now)

		if res.Status == dnsCache.StatusReady && len(res.Response) > 0 {
			// Cache Hit - Rewrite Transaction ID and send back
			if respond != nil {
				resp := dnsCache.PatchResponseForQuery(res.Response, query)
				respond(resp)
			}
			if c.log != nil {
				c.log.Infof("🔍 <green>DNS Cache Hit: %s (%d)</green>", question.Name, question.Type)
			}
			return true
		}

		if res.Status == dnsCache.StatusPending && !res.DispatchNeeded {
			// Already in the tunnel for someone else. Park on the same answer
			// rather than dispatching a second copy of the same question - on a
			// page loading a dozen assets from one host this is the common case.
			c.waitForDNSAnswer(key, query, respond)
			if c.log != nil {
				c.log.Debugf("🔍 <yellow>DNS Query Pending: %s (%d)</yellow>", question.Name, question.Type)
			}
			return false
		}

		// A miss we are about to dispatch: park before sending, so an answer
		// that comes back quickly cannot arrive before there is anyone to give
		// it to.
		c.waitForDNSAnswer(key, query, respond)
	}

	// 3. Dispatch to Tunnel
	c.log.Infof("🔍 <yellow>DNS Query Request: %s (%d)</yellow>", question.Name, question.Type)
	c.dispatchDNSQueryToTunnel(query)
	return false
}

func (c *Client) dispatchDNSQueryToTunnel(query []byte) {
	if !c.SessionReady() {
		return
	}

	c.streamsMu.RLock()
	s0, ok := c.active_streams[0]
	c.streamsMu.RUnlock()

	if !ok || s0 == nil {
		return
	}

	arqObj, ok := s0.Stream.(*arq.ARQ)
	if !ok {
		return
	}

	// Calculate target MTU for fragments
	fragments := fragmentPayload(query, c.syncedUploadMTU)
	total := uint8(len(fragments))

	// Generate a unique sequence number for this DNS query
	sn := uint16(c.mtuProbeCounter.Add(1) & 0xFFFF)

	for i, frag := range fragments {
		fragID := uint8(i)

		// Send via ARQ as a control packet
		arqObj.SendControlPacketWithTTL(Enums.PACKET_DNS_QUERY_REQ, sn, fragID, total, frag, Enums.DefaultPacketPriority(Enums.PACKET_DNS_QUERY_REQ), true, nil, 0)
	}
}
