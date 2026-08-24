// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/inflight"
)

var ErrInvalidDNSUpstream = errors.New("invalid dns upstream")

// Where the host itself sends its own lookups, used only when every configured
// upstream has failed. Read once - resolv.conf does not change under a running
// server often enough to be worth re-reading per query.
var (
	systemResolversOnce sync.Once
	systemResolvers     []string
)

// systemDNSUpstreams returns the nameservers from /etc/resolv.conf, in the form
// queryOneUpstream expects.
//
// 🔑 Why this exists. DNS_UPSTREAM_SERVERS defaults to 1.1.1.1, and a server on
// a network that cannot reach it answers SERVFAIL to every tunnelled lookup -
// while resolving names perfectly well for its own SOCKS5 CONNECT path, because
// that goes through the host resolver instead. Measured exactly that way from a
// phone: TCP through the tunnel returned http 200 while DNS returned nothing at
// all. One path worked and the other did not, on the same healthy tunnel.
//
// So: keep the configured upstreams as the intent, and fall back to what the
// host itself can reach rather than failing when the two disagree. Raw DNS is
// forwarded either way - reading the nameservers rather than using net.Resolver
// means no response has to be synthesised from parsed results.
func systemDNSUpstreams() []string {
	systemResolversOnce.Do(func() {
		raw, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			addr := fields[1]
			if net.ParseIP(addr) == nil {
				continue
			}
			systemResolvers = append(systemResolvers, net.JoinHostPort(addr, "53"))
		}
	})
	return systemResolvers
}

type dnsFragmentKey struct {
	sessionID   uint8
	sequenceNum uint16
}

type dnsResolveInflightEntry = inflight.Entry[[]byte]

type dnsResolveInflightManager struct {
	inner *inflight.Manager[[]byte]
}

func newDNSResolveInflightManager(timeout time.Duration) *dnsResolveInflightManager {
	return &dnsResolveInflightManager{
		inner: inflight.New(timeout, 16*time.Second, cloneInflightBytes),
	}
}

func (m *dnsResolveInflightManager) Acquire(cacheKey string, now time.Time) (*dnsResolveInflightEntry, bool) {
	if m == nil {
		return nil, false
	}
	return m.inner.Acquire(cacheKey, now)
}

func (m *dnsResolveInflightManager) Resolve(cacheKey string, response []byte) {
	if m == nil {
		return
	}
	m.inner.Resolve(cacheKey, response, len(response) != 0)
}

func (m *dnsResolveInflightManager) Wait(entry *dnsResolveInflightEntry, timeout time.Duration) ([]byte, bool) {
	if m == nil {
		return nil, false
	}
	return m.inner.Wait(entry, timeout)
}

func cloneInflightBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return append([]byte(nil), value...)
}

func (s *Server) buildDNSQueryResponsePayload(rawQuery []byte, sessionID uint8, sequenceNum uint16) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(rawQuery)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}
		response, responseErr := DnsParser.BuildFormatErrorResponse(rawQuery)
		if responseErr != nil {
			return nil
		}
		return response
	}

	if !parsed.HasQuestion {
		response, responseErr := DnsParser.BuildFormatErrorResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	if !DnsParser.IsSupportedTunnelDNSQuery(parsed.FirstQuestion.Type, parsed.FirstQuestion.Class) {
		response, responseErr := DnsParser.BuildNotImplementedResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	cacheKey := dnscache.BuildKey(parsed.FirstQuestion.Name, parsed.FirstQuestion.Type, parsed.FirstQuestion.Class)
	now := time.Now()
	if cached, ok := s.dnsCache.GetReady(cacheKey, rawQuery, now); ok {
		if s.log != nil {
			s.log.Debugf(
				"🧠 <green>Tunnel DNS Cache Hit</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		return cached
	}

	inflightEntry, leader := s.dnsResolveInflight.Acquire(cacheKey, now)
	if !leader {
		if s.log != nil {
			s.log.Debugf(
				"\U0001F9E9 <green>Tunnel DNS Inflight Reused</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		waitTimeout := s.cfg.DNSInflightWaitTimeout()
		if waitTimeout <= 0 {
			waitTimeout = 8 * time.Second
		}
		if resolved, ok := s.dnsResolveInflight.Wait(inflightEntry, waitTimeout); ok && len(resolved) != 0 {
			return dnscache.PatchResponseForQuery(resolved, rawQuery)
		}
		if cached, ok := s.dnsCache.GetReady(cacheKey, rawQuery, now); ok {
			return cached
		}
		response, responseErr := DnsParser.BuildServerFailureResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	resolved, err := s.resolveDNSUpstream(rawQuery)
	if s.log != nil {
		s.log.Debugf(
			"🔎 <green>Tunnel DNS Upstream Lookup</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
			parsed.FirstQuestion.Name,
			Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
			sessionID,
			sequenceNum,
		)
	}
	s.dnsResolveInflight.Resolve(cacheKey, resolved)
	if err != nil || len(resolved) == 0 {
		if s.log != nil {
			// ⚠️ Warn, not Debug. A server that cannot reach its upstreams
			// answers SERVFAIL to every lookup - which to a user is "the
			// internet does not work through this tunnel" - and at Debug that
			// is invisible on a production log level. This is the single line
			// that would have explained it, so it has to be visible without
			// anyone having to reproduce the fault at debug first.
			s.log.Warnf(
				"⚠️ <yellow>Tunnel DNS Upstream Failed</yellow> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Upstreams</blue>: <cyan>%s</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
				strings.Join(s.dnsUpstreamServers, ", "),
			)
		}
		response, responseErr := DnsParser.BuildServerFailureResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	s.dnsCache.SetReady(
		cacheKey,
		parsed.FirstQuestion.Name,
		parsed.FirstQuestion.Type,
		parsed.FirstQuestion.Class,
		resolved,
		now,
	)
	if s.log != nil {
		s.log.Debugf(
			"🌍 <green>Tunnel DNS Resolved Upstream</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Bytes</blue>: <cyan>%d</cyan>",
			parsed.FirstQuestion.Name,
			Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
			sessionID,
			sequenceNum,
			len(resolved),
		)
	}
	return resolved
}

func (s *Server) collectDNSQueryFragments(sessionID uint8, sequenceNum uint16, payload []byte, fragmentID uint8, totalFragments uint8, now time.Time) ([]byte, bool, bool) {
	if totalFragments == 0 {
		totalFragments = 1
	}
	assembled, ready, completed := s.dnsFragments.Collect(
		dnsFragmentKey{
			sessionID:   sessionID,
			sequenceNum: sequenceNum,
		},
		payload,
		fragmentID,
		totalFragments,
		now,
		s.dnsFragmentTimeout,
	)
	return assembled, ready, completed
}

func (s *Server) purgeDNSQueryFragments(now time.Time) {
	if s == nil || s.dnsFragments == nil {
		return
	}
	s.dnsFragments.Purge(now, s.dnsFragmentTimeout)
}

func (s *Server) removeDNSQueryFragmentsForSession(sessionID uint8) {
	if s == nil || s.dnsFragments == nil || sessionID == 0 {
		return
	}
	s.dnsFragments.RemoveIf(func(key dnsFragmentKey) bool {
		return key.sessionID == sessionID
	})
}

func (s *Server) fragmentDNSResponsePayload(response []byte, mtu int) [][]byte {
	if len(response) == 0 {
		return nil
	}
	limit := mtu
	if limit < 1 {
		limit = 256
	}
	if len(response) <= limit {
		return [][]byte{response}
	}

	total := (len(response) + limit - 1) / limit
	if total > 255 {
		return nil
	}

	fragments := make([][]byte, 0, total)
	for start := 0; start < len(response); start += limit {
		end := start + limit
		if end > len(response) {
			end = len(response)
		}
		fragments = append(fragments, response[start:end])
	}
	return fragments
}

func (s *Server) resolveDNSUpstream(rawQuery []byte) ([]byte, error) {
	if s != nil && s.resolveDNSQueryFn != nil {
		return s.resolveDNSQueryFn(rawQuery)
	}
	if len(rawQuery) == 0 {
		return nil, ErrInvalidDNSUpstream
	}
	resolved, err := s.resolveVia(s.dnsUpstreamServers, rawQuery)
	if err == nil && len(resolved) > 0 {
		return resolved, nil
	}

	// Every configured upstream is unreachable from here. Before giving the
	// client a SERVFAIL, try what the host itself uses - see systemDNSUpstreams
	// for why these two can differ, and why that difference is silent.
	fallback := systemDNSUpstreams()
	if len(fallback) == 0 {
		return nil, ErrInvalidDNSUpstream
	}
	resolved, err = s.resolveVia(fallback, rawQuery)
	if err != nil || len(resolved) == 0 {
		return nil, ErrInvalidDNSUpstream
	}
	if s.log != nil {
		s.log.Warnf(
			"🩹 <yellow>Tunnel DNS answered by the host resolver</yellow> <magenta>|</magenta> configured upstreams unreachable: <cyan>%s</cyan>",
			strings.Join(s.dnsUpstreamServers, ", "),
		)
	}
	return resolved, nil
}

// resolveVia forwards the raw query to the first of `upstreams` that answers,
// hedging across them so one slow server does not set the pace.
func (s *Server) resolveVia(upstreams []string, rawQuery []byte) ([]byte, error) {
	if len(upstreams) == 0 {
		return nil, ErrInvalidDNSUpstream
	}

	timeout := s.cfg.DNSUpstreamTimeout()
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	// Fast path: single upstream, no need for hedged requests.
	if len(upstreams) == 1 {
		resp, err := s.queryOneUpstream(upstreams[0], rawQuery, timeout)
		if err != nil || len(resp) == 0 {
			return nil, ErrInvalidDNSUpstream
		}
		return resp, nil
	}

	resultCh := make(chan []byte, len(upstreams))
	launch := func(upstream string) {
		go func(addr string) {
			resp, err := s.queryOneUpstream(addr, rawQuery, timeout)
			if err == nil && len(resp) > 0 {
				resultCh <- resp
				return
			}
			resultCh <- nil
		}(upstream)
	}

	launch(upstreams[0])

	hedgeDelay := dnsUpstreamHedgeDelay(timeout)
	hedgeTimer := time.NewTimer(hedgeDelay)
	defer hedgeTimer.Stop()

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	launched := 1
	received := 0
	hedged := false

	launchRemaining := func() {
		if hedged {
			return
		}
		hedged = true
		for _, upstream := range upstreams[1:] {
			launch(upstream)
			launched++
		}
	}

	for received < launched {
		select {
		case resp := <-resultCh:
			received++
			if len(resp) > 0 {
				return resp, nil
			}
			// Primary failed early: don't wait for the hedge timer to expire.
			if !hedged {
				if !hedgeTimer.Stop() {
					select {
					case <-hedgeTimer.C:
					default:
					}
				}
				launchRemaining()
			}
		case <-hedgeTimer.C:
			launchRemaining()
		case <-deadline.C:
			return nil, ErrInvalidDNSUpstream
		}
	}

	return nil, ErrInvalidDNSUpstream
}

func dnsUpstreamHedgeDelay(timeout time.Duration) time.Duration {
	delay := timeout / 5
	if delay < 100*time.Millisecond {
		delay = 100 * time.Millisecond
	}
	if delay > 350*time.Millisecond {
		delay = 350 * time.Millisecond
	}
	if delay >= timeout {
		return timeout / 2
	}
	return delay
}

// queryOneUpstream sends rawQuery to a single upstream DNS server and returns
// the response. It is safe to call concurrently from multiple goroutines.
func (s *Server) queryOneUpstream(upstream string, rawQuery []byte, timeout time.Duration) ([]byte, error) {
	conn, err := newUDPUpstreamConn(upstream)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(rawQuery); err != nil {
		_ = conn.Close()
		return nil, err
	}

	buffer := s.dnsUpstreamBufferPool.Get().([]byte)
	n, readErr := conn.Read(buffer)
	_ = conn.Close()

	if readErr != nil || n == 0 {
		s.dnsUpstreamBufferPool.Put(buffer)
		if readErr == nil {
			return nil, ErrInvalidDNSUpstream
		}
		return nil, readErr
	}

	if len(rawQuery) >= 2 && n >= 2 {
		if buffer[0] != rawQuery[0] || buffer[1] != rawQuery[1] {
			s.dnsUpstreamBufferPool.Put(buffer)
			return nil, ErrInvalidDNSUpstream
		}
	}

	response := make([]byte, n)
	copy(response, buffer[:n])
	s.dnsUpstreamBufferPool.Put(buffer)
	return response, nil
}

func newUDPUpstreamConn(endpoint string) (*net.UDPConn, error) {
	host, port, err := splitHostPortDefault53(endpoint)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}

func splitHostPortDefault53(value string) (string, string, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", "", ErrInvalidDNSUpstream
	}

	if strings.HasPrefix(text, "[") {
		host, port, err := net.SplitHostPort(text)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}

	if strings.Count(text, ":") == 0 {
		return text, "53", nil
	}
	if strings.Count(text, ":") == 1 {
		host, port, err := net.SplitHostPort(text)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}

	return text, "53", nil
}
