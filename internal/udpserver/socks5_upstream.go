// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
)

type upstreamSOCKS5Error struct {
	packetType uint8
	err        error
}

type blockedSOCKSTargetError struct {
	host string
}

var (
	externalSOCKS5NoAuthGreeting = []byte{0x05, 0x01, 0x00}
	externalSOCKS5UserPassAuth   = []byte{0x05, 0x01, 0x02}
)

type socks5FragmentKey struct {
	sessionID   uint8
	streamID    uint16
	sequenceNum uint16
}

func (e *upstreamSOCKS5Error) Error() string {
	if e == nil || e.err == nil {
		return "upstream socks5 error"
	}
	return e.err.Error()
}

func (e *upstreamSOCKS5Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (e *blockedSOCKSTargetError) Error() string {
	if e == nil || e.host == "" {
		return "blocked socks target"
	}
	return fmt.Sprintf("blocked socks target: %s", e.host)
}

func (s *Server) dialSOCKSStreamTarget(host string, port uint16, targetPayload []byte) (net.Conn, error) {
	return s.dialSOCKSStreamTargetContext(context.Background(), host, port, targetPayload)
}

func (s *Server) dialSOCKSStreamTargetContext(ctx context.Context, host string, port uint16, targetPayload []byte) (net.Conn, error) {
	if s == nil {
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("server unavailable"),
		}
	}

	if err := validateSOCKSTargetHost(host); err != nil {
		return nil, err
	}

	if !s.useExternalSOCKS5 || len(targetPayload) == 0 {
		return s.dialDirectSOCKSTarget(ctx, host, port)
	}
	return s.dialExternalSOCKS5TargetContext(ctx, targetPayload)
}

// dialDirectSOCKSTarget connects to a client-chosen target from this host.
//
// 🔴 A name is resolved HERE and every address it yields is checked before
// anything is dialled. validateSOCKSTargetHost can only judge a literal IP; a
// name went straight to the dialer, so any name whose A record says 127.0.0.1
// or 10.x or 169.254.169.254 (there are public ones built for exactly that)
// handed a subscriber this node's loopback services and private network. The
// connection goes to the address that was checked, so a record that changes
// between the check and the dial (rebinding) changes nothing.
func (s *Server) dialDirectSOCKSTarget(ctx context.Context, host string, port uint16) (net.Conn, error) {
	portText := strconv.Itoa(int(port))
	if _, err := netip.ParseAddr(strings.TrimSpace(host)); err == nil {
		return s.dialTCPTargetContext(ctx, net.JoinHostPort(host, portText))
	}

	lookup := s.lookupTargetIPsFn
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}

	allowed := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if !isBlockedSOCKSTargetIP(addr) {
			allowed = append(allowed, addr)
		}
	}
	if len(allowed) == 0 {
		return nil, &blockedSOCKSTargetError{host: host}
	}
	allowed = ipv4FirstInterleaved(allowed)
	if len(allowed) > maxDirectTargetAddrs {
		allowed = allowed[:maxDirectTargetAddrs]
	}
	return s.raceDirectTargets(ctx, allowed, portText)
}

const (
	maxDirectTargetAddrs      = 4
	directTargetFallbackDelay = 300 * time.Millisecond
)

// ipv4FirstInterleaved puts an IPv4 address first and then alternates the
// families, each family keeping the lookup's order (RFC 8305 section 4, with
// IPv4 as the first family: every node has IPv4, and not every node's IPv6
// reaches anything).
func ipv4FirstInterleaved(addrs []netip.Addr) []netip.Addr {
	var v4, v6 []netip.Addr
	for _, addr := range addrs {
		if addr.Unmap().Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	ordered := make([]netip.Addr, 0, len(addrs))
	for i := 0; i < len(v4) || i < len(v6); i++ {
		if i < len(v4) {
			ordered = append(ordered, v4[i])
		}
		if i < len(v6) {
			ordered = append(ordered, v6[i])
		}
	}
	return ordered
}

// raceDirectTargets connects to the first of addrs that answers. Each address
// gets directTargetFallbackDelay before the next one is started beside it, a
// failure starts the next one at once, and the first connection wins; the
// others are cancelled, and closed if they connect anyway.
//
// 🔴 Tried one at a time, an address that never answered held up every one
// after it. A node with an IPv6 address but no IPv6 route out drops the SYN
// rather than refusing it, and the lookup sorts IPv6 first: through the UK
// node a new connection to a dual-stack name sat out two IPv6 attempts of
// 3.75 s each before IPv4 was tried, and www.google.com, whose IPv6 addresses
// filled every attempt, did not connect at all (Claude 2026-10-22, measured
// through the relay). Literal addresses, which the Android app sends, never
// came here; names, which the Windows bridge sends, all did.
func (s *Server) raceDirectTargets(ctx context.Context, addrs []netip.Addr, port string) (net.Conn, error) {
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type dialResult struct {
		conn net.Conn
		err  error
	}
	results := make(chan dialResult, len(addrs))
	started, pending := 0, 0
	startNext := func() {
		address := net.JoinHostPort(addrs[started].String(), port)
		started++
		pending++
		go func() {
			conn, err := s.dialTCPTargetContext(raceCtx, address)
			results <- dialResult{conn: conn, err: err}
		}()
	}

	startNext()
	fallback := time.NewTimer(directTargetFallbackDelay)
	defer fallback.Stop()
	var lastErr error
	for pending > 0 {
		select {
		case result := <-results:
			pending--
			if result.err == nil {
				cancel()
				go func(left int) {
					for ; left > 0; left-- {
						if late := <-results; late.conn != nil {
							_ = late.conn.Close()
						}
					}
				}(pending)
				return result.conn, nil
			}
			lastErr = result.err
			if started < len(addrs) && ctx.Err() == nil {
				startNext()
				fallback.Reset(directTargetFallbackDelay)
			}
		case <-fallback.C:
			if started < len(addrs) {
				startNext()
				fallback.Reset(directTargetFallbackDelay)
			}
		}
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, lastErr
}

func validateSOCKSTargetHost(host string) error {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return &blockedSOCKSTargetError{host: host}
	}

	lower := strings.ToLower(trimmed)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return &blockedSOCKSTargetError{host: host}
	}

	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		// A name: judged by what it resolves to, in dialDirectSOCKSTarget.
		return nil
	}
	if isBlockedSOCKSTargetIP(addr) {
		return &blockedSOCKSTargetError{host: host}
	}
	return nil
}

var blockedSOCKSTargetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
}

// isBlockedSOCKSTargetIP reports addresses a subscriber must not reach through
// this node: its own loopback, private and link-local networks (which include
// cloud metadata at 169.254.169.254), multicast, and the special ranges above.
// An IPv4-mapped IPv6 address is judged as the IPv4 address it carries.
func isBlockedSOCKSTargetIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() ||
		!addr.IsGlobalUnicast() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsUnspecified() {
		return true
	}
	for _, prefix := range blockedSOCKSTargetPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) dialTCPTarget(address string) (net.Conn, error) {
	return s.dialTCPTargetContext(context.Background(), address)
}

func (s *Server) dialTCPTargetContext(ctx context.Context, address string) (net.Conn, error) {
	dialFn := s.dialStreamUpstreamFn
	timeout := s.socksConnectTimeout
	if timeout <= 0 {
		timeout = s.cfg.SOCKSConnectTimeout()
	}
	if deadline, ok := ctx.Deadline(); ok {
		untilDeadline := time.Until(deadline)
		if untilDeadline > 0 && (timeout <= 0 || untilDeadline < timeout) {
			timeout = untilDeadline
		}
	}
	startedAt := logger.NowUnixNano()

	if dialFn == nil {
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		return conn, err
	}
	if ctx == nil {
		conn, err := dialFn("tcp", address, timeout)
		return conn, err
	}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)
	go func() {
		conn, err := dialFn("tcp", address, timeout)
		resultCh <- dialResult{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			result := <-resultCh
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case result := <-resultCh:
		if s != nil && s.log != nil {
			s.log.Debugf(
				"DEFER upstream-connect-finish | address=%s | dur_ms=%d | err=%v",
				address,
				(logger.NowUnixNano()-startedAt)/1_000_000,
				result.err,
			)
		}
		return result.conn, result.err
	}
}

func (s *Server) dialExternalSOCKS5Target(targetPayload []byte) (net.Conn, error) {
	return s.dialExternalSOCKS5TargetContext(context.Background(), targetPayload)
}

func (s *Server) dialExternalSOCKS5TargetContext(ctx context.Context, targetPayload []byte) (net.Conn, error) {
	conn, err := s.dialTCPTargetContext(ctx, s.externalSOCKS5Address)
	if err != nil {
		return nil, err
	}

	stopCancelWatch := func() bool { return true }
	if ctx != nil {
		stopCancelWatch = context.AfterFunc(ctx, func() {
			_ = conn.Close()
		})
	}

	timeout := s.socksConnectTimeout
	if timeout <= 0 {
		timeout = s.cfg.SOCKSConnectTimeout()
	}
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if err := writeAll(conn, s.externalSOCKS5Greeting()); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}

	var greeting [2]byte

	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}
	if greeting[0] != 0x05 {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("upstream proxy is not a valid SOCKS5 server"),
		}
	}
	if err := s.handleExternalSOCKS5Auth(conn, greeting[1]); err != nil {
		_ = conn.Close()
		return nil, err
	}

	request := make([]byte, 3+len(targetPayload))
	request[0] = 0x05
	request[1] = 0x01
	request[2] = 0x00
	copy(request[3:], targetPayload)

	if err := writeAll(conn, request); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}

	var header [4]byte

	if _, err := io.ReadFull(conn, header[:]); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}
	if header[0] != 0x05 {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("invalid external SOCKS5 connect response"),
		}
	}
	if header[1] != 0x00 {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{
			packetType: socks5ReplyPacketType(header[1]),
			err:        fmt.Errorf("external SOCKS5 failed to connect to target: code %d", header[1]),
		}
	}
	if err := discardSOCKS5BoundAddress(conn, header[3]); err != nil {
		_ = conn.Close()
		return nil, &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE, err: err}
	}
	if !stopCancelWatch() {
		_ = conn.Close()
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_UPSTREAM_UNAVAILABLE,
			err:        errors.New("external SOCKS5 handshake cancelled"),
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (s *Server) externalSOCKS5Greeting() []byte {
	if s != nil && s.externalSOCKS5Auth {
		return externalSOCKS5UserPassAuth
	}
	return externalSOCKS5NoAuthGreeting
}

func (s *Server) handleExternalSOCKS5Auth(conn net.Conn, method byte) error {
	if !s.externalSOCKS5Auth {
		if method == 0x00 {
			return nil
		}
		return &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_AUTH_FAILED,
			err:        errors.New("external SOCKS5 requires unsupported authentication method"),
		}
	}

	if method != 0x02 {
		return &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_AUTH_FAILED,
			err:        errors.New("external SOCKS5 authentication method mismatch"),
		}
	}

	request := make([]byte, 3+len(s.externalSOCKS5User)+len(s.externalSOCKS5Pass))
	request[0] = 0x01
	request[1] = byte(len(s.externalSOCKS5User))
	offset := 2
	offset += copy(request[offset:], s.externalSOCKS5User)
	request[offset] = byte(len(s.externalSOCKS5Pass))
	offset++
	copy(request[offset:], s.externalSOCKS5Pass)
	if err := writeAll(conn, request); err != nil {
		return &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_AUTH_FAILED, err: err}
	}

	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return &upstreamSOCKS5Error{packetType: Enums.PACKET_SOCKS5_AUTH_FAILED, err: err}
	}
	if response[1] != 0x00 {
		return &upstreamSOCKS5Error{
			packetType: Enums.PACKET_SOCKS5_AUTH_FAILED,
			err:        errors.New("external SOCKS5 authentication failed"),
		}
	}
	return nil
}

func discardSOCKS5BoundAddress(conn net.Conn, atyp byte) error {
	length := 0
	switch atyp {
	case 0x01:
		length = 4 + 2
	case 0x03:
		var dlen [1]byte
		if _, err := io.ReadFull(conn, dlen[:]); err != nil {
			return err
		}
		length = int(dlen[0]) + 2
	case 0x04:
		length = 16 + 2
	default:
		return errors.New("unsupported SOCKS5 bound address type")
	}
	if length == 0 {
		return nil
	}
	var buffer [257]byte
	_, err := io.ReadFull(conn, buffer[:length])
	return err
}

func socks5ReplyPacketType(reply byte) uint8 {
	switch reply {
	case 0x02:
		return Enums.PACKET_SOCKS5_RULESET_DENIED
	case 0x03:
		return Enums.PACKET_SOCKS5_NETWORK_UNREACHABLE
	case 0x04:
		return Enums.PACKET_SOCKS5_HOST_UNREACHABLE
	case 0x05:
		return Enums.PACKET_SOCKS5_CONNECTION_REFUSED
	case 0x06:
		return Enums.PACKET_SOCKS5_TTL_EXPIRED
	case 0x07:
		return Enums.PACKET_SOCKS5_COMMAND_UNSUPPORTED
	case 0x08:
		return Enums.PACKET_SOCKS5_ADDRESS_TYPE_UNSUPPORTED
	default:
		return Enums.PACKET_SOCKS5_CONNECT_FAIL
	}
}

func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) != 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func (s *Server) collectSOCKS5SynFragments(sessionID uint8, streamID uint16, sequenceNum uint16, payload []byte, fragmentID uint8, totalFragments uint8, now time.Time) ([]byte, bool, bool) {
	if totalFragments == 0 {
		totalFragments = 1
	}

	assembled, ready, completed := s.socks5Fragments.Collect(
		socks5FragmentKey{
			sessionID:   sessionID,
			streamID:    streamID,
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

func (s *Server) purgeSOCKS5SynFragments(now time.Time) {
	if s == nil || s.socks5Fragments == nil {
		return
	}
	s.socks5Fragments.Purge(now, s.dnsFragmentTimeout)
}

func (s *Server) removeSOCKS5SynFragmentsForSession(sessionID uint8) {
	if s == nil || s.socks5Fragments == nil || sessionID == 0 {
		return
	}
	s.socks5Fragments.RemoveIf(func(key socks5FragmentKey) bool {
		return key.sessionID == sessionID
	})
}

func (s *Server) removeSOCKS5SynFragmentsForStream(sessionID uint8, streamID uint16) {
	if s == nil || s.socks5Fragments == nil || sessionID == 0 || streamID == 0 {
		return
	}
	s.socks5Fragments.RemoveIf(func(key socks5FragmentKey) bool {
		return key.sessionID == sessionID && key.streamID == streamID
	})
}
