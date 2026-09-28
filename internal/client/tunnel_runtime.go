// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (tunnel_runtime.go) handles low-level UDP network operations,
// including sending DNS-encapsulated packets and receiving responses.
// ==============================================================================

package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/dnsparser"
	"masterdnsvpn-go/internal/netutil"
	"masterdnsvpn-go/internal/sessioncrypto"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	// RuntimeUDPReadBufferSize defines the maximum size of the UDP read buffer.
	RuntimeUDPReadBufferSize         = 65535
	runtimeUDPMaxMismatchedResponses = 64
	runtimeUDPDrainGrace             = time.Millisecond

	// pooledConnMaxAge is the maximum time a UDP connection can remain idle in
	// the resolver pool before it is discarded and re-dialed. Stale connections can have their
	// NAT mappings expired, causing silent packet loss (writes succeed but
	// responses route to a dead port).
	pooledConnMaxAge = 90 * time.Second
)

type pooledUDPConn struct {
	conn     *net.UDPConn
	pooledAt time.Time
}

func (c *Client) drainStaleUDPResponses(conn *net.UDPConn, buffer []byte) error {
	if conn == nil || len(buffer) == 0 {
		return nil
	}

	for drained := 0; drained < runtimeUDPMaxMismatchedResponses*2; drained++ {
		if err := conn.SetReadDeadline(time.Now().Add(runtimeUDPDrainGrace)); err != nil {
			return err
		}

		_, err := conn.Read(buffer)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil
			}
			return err
		}
	}

	return nil
}

// exchangeUDPQueryWithConn sends one UDP packet through the provided connection
// and waits for a response with a matching DNS transaction ID.
func (c *Client) exchangeUDPQueryWithConn(conn *net.UDPConn, packet []byte, timeout time.Duration) ([]byte, error) {
	if len(packet) < 2 {
		return nil, errors.New("malformed dns query")
	}
	expectedID := binary.BigEndian.Uint16(packet[:2])

	bufferRef := c.getRuntimeUDPBuffer()
	defer c.putRuntimeUDPBuffer(bufferRef)
	buffer := *bufferRef
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	if err := c.drainStaleUDPResponses(conn, buffer); err != nil {
		return nil, err
	}

	writeDeadline := time.Now().Add(timeout)
	if err := conn.SetWriteDeadline(writeDeadline); err != nil {
		return nil, err
	}

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	if err := conn.SetReadDeadline(writeDeadline); err != nil {
		return nil, err
	}

	mismatchedResponses := 0

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}

		if n >= 2 && binary.BigEndian.Uint16(buffer[:2]) == expectedID {
			// Copy matched response out so the pooled buffer can be recycled.
			result := make([]byte, n)
			copy(result, buffer[:n])
			return result, nil
		}

		mismatchedResponses++
		if mismatchedResponses >= runtimeUDPMaxMismatchedResponses {
			return nil, errors.New("too many mismatched dns responses on shared udp socket")
		}
	}
}

func (c *Client) sendOneWayDNSQuery(resolver Connection, packet []byte, deadline time.Time) error {
	udpConn, err := c.getUDPConn(resolver.ResolverLabel)
	if err != nil {
		return err
	}

	if err := udpConn.SetWriteDeadline(deadline); err != nil {
		_ = udpConn.Close()
		return err
	}

	if _, err := udpConn.Write(packet); err != nil {
		_ = udpConn.Close()
		return err
	}

	c.putUDPConn(resolver.ResolverLabel, udpConn)
	return nil
}

// getUDPConn retrieves a UDP connection from the pool for the specified resolver.
// If no connection is available in the pool, it dials a new one.
func (c *Client) getUDPConn(resolverLabel string) (*net.UDPConn, error) {
	c.resolverConnsMu.Lock()
	pool, ok := c.resolverConns[resolverLabel]
	if !ok {
		pool = make(chan pooledUDPConn, c.cfg.EffectiveResolverUDPConnectionPoolSize())
		c.resolverConns[resolverLabel] = pool
	}
	c.resolverConnsMu.Unlock()

	now := time.Now()
	for {
		select {
		case pc := <-pool:
			if now.Sub(pc.pooledAt) > pooledConnMaxAge {
				_ = pc.conn.Close()
				continue // discard stale, try next
			}
			return pc.conn, nil
		default:
			return dialUDPResolver(resolverLabel)
		}
	}
}

// putUDPConn returns a UDP connection to the pool for the specified resolver.
// If the pool is full, the connection is closed.
func (c *Client) putUDPConn(resolverLabel string, conn *net.UDPConn) {
	if conn == nil {
		return
	}

	c.resolverConnsMu.Lock()
	pool := c.resolverConns[resolverLabel]
	c.resolverConnsMu.Unlock()

	if pool == nil {
		_ = conn.Close()
		return
	}

	select {
	case pool <- pooledUDPConn{conn: conn, pooledAt: time.Now()}:
	default:
		_ = conn.Close()
	}
}

func (c *Client) closeResolverConnPools() {
	if c == nil {
		return
	}

	c.resolverConnsMu.Lock()
	pools := c.resolverConns
	c.resolverConns = make(map[string]chan pooledUDPConn)
	c.resolverConnsMu.Unlock()

	for _, pool := range pools {
		for {
			select {
			case pc := <-pool:
				if pc.conn != nil {
					_ = pc.conn.Close()
				}
			default:
				goto nextPool
			}
		}
	nextPool:
	}
}

// getRuntimeUDPBuffer takes a RuntimeUDPReadBufferSize buffer from the
// internal pool, to spare an allocation per packet. The pool holds pointers:
// putting a bare slice back would allocate its header every time.
func (c *Client) getRuntimeUDPBuffer() *[]byte {
	if c != nil {
		if buf, _ := c.udpBufferPool.Get().(*[]byte); buf != nil && len(*buf) == RuntimeUDPReadBufferSize {
			return buf
		}
	}
	buf := make([]byte, RuntimeUDPReadBufferSize)
	return &buf
}

// putRuntimeUDPBuffer returns a buffer from getRuntimeUDPBuffer to the pool.
func (c *Client) putRuntimeUDPBuffer(buf *[]byte) {
	if c == nil || buf == nil || len(*buf) != RuntimeUDPReadBufferSize {
		return
	}
	c.udpBufferPool.Put(buf)
}

// protectPath is set at startup from the config. dialUDPResolver is a free
// function with no client to ask, and threading the path through every caller
// would spread an Android detail across code that has no other reason to know
// about it. It is atomic because a host app can start a new client while the
// old one's goroutines are still dialing.
var protectPath atomic.Pointer[string]

// SetProtectPath records where the VPN app listens to protect our sockets.
func SetProtectPath(p string) { protectPath.Store(&p) }

func currentProtectPath() string {
	if p := protectPath.Load(); p != nil {
		return *p
	}
	return ""
}

// dialUDPResolver resolves the resolver address and establishes a new UDP connection.
func dialUDPResolver(resolverLabel string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", resolverLabel)
	if err != nil {
		return nil, err
	}
	// Same reason as the listeners in async_runtime: this is our own path out
	// to a resolver and must not go through the tunnel we are providing.
	d := net.Dialer{Control: netutil.Control(currentProtectPath())}
	conn, err := d.Dial("udp", addr.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected conn type %T", conn)
	}
	return udpConn, nil
}

// normalizeTimeout ensures the timeout is positive, falling back to a default if necessary.
func normalizeTimeout(timeout time.Duration, fallback time.Duration) time.Duration {
	if timeout <= 0 {
		return fallback
	}
	return timeout
}

// udpQueryTransport wraps a UDP connection for queries.
type udpQueryTransport struct {
	conn *net.UDPConn
}

// newUDPQueryTransport creates a new transport for UDP queries to the specified resolver.
func newUDPQueryTransport(resolverLabel string) (*udpQueryTransport, error) {
	conn, err := dialUDPResolver(resolverLabel)
	if err != nil {
		return nil, err
	}

	return &udpQueryTransport{
		conn: conn,
	}, nil
}

// exchangeUDPQuery performs a synchronous UDP request-response cycle using the provided transport.
func (c *Client) exchangeUDPQuery(transport *udpQueryTransport, packet []byte, timeout time.Duration) ([]byte, error) {
	if transport == nil || transport.conn == nil {
		return nil, net.ErrClosed
	}

	return c.exchangeUDPQueryWithConn(transport.conn, packet, timeout)
}

// exchangeDNSOverConnection sends a DNS query and returns the extracted VPN packet.
// exchangeDNSOverConnectionWith sends one tunnel query on a pooled socket and
// reads its answer, decoded as base64 says, and opened with keys when the
// answer may be sealed (a v2 SESSION_INIT). sealed reports whether it was.
func (c *Client) exchangeDNSOverConnectionWith(conn Connection, query []byte, timeout time.Duration, base64 bool, keys *sessioncrypto.Keys) (VpnProto.Packet, bool, error) {
	udpConn, err := c.getUDPConn(conn.ResolverLabel)
	if err != nil {
		return VpnProto.Packet{}, false, err
	}

	response, err := c.exchangeUDPQueryWithConn(udpConn, query, timeout)
	if err != nil {
		_ = udpConn.Close()
		return VpnProto.Packet{}, false, err
	}

	c.putUDPConn(conn.ResolverLabel, udpConn)

	var open func([]byte) ([]byte, bool)
	if keys != nil {
		open = keys.OpenDown
	}
	packet, sealed, err := dnsparser.ExtractVPNResponseWith(response, base64, open)
	if err != nil {
		return VpnProto.Packet{}, false, err
	}

	return packet, sealed, nil
}
