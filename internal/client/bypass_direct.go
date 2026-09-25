package client

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"masterdnsvpn-go/internal/netutil"
)

// directDialTimeout bounds a direct connection attempt. The address is
// domestic and close; a dial that takes longer than this is not going to
// succeed, and the app behind hev is waiting on the SOCKS reply.
const directDialTimeout = 10 * time.Second

// bypassTarget returns the destination as an IP when it is an address in the
// bypass ranges. Domain targets never match: only an address can be compared
// with a range, and resolving here would add a lookup to every CONNECT.
func (c *Client) bypassTarget(atyp byte, addr string) (net.IP, bool) {
	if c == nil || c.bypassCIDRs == nil || c.bypassCIDRs.Len() == 0 {
		return nil, false
	}
	if atyp != SOCKS5_ATYP_IPV4 && atyp != SOCKS5_ATYP_IPV6 {
		return nil, false
	}
	ip := net.ParseIP(addr)
	if ip == nil || !c.bypassCIDRs.Contains(ip) {
		return nil, false
	}
	return ip, true
}

// handleDirectConnect serves a CONNECT to a bypassed address without the
// tunnel: dial it from here, answer the SOCKS request, and relay until either
// side is done. It owns conn from here on and closes it.
//
// 🔑 The dial goes through the same protect control as the resolver sockets.
// On Android this process is already kept out of the app's own VPN, so the
// control is the second safety net against the one failure that matters: a
// "direct" connection that re-enters the TUN and loops back into this client.
func (c *Client) handleDirectConnect(ctx context.Context, conn net.Conn, ip net.IP, port uint16, socksVersion byte) {
	defer func() { _ = conn.Close() }()

	target := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	c.log.Infof("↩️ <green>Direct TCP CONNECT to <cyan>%s</cyan> (bypass range)</green>", target)

	d := net.Dialer{Timeout: directDialTimeout, Control: netutil.Control(protectPath)}
	upstream, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		c.log.Debugf("↩️ <yellow>Direct dial to %s failed: %v</yellow>", target, err)
		if socksVersion == SOCKS4_VERSION {
			_ = c.sendSocks4Reply(conn, false)
		} else {
			_ = c.sendSocksReply(conn, directDialReply(err), SOCKS5_ATYP_IPV4, net.IPv4zero, 0)
		}
		return
	}
	defer func() { _ = upstream.Close() }()

	if socksVersion == SOCKS4_VERSION {
		if err := c.sendSocks4Reply(conn, true); err != nil {
			return
		}
	} else {
		bindIP, bindPort := net.IPv4zero, uint16(0)
		bindATYP := byte(SOCKS5_ATYP_IPV4)
		if la, ok := upstream.LocalAddr().(*net.TCPAddr); ok && la != nil {
			bindPort = uint16(la.Port)
			if v4 := la.IP.To4(); v4 != nil {
				bindIP = v4
			} else if la.IP != nil {
				bindIP, bindATYP = la.IP, SOCKS5_ATYP_IPV6
			}
		}
		if err := c.sendSocksReply(conn, SOCKS5_REPLY_SUCCESS, bindATYP, bindIP, bindPort); err != nil {
			return
		}
	}

	relayDirect(ctx, conn, upstream)
}

// relayDirect copies both ways until both directions have finished, passing a
// half-close through so a request/response protocol still sees its EOF. The
// client shutting down closes both ends.
func relayDirect(ctx context.Context, a, b net.Conn) {
	stop := context.AfterFunc(ctx, func() {
		_ = a.Close()
		_ = b.Close()
	})
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go pipe(b, a)
	go pipe(a, b)
	wg.Wait()
}

// directDialReply maps a dial error to the SOCKS5 reply that names it, so the
// app sees "refused" as refused rather than as a generic failure.
func directDialReply(err error) byte {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return SOCKS5_REPLY_CONNECTION_REFUSED
	case errors.Is(err, syscall.ENETUNREACH):
		return SOCKS5_REPLY_NETWORK_UNREACHABLE
	default:
		return SOCKS5_REPLY_HOST_UNREACHABLE
	}
}

// directUDPRelay carries one UDP association's datagrams to bypassed
// addresses without the tunnel.
//
// Before this, the association answered DNS and dropped everything else; with
// the domestic ranges as VPN routes that did not matter, because domestic UDP
// (QUIC, calls) never reached the TUN. Matched here instead, it would have been
// dropped - so it is relayed here instead.
type directUDPRelay struct {
	c      *Client
	out    *net.UDPConn // protected, unconnected: one socket for every target
	assoc  *net.UDPConn // the association socket the client talks to
	peer   atomic.Pointer[net.UDPAddr]
	closed atomic.Bool
}

func (c *Client) newDirectUDPRelay(assoc *net.UDPConn) (*directUDPRelay, error) {
	lc := net.ListenConfig{Control: netutil.Control(protectPath)}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, err
	}
	out, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("direct UDP socket is not a UDPConn")
	}
	r := &directUDPRelay{c: c, out: out, assoc: assoc}
	go r.readLoop()
	return r, nil
}

// send forwards one datagram and remembers where the client is, so replies
// can be wrapped and returned to it.
func (r *directUDPRelay) send(peer *net.UDPAddr, ip net.IP, port uint16, payload []byte) {
	r.peer.Store(peer)
	_, _ = r.out.WriteToUDP(payload, &net.UDPAddr{IP: ip, Port: int(port)})
}

func (r *directUDPRelay) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := r.out.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Only answers from bypassed addresses: this socket only ever sent to
		// them, and anything else arriving on it is not ours to deliver.
		if from == nil || !r.c.bypassCIDRs.Contains(from.IP) {
			continue
		}
		peer := r.peer.Load()
		if peer == nil {
			continue
		}
		// RFC 1928 §7: the reply names the address the datagram came from,
		// which is how the client matches it to what it sent.
		hdr := make([]byte, 0, 22+n)
		if v4 := from.IP.To4(); v4 != nil {
			hdr = append(hdr, 0, 0, 0, SOCKS5_ATYP_IPV4)
			hdr = append(hdr, v4...)
		} else {
			hdr = append(hdr, 0, 0, 0, SOCKS5_ATYP_IPV6)
			hdr = append(hdr, from.IP.To16()...)
		}
		hdr = append(hdr, byte(from.Port>>8), byte(from.Port))
		_, _ = r.assoc.WriteToUDP(append(hdr, buf[:n]...), peer)
	}
}

func (r *directUDPRelay) Close() {
	if r != nil && r.closed.CompareAndSwap(false, true) {
		_ = r.out.Close()
	}
}
