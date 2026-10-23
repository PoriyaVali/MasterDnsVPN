package client

import (
	"errors"
	"net"
)

// A SOCKS UDP association belongs to the authenticated TCP peer (RFC 1928,
// sections 6 and 7). The client may leave its UDP port unspecified until its
// first valid datagram; it must not move an established association to another
// socket. Only the association's read goroutine accesses this state.
type socksUDPPeer struct {
	ip   net.IP
	zone string
	port int
}

func newSocksUDPPeer(addr net.Addr, declaredPort uint16) (*socksUDPPeer, error) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp == nil || tcp.IP == nil || tcp.IP.IsUnspecified() {
		return nil, errors.New("SOCKS UDP association has no authenticated TCP peer")
	}
	ip := tcp.IP.To4()
	if ip == nil {
		ip = tcp.IP.To16()
	}
	if ip == nil {
		return nil, errors.New("invalid SOCKS UDP peer address")
	}
	return &socksUDPPeer{ip: append(net.IP(nil), ip...), zone: tcp.Zone, port: int(declaredPort)}, nil
}

// allowed is checked before parsing or processing any untrusted datagram.
// net.IP.Equal treats Windows IPv4-mapped IPv6 addresses as the same IPv4 peer.
func (p *socksUDPPeer) allowed(addr *net.UDPAddr) bool {
	return addr != nil && addr.Port > 0 && addr.Port <= 65535 &&
		p.ip.Equal(addr.IP) && (p.zone == "" || p.zone == addr.Zone) &&
		(p.port == 0 || p.port == addr.Port)
}

// Pin only after a complete, unfragmented SOCKS UDP header has been validated:
// malformed datagrams cannot take ownership of an unspecified client port.
func (p *socksUDPPeer) pin(addr *net.UDPAddr) {
	if p.port == 0 {
		p.port = addr.Port
	}
}

// Bind the relay to the interface on which the TCP control connection arrived.
// In the app this is loopback; a wildcard UDP socket would otherwise expose a
// supposedly local association on every physical IPv4/IPv6 interface.
func listenSocksUDP(conn net.Conn) (*net.UDPConn, error) {
	tcp, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || tcp == nil || tcp.IP == nil || tcp.IP.IsUnspecified() {
		return nil, errors.New("SOCKS UDP association has no concrete TCP local address")
	}
	ip, network := tcp.IP.To4(), "udp4"
	if ip == nil {
		ip, network = tcp.IP.To16(), "udp6"
	}
	if ip == nil {
		return nil, errors.New("invalid SOCKS UDP local address")
	}
	return net.ListenUDP(network, &net.UDPAddr{IP: ip, Zone: tcp.Zone})
}
