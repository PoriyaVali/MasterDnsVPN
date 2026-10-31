// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import "net/netip"

// clientAddr is where a query came from. Its text is made only when a packet
// needs it: a v2 session names its own device, so most packets never do, and
// making it for every packet was an allocation each.
type clientAddr struct {
	addr netip.Addr
	text string // given by the caller, when it has it as text
}

// String is the client's IP as net.IP.String wrote it, which is what device
// accounting is keyed on: an IPv4 client of a dual-stack socket as plain
// IPv4, and no zone.
func (c clientAddr) String() string {
	if c.text != "" || !c.addr.IsValid() {
		return c.text
	}
	return c.addr.Unmap().WithZone("").String()
}
