package client

import (
	"net"
	"strings"
	"time"
)

// bypassDNSTimeout bounds a direct lookup.
//
// Short on purpose: this path exists because it is meant to be much faster than
// the tunnel, and a bypass that stalls is worse than no bypass at all - the
// caller has already skipped the tunnel by the time it is waiting here. On
// timeout the query falls back to the tunnel, so a slow domestic resolver costs
// this much once, not the answer.
const bypassDNSTimeout = 2 * time.Second

// resolveBypassDirect answers a DNS query without the tunnel.
//
// 🔑 The socket is dialled through dialUDPResolver, which applies the same
// protect control every other outbound socket here uses. Without it the query
// would leave through the TUN this client is itself providing - straight into
// the tunnel it was trying to avoid, and on Android into a routing loop.
//
// 🔑 Every resolver is asked at once and the first usable answer wins. Tried in
// turn instead, each dead resolver costs its full timeout before the next is
// reached: ten resolvers with nine down is eighteen seconds for a name, and a
// page pulls in dozens of names. Racing makes nine of ten being down cost
// nothing at all - which is the situation this whole feature exists for, when
// the foreign internet is gone and only some domestic resolvers still answer.
//
// The cost is one extra UDP packet per resolver per uncached name. That is the
// right trade against a tunnel that carries DNS inside DNS.
//
// Returns the raw response, or nil when the caller should fall back to the
// tunnel. Every failure returns nil rather than an error: there is exactly one
// thing the caller can do about any of them, and it is the same thing.
func (c *Client) resolveBypassDirect(query []byte) []byte {
	servers := c.bypassServers()
	if len(servers) == 0 {
		return nil
	}

	// Buffered by the number of racers, so a loser that finishes after the
	// winner has been taken still has somewhere to put its result and exits
	// instead of leaking on a blocked send.
	results := make(chan []byte, len(servers))
	deadline := time.Now().Add(bypassDNSTimeout)

	for _, srv := range servers {
		go func(srv string) {
			results <- queryResolverOnce(srv, query, deadline)
		}(srv)
	}

	for range servers {
		select {
		case resp := <-results:
			if resp != nil {
				return resp
			}
		case <-time.After(time.Until(deadline)):
			return nil
		}
	}
	return nil
}

// queryResolverOnce sends one query to one resolver and returns its reply.
func queryResolverOnce(srv string, query []byte, deadline time.Time) []byte {
	conn, err := dialUDPResolver(srv)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil
	}
	if _, err := conn.Write(query); err != nil {
		return nil
	}
	// 4096 covers an EDNS0 answer; anything larger is a response this path has
	// no business carrying, and truncation makes the client retry over TCP
	// through the ordinary route.
	buf := make([]byte, 4096)
	// Read until this resolver has answered or the deadline passes. A late
	// reply to an older query, or a stray datagram from anywhere else, must not
	// end the attempt - but this resolver's own answer does, usable or not.
	// ⚠️ It used to keep reading after a rejected answer too, and a resolver
	// sends one answer per question: every racer that got a NODATA then sat out
	// the full deadline, so an AAAA or HTTPS lookup for an IPv4-only domestic
	// site - most of them - cost two seconds before it even reached the tunnel.
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return nil
		}
		reply := buf[:n]
		if !answersQuery(reply, query) {
			continue
		}
		if usableDNSReply(reply, query) {
			return append([]byte(nil), reply...)
		}
		return nil
	}
}

// answersQuery reports whether a datagram is a response to `query` at all:
// long enough, same transaction ID, QR set. Anything else is somebody else's
// traffic and is skipped.
func answersQuery(resp, query []byte) bool {
	const headerLen = 12
	if len(resp) < headerLen || len(query) < headerLen {
		return false
	}
	if resp[0] != query[0] || resp[1] != query[1] {
		return false
	}
	return resp[2]&0x80 != 0
}

// usableDNSReply reports whether a datagram is an answer to `query` worth
// handing back.
//
// 🔑 Racing makes this necessary rather than merely tidy. Taking the first
// reply that arrives, unchecked, selects for whichever resolver answers
// fastest - and on a censored network the fastest answer is very often a
// hijacked one: an instant NXDOMAIN or a redirect to a block page, while the
// honest resolver is still working. Without this the bypass would prefer the
// liar, and the more resolvers raced the likelier that becomes.
//
// Checked cheapest first:
//   - is it long enough to be a DNS header at all
//   - does the transaction ID match the query we sent
//   - is it a response rather than someone else's question
//   - did it succeed; an error rcode is not an answer, and letting the race
//     continue gives a working resolver the chance to reply
//   - is an empty or NXDOMAIN answer backed by the zone's SOA
func usableDNSReply(resp, query []byte) bool {
	if !answersQuery(resp, query) {
		return false
	}
	hasAnswers := resp[6] != 0 || resp[7] != 0
	hasAuthority := resp[8] != 0 || resp[9] != 0
	switch resp[3] & 0x0F {
	case 0: // NOERROR
		// With records it is an answer. Without, it is only believed when it
		// carries the zone's SOA (RFC 2308): that is how an honest resolver says
		// "this name has no record of this type" - the everyday case for AAAA
		// and HTTPS lookups - while a bare empty reply is the shape a filtered
		// one takes.
		return hasAnswers || hasAuthority
	case 3: // NXDOMAIN
		// Same rule: a real NXDOMAIN names its zone's SOA; an instant bare one
		// is the classic injected lie, and rejecting it lets the race go on.
		return hasAuthority
	default:
		return false // SERVFAIL, REFUSED, ...: not an answer about the name
	}
}

// bypassServers is who answers a bypassed name.
//
// ⚠️ Deliberately not the tunnel's own resolvers. Those are chosen for being
// reachable from a censored network and for carrying tunnel traffic; a bypassed
// name wants whichever resolver gives the *closest* answer, which for domestic
// names is a domestic resolver. Configured rather than guessed, because that
// choice belongs to whoever knows the network.
func (c *Client) bypassServers() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.cfg.BypassDNSServers))
	for _, s := range c.cfg.BypassDNSServers {
		if s = normalizeResolverLabel(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// normalizeResolverLabel accepts "1.2.3.4" or "1.2.3.4:53" and returns a
// dialable label, so the config can be written either way.
//
// ⚠️ SplitHostPort rather than looking for a colon: an IPv6 literal is full of
// them, and "::1" is an address, not a host and a port.
func normalizeResolverLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}
