package client

import (
	"net"
	"testing"
)

// A pipe end that just records what was written.
type capture struct {
	net.Conn
	buf []byte
}

func (c *capture) Write(p []byte) (int, error) { c.buf = append(c.buf, p...); return len(p), nil }

// The reply's length is a promise the ATYP byte makes. Breaking it is invisible
// to the client, which reads the port as part of the address and whatever comes
// next as the port - and is then told to send its UDP somewhere that does not
// exist.
//
// Measured on a phone before the fix: the associate succeeded and reported a
// relay endpoint of 174.146.0.0:0. 0xAE92 is 44690, the real bound port, read
// two bytes too early.
func TestUDPAssociateReplyIsNeverShort(t *testing.T) {
	cases := []struct {
		name string
		atyp byte
		ip   net.IP
		want int // 4 header + address + 2 port
	}{
		{"ipv4 address", SOCKS5_ATYP_IPV4, net.IPv4(127, 0, 0, 1), 10},
		{"ipv6 address", SOCKS5_ATYP_IPV6, net.ParseIP("::1"), 22},
		// 🔑 The regression: an IPv6 address under an IPv4 ATYP. To4() is nil,
		// and appending nil used to append nothing.
		{"v6 bind under v4 atyp", SOCKS5_ATYP_IPV4, net.IPv6unspecified, 10},
		{"nil address under v4 atyp", SOCKS5_ATYP_IPV4, nil, 10},
		{"domain atyp is rewritten to v4", SOCKS5_ATYP_DOMAIN, net.IPv4zero, 10},
	}
	c := &Client{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &capture{}
			if err := c.sendSocksReply(w, SOCKS5_REPLY_SUCCESS, tc.atyp, tc.ip, 44690); err != nil {
				t.Fatalf("sendSocksReply: %v", err)
			}
			if len(w.buf) != tc.want {
				t.Fatalf("reply is %d bytes, want %d - a client reading this is "+
					"pointed at an endpoint that does not exist. bytes=%v",
					len(w.buf), tc.want, w.buf)
			}
			// And the port must land where the client will look for it.
			port := int(w.buf[len(w.buf)-2])<<8 | int(w.buf[len(w.buf)-1])
			if port != 44690 {
				t.Fatalf("port read back as %d, want 44690 (bytes=%v)", port, w.buf)
			}
		})
	}
}
