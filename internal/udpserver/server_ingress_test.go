package udpserver

import (
	"encoding/binary"
	"testing"

	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
)

func TestHandlePacketRejectsUnauthorizedDomainAsNXDOMAIN(t *testing.T) {
	server := &Server{
		domainMatcher: domainMatcher.New([]string{"vpn.example.com"}, 3),
	}
	request := buildTestDNSQuery(0x4242, "example.org", Enums.DNS_RECORD_TYPE_A)

	response := server.handlePacket(request, "")
	if response == nil {
		t.Fatal("expected DNS response, got nil")
	}

	flags := binary.BigEndian.Uint16(response[2:4])
	if got := flags & 0x000F; got != Enums.DNSR_CODE_NAME_ERROR {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, Enums.DNSR_CODE_NAME_ERROR)
	}
	if flags&(1<<7) != 0 {
		t.Fatal("unauthorized-domain response must clear RA")
	}
	if flags&(1<<10) == 0 {
		t.Fatal("unauthorized-domain response must set AA")
	}
	if flags&(1<<8) == 0 {
		t.Fatal("unauthorized-domain response must preserve RD")
	}
	if got := binary.BigEndian.Uint16(response[4:6]); got != 1 {
		t.Fatalf("unexpected qdcount: got=%d want=1", got)
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 0 {
		t.Fatalf("unexpected ancount: got=%d want=0", got)
	}
}

func TestHandlePacketRejectsMatcherFormatErrorAsFORMERR(t *testing.T) {
	server := &Server{
		domainMatcher: domainMatcher.New([]string{"vpn.example.com"}, 3),
	}
	request := buildTestDNSQuery(0x5151, ".", Enums.DNS_RECORD_TYPE_TXT)

	response := server.handlePacket(request, "")
	if response == nil {
		t.Fatal("expected DNS response, got nil")
	}

	flags := binary.BigEndian.Uint16(response[2:4])
	if got := flags & 0x000F; got != Enums.DNSR_CODE_FORMAT_ERROR {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, Enums.DNSR_CODE_FORMAT_ERROR)
	}
}

func TestHandlePacketKeepsUnsupportedAllowedAQueryAsNoData(t *testing.T) {
	server := &Server{
		domainMatcher: domainMatcher.New([]string{"vpn.example.com"}, 3),
	}
	request := buildTestDNSQuery(0x6161, "probe.vpn.example.com", Enums.DNS_RECORD_TYPE_A)

	response := server.handlePacket(request, "")
	if response == nil {
		t.Fatal("expected DNS response, got nil")
	}

	flags := binary.BigEndian.Uint16(response[2:4])
	if got := flags & 0x000F; got != Enums.DNSR_CODE_NO_ERROR {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, Enums.DNSR_CODE_NO_ERROR)
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 0 {
		t.Fatalf("unexpected ancount: got=%d want=0", got)
	}
}

// With the switch on (the default), a non-TXT query below the tunnel domain is
// NXDOMAIN, so a QNAME-minimising resolver stops walking the tunnel labels.
// The domain itself, and TXT queries, are never NXDOMAIN.
func TestHandlePacketNXDOMAINBelowTunnelDomain(t *testing.T) {
	server := &Server{
		domainMatcher:       domainMatcher.New([]string{"vpn.example.com"}, 3),
		nxdomainBelowTunnel: true,
	}
	cases := []struct {
		name  string
		qtype uint16
		rcode uint8
	}{
		{"probe.vpn.example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSR_CODE_NAME_ERROR},
		{"_.vpn.example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSR_CODE_NAME_ERROR},
		{"a.b.vpn.example.com", Enums.DNS_RECORD_TYPE_NS, Enums.DNSR_CODE_NAME_ERROR},
		{"vpn.example.com", Enums.DNS_RECORD_TYPE_A, Enums.DNSR_CODE_NO_ERROR},
		{"vpn.example.com", Enums.DNS_RECORD_TYPE_NS, Enums.DNSR_CODE_NO_ERROR},
		{"vpn.example.com", Enums.DNS_RECORD_TYPE_TXT, Enums.DNSR_CODE_NO_ERROR},
		{"ab.vpn.example.com", Enums.DNS_RECORD_TYPE_TXT, Enums.DNSR_CODE_NO_ERROR},
	}
	for _, c := range cases {
		response := server.handlePacket(buildTestDNSQuery(0x7171, c.name, c.qtype), "")
		if response == nil {
			t.Fatalf("%s/%d: no response", c.name, c.qtype)
		}
		flags := binary.BigEndian.Uint16(response[2:4])
		if got := uint8(flags & 0x000F); got != c.rcode {
			t.Fatalf("%s/%d: rcode=%d want=%d", c.name, c.qtype, got, c.rcode)
		}
		if flags&(1<<10) == 0 || flags&(1<<7) != 0 {
			t.Fatalf("%s/%d: want AA set and RA clear, flags=%#04x", c.name, c.qtype, flags)
		}
		if got := binary.BigEndian.Uint16(response[6:8]) + binary.BigEndian.Uint16(response[8:10]); got != 0 {
			t.Fatalf("%s/%d: want no answer or authority records, got %d", c.name, c.qtype, got)
		}
	}
}

func TestHandlePacketNoDataIsAuthoritative(t *testing.T) {
	server := &Server{
		domainMatcher: domainMatcher.New([]string{"vpn.example.com"}, 3),
	}
	response := server.handlePacket(buildTestDNSQuery(0x6262, "probe.vpn.example.com", Enums.DNS_RECORD_TYPE_A), "")
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&(1<<10) == 0 || flags&(1<<7) != 0 {
		t.Fatalf("want AA set and RA clear, flags=%#04x", flags)
	}
}

func buildTestDNSQuery(id uint16, name string, qtype uint16) []byte {
	qname := encodeTestDNSName(name)
	packet := make([]byte, 12+len(qname)+4)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)

	offset := 12
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qtype)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	return packet
}

func encodeTestDNSName(name string) []byte {
	if name == "." || name == "" {
		return []byte{0}
	}

	encoded := make([]byte, 0, len(name)+2)
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' {
			continue
		}

		labelLen := i - labelStart
		encoded = append(encoded, byte(labelLen))
		encoded = append(encoded, name[labelStart:i]...)
		labelStart = i + 1
	}
	return append(encoded, 0)
}
