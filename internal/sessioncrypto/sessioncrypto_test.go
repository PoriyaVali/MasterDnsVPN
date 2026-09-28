package sessioncrypto

import (
	"bytes"
	"net/netip"
	"testing"
)

var (
	secret = []byte("node-secret-from-the-panel")
	sig    = []byte{0, 0x11, 0, 120, 1, 244, 9, 8, 7, 6}
)

func pair(t *testing.T, uuid string, device [DeviceLen]byte) (*Keys, *Keys) {
	t.Helper()
	client, err := DeriveKeys(DeriveUserKey(secret, uuid), sig, device)
	if err != nil {
		t.Fatal(err)
	}
	server, err := DeriveKeys(DeriveUserKey(secret, uuid), sig, device)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestRoundTripBothDirections(t *testing.T) {
	mask := DeriveMaskKey(secret)
	client, server := pair(t, "alice", DeviceHash("phone-1"))
	frame := []byte{7, 3, 0, 1, 0, 9, 0x42, 0x99, 'h', 'e', 'l', 'l', 'o'}

	up, err := client.SealUp(&mask, 7, frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(up) != len(frame)+UpOverhead {
		t.Fatalf("upstream overhead %d, want %d", len(up)-len(frame), UpOverhead)
	}
	sid, ok := PeekRoute(&mask, up)
	if !ok || sid != 7 {
		t.Fatalf("route: sid=%d ok=%v", sid, ok)
	}
	got, ok := server.OpenUp(up)
	if !ok || !bytes.Equal(got, frame) {
		t.Fatal("upstream did not round-trip")
	}

	down, err := server.SealDown(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(down) != len(frame)+DownOverhead {
		t.Fatalf("downstream overhead %d, want %d", len(down)-len(frame), DownOverhead)
	}
	if bytes.Contains(down, []byte("hello")) || bytes.Contains(up, []byte("hello")) {
		t.Fatal("plaintext visible on the wire")
	}
	got, ok = client.OpenDown(down)
	if !ok || !bytes.Equal(got, frame) {
		t.Fatal("downstream did not round-trip")
	}
}

// The property the whole design is for: another subscriber - who holds the
// node secret and the transport key, but not this user's UUID - can neither
// read nor forge this session's traffic.
func TestAnotherSubscriberCannotReadOrForge(t *testing.T) {
	mask := DeriveMaskKey(secret)
	victim, server := pair(t, "victim-uuid", DeviceHash("a"))
	attacker, _ := pair(t, "attacker-uuid", DeviceHash("a"))

	down, _ := server.SealDown([]byte("victim's downstream"))
	if _, ok := attacker.OpenDown(down); ok {
		t.Fatal("another user's key opened the victim's downstream")
	}
	forged, _ := attacker.SealUp(&mask, 7, []byte{7, 1, 0, 0})
	if _, ok := server.OpenUp(forged); ok {
		t.Fatal("a frame sealed with another user's key was accepted")
	}
	_ = victim
}

func TestTamperingIsDetected(t *testing.T) {
	mask := DeriveMaskKey(secret)
	client, server := pair(t, "alice", [DeviceLen]byte{})
	up, _ := client.SealUp(&mask, 3, []byte{3, 1, 5, 6, 7, 8})
	for i := range up {
		b := append([]byte(nil), up...)
		b[i] ^= 0x01
		if _, ok := server.OpenUp(b); ok {
			t.Fatalf("flipping byte %d went unnoticed", i)
		}
	}
	down, _ := server.SealDown([]byte{3, 1, 5, 6, 7, 8})
	for i := range down {
		b := append([]byte(nil), down...)
		b[i] ^= 0x80
		if _, ok := client.OpenDown(b); ok {
			t.Fatalf("flipping downstream byte %d went unnoticed", i)
		}
	}
}

func TestKeysAreBoundToSignatureAndDevice(t *testing.T) {
	k := DeriveUserKey(secret, "alice")
	a, _ := DeriveKeys(k, sig, DeviceHash("phone"))
	otherSig := append([]byte(nil), sig...)
	otherSig[9] ^= 1
	b, _ := DeriveKeys(k, otherSig, DeviceHash("phone"))
	c, _ := DeriveKeys(k, sig, DeviceHash("laptop"))
	down, _ := a.SealDown([]byte("x"))
	if _, ok := b.OpenDown(down); ok {
		t.Fatal("a different session signature derived the same keys")
	}
	if _, ok := c.OpenDown(down); ok {
		t.Fatal("a different device derived the same keys")
	}
}

func TestV1BytesAreNotMistakenForV2(t *testing.T) {
	mask := DeriveMaskKey(secret)
	_, server := pair(t, "alice", [DeviceLen]byte{})
	hits := 0
	for i := 0; i < 4096; i++ {
		b := make([]byte, 40)
		for j := range b {
			b[j] = byte(i*31 + j*7)
		}
		if _, ok := PeekRoute(&mask, b); ok {
			hits++
			if _, opened := server.OpenUp(b); opened {
				t.Fatal("random bytes opened as a v2 frame")
			}
		}
	}
	// About 1 in 256 random frames show the marker; all of them must then fail
	// to open, which is what sends them down the v1 path.
	if hits > 64 {
		t.Fatalf("marker matched %d/4096 random frames", hits)
	}
}

func TestInitProof(t *testing.T) {
	k := DeriveUserKey(secret, "alice")
	dev := DeviceHash("phone")
	proof := InitProof(k, sig, Version, dev)
	if !VerifyInitProof(k, sig, Version, dev, proof[:]) {
		t.Fatal("valid proof rejected")
	}
	if VerifyInitProof(DeriveUserKey(secret, "mallory"), sig, Version, dev, proof[:]) {
		t.Fatal("proof accepted under another user's key")
	}
	if VerifyInitProof(k, sig, Version, DeviceHash("other"), proof[:]) {
		t.Fatal("proof accepted for another device")
	}
}

func TestDeviceAddr(t *testing.T) {
	if DeviceAddr([DeviceLen]byte{}) != "" {
		t.Fatal("no device must map to no address")
	}
	a := DeviceAddr(DeviceHash("phone"))
	addr, err := netip.ParseAddr(a)
	if err != nil || !addr.Is6() || !addr.IsPrivate() {
		t.Fatalf("device address %q is not a unique-local IPv6", a)
	}
	if a != DeviceAddr(DeviceHash("phone")) || a == DeviceAddr(DeviceHash("laptop")) {
		t.Fatal("device address is not a stable function of the device")
	}
	if DeviceHash("") != ([DeviceLen]byte{}) {
		t.Fatal("empty device id must hash to no device")
	}
}
