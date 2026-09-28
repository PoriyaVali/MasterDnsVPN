// Package sessioncrypto is session protocol v2: every packet of a session is
// encrypted and authenticated under keys that belong to that session alone.
//
// Why it exists. A node has one transport key and every subscriber holds it
// (it is in their subscription link). Under protocol v1 that key was the only
// protection a session had, and three things followed from it:
//
//   - Server -> client traffic was not encrypted at all: responses carried the
//     raw frame, so the payload - and every name the user resolved through the
//     tunnel - crossed the network in clear.
//   - A session was identified by an 8-bit ID and an 8-bit cookie. Anyone with
//     the node key (any subscriber) could guess both in at most 65536 tries and
//     then close the session, inject into it, or answer its queries and so
//     receive its downstream data.
//   - Method 2 (ChaCha20) has no authenticator, so a frame could be altered in
//     flight without detection.
//
// v2 keys each session from the subscriber's own identity, which other
// subscribers do not have:
//
//	userKey  = HMAC-SHA256(nodeSecret, "mdns/v2/user\x00" || uuid)
//	keys     = HKDF-SHA256(userKey, salt = signature || device, "mdns/v2/session")
//
// and seals both directions with ChaCha20-Poly1305. SESSION_INIT carries a
// proof made with userKey, so knowing a user's 8-byte token (which crosses the
// wire, under the shared key) is not enough to open a session as them.
//
// Wire formats (bytes before the DNS-level encoding):
//
//	client -> server: r[8] | route[2] | AEAD(upKey, nonce=0^4||r, frame, ad=r||route)
//	server -> client: nonce[12] | AEAD(downKey, nonce, frame)
//
// route is {sessionID, marker} XOR a keystream derived from the node secret and
// r, so the server can find the session (and tell v2 from v1) before it knows
// which key to use, while every byte on the wire still looks random. A v1 frame
// that happens to show the marker (1 in 256) simply fails to open and is then
// read as v1.
package sessioncrypto

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Version is the byte a v2 SESSION_INIT carries after the user token.
	Version byte = 0x02

	DeviceLen = 8
	ProofLen  = 8

	// InitTailLen is what a v2 SESSION_INIT adds after signature and token:
	// version, device hash, proof.
	InitTailLen = 1 + DeviceLen + ProofLen

	upRandLen  = 8
	upRouteLen = 2
	upHeadLen  = upRandLen + upRouteLen

	// UpOverhead is what sealing adds to a client -> server frame.
	UpOverhead = upHeadLen + chacha20poly1305.Overhead
	// DownOverhead is what sealing adds to a server -> client frame.
	DownOverhead = chacha20poly1305.NonceSize + chacha20poly1305.Overhead

	// Smallest frame the tunnel protocol can produce (ID, type, cookie, check).
	minFrameLen = 4

	routeMarker byte = 0x5A
)

var ErrShortKey = errors.New("sessioncrypto: short key material")

// UserKey is the per-subscriber secret v2 is keyed from.
type UserKey [32]byte

// DeriveUserKey computes a subscriber's key. Both ends derive it; it never
// crosses the wire.
func DeriveUserKey(nodeSecret []byte, uuid string) UserKey {
	mac := hmac.New(sha256.New, nodeSecret)
	mac.Write([]byte("mdns/v2/user\x00"))
	mac.Write([]byte(uuid))
	var k UserKey
	copy(k[:], mac.Sum(nil))
	return k
}

// MaskKey hides the session route of an upstream frame from anyone without
// the node secret.
type MaskKey [32]byte

func DeriveMaskKey(nodeSecret []byte) MaskKey {
	h := sha256.New()
	h.Write([]byte("mdns/v2/mask\x00"))
	h.Write(nodeSecret)
	var k MaskKey
	copy(k[:], h.Sum(nil))
	return k
}

// DeviceHash turns a device identifier into the 8 bytes a SESSION_INIT
// carries. An empty identifier gives all zeros, which means "no device".
func DeviceHash(deviceID string) [DeviceLen]byte {
	var out [DeviceLen]byte
	if deviceID == "" {
		return out
	}
	sum := sha256.Sum256([]byte("mdns/v2/device\x00" + deviceID))
	copy(out[:], sum[:DeviceLen])
	if out == ([DeviceLen]byte{}) {
		out[0] = 1 // never collide with "no device"
	}
	return out
}

// DeviceAddr renders a device hash as a stable IPv6 address in fd6d:6473::/32
// (unique-local space), or "" for no device.
//
// It stands in for the client's address wherever the embedder counts devices.
// A DNS tunnel only ever sees recursive resolvers, not the phone - so an
// address-based count measured resolvers: one phone rotating through a public
// resolver's egress pool looked like many devices, and two phones behind one
// resolver looked like one. The panel keys devices by address string, so a
// device-derived address slots in with no change there.
func DeviceAddr(device [DeviceLen]byte) string {
	if device == ([DeviceLen]byte{}) {
		return ""
	}
	var a [16]byte
	a[0], a[1], a[2], a[3] = 0xfd, 0x6d, 0x64, 0x73
	copy(a[4:12], device[:])
	return netip.AddrFrom16(a).String()
}

// InitProof binds a v2 SESSION_INIT to the subscriber's key.
func InitProof(k UserKey, signature []byte, version byte, device [DeviceLen]byte) [ProofLen]byte {
	mac := hmac.New(sha256.New, k[:])
	mac.Write([]byte("mdns/v2/init\x00"))
	mac.Write(signature)
	mac.Write([]byte{version})
	mac.Write(device[:])
	var out [ProofLen]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func VerifyInitProof(k UserKey, signature []byte, version byte, device [DeviceLen]byte, proof []byte) bool {
	want := InitProof(k, signature, version, device)
	return len(proof) == ProofLen && hmac.Equal(want[:], proof)
}

// Keys are one session's two directional AEADs. Safe for concurrent use.
type Keys struct {
	up   cipher.AEAD
	down cipher.AEAD
}

// DeriveKeys computes a session's keys from the subscriber key and what the
// SESSION_INIT committed to. Deterministic: the client derives them before it
// sends the init, the server when it accepts it.
func DeriveKeys(k UserKey, signature []byte, device [DeviceLen]byte) (*Keys, error) {
	salt := make([]byte, 0, len(signature)+DeviceLen)
	salt = append(salt, signature...)
	salt = append(salt, device[:]...)
	okm, err := hkdf.Key(sha256.New, k[:], salt, "mdns/v2/session", 2*chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	if len(okm) < 2*chacha20poly1305.KeySize {
		return nil, ErrShortKey
	}
	up, err := chacha20poly1305.New(okm[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, err
	}
	down, err := chacha20poly1305.New(okm[chacha20poly1305.KeySize:])
	if err != nil {
		return nil, err
	}
	return &Keys{up: up, down: down}, nil
}

func routeMask(mask *MaskKey, r []byte) ([upRouteLen]byte, error) {
	var nonce [chacha20.NonceSize]byte
	copy(nonce[4:], r[:upRandLen])
	stream, err := chacha20.NewUnauthenticatedCipher(mask[:], nonce[:])
	if err != nil {
		return [upRouteLen]byte{}, err
	}
	var ks [upRouteLen]byte
	stream.XORKeyStream(ks[:], ks[:])
	return ks, nil
}

func upNonce(r []byte) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce[chacha20poly1305.NonceSize-upRandLen:], r[:upRandLen])
	return nonce
}

// SealUp seals a client -> server frame for session sessionID.
func (k *Keys) SealUp(mask *MaskKey, sessionID uint8, frame []byte) ([]byte, error) {
	if k == nil || mask == nil {
		return nil, errors.New("sessioncrypto: no keys")
	}
	out := make([]byte, upHeadLen, upHeadLen+len(frame)+chacha20poly1305.Overhead)
	if _, err := rand.Read(out[:upRandLen]); err != nil {
		return nil, fmt.Errorf("sessioncrypto: nonce: %w", err)
	}
	ks, err := routeMask(mask, out[:upRandLen])
	if err != nil {
		return nil, err
	}
	out[upRandLen] = sessionID ^ ks[0]
	out[upRandLen+1] = routeMarker ^ ks[1]
	return k.up.Seal(out, upNonce(out[:upRandLen]), frame, out[:upHeadLen]), nil
}

// PeekRoute reports the session a sealed upstream frame is addressed to, or
// ok=false when b is not shaped like one (it is then a v1 frame). A true
// answer is only a routing hint: nothing is trusted until OpenUp succeeds.
func PeekRoute(mask *MaskKey, b []byte) (sessionID uint8, ok bool) {
	if mask == nil || len(b) < UpOverhead+minFrameLen {
		return 0, false
	}
	ks, err := routeMask(mask, b[:upRandLen])
	if err != nil {
		return 0, false
	}
	if b[upRandLen+1]^ks[1] != routeMarker {
		return 0, false
	}
	return b[upRandLen] ^ ks[0], true
}

// OpenUp authenticates and decrypts a sealed upstream frame.
func (k *Keys) OpenUp(b []byte) ([]byte, bool) {
	if k == nil || len(b) < UpOverhead {
		return nil, false
	}
	frame, err := k.up.Open(nil, upNonce(b[:upRandLen]), b[upHeadLen:], b[:upHeadLen])
	if err != nil {
		return nil, false
	}
	return frame, true
}

// SealDown seals a server -> client frame.
func (k *Keys) SealDown(frame []byte) ([]byte, error) {
	if k == nil {
		return nil, errors.New("sessioncrypto: no keys")
	}
	out := make([]byte, chacha20poly1305.NonceSize, chacha20poly1305.NonceSize+len(frame)+chacha20poly1305.Overhead)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("sessioncrypto: nonce: %w", err)
	}
	return k.down.Seal(out, out[:chacha20poly1305.NonceSize], frame, nil), nil
}

// OpenDown authenticates and decrypts a sealed downstream frame.
func (k *Keys) OpenDown(b []byte) ([]byte, bool) {
	if k == nil || len(b) < DownOverhead {
		return nil, false
	}
	frame, err := k.down.Open(nil, b[:chacha20poly1305.NonceSize], b[chacha20poly1305.NonceSize:], nil)
	if err != nil {
		return nil, false
	}
	return frame, true
}
