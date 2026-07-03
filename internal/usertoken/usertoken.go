// ==============================================================================
// MasterDnsVPN — per-user handshake token
//
// Shared by the server (to authenticate) and the client (to present identity)
// so both derive the exact same value: HMAC-SHA256(node_secret, uuid)[:Len].
// The raw UUID never travels the wire; a leaked token can't be reversed.
// ==============================================================================

package usertoken

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Len is the number of token bytes carried in the SESSION_INIT handshake.
const Len = 8

// Token identifies a user to the node.
type Token [Len]byte

// Derive computes the handshake token for a UUID under a node secret.
func Derive(secret []byte, uuid string) Token {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(uuid))
	sum := mac.Sum(nil)
	var t Token
	copy(t[:], sum[:Len])
	return t
}
