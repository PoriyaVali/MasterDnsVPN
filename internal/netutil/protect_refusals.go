package netutil

import "sync/atomic"

var protectRefusals atomic.Uint64

// ProtectRefusals is how many sockets the VPN app answered it could not
// protect (see SendFD). Zero where nothing protects sockets.
func ProtectRefusals() uint64 {
	return protectRefusals.Load()
}
