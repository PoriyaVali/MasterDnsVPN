//go:build !linux

package netutil

import "syscall"

// Protecting a socket is an Android/VpnService idea and has no counterpart on
// the desktop and router builds, where nothing is capturing our own traffic.
// Keeping the same names here means the call sites do not need build tags.

// SendFD does nothing off Linux.
func SendFD(path string, fd uintptr) error { return nil }

// Control returns nil off Linux, which leaves a dialler unchanged.
func Control(path string) func(network, address string, c syscall.RawConn) error {
	return nil
}
