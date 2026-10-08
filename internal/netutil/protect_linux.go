//go:build linux

package netutil

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// Protecting a socket means asking the VPN app to keep it off the tunnel it is
// running. Without it the client's own packets to the resolvers are captured by
// the TUN the client is feeding, and the tunnel talks to itself.
//
// Android exposes this only to the app holding the VpnService, so the app
// listens on an abstract unix socket and we hand it the file descriptor. The
// exchange is one byte with the descriptor attached as SCM_RIGHTS, then one
// byte back once VpnService.protect() has been called - the reply matters,
// because the socket must not be used until the app has finished with it.
//
// The path is passed by the app; an empty one means nothing is listening and
// every function here does nothing, which is the case on any platform where the
// app relies on excluding itself from the tunnel instead.
const protectTimeout = 2 * time.Second

// protectAckRefused is the app's answer when VpnService.protect() failed.
const protectAckRefused = 1

// SendFD asks the listener at path to protect fd.
func SendFD(path string, fd uintptr) error {
	if path == "" {
		return nil
	}
	conn, err := net.DialTimeout("unix", path, protectTimeout)
	if err != nil {
		return fmt.Errorf("protect: dial %s: %w", path, err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("protect: %s is not a unix socket", path)
	}
	_ = unixConn.SetDeadline(time.Now().Add(protectTimeout))

	rights := syscall.UnixRights(int(fd))
	if _, _, err := unixConn.WriteMsgUnix([]byte{1}, rights, nil); err != nil {
		return fmt.Errorf("protect: send descriptor: %w", err)
	}

	// Waiting for the acknowledgement is the point of the round trip: it is what
	// tells us the descriptor has actually been protected rather than merely
	// received.
	ack := make([]byte, 1)
	if _, err := unixConn.Read(ack); err != nil {
		return fmt.Errorf("protect: no acknowledgement: %w", err)
	}
	// ⚠️ The byte is the answer, not just a receipt: the app writes 0 when
	// VpnService.protect() succeeded and 1 when it did not, and this used to
	// read it and throw it away. A refusal is counted, not turned into an
	// error: the app also keeps its own uid - this process - off the tunnel,
	// and protect is its second line, so the socket still works. Failing it
	// would reject a resolver for a reason that has nothing to do with it.
	if ack[0] == protectAckRefused {
		protectRefusals.Add(1)
	}
	return nil
}

// Control returns a Control hook for net.Dialer and net.ListenConfig that
// protects the socket before it is bound or connected, which is the only moment
// the descriptor exists and no traffic has crossed it yet.
//
// A nil result when path is empty is deliberate: assigning it leaves the
// dialler exactly as it was.
func Control(path string) func(network, address string, c syscall.RawConn) error {
	if path == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var sendErr error
		if err := c.Control(func(fd uintptr) { sendErr = SendFD(path, fd) }); err != nil {
			return err
		}
		return sendErr
	}
}
