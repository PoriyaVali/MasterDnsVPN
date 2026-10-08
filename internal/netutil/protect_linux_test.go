//go:build linux

package netutil

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// fakeProtector answers every protect request with ack.
func fakeProtector(t *testing.T, ack byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "protect.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			buf, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
			_, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
			if err == nil {
				if msgs, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
					for _, m := range msgs {
						if fds, err := syscall.ParseUnixRights(&m); err == nil {
							for _, fd := range fds {
								_ = syscall.Close(fd)
							}
						}
					}
				}
				_, _ = c.Write([]byte{ack})
			}
			_ = c.Close()
		}
	}()
	return path
}

func TestSendFDCountsRefusalsButKeepsTheSocket(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fd")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	before := ProtectRefusals()
	if err := SendFD(fakeProtector(t, 0), f.Fd()); err != nil {
		t.Fatalf("protected: %v", err)
	}
	if ProtectRefusals() != before {
		t.Fatal("a successful protect was counted as refused")
	}

	if err := SendFD(fakeProtector(t, protectAckRefused), f.Fd()); err != nil {
		t.Fatalf("a refused protect must not fail the socket: %v", err)
	}
	if ProtectRefusals() != before+1 {
		t.Fatal("a refused protect was not counted")
	}
}
