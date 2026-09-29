package sessioncrypto

import (
	"bytes"
	"testing"
)

func TestSealDownToReusesTheBuffer(t *testing.T) {
	uk := DeriveUserKey([]byte("secret"), "uuid")
	var dev [DeviceLen]byte
	keys, err := DeriveKeys(uk, []byte("0123456789"), dev)
	if err != nil {
		t.Fatal(err)
	}
	frame := bytes.Repeat([]byte("frame"), 100)
	buf := make([]byte, 0, 2048)
	sealed, err := keys.SealDownTo(buf, frame)
	if err != nil {
		t.Fatal(err)
	}
	if &sealed[0] != &buf[:1][0] {
		t.Fatal("a large enough buffer was not reused")
	}
	opened, ok := keys.OpenDown(sealed)
	if !ok || !bytes.Equal(opened, frame) {
		t.Fatal("frame sealed into a reused buffer does not open")
	}
	if allocs := testing.AllocsPerRun(100, func() { _, _ = keys.SealDownTo(buf, frame) }); allocs != 0 {
		t.Fatalf("%.0f allocations sealing into a large enough buffer", allocs)
	}
	firstNonce := append([]byte(nil), sealed[:12]...)
	again, _ := keys.SealDownTo(buf, frame)
	if bytes.Equal(again[:12], firstNonce) {
		t.Fatal("two seals used the same nonce")
	}
}
