package security

import "testing"

// A counter near 2^32 on the wire used to panic the process from inside the
// cipher. It must be rejected as bad ciphertext instead.
func TestChachaDecryptRejectsOverflowingCounter(t *testing.T) {
	c, err := NewCodec(2, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	crafted := make([]byte, chachaNonceSize+200)
	crafted[0], crafted[1], crafted[2], crafted[3] = 0xff, 0xff, 0xff, 0xff

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("one crafted packet panicked the decoder: %v", r)
		}
	}()
	if _, err := c.Decrypt(crafted); err != ErrInvalidCiphertext {
		t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
	}
	// Exactly at the edge is still valid: counter 2^32-4 with 4 blocks.
	edge := make([]byte, chachaNonceSize+256)
	edge[0], edge[1], edge[2], edge[3] = 0xfc, 0xff, 0xff, 0xff
	if _, err := c.Decrypt(edge); err != nil {
		t.Fatalf("a counter that just fits was refused: %v", err)
	}
}

// Every nonce this side generates leaves the counter room to spare.
func TestChachaEncryptNeverStartsNearTheCounterLimit(t *testing.T) {
	c, err := NewCodec(2, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4000)
	for i := 0; i < 2000; i++ {
		out, err := c.Encrypt(payload)
		if err != nil {
			t.Fatal(err)
		}
		if out[3]&0x80 != 0 {
			t.Fatalf("counter started at %x%x%x%x", out[3], out[2], out[1], out[0])
		}
		back, err := c.Decrypt(out)
		if err != nil || len(back) != len(payload) {
			t.Fatalf("round trip failed: %v", err)
		}
	}
}
