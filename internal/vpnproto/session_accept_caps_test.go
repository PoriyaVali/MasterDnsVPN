package vpnproto

import "testing"

func TestSessionAcceptCapsRoundTrip(t *testing.T) {
	in := SessionAcceptPayload{
		SessionID:           3,
		SessionCookie:       9,
		HasClientPolicySync: true,
		ClientPolicy:        SessionAcceptClientPolicy{MaxUploadMTU: 150, MaxDownloadMTU: 900, MaxRxTxWorkers: 32},
		Caps:                SessionCapEarlyData,
	}
	raw := EncodeSessionAcceptPayload(in)
	if len(raw) != SessionAcceptWireSize {
		t.Fatalf("payload with caps is %d bytes, want %d", len(raw), SessionAcceptWireSize)
	}
	out, err := DecodeSessionAcceptPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Caps != SessionCapEarlyData || out.ClientPolicy.MaxDownloadMTU != 900 {
		t.Fatalf("decoded %+v", out)
	}
}

func TestSessionAcceptWithoutCapsIsUnchanged(t *testing.T) {
	// No capabilities: byte for byte what a node sent before they existed,
	// so a client that predates them reads exactly the same thing.
	raw := EncodeSessionAcceptPayload(SessionAcceptPayload{HasClientPolicySync: true})
	if len(raw) != SessionAcceptPayloadSize {
		t.Fatalf("payload without caps is %d bytes, want %d", len(raw), SessionAcceptPayloadSize)
	}
	out, err := DecodeSessionAcceptPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Caps != 0 {
		t.Fatalf("an old node's accept read as caps %#x", out.Caps)
	}
}
