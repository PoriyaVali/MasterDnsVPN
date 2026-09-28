package config

import (
	"os"
	"path/filepath"
	"testing"
)

// An unknown SESSION_V2 value must not stop the core from starting: a config
// written by a newer launcher still has to load here.
func TestSessionV2ModeNormalises(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("8.8.8.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{"": "auto", "auto": "auto", "ON": "on", " off ": "off", "maybe": "auto"} {
		cfg := defaultClientConfig()
		cfg.ConfigDir = dir
		cfg.Domains = []string{"v.example.com"}
		cfg.EncryptionKey = "k"
		cfg.SessionV2 = in
		cfg.DeviceID = "  phone  "
		got, err := finalizeClientConfig(cfg)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got.SessionV2 != want || got.DeviceID != "phone" {
			t.Fatalf("%q -> %q (device %q), want %q", in, got.SessionV2, got.DeviceID, want)
		}
	}
}
