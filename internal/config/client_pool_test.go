package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePoolConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("8.8.8.8\n1.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "client_config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const poolTOML = `
DOMAINS = ["primary.example.com"]
ENCRYPTION_KEY = "shared-key"
DATA_ENCRYPTION_METHOD = 2
LISTEN_PORT = 18080
RX_TX_WORKERS = 6
LOAD_BALANCER_STRATEGY = "round-robin"
LOAD_BALANCER_STICKY_SECONDS = 120

[[SERVERS]]
NAME = "de-1"
DOMAINS = ["a.example.com"]
ENCRYPTION_KEY = "key-a"
UUID = "uuid-a"
NODE_SECRET = "secret-a"
WEIGHT = 3
LISTEN_PORT = 9999

[[SERVERS]]
DOMAINS = ["b.example.com", "b2.example.com"]
RESOLVERS = ["9.9.9.9", "149.112.112.112:5353"]
RX_TX_WORKERS = 12
WEIGHT = 1000
`

func TestLoadBalancedTOMLExpandsServers(t *testing.T) {
	cfg, err := LoadClientConfig(writePoolConfig(t, poolTOML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.IsLoadBalanced() || len(cfg.ServerProfiles) != 2 {
		t.Fatalf("want 2 server profiles, got %d", len(cfg.ServerProfiles))
	}
	if cfg.LoadBalancerStrategy != LoadBalancerRoundRobin {
		t.Fatalf("strategy = %q", cfg.LoadBalancerStrategy)
	}
	if !cfg.LoadBalancerSticky || cfg.LoadBalancerStickySeconds != 120 {
		t.Fatalf("sticky = %v / %v", cfg.LoadBalancerSticky, cfg.LoadBalancerStickySeconds)
	}

	a, b := cfg.ServerProfiles[0], cfg.ServerProfiles[1]

	if a.ServerName != "de-1" || a.EncryptionKey != "key-a" || a.Uuid != "uuid-a" || a.NodeSecret != "secret-a" {
		t.Fatalf("server a did not take its own values: %+v", a)
	}
	if a.ServerWeight != 3 {
		t.Fatalf("server a weight = %d", a.ServerWeight)
	}
	if strings.Join(a.Domains, ",") != "a.example.com" {
		t.Fatalf("server a domains = %v", a.Domains)
	}
	// Shared-only keys stay the top level's.
	if a.ListenPort != 18080 {
		t.Fatalf("a SERVERS entry changed LISTEN_PORT to %d", a.ListenPort)
	}
	// Inherited, and loaded from the shared resolver file.
	if a.DataEncryptionMethod != 2 || a.RX_TX_Workers != 6 || len(a.Resolvers) != 2 {
		t.Fatalf("server a did not inherit: enc=%d workers=%d resolvers=%d", a.DataEncryptionMethod, a.RX_TX_Workers, len(a.Resolvers))
	}

	if b.ServerName != "b2.example.com" { // domains are kept longest first
		t.Fatalf("server b default name = %q", b.ServerName)
	}
	if b.EncryptionKey != "shared-key" {
		t.Fatalf("server b did not inherit the key: %q", b.EncryptionKey)
	}
	if b.ServerWeight != 100 {
		t.Fatalf("server b weight not clamped: %d", b.ServerWeight)
	}
	if b.RX_TX_Workers != 12 {
		t.Fatalf("server b RX_TX_WORKERS = %d", b.RX_TX_Workers)
	}
	if len(b.Resolvers) != 2 || b.Resolvers[0].IP != "149.112.112.112" || b.Resolvers[0].Port != 5353 {
		t.Fatalf("server b inline resolvers = %+v", b.Resolvers)
	}
	for _, p := range cfg.ServerProfiles {
		if len(p.Servers) != 0 || len(p.ServerProfiles) != 0 {
			t.Fatal("a server profile carries SERVERS of its own")
		}
	}
}

func TestLoadBalancedJSONBase64ExpandsServers(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte("8.8.8.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := `{
		"ENCRYPTION_KEY": "k",
		"LOAD_BALANCER_STRATEGY": "failover",
		"LOAD_BALANCER_STICKY": false,
		"SERVERS": [
			{"NAME": "one", "DOMAINS": ["one.example.com"], "DATA_ENCRYPTION_METHOD": 3},
			{"NAME": "two", "DOMAINS": ["two.example.com"], "MAX_DOWNLOAD_MTU": 700}
		]
	}`
	cfg, err := LoadClientConfigFromJSONBase64(base64.StdEncoding.EncodeToString([]byte(raw)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.ServerProfiles) != 2 || cfg.LoadBalancerStrategy != LoadBalancerFailover || cfg.LoadBalancerSticky {
		t.Fatalf("pool settings: %d profiles, %q, sticky=%v", len(cfg.ServerProfiles), cfg.LoadBalancerStrategy, cfg.LoadBalancerSticky)
	}
	if cfg.ServerProfiles[0].DataEncryptionMethod != 3 || cfg.ServerProfiles[1].MaxDownloadMTU != 700 {
		t.Fatalf("per-server values lost: %+v", cfg.ServerProfiles)
	}
}

func TestLoadBalancedServerIsValidatedOnItsOwn(t *testing.T) {
	body := `
ENCRYPTION_KEY = "k"

[[SERVERS]]
NAME = "ok"
DOMAINS = ["ok.example.com"]

[[SERVERS]]
NAME = "broken"
`
	_, err := LoadClientConfig(writePoolConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "SERVERS[1] (broken)") || !strings.Contains(err.Error(), "DOMAINS") {
		t.Fatalf("want an error naming SERVERS[1] (broken) and DOMAINS, got %v", err)
	}
}

func TestLoadBalancedNamesAreUnique(t *testing.T) {
	body := `
ENCRYPTION_KEY = "k"
DOMAINS = ["same.example.com"]

[[SERVERS]]
ENCRYPTION_KEY = "k1"

[[SERVERS]]
ENCRYPTION_KEY = "k2"
`
	cfg, err := LoadClientConfig(writePoolConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerProfiles[0].ServerName == cfg.ServerProfiles[1].ServerName {
		t.Fatalf("two servers share the name %q", cfg.ServerProfiles[0].ServerName)
	}
}

func TestLoadBalancedServerCountIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("ENCRYPTION_KEY = \"k\"\nDOMAINS = [\"x.example.com\"]\n")
	for i := 0; i <= maxLoadBalancedServers; i++ {
		b.WriteString("[[SERVERS]]\n")
	}
	if _, err := LoadClientConfig(writePoolConfig(t, b.String())); err == nil {
		t.Fatal("more servers than the limit were accepted")
	}
}

func TestSingleServerConfigIsNotLoadBalanced(t *testing.T) {
	cfg, err := LoadClientConfig(writePoolConfig(t, "DOMAINS = [\"v.example.com\"]\nENCRYPTION_KEY = \"k\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IsLoadBalanced() {
		t.Fatal("a config without SERVERS is load balanced")
	}
	if cfg.LoadBalancerStrategy != LoadBalancerLeastLoad || !cfg.LoadBalancerSticky {
		t.Fatalf("defaults: %q sticky=%v", cfg.LoadBalancerStrategy, cfg.LoadBalancerSticky)
	}
}

func TestInlineResolversWinOverTheFile(t *testing.T) {
	body := "DOMAINS = [\"v.example.com\"]\nENCRYPTION_KEY = \"k\"\nRESOLVERS = [\"10.0.0.0/30\"]\n"
	cfg, err := LoadClientConfig(writePoolConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Resolvers) != 2 || cfg.Resolvers[0].IP != "10.0.0.1" {
		t.Fatalf("inline resolvers = %+v", cfg.Resolvers)
	}
}

func TestNormalizeLoadBalancerStrategy(t *testing.T) {
	cases := map[string]string{
		"":            LoadBalancerLeastLoad,
		"least-load":  LoadBalancerLeastLoad,
		"ROUND_ROBIN": LoadBalancerRoundRobin,
		"rr":          LoadBalancerRoundRobin,
		"random":      LoadBalancerRandom,
		"priority":    LoadBalancerFailover,
		"some-future": LoadBalancerLeastLoad,
	}
	for in, want := range cases {
		if got := normalizeLoadBalancerStrategy(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
