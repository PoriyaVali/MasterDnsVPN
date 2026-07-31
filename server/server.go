// ==============================================================================
// MasterDnsVPN — public embeddable server (for V2bX / other Go hosts)
//
// internal/udpserver is an internal package and cannot be imported by other
// modules. This package is the stable, public surface: an embedder builds a
// node from Options, starts it, manages users, and reads per-user traffic.
// ==============================================================================

package server

import (
	"context"
	"errors"
	"sync"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	udp "masterdnsvpn-go/internal/udpserver"
)

// UserBytes is a per-user traffic sample (bytes since the last reset).
type UserBytes = udp.UserBytes

// Options is the minimal per-node configuration an embedder supplies. Every
// other tunnel parameter falls back to the library defaults.
type Options struct {
	Domains           []string // delegated DNS zone(s) — required
	UDPHost           string   // listen host ("" = all interfaces)
	UDPPort           int      // UDP listener port
	EncryptionMethod  int      // 0..5 (NONE/XOR/ChaCha20/AES-128/192/256-GCM)
	EncryptionKey     string   // node transport key (hex; length must match method)
	NodeSecret        string   // secret for per-user token derivation (from panel)
	LogLevel          string   // "error"/"warn"/"info"/"debug" ("" keeps default)
	UseExternalSOCKS5 bool     // route egress through an upstream SOCKS5
	ForwardIP         string   // upstream SOCKS5 host (when UseExternalSOCKS5)
	ForwardPort       int      // upstream SOCKS5 port
}

// Server is a running (or startable) MasterDnsVPN node.
type Server struct {
	inner *udp.Server
	log   *logger.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// New builds a node from opts but does not start it.
func New(opts Options) (*Server, error) {
	if len(opts.Domains) == 0 {
		return nil, errors.New("mdns server: at least one domain is required")
	}
	if opts.UDPPort <= 0 {
		return nil, errors.New("mdns server: UDPPort must be set")
	}

	cfg := config.DefaultServerConfig()
	cfg.Domain = opts.Domains
	cfg.UDPHost = opts.UDPHost
	cfg.UDPPort = opts.UDPPort
	cfg.DataEncryptionMethod = opts.EncryptionMethod
	cfg.NodeSecret = opts.NodeSecret
	cfg.UseExternalSOCKS5 = opts.UseExternalSOCKS5
	cfg.ForwardIP = opts.ForwardIP
	cfg.ForwardPort = opts.ForwardPort
	if opts.LogLevel != "" {
		cfg.LogLevel = opts.LogLevel
	}

	cfg, err := config.FinalizeServerConfig(cfg)
	if err != nil {
		return nil, err
	}
	codec, err := security.NewCodec(cfg.DataEncryptionMethod, opts.EncryptionKey)
	if err != nil {
		return nil, err
	}

	log := logger.New("mdns", cfg.LogLevel)
	return &Server{inner: udp.New(cfg, log, codec), log: log}, nil
}

// Start runs the node in the background. Returns immediately.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return errors.New("mdns server already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		_ = s.inner.Run(ctx)
	}()
	return nil
}

// Close stops the node and waits for it to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return nil
}

// AddUser registers a user by V2board UUID (idempotent).
func (s *Server) AddUser(uuid string) { s.inner.AddUser(uuid) }

// DelUser removes a user; its future sessions are rejected.
func (s *Server) DelUser(uuid string) { s.inner.DelUser(uuid) }

// UserCount is the number of registered users.
func (s *Server) UserCount() int { return s.inner.UserCount() }

// Traffic returns per-user byte counters, resetting them when reset is true.
func (s *Server) Traffic(reset bool) []UserBytes { return s.inner.Traffic(reset) }

// SetUserSpeedLimit paces a user to bytesPerSecond across both directions;
// zero or negative removes the limit. Unknown users are ignored, so a caller can
// push a whole panel list without checking membership first.
func (s *Server) SetUserSpeedLimit(uuid string, bytesPerSecond int64) {
	s.inner.SetUserSpeedLimit(uuid, bytesPerSecond)
}

// OnlineIPs reports the source addresses each user has recently been seen from,
// keyed by UUID, so a panel can count devices on this node. Users with no live
// address are omitted.
func (s *Server) OnlineIPs() map[string][]string { return s.inner.OnlineIPs() }
