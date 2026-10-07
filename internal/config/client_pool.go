// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// maxLoadBalancedServers bounds SERVERS. Every server costs its own MTU scan,
// sockets and workers, so a subscription with dozens of nodes must not turn
// into dozens of tunnels on a phone.
const maxLoadBalancedServers = 16

// poolSharedOnlyKeys are the keys a SERVERS entry cannot change: they describe
// the one local proxy every server is reached through, or the balancer
// itself. An entry that sets one is not an error - a config written by a newer
// app must still load - it is just not per-server.
var poolSharedOnlyKeys = map[string]struct{}{
	"PROTOCOL_TYPE":                          {},
	"LISTEN_IP":                              {},
	"LISTEN_PORT":                            {},
	"SOCKS5_AUTH":                            {},
	"SOCKS5_USER":                            {},
	"SOCKS5_PASS":                            {},
	"PROTECT_PATH":                           {},
	"BYPASS_DOMAINS_FILE":                    {},
	"BYPASS_DNS_SERVERS":                     {},
	"BYPASS_CIDRS_FILE":                      {},
	"LOCAL_DNS_ENABLED":                      {},
	"LOCAL_DNS_IP":                           {},
	"LOCAL_DNS_PORT":                         {},
	"LOCAL_DNS_CACHE_MAX_RECORDS":            {},
	"LOCAL_DNS_CACHE_TTL_SECONDS":            {},
	"LOCAL_DNS_PENDING_TIMEOUT_SECONDS":      {},
	"LOCAL_DNS_CACHE_PERSIST_TO_FILE":        {},
	"LOCAL_DNS_CACHE_FLUSH_INTERVAL_SECONDS": {},
	"LOG_LEVEL":                              {},
	"SERVERS":                                {},
	"LOAD_BALANCER_STRATEGY":                 {},
	"LOAD_BALANCER_STICKY":                   {},
	"LOAD_BALANCER_STICKY_SECONDS":           {},
}

// expandServerProfiles turns each SERVERS entry into a complete client config:
// the top level as written, with the entry's own keys on top, finalized and
// checked exactly like a single-server config.
func expandServerProfiles(base ClientConfig) ([]ClientConfig, error) {
	if len(base.Servers) > maxLoadBalancedServers {
		return nil, fmt.Errorf("SERVERS lists %d servers; at most %d can be load balanced", len(base.Servers), maxLoadBalancedServers)
	}

	profiles := make([]ClientConfig, 0, len(base.Servers))
	names := make(map[string]int, len(base.Servers))
	for i, entry := range base.Servers {
		member := base
		member.Servers = nil
		member.ServerProfiles = nil
		member.ServerName = ""
		member.ServerWeight = 0
		member.Domains = append([]string(nil), base.Domains...)
		member.ResolverList = append([]string(nil), base.ResolverList...)

		filtered := make(map[string]any, len(entry))
		for key, value := range entry {
			normalized := strings.ToUpper(strings.TrimSpace(key))
			if _, shared := poolSharedOnlyKeys[normalized]; shared {
				continue
			}
			filtered[normalized] = value
		}

		raw, err := json.Marshal(filtered)
		if err != nil {
			return nil, fmt.Errorf("SERVERS[%d]: %w", i, err)
		}
		defined, err := decodeConfigJSONInto(&member, raw)
		if err != nil {
			return nil, fmt.Errorf("SERVERS[%d]: %w", i, err)
		}
		if defined["RX_TX_Workers"] {
			member.explicitRX_TX_Workers = true
		}
		if defined["TunnelProcessWorkers"] {
			member.explicitTunnelProcessWorkers = true
		}

		member, err = finalizeClientConfigCommon(member, true)
		if err != nil {
			label := fmt.Sprintf("SERVERS[%d]", i)
			if name, ok := filtered["NAME"].(string); ok && strings.TrimSpace(name) != "" {
				label += " (" + strings.TrimSpace(name) + ")"
			}
			return nil, fmt.Errorf("%s: %w", label, err)
		}

		if member.ServerName == "" {
			member.ServerName = member.Domains[0]
		}
		// Names label log lines and the app's status; two servers must never
		// share one.
		if n := names[member.ServerName]; n > 0 {
			names[member.ServerName] = n + 1
			member.ServerName = fmt.Sprintf("%s#%d", member.ServerName, n+1)
		} else {
			names[member.ServerName] = 1
		}
		profiles = append(profiles, member)
	}
	return profiles, nil
}

// normalizeLoadBalancerStrategy maps LOAD_BALANCER_STRATEGY to one of the
// LoadBalancer* constants. An unknown value is read as least_load rather than
// refused, for the same reason unknown keys are ignored: a config written by a
// newer app must still start this core.
func normalizeLoadBalancerStrategy(raw string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", "_")) {
	case "round_robin", "roundrobin", "rr":
		return LoadBalancerRoundRobin
	case "random":
		return LoadBalancerRandom
	case "failover", "priority", "fallback":
		return LoadBalancerFailover
	default:
		return LoadBalancerLeastLoad
	}
}
