// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (tunnel_query.go) handles the construction of DNS tunnel queries.
// ==============================================================================
package client

import (
	baseCodec "masterdnsvpn-go/internal/basecodec"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type preparedTunnelDomain struct {
	normalized string
	qname      []byte
}

func buildTunnelTXTQuestionBytes(domain string, encoded []byte) ([]byte, error) {
	return DnsParser.BuildTunnelTXTQuestionPacket(domain, encoded, Enums.DNS_RECORD_TYPE_TXT, EDnsSafeUDPSize)
}

func prepareTunnelDomain(domain string) (preparedTunnelDomain, error) {
	normalized, qname, err := DnsParser.PrepareTunnelDomainQname(domain)
	if err != nil {
		return preparedTunnelDomain{}, err
	}
	return preparedTunnelDomain{normalized: normalized, qname: qname}, nil
}

// buildTunnelTXTQueryRaw builds an encoded tunnel query using the provided options and codec.
func (c *Client) buildTunnelTXTQueryRaw(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	raw, err := VpnProto.BuildRaw(options)
	if err != nil {
		return nil, err
	}
	encoded, err := c.encodeFrame(options.SessionID, options.PacketType, raw)
	if err != nil {
		return nil, err
	}
	return buildTunnelTXTQuestionBytes(domain, encoded)
}

func (c *Client) buildEncodedAutoWithCompressionTrace(options VpnProto.BuildOptions) ([]byte, error) {
	raw, err := VpnProto.BuildRawAuto(options, c.cfg.CompressionMinSize)
	if err != nil {
		return nil, err
	}
	return c.encodeFrame(options.SessionID, options.PacketType, raw)
}

// encodeFrame turns a raw frame into query-name bytes. A frame belonging to a
// v2 session is sealed under that session's keys; anything else - every frame
// of a v1 session, and the pre-session requests (MTU probes, SESSION_INIT),
// which have no session to be sealed for - goes under the node's shared codec
// as it always has.
func (c *Client) encodeFrame(sessionID uint8, packetType uint8, raw []byte) ([]byte, error) {
	if sessionID != 0 && !isPreSessionPacketType(packetType) {
		if keys := c.sessionKeys.Load(); keys != nil {
			sealed, err := keys.SealUp(&c.v2Mask, sessionID, raw)
			if err != nil {
				return nil, err
			}
			return baseCodec.EncodeToBytes(sealed), nil
		}
	}
	if c.codec == nil {
		return nil, VpnProto.ErrCodecUnavailable
	}
	return c.codec.EncryptAndEncodeBytes(raw)
}

func isPreSessionPacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_SESSION_INIT, Enums.PACKET_MTU_UP_REQ, Enums.PACKET_MTU_DOWN_REQ:
		return true
	default:
		return false
	}
}

// buildTunnelTXTQuery builds an encoded tunnel query with automatic option handling.
func (c *Client) buildTunnelTXTQuery(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	encoded, err := c.buildEncodedAutoWithCompressionTrace(options)
	if err != nil {
		return nil, err
	}
	return buildTunnelTXTQuestionBytes(domain, encoded)
}
