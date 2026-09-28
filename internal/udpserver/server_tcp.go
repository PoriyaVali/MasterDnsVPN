// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/dnstcp"
)

// DNS over TCP (RFC 7766) on the same address as UDP. Resolvers fall back to
// TCP when they are configured to, when a network drops UDP, or after a
// truncated answer; without a listener every such lookup failed. Queries go
// through the same request queue and workers as UDP, and a connection may
// pipeline them: answers are written as they are ready, which RFC 7766
// allows (clients match them by ID).
const (
	tcpIdleTimeout  = 30 * time.Second
	tcpWriteTimeout = 10 * time.Second
)

// startTCP listens on the UDP address over TCP. A port already taken for TCP
// is not fatal: the server keeps serving UDP, as it did before TCP existed.
func (s *Server) startTCP(ctx context.Context, reqCh chan<- request, wg *sync.WaitGroup) {
	if !s.cfg.TCPEnabled {
		return
	}
	address := net.JoinHostPort(s.cfg.UDPHost, strconv.Itoa(s.cfg.UDPPort))
	ln, err := net.Listen("tcp", address)
	if err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>TCP Listener Not Started, Addr: <cyan>%s</cyan>, Error: <cyan>%v</cyan>; serving UDP only</yellow>", address, err)
		return
	}
	s.log.Infof("\U0001F4E1 <green>TCP Listener Ready, Addr: <cyan>%s</cyan>, Max Connections: <cyan>%d</cyan></green>", address, s.cfg.TCPMaxConnections)

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.serveTCP(ctx, ln, reqCh, wg)
	}()
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener, reqCh chan<- request, wg *sync.WaitGroup) {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	defer ln.Close()

	slots := make(chan struct{}, max(1, s.cfg.TCPMaxConnections))
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Debugf("\U0001F4A5 <yellow>TCP Accept Error, <cyan>%v</cyan></yellow>", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			// Over the cap: the resolver retries, over UDP or later.
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			s.serveTCPConn(ctx, conn, reqCh)
		}()
	}
}

// tcpConnWriteBacklog is how many answers may wait for a slow reader before
// more are dropped. Workers never block on a TCP peer.
const tcpConnWriteBacklog = 128

func (s *Server) serveTCPConn(ctx context.Context, conn net.Conn, reqCh chan<- request) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer conn.Close()

	var addr *net.UDPAddr
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		addr = &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone}
	}

	writer := dnstcp.NewWriter(conn, tcpConnWriteBacklog, tcpWriteTimeout)
	var pending atomic.Int64
	// reply is called by a worker once per query, with an empty response
	// when there is nothing to send.
	reply := func(response []byte) {
		defer pending.Add(-1)
		if len(response) != 0 {
			writer.Send(response)
		}
	}

	s.readTCPQueries(ctx, conn, addr, reqCh, reply, &pending)

	// The peer is done sending (or went quiet): give queries already queued
	// a bounded time to be answered, then flush and close.
	deadline := time.Now().Add(tcpWriteTimeout)
	for pending.Load() > 0 && ctx.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	writer.Close()
}

func (s *Server) readTCPQueries(ctx context.Context, conn net.Conn, addr *net.UDPAddr, reqCh chan<- request, reply func([]byte), pending *atomic.Int64) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		buffer := s.packetPool.Get().([]byte)
		size, err := dnstcp.ReadMessage(conn, buffer)
		if err != nil {
			s.packetPool.Put(buffer)
			return
		}

		pending.Add(1)
		select {
		case reqCh <- request{buf: buffer, size: size, addr: addr, reply: reply}:
		case <-ctx.Done():
			pending.Add(-1)
			s.packetPool.Put(buffer)
			return
		default:
			pending.Add(-1)
			s.packetPool.Put(buffer)
			s.onDrop(addr, len(reqCh), cap(reqCh))
		}
	}
}
