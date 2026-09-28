// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

// Package dnstcp carries DNS messages over TCP (RFC 7766): each message is
// preceded by its length as two big-endian bytes.
package dnstcp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// ErrMessageSize is a message that is empty or does not fit a length prefix.
var ErrMessageSize = errors.New("dns tcp message size out of range")

// Frame returns msg with its length prefix.
func Frame(msg []byte) ([]byte, error) {
	if len(msg) == 0 || len(msg) > 0xFFFF {
		return nil, ErrMessageSize
	}
	framed := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(framed, uint16(len(msg)))
	copy(framed[2:], msg)
	return framed, nil
}

// ReadMessage reads one message into buf and returns its length. A message
// longer than buf, or of length zero, is an error.
func ReadMessage(r io.Reader, buf []byte) (int, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 || n > len(buf) {
		return 0, ErrMessageSize
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

// Exchange sends query on a new TCP connection to address and returns the
// answer, which must carry the query's ID.
func Exchange(dialer *net.Dialer, address string, query []byte, timeout time.Duration) ([]byte, error) {
	framed, err := Frame(query)
	if err != nil || len(query) < 2 {
		return nil, ErrMessageSize
	}
	d := net.Dialer{Timeout: timeout}
	if dialer != nil {
		d = *dialer
		d.Timeout = timeout
	}
	conn, err := d.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	answer := make([]byte, 0xFFFF)
	n, err := ReadMessage(conn, answer)
	if err != nil {
		return nil, err
	}
	if n < 12 || answer[0] != query[0] || answer[1] != query[1] {
		return nil, errors.New("dns tcp answer does not match the query")
	}
	return answer[:n:n], nil
}

// Writer writes answers to one connection from its own goroutine, so whoever
// produces an answer never waits on a slow or stalled peer. Answers are
// written in the order they are sent; a full backlog drops them.
type Writer struct {
	conn     net.Conn
	timeout  time.Duration
	out      chan []byte
	closing  chan struct{}
	finished chan struct{}
}

// NewWriter starts the writer for conn. Each write gets timeout; a failed
// write closes conn.
func NewWriter(conn net.Conn, backlog int, timeout time.Duration) *Writer {
	w := &Writer{
		conn:     conn,
		timeout:  timeout,
		out:      make(chan []byte, max(1, backlog)),
		closing:  make(chan struct{}),
		finished: make(chan struct{}),
	}
	go w.run()
	return w
}

// Send queues msg; false if it was dropped (bad size, backlog full, or the
// writer is closing). It never blocks and is safe after Close.
func (w *Writer) Send(msg []byte) bool {
	framed, err := Frame(msg)
	if err != nil {
		return false
	}
	select {
	case <-w.closing:
		return false
	default:
	}
	select {
	case w.out <- framed:
		return true
	default:
		return false
	}
}

// Close writes what is already queued, then stops. It does not close conn.
func (w *Writer) Close() {
	select {
	case <-w.closing:
	default:
		close(w.closing)
	}
	<-w.finished
}

func (w *Writer) run() {
	defer close(w.finished)
	write := func(framed []byte) bool {
		_ = w.conn.SetWriteDeadline(time.Now().Add(w.timeout))
		if _, err := w.conn.Write(framed); err != nil {
			_ = w.conn.Close()
			return false
		}
		return true
	}
	for {
		select {
		case framed := <-w.out:
			if !write(framed) {
				return
			}
		case <-w.closing:
			for {
				select {
				case framed := <-w.out:
					if !write(framed) {
						return
					}
				default:
					return
				}
			}
		}
	}
}
