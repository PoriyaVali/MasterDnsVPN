package dnstcp

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestFrameAndReadMessage(t *testing.T) {
	msg := bytes.Repeat([]byte{0xAB}, 300)
	framed, err := Frame(msg)
	if err != nil {
		t.Fatal(err)
	}
	if framed[0] != 0x01 || framed[1] != 0x2C {
		t.Fatalf("length prefix % x, want 01 2c", framed[:2])
	}
	buf := make([]byte, 512)
	n, err := ReadMessage(bytes.NewReader(framed), buf)
	if err != nil || n != 300 || !bytes.Equal(buf[:n], msg) {
		t.Fatalf("n=%d err=%v", n, err)
	}

	if _, err := ReadMessage(bytes.NewReader(framed), make([]byte, 100)); !errors.Is(err, ErrMessageSize) {
		t.Fatalf("a message larger than the buffer: err=%v", err)
	}
	if _, err := ReadMessage(bytes.NewReader([]byte{0, 0}), buf); !errors.Is(err, ErrMessageSize) {
		t.Fatalf("an empty message: err=%v", err)
	}
	if _, err := Frame(nil); err == nil {
		t.Fatal("framing an empty message must fail")
	}
	if _, err := Frame(make([]byte, 0x10000)); err == nil {
		t.Fatal("framing a message over 65535 bytes must fail")
	}
}

func TestWriterFlushesQueuedAnswersOnClose(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	w := NewWriter(server, 8, time.Second)

	got := make(chan []byte, 3)
	go func() {
		buf := make([]byte, 64)
		for i := 0; i < 3; i++ {
			n, err := ReadMessage(client, buf)
			if err != nil {
				return
			}
			got <- append([]byte(nil), buf[:n]...)
		}
	}()
	for _, m := range []string{"one", "two", "three"} {
		if !w.Send([]byte(m)) {
			t.Fatalf("%s dropped", m)
		}
	}
	w.Close()
	for _, want := range []string{"one", "two", "three"} {
		select {
		case m := <-got:
			if string(m) != want {
				t.Fatalf("got %q, want %q", m, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s never arrived", want)
		}
	}
	if w.Send([]byte("late")) {
		t.Fatal("Send after Close must report the drop")
	}
}

// A peer that never reads must not block whoever produces answers.
func TestWriterNeverBlocksTheSender(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	w := NewWriter(server, 2, 50*time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			w.Send([]byte("answer"))
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Send blocked on a peer that does not read")
	}
	w.Close()
}

func TestExchange(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 512)
		n, err := ReadMessage(conn, buf)
		if err != nil {
			return
		}
		answer := append(buf[:n:n], bytes.Repeat([]byte{7}, 20)...)
		answer[2] |= 0x80
		framed, _ := Frame(answer)
		_, _ = conn.Write(framed)
	}()

	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}
	answer, err := Exchange(nil, ln.Addr().String(), query, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer) != len(query)+20 || answer[0] != 0x12 || answer[1] != 0x34 {
		t.Fatalf("unexpected answer % x", answer)
	}
}
