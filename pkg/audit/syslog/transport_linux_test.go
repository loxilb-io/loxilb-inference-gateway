//go:build linux

/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package syslog

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timeout waiting for %s", what)
}

func sinkFor(t *testing.T, addr string, caPEM []byte) *Sink {
	t.Helper()
	trusted := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(trusted, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Address: addr, CABundlePath: trusted, ServerName: "localhost", Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// What a receiver has taken is acknowledged, and nothing is left to call
// unconfirmed.
func TestUnconfirmedIsNothingOnceTheReceiverHasAcknowledged(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	srv, addr, _ := tlsReceiver(t, serverCert(t, caCert, caKey))
	defer srv.Close()
	s := sinkFor(t, addr, caPEM)
	if n, ok := s.Unconfirmed(); n != 0 || ok {
		t.Fatalf("before any session: %d unconfirmed, known %v; want nothing known", n, ok)
	}
	for i := 0; i < 5; i++ {
		if err := s.Submit([]byte(sampleRecord)); err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	eventually(t, "the five frames to be acknowledged", func() bool {
		n, ok := s.Unconfirmed()
		return ok && n == 0
	})
}

// stalledReceiver completes the TLS handshake and then takes nothing until
// it is released. Its receive buffer is small, so what a sender writes
// beyond it stays unacknowledged in the sender's socket: the writes
// succeed and the bytes have gone nowhere.
func stalledReceiver(t *testing.T, cert tls.Certificate) (addr string, release func()) {
	addr, release, _ = stalledReceiverWithReset(t, cert)
	return addr, release
}

// stalledReceiverWithReset is stalledReceiver with a way to end the
// session from the receiver's side with what it was sent unread, which
// the sender sees as a reset.
func stalledReceiverWithReset(t *testing.T, cert tls.Certificate) (addr string, release, reset func()) {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
		})
	}}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		accepted <- c
		<-gate
		_, _ = io.Copy(io.Discard, tc)
	}()
	t.Cleanup(func() { ln.Close() })
	reset = func() {
		select {
		case c := <-accepted:
			_ = c.Close()
		case <-time.After(5 * time.Second):
			t.Error("the receiver never had a session to reset")
		}
	}
	return ln.Addr().String(), func() { close(gate) }, reset
}

// A write that returned without error is not a frame the receiver has.
// The frames a stalled receiver has not acknowledged are counted, the
// count is the end of what was submitted, and it goes when the receiver
// takes them.
func TestUnconfirmedCountsWhatTheReceiverHasNotAcknowledged(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	addr, release := stalledReceiver(t, serverCert(t, caCert, caKey))
	defer release()
	s := sinkFor(t, addr, caPEM)

	const frames = 600
	for i := 0; i < frames; i++ {
		if err := s.Submit([]byte(sampleRecord)); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	// Wait for actual partial acknowledgement before accepting a stable
	// count. Two equal samples can occur before Linux sends a delayed ACK,
	// while every submitted frame is still unconfirmed.
	var held int
	eventually(t, "the count to settle", func() bool {
		n, ok := s.Unconfirmed()
		if !ok {
			t.Fatal("the transport cannot be asked on this platform")
		}
		settled := n == held
		held = n
		return settled && n > 0 && n < frames
	})
	if held >= frames {
		t.Fatalf("%d of %d frames unconfirmed: the receiver's buffer took none", held, frames)
	}
	if st := s.Stats(); st.Submitted != frames {
		t.Fatalf("%d submitted, want %d: every write returned without error", st.Submitted, frames)
	}

	// A session that ends keeps what it left, for the caller that asks
	// why it ended.
	s.Close()
	if n, ok := s.Unconfirmed(); !ok || n != held {
		t.Fatalf("after the session ended: %d unconfirmed (known %v), want the %d it left", n, ok, held)
	}
}

func TestUnconfirmedGoesWhenAStalledReceiverTakesTheFrames(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	addr, release := stalledReceiver(t, serverCert(t, caCert, caKey))
	s := sinkFor(t, addr, caPEM)
	for i := 0; i < 600; i++ {
		if err := s.Submit([]byte(sampleRecord)); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	if n, _ := s.Unconfirmed(); n == 0 {
		t.Fatal("nothing unconfirmed with the receiver stalled")
	}
	release()
	eventually(t, "the frames to be acknowledged", func() bool {
		n, ok := s.Unconfirmed()
		return ok && n == 0
	})
}

// A receiver that closed takes nothing more, and the first write into the
// closed session would still succeed. The submission is refused before
// anything is written.
func TestSubmitIsNotWrittenIntoASessionTheReceiverClosed(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	srv, addr, _ := tlsReceiver(t, serverCert(t, caCert, caKey))
	s := sinkFor(t, addr, caPEM)
	if err := s.Submit([]byte(sampleRecord)); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	srv.Close()
	eventually(t, "the receiver's close to arrive", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, closed, _ := transportState(s.raw.Conn)
		return closed
	})
	err := s.Submit([]byte(sampleRecord))
	if !errors.Is(err, ErrNotAttempted) || !errors.Is(err, ErrPeerClosed) {
		t.Fatalf("submit into a closed session: %v, want nothing attempted because the receiver closed", err)
	}
	if st := s.Stats(); st.Submitted != 1 || st.Connected {
		t.Fatalf("stats %+v, want one submission and no session", st)
	}
}

// A sink with nothing to send learns that the receiver closed by asking.
// It is told once, and the session is ended by the answer.
func TestBrokenSaysOnceThatTheReceiverClosed(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	srv, addr, _ := tlsReceiver(t, serverCert(t, caCert, caKey))
	s := sinkFor(t, addr, caPEM)
	if s.Broken() {
		t.Fatal("broken before any session")
	}
	if err := s.Submit([]byte(sampleRecord)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if s.Broken() {
		t.Fatal("broken with the receiver up")
	}
	srv.Close()
	eventually(t, "the sink to find the session closed", s.Broken)
	if s.Broken() {
		t.Fatal("the same session was reported twice")
	}
	if st := s.Stats(); st.Connected {
		t.Fatalf("still connected after the receiver closed: %+v", st)
	}
}

// A session the receiver resets is gone with everything it had not
// acknowledged, and the count of that is what the session leaves: the
// socket's failure must not read as the acknowledgement of what was in it.
func TestUnconfirmedIsKeptWhenTheSessionIsReset(t *testing.T) {
	caCert, caKey, caPEM := genCAFull(t)
	addr, release, reset := stalledReceiverWithReset(t, serverCert(t, caCert, caKey))
	defer release()
	s := sinkFor(t, addr, caPEM)
	const frames = 600
	for i := 0; i < frames; i++ {
		if err := s.Submit([]byte(sampleRecord)); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	var held int
	eventually(t, "the count to settle", func() bool {
		n, _ := s.Unconfirmed()
		settled := n == held
		held = n
		return settled && n > 0
	})
	reset()
	eventually(t, "the sink to find the session gone", s.Broken)
	n, ok := s.Unconfirmed()
	if !ok || n == 0 || n > held {
		t.Fatalf("after the reset: %d unconfirmed (known %v), want what the session left, at most %d and not none", n, ok, held)
	}
}
