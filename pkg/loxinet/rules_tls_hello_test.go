/*
 * Copyright (c) 2026 LoxiLB Authors
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

package loxinet

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedTLSCert mints an ephemeral self-signed RSA cert for "localhost"/127.0.0.1
// so the tls-hello probe can be exercised against a real TLS handshake without
// any on-disk fixture. The chain is intentionally untrusted — tls-hello is handshake-only
// liveness, it must NOT validate the chain.
func selfSignedTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSListener spins up a real TLS listener on 127.0.0.1:0 that completes the
// handshake (any client) and immediately closes. Returns the bound port.
func startTLSListener(t *testing.T) uint16 {
	t.Helper()
	cert := selfSignedTLSCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Force the handshake to complete, then close.
			if tc, ok := c.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	return port
}

// startPlainTCPListener spins up a plain (non-TLS) TCP listener — a TLS handshake
// against it must FAIL (no ServerHello), so tls-hello marks it DOWN.
func startPlainTCPListener(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept the TCP connection but never speak TLS — handshake will hang/fail.
			go func(conn net.Conn) {
				buf := make([]byte, 1)
				conn.Read(buf) // drain a byte then drop; no ServerHello is ever sent.
				conn.Close()
			}(c)
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	return port
}

// TestTLSHelloProbeUpOnTLSPort: a tls-hello probe against a real TLS listener with a
// self-signed (untrusted) cert completes the handshake ⇒ UP. Chain is NOT validated.
func TestTLSHelloProbeUpOnTLSPort(t *testing.T) {
	port := startTLSListener(t)
	if !tlsHelloProbe(net.ParseIP("127.0.0.1"), port, "localhost") {
		t.Fatalf("tls-hello against a real TLS listener should be UP (handshake completes, self-signed accepted)")
	}
}

// TestTLSHelloProbeDownOnPlainPort: a tls-hello probe against a non-TLS port fails the
// handshake ⇒ DOWN.
func TestTLSHelloProbeDownOnPlainPort(t *testing.T) {
	port := startPlainTCPListener(t)
	if tlsHelloProbe(net.ParseIP("127.0.0.1"), port, "localhost") {
		t.Fatalf("tls-hello against a non-TLS port should be DOWN (handshake fails)")
	}
}

// TestTLSHelloProbeDownOnClosedPort: nothing listening ⇒ dial fails ⇒ DOWN.
func TestTLSHelloProbeDownOnClosedPort(t *testing.T) {
	// Pick a port that is almost certainly closed by binding+closing immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	if tlsHelloProbe(net.ParseIP("127.0.0.1"), port, "localhost") {
		t.Fatalf("tls-hello against a closed port should be DOWN")
	}
}

// TestHostProbeTLSHelloAllowed: the tls-hello probe type is accepted by the
// epHostOpts validation allowlist (no probe-port required, handshake-only liveness).
func TestHostProbeTLSHelloAllowed(t *testing.T) {
	if _, err := validateEPHostOpts("10.0.0.1", epHostOpts{probeType: HostProbeTLSHello}); err != nil {
		t.Fatalf("tls-hello must be an allowed probe type, got err: %v", err)
	}
	if HostProbeTLSHello != "tls-hello" {
		t.Fatalf("HostProbeTLSHello must equal %q, got %q", "tls-hello", HostProbeTLSHello)
	}
}
