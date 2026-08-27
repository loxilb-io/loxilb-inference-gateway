/*
 * Copyright (c) 2025 LoxiLB Authors
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
package aikey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestPKI generates a throwaway CA and a client keypair signed by it,
// and returns their file paths. Real files, because the code under test reads
// files — a fixture that stubbed the reads would not exercise the code that
// actually runs in production.
func writeTestPKI(t *testing.T) (caFile, certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aikey-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "aigwuser"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign client cert: %v", err)
	}
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	caFile = filepath.Join(dir, "ca.crt")
	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")
	write := func(path, blockType string, der []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(caFile, "CERTIFICATE", caDER)
	write(certFile, "CERTIFICATE", clientDER)
	write(keyFile, "EC PRIVATE KEY", clientKeyDER)
	return caFile, certFile, keyFile
}

// U-15 — the connection config asked for over TLS carries a verified chain, a
// TLS 1.2 floor, a ServerName to verify against, and no plaintext fallback.
//
// Fallbacks is the load-bearing one: pgx derives a non-TLS fallback from
// sslmode, so leaving it in place means a server that refuses TLS gets a
// plaintext connection carrying the store password instead of an error.
func TestSecureConnConfigHasNoPlaintextFallback(t *testing.T) {
	caFile, certFile, keyFile := writeTestPKI(t)

	// sslmode=prefer is the pessimal case on purpose: it is the mode that
	// leaves a plaintext fallback behind.
	dsn := PostgresDSN("aigwuser", "p@ss", "db.example.internal", "5432", "loxilb", "prefer")

	cfg, err := secureConnConfig(dsn, caFile, certFile, keyFile)
	if err != nil {
		t.Fatalf("secureConnConfig: %v", err)
	}

	if cfg.Fallbacks != nil {
		t.Errorf("Fallbacks = %+v, want nil — a TLS connection must not be able to downgrade", cfg.Fallbacks)
	}
	if cfg.TLSConfig == nil {
		t.Fatal("TLSConfig is nil — the connection would not be encrypted at all")
	}
	if cfg.TLSConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want >= %#x (TLS 1.2)", cfg.TLSConfig.MinVersion, tls.VersionTLS12)
	}
	if cfg.TLSConfig.ServerName != "db.example.internal" {
		t.Errorf("ServerName = %q, want %q — without it every certificate fails verification",
			cfg.TLSConfig.ServerName, "db.example.internal")
	}
	if cfg.TLSConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set — the chain would not be verified")
	}
	if cfg.TLSConfig.RootCAs == nil {
		t.Error("RootCAs is nil — verification would fall back to the system pool")
	}
	if len(cfg.TLSConfig.Certificates) != 1 {
		t.Errorf("Certificates = %d, want 1 client keypair", len(cfg.TLSConfig.Certificates))
	}
}

// A CA file that exists but holds no certificate must be reported by name.
// AppendCertsFromPEM signals this only through its return value; ignoring it
// leaves an empty pool that fails every connection with an opaque error.
func TestSecureTLSConfigRejectsEmptyCAFile(t *testing.T) {
	_, certFile, keyFile := writeTestPKI(t)
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := secureTLSConfig("db.example.internal", empty, certFile, keyFile)
	if err == nil {
		t.Fatal("expected an error for a CA file containing no certificate")
	}
	if !strings.Contains(err.Error(), empty) {
		t.Errorf("error does not name the offending file: %v", err)
	}
}

// A missing certificate must return an error rather than terminate the
// process. The OAM original calls log.Fatalf here, which is defensible in a
// command's startup path and not in a long-running gateway: the data plane
// keeps serving cached keys while the store is unreachable.
func TestSecureTLSConfigMissingFilesReturnError(t *testing.T) {
	caFile, certFile, keyFile := writeTestPKI(t)
	missing := filepath.Join(t.TempDir(), "absent.pem")

	if _, err := secureTLSConfig("h", missing, certFile, keyFile); err == nil {
		t.Error("expected an error for a missing CA file")
	}
	if _, err := secureTLSConfig("h", caFile, missing, keyFile); err == nil {
		t.Error("expected an error for a missing client certificate")
	}
	if _, err := secureTLSConfig("h", caFile, certFile, missing); err == nil {
		t.Error("expected an error for a missing client key")
	}
}

// The store password is resolved from a file when one is named and from the
// environment otherwise, and its absence is an error rather than an empty
// password on the wire.
func TestResolvePassword(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Setenv(PasswordEnv, "env-secret")
	got, err := ResolvePassword(pwFile)
	if err != nil {
		t.Fatalf("ResolvePassword(file): %v", err)
	}
	// The file wins: it is the deployment-managed secret mount, and a stale
	// exported variable must not quietly override it.
	if got != "file-secret" {
		t.Errorf("password = %q, want %q (file must win over the environment)", got, "file-secret")
	}

	if got, err = ResolvePassword(""); err != nil || got != "env-secret" {
		t.Errorf("ResolvePassword(env) = %q, %v; want %q, nil", got, err, "env-secret")
	}

	os.Unsetenv(PasswordEnv)
	if _, err = ResolvePassword(""); err == nil {
		t.Error("expected an error when neither a password file nor the environment supplies one")
	}

	// A named-but-unreadable file is an error, never a fall-through to the
	// environment: a broken secret mount must not become a confusing
	// authentication failure against a stale password.
	t.Setenv(PasswordEnv, "env-secret")
	if _, err = ResolvePassword(filepath.Join(dir, "absent")); err == nil {
		t.Error("expected an error for an unreadable password file, not a fall-through to the environment")
	}
	empty := filepath.Join(dir, "empty")
	if err = os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err = ResolvePassword(empty); err == nil {
		t.Error("expected an error for an empty password file")
	}
}

// An interior space or tab is part of the password; only the trailing newline
// every `echo secret > file` leaves behind is stripped.
func TestResolvePasswordPreservesInteriorWhitespace(t *testing.T) {
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte("two words\there\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ResolvePassword(pwFile)
	if err != nil {
		t.Fatalf("ResolvePassword: %v", err)
	}
	if got != "two words\there" {
		t.Errorf("password = %q, want %q", got, "two words\there")
	}
}
