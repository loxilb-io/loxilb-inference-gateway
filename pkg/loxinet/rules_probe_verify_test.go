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
	"crypto/x509"
	"encoding/pem"
	"net"
	ghttp "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// newUntrustedTLSServer returns an httptest TLS server (self-signed, untrusted by the
// system pool) that answers 200 on any path, plus its host IP and port parsed out.
func newUntrustedTLSServer(t *testing.T) (*httptest.Server, string, uint16) {
	t.Helper()
	srv := httptest.NewTLSServer(ghttp.HandlerFunc(func(w ghttp.ResponseWriter, r *ghttp.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	p, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	return srv, u.Hostname(), uint16(p)
}

// probeRuleH builds a minimal RuleH carrying an EMPTY root CA pool — so a self-signed
// httptest cert is untrusted by default (verify-on must fail).
func probeRuleH() *RuleH {
	return &RuleH{rootCAPool: x509.NewCertPool()}
}

// TestProbeVerifyOnRejectsUntrusted: with probeVerify=true (the default contract) an
// untrusted self-signed server fails the verify ⇒ DOWN. This is the today behaviour
// (verification ON by default).
func TestProbeVerifyOnRejectsUntrusted(t *testing.T) {
	_, host, port := newUntrustedTLSServer(t)
	R := probeRuleH()
	opts := epHostOpts{
		probePort:     port,
		domainName:    host,
		expectedCodes: "200",
		probeVerify:   true, // verify ON (the resolved default)
	}
	if R.httpsContentProbe(net.ParseIP(host), opts) {
		t.Fatalf("verify-on against an untrusted self-signed server should FAIL (cert not in pool)")
	}
}

// TestProbeVerifyOffAcceptsUntrusted: probe_verify=false ⇒ InsecureSkipVerify ⇒ the
// untrusted self-signed server is accepted (UP). This is the explicit operator opt-out
// (mitigation: a conscious choice, never the default).
func TestProbeVerifyOffAcceptsUntrusted(t *testing.T) {
	_, host, port := newUntrustedTLSServer(t)
	R := probeRuleH()
	opts := epHostOpts{
		probePort:     port,
		domainName:    host,
		expectedCodes: "200",
		probeVerify:   false, // explicit verify-off
	}
	if !R.httpsContentProbe(net.ParseIP(host), opts) {
		t.Fatalf("verify-off (InsecureSkipVerify) against the self-signed server should be UP")
	}
}

// TestProbeCAPathOverride: a probe_ca_path pointing at the server's own CA makes
// verify-on succeed without InsecureSkipVerify (per-probe CA bundle override).
func TestProbeCAPathOverride(t *testing.T) {
	srv, host, port := newUntrustedTLSServer(t)

	// Write the server's CA (its own self-signed cert) to a temp PEM file.
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	dir := t.TempDir()
	caFile := filepath.Join(dir, "probe-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}

	R := probeRuleH()
	opts := epHostOpts{
		probePort:     port,
		domainName:    host,
		expectedCodes: "200",
		probeVerify:   true, // verify ON, but trust the overridden CA
		probeCAPath:   caFile,
	}
	if !R.httpsContentProbe(net.ParseIP(host), opts) {
		t.Fatalf("probe_ca_path override should make verify-on succeed against the server's own CA")
	}
}
