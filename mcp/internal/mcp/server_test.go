/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 */

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/guard"
)

const testToken = "0123456789abcdef0123456789abcdef"

func testConfig(targetURL string) *Config {
	return &Config{
		DefaultTarget: "t1",
		Targets:       map[string]Target{"t1": {URL: targetURL}},
		Clients:       []ClientToken{{Name: "ci", Role: "admin", Token: testToken}},
	}
}

func newTestBridge(t *testing.T, cfg *Config) *Bridge {
	t.Helper()
	b, err := NewBridge(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// T2: plaintext bearer auth on a non-loopback bind must be refused.
func TestRunHTTPRefusesPlaintextNonLoopback(t *testing.T) {
	b := newTestBridge(t, testConfig("http://127.0.0.1:11111"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := b.RunHTTP(ctx, HTTPOptions{Listen: "0.0.0.0:0"})
	if err == nil || !strings.Contains(err.Error(), "refusing plaintext") {
		t.Fatalf("want plaintext refusal, got %v", err)
	}
	// Loopback names must be recognized.
	for _, l := range []string{"127.0.0.1:1", "localhost:1", "[::1]:1"} {
		if !listenIsLoopback(l) {
			t.Errorf("listenIsLoopback(%q) = false", l)
		}
	}
	for _, l := range []string{"0.0.0.0:1", ":1", "192.168.1.5:1"} {
		if listenIsLoopback(l) {
			t.Errorf("listenIsLoopback(%q) = true", l)
		}
	}
}

// HTTP mode without any client tokens must refuse to serve.
func TestHTTPHandlerRequiresClientTokens(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:11111")
	cfg.Clients = nil
	b := newTestBridge(t, cfg)
	if _, err := b.HTTPHandler(); err == nil {
		t.Fatal("handler built without client tokens")
	}
}

func initializeBody(t *testing.T) *strings.Reader {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReader(string(body))
}

func doInitialize(t *testing.T, url string, mutate func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, initializeBody(t))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if mutate != nil {
		mutate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// T1/T3/T9: auth required, wrong token rejected, cross-origin rejected,
// valid token + non-browser request accepted.
func TestHTTPAuthAndOrigin(t *testing.T) {
	b := newTestBridge(t, testConfig("http://127.0.0.1:11111"))
	h, err := b.HTTPHandler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	if resp := doInitialize(t, srv.URL, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", resp.StatusCode)
	}
	if resp := doInitialize(t, srv.URL, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer wrong-token-wrong-token-wrong-tok")
	}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d, want 401", resp.StatusCode)
	}
	if resp := doInitialize(t, srv.URL, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+testToken)
		r.Header.Set("Origin", "http://evil.example")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin: got %d, want 403", resp.StatusCode)
	}
	if resp := doInitialize(t, srv.URL, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+testToken)
	}); resp.StatusCode != http.StatusOK {
		t.Errorf("valid: got %d, want 200", resp.StatusCode)
	}
}

// T7: model-supplied target names resolve only against the config.
func TestResolveRejectsUnknownAndURLTargets(t *testing.T) {
	b := newTestBridge(t, testConfig("http://127.0.0.1:11111"))
	if _, err := b.resolve(""); err != nil {
		t.Errorf("default target: %v", err)
	}
	for _, bad := range []string{"http://169.254.169.254", "unknown", "t2"} {
		if _, err := b.resolve(bad); err == nil {
			t.Errorf("resolve(%q) succeeded, want error", bad)
		}
	}
}

// T8: per-client token bucket limits request rate.
func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(1, 3)
	allowed := 0
	for range 10 {
		if rl.allow("c") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("burst: allowed %d, want 3", allowed)
	}
	if rl.allow("other") != true {
		t.Error("independent client must have its own bucket")
	}
}

// Role-scoped servers: a viewer server must not expose mutating tools once
// later phases add them; for assert build succeeds per role and the
// read-only policy path works end-to-end via config.
func TestBuildServerPerRole(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:11111")
	cfg.Clients = append(cfg.Clients, ClientToken{Name: "ro", Role: "viewer", Token: strings.Repeat("v", 32)})
	b := newTestBridge(t, cfg)
	for _, r := range []string{"viewer", "operator", "admin"} {
		role, err := guard.ParseRole(r)
		if err != nil {
			t.Fatal(err)
		}
		if s := b.BuildServer(role); s == nil {
			t.Errorf("BuildServer(%s) = nil", r)
		}
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	good := write("good.yaml", `
default_target: kv
targets:
  kv:
    url: http://192.168.80.9:11111
clients:
  - name: ci
    role: operator
    token: 0123456789abcdef0123456789abcdef
`)
	cfg, err := LoadConfig(good)
	if err != nil {
		t.Fatalf("good config rejected: %v", err)
	}
	if cfg.DefaultTarget != "kv" || len(cfg.Clients) != 1 {
		t.Errorf("config parsed wrong: %+v", cfg)
	}

	for name, content := range map[string]string{
		"notargets.yaml": `clients: []`,
		"badrole.yaml": `
targets: {a: {url: http://x:1}}
clients: [{name: c, role: root, token: 0123456789abcdef0123456789abcdef}]`,
		"unknownfield.yaml": `
targets: {a: {url: http://x:1}}
bogus_key: true`,
		"bothtokens.yaml": `
targets: {a: {url: http://x:1}}
clients: [{name: c, role: admin, token: 0123456789abcdef0123456789abcdef, token_env: X}]`,
	} {
		if _, err := LoadConfig(write(name, content)); err == nil {
			t.Errorf("%s accepted, want error", name)
		}
	}
}
