/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 */

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newMockLoxilb simulates a --userservice loxilb: /auth/login issues a token,
// everything else 401s without it.
func newMockLoxilb(t *testing.T) *httptest.Server {
	t.Helper()
	const issued = "jwt-token-issued-by-mock"
	mux := http.NewServeMux()
	mux.HandleFunc("/netlox/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Username, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Username != "admin" || body.Password != "pw" {
			http.Error(w, `{"message":"bad credentials"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": issued})
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+issued {
				http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/netlox/v1/version", authed(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "0.9.8.6", "buildInfo": "test"})
	}))
	mux.HandleFunc("/netlox/v1/config/loadbalancer/all", authed(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"lbAttr": []map[string]any{
			{"serviceArguments": map[string]any{"externalIP": "20.20.20.1", "port": 2020, "protocol": "tcp", "name": "web"},
				"endpoints": []map[string]any{{"endpointIP": "31.31.31.1", "weight": 1, "state": "active"}}},
		}})
	}))
	mux.HandleFunc("/netlox/v1/config/conntrack/all", authed(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ctAttr": []map[string]any{
			{"sourceIP": "1.1.1.1", "destinationIP": "20.20.20.1", "sourcePort": 40000,
				"destinationPort": 2020, "protocol": "tcp", "conntrackState": "est", "servName": "web"},
		}})
	}))
	return httptest.NewServer(mux)
}

func TestClientReloginOn401(t *testing.T) {
	srv := newMockLoxilb(t)
	defer srv.Close()

	c, err := New("test", Options{URL: srv.URL, Username: "admin", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Version(context.Background())
	if err != nil {
		t.Fatalf("Version after transparent login: %v", err)
	}
	if v.Version != "0.9.8.6" {
		t.Errorf("version = %q", v.Version)
	}

	rules, err := c.LBRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d lb rules", len(rules))
	}
	cts, err := c.Conntracks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cts) != 1 || cts[0].State != "est" || cts[0].ServName != "web" {
		t.Errorf("conntrack decode wrong: %+v", cts)
	}
}

func TestClientNoCredentials401IsActionable(t *testing.T) {
	srv := newMockLoxilb(t)
	defer srv.Close()

	c, err := New("test", Options{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Version(context.Background())
	if err == nil {
		t.Fatal("expected error without credentials")
	}
	// The F11 hint must be present so operators know what to fix.
	if want := "userservice"; !contains(err.Error(), want) {
		t.Errorf("error %q should mention %q", err, want)
	}
}

func TestClientRejectsBadURL(t *testing.T) {
	if _, err := New("x", Options{URL: "ftp://nope"}); err == nil {
		t.Error("ftp scheme accepted")
	}
	if _, err := New("x", Options{URL: "not a url"}); err == nil {
		t.Error("garbage URL accepted")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
