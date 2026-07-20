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

package opa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetcherSuccess(t *testing.T) {
	rules := []OPARule{
		{
			SourceIP:           "10.0.0.0/8",
			DestinationIP:      "192.168.1.0/24",
			Protocol:           6,
			MinSourcePort:      0,
			MaxSourcePort:      65535,
			MinDestinationPort: 80,
			MaxDestinationPort: 80,
			Preference:         100,
			Action:             "allow",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept: application/json, got %s", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeOPAResponse(rules))
	}))
	defer srv.Close()

	cb := NewCircuitBreaker()
	pf := NewPolicyFetcher(srv.URL, "loxilb/l4", cb)

	resp, err := pf.Fetch(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Result.L4.FirewallAccessRules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(resp.Result.L4.FirewallAccessRules))
	}
	if resp.Result.L4.FirewallAccessRules[0].SourceIP != "10.0.0.0/8" {
		t.Errorf("unexpected sourceIP: %s", resp.Result.L4.FirewallAccessRules[0].SourceIP)
	}
	if cb.State() != CircuitClosed {
		t.Error("expected circuit breaker to remain CLOSED after success")
	}
}

func TestFetcherHTTP500RecordsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cb := NewCircuitBreaker()
	pf := NewPolicyFetcher(srv.URL, "loxilb/l4", cb)

	_, err := pf.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestFetcherInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()

	cb := NewCircuitBreaker()
	pf := NewPolicyFetcher(srv.URL, "loxilb/l4", cb)

	_, err := pf.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFetcherCircuitBreakerOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach server when circuit breaker is open")
	}))
	defer srv.Close()

	cb := NewCircuitBreaker()
	// Trip the circuit breaker
	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Fatal("expected circuit breaker OPEN")
	}

	pf := NewPolicyFetcher(srv.URL, "loxilb/l4", cb)

	_, err := pf.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error when circuit breaker is open")
	}
}

func TestFetcherContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeOPAResponse(nil))
	}))
	defer srv.Close()

	cb := NewCircuitBreaker()
	pf := NewPolicyFetcher(srv.URL, "loxilb/l4", cb)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := pf.Fetch(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestFetcherURLConstruction(t *testing.T) {
	var requestPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeOPAResponse(nil))
	}))
	defer srv.Close()

	cb := NewCircuitBreaker()
	// Test with trailing slash on URL and leading slash on path
	pf := NewPolicyFetcher(srv.URL+"/", "/loxilb/l4", cb)

	_, err := pf.Fetch(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestPath != "/v1/data/loxilb/l4" {
		t.Errorf("expected path /v1/data/loxilb/l4, got %s", requestPath)
	}
}

func TestFetcherEmptyRules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := OPAPolicyResponse{}
		b, _ := json.Marshal(resp)
		w.Write(b)
	}))
	defer srv.Close()

	cb := NewCircuitBreaker()
	pf := NewPolicyFetcher(srv.URL, "loxilb/l4", cb)

	resp, err := pf.Fetch(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Result.L4.FirewallAccessRules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(resp.Result.L4.FirewallAccessRules))
	}
}

func TestFetcherMultipleRules(t *testing.T) {
	rules := []OPARule{
		{SourceIP: "10.0.0.0/8", DestinationIP: "0.0.0.0/0", Protocol: 6, Action: "allow", Preference: 100},
		{SourceIP: "172.16.0.0/12", DestinationIP: "0.0.0.0/0", Protocol: 17, Action: "deny", Preference: 200},
		{SourceIP: "192.168.0.0/16", DestinationIP: "10.0.0.0/8", Protocol: 132, Action: "allow", Preference: 300},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeOPAResponse(rules))
	}))
	defer srv.Close()

	cb := NewCircuitBreaker()
	pf := NewPolicyFetcher(srv.URL, "loxilb/l4", cb)

	resp, err := pf.Fetch(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Result.L4.FirewallAccessRules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(resp.Result.L4.FirewallAccessRules))
	}
}
