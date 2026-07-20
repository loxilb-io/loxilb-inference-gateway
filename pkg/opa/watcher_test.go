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
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// makeOPAResponse builds a JSON response matching OPAPolicyResponse structure.
func makeOPAResponse(rules []OPARule) []byte {
	resp := OPAPolicyResponse{}
	resp.Result.L4.FirewallAccessRules = rules
	b, _ := json.Marshal(resp)
	return b
}

func TestWatcherSingleSyncCycle(t *testing.T) {
	var fwPostCount int32

	// Mock OPA server returns 2 rules
	opaRules := []OPARule{
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
		{
			SourceIP:           "172.16.0.0/12",
			DestinationIP:      "10.0.0.1/32",
			Protocol:           17,
			MinSourcePort:      0,
			MaxSourcePort:      65535,
			MinDestinationPort: 53,
			MaxDestinationPort: 53,
			Preference:         200,
			Action:             "deny",
		},
	}

	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeOPAResponse(opaRules))
	}))
	defer opaSrv.Close()

	// Mock LoxiLB server accepts all requests
	loxiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(&fwPostCount, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer loxiSrv.Close()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	w := NewWatcher(WatcherConfig{
		OPAURL:       opaSrv.URL,
		PolicyPath:   "loxilb/l4",
		PollInterval: 1 * time.Hour, // long interval so only manual sync fires
		InitialDelay: 0,
		LoxiLBURL:    loxiSrv.URL,
		StatePath:    statePath,
	})

	// Execute single sync
	w.syncOnce(context.Background())

	// Verify cache was updated with 2 rules
	rules := w.cache.GetAllRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 cached rules, got %d", len(rules))
	}

	// Verify LoxiLB received POST requests for both rules
	posts := atomic.LoadInt32(&fwPostCount)
	if posts != 2 {
		t.Errorf("expected 2 POST requests to LoxiLB, got %d", posts)
	}

	// Verify status
	status := w.GetStatus()
	if status.LastError != "" {
		t.Errorf("expected no error, got %q", status.LastError)
	}
	if status.RulesCount != 2 {
		t.Errorf("expected status.RulesCount=2, got %d", status.RulesCount)
	}
}

func TestWatcherOPAUnavailable(t *testing.T) {
	// OPA server that returns 500
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer opaSrv.Close()

	loxiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer loxiSrv.Close()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	w := NewWatcher(WatcherConfig{
		OPAURL:       opaSrv.URL,
		PolicyPath:   "loxilb/l4",
		PollInterval: 1 * time.Hour,
		InitialDelay: 0,
		LoxiLBURL:    loxiSrv.URL,
		StatePath:    statePath,
	})

	// Pre-populate cache with one rule to verify it is preserved
	normalizer := NewRuleNormalizer()
	testResp := &OPAPolicyResponse{}
	testResp.Result.L4.FirewallAccessRules = []OPARule{
		{
			SourceIP:           "10.0.0.0/8",
			DestinationIP:      "0.0.0.0/0",
			Protocol:           6,
			MinSourcePort:      0,
			MaxSourcePort:      65535,
			MinDestinationPort: 443,
			MaxDestinationPort: 443,
			Preference:         50,
			Action:             "allow",
		},
	}
	rules, opts, _ := normalizer.Normalize(testResp)
	for k, v := range rules {
		w.cache.Set(k, v, opts[k])
	}

	// Attempt sync (should fail)
	w.syncOnce(context.Background())

	// Cache should be preserved
	cachedRules := w.cache.GetAllRules()
	if len(cachedRules) != 1 {
		t.Errorf("expected cache preserved with 1 rule, got %d", len(cachedRules))
	}

	// Status should have an error
	status := w.GetStatus()
	if status.LastError == "" {
		t.Error("expected a last error after OPA failure, got empty")
	}
}

func TestWatcherPolicyChange(t *testing.T) {
	var callCount int32
	var fwDeleteCount, fwPostCount int32

	// First call returns 2 rules, second call returns 1 different rule
	rulesV1 := []OPARule{
		{
			SourceIP:           "10.0.0.0/8",
			DestinationIP:      "0.0.0.0/0",
			Protocol:           6,
			MinSourcePort:      0,
			MaxSourcePort:      65535,
			MinDestinationPort: 80,
			MaxDestinationPort: 80,
			Preference:         100,
			Action:             "allow",
		},
		{
			SourceIP:           "172.16.0.0/12",
			DestinationIP:      "0.0.0.0/0",
			Protocol:           6,
			MinSourcePort:      0,
			MaxSourcePort:      65535,
			MinDestinationPort: 443,
			MaxDestinationPort: 443,
			Preference:         200,
			Action:             "allow",
		},
	}
	rulesV2 := []OPARule{
		{
			SourceIP:           "192.168.0.0/16",
			DestinationIP:      "0.0.0.0/0",
			Protocol:           17,
			MinSourcePort:      0,
			MaxSourcePort:      65535,
			MinDestinationPort: 53,
			MaxDestinationPort: 53,
			Preference:         300,
			Action:             "deny",
		},
	}

	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.Write(makeOPAResponse(rulesV1))
		} else {
			w.Write(makeOPAResponse(rulesV2))
		}
	}))
	defer opaSrv.Close()

	loxiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			atomic.AddInt32(&fwPostCount, 1)
		case http.MethodDelete:
			atomic.AddInt32(&fwDeleteCount, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer loxiSrv.Close()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	w := NewWatcher(WatcherConfig{
		OPAURL:       opaSrv.URL,
		PolicyPath:   "loxilb/l4",
		PollInterval: 1 * time.Hour,
		InitialDelay: 0,
		LoxiLBURL:    loxiSrv.URL,
		StatePath:    statePath,
	})

	// First sync: 2 rules added
	w.syncOnce(context.Background())
	if w.cache.Len() != 2 {
		t.Fatalf("after first sync expected 2 rules, got %d", w.cache.Len())
	}

	// Reset counters for second sync
	atomic.StoreInt32(&fwPostCount, 0)
	atomic.StoreInt32(&fwDeleteCount, 0)

	// Second sync: policy changed to 1 different rule
	// Expect: 2 deletes (old rules) + 1 add (new rule)
	w.syncOnce(context.Background())

	if w.cache.Len() != 1 {
		t.Errorf("after second sync expected 1 rule, got %d", w.cache.Len())
	}

	deletes := atomic.LoadInt32(&fwDeleteCount)
	if deletes != 2 {
		t.Errorf("expected 2 DELETE requests, got %d", deletes)
	}

	posts := atomic.LoadInt32(&fwPostCount)
	if posts != 1 {
		t.Errorf("expected 1 POST request, got %d", posts)
	}
}
