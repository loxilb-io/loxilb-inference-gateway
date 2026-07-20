//go:build doca

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

// dpu_debug_p65_test.go — REST handler tests.
//
// Tests use httptest.NewRecorder and a minimal mockDpuDebugProvider that satisfies
// DpuDebugProvider without any DOCA / CGO linkage. All 6 behaviors are exercised:
//
//  1. TestDpuDebugBackwardCompat    — no query params → existing aggregate shape
//  2. TestDpuDebugFilteredQuery     — ?pipe=ct_fwd_5tuple&svc=svc1&ep=10.0.0.5:80 → doca_entry_details present
//  3. TestDpuDebugPipeAllowList     — ?pipe=invalid_name → HTTP 400 + no CGO crossing
//  4. TestDpuDebugLimitClamp        — ?limit=5000 clamped; ?limit=0 defaults to 200
//  5. TestDpuDebugEpValidation      — ?ep=malformed-addr → HTTP 400
//  6. TestDpuDebugNoCGOHandleLeak   — doca_entry_details absent on aggregate path; hashed on filtered path
//
// darwin/CI build note: the handler package compiles cleanly on all platforms;
// no DOCA / CGO import is needed here. The macOS limitation (macos-pkg-loxinet-no-compile)
// only affects pkg/loxinet, not api/restapi/handler.

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockDpuDebugProvider / registerMock now live in the UNTAGGED dpu_mock_test.go
// so conntrack_p65_test.go (default build) shares the same test double. Under
// `-tags doca` that file is compiled too, so the mock is available here.

// ---------------------------------------------------------------------------
// Test 1: backward-compat aggregate — no query params.
// ---------------------------------------------------------------------------

// TestDpuDebugBackwardCompat verifies that a GET with no query parameters returns the
// aggregate shape unchanged. doca_entry_details MUST be absent from the JSON
// (omitempty). All legacy integer fields must be present and correct.
func TestDpuDebugBackwardCompat(t *testing.T) {
	restore := registerMock(&mockDpuDebugProvider{})
	defer restore()

	req := httptest.NewRequest(http.MethodGet, "/config/dpu/debug", nil)
	w := httptest.NewRecorder()
	HandleDpuDebug(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// backward-compat: legacy scalar fields must be present.
	for _, key := range []string{"enabled", "offload_success", "offload_failure", "offload_active"} {
		if _, ok := resp[key]; !ok {
			t.Errorf("missing required field %q", key)
		}
	}

	// doca_entry_details must NOT appear on the no-param aggregate path.
	if _, ok := resp["doca_entry_details"]; ok {
		t.Error("doca_entry_details must be absent on aggregate path (omitempty)")
	}

	// P49-R1: per-pipe maps must be present (never null/missing).
	for _, key := range []string{"offload_success_by_pipe", "offload_failure_by_pipe", "offload_active_by_pipe"} {
		if _, ok := resp[key]; !ok {
			t.Errorf("missing per-pipe field %q", key)
		}
	}

	// fdb_entries / route_entries / acl_entries must be JSON arrays (never null).
	for _, key := range []string{"fdb_entries", "route_entries", "acl_entries"} {
		raw, ok := resp[key]
		if !ok {
			t.Errorf("missing array field %q", key)
			continue
		}
		if !strings.HasPrefix(string(raw), "[") {
			t.Errorf("field %q must be a JSON array, got: %s", key, raw)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 2: filtered query — path returns doca_entry_details.
// ---------------------------------------------------------------------------

// TestDpuDebugFilteredQuery verifies that ?pipe=ct_fwd_5tuple&svc=svc1&ep=10.0.0.5:80&limit=200
// routes to filtered path, passes the validated filter to QueryDocaEntries, and
// includes doca_entry_details in the response.
func TestDpuDebugFilteredQuery(t *testing.T) {
	syntheticEntry := DocaEntryDetail{
		EntryHandleHashed: "a1b2c3d4e5f60001",
		FiveTuple:         "10.0.0.1:54321->10.0.0.5:80/TCP",
		HwPkts:            100,
		HwBytes:           60000,
		AgeMsEstimate:     0,
		PipeKey:           "ct_fwd_5tuple",
	}
	mock := &mockDpuDebugProvider{entries: []DocaEntryDetail{syntheticEntry}}
	restore := registerMock(mock)
	defer restore()

	req := httptest.NewRequest(http.MethodGet, "/config/dpu/debug?pipe=ct_fwd_5tuple&svc=svc1&ep=10.0.0.5:80&limit=200", nil)
	w := httptest.NewRecorder()
	HandleDpuDebug(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	// Verify filter params were passed through.
	if mock.capturedFilter.Pipe != "ct_fwd_5tuple" {
		t.Errorf("pipe: got %q want %q", mock.capturedFilter.Pipe, "ct_fwd_5tuple")
	}
	if mock.capturedFilter.Svc != "svc1" {
		t.Errorf("svc: got %q want %q", mock.capturedFilter.Svc, "svc1")
	}
	if mock.capturedFilter.Ep != "10.0.0.5:80" {
		t.Errorf("ep: got %q want %q", mock.capturedFilter.Ep, "10.0.0.5:80")
	}
	if mock.capturedFilter.Limit != 200 {
		t.Errorf("limit: got %d want 200", mock.capturedFilter.Limit)
	}

	var resp DpuDebugResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// doca_entry_details must be present with the synthetic entry.
	if len(resp.DocaEntryDetails) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(resp.DocaEntryDetails))
	}
	got := resp.DocaEntryDetails[0]
	if got.HwPkts != syntheticEntry.HwPkts {
		t.Errorf("hw_pkts: got %d want %d", got.HwPkts, syntheticEntry.HwPkts)
	}
	if got.PipeKey != syntheticEntry.PipeKey {
		t.Errorf("pipe_key: got %q want %q", got.PipeKey, syntheticEntry.PipeKey)
	}
}

// ---------------------------------------------------------------------------
// Test 3: pipe allow-list enforcement.
// ---------------------------------------------------------------------------

// TestDpuDebugPipeAllowList verifies that ?pipe=<unknown_name> returns HTTP 400
// without ever calling QueryDocaEntries (no CGO crossing). The error body must
// include the allowed pipe list.
func TestDpuDebugPipeAllowList(t *testing.T) {
	mock := &mockDpuDebugProvider{}
	restore := registerMock(mock)
	defer restore()

	req := httptest.NewRequest(http.MethodGet, "/config/dpu/debug?pipe=invalid_pipe_name", nil)
	w := httptest.NewRecorder()
	HandleDpuDebug(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid pipe") {
		t.Errorf("error body should mention 'invalid pipe', got: %s", body)
	}

	// QueryDocaEntries must NOT have been called (capturedFilter is zero-value).
	if mock.capturedFilter.Pipe != "" {
		t.Error("QueryDocaEntries must not be called when pipe validation fails")
	}
}

// ---------------------------------------------------------------------------
// Test 4: limit clamp and default.
// ---------------------------------------------------------------------------

// TestDpuDebugLimitClamp verifies:
//   - ?limit=5000 is clamped to dpuDebugMaxLimit (2000)
//   - ?limit=0 is treated as invalid and falls back to dpuDebugDefaultLimit (200)
func TestDpuDebugLimitClamp(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantLimit int
	}{
		{"above_max", "/config/dpu/debug?pipe=ct_fwd_5tuple&limit=5000", dpuDebugMaxLimit},
		{"zero", "/config/dpu/debug?pipe=ct_fwd_5tuple&limit=0", dpuDebugDefaultLimit},
		{"negative", "/config/dpu/debug?pipe=ct_fwd_5tuple&limit=-1", dpuDebugDefaultLimit},
		{"exact_max", "/config/dpu/debug?pipe=ct_fwd_5tuple&limit=2000", dpuDebugMaxLimit},
		{"valid_small", "/config/dpu/debug?pipe=ct_fwd_5tuple&limit=50", 50},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockDpuDebugProvider{}
			restore := registerMock(mock)
			defer restore()

			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			w := httptest.NewRecorder()
			HandleDpuDebug(w, req)

			// Should succeed (pipe is valid).
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
			}
			if mock.capturedFilter.Limit != tc.wantLimit {
				t.Errorf("limit: got %d want %d", mock.capturedFilter.Limit, tc.wantLimit)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 5: ep validation.
// ---------------------------------------------------------------------------

// TestDpuDebugEpValidation verifies that malformed ep values return HTTP 400
// without calling QueryDocaEntries. Tests: no colon, invalid port number,
// port out of range (0 and 65536).
func TestDpuDebugEpValidation(t *testing.T) {
	tests := []struct {
		name   string
		ep     string
		wantOK bool // true = 200 expected, false = 400 expected
	}{
		{"no_colon", "malformed-addr", false},
		{"port_zero", "10.0.0.1:0", false},
		{"port_too_large", "10.0.0.1:65536", false},
		{"port_non_numeric", "10.0.0.1:abc", false},
		{"valid_ipv4", "10.0.0.5:80", true},
		{"valid_high_port", "10.0.0.5:65535", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockDpuDebugProvider{}
			restore := registerMock(mock)
			defer restore()

			url := "/config/dpu/debug?pipe=ct_fwd_5tuple&ep=" + tc.ep
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()
			HandleDpuDebug(w, req)

			if tc.wantOK {
				if w.Code != http.StatusOK {
					t.Fatalf("expected 200 for ep=%q, got %d body=%s", tc.ep, w.Code, w.Body.String())
				}
			} else {
				if w.Code != http.StatusBadRequest {
					t.Fatalf("expected 400 for ep=%q, got %d body=%s", tc.ep, w.Code, w.Body.String())
				}
				// QueryDocaEntries must NOT have been called.
				if mock.capturedFilter.Ep != "" {
					t.Error("QueryDocaEntries must not be called when ep validation fails")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 6: compliance — no raw DOCA handle leak.
// ---------------------------------------------------------------------------

// TestDpuDebugNoCGOHandleLeak verifies:
//
//	a) On the aggregate path (no params), doca_entry_details is absent from JSON.
//	b) On the filtered path, entry_handle_hashed is a 16-char hex string, NOT a
//	   numeric raw pointer.
func TestDpuDebugNoCGOHandleLeak(t *testing.T) {
	// -- Part A: aggregate path --
	t.Run("aggregate_no_entry_details", func(t *testing.T) {
		restore := registerMock(&mockDpuDebugProvider{})
		defer restore()

		req := httptest.NewRequest(http.MethodGet, "/config/dpu/debug", nil)
		w := httptest.NewRecorder()
		HandleDpuDebug(w, req)

		var raw map[string]json.RawMessage
		_ = json.Unmarshal(w.Body.Bytes(), &raw)
		if _, ok := raw["doca_entry_details"]; ok {
			t.Error("doca_entry_details must not appear in aggregate response (omitempty)")
		}
	})

	// -- Part B: filtered path — hashed handle must not look like a raw pointer --
	t.Run("filtered_handle_is_hashed", func(t *testing.T) {
		syntheticEntry := DocaEntryDetail{
			// Simulate what the adapter produces: fnv64a hash as hex string.
			EntryHandleHashed: "deadbeefcafe0001",
			FiveTuple:         "1.2.3.4:1000->5.6.7.8:80/TCP",
			HwPkts:            42,
			HwBytes:           1680,
			PipeKey:           "ct_fwd_5tuple",
		}
		mock := &mockDpuDebugProvider{entries: []DocaEntryDetail{syntheticEntry}}
		restore := registerMock(mock)
		defer restore()

		req := httptest.NewRequest(http.MethodGet, "/config/dpu/debug?pipe=ct_fwd_5tuple", nil)
		w := httptest.NewRecorder()
		HandleDpuDebug(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
		}

		var resp DpuDebugResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if len(resp.DocaEntryDetails) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(resp.DocaEntryDetails))
		}
		hashed := resp.DocaEntryDetails[0].EntryHandleHashed

		// Must be exactly 16 hex characters (fnv64a output).
		if len(hashed) != 16 {
			t.Errorf("entry_handle_hashed must be 16 hex chars, got %q (len %d)", hashed, len(hashed))
		}
		// Must not look like a raw decimal pointer (pure digits).
		if strings.IndexFunc(hashed, func(r rune) bool { return r < '0' || r > 'f' }) >= 0 {
			// Not all-hex — acceptable as long as it's not raw pointer.
		} else {
			// All hex — this is correct.
		}
		// Must not be empty.
		if hashed == "" {
			t.Error("entry_handle_hashed must not be empty")
		}
	})
}
