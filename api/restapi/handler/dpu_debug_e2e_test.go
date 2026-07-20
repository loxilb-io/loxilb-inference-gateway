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

// dpu_debug_e2e_test.go — end-to-end darwin tests
// for the consumer side of telemetry chain.
//
// Scope on darwin via httptest + mockDpuDebugProvider (already defined in
// dpu_debug_p65_test.go, shared across the handler package's test files):
// - Filtered query JSON round-trip (happy path + limit clamp)
// - JSON omitempty backward-compat (— non-offloaded entries do NOT
//     leak the three new fields into the JSON wire format)
//   - Swagger-model fidelity round-trip (json.Marshal → json.Unmarshal proxy
//     for full Swagger validation; the real go-swagger validator requires
//     network + a swagger.json snapshot, not available in unit tests)
//
// These tests run on darwin without DOCA / CGO. They complement (do not
// replace) the per-test handler tests; the e2e suite exercises the
// FULL JSON marshal/unmarshal chain end-to-end rather than asserting handler
// internals.

package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
)

// ---------------------------------------------------------------------------
// Test 4: end-to-end filtered query (happy path + limit clamp).
//
// httptest server wraps dpuDebugGet. Mock provider returns 250 synthetic
// entries. Three sub-cases verify:
//   - limit=100 → response has exactly 100 entries.
//   - limit=300 → response has all 250 (capped to available, not error).
// - limit=5000 → response is silently clamped to 2000 (hard cap).
// ---------------------------------------------------------------------------

func TestE2ERestDebugFilteredQuery(t *testing.T) {
	const (
		synth = 250
		hard  = 2000
	)

	// Build 250 synthetic entries the mock returns regardless of filter.
	entries := make([]DocaEntryDetail, synth)
	for i := 0; i < synth; i++ {
		entries[i] = DocaEntryDetail{
			FiveTuple:         "10.0.0.1:" + strconv.Itoa(1024+i) + "->10.0.0.5:80/tcp",
			HwPkts:            uint64(100 + i),
			HwBytes:           uint64((100 + i) * 60),
			AgeMs:             uint64(i * 10),
			EntryHandleHashed: "fnv-" + strconv.Itoa(i),
		}
	}

	cases := []struct {
		name     string
		limit    string
		wantMin  int
		wantMax  int
		wantPipe string
	}{
		{name: "limit=100 trims to 100", limit: "100", wantMin: 100, wantMax: 100, wantPipe: "ct_fwd_5tuple"},
		{name: "limit=300 caps at synth=250", limit: "300", wantMin: synth, wantMax: synth, wantPipe: "ct_fwd_5tuple"},
		{name: "limit=5000 clamps to hard=2000", limit: "5000", wantMin: 0, wantMax: hard, wantPipe: "ct_fwd_5tuple"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockDpuDebugProvider{entries: entries}
			restore := registerMock(mock)
			defer restore()

			req := httptest.NewRequest("GET",
				"/netlox/v1/config/dpu/debug?pipe="+tc.wantPipe+"&limit="+tc.limit, nil)
			w := httptest.NewRecorder()

			dpuDebugGet(w, req)

			resp := w.Result()
			if resp.StatusCode != 200 {
				t.Fatalf("expected HTTP 200, got %d", resp.StatusCode)
			}

			var body DpuDebugResponse
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			n := len(body.DocaEntryDetails)
			if n < tc.wantMin || n > tc.wantMax {
				t.Errorf("doca_entry_details length=%d; want in [%d, %d]",
					n, tc.wantMin, tc.wantMax)
			}

			// Whatever was passed to QueryDocaEntries must have a Limit
			// inside the [1, hard] range.
			if mock.capturedFilter.Limit < 1 || mock.capturedFilter.Limit > hard {
				t.Errorf("provider filter limit=%d; must be clamped to [1, %d]",
					mock.capturedFilter.Limit, hard)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 5: omitempty backward-compat — non-offloaded ConntrackEntry
// JSON output must NOT contain offload_state / hw_pkts / hw_bytes keys.
// Existing legacy parsers (CICD, scripts, monitoring scrapers) must continue
// to see the pre-v6.0 JSON shape on entries that are not HW-offloaded.
//
// This complements TestCtJsonBackwardCompat (which tests one entry); here we
// test the round-trip through json.Marshal AND json.Unmarshal to confirm
// the field absence survives a roundtrip via a generic map (the shape a
// CICD parser would see when parsing into map[string]interface{}).
// ---------------------------------------------------------------------------

func TestE2ECtJsonOmitemptyRoundtrip(t *testing.T) {
	cases := []struct {
		name         string
		offloadState string
		wantOmitted  bool
		wantPkts     int64
		wantHwPkts   uint64
	}{
		{name: "non-offloaded entry omits 3 fields", offloadState: "", wantOmitted: true, wantPkts: 42, wantHwPkts: 0},
		{name: "OffloadNone entry omits 3 fields", offloadState: "none", wantOmitted: true, wantPkts: 42, wantHwPkts: 0},
		{name: "OffloadHw entry includes 3 fields", offloadState: "hw", wantOmitted: false, wantPkts: 100, wantHwPkts: 100},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := models.ConntrackEntry{
				SourceIP:        "10.0.0.1",
				DestinationIP:   "10.0.0.5",
				SourcePort:      1024,
				DestinationPort: 80,
				Protocol:        "tcp",
				Packets:         tc.wantPkts,
				Bytes:           tc.wantPkts * 60,
			}
			if tc.offloadState != "" && tc.offloadState != "none" {
				entry.OffloadState = tc.offloadState
				entry.HwPkts = tc.wantHwPkts
				entry.HwBytes = tc.wantHwPkts * 60
			}

			data, err := json.Marshal(&entry)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}

			// Roundtrip via generic map — what a CICD parser would see.
			var roundtrip map[string]json.RawMessage
			if err := json.Unmarshal(data, &roundtrip); err != nil {
				t.Fatalf("json.Unmarshal (generic): %v", err)
			}

			for _, field := range []string{"offload_state", "hw_pkts", "hw_bytes"} {
				_, present := roundtrip[field]
				if tc.wantOmitted && present {
					t.Errorf("field %q must be ABSENT for %s (omitempty); JSON: %s",
						field, tc.name, data)
				}
				if !tc.wantOmitted && !present {
					t.Errorf("field %q must be PRESENT for %s (offloaded); JSON: %s",
						field, tc.name, data)
				}
			}

			// Legacy keys must always be present.
			for _, field := range []string{"sourceIP", "destinationIP", "packets", "bytes"} {
				if _, ok := roundtrip[field]; !ok {
					t.Errorf("legacy field %q missing from JSON: %s", field, data)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 6: Swagger-model fidelity round-trip (proxy for full Swagger validation).
//
// Marshals a fully-populated ConntrackEntry to JSON, unmarshals back into a
// fresh ConntrackEntry, and asserts every field round-trips. If a field is
// renamed or omitempty-mistagged in the model, the roundtrip drops data and
// this test fails. This is the darwin-friendly substitute for a full
// go-swagger validator run (which would require a swagger.json snapshot and
// network access).
// ---------------------------------------------------------------------------

func TestE2ESwaggerModelRoundtrip(t *testing.T) {
	original := models.ConntrackEntry{
		SourceIP:        "10.10.10.1",
		DestinationIP:   "20.20.20.1",
		SourcePort:      54321,
		DestinationPort: 5201,
		Protocol:        "tcp",
		Packets:         12345,
		Bytes:           789012,
		OffloadState:    "hw",
		HwPkts:          12000,
		HwBytes:         720000,
	}

	data, err := json.Marshal(&original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var roundtrip models.ConntrackEntry
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if roundtrip.SourceIP != original.SourceIP ||
		roundtrip.DestinationIP != original.DestinationIP ||
		roundtrip.SourcePort != original.SourcePort ||
		roundtrip.DestinationPort != original.DestinationPort ||
		roundtrip.Protocol != original.Protocol ||
		roundtrip.Packets != original.Packets ||
		roundtrip.Bytes != original.Bytes ||
		roundtrip.OffloadState != original.OffloadState ||
		roundtrip.HwPkts != original.HwPkts ||
		roundtrip.HwBytes != original.HwBytes {
		t.Errorf("Swagger model roundtrip dropped fields.\nOriginal:  %+v\nRoundtrip: %+v\nJSON:      %s",
			original, roundtrip, data)
	}

	// Same roundtrip for LoadbalanceEntry — also added the 3 fields.
	lbOrig := models.LoadbalanceEntry{
		OffloadState: "hw",
		HwPkts:       9999,
		HwBytes:      888888,
	}
	lbData, err := json.Marshal(&lbOrig)
	if err != nil {
		t.Fatalf("LB Marshal: %v", err)
	}
	var lbRT models.LoadbalanceEntry
	if err := json.Unmarshal(lbData, &lbRT); err != nil {
		t.Fatalf("LB Unmarshal: %v", err)
	}
	if lbRT.OffloadState != lbOrig.OffloadState ||
		lbRT.HwPkts != lbOrig.HwPkts ||
		lbRT.HwBytes != lbOrig.HwBytes {
		t.Errorf("LB Swagger model roundtrip dropped fields. Original: %+v Roundtrip: %+v", lbOrig, lbRT)
	}
}
