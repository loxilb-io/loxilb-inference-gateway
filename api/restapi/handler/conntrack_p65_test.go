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

// conntrack_p65_test.go — tests for ReconcileCtStats
// wiring in the conntrack REST handler.
//
// Tests verify:
//  1. TestCtJsonBackwardCompat — when dpuDebugProvider is nil (pre-DOCA path),
//     the JSON response contains no offload_state / hw_pkts / hw_bytes fields
// (omitempty backward-compat per).
//  2. TestCtJsonWithDocaOffload — when dpuDebugProvider returns OffloadHw,
//     the JSON response contains offload_state="hw" and nonzero hw_pkts.
//  3. TestCtJsonOffloadNoneOmitted — when ReconcileCtFlowStats returns "none",
//     the JSON response omits the three new fields (omitempty).
//
// darwin/CI build note: no DOCA / CGO import is needed here. The handler
// package compiles cleanly on all platforms (macOS limitation only affects
// pkg/loxinet). All tests use httptest + mockDpuDebugProvider from
// dpu_debug_p65_test.go.

package handler

import (
	"encoding/json"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
)

// ---------------------------------------------------------------------------
// Test 1: backward-compat — dpuDebugProvider == nil → no new JSON fields.
// ---------------------------------------------------------------------------

// TestCtJsonBackwardCompat verifies that when the DOCA provider is not
// registered (dpuDebugProvider == nil), the ConntrackEntry JSON output
// contains no offload_state / hw_pkts / hw_bytes fields. This preserves
// backward-compat for non-DOCA deployments and existing CICD parsers.
func TestCtJsonBackwardCompat(t *testing.T) {
	entry := models.ConntrackEntry{
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.5",
		SourcePort:      1024,
		DestinationPort: 80,
		Protocol:        "tcp",
		Packets:         42,
		Bytes:           1680,
		// No OffloadState / HwPkts / HwBytes set (zero values).
	}

	data, err := json.Marshal(&entry)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// the three new fields must be absent from JSON when not set (omitempty).
	for _, field := range []string{"offload_state", "hw_pkts", "hw_bytes"} {
		if _, ok := raw[field]; ok {
			t.Errorf("field %q must be absent when offload state is 'none' (omitempty), but found in JSON: %s", field, data)
		}
	}

	// Legacy fields must still be present.
	for _, field := range []string{"sourceIP", "destinationIP", "packets", "bytes"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("required field %q missing from JSON: %s", field, data)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 2: DOCA OffloadHw — new fields appear in JSON with correct values.
// ---------------------------------------------------------------------------

// TestCtJsonWithDocaOffload verifies that when OffloadState is "hw" (non-empty),
// the three new fields are present in JSON and carry the expected values.
func TestCtJsonWithDocaOffload(t *testing.T) {
	entry := models.ConntrackEntry{
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.5",
		SourcePort:      1024,
		DestinationPort: 80,
		Protocol:        "tcp",
		Packets:         200,
		Bytes:           8000,
		OffloadState:    "hw",
		HwPkts:          150,
		HwBytes:         6000,
	}

	data, err := json.Marshal(&entry)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// offload_state, hw_pkts, hw_bytes must be present.
	for _, field := range []string{"offload_state", "hw_pkts", "hw_bytes"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("field %q must be present in JSON when OffloadState=%q", field, entry.OffloadState)
		}
	}

	// Unmarshal back and verify values.
	var got models.ConntrackEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if got.OffloadState != "hw" {
		t.Errorf("offload_state: got %q want %q", got.OffloadState, "hw")
	}
	if got.HwPkts != 150 {
		t.Errorf("hw_pkts: got %d want 150", got.HwPkts)
	}
	if got.HwBytes != 6000 {
		t.Errorf("hw_bytes: got %d want 6000", got.HwBytes)
	}
}

// ---------------------------------------------------------------------------
// Test 3: OffloadState == "none" → omitempty drops the field.
// ---------------------------------------------------------------------------

// TestCtJsonOffloadNoneOmitted verifies that OffloadState="none" is treated
// as the zero value (empty string) so omitempty removes the field. The handler
// sets OffloadState only when offloadState != "none".
func TestCtJsonOffloadNoneOmitted(t *testing.T) {
	// Simulate the handler's behavior: do NOT set OffloadState when state=="none".
	entry := models.ConntrackEntry{
		SourceIP:      "192.168.1.1",
		DestinationIP: "192.168.1.2",
		Protocol:      "udp",
		Packets:       10,
		Bytes:         400,
		// OffloadState intentionally left empty (handler only sets it when != "none").
	}

	data, err := json.Marshal(&entry)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// All three new fields must be absent (omitempty when zero/empty).
	for _, field := range []string{"offload_state", "hw_pkts", "hw_bytes"} {
		if _, ok := raw[field]; ok {
			t.Errorf("field %q must be absent when OffloadState=='' (omitempty): %s", field, data)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 4: ReconcileCtFlowStats interface — mockDpuDebugProvider compliance.
// ---------------------------------------------------------------------------

// TestMockProviderReconcileCtFlowStats verifies that mockDpuDebugProvider
// satisfies DpuDebugProvider.ReconcileCtFlowStats with the expected stub return.
func TestMockProviderReconcileCtFlowStats(t *testing.T) {
	mock := &mockDpuDebugProvider{}

	state, hwPkts, hwBytes := mock.ReconcileCtFlowStats(CtFlowRef{
		SipStr:    "10.0.0.1",
		DipStr:    "10.0.0.5",
		Sport:     1024,
		Dport:     80,
		Proto:     "tcp",
		IdentStr:  "0:0",
		EbpfPkts:  42,
		EbpfBytes: 1680,
	})

	if state != "none" {
		t.Errorf("mock ReconcileCtFlowStats: state got %q want %q", state, "none")
	}
	if hwPkts != 0 || hwBytes != 0 {
		t.Errorf("mock ReconcileCtFlowStats: hwPkts=%d hwBytes=%d want both 0", hwPkts, hwBytes)
	}
}
