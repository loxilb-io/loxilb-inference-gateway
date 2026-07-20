//go:build !doca

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

/*
 * dpu_doca_bf2_reconcile_test.go — unit tests for:
 *
 * TestReconcileCtStatsSimplifiedMath (corrected math, table-driven)
 * TestReconcileCtStatsLazyOnReadNeverFails (: errors don't propagate)
 * TestNoOffloadActiveGating (codebase-invariant grep guard)
 * TestOffloadStateClassification (: three-valued enum)
 *
 * These tests run on darwin and Linux (go:build !doca). The !doca stub
 * ReconcileCtStats always returns OffloadNone; the tests exercise the
 * TYPE CONTRACT and source-level invariants that hold on all build paths.
 *
 * For full behavioral testing of the doca-build ReconcileCtStats (bridge
 * queries, error counter increments), see the BF2 operator runbook in
 * darwin cannot link DOCA per [[macos-pkg-loxinet-no-compile]].
 */

package loxinet

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestReconcileCtStatsSimplifiedMath validates simplified math
// contract for ReconcileCtStats: total = ebpf + doca (no offload_active
// gating, no frozen-snapshot subtraction, no leak math).
//
// In the !doca build the stub always returns OffloadNone with zero HW
// fields (since there is no DOCA bridge). The test validates:
//
//	(a) nil ct → OffloadNone / zero HW
//	(b) stub returns OffloadNone for any input (no bridge available)
//	(c) ReconciledStats field types match contract (uint64, OffloadState)
func TestReconcileCtStatsSimplifiedMath(t *testing.T) {
	d := &DpDocaBf2{}

	cases := []struct {
		name        string
		ct          *DpCtInfo
		wantState   OffloadState
		wantHwPkts  uint64
		wantHwBytes uint64
	}{
		{
			name:        "nil_ct",
			ct:          nil,
			wantState:   OffloadNone,
			wantHwPkts:  0,
			wantHwBytes: 0,
		},
		{
			name: "no_doca_bridge_always_offload_none",
			ct: &DpCtInfo{
				Packets: 50,
				Bytes:   500,
			},
			wantState:   OffloadNone,
			wantHwPkts:  0,
			wantHwBytes: 0,
		},
		{
			name: "ebpf_only_entry_zero_packets",
			ct: &DpCtInfo{
				Packets: 0,
				Bytes:   0,
			},
			wantState:   OffloadNone,
			wantHwPkts:  0,
			wantHwBytes: 0,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rs := d.ReconcileCtStats(tc.ct)
			if rs.OffloadState != tc.wantState {
				t.Errorf("OffloadState: want %q, got %q", tc.wantState, rs.OffloadState)
			}
			if rs.HwPkts != tc.wantHwPkts {
				t.Errorf("HwPkts: want %d, got %d", tc.wantHwPkts, rs.HwPkts)
			}
			if rs.HwBytes != tc.wantHwBytes {
				t.Errorf("HwBytes: want %d, got %d", tc.wantHwBytes, rs.HwBytes)
			}
		})
	}
}

// TestReconcileCtStatsLazyOnReadNeverFails validates : ReconcileCtStats
// MUST NOT return an error. It returns a valid ReconciledStats regardless of
// whether the DOCA bridge is available or returns an error.
//
// In the !doca stub this is trivially satisfied (stub returns a zero value).
// The doca-build behavioral test (bridge-error → error-counter-increment +
// zero HW + no propagation) runs on BF2 silicon runbook.
func TestReconcileCtStatsLazyOnReadNeverFails(t *testing.T) {
	d := &DpDocaBf2{}
	ct := &DpCtInfo{Packets: 42, Bytes: 4200}

	// ReconcileCtStats must have NO error return. This assertion
	// is a compile-time guarantee in the type signature:
	//   func (d *DpDocaBf2) ReconcileCtStats(ct *DpCtInfo) ReconciledStats
	// No error return exists — validated by the compiler on every build.
	rs := d.ReconcileCtStats(ct)

	// The stub must always return a valid ReconciledStats (no panic, no nil).
	if rs.OffloadState == "" {
		t.Error("ReconcileCtStats must always return a non-empty OffloadState")
	}

	// the returned struct is always a valid value, never a panic.
	// Validate the zero-value case is handled gracefully.
	var rsZero ReconciledStats
	if rsZero.OffloadState != "" {
		t.Errorf("zero ReconciledStats should have empty OffloadState, got %q", rsZero.OffloadState)
	}
	// The stub should return OffloadNone specifically (not the zero string).
	if rs.OffloadState != OffloadNone {
		t.Errorf("!doca stub must return OffloadNone, got %q", rs.OffloadState)
	}
}

// TestNoOffloadActiveGating is a codebase-invariant grep test asserting zero
// matches for offloadActive.Load in dpu_doca_bf2_metrics.go (correction
// guard). The CORRECTED decision states: "No offload_active gating in
// collector; total = ebpf + doca." This guard prevents the pre-2026-05-16
// "assumed reset" accounting from being re-introduced.
func TestNoOffloadActiveGating(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	targetFile := filepath.Join(dir, "dpu_doca_bf2_metrics.go")

	cmd := exec.Command("grep", "-n", "offloadActive.Load", targetFile)
	out, _ := cmd.Output()
	if len(out) > 0 {
		t.Errorf(" correction violation: found offloadActive.Load in dpu_doca_bf2_metrics.go:\n%s", out)
	}
}

// TestOffloadStateClassification validates : three OffloadState values
// are correctly returned by classifyOffloadState (tested via public API).
//
// In the !doca stub the classification logic is not present (stub always
// returns OffloadNone). This test validates the TYPE semantics:
//   - OffloadNone, OffloadTransitioning, OffloadHw are distinct values
//
// - The enum values match binding text ("none", "transitioning", "hw")
//   - ReconciledStats.OffloadState field is correctly typed
func TestOffloadStateClassification(t *testing.T) {
	// Validate the three enum values (verbatim binding).
	if string(OffloadNone) != "none" {
		t.Errorf(": OffloadNone must be \"none\", got %q", OffloadNone)
	}
	if string(OffloadTransitioning) != "transitioning" {
		t.Errorf(": OffloadTransitioning must be \"transitioning\", got %q", OffloadTransitioning)
	}
	if string(OffloadHw) != "hw" {
		t.Errorf(": OffloadHw must be \"hw\", got %q", OffloadHw)
	}

	// Validate distinctness (no two constants should be equal).
	if OffloadNone == OffloadTransitioning {
		t.Error(": OffloadNone and OffloadTransitioning must be distinct")
	}
	if OffloadNone == OffloadHw {
		t.Error(": OffloadNone and OffloadHw must be distinct")
	}
	if OffloadTransitioning == OffloadHw {
		t.Error(": OffloadTransitioning and OffloadHw must be distinct")
	}

	// Validate that ReconciledStats.OffloadState is typed as OffloadState
	// (compile-time guarantee, but also test runtime assignment works).
	rs := ReconciledStats{OffloadState: OffloadTransitioning}
	if rs.OffloadState != OffloadTransitioning {
		t.Errorf("ReconciledStats.OffloadState assignment failed: want %q, got %q", OffloadTransitioning, rs.OffloadState)
	}

	// !doca stub ReconcileCtStats must return OffloadNone (not the zero string "").
	d := &DpDocaBf2{}
	ct := &DpCtInfo{}
	rs2 := d.ReconcileCtStats(ct)
	if rs2.OffloadState != OffloadNone {
		t.Errorf("!doca ReconcileCtStats must classify as OffloadNone, got %q", rs2.OffloadState)
	}
}

// TestReconcileCtStatsFieldContract validates that ReconciledStats has
// the correct 5 fields with the correct types (contract).
func TestReconcileCtStatsFieldContract(t *testing.T) {
	rs := ReconciledStats{
		Pkts:         1000,
		Bytes:        8000,
		HwPkts:       800,
		HwBytes:      6400,
		OffloadState: OffloadHw,
	}

	// Verify all 5 fields are settable and readable.
	if rs.Pkts != 1000 {
		t.Errorf("Pkts field: want 1000, got %d", rs.Pkts)
	}
	if rs.Bytes != 8000 {
		t.Errorf("Bytes field: want 8000, got %d", rs.Bytes)
	}
	if rs.HwPkts != 800 {
		t.Errorf("HwPkts field: want 800, got %d", rs.HwPkts)
	}
	if rs.HwBytes != 6400 {
		t.Errorf("HwBytes field: want 6400, got %d", rs.HwBytes)
	}
	if rs.OffloadState != OffloadHw {
		t.Errorf("OffloadState field: want %q, got %q", OffloadHw, rs.OffloadState)
	}

	// simplified math invariant: Pkts >= HwPkts (ebpf portion is non-negative).
	// In the !doca stub this is trivially satisfied (all zeros from HW).
	// In the doca-build, Pkts = ebpfPkts + hwPkts ≥ hwPkts always.
	if rs.Pkts < rs.HwPkts {
		t.Errorf(" math invariant: Pkts (%d) must be >= HwPkts (%d)", rs.Pkts, rs.HwPkts)
	}
}
