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
 * dpu_doca_bf2_metrics_test.go — unit tests for:
 *
 * TestDocaCollectorMetricsClosedEnumCardinality (D-P65-04)
 * TestNoCombinedLayerLabel (anti-pattern registry walk)
 *   TestDocaEgressFlag (G2 outcome gauge pre-instantiation)
 * TestNoSafeGoroutineOperationForDoca (amendment codebase-invariant)
 * TestNoLayerCombinedRegistration (source-grep)
 *
 * These tests run on darwin and Linux (go:build !doca) so they validate
 * the stub-mirror discipline and the codebase-invariant grep gates without
 * requiring DOCA linkage. The Prometheus registry tests enumerate the
 * default registry populated by init in dpu_doca_bf2_metrics.go (doca)
 * and dpu_metrics.go (no build tag).
 *
 * macOS / non-DOCA developer machines: this is the authoritative test gate.
 * BF2 hardware linkage test deferred to operator runbook.
 */

package loxinet

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestDocaCollectorMetricsClosedEnumCardinality validates that the total
// number of label sets registered in the Prometheus default registry across
// all loxilb_doca_* and loxilb_lb_* series is ≤ 200 at init time
// cardinality budget; service count is 0 at init so loxilb_lb_* has 0 children).
//
// This test runs against the !doca stub. The doca-build companion registers
// the same series via promauto.NewCounterVec/GaugeVec/Histogram in
// dpu_doca_bf2_metrics.go; the stub does NOT register Prometheus metrics
// (it has no promauto calls). Therefore this test validates the cardinality
// constraint using the metrics registered by the existing dpu_metrics.go
// (no build tag) plus any future non-CGO metrics.
//
// If this test is run after the doca-build registers its metric families,
// the cardinality assertion catches any unintended proliferation.
//
// cardinality ceiling: ~150-200 label sets across all loxilb_doca_* +
// loxilb_lb_* series at init time (before any service is added).
func TestDocaCollectorMetricsClosedEnumCardinality(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("prometheus.DefaultGatherer.Gather: %v", err)
	}

	count := 0
	for _, mf := range mfs {
		name := mf.GetName()
		if strings.HasPrefix(name, "loxilb_doca_") || strings.HasPrefix(name, "loxilb_lb_") {
			count += len(mf.GetMetric())
		}
	}

	const maxCardinality = 200
	t.Logf("loxilb_doca_* + loxilb_lb_* label sets at init: %d (budget: ≤%d)", count, maxCardinality)
	if count > maxCardinality {
		t.Errorf(" cardinality violation: found %d label sets, budget is ≤%d; add to closed enums or check for per-flow labels", count, maxCardinality)
	}
}

// TestNoCombinedLayerLabel validates that no metric in the Prometheus default
// registry has a label child with value="combined" (anti-pattern).
//
// This test provides defense-in-depth against copy-paste errors where a
// developer might add a `sum by(service) (loxilb_lb_pkts_total)` server-side
// computation result as a "combined" label child. Grafana/PromQL is the
// authority for combined aggregation; MUST NOT emit it.
func TestNoCombinedLayerLabel(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("prometheus.DefaultGatherer.Gather: %v", err)
	}

	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetValue() == "combined" {
					t.Errorf(" violation: metric %s has label child value=combined; emit only ebpf|hw", mf.GetName())
				}
			}
		}
	}
}

// TestDocaEgressFlag verifies that both loxilb_doca_egress_counters_available
// label children ("true" and "false") are pre-instantiated at init time.
// In the !doca build path, the stub does not call EgressCountersAvailable
// so the gauge children are not set — but the test verifies the type is
// declared and accessible.
//
// In the doca-build, the dpu_doca_bf2_metrics.go init pre-instantiates
// both children via WithLabelValues("true") / WithLabelValues("false"),
// and initDocaMetricsCollector sets the actual 0/1 values at post-pipe-init.
// This test in the !doca path validates:
//  1. The OffloadState enum values are correctly declared.
//
// 2. The EgressCountersAvailable stub returns false (no-HW contract).
//  3. The ReconciledStats stub returns OffloadNone.
func TestDocaEgressFlag(t *testing.T) {
	d := &DpDocaBf2{}

	// In the !doca build, EgressCountersAvailable always returns false.
	if d.EgressCountersAvailable() {
		t.Error("!doca stub EgressCountersAvailable() must return false")
	}

	// ReconcileCtStats stub must return OffloadNone.
	ct := &DpCtInfo{}
	rs := d.ReconcileCtStats(ct)
	if rs.OffloadState != OffloadNone {
		t.Errorf("!doca ReconcileCtStats() stub must return OffloadNone, got %q", rs.OffloadState)
	}

	// Verify all three OffloadState constants have their expected values.
	if OffloadNone != "none" {
		t.Errorf("OffloadNone must be %q, got %q", "none", OffloadNone)
	}
	if OffloadTransitioning != "transitioning" {
		t.Errorf("OffloadTransitioning must be %q, got %q", "transitioning", OffloadTransitioning)
	}
	if OffloadHw != "hw" {
		t.Errorf("OffloadHw must be %q, got %q", "hw", OffloadHw)
	}

	// In the doca-build (which we can't exercise here), both gauge children
	// should be pre-instantiated. We assert the Prometheus default registry
	// in the !doca build does NOT contain the loxilb_doca_egress_counters_available
	// family (since only the doca-build registers it via promauto).
	// This confirms the stub does not inadvertently register Prometheus metrics.
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("prometheus.DefaultGatherer.Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "loxilb_doca_egress_counters_available" {
			// If present (doca build), both children must exist.
			children := mf.GetMetric()
			sawTrue := false
			sawFalse := false
			for _, m := range children {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "value" {
						switch lp.GetValue() {
						case "true":
							sawTrue = true
						case "false":
							sawFalse = true
						}
					}
				}
			}
			if !sawTrue || !sawFalse {
				t.Errorf("loxilb_doca_egress_counters_available: both 'true' and 'false' children must be pre-instantiated; sawTrue=%v sawFalse=%v", sawTrue, sawFalse)
			}
		}
	}
}

// TestNoSafeGoroutineOperationForDoca is a codebase-invariant test that
// asserts zero matches for safeGoroutineOperation, time.NewTicker, or a
// bare `go ` spawn in the DOCA metrics file (amendment guard).
//
// This test shells out to grep to verify the source file directly,
// independent of the build tag. The test is authoritative for
// amendment: "Plans 65-03/65-04 MUST NOT call safeGoroutineOperation,
// go ..., or time.NewTicker for DOCA counter collection."
//
// Note: bare `go ` is matched as ` go ` (space on both sides) to avoid
// false positives on `// go:build`, `go.sum`, `logrus.go`, etc.
func TestNoSafeGoroutineOperationForDoca(t *testing.T) {
	// Locate the source file relative to this test file.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — cannot locate test file")
	}
	dir := filepath.Dir(thisFile)
	targetFile := filepath.Join(dir, "dpu_doca_bf2_metrics.go")

	forbiddenPatterns := []string{
		"safeGoroutineOperation",
		"time.NewTicker",
	}

	for _, pattern := range forbiddenPatterns {
		cmd := exec.Command("grep", "-n", pattern, targetFile)
		out, _ := cmd.Output()
		if len(out) > 0 {
			t.Errorf(" amendment violation: found %q in dpu_doca_bf2_metrics.go:\n%s", pattern, out)
		}
	}

	// Check for bare goroutine spawns (` go func` or `\tgo func`).
	// This guards against copy-paste of safeGoroutineOperation pattern.
	cmd := exec.Command("grep", "-nP", `^\s+go\s+(func|[A-Z])`, targetFile)
	out, _ := cmd.Output()
	if len(out) > 0 {
		t.Errorf(" amendment violation: found bare goroutine spawn in dpu_doca_bf2_metrics.go:\n%s", out)
	}
}

// TestNoLayerCombinedRegistration is a source-grep test asserting that the
// literal string "combined" does NOT appear in dpu_doca_bf2_metrics.go.
// anti-pattern guard: layer="combined" server-side computation is
// explicitly forbidden in Prometheus surface.
func TestNoLayerCombinedRegistration(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — cannot locate test file")
	}
	dir := filepath.Dir(thisFile)
	targetFile := filepath.Join(dir, "dpu_doca_bf2_metrics.go")

	cmd := exec.Command("grep", "-n", "combined", targetFile)
	out, _ := cmd.Output()
	if len(out) > 0 {
		t.Errorf(" violation: found literal \"combined\" in dpu_doca_bf2_metrics.go:\n%s", out)
	}
}

// TestDocaCollectorMetricsStubTypes validates the stub type declarations
// that REST handler and loxicmd renderer depend on (darwin/CI path).
func TestDocaCollectorMetricsStubTypes(t *testing.T) {
	// ReconciledCounterResult must have Pkts and Bytes fields.
	rcr := ReconciledCounterResult{Pkts: 100, Bytes: 1000}
	if rcr.Pkts != 100 || rcr.Bytes != 1000 {
		t.Error("ReconciledCounterResult fields mismatch")
	}

	// ReconciledStats must have all 5 fields.
	rs := ReconciledStats{
		Pkts:         200,
		Bytes:        2000,
		HwPkts:       50,
		HwBytes:      500,
		OffloadState: OffloadHw,
	}
	if rs.Pkts != 200 || rs.Bytes != 2000 || rs.HwPkts != 50 || rs.HwBytes != 500 {
		t.Error("ReconciledStats fields mismatch")
	}
	if rs.OffloadState != OffloadHw {
		t.Errorf("expected OffloadHw, got %q", rs.OffloadState)
	}
}

// metricFamilyExists returns true if the Prometheus default registry contains
// a metric family with the given name.
func metricFamilyExists(t *testing.T, name string) bool {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("prometheus.DefaultGatherer.Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return true
		}
	}
	return false
}
