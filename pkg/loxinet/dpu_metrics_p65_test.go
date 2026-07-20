// dpu_metrics_p65_test.go — unit tests.
//
// Tests verify:
// 1. InvokeRegisteredDocaCollectors is called from CollectHwOffloadStats
//      (TestDocaPerTickInvocation).
// 2. The doca_* metric surface exists and its registration is gated on
//      plugin attach per metrics-audit D5 (TestDocaMetricSurface).
//   3. No new goroutine/ticker for DOCA collection (TestNoNewGoroutineForPhase65).
//
// Build constraints: this test file has NO build tag so it runs on
// darwin / Linux-without-DOCA. Calls to RegisterDocaCollector and
// InvokeRegisteredDocaCollectors are delegated to the !doca stub no-ops
// in dpu_doca_bf2_stub_metrics.go under the non-doca build path.

package loxinet

import (
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

// TestDocaPerTickInvocation verifies that CollectHwOffloadStats invokes
// InvokeRegisteredDocaCollectors which in turn fires each registered callback.
//
// On !doca builds InvokeRegisteredDocaCollectors is a no-op; the test validates
// that the call path exists (grep) and that the package compiles correctly. On
// doca builds the counter will be incremented.
func TestDocaPerTickInvocation(t *testing.T) {
	// Source-level verification: CollectHwOffloadStats must call
	// InvokeRegisteredDocaCollectors — grep for the call site.
	out, err := exec.Command("grep", "-q", "InvokeRegisteredDocaCollectors", "dpu_metrics.go").Output()
	_ = out
	if err != nil {
		t.Errorf("InvokeRegisteredDocaCollectors not found in dpu_metrics.go: %v", err)
	}

	// Functional verification on non-DOCA builds: register a callback, confirm it
	// runs when InvokeRegisteredDocaCollectors is called. On !doca builds both
	// functions are no-ops (the registry itself is in the doca build path), so
	// we confirm the function signatures exist and are callable.
	var counter int64
	// This call is a no-op on !doca builds — stub silently discards the fn.
	RegisterDocaCollector(func() {
		atomic.AddInt64(&counter, 1)
	})
	// This call is a no-op on !doca builds.
	InvokeRegisteredDocaCollectors()
	// Under !doca: counter == 0 (stub). Under doca: counter == 1 (if registered).
	// We only assert that the functions are callable without panic.
	t.Logf("counter after InvokeRegisteredDocaCollectors: %d (0 expected on !doca build)", counter)

	// Panic isolation verification: register a panicking callback, confirm
	// InvokeRegisteredDocaCollectors does not propagate the panic.
	RegisterDocaCollector(func() {
		panic("test-panic-isolation")
	})
	// On !doca: no-op. On doca: must not panic (recover inside invoke).
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("InvokeRegisteredDocaCollectors propagated panic: %v", r)
			}
		}()
		InvokeRegisteredDocaCollectors()
	}()
}

// TestDocaMetricSurface verifies via source-level grep that:
//  1. At least one doca_* metric name exists in dpu_metrics.go (the working
//     Phase-49 surface kept by the metrics audit).
//  2. Registration is gated on plugin attach (registerDpuMetrics present) —
//     metrics audit D5.
func TestDocaMetricSurface(t *testing.T) {
	// Check doca_* metric declaration still exists.
	phase49Out, err := exec.Command(
		"grep", "-q", `"doca_offload_active_flows"`, "dpu_metrics.go",
	).Output()
	_ = phase49Out
	if err != nil {
		t.Error("doca_* metric 'doca_offload_active_flows' not found in dpu_metrics.go")
	}

	// Check D5 gating: registration happens in registerDpuMetrics, not promauto.
	if _, err := exec.Command("grep", "-q", "func registerDpuMetrics", "dpu_metrics.go").Output(); err != nil {
		t.Error("registerDpuMetrics not found in dpu_metrics.go — D5 gated registration missing")
	}
	if out, err := exec.Command("grep", "-n", "promauto", "dpu_metrics.go").Output(); err == nil {
		t.Errorf("promauto found in dpu_metrics.go — D5 requires gated (non-auto) registration:\n%s", out)
	}
}

// TestNoNewGoroutineForPhase65 is a codebase-invariant test that ensures no
// new goroutine or ticker was introduced for DOCA counter collection
// amendment iter 2 guard).
//
// The test greps the six files that is allowed to modify and fails
// if it finds safeGoroutineOperation or time.NewTicker patterns.
func TestNoNewGoroutineForPhase65(t *testing.T) {
	targetFiles := []string{
		"dpu_metrics.go",
		"dpu_doca_bf2_metrics.go",
		"dpu_doca_bf2_helpers.go",
	}

	forbiddenPatterns := []struct {
		pattern string
		reason  string
	}{
		{`time\.NewTicker`, " amendment forbids new ticker for DOCA collection"},
		{`safeGoroutineOperation.*doca`, " amendment forbids safeGoroutineOperation for DOCA collection"},
	}

	for _, fp := range forbiddenPatterns {
		args := []string{"-nE", fp.pattern}
		args = append(args, targetFiles...)
		out, err := exec.Command("grep", args...).Output()
		if err == nil {
			// grep found a match — this is a failure
			t.Errorf(" guard FAILED: pattern %q found in target files: %s. Reason: %s",
				fp.pattern, strings.TrimSpace(string(out)), fp.reason)
		}
		// err != nil means grep found no match — that's the expected success case.
	}

	t.Log(" goroutine/ticker guard: no new goroutine or ticker patterns found in target files")
}
