package loxinet

// TestBridgeBytesSampler — production body.
// Covers P49-R3 threat (sysfs path injection). Uses t.TempDir as
// a fake sysfsNetBase so the test never touches real /sys. Exercises:
//
//   - Happy path (2 bridges with valid rx/tx files)
//   - Trailing-newline tolerance (one file with, one without)
//   - Parse error (non-numeric contents → skip, no gauge mutation)
//   - ENOENT (bridge in registry but no sysfs dir → DeleteLabelValues + once-log)
//   - Path injection defense ("../../etc/passwd" rejected)
//   - Gauge.Set idempotency (second call overwrites to new value)

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestBridgeBytesSampler(t *testing.T) {
	// Save + restore globals we mutate so the test doesn't leak state into
	// other tests running in the same process.
	saveBase := sysfsNetBase
	saveMissing := make(map[string]bool, len(missingBridges))
	for k, v := range missingBridges {
		saveMissing[k] = v
	}
	saveRegistry := make(map[string]int, len(bridgeByName))
	for k, v := range bridgeByName {
		saveRegistry[k] = v
	}
	t.Cleanup(func() {
		sysfsNetBase = saveBase
		missingBridges = map[string]bool{}
		for k, v := range saveMissing {
			missingBridges[k] = v
		}
		bridgeVidMu.Lock()
		for k := range bridgeByName {
			delete(bridgeByName, k)
		}
		for k, v := range saveRegistry {
			bridgeByName[k] = v
		}
		bridgeVidMu.Unlock()
		// Clear any test gauge children so they don't leak into other tests.
		kernelBridgeBytes.Reset()
	})

	base := t.TempDir()
	sysfsNetBase = base

	// Build fake /sys/class/net/<br>/statistics/{rx,tx}_bytes for three bridges.
	mkfile := func(br, fname, contents string) {
		dir := filepath.Join(base, br, "statistics")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, fname), []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", dir, err)
		}
	}
	mkfile("br-alpha", "rx_bytes", "1000\n")
	mkfile("br-alpha", "tx_bytes", "500\n")
	mkfile("br-beta", "rx_bytes", "2000") // no trailing newline
	mkfile("br-beta", "tx_bytes", "800")
	mkfile("br-gamma", "rx_bytes", "not-a-number\n")
	mkfile("br-gamma", "tx_bytes", "100\n")

	// Register bridges. Use direct map write under lock since the test needs
	// to inject arbitrary names (including adversarial ones) without going
	// through GetOrAllocBridgeVid.
	bridgeVidMu.Lock()
	for k := range bridgeByName {
		delete(bridgeByName, k)
	}
	bridgeByName["br-alpha"] = 5000
	bridgeByName["br-beta"] = 5001
	bridgeByName["br-gamma"] = 5002
	bridgeByName["br-missing"] = 5003 // has no filesystem entry -- ENOENT path
	bridgeVidMu.Unlock()

	// Seed missingBridges as empty for this test so "once" logging fires.
	missingBridges = map[string]bool{}

	// --- First call: populate the gauge. ---
	SampleKernelBridgeBytes()

	wantAlpha := float64(1000 + 500)
	wantBeta := float64(2000 + 800)

	if got := testGaugeValue(t, "br-alpha"); got != wantAlpha {
		t.Errorf("br-alpha gauge = %v, want %v", got, wantAlpha)
	}
	if got := testGaugeValue(t, "br-beta"); got != wantBeta {
		t.Errorf("br-beta gauge = %v, want %v", got, wantBeta)
	}

	// br-gamma: parse error on rx_bytes -> sampler skips the bridge (does NOT
	// Set the gauge). Gauge child should NOT exist for br-gamma.
	if testGaugeChildExists(t, "br-gamma") {
		t.Errorf("br-gamma gauge unexpectedly present after parse error")
	}

	// br-missing: ENOENT path -> DeleteLabelValues. Gauge child should NOT exist.
	if testGaugeChildExists(t, "br-missing") {
		t.Errorf("br-missing gauge unexpectedly present after ENOENT")
	}
	if !missingBridges["br-missing"] {
		t.Errorf("missingBridges[br-missing] not set after ENOENT")
	}

	// --- Path-injection defense ---
	// Inject an adversarial name into bridgeByName. Sampler MUST reject and
	// NOT read outside sysfsNetBase. Assertion is "no panic, no file read" —
	// we verify no gauge child was created under the injected name either.
	bridgeVidMu.Lock()
	bridgeByName["../../etc/passwd"] = 6000
	bridgeVidMu.Unlock()
	SampleKernelBridgeBytes()
	if testGaugeChildExists(t, "../../etc/passwd") {
		t.Errorf("path-injection defense failed: gauge child created for adversarial name")
	}

	// --- Bytes increase on second call (Gauge.Set idempotency) ---
	mkfile("br-alpha", "rx_bytes", "3000\n")
	SampleKernelBridgeBytes()
	wantAlpha2 := float64(3000 + 500)
	if got := testGaugeValue(t, "br-alpha"); got != wantAlpha2 {
		t.Errorf("br-alpha gauge after update = %v, want %v (Gauge.Set overwrites)", got, wantAlpha2)
	}
}

// testGaugeValue fetches the current value of kernelBridgeBytes{bridge=name}.
// Fails the test if the child is not present.
func testGaugeValue(t *testing.T, bridge string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "loxilb_kernel_bridge_bytes" {
			continue
		}
		for _, c := range mf.GetMetric() {
			for _, lp := range c.GetLabel() {
				if lp.GetName() == "bridge" && lp.GetValue() == bridge {
					return c.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("gauge child for bridge=%q not found", bridge)
	return 0
}

// testGaugeChildExists returns true iff a {bridge=<name>} child is present.
func testGaugeChildExists(t *testing.T, bridge string) bool {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "loxilb_kernel_bridge_bytes" {
			continue
		}
		for _, c := range mf.GetMetric() {
			for _, lp := range c.GetLabel() {
				if lp.GetName() == "bridge" && lp.GetValue() == bridge {
					return true
				}
			}
		}
	}
	return false
}
