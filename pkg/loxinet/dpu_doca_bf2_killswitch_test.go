//go:build !doca

/*
 * Copyright (c) 2022 NetLOX Inc
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

// kill-switch unit tests.
//
// These tests assert that the BF2_BIDIR_OFFLOAD env var read at DpDocaBf2.Init
// follows the contract documented in:
//
//   1. Default ON: env var unset (or any value other than "0") -> bidirEnabled=true.
//   2. Kill switch OFF: BF2_BIDIR_OFFLOAD=0 -> bidirEnabled=false.
//   3. Manager-seam dispatch: with bidirEnabled=false, ShadowPairOrDispatch routes
//      to the legacy ShadowLBFlowOffload path (no PairOffloader.PairOrDispatch
//      invocation).
//
// The DOCA-build Init in dpu_doca_bf2.go reads the env var via
// `d.bidirEnabled = os.Getenv("BF2_BIDIR_OFFLOAD") != "0"`. Under !doca, Init
// is a stub that returns ErrNotSupported and does NOT touch the env var, so
// these tests:
//
//   - Validate the env-var read EXPRESSION (the exact comparison from Init)
//     against t.Setenv-controlled values, asserting the same logic the
//     production Init runs.
// - Validate the BidirEnabled / GetBidirEnabled / ShadowPairOrDispatch
//     plumbing on a constructed DpDocaBf2 + DpuManager instance with
//     bidirEnabled set directly — this is the dispatch contract that
//     goCtHwOffloadHandler depends on (per 51-PATTERNS.md "manager-level seam").
//
// The plan (51-05-PLAN.md) explicitly notes: "Test 3 instead exercises
// the manager-level seam (ShadowPairOrDispatch + GetBidirEnabled) which is the
// dispatch contract goCtHwOffloadHandler relies on."

package loxinet

import (
	"os"
	"testing"
)

// readBidirEnv mirrors the EXACT expression used in DpDocaBf2.Init at
// dpu_doca_bf2.go:432 — `os.Getenv("BF2_BIDIR_OFFLOAD") != "0"`. Test-only
// reproduction so we can exercise the env-var contract under !doca without
// running the DOCA-build Init body. Any drift between this expression and
// production Init must be caught by the static-analysis grep gate documented
// in 51-05-PLAN.md acceptance criteria
// (`grep -c 'os.Getenv.*BF2_BIDIR_OFFLOAD' pkg/loxinet/dpu_doca_bf2.go == 1`).
func readBidirEnv() bool {
	return os.Getenv("BF2_BIDIR_OFFLOAD") != "0"
}

// TestPhase51_KillSwitch_DefaultOn — env var unset -> bidirEnabled=true.
//
// Per : "default ON. ON = new pairing path. OFF = original
// per-direction path." Operators who do nothing get the new bidirectional
// behavior; the kill switch must be opt-IN to disable.
func TestPhase51_KillSwitch_DefaultOn(t *testing.T) {
	// t.Setenv("", "") leaves the var DEFINED with empty value; for the
	// "truly unset" case we need explicit Unsetenv with a Cleanup restore.
	prev, hadPrev := os.LookupEnv("BF2_BIDIR_OFFLOAD")
	if err := os.Unsetenv("BF2_BIDIR_OFFLOAD"); err != nil {
		t.Fatalf("Unsetenv failed: %v", err)
	}
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv("BF2_BIDIR_OFFLOAD", prev)
		} else {
			_ = os.Unsetenv("BF2_BIDIR_OFFLOAD")
		}
	})

	got := readBidirEnv()
	if !got {
		t.Fatalf("env var unset: expected bidirEnabled=true (default ON), got %v", got)
	}

	// Sanity: a non-"0" value also yields true.
	t.Setenv("BF2_BIDIR_OFFLOAD", "1")
	if !readBidirEnv() {
		t.Fatalf("BF2_BIDIR_OFFLOAD=1: expected bidirEnabled=true, got false")
	}

	// Empty string is also != "0", so still true (default ON semantics).
	t.Setenv("BF2_BIDIR_OFFLOAD", "")
	if !readBidirEnv() {
		t.Fatalf("BF2_BIDIR_OFFLOAD=\"\": expected bidirEnabled=true, got false")
	}

	// Construct a DpDocaBf2 with bidirEnabled mirrored from the env-var read
	// and assert the BidirEnabled accessor returns the same value (the
	// goCtHwOffloadHandler gate path).
	d := newKillSwitchTestDpDocaBf2()
	d.bidirEnabled = readBidirEnv()
	if !d.BidirEnabled() {
		t.Fatalf("BidirEnabled accessor returned false after default-ON env read")
	}
}

// TestPhase51_KillSwitch_LegacyPath — BF2_BIDIR_OFFLOAD=0 -> bidirEnabled=false.
//
// Per : "Operator can flip via service env if production
// regression appears. Two prior reverts justify this escape hatch." When set
// to "0", BidirEnabled must return false so goCtHwOffloadHandler takes the
// legacy per-direction branch (dpebpf_linux.go:4414).
func TestPhase51_KillSwitch_LegacyPath(t *testing.T) {
	t.Setenv("BF2_BIDIR_OFFLOAD", "0")

	got := readBidirEnv()
	if got {
		t.Fatalf("BF2_BIDIR_OFFLOAD=0: expected bidirEnabled=false (kill switch engaged), got true")
	}

	d := newKillSwitchTestDpDocaBf2()
	d.bidirEnabled = readBidirEnv()
	if d.BidirEnabled() {
		t.Fatalf("BidirEnabled accessor returned true after kill-switch env read")
	}
}

// TestPhase51_KillSwitch_DispatchBranch — manager-seam dispatch contract.
//
// Asserts the dispatch invariant goCtHwOffloadHandler relies on:
// when BidirEnabled returns false, ShadowPairOrDispatch must NOT invoke
// PairOrDispatch on the plugin. Production code (dpebpf_linux.go:4496) gates
// the entire bidir branch with `!mh.dpuMgr.GetBidirEnabled`, so this test
// exercises the GetBidirEnabled == false case at the manager seam (which
// would otherwise dispatch through ShadowPairOrDispatch in the bidir branch).
//
// Per 51-PATTERNS.md: "Test 3 instead exercises the manager-level seam
// (ShadowPairOrDispatch + GetBidirEnabled) which is the dispatch contract
// goCtHwOffloadHandler relies on."
func TestPhase51_KillSwitch_DispatchBranch(t *testing.T) {
	mgr := DpuManagerInit()
	plugin := newKillSwitchPairOffloader("ks-plugin", false /* bidirEnabled */)
	mgr.Register(plugin)

	if mgr.GetBidirEnabled() {
		t.Fatalf("GetBidirEnabled() returned true with bidirEnabled=false plugin")
	}

	// Drive the manager seam used by the bidir branch.
	ct := &DpCtInfo{Proto: "tcp"}
	paired, fwd, rev := mgr.ShadowPairOrDispatch(ct, 0)
	if paired {
		t.Fatalf("paired=true with kill switch engaged; got fwd=%q rev=%q", fwd, rev)
	}
	if fwd != "" || rev != "" {
		t.Fatalf("expected empty keys with kill switch engaged; got fwd=%q rev=%q", fwd, rev)
	}

	if plugin.pairOrDispatchCalls != 0 {
		t.Fatalf("PairOrDispatch invoked %d time(s) with kill switch engaged; expected 0",
			plugin.pairOrDispatchCalls)
	}

	// Cross-check: with bidirEnabled=true on the same plugin shape,
	// ShadowPairOrDispatch DOES invoke PairOrDispatch — proving the assertion
	// above is a behavior gate, not a no-op.
	mgr2 := DpuManagerInit()
	plugin2 := newKillSwitchPairOffloader("ks-plugin-on", true /* bidirEnabled */)
	mgr2.Register(plugin2)
	if !mgr2.GetBidirEnabled() {
		t.Fatalf("GetBidirEnabled() returned false with bidirEnabled=true plugin")
	}
	_, _, _ = mgr2.ShadowPairOrDispatch(&DpCtInfo{Proto: "tcp"}, 0)
	if plugin2.pairOrDispatchCalls != 1 {
		t.Fatalf("PairOrDispatch invoked %d time(s) with bidir ON; expected 1",
			plugin2.pairOrDispatchCalls)
	}
}

// === Test helpers ===

// newKillSwitchTestDpDocaBf2 returns a minimally-initialized DpDocaBf2 stub
// suitable for kill-switch tests. The BidirEnabled accessor only reads
// d.bidirEnabled, so no other fields are required.
func newKillSwitchTestDpDocaBf2() *DpDocaBf2 {
	return &DpDocaBf2{}
}

// killSwitchPairPlugin is a minimal DpuPlugin + PairOffloader composite for
// the dispatch-seam test. Counts PairOrDispatch and LBFlowOffload calls so
// the test can prove which branch the manager took.
type killSwitchPairPlugin struct {
	name                string
	bidirEnabled        bool
	pairOrDispatchCalls int
	lbFlowOffloadCalls  int
}

func newKillSwitchPairOffloader(name string, bidir bool) *killSwitchPairPlugin {
	return &killSwitchPairPlugin{name: name, bidirEnabled: bidir}
}

// DpuPlugin interface — minimal stubs.
func (p *killSwitchPairPlugin) Init(cfg DpuConfig) error { return nil }
func (p *killSwitchPairPlugin) Shutdown() error          { return nil }
func (p *killSwitchPairPlugin) Name() string             { return p.name }
func (p *killSwitchPairPlugin) Capabilities() DpuCapabilities {
	return DpuCapabilities{LBOffload: true}
}

func (p *killSwitchPairPlugin) LBFlowOffload(ct *DpCtInfo, lbMark int) error {
	p.lbFlowOffloadCalls++
	return nil
}
func (p *killSwitchPairPlugin) LBFlowRemove(ct *DpCtInfo) error { return nil }
func (p *killSwitchPairPlugin) RouteAdd(w *RouteDpWorkQ) error  { return ErrNotSupported }
func (p *killSwitchPairPlugin) RouteDel(w *RouteDpWorkQ) error  { return ErrNotSupported }
func (p *killSwitchPairPlugin) RouteFlowOffload(ct *DpCtInfo, rid int) error {
	return ErrNotSupported
}
func (p *killSwitchPairPlugin) FdbFlowOffload(fdb *FdbEnt) error   { return ErrNotSupported }
func (p *killSwitchPairPlugin) FdbFlowRemove(fdb *FdbEnt) error    { return ErrNotSupported }
func (p *killSwitchPairPlugin) FwRuleAdd(w *FwDpWorkQ) error       { return ErrNotSupported }
func (p *killSwitchPairPlugin) FwRuleDel(w *FwDpWorkQ) error       { return ErrNotSupported }
func (p *killSwitchPairPlugin) NextHopAdd(w *NextHopDpWorkQ) error { return ErrNotSupported }
func (p *killSwitchPairPlugin) NextHopDel(w *NextHopDpWorkQ) error { return ErrNotSupported }
func (p *killSwitchPairPlugin) MeterAdd(w *PolDpWorkQ) error       { return ErrNotSupported }
func (p *killSwitchPairPlugin) MeterDel(w *PolDpWorkQ) error       { return ErrNotSupported }
func (p *killSwitchPairPlugin) FlowStats(ct *DpCtInfo) (uint64, uint64, error) {
	return 0, 0, ErrNotSupported
}
func (p *killSwitchPairPlugin) PipeStats(name string) (uint32, error) {
	return 0, ErrNotSupported
}

// PairOffloader interface —.
func (p *killSwitchPairPlugin) PairOrDispatch(ct *DpCtInfo, lbMark int) (bool, string, string) {
	p.pairOrDispatchCalls++
	return false, "", ""
}
func (p *killSwitchPairPlugin) BidirEnabled() bool { return p.bidirEnabled }
