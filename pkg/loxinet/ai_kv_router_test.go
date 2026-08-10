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

package loxinet

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
)

// ============================================================================
// unified prefix-CHWBL + capacity-weighted bounded-load
// scoring. These drive the PURE-GO core (kvUnifiedSelect / kvCapFor /
// kvClampCapacity) directly — no cgo, no datapath — so the algorithm is proven
// in isolation. llb_ai_kv_best_worker merely gathers candidates + delegates.
// ============================================================================

// TestKvClampCapacityGuard proves the V5 divide-by-zero/overflow guard
// : a NumGPUBlocks=0 (absent/malicious) clamps to 1 (smallest
// positive weight, never zeroes the sum), and a huge value clamps to MAX.
func TestKvClampCapacityGuard(t *testing.T) {
	tests := []struct {
		in   uint32
		want uint64
	}{
		{0, 1},                                   // malicious/absent → 1, never 0
		{1, 1},                                   // already minimal
		{2048, 2048},                             // typical
		{kvCapacityClampMax, kvCapacityClampMax}, // at the bound
		{kvCapacityClampMax + 1, kvCapacityClampMax}, // overflow guard
		{4294967295, kvCapacityClampMax},             // uint32 max clamps
	}
	for _, tc := range tests {
		if got := kvClampCapacity(tc.in); got != tc.want {
			t.Errorf("kvClampCapacity(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestKvCapFormula proves cap_i = ceil((1+ε)·total_load·capacity_i/Σcapacity)
// with ε via mean_load_factor/100 (175⇒ε=0.75), and the capacity-weighting
// ordering: a larger-capacity EP gets a proportionally larger cap.
func TestKvCapFormula(t *testing.T) {
	// Two EPs, capacity ratio 4:1 (e.g. A100 vs A10/L4 NumGPUBlocks contrast),
	// total_load = 100, ε=0.75 (mlf=175). total_cap = 4+1 = 5.
	//   capA = ceil(175*100*4 / (100*5)) = ceil(70000/500) = 140
	//   capB = ceil(175*100*1 / (100*5)) = ceil(17500/500) = 35
	// Ratio capA:capB == 140:35 == 4:1 == capacity ratio.
	capA := kvCapFor(100, 4, 5, 175)
	capB := kvCapFor(100, 1, 5, 175)
	if capA != 140 {
		t.Errorf("capA = %d, want 140", capA)
	}
	if capB != 35 {
		t.Errorf("capB = %d, want 35", capB)
	}
	if capA != 4*capB {
		t.Errorf("capacity-weighted cap ordering broken: capA=%d capB=%d (want 4:1)", capA, capB)
	}

	// ε knob: a larger mean_load_factor loosens the cap proportionally.
	// mlf=300 ⇒ ε=2 ⇒ capA' = ceil(300*100*4/500) = 240 > 140.
	capALoose := kvCapFor(100, 4, 5, 300)
	if capALoose <= capA {
		t.Errorf("larger ε must loosen the cap: capALoose=%d not > capA=%d", capALoose, capA)
	}

	// cap is floored at 1 even at zero load (a live EP always has room for one).
	if c := kvCapFor(0, 1, 5, 175); c != 1 {
		t.Errorf("zero-load cap floored at 1, got %d", c)
	}
}

// TestKvUnifiedAffinityPreservedBelowCap: in the unloaded/under-cap case the
// unified selector picks the SAME EP as pure overlap-argmax (preserves W3).
func TestKvUnifiedAffinityPreservedBelowCap(t *testing.T) {
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 2048, load: 0}, // highest overlap, idle
		{epIdx: 1, overlap: 3, capacity: 2048, load: 0},
		{epIdx: 2, overlap: 7, capacity: 2048, load: 0},
	}
	got, spilled := kvUnifiedSelect(cands, 175)
	if got != 0 {
		t.Errorf("affinity-preserved winner = ep%d, want ep0 (highest overlap)", got)
	}
	if spilled {
		t.Error("must NOT spill when the affinity winner is under cap")
	}
}

// TestKvUnifiedSpillOnOverflow: when the highest-overlap EP is at/over its cap,
// the selector spills to the next-best under-cap EP and reports the spill.
func TestKvUnifiedSpillOnOverflow(t *testing.T) {
	// ep0 has the highest overlap but is heavily loaded beyond its cap; ep2 is
	// the next-best overlap and idle. Homogeneous capacity so the cap is the
	// uniform bounded-load cap.
	//   total_load = 1000 (ep0) + 0 + 0 = 1000; total_cap = 3 (1 each clamped).
	//   cap0 = ceil(175*1000*1/(100*3)) = ceil(175000/300) = 584.
	//   ep0 load 1000 >= 584 → over cap → spill.
	//   ep2 load 0 < its cap → eligible; it has the next-highest overlap.
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 1000},
		{epIdx: 1, overlap: 3, capacity: 1, load: 0},
		{epIdx: 2, overlap: 7, capacity: 1, load: 0},
	}
	got, spilled := kvUnifiedSelect(cands, 175)
	if got != 2 {
		t.Errorf("spill winner = ep%d, want ep2 (next-best overlap under cap)", got)
	}
	if !spilled {
		t.Error("expected spilled=true when the affinity winner is over cap")
	}
}

// TestKvUnifiedCapacityWeightedSpill: a high-overlap but SMALL-capacity EP
// spills under load while a large-capacity EP keeps absorbing — the capacity
// weighting (not just raw load) drives the decision (the C4 heterogeneous case).
func TestKvUnifiedCapacityWeightedSpill(t *testing.T) {
	// ep0: best overlap, tiny capacity (1), moderate load 60.
	// ep1: lower overlap, large capacity (4), same load 60.
	// total_load=120, total_cap=5.
	//   cap0 = ceil(175*120*1/(100*5)) = ceil(21000/500) = 42  → load 60 >= 42 → over cap.
	//   cap1 = ceil(175*120*4/(100*5)) = ceil(84000/500) = 168 → load 60 < 168 → under cap.
	// So the small-capacity affinity winner spills to the large-capacity EP.
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 60},
		{epIdx: 1, overlap: 6, capacity: 4, load: 60},
	}
	got, spilled := kvUnifiedSelect(cands, 175)
	if got != 1 {
		t.Errorf("capacity-weighted spill winner = ep%d, want ep1 (large capacity absorbs)", got)
	}
	if !spilled {
		t.Error("expected spilled=true: small-capacity affinity winner over cap")
	}
}

// TestKvUnifiedAllZeroCapacityNoPanic: every EP advertises NumGPUBlocks=0
// (Σcapacity would be 0 without the clamp) — must fall back to a uniform cap,
// no panic, no divide-by-zero. With equal clamped capacity it
// behaves like the homogeneous bounded-load case.
func TestKvUnifiedAllZeroCapacityNoPanic(t *testing.T) {
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 0, load: 0},
		{epIdx: 1, overlap: 5, capacity: 0, load: 0},
	}
	// Must not panic and must pick the highest-overlap idle EP (ep0).
	got, spilled := kvUnifiedSelect(cands, 175)
	if got != 0 {
		t.Errorf("all-zero-capacity winner = ep%d, want ep0", got)
	}
	if spilled {
		t.Error("idle EPs under uniform cap must not spill")
	}
}

// TestKvUnifiedSkewedSpill: a sharply load-skewed fleet (one EP hoarding the
// load) drives the affinity winner over its cap and the selector spills to the
// idle EP. This is the C4 herding case the unified method fixes.
//
// NOTE on the "all-over-cap saturated" branch: under cap_i =
// ceil((1+ε)·total_load·cap_i/Σcap) the per-EP caps sum to (1+ε)·total_load >
// total_load, so by pigeonhole NOT every EP can simultaneously exceed its own
// cap — the saturated least-loaded fallback in kvUnifiedSelect is therefore a
// DEFENSIVE branch (e.g. future scoring changes), not reachable with this
// formula. We assert the reachable skewed-spill behavior here.
func TestKvUnifiedSkewedSpill(t *testing.T) {
	// ep0 hoards the load; ep1 is nearly idle.
	//   total_load = 100000 + 10 = 100010; total_cap = 2 (1 each clamped).
	//   cap0 = ceil(175*100010*1/(100*2)) = ceil(17501750/200) = 87509.
	//   ep0 load 100000 >= 87509 → over cap → spill off the affinity winner.
	//   ep1 load 10 < 87509 → under cap → the spill target (only eligible).
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 100000},
		{epIdx: 1, overlap: 8, capacity: 1, load: 10},
	}
	got, spilled := kvUnifiedSelect(cands, 175)
	if got != 1 {
		t.Errorf("skewed spill = ep%d, want ep1 (idle, under cap)", got)
	}
	if !spilled {
		t.Error("skewed spill off the over-cap affinity winner must report spilled=true")
	}
}

// TestKvSpillReliefTarget guards hot-prefix pressure-relief. The RUNTIME
// filters the primary candidate set to positive-overlap EPs (ai_kv_subscriber.go
// `score > 0`), so a hot SINGLE-cached prefix reaches kvUnifiedSelect with cands=1 and
// pins to that EP (live-observed 288/288 at L≈90, 0 spills). Relief is applied POST-
// selection over the FULL healthy-prefill fleet by kvSpillReliefTarget — this drives it
// directly (the env gating lives at the caller, not here).
func TestKvSpillReliefTarget(t *testing.T) {
	// Hotspot: ep0 hoards the load, ep1/ep2 idle (overlap is ignored by relief).
	//   total_load=100000, total_cap=3 → cap0=ceil(175*100000*1/(100*3))=58334.
	//   ep0 load 100000 >= 58334 → over its FLEET-WIDE cap → relieve to a less-loaded EP.
	hot := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 100000},
		{epIdx: 1, overlap: 0, capacity: 1, load: 0},
		{epIdx: 2, overlap: 0, capacity: 1, load: 0},
	}
	got, spilled := kvSpillReliefTarget(hot, 0, 175)
	if !spilled {
		t.Fatalf("hotspot: expected relief spill off the over-cap EP0, got spilled=false (ep%d)", got)
	}
	if got != 1 && got != 2 {
		t.Errorf("hotspot: relief target ep%d, want an idle EP (ep1/ep2)", got)
	}

	// Balanced fleet: the affinity winner is UNDER its fleet-wide cap → keep affinity.
	//   total_load=15, total_cap=3 → cap0=ceil(175*15/(300))=9; ep0 load 5 < 9 → no relief.
	balanced := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 5},
		{epIdx: 1, overlap: 0, capacity: 1, load: 5},
		{epIdx: 2, overlap: 0, capacity: 1, load: 5},
	}
	if got, spilled := kvSpillReliefTarget(balanced, 0, 175); spilled || got != 0 {
		t.Errorf("balanced: got ep%d spilled=%v, want ep0 spilled=false (affinity preserved, no hotspot)", got, spilled)
	}

	// Singleton fleet (nothing to relieve to) → no spill.
	if got, spilled := kvSpillReliefTarget(hot[:1], 0, 175); spilled || got != 0 {
		t.Errorf("singleton: got ep%d spilled=%v, want ep0 spilled=false", got, spilled)
	}

	// kvSpillReliefFor tri-state env gate (§9). Reset the once each read.
	reset := func() { kvSpillReliefOnce = sync.Once{}; kvSpillReliefResolved = "" }
	defer reset()
	t.Setenv("LOXILB_KV_SPILL_RELIEF", "0")
	reset()
	if kvSpillReliefFor(true) || kvSpillReliefFor(false) {
		t.Error("kvSpillReliefFor: explicit '0' must be OFF for every service (kill switch)")
	}
	t.Setenv("LOXILB_KV_SPILL_RELIEF", "1")
	reset()
	if !kvSpillReliefFor(true) || !kvSpillReliefFor(false) {
		t.Error("kvSpillReliefFor: explicit '1' must be ON for every service (opt-in)")
	}
	// UNSET → auto: ON for single-role only (the §9 evidence-banked default);
	// P/D keeps default-OFF verdict.
	t.Setenv("LOXILB_KV_SPILL_RELIEF", "")
	reset()
	if !kvSpillReliefFor(true) {
		t.Error("kvSpillReliefFor: unset must default ON for single-role (kvExactMode=3) — §9")
	}
	if kvSpillReliefFor(false) {
		t.Error("kvSpillReliefFor: unset must default OFF for P/D — verdict preserved")
	}
}

// TestKvUnifiedEmptyAndNoOverlap: empty candidate set or all-zero-overlap →
// miss (1), identical to the pure-argmax miss branch.
func TestKvUnifiedEmptyAndNoOverlap(t *testing.T) {
	if got, _ := kvUnifiedSelect(nil, 175); got != -1 {
		t.Errorf("empty candidates = ep%d, want -1 (miss)", got)
	}
	cands := []kvCandidate{
		{epIdx: 0, overlap: 0, capacity: 2048, load: 0},
		{epIdx: 1, overlap: 0, capacity: 2048, load: 0},
	}
	if got, _ := kvUnifiedSelect(cands, 175); got != -1 {
		t.Errorf("all-zero-overlap = ep%d, want -1 (miss)", got)
	}
}

// TestKvUnifiedModeDefaultOn proves : the unified blend is loxilb's
// DOCUMENTED DEFAULT — ON when LOXILB_KV_UNIFIED_MODE is unset, OFF only on an
// explicit disable value, and still ON on an explicit enable value (back-compat
// for callers that still set it). So "loxilb" in the competitive benchmark is
// loxilb-best. (The once-guard is reset between sub-cases so the env is re-read.)
func TestKvUnifiedModeDefaultOn(t *testing.T) {
	// Sub-case 1: UNSET → the blend is the DEFAULT (ON).
	kvUnifiedModeOnce = sync.Once{}
	kvUnifiedModeEnabled = false
	t.Setenv("LOXILB_KV_UNIFIED_MODE", "")
	if !kvUnifiedModeOn() {
		t.Error("unified mode must default ON (loxilb-best) when LOXILB_KV_UNIFIED_MODE is unset")
	}

	// Sub-case 2: an explicit disable value → OFF (the legacy overlap-argmax leg).
	for _, off := range []string{"0", "false", "off", "no", "FALSE", "Off", "No"} {
		kvUnifiedModeOnce = sync.Once{}
		kvUnifiedModeEnabled = false
		t.Setenv("LOXILB_KV_UNIFIED_MODE", off)
		if kvUnifiedModeOn() {
			t.Errorf("unified mode must be OFF when LOXILB_KV_UNIFIED_MODE=%q", off)
		}
	}

	// Sub-case 3: an explicit enable value → still ON (back-compat).
	kvUnifiedModeOnce = sync.Once{}
	kvUnifiedModeEnabled = false
	t.Setenv("LOXILB_KV_UNIFIED_MODE", "1")
	if !kvUnifiedModeOn() {
		t.Error("unified mode must be ON when LOXILB_KV_UNIFIED_MODE=1")
	}

	// Restore the default (ON) for any later tests in the package.
	kvUnifiedModeOnce = sync.Once{}
	kvUnifiedModeEnabled = false
}

// ============================================================================
// -07 (C2) / (Option B): blend made cleanly
// selectable via kvSelectArm(cands, mode, mlf, lambda). mode "off" is the
// shipped pure overlap-argmax — byte-identical to today. mode "hard" is
// the capacity-weighted bounded-load blend (the former arm C2). One build,
// mode-toggled. (widened the old c2On bool into the mode string.)
// ============================================================================

// TestKvArmC1ByteIdentical proves : with C2 OFF (arm C1), kvSelectArm
// returns EXACTLY the pure overlap-argmax EP — never the capacity/load-aware
// winner — across the same candidate sets the blend would have moved. This is
// the one-build A/B integrity guarantee: toggling the arm OFF reproduces the W3
// baseline selector bit-for-bit.
func TestKvArmC1ByteIdentical(t *testing.T) {
	cases := [][]kvCandidate{
		// affinity winner heavily loaded — C2 would spill, C1 must NOT.
		{
			{epIdx: 0, overlap: 10, capacity: 1, load: 1000},
			{epIdx: 1, overlap: 3, capacity: 1, load: 0},
			{epIdx: 2, overlap: 7, capacity: 1, load: 0},
		},
		// capacity-skewed — C2 would weight by capacity, C1 ignores it.
		{
			{epIdx: 0, overlap: 10, capacity: 1, load: 60},
			{epIdx: 1, overlap: 6, capacity: 4, load: 60},
		},
		// idle homogeneous — both arms agree (highest overlap).
		{
			{epIdx: 0, overlap: 4, capacity: 2048, load: 0},
			{epIdx: 1, overlap: 9, capacity: 2048, load: 0},
		},
	}
	for i, cands := range cases {
		wantC1 := kvArmPureArgmax(cands) // the shipped overlap-argmax winner
		gotC1, spilledC1 := kvSelectArm(cands, "off" /* arm C1 */, 175, 0)
		if gotC1 != wantC1 {
			t.Errorf("case %d: arm C1 = ep%d, want pure argmax ep%d (broken)",
				i, gotC1, wantC1)
		}
		if spilledC1 {
			t.Errorf("case %d: arm C1 must NEVER report a spill (C1 has no load guard)", i)
		}
	}
}

// TestKvArmC2EngagesBlend proves arm C2 (c2On=true) actually applies the
// capacity-weighted bounded-load blend (i.e. it can move off the argmax EP),
// using the same over-cap case where C1 stays put.
func TestKvArmC2EngagesBlend(t *testing.T) {
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 1000}, // argmax but over cap
		{epIdx: 1, overlap: 3, capacity: 1, load: 0},
		{epIdx: 2, overlap: 7, capacity: 1, load: 0}, // next-best, idle
	}
	gotC2, spilledC2 := kvSelectArm(cands, "hard" /* C2/hard on */, 175, 0)
	if gotC2 != 2 {
		t.Errorf("arm C2 = ep%d, want ep2 (spill off over-cap argmax)", gotC2)
	}
	if !spilledC2 {
		t.Error("arm C2 must report spilled=true on the over-cap spill")
	}
	// And C1 on the SAME set stays on the argmax (contrast).
	gotC1, _ := kvSelectArm(cands, "off", 175, 0)
	if gotC1 != 0 {
		t.Errorf("arm C1 on same set = ep%d, want ep0 (argmax, no spill)", gotC1)
	}
}

// TestKvArmC2EpsilonMonotonic proves the ε knob behaves monotonically (feeds
// ε sweep): a LARGER ε (looser cap) keeps MORE traffic on the
// affinity EP (it spills LESS), a TIGHTER ε spreads MORE. Concretely, there
// exists a load where a tight ε spills off the argmax but a loose ε keeps it.
func TestKvArmC2EpsilonMonotonic(t *testing.T) {
	// ep0 argmax, homogeneous capacity, load chosen so the cap crosses between
	// a tight and a loose ε.
	//   total_load = 200; total_cap = 2 (1 each clamped).
	//   tight ε: mlf=100 ⇒ cap0 = ceil(100·200·1/(100·2)) = 100 ; load 150 >= 100 → spill.
	//   loose ε: mlf=300 ⇒ cap0 = ceil(300·200·1/(100·2)) = 300 ; load 150 <  300 → keep.
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 150}, // argmax, moderately loaded
		{epIdx: 1, overlap: 4, capacity: 1, load: 50},   // next-best, lighter
	}

	gotTight, spilledTight := kvSelectArm(cands, "hard", 100, 0) // ε=0 (tightest)
	gotLoose, spilledLoose := kvSelectArm(cands, "hard", 300, 0) // ε=2 (loose)

	if !spilledTight || gotTight == 0 {
		t.Errorf("tight ε (mlf=100) must SPREAD (spill off argmax): got ep%d spilled=%v",
			gotTight, spilledTight)
	}
	if spilledLoose || gotLoose != 0 {
		t.Errorf("loose ε (mlf=300) must KEEP affinity on argmax ep0: got ep%d spilled=%v",
			gotLoose, spilledLoose)
	}

	// Monotonicity statement: spilling under tight ε but not under loose ε is
	// exactly "larger ε keeps more on the affinity EP".
	if spilledTight && !spilledLoose {
		return // monotonic as required
	}
	t.Error("ε must be monotonic: a larger ε keeps strictly more traffic on the affinity EP")
}

// TestKvArmC2DivByZeroSafe proves arm C2 inherits the V5 guards through
// kvSelectArm: a Σcapacity=0 / single-NumGPUBlocks=0 candidate set must not
// panic (clamp 0→1, Σ>0). Mirrors unified guard but via the arm seam.
func TestKvArmC2DivByZeroSafe(t *testing.T) {
	cases := [][]kvCandidate{
		nil,
		{{epIdx: 0, overlap: 5, capacity: 0, load: 0}},
		{
			{epIdx: 0, overlap: 10, capacity: 0, load: 0},
			{epIdx: 1, overlap: 5, capacity: 0, load: 0},
		},
		{
			{epIdx: 0, overlap: 10, capacity: 0, load: 100},
			{epIdx: 1, overlap: 5, capacity: 4, load: 100},
		},
	}
	for i, cands := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: arm C2 panicked on zero/edge capacity: %v", i, r)
				}
			}()
			_, _ = kvSelectArm(cands, "hard", 175, 0)
		}()
	}
}

// ============================================================================
// (Option B) : LOXILB_KV_LB_MODE resolver + precedence matrix +
// mode-aware kvSelectArm dispatch (off → argmax, hard → unified, soft → blend).
// ============================================================================

// resetKvLbModeEnv resets the kvLbMode once-guard so a sub-case re-reads the env
// (same idiom the kvUnifiedModeOnce tests use). Caller pairs it with t.Setenv.
func resetKvLbModeEnv() {
	kvLbModeOnce = sync.Once{}
	kvLbModeResolved = ""
}

// TestKvLbMode proves the precedence matrix: LOXILB_KV_LB_MODE when set to a
// valid value wins; when unset the legacy LOXILB_KV_UNIFIED_MODE maps; garbage
// falls back to "hard" with a warn; and the new var beats the legacy var.
func TestKvLbMode(t *testing.T) {
	tests := []struct {
		name      string
		lbMode    string // "" == unset
		setLbMode bool
		unified   string // "" == unset
		setUni    bool
		want      string
	}{
		{"both unset -> hard (default)", "", false, "", false, "hard"},
		{"lb_mode=off", "off", true, "", false, "off"},
		{"lb_mode=hard", "hard", true, "", false, "hard"},
		{"lb_mode=soft", "soft", true, "", false, "soft"},
		{"lb_mode=garbage -> default hard", "wat", true, "", false, "hard"},
		{"lb_mode unset + unified=0 -> off", "", false, "0", true, "off"},
		{"lb_mode unset + unified=1 -> hard", "", false, "1", true, "hard"},
		{"lb_mode unset + unified=off -> off", "", false, "off", true, "off"},
		{"lb_mode=soft beats unified=0 (precedence)", "soft", true, "0", true, "soft"},
		{"lb_mode=off beats unified=1 (precedence)", "off", true, "1", true, "off"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetKvLbModeEnv()
			if tc.setLbMode {
				t.Setenv("LOXILB_KV_LB_MODE", tc.lbMode)
			} else {
				t.Setenv("LOXILB_KV_LB_MODE", "")
			}
			if tc.setUni {
				t.Setenv("LOXILB_KV_UNIFIED_MODE", tc.unified)
			} else {
				t.Setenv("LOXILB_KV_UNIFIED_MODE", "")
			}
			if got := kvLbMode(); got != tc.want {
				t.Errorf("kvLbMode() = %q, want %q", got, tc.want)
			}
		})
	}
	resetKvLbModeEnv()
}

// TestKvSelectArmDispatch proves kvSelectArm routes each mode to the right
// selector: off → kvArmPureArgmax (never spills), hard → kvUnifiedSelect, soft
// → kvSoftBlendSelect. Uses an over-cap argmax case so the three diverge.
func TestKvSelectArmDispatch(t *testing.T) {
	// ep0 highest overlap but heavily loaded (over cap); ep2 next-best, idle.
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 1000},
		{epIdx: 1, overlap: 3, capacity: 1, load: 0},
		{epIdx: 2, overlap: 7, capacity: 1, load: 0},
	}

	// off → pure argmax (ep0), never spills.
	gotOff, spilledOff := kvSelectArm(cands, "off", 175, 32)
	if gotOff != 0 || spilledOff {
		t.Errorf("off: got ep%d spilled=%v, want ep0 spilled=false", gotOff, spilledOff)
	}

	// hard → kvUnifiedSelect spills off the over-cap argmax to ep2.
	gotHard, spilledHard := kvSelectArm(cands, "hard", 175, 32)
	wantHard, wantSpillHard := kvUnifiedSelect(cands, 175)
	if gotHard != wantHard || spilledHard != wantSpillHard {
		t.Errorf("hard: got (ep%d,%v), want kvUnifiedSelect (ep%d,%v)",
			gotHard, spilledHard, wantHard, wantSpillHard)
	}

	// soft → kvSoftBlendSelect (penalty pushes off the loaded ep0).
	gotSoft, spilledSoft := kvSelectArm(cands, "soft", 175, 32)
	wantSoft, wantSpillSoft := kvSoftBlendSelect(cands, 32)
	if gotSoft != wantSoft || spilledSoft != wantSpillSoft {
		t.Errorf("soft: got (ep%d,%v), want kvSoftBlendSelect (ep%d,%v)",
			gotSoft, spilledSoft, wantSoft, wantSpillSoft)
	}

	// Unexpected mode degrades to hard (the safe load-aware selector).
	gotFallthrough, _ := kvSelectArm(cands, "bogus", 175, 32)
	if gotFallthrough != wantHard {
		t.Errorf("unexpected mode: got ep%d, want hard's ep%d", gotFallthrough, wantHard)
	}
}

// ============================================================================
// (Option B) : kvSoftBlendSelect — continuous penalty-score
// selector (argmin uncached_blocks + λ·load/cap_weight). Capacity-weighted,
// divide-by-zero-safe, monotone in λ, reduces to argmax at zero load.
// ============================================================================

// TestKvSoftZeroLoadIsArgmax: at zero load the soft selector reduces to
// overlap-argmax (argmin uncached == argmax overlap), never spills.
func TestKvSoftZeroLoadIsArgmax(t *testing.T) {
	cands := []kvCandidate{
		{epIdx: 0, overlap: 4, capacity: 2048, load: 0},
		{epIdx: 1, overlap: 9, capacity: 2048, load: 0}, // highest overlap
		{epIdx: 2, overlap: 7, capacity: 2048, load: 0},
	}
	got, spilled := kvSoftBlendSelect(cands, 32)
	if got != 1 {
		t.Errorf("zero-load soft = ep%d, want ep1 (argmax overlap)", got)
	}
	if spilled {
		t.Error("zero-load soft must NOT spill (it IS the argmax)")
	}
}

// TestKvSoftLoadShiftsWinner: a high-overlap EP under rising load eventually
// loses to a lower-overlap idle EP once λ·load exceeds the overlap-block gap.
func TestKvSoftLoadShiftsWinner(t *testing.T) {
	// ep0 overlap 10 (the argmax) but loaded; ep1 overlap 6, idle. Homogeneous
	// capacity 1 (cap_weight 1). promptBlocks = 10.
	//   cost0 = (10-10)*1000 + λ*load0/1 = λ*load0.
	//   cost1 = (10-6)*1000  + λ*0/1     = 4000.
	// With λ=100, load0=50 → cost0=5000 > 4000 → ep1 wins (crossover).
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 50},
		{epIdx: 1, overlap: 6, capacity: 1, load: 0},
	}
	got, spilled := kvSoftBlendSelect(cands, 100)
	if got != 1 {
		t.Errorf("loaded argmax should lose: got ep%d, want ep1 (idle lower-overlap)", got)
	}
	if !spilled {
		t.Error("moving off the overlap-argmax must report spilled=true")
	}

	// Below the crossover (load0=30 → cost0=3000 < 4000) the argmax keeps it.
	cands[0].load = 30
	got2, spilled2 := kvSoftBlendSelect(cands, 100)
	if got2 != 0 || spilled2 {
		t.Errorf("below crossover: got ep%d spilled=%v, want ep0 spilled=false", got2, spilled2)
	}
}

// TestKvSoftMonotonicInLambda: increasing λ never moves the winner BACK toward
// the loaded high-overlap EP — once the idle EP wins at some λ it keeps winning
// for all larger λ.
func TestKvSoftMonotonicInLambda(t *testing.T) {
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 50}, // argmax, loaded
		{epIdx: 1, overlap: 6, capacity: 1, load: 0},   // idle, lower overlap
	}
	// crossover at λ where λ*50 > 4000 → λ > 80.
	wonIdle := false
	for lambda := uint32(1); lambda <= 400; lambda += 1 {
		got, _ := kvSoftBlendSelect(cands, lambda)
		if got == 1 {
			wonIdle = true
		} else if wonIdle {
			// Once the idle EP won, a LARGER λ flipped back to the loaded argmax.
			t.Fatalf("non-monotone: λ=%d moved the winner BACK to the loaded ep0", lambda)
		}
	}
	if !wonIdle {
		t.Error("expected the idle EP to win at large λ (sanity: crossover reachable)")
	}
}

// TestKvSoftCapacityWeighting: a larger-capacity EP is penalized LESS per unit
// load (load/cap_weight), so it absorbs more before losing — it wins where a
// small-cap peer at the same load would have lost.
func TestKvSoftCapacityWeighting(t *testing.T) {
	// ep0 overlap 10 (argmax) load 50 cap 1; ep1 overlap 6 load 50 cap 100.
	// promptBlocks=10.
	//   cost0 = 0      + λ*50/1   = λ*50.
	//   cost1 = 4*1000 + λ*50/100 = 4000 + λ*0 (floor) ≈ 4000.
	// With λ=100: cost0=5000 > 4000 → the large-capacity ep1 wins despite equal
	// raw load, BECAUSE its per-unit-load penalty is 100× smaller.
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 50},
		{epIdx: 1, overlap: 6, capacity: 100, load: 50},
	}
	got, _ := kvSoftBlendSelect(cands, 100)
	if got != 1 {
		t.Errorf("capacity weighting: got ep%d, want ep1 (large cap absorbs load)", got)
	}

	// Contrast: if ep1 were small-capacity (1) too, its load penalty matches and
	// the lower-overlap EP would NOT win (argmax ep0 keeps it).
	cands[1].capacity = 1
	got2, _ := kvSoftBlendSelect(cands, 100)
	// cost0 = λ*50 = 5000; cost1 = 4000 + λ*50 = 9000 → ep0 wins.
	if got2 != 0 {
		t.Errorf("small-cap peer: got ep%d, want ep0 (no capacity advantage)", got2)
	}
}

// TestKvSoftZeroCapacityGuard: a Σcapacity=0 / single-zero-capacity set must not
// panic and must not divide by zero (cap_weight clamped to >=1).
func TestKvSoftZeroCapacityGuard(t *testing.T) {
	cases := [][]kvCandidate{
		nil,
		{{epIdx: 0, overlap: 5, capacity: 0, load: 0}},
		{
			{epIdx: 0, overlap: 10, capacity: 0, load: 100},
			{epIdx: 1, overlap: 5, capacity: 0, load: 100},
		},
	}
	for i, cands := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: kvSoftBlendSelect panicked on zero capacity: %v", i, r)
				}
			}()
			_, _ = kvSoftBlendSelect(cands, 100)
		}()
	}
}

// TestKvSoftTieBreak: equal cost → higher overlap, then lower load, then lowest
// epIdx (deterministic).
func TestKvSoftTieBreak(t *testing.T) {
	// All idle, all capacity 1, all overlap 5 → equal cost (uncached gap 0 each).
	// Tie-break should pick the lowest epIdx among equal overlap+load.
	cands := []kvCandidate{
		{epIdx: 2, overlap: 5, capacity: 1, load: 0},
		{epIdx: 0, overlap: 5, capacity: 1, load: 0},
		{epIdx: 1, overlap: 5, capacity: 1, load: 0},
	}
	got, _ := kvSoftBlendSelect(cands, 100)
	if got != 0 {
		t.Errorf("tie-break = ep%d, want ep0 (lowest epIdx on equal cost)", got)
	}
}

// TestKvSoftMiss: empty set or all-zero-overlap → -1 (Tier-1.5 miss), matching
// the other arms.
func TestKvSoftMiss(t *testing.T) {
	if got, _ := kvSoftBlendSelect(nil, 100); got != -1 {
		t.Errorf("empty soft = ep%d, want -1", got)
	}
	cands := []kvCandidate{
		{epIdx: 0, overlap: 0, capacity: 2048, load: 0},
		{epIdx: 1, overlap: 0, capacity: 2048, load: 0},
	}
	if got, _ := kvSoftBlendSelect(cands, 100); got != -1 {
		t.Errorf("all-zero-overlap soft = ep%d, want -1", got)
	}
}

// TestKvLoadPenaltyResolver proves the λ resolver: default when unset, valid
// in-range value used, out-of-range/garbage → default with warn.
func TestKvLoadPenaltyResolver(t *testing.T) {
	tests := []struct {
		name string
		set  bool
		val  string
		want uint32
	}{
		{"unset -> default", false, "", kvLbDefaultLoadPenalty},
		{"valid", true, "64", 64},
		{"min boundary", true, "1", 1},
		{"max boundary", true, "100000", 100000},
		{"zero -> default", true, "0", kvLbDefaultLoadPenalty},
		{"over max -> default", true, "100001", kvLbDefaultLoadPenalty},
		{"garbage -> default", true, "abc", kvLbDefaultLoadPenalty},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kvLoadPenaltyOnce = sync.Once{}
			kvLoadPenaltyResolved = 0
			if tc.set {
				t.Setenv("LOXILB_KV_LOAD_PENALTY", tc.val)
			} else {
				t.Setenv("LOXILB_KV_LOAD_PENALTY", "")
			}
			if got := kvLoadPenalty(); got != tc.want {
				t.Errorf("kvLoadPenalty() = %d, want %d", got, tc.want)
			}
		})
	}
	kvLoadPenaltyOnce = sync.Once{}
	kvLoadPenaltyResolved = 0
}

// ============================================================================
// (Option B) : hard negligible-cache refinement.
// ============================================================================

// TestKvHardNegligibleCacheRefinement: when the best under-cap candidate has
// overlap <= kvNegligibleOverlap ("no meaningful cache hit"), hard prefers the
// LEAST-LOADED under-cap EP rather than an arbitrary cache-irrelevant pick.
//
// kvNegligibleOverlap is 0 today and the candidate loop filters overlap<=0, so
// the refinement is a guarded no-op for the current threshold; this test pins
// the regression contract that POSITIVE overlaps are NEVER diverted by it.
func TestKvHardNegligibleCacheRefinement(t *testing.T) {
	// All candidates have meaningful (positive) overlap and are genuinely under
	// cap → the refinement must NOT engage; the affinity winner (highest overlap)
	// stands even though it is NOT the least-loaded EP. With mlf=175 and equal
	// capacity, cap_i = ceil(1.75·totalLoad/3) = ceil(1.75·12/3) = 7, so loads
	// {5,4,3} are all < 7 (every EP under cap). ep2 is the least loaded; if the
	// refinement wrongly fired it would divert to ep2 — it must not, because the
	// positive-overlap affinity winner ep1 (overlap 8) is the bounded-load pick.
	cands := []kvCandidate{
		{epIdx: 0, overlap: 2, capacity: 1, load: 5}, // low overlap
		{epIdx: 1, overlap: 8, capacity: 1, load: 4}, // highest overlap, under cap
		{epIdx: 2, overlap: 4, capacity: 1, load: 3}, // least loaded (lure for a bad refinement)
	}
	got, _ := kvUnifiedSelect(cands, 175)
	if got != 1 {
		t.Errorf("positive-overlap winner = ep%d, want ep1 (refinement must not divert)", got)
	}
}

// TestKvHardRefinementNoRegression: every existing TestKvUnified* expected
// winner (all positive overlap) is unchanged by the refinement.
func TestKvHardRefinementNoRegression(t *testing.T) {
	// Mirror TestKvUnifiedAffinityPreservedBelowCap and TestKvUnifiedSpillOnOverflow
	// winners — both have overlap >> kvNegligibleOverlap so neither is diverted.
	below := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 2048, load: 0},
		{epIdx: 1, overlap: 3, capacity: 2048, load: 0},
		{epIdx: 2, overlap: 7, capacity: 2048, load: 0},
	}
	if got, spilled := kvUnifiedSelect(below, 175); got != 0 || spilled {
		t.Errorf("below-cap regression: got (ep%d,%v), want (ep0,false)", got, spilled)
	}
	spill := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 1000},
		{epIdx: 1, overlap: 3, capacity: 1, load: 0},
		{epIdx: 2, overlap: 7, capacity: 1, load: 0},
	}
	if got, spilled := kvUnifiedSelect(spill, 175); got != 2 || !spilled {
		t.Errorf("spill regression: got (ep%d,%v), want (ep2,true)", got, spilled)
	}
}

// mockTokenizer implements KvTokenizer for testing.
type mockTokenizer struct {
	ids []uint32
}

func (m *mockTokenizer) Encode(text string) []uint32 {
	return m.ids
}

func (m *mockTokenizer) Close() {}

// mockBackend implements KvTokenizerBackend for testing.
type mockBackend struct {
	tokenizers map[string]*mockTokenizer
}

func (b *mockBackend) LoadModel(tokenizerPath string) KvTokenizer {
	if t, ok := b.tokenizers[tokenizerPath]; ok {
		return t
	}
	return nil
}

func (b *mockBackend) Name() string { return "mock" }

func TestKvModelSlug(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"meta-llama/Llama-3-8B", "meta-llama__Llama-3-8B"},
		{"gpt-4", "gpt-4"},
		{"org/sub/model", "org__sub__model"},
		{"", ""},
	}

	for _, tc := range tests {
		got := kvModelSlug(tc.input)
		if got != tc.expected {
			t.Errorf("kvModelSlug(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestKvTokenCacheLRU(t *testing.T) {
	// Reset state
	KvTokenCacheReset()
	KvTokenizerPoolReset()
	defer KvTokenCacheReset()
	defer KvTokenizerPoolReset()

	// Reduce cache size for testing
	origMax := kvTokenCacheMax
	kvTokenCacheMax = 3
	defer func() { kvTokenCacheMax = origMax }()

	// Register mock backend with a tokenizer
	backend := &mockBackend{
		tokenizers: map[string]*mockTokenizer{
			"/etc/loxilb/tokenizers/test-model/tokenizer.json": {
				ids: []uint32{100, 200, 300},
			},
		},
	}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	// Fill cache to capacity
	for i := 0; i < 3; i++ {
		text := string(rune('A' + i))
		result := kvTokenizeWithCache(text, "test-model", 100)
		if result == nil {
			t.Fatalf("kvTokenizeWithCache returned nil for text %q", text)
		}
	}

	// Verify cache is full
	kvTokenCacheMu.RLock()
	if len(kvTokenCache) != 3 {
		t.Errorf("cache size = %d, want 3", len(kvTokenCache))
	}
	kvTokenCacheMu.RUnlock()

	// Add one more — should evict the oldest (text "A")
	result := kvTokenizeWithCache("D", "test-model", 100)
	if result == nil {
		t.Fatal("kvTokenizeWithCache returned nil for text D")
	}

	kvTokenCacheMu.RLock()
	if len(kvTokenCache) != 3 {
		t.Errorf("cache size after eviction = %d, want 3", len(kvTokenCache))
	}
	// Check that "A" was evicted (full-text-identity key — see tokenCacheKey)
	slug := kvModelSlug("test-model")
	keyA := kvTokenCacheKeyFor(slug, "A")
	if _, ok := kvTokenCache[keyA]; ok {
		t.Error("expected key A to be evicted from cache")
	}
	kvTokenCacheMu.RUnlock()
}

func TestKvTokenCacheHit(t *testing.T) {
	// Reset state
	KvTokenCacheReset()
	KvTokenizerPoolReset()
	defer KvTokenCacheReset()
	defer KvTokenizerPoolReset()

	// A registered backend is REQUIRED for kvLoadTokenizer to reach the pool fast-path
	// (it returns nil when kvRegisteredBackend == nil, before consulting the pool). The
	// preceding tests leave the backend nil, so register one here — same pattern as the
	// other backend-backed tests. The pool entry below is then what a real load produced.
	KvRegisterTokenizerBackend(&mockBackend{tokenizers: map[string]*mockTokenizer{}})
	defer KvRegisterTokenizerBackend(nil)

	// Track encode calls
	callCount := 0
	mt := &mockTokenizer{ids: []uint32{10, 20, 30}}

	// Inject mock directly into pool
	slug := kvModelSlug("test-model")
	kvTokenizerMu.Lock()
	kvTokenizerPool[slug] = &countingTokenizer{
		inner:     mt,
		callCount: &callCount,
	}
	kvTokenizerMu.Unlock()

	// First call — should call Encode
	result := kvTokenizeWithCache("hello world", "test-model", 100)
	if result == nil || len(result) != 3 {
		t.Fatalf("first call: got %v, want [10,20,30]", result)
	}
	if callCount != 1 {
		t.Errorf("first call: encode called %d times, want 1", callCount)
	}

	// Second call with same text — should hit cache, NOT call Encode
	result = kvTokenizeWithCache("hello world", "test-model", 100)
	if result == nil || len(result) != 3 {
		t.Fatalf("second call: got %v, want [10,20,30]", result)
	}
	if callCount != 1 {
		t.Errorf("second call: encode called %d times, want 1 (cache hit)", callCount)
	}
}

// countingTokenizer wraps a tokenizer and counts Encode calls.
type countingTokenizer struct {
	inner     *mockTokenizer
	callCount *int
}

func (c *countingTokenizer) Encode(text string) []uint32 {
	*c.callCount++
	return c.inner.Encode(text)
}

func (c *countingTokenizer) Close() { c.inner.Close() }

func TestKvLoadTokenizerMissing(t *testing.T) {
	// Reset state
	KvTokenizerPoolReset()
	defer KvTokenizerPoolReset()

	// Register backend that returns nil for all models
	backend := &mockBackend{tokenizers: map[string]*mockTokenizer{}}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	// First call — should return nil
	tok := kvLoadTokenizer("missing-model")
	if tok != nil {
		t.Error("expected nil for missing model")
	}

	// Second call — should still return nil (cached failure, no retry)
	tok = kvLoadTokenizer("missing-model")
	if tok != nil {
		t.Error("expected nil on second call for missing model")
	}
}

func TestKvLoadTokenizerWarnOnce(t *testing.T) {
	// Reset state
	KvTokenizerPoolReset()
	defer KvTokenizerPoolReset()

	backend := &mockBackend{tokenizers: map[string]*mockTokenizer{}}
	KvRegisterTokenizerBackend(backend)
	defer KvRegisterTokenizerBackend(nil)

	slug := kvModelSlug("warn-test-model")

	// Clear the warn map for this model
	kvTokenizerWarnMap.Delete(slug)

	// First call — should set warned flag
	_ = kvLoadTokenizer("warn-test-model")
	if _, warned := kvTokenizerWarnMap.Load(slug); !warned {
		t.Error("expected warn flag to be set after first load failure")
	}
}

func TestKvTokenizeNoBackend(t *testing.T) {
	// Reset state
	KvTokenizerPoolReset()
	KvTokenCacheReset()
	defer KvTokenizerPoolReset()
	defer KvTokenCacheReset()

	// No backend registered
	KvRegisterTokenizerBackend(nil)

	result := kvTokenizeWithCache("hello", "test-model", 100)
	if result != nil {
		t.Errorf("expected nil when no backend registered, got %v", result)
	}
}

func TestKvTokenCacheConcurrent(t *testing.T) {
	// Reset state
	KvTokenCacheReset()
	KvTokenizerPoolReset()
	defer KvTokenCacheReset()
	defer KvTokenizerPoolReset()

	// A registered backend is REQUIRED for kvLoadTokenizer to consult the pool:
	// it short-circuits to nil when kvRegisteredBackend == nil, BEFORE the pool
	// fast-path. The preceding TestKvTokenizeNoBackend leaves the backend nil and
	// does not restore it, so register one here (the pool entry below is then the
	// state a real backend-backed load would have produced). Without this every
	// concurrent call returns nil — a test-ordering artifact, not a production race.
	KvRegisterTokenizerBackend(&mockBackend{tokenizers: map[string]*mockTokenizer{}})
	defer KvRegisterTokenizerBackend(nil)

	// Inject mock tokenizer
	slug := kvModelSlug("concurrent-model")
	kvTokenizerMu.Lock()
	kvTokenizerPool[slug] = &mockTokenizer{ids: []uint32{1, 2, 3}}
	kvTokenizerMu.Unlock()

	// Concurrent access
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			text := string(rune('A' + (idx % 26)))
			result := kvTokenizeWithCache(text, "concurrent-model", 100)
			if result == nil {
				t.Errorf("concurrent call %d returned nil", idx)
			}
		}(i)
	}
	wg.Wait()
}

// ============================================================================
// cross-model overlap false-positive bound.
//
// KV routing is single-model-per-rule today; multi-model-behind-one-rule is
// (deferred). Because block hashes are CONTENT-ADDRESSED (a function
// of the parent-hash chain + token-id stream), the question "do two distinct
// models' block hashes spuriously collide in one shared EP inventory?" is
// EMPIRICAL, not assumable. This test quantifies the rate so the paper + Phase
// 85 can cite a number rather than guess:
//   - a near-zero rate VERIFIES model filtering is NOT needed for the
//     single-model-per-rule baseline (the as-shipped target);
// - a high rate would FAIL here, flagging that multi-model needs a
//     model-discriminator BEFORE it ships.
//
// We mirror the vLLM block-hash contract's KEY property: a block hash is the
// low-64-bits of SHA256 over a canonical encoding of (parent_hash, token_ids).
// Two distinct models = two distinct tokenizers → distinct token-id streams
// for the same prompt → distinct CBOR/bytes → distinct digests. The exact wire
// format (CBOR vs the canonical bytes used here) is NOT load-bearing for a
// COLLISION-rate measurement — only that distinct token streams hash distinctly
// and deterministically (fixed seeds parity).

// TestKvCrossModelOverlapFalsePositiveBound measures the spurious-match rate
// when model-B block hashes are queried against an inventory populated ONLY
// with model-A blocks, and asserts it is within an acceptable bound.
//
// Measured result (deterministic, fixed seeds): 0 spurious matches over 5000
// query blocks ⇒ 0.000% cross-model false-positive rate. This VERIFIES that
// content-addressed 64-bit block hashes from distinct models do NOT collide at
// any meaningful rate, so model filtering is NOT required for the
// single-model-per-rule baseline. (Expected per the birthday bound: for two
// disjoint sets of n≈5000 distinct 64-bit values the expected collision count
// is ≈ n²/2^64 ≈ 1.4e-9 — i.e. effectively zero.) Recorded for the paper +
func TestKvCrossModelOverlapFalsePositiveBound(t *testing.T) {
	const (
		nBlocks   = 5000
		blockSize = 16
		// Acceptable bound: well above the ~1.4e-9 birthday expectation yet far
		// below any rate that would distort routing. A single 64-bit collision
		// over 5000 blocks (rate 2e-4) would still pass; two would fail — a
		// genuine collision problem would produce orders of magnitude more.
		maxFPRate = 0.001 // 0.1%
	)

	modelA := buildModelCorpus(1, nBlocks, blockSize)
	modelB := buildModelCorpus(2, nBlocks, blockSize)

	// Sanity: a model's own hashes MUST fully match its own inventory (proves
	// the hash core is deterministic and the harness wires MatchCount right —
	// guards against a false "0% FP" that is really "0% because nothing matches
	// anything").
	invSelf := newKvInventory()
	invSelf.AddBlocks(modelA)
	if self := invSelf.MatchCount(modelA); self != nBlocks {
		t.Fatalf("self-match sanity failed: model-A matched %d/%d of its own blocks "+
			"(harness/hash-core broken — a 0%% cross-model rate would be meaningless)",
			self, nBlocks)
	}

	// Cross-model: inventory holds ONLY model-A; query with model-B.
	invA := newKvInventory()
	invA.AddBlocks(modelA)
	spurious := invA.MatchCount(modelB)
	fpRate := float64(spurious) / float64(nBlocks)

	t.Logf("cross-model FP: %d spurious matches / %d query blocks = %.6f%% "+
		"(bound %.4f%%) — VERIFIES single-model-per-rule needs no model filter (C3)",
		spurious, nBlocks, fpRate*100, maxFPRate*100)

	if fpRate > maxFPRate {
		t.Errorf("cross-model false-positive rate %.6f exceeds bound %.6f "+
			"(%d/%d) — content-addressed hashes collide across models;"+
			"multi-model needs a model-discriminator BEFORE shipping",
			fpRate, maxFPRate, spurious, nBlocks)
	}
}

// buildModelCorpus produces a deterministic chain of content-addressed 64-bit
// block hashes for a synthetic model identified by modelSeed. It mirrors the
// load-bearing property of the vLLM block-hash contract: each block hash is the
// low-64 bits of SHA256 over a canonical encoding of (parent_hash, token_ids),
// so the hashes form a chain and two DISTINCT models (distinct tokenizers ⇒
// distinct token-id streams for the same prompt) yield distinct, deterministic
// hash chains. The exact wire encoding (CBOR vs the fixed little-endian bytes
// used here) is NOT load-bearing for a collision-RATE measurement — only that
// distinct token streams hash distinctly and reproducibly. Fixed inputs ⇒ fixed
// output (no Math.random/time parity).
// ============================================================================
// the Tier-1.5 selector now reads loxilb's OWN per-EP live
// load + advertised capacity from the C-side pd_ep_loads arrays passed across
// cgo (kv_load[]/kv_cap[]), NOT the dead workerMetrics scraper (which returned
// (0,0) for every EP — blind-blend root cause). These tests drive the
// pure-Go array reader directly (no cgo, no datapath).
// ============================================================================

// TestKvLoadCapFromArraysReturnsPassed proves the candidate loop reads the
// passed (cap,load) for an in-range epIdx — NOT (0,0). This is the regression
// for blind blend: with real per-EP load the cap can actually bind.
func TestKvLoadCapFromArraysReturnsPassed(t *testing.T) {
	load := []uint32{3, 7, 0, 11}
	capa := []uint32{7408, 7408, 7408, 7408}
	for epIdx, wantLoad := range load {
		gotCap, gotLoad := kvLoadCapFromArrays(load, capa, epIdx)
		if gotLoad != wantLoad {
			t.Errorf("epIdx %d: load = %d, want %d", epIdx, gotLoad, wantLoad)
		}
		if gotCap != capa[epIdx] {
			t.Errorf("epIdx %d: cap = %d, want %d", epIdx, gotCap, capa[epIdx])
		}
	}
}

// TestKvLoadCapFromArraysOutOfRange proves a nil/short array or an out-of-range
// epIdx returns (0,0) safely (no panic, no out-of-bounds) — the Tier-2-safe
// degenerate case (bounds-check).
func TestKvLoadCapFromArraysOutOfRange(t *testing.T) {
	load := []uint32{5, 6}
	capa := []uint32{100, 200}
	cases := []struct {
		name       string
		load, capa []uint32
		epIdx      int
	}{
		{"epIdx >= len", load, capa, 2},
		{"epIdx >= len far", load, capa, 99},
		{"negative epIdx", load, capa, -1},
		{"nil load", nil, capa, 0},
		{"nil cap", load, nil, 0},
		{"both nil", nil, nil, 0},
		{"empty slices", []uint32{}, []uint32{}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCap, gotLoad := kvLoadCapFromArrays(tc.load, tc.capa, tc.epIdx)
			if gotCap != 0 || gotLoad != 0 {
				t.Errorf("%s: got (cap=%d, load=%d), want (0,0)", tc.name, gotCap, gotLoad)
			}
		})
	}
}

// TestKvLoadCapMismatchedLenSafe proves that if cap[] and load[] have different
// lengths, each is bounds-checked independently (no cross-slice OOB).
func TestKvLoadCapMismatchedLenSafe(t *testing.T) {
	load := []uint32{1, 2, 3, 4}
	capa := []uint32{500} // shorter than load
	// epIdx 0 is in range for both.
	gotCap, gotLoad := kvLoadCapFromArrays(load, capa, 0)
	if gotLoad != 1 || gotCap != 500 {
		t.Errorf("epIdx 0: got (cap=%d, load=%d), want (500,1)", gotCap, gotLoad)
	}
	// epIdx 2 is in range for load but OOB for cap → cap falls back to 0,
	// load reads 3.
	gotCap, gotLoad = kvLoadCapFromArrays(load, capa, 2)
	if gotLoad != 3 || gotCap != 0 {
		t.Errorf("epIdx 2: got (cap=%d, load=%d), want (0,3)", gotCap, gotLoad)
	}
}

func buildModelCorpus(modelSeed, nBlocks, blockSize int) []uint64 {
	hashes := make([]uint64, nBlocks)
	var parent uint64 // NONE_HASH seed = 0 (chain root)
	buf := make([]byte, 8+8*blockSize)
	for b := 0; b < nBlocks; b++ {
		binary.LittleEndian.PutUint64(buf[0:8], parent)
		for i := 0; i < blockSize; i++ {
			// Token id derived from (modelSeed, block, position). The modelSeed
			// term makes model 1 and model 2 produce disjoint token streams, so
			// their block-hash chains are independent — exactly the "two distinct
			// models" condition under test.
			tok := uint64(modelSeed)*1000003 + uint64(b)*uint64(blockSize) + uint64(i)
			binary.LittleEndian.PutUint64(buf[8+8*i:8+8*i+8], tok)
		}
		sum := sha256.Sum256(buf)
		h := binary.LittleEndian.Uint64(sum[:8])
		hashes[b] = h
		parent = h
	}
	return hashes
}

// ============================================================================
// load-adaptive ε/λ law + adaptive mode gate. These drive the
// PURE-GO accessors (kvAdaptiveMeanLoadFactor / kvAdaptiveLoadPenalty /
// kvAdaptiveEwmaLoad) and the extended kvLbMode/kvSelectArm directly — no cgo —
// asserting the §0.1 calibrated coefficients (floor 175/50000, cap 300/100000,
// anchor 16, sat 26, midpoint L=21 → ε≈237 / λ=75000 — re-fit 2026-06-28 to the
// TRUE [KV_INV] totalLoad; see §0.2).
// ============================================================================

// kvAdaptiveCandsForLoad builds a candidate set whose Σ load == target, spread
// over two EPs (overlap/capacity are irrelevant to the load accessors — they sum
// only c.load). A target of 0 yields an empty set (the Σload==0 floor case).
func kvAdaptiveCandsForLoad(target uint32) []kvCandidate {
	if target == 0 {
		return nil
	}
	a := target / 2
	b := target - a
	return []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 4, load: a},
		{epIdx: 1, overlap: 5, capacity: 4, load: b},
	}
}

// TestKvAdaptiveLawBackCompat proves the low-load floor: Σload≤16 (and empty
// cands) → ε==175 AND λ==50000, byte-identical to the hard/soft defaults. This is
// the §0.1 back-compat guarantee (adaptive at low load == today's behavior). The
// re-fit anchor is 16 (the TRUE rate-1.0 totalLoad), so rate ≈1.0 correctly sits
// at the floor (the §8 rate-1.0 optimum) — L=16 is included to lock that in.
func TestKvAdaptiveLawBackCompat(t *testing.T) {
	for _, load := range []uint32{0, 1, 5, 6, 10, 16} {
		cands := kvAdaptiveCandsForLoad(load)
		if eps := kvAdaptiveMeanLoadFactor(cands); eps != kvUnifiedDefaultMeanLoadFactor {
			t.Errorf("Σload=%d: ε=%d, want floor %d", load, eps, kvUnifiedDefaultMeanLoadFactor)
		}
		if lam := kvAdaptiveLoadPenalty(cands); lam != kvAdaptiveLambdaFloor {
			t.Errorf("Σload=%d: λ=%d, want floor %d", load, lam, kvAdaptiveLambdaFloor)
		}
	}
	// Explicit empty-cands case.
	if eps := kvAdaptiveMeanLoadFactor(nil); eps != kvAdaptiveEpsFloorPct {
		t.Errorf("empty cands: ε=%d, want floor %d", eps, kvAdaptiveEpsFloorPct)
	}
	if lam := kvAdaptiveLoadPenalty(nil); lam != kvAdaptiveLambdaFloor {
		t.Errorf("empty cands: λ=%d, want floor %d", lam, kvAdaptiveLambdaFloor)
	}
}

// TestKvAdaptiveLawCaps proves the high-load cap: Σload≥26 → ε==300 AND
// λ==100000 (the §8 rate-2.0 optimum), clamped flat above saturation.
func TestKvAdaptiveLawCaps(t *testing.T) {
	for _, load := range []uint32{26, 40, 100, 1000} {
		cands := kvAdaptiveCandsForLoad(load)
		if eps := kvAdaptiveMeanLoadFactor(cands); eps != kvAdaptiveEpsCapPct {
			t.Errorf("Σload=%d: ε=%d, want cap %d", load, eps, kvAdaptiveEpsCapPct)
		}
		if lam := kvAdaptiveLoadPenalty(cands); lam != kvAdaptiveLambdaCap {
			t.Errorf("Σload=%d: λ=%d, want cap %d", load, lam, kvAdaptiveLambdaCap)
		}
	}
}

// TestKvAdaptiveLawMidpoint proves the re-fit midpoint L=21 (halfway in the [16,26]
// band): ε==175+(125·5)/10=237 (allow ±1 for the integer-division floor) and
// λ==50000+5000·5=75000 (exact).
func TestKvAdaptiveLawMidpoint(t *testing.T) {
	cands := kvAdaptiveCandsForLoad(21)
	eps := kvAdaptiveMeanLoadFactor(cands)
	if eps < 237 || eps > 238 {
		t.Errorf("Σload=21: ε=%d, want 237±1", eps)
	}
	if lam := kvAdaptiveLoadPenalty(cands); lam != 75000 {
		t.Errorf("Σload=21: λ=%d, want exactly 75000", lam)
	}
}

// TestKvAdaptiveLawMonotonic proves both knobs are non-decreasing in Σload, and
// strictly increasing across the active [16,26] band, per §0.1 (re-fit).
func TestKvAdaptiveLawMonotonic(t *testing.T) {
	loads := []uint32{6, 16, 18, 22, 26, 40}
	var prevEps, prevLam uint32
	for i, load := range loads {
		cands := kvAdaptiveCandsForLoad(load)
		eps := kvAdaptiveMeanLoadFactor(cands)
		lam := kvAdaptiveLoadPenalty(cands)
		if i > 0 {
			if eps < prevEps {
				t.Errorf("ε not monotone: Σload=%d ε=%d < prev %d", load, eps, prevEps)
			}
			if lam < prevLam {
				t.Errorf("λ not monotone: Σload=%d λ=%d < prev %d", load, lam, prevLam)
			}
		}
		prevEps, prevLam = eps, lam
	}
	// Strictly increasing in the band: ε(20) > ε(17), λ(22) > λ(18).
	if kvAdaptiveMeanLoadFactor(kvAdaptiveCandsForLoad(20)) <= kvAdaptiveMeanLoadFactor(kvAdaptiveCandsForLoad(17)) {
		t.Error("ε must strictly increase from L=17 to L=20 in the active band")
	}
	if kvAdaptiveLoadPenalty(kvAdaptiveCandsForLoad(22)) <= kvAdaptiveLoadPenalty(kvAdaptiveCandsForLoad(18)) {
		t.Error("λ must strictly increase from L=18 to L=22 in the active band")
	}
}

// TestKvAdaptiveEwma proves the integer EWMA hysteresis (design §4): first
// observation returns rawL exactly; a single spike moves the smoothed value
// strictly less than the full delta; repeated identical input converges toward rawL.
func TestKvAdaptiveEwma(t *testing.T) {
	key := "svc-test-ewma"
	// First observation seeds with rawL.
	if got := kvAdaptiveEwmaLoad(key, 10); got != 10 {
		t.Fatalf("first observation: got %d, want seed 10", got)
	}
	// A single upward spike to 50: smoothed must move LESS than the full delta
	// (i.e. land strictly between the prev 10 and the spike 50).
	spiked := kvAdaptiveEwmaLoad(key, 50)
	if spiked <= 10 || spiked >= 50 {
		t.Errorf("single spike: smoothed=%d, want strictly in (10,50) — damped by α<1", spiked)
	}
	// Repeated identical input converges toward the steady value (monotone toward 50).
	prev := spiked
	for i := 0; i < 50; i++ {
		cur := kvAdaptiveEwmaLoad(key, 50)
		if cur < prev {
			t.Fatalf("convergence not monotone: step %d cur=%d < prev=%d", i, cur, prev)
		}
		prev = cur
	}
	if prev < 45 { // with α=1/4 it converges to within rounding of 50
		t.Errorf("repeated input 50 did not converge toward 50: settled at %d", prev)
	}
	// Distinct keys are independent (first observation on a fresh key seeds raw).
	if got := kvAdaptiveEwmaLoad("svc-other", 7); got != 7 {
		t.Errorf("independent key: got %d, want seed 7", got)
	}
}

// TestKvLbModeAdaptive proves the mode gate accepts the new adaptive values and
// preserves the legacy default: =adaptive→"adaptive", =adaptive-soft→
// "adaptive-soft", unset→"hard", bogus→"hard". Reuses the resetKvLbModeEnv +
// t.Setenv idiom (no cross-test bleed).
func TestKvLbModeAdaptive(t *testing.T) {
	tests := []struct {
		name   string
		lbMode string // "" == unset
		set    bool
		want   string
	}{
		{"adaptive", "adaptive", true, "adaptive"},
		{"adaptive-soft", "adaptive-soft", true, "adaptive-soft"},
		{"unset still hard", "", false, "hard"},
		{"bogus -> hard", "adaptive-wat", true, "hard"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetKvLbModeEnv()
			if tc.set {
				t.Setenv("LOXILB_KV_LB_MODE", tc.lbMode)
			} else {
				t.Setenv("LOXILB_KV_LB_MODE", "")
			}
			t.Setenv("LOXILB_KV_UNIFIED_MODE", "")
			if got := kvLbMode(); got != tc.want {
				t.Errorf("kvLbMode() = %q, want %q", got, tc.want)
			}
		})
	}
	resetKvLbModeEnv()
}

// TestKvSelectArmAdaptiveDispatch proves kvSelectArm routes the adaptive modes to
// the right underlying selector: "adaptive" matches kvUnifiedSelect (the hard/cap
// path) for the given ε; "adaptive-soft" matches kvSoftBlendSelect for the given
// λ. Uses an over-cap argmax case so the dispatch is observable.
func TestKvSelectArmAdaptiveDispatch(t *testing.T) {
	cands := []kvCandidate{
		{epIdx: 0, overlap: 10, capacity: 1, load: 1000},
		{epIdx: 1, overlap: 3, capacity: 1, load: 0},
		{epIdx: 2, overlap: 7, capacity: 1, load: 0},
	}

	// adaptive → kvUnifiedSelect with the adaptive ε (here a literal 175 to mirror
	// the floor); identical winner to a direct kvUnifiedSelect call.
	gotA, spillA := kvSelectArm(cands, "adaptive", 175, 32)
	wantA, wantSpillA := kvUnifiedSelect(cands, 175)
	if gotA != wantA || spillA != wantSpillA {
		t.Errorf("adaptive: got (ep%d,%v), want kvUnifiedSelect (ep%d,%v)",
			gotA, spillA, wantA, wantSpillA)
	}

	// adaptive-soft → kvSoftBlendSelect with the adaptive λ; identical winner to a
	// direct kvSoftBlendSelect call.
	gotS, spillS := kvSelectArm(cands, "adaptive-soft", 175, 50000)
	wantS, wantSpillS := kvSoftBlendSelect(cands, 50000)
	if gotS != wantS || spillS != wantSpillS {
		t.Errorf("adaptive-soft: got (ep%d,%v), want kvSoftBlendSelect (ep%d,%v)",
			gotS, spillS, wantS, wantSpillS)
	}
}

// ============================================================================
// plan 03: Σcapacity normalization of the
// adaptive ε/λ load band — the fix for the memo'd capacity-blindness
//. The law's magnitude key becomes
// L′ = L × (capRef / capActual) when BOTH the calibration ref (const, plan
// fills it) and LOXILB_KV_CAP_SUM_MILLI are set; otherwise the raw path
// is taken with ZERO arithmetic (byte-identical). These tests execute at
// the wave-4 remote gate: `go test ./pkg/loxinet/ -run TestKvAdaptive`
// — pkg/loxinet is CGO and cannot run on darwin.
// ============================================================================

// resetKvCapNormEnv resets the kvCapActualMilli once-guard AND restores the
// effective calibration ref to the shipped const so a sub-case re-reads the
// env (the resetKvLbModeEnv idiom). Caller pairs it with t.Setenv.
func resetKvCapNormEnv() {
	kvCapActualOnce = sync.Once{}
	kvCapActualResolvedMilli = 0
	kvCapRefMilli = kvAdaptiveCapRefMilli
}

// setKvCapNormForTest injects a TEST calibration ref (the shipped
// kvAdaptiveCapRefMilli is the placeholder 0 until sweep) and points
// the env at capActual, resetting the once-guard so the next accessor call
// re-resolves. Cleanup restores the shipped default-OFF state.
func setKvCapNormForTest(t *testing.T, refMilli uint64, capActual string) {
	t.Helper()
	resetKvCapNormEnv()
	kvCapRefMilli = refMilli
	t.Setenv("LOXILB_KV_CAP_SUM_MILLI", capActual)
	t.Cleanup(resetKvCapNormEnv)
}

// kvAdaptiveLawExpected is the LOCKED shipped-law table — an INDEPENDENT
// integer re-derivation of §0.1 (floor 175/50000 at L≤16, cap 300/100000 at
// L≥26, slopes 12.5/5000 per unit in the band). The assertions
// compare the accessors against THIS, not against themselves, so a law drift
// and a normalization bug cannot cancel out.
func kvAdaptiveLawExpected(l uint64) (eps uint32, lam uint32) {
	if l <= 16 {
		return 175, 50000
	}
	if l >= 26 {
		return 300, 100000
	}
	d := l - 16
	return uint32(175 + (125*d)/10), uint32(50000 + 5000*d)
}

// kvCapNormTestRefMilli is the injected test calibration ref: 5,000,000 milli
// (an arbitrary round anchor-fleet Σcapacity stand-in — scenarios only
// exercise RATIOS against it, so its absolute value is irrelevant).
const kvCapNormTestRefMilli uint64 = 5_000_000

// TestKvAdaptiveCapNormD07ByteIdentical proves both ways:
// (a) env UNSET ⇒ the raw no-arithmetic path is taken (asserted STRUCTURALLY
// via kvCapNormEnabled, not output equality alone) and both accessors match
// the locked law table over L ∈ {0..30, 100};
// (b) env set to EXACTLY the ref ⇒ factor is exactly 1 ⇒ outputs identical to
// the unset run (integer rounding cannot bite at factor 1).
func TestKvAdaptiveCapNormD07ByteIdentical(t *testing.T) {
	loads := make([]uint32, 0, 32)
	for l := uint32(0); l <= 30; l++ {
		loads = append(loads, l)
	}
	loads = append(loads, 100)

	t.Run("unset env — raw path, locked tables", func(t *testing.T) {
		resetKvCapNormEnv()
		t.Setenv("LOXILB_KV_CAP_SUM_MILLI", "")
		t.Cleanup(resetKvCapNormEnv)
		if kvCapNormEnabled() {
			t.Fatal(": kvCapNormEnabled must be false with LOXILB_KV_CAP_SUM_MILLI unset — the arithmetic path must be SKIPPED")
		}
		for _, l := range loads {
			cands := kvAdaptiveCandsForLoad(l)
			wantEps, wantLam := kvAdaptiveLawExpected(uint64(l))
			if eps := kvAdaptiveMeanLoadFactor(cands); eps != wantEps {
				t.Errorf("unset: Σload=%d ε=%d, want locked %d", l, eps, wantEps)
			}
			if lam := kvAdaptiveLoadPenalty(cands); lam != wantLam {
				t.Errorf("unset: Σload=%d λ=%d, want locked %d", l, lam, wantLam)
			}
		}
	})

	t.Run("env == ref — factor exactly 1, outputs identical", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "5000000")
		if !kvCapNormEnabled() {
			t.Fatal("kvCapNormEnabled() must be true with ref and env both set (ref==actual)")
		}
		for _, l := range loads {
			cands := kvAdaptiveCandsForLoad(l)
			wantEps, wantLam := kvAdaptiveLawExpected(uint64(l))
			if eps := kvAdaptiveMeanLoadFactor(cands); eps != wantEps {
				t.Errorf("ref==actual: Σload=%d ε=%d, want %d (factor 1 must be output-identical)", l, eps, wantEps)
			}
			if lam := kvAdaptiveLoadPenalty(cands); lam != wantLam {
				t.Errorf("ref==actual: Σload=%d λ=%d, want %d (factor 1 must be output-identical)", l, lam, wantLam)
			}
		}
	})
}

// TestKvAdaptiveCapNormD08ResizedFleet proves semantics on three fleet
// scenarios (simulation): equal PER-CAPACITY load must produce identical
// ε/λ across the reference, doubled, and shrunk fleets — and the UN-normalized
// law must demonstrably mis-fire at those same raw loads (memo
// defect, regression-locked in BOTH directions).
func TestKvAdaptiveCapNormD08ResizedFleet(t *testing.T) {
	t.Run("scenario A — reference fleet, factor 1", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "5000000")
		// Law hits the ε/λ floor at L=16 and the cap at L=26 (the shipped anchors).
		if eps := kvAdaptiveMeanLoadFactor(kvAdaptiveCandsForLoad(16)); eps != 175 {
			t.Errorf("A: L=16 ε=%d, want floor 175", eps)
		}
		if lam := kvAdaptiveLoadPenalty(kvAdaptiveCandsForLoad(16)); lam != 50000 {
			t.Errorf("A: L=16 λ=%d, want floor 50000", lam)
		}
		if eps := kvAdaptiveMeanLoadFactor(kvAdaptiveCandsForLoad(17)); eps <= 175 {
			t.Errorf("A: L=17 ε=%d, want > floor (band entry)", eps)
		}
		if eps := kvAdaptiveMeanLoadFactor(kvAdaptiveCandsForLoad(26)); eps != 300 {
			t.Errorf("A: L=26 ε=%d, want cap 300", eps)
		}
		if lam := kvAdaptiveLoadPenalty(kvAdaptiveCandsForLoad(26)); lam != 100000 {
			t.Errorf("A: L=26 λ=%d, want cap 100000", lam)
		}
	})

	t.Run("scenario B — doubled fleet, factor 1/2", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "10000000")
		if !kvCapNormEnabled() {
			t.Fatal("B: normalization must be enabled")
		}
		// Equal per-capacity load: raw L on the doubled fleet ≡ L/2 on the
		// reference fleet. Floor now needs raw 32, cap raw 52.
		pairs := []struct{ rawB, refEquiv uint32 }{
			{32, 16}, {34, 17}, {42, 21}, {52, 26}, {60, 30},
		}
		for _, p := range pairs {
			wantEps, wantLam := kvAdaptiveLawExpected(uint64(p.refEquiv))
			cands := kvAdaptiveCandsForLoad(p.rawB)
			if eps := kvAdaptiveMeanLoadFactor(cands); eps != wantEps {
				t.Errorf("B: raw=%d (≡ref %d) ε=%d, want %d (equal per-capacity load must match scenario A)",
					p.rawB, p.refEquiv, eps, wantEps)
			}
			if lam := kvAdaptiveLoadPenalty(cands); lam != wantLam {
				t.Errorf("B: raw=%d (≡ref %d) λ=%d, want %d", p.rawB, p.refEquiv, lam, wantLam)
			}
		}
	})

	t.Run("B mis-fire lock — un-normalized law over-reacts at raw 32", func(t *testing.T) {
		// The memo defect: WITHOUT normalization, raw 32 on a doubled
		// fleet (really anchor-equivalent per-capacity load ⇒ should be at the
		// floor) drives the law to its CAP — the mis-fire this plan fixes.
		resetKvCapNormEnv()
		t.Setenv("LOXILB_KV_CAP_SUM_MILLI", "")
		t.Cleanup(resetKvCapNormEnv)
		cands := kvAdaptiveCandsForLoad(32)
		if eps := kvAdaptiveMeanLoadFactor(cands); eps != 300 {
			t.Errorf("un-normalized raw=32: ε=%d, want mis-fired cap 300 (regression lock on the memo defect)", eps)
		}
		if lam := kvAdaptiveLoadPenalty(cands); lam != 100000 {
			t.Errorf("un-normalized raw=32: λ=%d, want mis-fired cap 100000", lam)
		}
	})

	t.Run("scenario C — shrunk fleet, factor 2", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "2500000")
		if !kvCapNormEnabled() {
			t.Fatal("C: normalization must be enabled")
		}
		// Equal per-capacity load: raw L on the half fleet ≡ 2L on the
		// reference fleet. Floor edge at raw 8, cap at raw 13.
		pairs := []struct{ rawC, refEquiv uint32 }{
			{8, 16}, {10, 20}, {13, 26}, {20, 40},
		}
		for _, p := range pairs {
			wantEps, wantLam := kvAdaptiveLawExpected(uint64(p.refEquiv))
			cands := kvAdaptiveCandsForLoad(p.rawC)
			if eps := kvAdaptiveMeanLoadFactor(cands); eps != wantEps {
				t.Errorf("C: raw=%d (≡ref %d) ε=%d, want %d (equal per-capacity load must match scenario A)",
					p.rawC, p.refEquiv, eps, wantEps)
			}
			if lam := kvAdaptiveLoadPenalty(cands); lam != wantLam {
				t.Errorf("C: raw=%d (≡ref %d) λ=%d, want %d", p.rawC, p.refEquiv, lam, wantLam)
			}
		}
	})

	t.Run("C mis-fire lock — un-normalized law under-reacts at raw 13", func(t *testing.T) {
		// Symmetric defect: raw 13 on a half-capacity fleet is really
		// saturation-equivalent per-capacity load (⇒ should be at the CAP),
		// but the un-normalized law sits at the floor.
		resetKvCapNormEnv()
		t.Setenv("LOXILB_KV_CAP_SUM_MILLI", "")
		t.Cleanup(resetKvCapNormEnv)
		cands := kvAdaptiveCandsForLoad(13)
		if eps := kvAdaptiveMeanLoadFactor(cands); eps != 175 {
			t.Errorf("un-normalized raw=13: ε=%d, want mis-fired floor 175 (regression lock, other direction)", eps)
		}
		if lam := kvAdaptiveLoadPenalty(cands); lam != 50000 {
			t.Errorf("un-normalized raw=13: λ=%d, want mis-fired floor 50000", lam)
		}
	})
}

// TestKvAdaptiveCapNormClampGuard proves fat-finger guard:
// an env yielding a normalization factor OUTSIDE [1/8, 8] disables
// normalization outright (raw outputs, predicate false); the exact [1/8, 8]
// boundaries stay ENABLED; garbage/zero parse-or-disable; the SHIPPED
// calibrated ref (: 15284310 milli) stays OFF without the env and
// is exactly factor-1/raw-identical with the matching env (today's fleet).
func TestKvAdaptiveCapNormClampGuard(t *testing.T) {
	// Midpoint L=21 raw expectation (237/75000) — the sentinel that proves the
	// disabled paths emit RAW law outputs.
	const sentinelLoad = 21
	wantEps, wantLam := kvAdaptiveLawExpected(sentinelLoad)

	assertDisabledRaw := func(t *testing.T, label string) {
		t.Helper()
		if kvCapNormEnabled() {
			t.Fatalf("%s: kvCapNormEnabled() must be false", label)
		}
		cands := kvAdaptiveCandsForLoad(sentinelLoad)
		if eps := kvAdaptiveMeanLoadFactor(cands); eps != wantEps {
			t.Errorf("%s: Σload=%d ε=%d, want raw %d", label, sentinelLoad, eps, wantEps)
		}
		if lam := kvAdaptiveLoadPenalty(cands); lam != wantLam {
			t.Errorf("%s: Σload=%d λ=%d, want raw %d", label, sentinelLoad, lam, wantLam)
		}
	}

	t.Run("factor 16 > 8 — disabled", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "312500") // ref/16
		assertDisabledRaw(t, "factor 16")
	})
	t.Run("factor 1/16 < 1/8 — disabled", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "80000000") // ref×16
		assertDisabledRaw(t, "factor 1/16")
	})
	t.Run("boundary factor exactly 8 — enabled", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "625000") // ref/8
		if !kvCapNormEnabled() {
			t.Fatal("factor exactly 8 must stay ENABLED (clamp is on OUTSIDE [1/8,8])")
		}
		// raw 2 → L′=16 → floor; raw 3 → L′=24 → in-band 275/90000.
		if eps := kvAdaptiveMeanLoadFactor(kvAdaptiveCandsForLoad(2)); eps != 175 {
			t.Errorf("factor 8: raw=2 ε=%d, want floor 175 (L′=16)", eps)
		}
		if eps := kvAdaptiveMeanLoadFactor(kvAdaptiveCandsForLoad(3)); eps != 275 {
			t.Errorf("factor 8: raw=3 ε=%d, want 275 (L′=24)", eps)
		}
		if lam := kvAdaptiveLoadPenalty(kvAdaptiveCandsForLoad(3)); lam != 90000 {
			t.Errorf("factor 8: raw=3 λ=%d, want 90000 (L′=24)", lam)
		}
	})
	t.Run("boundary factor exactly 1/8 — enabled", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "40000000") // ref×8
		if !kvCapNormEnabled() {
			t.Fatal("factor exactly 1/8 must stay ENABLED (clamp is on OUTSIDE [1/8,8])")
		}
		// raw 128 → L′=16 → floor; raw 168 → L′=21 → 237/75000; raw 208 → L′=26 → cap.
		if eps := kvAdaptiveMeanLoadFactor(kvAdaptiveCandsForLoad(128)); eps != 175 {
			t.Errorf("factor 1/8: raw=128 ε=%d, want floor 175 (L′=16)", eps)
		}
		if eps := kvAdaptiveMeanLoadFactor(kvAdaptiveCandsForLoad(168)); eps != 237 {
			t.Errorf("factor 1/8: raw=168 ε=%d, want 237 (L′=21)", eps)
		}
		if lam := kvAdaptiveLoadPenalty(kvAdaptiveCandsForLoad(208)); lam != 100000 {
			t.Errorf("factor 1/8: raw=208 λ=%d, want cap 100000 (L′=26)", lam)
		}
	})
	t.Run("garbage env — parse-or-disable", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "wat")
		assertDisabledRaw(t, "garbage")
	})
	t.Run("zero env — parse-or-disable", func(t *testing.T) {
		setKvCapNormForTest(t, kvCapNormTestRefMilli, "0")
		assertDisabledRaw(t, "zero")
	})
	t.Run("shipped calibrated ref + unset env — still disabled", func(t *testing.T) {
		// The sweep filled kvAdaptiveCapRefMilli with the calibrated
		// anchor-fleet Σ. Without the operator env the unset path must STILL
		// be byte-identical raw law (default-OFF survives the backfill).
		resetKvCapNormEnv() // ref back to the shipped const; env stays unset
		t.Cleanup(resetKvCapNormEnv)
		if kvAdaptiveCapRefMilli != 15284310 {
			t.Fatalf("shipped ref = %d, want calibrated 15284310", kvAdaptiveCapRefMilli)
		}
		assertDisabledRaw(t, "calibrated ref, unset env")
	})
	t.Run("shipped calibrated ref + matching env — factor 1, raw-identical", func(t *testing.T) {
		// Today's deployment IS the anchor fleet: env == ref ⇒ factor exactly
		// 1.0 ⇒ L′ = L, so ENABLED normalization must emit byte-identical law
		// outputs (the "factor exactly 1 today" contract).
		resetKvCapNormEnv()
		t.Setenv("LOXILB_KV_CAP_SUM_MILLI", "15284310")
		t.Cleanup(resetKvCapNormEnv)
		if !kvCapNormEnabled() {
			t.Fatal("factor-1 normalization must be ENABLED")
		}
		cands := kvAdaptiveCandsForLoad(sentinelLoad)
		if eps := kvAdaptiveMeanLoadFactor(cands); eps != wantEps {
			t.Errorf("factor-1: ε=%d, want raw-identical %d", eps, wantEps)
		}
		if lam := kvAdaptiveLoadPenalty(cands); lam != wantLam {
			t.Errorf("factor-1: λ=%d, want raw-identical %d", lam, wantLam)
		}
	})
}

// ============================================================================
// Long-context token-cache identity
// ============================================================================
// The cache key MUST identify the FULL text. The original key (modelSlug +
// text[:512]) collided for the long-context coding-assistant workload: two
// prompts sharing a >=512-byte preamble (same system prompt + repo header,
// divergent tail) returned each other's token ids, so the block-hash chain
// hashed the WRONG request and Tier-1.5 mis-routed. This test drives two such
// prompts through kvTokenizeWithCache with a content-sensitive tokenizer and
// requires distinct ids (it FAILS against the prefix key: the second lookup
// hits the first entry and returns identical ids).

// contentTokenizer derives ids from the text bytes, so two different texts can
// never legitimately produce the same id stream (unlike mockTokenizer's fixed
// ids, which would mask a cache-identity collision).
type contentTokenizer struct{}

func (c *contentTokenizer) Encode(text string) []uint32 {
	sum := sha256.Sum256([]byte(text))
	ids := make([]uint32, 8)
	for i := range ids {
		ids[i] = binary.BigEndian.Uint32(sum[i*4 : i*4+4])
	}
	return ids
}

func (c *contentTokenizer) Close() {}

type contentBackend struct{}

func (b *contentBackend) LoadModel(tokenizerPath string) KvTokenizer { return &contentTokenizer{} }
func (b *contentBackend) Name() string                               { return "content-mock" }

func TestKvTokenCacheLongPromptNoCollision(t *testing.T) {
	KvTokenCacheReset()
	KvTokenizerPoolReset()
	defer KvTokenCacheReset()
	defer KvTokenizerPoolReset()

	KvRegisterTokenizerBackend(&contentBackend{})
	defer KvRegisterTokenizerBackend(nil)

	// Shared 600-byte preamble (> the old 512-byte key window), divergent tails —
	// the coding-assistant shared-prefix shape.
	head := make([]byte, 600)
	for i := range head {
		head[i] = byte('a' + i%26)
	}
	textA := string(head) + "\nfunc tailA() { return 1 }\n"
	textB := string(head) + "\nfunc tailB() { completely different suffix }\n"

	idsA := kvTokenizeWithCache(textA, "test-model", 100)
	idsB := kvTokenizeWithCache(textB, "test-model", 100)
	if idsA == nil || idsB == nil {
		t.Fatal("tokenize returned nil")
	}

	same := len(idsA) == len(idsB)
	if same {
		for i := range idsA {
			if idsA[i] != idsB[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Fatalf("cache-identity collision: two long prompts sharing a 600-byte head returned IDENTICAL token ids (%v) — the cache key does not cover the full text", idsA)
	}

	// Both texts must occupy distinct cache entries.
	kvTokenCacheMu.RLock()
	n := len(kvTokenCache)
	kvTokenCacheMu.RUnlock()
	if n != 2 {
		t.Errorf("cache entries = %d, want 2 (one per distinct full text)", n)
	}

	// And a genuine repeat must still HIT (identical ids for identical text).
	idsA2 := kvTokenizeWithCache(textA, "test-model", 100)
	if len(idsA2) != len(idsA) {
		t.Fatalf("repeat lookup length mismatch: %d vs %d", len(idsA2), len(idsA))
	}
	for i := range idsA {
		if idsA2[i] != idsA[i] {
			t.Fatalf("repeat lookup returned different ids at %d", i)
		}
	}
}
