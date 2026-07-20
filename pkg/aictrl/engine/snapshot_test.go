/*
 * Copyright (c) 2026 LoxiLB Authors
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

package engine

import (
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/aictrl"
)

func convergedWeights() map[string]uint32 {
	return map[string]uint32{
		"10.0.0.7": 50, "10.0.0.8": 50, "10.0.0.9": 50,
		"10.0.0.11": 100, "10.0.0.10": 100,
	}
}

func allNeutral() map[string]uint32 {
	return map[string]uint32{
		"10.0.0.7": 100, "10.0.0.8": 100, "10.0.0.9": 100,
		"10.0.0.11": 100, "10.0.0.10": 100,
	}
}

// TestSnapshotEpochMonotonicAndShape: epochs are strictly monotonic across
// output changes; every emission carries the SotW shape (all 5 EPs in
// ep_idx order, correct addresses/roles, default-ACTIVE states).
func TestSnapshotEpochMonotonicAndShape(t *testing.T) {
	reg := fleetRegistry()
	g := NewGenerator(reg, GeneratorConfig{})
	now := testNow

	s1 := g.Maybe(now, allNeutral(), nil, false)
	if s1 == nil {
		t.Fatal("first emission suppressed")
	}
	if s1.GetEpoch() != 1 {
		t.Fatalf("first epoch = %d, want 1", s1.GetEpoch())
	}

	now = now.Add(10 * time.Second)
	s2 := g.Maybe(now, convergedWeights(), nil, false) // output changed
	if s2 == nil {
		t.Fatal("changed output after min-gap suppressed")
	}
	if s2.GetEpoch() != 2 {
		t.Fatalf("second epoch = %d, want 2 (strictly monotonic)", s2.GetEpoch())
	}
	if s1.GetNonce() == s2.GetNonce() || len(s2.GetNonce()) == 0 {
		t.Fatalf("nonces not fresh: %q vs %q", s1.GetNonce(), s2.GetNonce())
	}

	// SotW shape: one service, all 5 EPs, ep_idx order 0..4.
	if len(s2.GetServices()) != 1 {
		t.Fatalf("services = %d, want 1", len(s2.GetServices()))
	}
	svc := s2.GetServices()[0]
	if svc.GetServiceKey() != "10.0.0.12:9003:tcp" {
		t.Fatalf("service_key = %q", svc.GetServiceKey())
	}
	if len(svc.GetEps()) != 5 {
		t.Fatalf("eps = %d, want 5 (SotW: every EP, every time)", len(svc.GetEps()))
	}
	wantAddr := []string{"10.0.0.7:8100", "10.0.0.8:8100", "10.0.0.9:8100",
		"10.0.0.11:8100", "10.0.0.10:8200"}
	wantW := []uint32{50, 50, 50, 100, 100}
	for i, ep := range svc.GetEps() {
		if ep.GetEpIdx() != uint32(i) {
			t.Fatalf("eps[%d].ep_idx = %d (want registry ep_idx order)", i, ep.GetEpIdx())
		}
		if ep.GetEpAddr() != wantAddr[i] {
			t.Fatalf("eps[%d].ep_addr = %q, want %q", i, ep.GetEpAddr(), wantAddr[i])
		}
		if ep.GetWeight() != wantW[i] {
			t.Fatalf("eps[%d].weight = %d, want %d", i, ep.GetWeight(), wantW[i])
		}
		if ep.GetState() != aictrl.EpState_EP_STATE_ACTIVE {
			t.Fatalf("eps[%d].state = %v, want ACTIVE (v1 default)", i, ep.GetState())
		}
		wantRole := aictrl.Role_ROLE_PREFILL
		if i == 4 {
			wantRole = aictrl.Role_ROLE_DECODE
		}
		if ep.GetRole() != wantRole {
			t.Fatalf("eps[%d].role = %v, want %v", i, ep.GetRole(), wantRole)
		}
	}
}

// TestSnapshotChurnGuardAndReanchor (P6 + liveness fix): identical
// output FASTER than one epoch (MinEpochGap) is suppressed as churn; but with
// the corrected default (ReanchorEvery == EpochPeriod) an IDENTICAL SotW MUST
// re-emit every epoch as the applier LIVENESS HEARTBEAT — each emission
// refreshes the staleness deadline so a healthy but steady-state controller
// never lets appliers decay to Autonomous. (The prior 60s re-anchor against a
// 30s deadline guaranteed that false-Autonomous oscillation.)
func TestSnapshotChurnGuardAndReanchor(t *testing.T) {
	reg := fleetRegistry()
	g := NewGenerator(reg, GeneratorConfig{}) // defaults: EpochPeriod=MinEpochGap=ReanchorEvery=10s
	now := testNow
	w := convergedWeights()

	if g.Maybe(now, w, nil, false) == nil {
		t.Fatal("first emission suppressed")
	}
	// Churn guard: identical output FASTER than one epoch (MinEpochGap) is
	// suppressed and consumes no epoch.
	if s := g.Maybe(now.Add(5*time.Second), w, nil, false); s != nil {
		t.Fatal("identical output at +5s emitted (churn guard broken)")
	}
	// Heartbeat re-anchor: at one epoch the identical SotW re-emits so the
	// applier's staleness deadline is refreshed (no false Autonomous decay).
	reanchor := g.Maybe(now.Add(10*time.Second), w, nil, false)
	if reanchor == nil {
		t.Fatal("re-anchor heartbeat at +10s (one epoch) not emitted — a healthy controller would decay appliers to Autonomous")
	}
	if reanchor.GetEpoch() != 2 {
		t.Fatalf("re-anchor epoch = %d, want 2 (the +5s churn suppression consumes no epoch)",
			reanchor.GetEpoch())
	}
	// Identical CONTENT: same weights per EP.
	for i, ep := range reanchor.GetServices()[0].GetEps() {
		if ep.GetWeight() != []uint32{50, 50, 50, 100, 100}[i] {
			t.Fatalf("re-anchor eps[%d].weight = %d changed", i, ep.GetWeight())
		}
	}
	// The heartbeat is PERIODIC (not a one-shot): the next epoch re-emits again.
	if s := g.Maybe(now.Add(20*time.Second), w, nil, false); s == nil {
		t.Fatal("second heartbeat at +20s suppressed — the re-anchor must fire every epoch")
	}
}

// TestSnapshotMinEpochGap: the min inter-epoch interval is enforced EVEN
// when the output changes.
func TestSnapshotMinEpochGap(t *testing.T) {
	reg := fleetRegistry()
	g := NewGenerator(reg, GeneratorConfig{})
	now := testNow

	if g.Maybe(now, allNeutral(), nil, false) == nil {
		t.Fatal("first emission suppressed")
	}
	// Output CHANGES 5s later — still inside the 10s gap ⇒ nil.
	if s := g.Maybe(now.Add(5*time.Second), convergedWeights(), nil, false); s != nil {
		t.Fatalf("changed output inside MinEpochGap emitted (epoch %d)", s.GetEpoch())
	}
	// At the gap boundary the change goes out.
	s := g.Maybe(now.Add(10*time.Second), convergedWeights(), nil, false)
	if s == nil {
		t.Fatal("changed output at MinEpochGap suppressed")
	}
	if s.GetEpoch() != 2 {
		t.Fatalf("epoch = %d, want 2", s.GetEpoch())
	}
}

// TestSnapshotFleetStaleStops (CTRL-02): fleetStale ⇒ nil ALWAYS — even
// when a first emission or a re-anchor would otherwise be due.
func TestSnapshotFleetStaleStops(t *testing.T) {
	reg := fleetRegistry()
	g := NewGenerator(reg, GeneratorConfig{})
	now := testNow

	if s := g.Maybe(now, allNeutral(), nil, true); s != nil {
		t.Fatal("fleet-stale first call emitted")
	}
	if g.Maybe(now, allNeutral(), nil, false) == nil {
		t.Fatal("recovery emission suppressed")
	}
	// Long after the re-anchor is due, staleness still stops emission.
	if s := g.Maybe(now.Add(10*time.Minute), allNeutral(), nil, true); s != nil {
		t.Fatal("fleet-stale re-anchor emitted")
	}
	if g.Epoch() != 1 {
		t.Fatalf("epoch advanced under staleness: %d", g.Epoch())
	}
}

// TestSnapshotDeadline: staleness_deadline = now + 3×epoch_period
// (30s at the default seeded from the registry).
func TestSnapshotDeadline(t *testing.T) {
	reg := fleetRegistry()
	g := NewGenerator(reg, GeneratorConfig{})
	s := g.Maybe(testNow, allNeutral(), nil, false)
	if s == nil {
		t.Fatal("emission suppressed")
	}
	want := uint64(testNow.Add(30 * time.Second).UnixMilli())
	if s.GetStalenessDeadlineUnixMs() != want {
		t.Fatalf("deadline = %d, want %d (now+30s)", s.GetStalenessDeadlineUnixMs(), want)
	}
}

// TestSnapshotBootID: constant across epochs of one Generator, different
// across Generator instances (controller restart ⇒ fresh acceptance floor).
func TestSnapshotBootID(t *testing.T) {
	reg := fleetRegistry()
	g1 := NewGenerator(reg, GeneratorConfig{})
	g2 := NewGenerator(reg, GeneratorConfig{})
	if g1.BootID() == "" || g1.BootID() == g2.BootID() {
		t.Fatalf("boot_ids not distinct per instance: %q vs %q", g1.BootID(), g2.BootID())
	}
	s1 := g1.Maybe(testNow, allNeutral(), nil, false)
	s2 := g1.Maybe(testNow.Add(10*time.Second), convergedWeights(), nil, false)
	if s1.GetBootId() != g1.BootID() || s2.GetBootId() != g1.BootID() {
		t.Fatalf("boot_id drifted across epochs: %q, %q, %q",
			g1.BootID(), s1.GetBootId(), s2.GetBootId())
	}
}

// TestSnapshotAcceptedByValidateSnapshot: cross-package consistency — what
// the generator emits, applier's V5 validation accepts (and the
// epoch sequence keeps validating as the applier's floor advances).
func TestSnapshotAcceptedByValidateSnapshot(t *testing.T) {
	reg := fleetRegistry()
	g := NewGenerator(reg, GeneratorConfig{})
	known := map[string][]uint32{"10.0.0.12:9003:tcp": {0, 1, 2, 3, 4}}
	decay := 30 * time.Second

	now := testNow
	s1 := g.Maybe(now, allNeutral(), nil, false)
	if s1 == nil {
		t.Fatal("emission suppressed")
	}
	if err := aictrl.ValidateSnapshot(s1, known, "", 0, now, decay); err != nil {
		t.Fatalf("applier rejected generator output: %v", err)
	}

	now = now.Add(10 * time.Second)
	s2 := g.Maybe(now, convergedWeights(), nil, false)
	if s2 == nil {
		t.Fatal("second emission suppressed")
	}
	if err := aictrl.ValidateSnapshot(s2, known,
		s1.GetBootId(), s1.GetEpoch(), now, decay); err != nil {
		t.Fatalf("applier rejected epoch-2 snapshot: %v", err)
	}

	// And the replay direction still trips: re-validating epoch 1 after
	// accepting epoch 2 must fail.
	if err := aictrl.ValidateSnapshot(s1, known,
		s2.GetBootId(), s2.GetEpoch(), now, decay); err == nil {
		t.Fatal("stale epoch re-accepted — replay rule broken")
	}
}

// TestSnapshotInjectedStates: operator/harness-injected DRAINING/DISABLED
// states pass through (applies-and-exports scope; G1-inert single decode).
func TestSnapshotInjectedStates(t *testing.T) {
	reg := fleetRegistry()
	g := NewGenerator(reg, GeneratorConfig{})
	states := map[string]aictrl.EpState{
		"10.0.0.8":  aictrl.EpState_EP_STATE_DRAINING,
		"10.0.0.11": aictrl.EpState_EP_STATE_DISABLED,
	}
	s := g.Maybe(testNow, allNeutral(), states, false)
	if s == nil {
		t.Fatal("emission suppressed")
	}
	got := map[uint32]aictrl.EpState{}
	for _, ep := range s.GetServices()[0].GetEps() {
		got[ep.GetEpIdx()] = ep.GetState()
	}
	if got[1] != aictrl.EpState_EP_STATE_DRAINING {
		t.Fatalf("ep_idx 1 state = %v, want DRAINING", got[1])
	}
	if got[3] != aictrl.EpState_EP_STATE_DISABLED {
		t.Fatalf("ep_idx 3 state = %v, want DISABLED", got[3])
	}
	if got[0] != aictrl.EpState_EP_STATE_ACTIVE || got[4] != aictrl.EpState_EP_STATE_ACTIVE {
		t.Fatalf("untouched EPs not ACTIVE: %v", got)
	}
	// A state change alone (same weights) IS an output change next epoch.
	s2 := g.Maybe(testNow.Add(10*time.Second), allNeutral(), nil, false)
	if s2 == nil {
		t.Fatal("state-only output change suppressed")
	}
}
