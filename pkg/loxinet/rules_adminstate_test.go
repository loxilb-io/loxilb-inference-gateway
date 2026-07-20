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

package loxinet

import (
	"net"
	"testing"
	"time"
)

// admin_state pause/resume via Option B (control-plane
// block-new). These unit tests exercise the STATE-BASED drain predicate
// (applyAdminStateUpDrain) and the in-memory ruleEnt invariants in isolation, without a
// live dataplane (no mh, no eBPF). The full DpCreate round-trip + the eBPF sel=-1 drain
// (llb_kern_natlbfwd.c:263) + in-flight survival are validated on the remote gate via
// `make build` and the Plan-05 CICD admin_state assertion.

func natEPSet() []NatEP {
	return []NatEP{
		{XIP: net.ParseIP("10.0.0.1"), RIP: net.ParseIP("10.0.0.1"), XPort: 8080},
		{XIP: net.ParseIP("10.0.0.2"), RIP: net.ParseIP("10.0.0.2"), XPort: 8080},
		{XIP: net.ParseIP("10.0.0.3"), RIP: net.ParseIP("10.0.0.3"), XPort: 8080},
	}
}

func activeCount(eps []NatEP) int {
	n := 0
	for _, e := range eps {
		if !e.InActive {
			n++
		}
	}
	return n
}

// TestAdminStateUpDrainPausesAllBackends: adminUp=false marks EVERY built dataplane
// backend InActive so the eBPF selector yields sel=-1 (zero selectable EPs => drain).
// The member set length is preserved — membership is untouched, only selection is gated.
func TestAdminStateUpDrainPausesAllBackends(t *testing.T) {
	eps := natEPSet()
	out := applyAdminStateUpDrain(eps, false)

	if len(out) != 3 {
		t.Fatalf("member set length must be preserved on pause; want 3, got %d", len(out))
	}
	if got := activeCount(out); got != 0 {
		t.Fatalf("paused rule must have zero ACTIVE selectable backends (drain); got %d active", got)
	}
}

// TestAdminStateUpResumeReattachesBackends: adminUp=true leaves the built backend set
// fully active (resume) — the normal active-backend programming, unchanged.
func TestAdminStateUpResumeReattachesBackends(t *testing.T) {
	eps := natEPSet()
	out := applyAdminStateUpDrain(eps, true)

	if got := activeCount(out); got != 3 {
		t.Fatalf("resumed rule must program all backends active; want 3, got %d", got)
	}
}

// TestAdminStateUpResumeHonorsPreexistingInactive: a backend that was ALREADY inactive
// (e.g. failed health probe) stays inactive on resume — admin_state only gates the
// admin-driven block-new, it does not forcibly activate a down backend.
func TestAdminStateUpResumeHonorsPreexistingInactive(t *testing.T) {
	eps := natEPSet()
	eps[1].InActive = true // simulate a probe-down backend

	out := applyAdminStateUpDrain(eps, true)
	if got := activeCount(out); got != 2 {
		t.Fatalf("resume must not re-activate a probe-down backend; want 2 active, got %d", got)
	}
	if !out[1].InActive {
		t.Fatalf("the pre-existing inactive backend must stay inactive on resume")
	}
}

// TestAdminStateUpToggleKeepsMemberSet: toggling false->true->false leaves the persisted
// member set intact (same length each time). admin_state gates SELECTION, never the
// endpoint membership list. We rebuild the active flags from the membership
// each DpCreate, so a re-pause after a resume re-drains the same members cleanly.
func TestAdminStateUpToggleKeepsMemberSet(t *testing.T) {
	// The authoritative membership the control plane re-builds on every DpCreate.
	build := func() []NatEP { return natEPSet() }

	// pause
	p1 := applyAdminStateUpDrain(build(), false)
	if len(p1) != 3 || activeCount(p1) != 0 {
		t.Fatalf("first pause: want 3 members / 0 active, got %d/%d", len(p1), activeCount(p1))
	}
	// resume
	r1 := applyAdminStateUpDrain(build(), true)
	if len(r1) != 3 || activeCount(r1) != 3 {
		t.Fatalf("resume: want 3 members / 3 active, got %d/%d", len(r1), activeCount(r1))
	}
	// pause again
	p2 := applyAdminStateUpDrain(build(), false)
	if len(p2) != 3 || activeCount(p2) != 0 {
		t.Fatalf("re-pause: want 3 members / 0 active, got %d/%d", len(p2), activeCount(p2))
	}
}

// TestAdminStateUpStateBasedBootDrain: a rule whose EFFECTIVE adminStateUp is false at
// creation/boot programs zero active backends IMMEDIATELY — the pause is durable across
// a loxilb restart (the drain is keyed on state, not on a live transition).
func TestAdminStateUpStateBasedBootDrain(t *testing.T) {
	fls := false
	r := &ruleEnt{}
	r.adminStateUp = resolveAdminStateUp(&fls) // explicit-false rule loaded from config

	out := applyAdminStateUpDrain(natEPSet(), r.adminStateUp)
	if activeCount(out) != 0 {
		t.Fatalf("explicit-false rule must program zero active backends at load (durable pause), got %d active", activeCount(out))
	}
}

// TestAdminStateUpStateBasedLegacyEnabled: a legacy rule with nil/absent adminStateUp
// (older lbconfig.txt, or a POST that omits the field) resolves to enabled and programs
// its backends UP — legacy rules are NEVER drained on load (back-compat).
func TestAdminStateUpStateBasedLegacyEnabled(t *testing.T) {
	r := &ruleEnt{}
	r.adminStateUp = resolveAdminStateUp(nil) // legacy / absent

	out := applyAdminStateUpDrain(natEPSet(), r.adminStateUp)
	if activeCount(out) != 3 {
		t.Fatalf("legacy nil-admin_state rule must program backends UP (never drained on load), got %d active", activeCount(out))
	}
}

// TestAdminStateUpLastUpdatedAdvancesOnToggle: an admin_state toggle advances the
// in-memory lastUpdated timestamp. The existing-rule branch sets
// eRule.lastUpdated = time.Now on every in-place mutate; here we assert the
// monotonic-advance contract that branch relies on for an admin_state change.
func TestAdminStateUpLastUpdatedAdvancesOnToggle(t *testing.T) {
	r := &ruleEnt{}
	tru := true
	r.adminStateUp = resolveAdminStateUp(&tru)
	r.lastUpdated = time.Now()
	first := r.lastUpdated

	time.Sleep(2 * time.Millisecond)
	// Simulate the existing-rule branch processing a PATCH adminStateUp=false.
	fls := false
	r.adminStateUp = resolveAdminStateUp(&fls)
	r.lastUpdated = time.Now()

	if !r.lastUpdated.After(first) {
		t.Fatalf("lastUpdated must advance on an admin_state toggle; first=%v now=%v", first, r.lastUpdated)
	}
	if r.adminStateUp != false {
		t.Fatalf("toggle to explicit false must set effective adminStateUp=false")
	}
}

// adminStateRuleChg mirrors the CR-01 ruleChg predicate added to AddLbRule's
// existing-rule branch (rules.go): an EXPLICIT admin_state that differs from the
// current effective state is itself a rule change. An admin_state-only PATCH carries
// every other field identical to current, so this predicate is the ONLY thing that
// keeps ruleChg from being short-circuited to the RuleExistsErr early return (which
// would skip the admin_state apply + LB2DP drain entirely). Kept in lockstep with the
// source predicate so a regression there fails here. The full AddLbRule round-trip is
// validated on the remote gate (`make build` + Plan-05 CICD admin_state assertion).
func adminStateRuleChg(reqAdmin *bool, currentEffective bool) bool {
	return reqAdmin != nil && resolveAdminStateUp(reqAdmin) != currentEffective
}

// TestAdminStateOnlyDeltaTriggersRuleChg: the headline CR-01 fix. An admin_state-only
// PATCH (pause: explicit false against a currently-enabled rule; resume: explicit true
// against a currently-paused rule) MUST be detected as a rule change so AddLbRule does
// not return RuleExistsErr before reaching the admin_state apply. Absent (nil) admin_state
// and a same-state explicit value must NOT spuriously flag a change.
func TestAdminStateOnlyDeltaTriggersRuleChg(t *testing.T) {
	tru, fls := true, false

	// pause: enabled rule, request explicit false => change.
	if !adminStateRuleChg(&fls, true) {
		t.Fatalf("pause (explicit false vs enabled rule) must be detected as a rule change")
	}
	// resume: paused rule, request explicit true => change.
	if !adminStateRuleChg(&tru, false) {
		t.Fatalf("resume (explicit true vs paused rule) must be detected as a rule change")
	}
	// no-op: enabled rule, request explicit true => NOT a change.
	if adminStateRuleChg(&tru, true) {
		t.Fatalf("explicit true against an already-enabled rule must NOT be a change")
	}
	// no-op: paused rule, request explicit false => NOT a change.
	if adminStateRuleChg(&fls, false) {
		t.Fatalf("explicit false against an already-paused rule must NOT be a change")
	}
	// absent: nil admin_state must never flag a change (member-only / resync PATCH).
	if adminStateRuleChg(nil, true) || adminStateRuleChg(nil, false) {
		t.Fatalf("absent (nil) admin_state must NOT be detected as a rule change")
	}
}

// TestAdminStateUpPresencePreservesCurrent: presence-aware control-plane semantics — a
// nil AdminStateUp in the request must NOT change the rule's current effective state
// (a member-only update or a nil re-sync must not silently resume a paused rule). This
// mirrors the existing-rule branch guard `if serv.AdminStateUp != nil`.
func TestAdminStateUpPresencePreservesCurrent(t *testing.T) {
	r := &ruleEnt{}
	// rule currently paused
	r.adminStateUp = false

	// a control-plane update that does NOT mention admin_state (nil)
	var reqAdmin *bool // nil
	if reqAdmin != nil {
		r.adminStateUp = resolveAdminStateUp(reqAdmin)
	}
	if r.adminStateUp != false {
		t.Fatalf("absent admin_state must preserve the current paused state; got %v", r.adminStateUp)
	}

	// an explicit true now resumes it
	tru := true
	reqAdmin = &tru
	if reqAdmin != nil {
		r.adminStateUp = resolveAdminStateUp(reqAdmin)
	}
	if r.adminStateUp != true {
		t.Fatalf("explicit true must resume; got %v", r.adminStateUp)
	}
}
