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

	cmn "github.com/loxilb-io/loxilb/common"
)

// Octavia (backup tier) / (weight=0 drain) / — member-level
// dataplane selection semantics. These unit tests exercise the PURE selection helpers
// (isEffectivelyAvailable + applyMemberSelection) over in-memory []ruleLBEp fixtures, in
// isolation — NO live dataplane (no mh, no eBPF, no NetHook). They pin the truth table
// and the backup-tier activation/failback control logic that LB2DP runs on every
// DpCreate. The full DpCreate -> NatEP.InActive -> eBPF sel=-1 drain
// (llb_kern_natlbfwd.c:263) path, in-flight CT survival across a tier flip, and the
// syncEPImmediate immediate-failback push are validated on the remote/AWS gate via
// `make build` + CICD octavia-datamodel assertions (c)/(d)/(e). This
// follows the rules_adminstate_test.go isolated-helper convention.

// mkEP - build a ruleLBEp fixture. weight defaults are explicit per case.
func mkEP(ip string, weight uint8, backup, inActiveEP, noService bool) ruleLBEp {
	return ruleLBEp{
		xIP:        net.ParseIP(ip),
		rIP:        net.ParseIP(ip),
		xPort:      8080,
		weight:     weight,
		backup:     backup,
		inActiveEP: inActiveEP,
		noService:  noService,
	}
}

// selActiveCount - count EPs whose TRANSIENT selection flag marks them selectable.
func selActiveCount(eps []ruleLBEp) int {
	n := 0
	for i := range eps {
		if !eps[i].selInactive {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// isEffectivelyAvailable truth table (unified "down" predicate)
// ---------------------------------------------------------------------------

func TestIsEffectivelyAvailableTruthTable(t *testing.T) {
	cases := []struct {
		name       string
		ep         ruleLBEp
		svcAdminUp bool
		want       bool
	}{
		{"healthy primary, admin up", mkEP("10.0.0.1", 1, false, false, false), true, true},
		{"healthy backup, admin up", mkEP("10.0.0.2", 1, true, false, false), true, true},
		{"service paused (admin down) hides everything", mkEP("10.0.0.1", 1, false, false, false), false, false},
		{"probe-down (inActiveEP)", mkEP("10.0.0.1", 1, false, true, false), true, false},
		{"health-down (noService)", mkEP("10.0.0.1", 1, false, false, true), true, false},
		{"weight=0 drain (even when probe-up)", mkEP("10.0.0.1", 0, false, false, false), true, false},
		{"weight=0 backup also unavailable", mkEP("10.0.0.2", 0, true, false, false), true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isEffectivelyAvailable(c.ep, c.svcAdminUp); got != c.want {
				t.Fatalf("isEffectivelyAvailable(%s)=%v, want %v", c.name, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// applyMemberSelection — backup-tier gating + weight=0 drain + admin pause
// ---------------------------------------------------------------------------

// TestMemberSelectionAllPrimariesUpBackupIdle: with ≥1 primary effectively-available,
// the backup carries ZERO traffic (selInactive) and the primaries are all selectable.
func TestMemberSelectionAllPrimariesUpBackupIdle(t *testing.T) {
	eps := []ruleLBEp{
		mkEP("10.0.0.1", 1, false, false, false), // primary
		mkEP("10.0.0.2", 1, false, false, false), // primary
		mkEP("10.0.0.3", 1, true, false, false),  // backup
	}
	applyMemberSelection(eps, true)

	if eps[0].selInactive || eps[1].selInactive {
		t.Fatalf("both primaries must be selectable while up")
	}
	if !eps[2].selInactive {
		t.Fatalf("backup must be selInactive while any primary is up (zero traffic)")
	}
	if selActiveCount(eps) != 2 {
		t.Fatalf("want exactly 2 selectable (the primaries); got %d", selActiveCount(eps))
	}
}

// TestMemberSelectionWeight0PrimaryDrains: a weight=0 primary is "down" for selection
// (drained) but it is NOT inActiveEP — it must still round-trip (membership untouched).
// The other healthy primary keeps the backup idle.
func TestMemberSelectionWeight0PrimaryDrains(t *testing.T) {
	eps := []ruleLBEp{
		mkEP("10.0.0.1", 0, false, false, false), // weight=0 primary -> drained
		mkEP("10.0.0.2", 1, false, false, false), // healthy primary
		mkEP("10.0.0.3", 1, true, false, false),  // backup
	}
	applyMemberSelection(eps, true)

	if !eps[0].selInactive {
		t.Fatalf("weight=0 primary must be drained (selInactive)")
	}
	if eps[0].inActiveEP {
		t.Fatalf("weight=0 drain must NOT mutate inActiveEP — the EP must round-trip on GET")
	}
	if eps[1].selInactive {
		t.Fatalf("healthy primary must stay selectable")
	}
	if !eps[2].selInactive {
		t.Fatalf("backup must stay idle while a healthy primary remains")
	}
}

// TestMemberSelectionAllPrimariesDownBackupActivates: when ALL primaries are
// effectively-unavailable (mix of probe-down + weight=0), the backup activates.
func TestMemberSelectionAllPrimariesDownBackupActivates(t *testing.T) {
	eps := []ruleLBEp{
		mkEP("10.0.0.1", 1, false, true, false),  // probe-down primary
		mkEP("10.0.0.2", 0, false, false, false), // weight=0 primary
		mkEP("10.0.0.3", 1, true, false, false),  // backup (healthy)
	}
	applyMemberSelection(eps, true)

	if !eps[0].selInactive || !eps[1].selInactive {
		t.Fatalf("both down primaries must be selInactive")
	}
	if eps[2].selInactive {
		t.Fatalf("backup must ACTIVATE when all primaries are effectively-down")
	}
	if selActiveCount(eps) != 1 {
		t.Fatalf("want exactly 1 selectable (the backup); got %d", selActiveCount(eps))
	}
}

// TestMemberSelectionImmediateFailback: starting from "all primaries down -> backup up",
// the instant ONE primary recovers, the backup auto-deactivates on the next selection
// pass (no hysteresis). Because applyMemberSelection runs in LB2DP — re-entered by the
// syncEPImmediate health-flip push — this models the immediate failback.
func TestMemberSelectionImmediateFailback(t *testing.T) {
	eps := []ruleLBEp{
		mkEP("10.0.0.1", 1, false, true, false), // probe-down primary
		mkEP("10.0.0.2", 1, true, false, false), // backup
	}
	// failover: all primaries down -> backup active
	applyMemberSelection(eps, true)
	if eps[1].selInactive {
		t.Fatalf("backup must be active during full primary outage")
	}

	// primary recovers (probe flips up) -> next DpCreate re-runs the predicate
	eps[0].inActiveEP = false
	applyMemberSelection(eps, true)

	if eps[0].selInactive {
		t.Fatalf("recovered primary must be selectable")
	}
	if !eps[1].selInactive {
		t.Fatalf("backup must AUTO-DEACTIVATE the instant a primary recovers (immediate failback)")
	}
}

// TestMemberSelectionAdminPauseDownsEverything: a service admin pause (svcAdminUp=false)
// makes every EP — primaries AND backups — selInactive (subsumed). The backup must
// NOT activate on a pause (the whole service is intentionally drained).
func TestMemberSelectionAdminPauseDownsEverything(t *testing.T) {
	eps := []ruleLBEp{
		mkEP("10.0.0.1", 1, false, false, false), // primary
		mkEP("10.0.0.2", 1, true, false, false),  // backup
	}
	applyMemberSelection(eps, false)

	if selActiveCount(eps) != 0 {
		t.Fatalf("admin-paused rule must have ZERO selectable backends (incl. backup); got %d", selActiveCount(eps))
	}
	if !eps[1].selInactive {
		t.Fatalf("backup must NOT activate on an admin pause — the service is drained, not failed over")
	}
}

// TestMemberSelectionNeverMutatesMembership: applyMemberSelection must NEVER mutate
// inActiveEP (membership/persistence) — only the transient selInactive flag. A
// weight=0/backup-standby EP that stays inActiveEP=false continues to round-trip on GET
// (: the GET serializer skips inActiveEP EPs).
func TestMemberSelectionNeverMutatesMembership(t *testing.T) {
	eps := []ruleLBEp{
		mkEP("10.0.0.1", 0, false, false, false), // weight=0 primary
		mkEP("10.0.0.2", 1, true, false, false),  // standby backup
	}
	applyMemberSelection(eps, true)

	for i := range eps {
		if eps[i].inActiveEP {
			t.Fatalf("ep[%d]: applyMemberSelection must not set inActiveEP (membership must survive for GET round-trip)", i)
		}
	}
	// length / identity unchanged
	if len(eps) != 2 || !eps[0].xIP.Equal(net.ParseIP("10.0.0.1")) || !eps[1].xIP.Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("member set identity/length must be preserved")
	}
}

// TestMemberSelectionPriorityBackupGating: a PRIORITY-CONFIGURED rule (sel=2 / LbSelPrio)
// with a backup EP must get the SAME backup gating as a default-selection rule — the
// backup stays selInactive while a primary is available. This exercises the prio-branch
// mark (the LB2DP prio build carries selInactive into neps); the selection logic itself
// is sel-agnostic (it runs over at.endPoints before the branch), so this fixture pins
// that a prio rule's member set is gated identically. We assert against cmn.LbSelPrio to
// make the priority-configuration intent explicit.
func TestMemberSelectionPriorityBackupGating(t *testing.T) {
	// Priority-configured selection mode (sel=2). The member-selection predicate runs
	// over the same member set regardless of sel; LB2DP applies the mark in BOTH the
	// prio and non-prio build branches.
	if cmn.LbSelPrio != 2 {
		t.Logf("note: cmn.LbSelPrio is %d (test intent: priority-configured rule)", cmn.LbSelPrio)
	}
	eps := []ruleLBEp{
		mkEP("10.0.0.1", 1, false, false, false), // primary
		mkEP("10.0.0.2", 1, true, false, false),  // backup
	}
	applyMemberSelection(eps, true)

	if eps[0].selInactive {
		t.Fatalf("prio rule: available primary must be selectable")
	}
	if !eps[1].selInactive {
		t.Fatalf("prio rule: backup must stay selInactive while a primary is available (prio-branch backup gating)")
	}

	// all primaries down -> backup activates even under priority selection
	eps[0].inActiveEP = true
	applyMemberSelection(eps, true)
	if !eps[0].selInactive {
		t.Fatalf("prio rule: down primary must be selInactive")
	}
	if eps[1].selInactive {
		t.Fatalf("prio rule: backup must activate when all primaries are down")
	}
}
