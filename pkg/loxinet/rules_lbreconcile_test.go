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

// mkEp builds a minimal ruleLBEp with a given (xIP,xPort) identity and an
// optional CT-bearing marker (epCreated) used to assert conntrack preservation
// across a declarative reconcile.
func mkEp(ip string, port uint16, ctBorne bool) ruleLBEp {
	return ruleLBEp{
		xIP:       net.ParseIP(ip),
		rIP:       net.ParseIP(ip),
		xPort:     port,
		epCreated: ctBorne,
	}
}

// TestSnapshotLBEndpointsDeepCopyIndependent: snapshotLBEndpoints must produce a
// fully independent copy — mutating the live slice (as modNatEpHost/electEPSrc do
// in place) must NOT bleed into the snapshot used rollback.
func TestSnapshotLBEndpointsDeepCopyIndependent(t *testing.T) {
	live := []ruleLBEp{mkEp("31.31.31.1", 8080, true), mkEp("32.32.32.1", 8080, false)}
	snap := snapshotLBEndpoints(live)

	if len(snap) != len(live) {
		t.Fatalf("snapshot length mismatch: got %d want %d", len(snap), len(live))
	}

	// Mutate the live slice in place: change an IP byte, a port, and a flag.
	live[0].xIP[len(live[0].xIP)-1] = 99
	live[0].xPort = 1
	live[1].epCreated = true

	if snap[0].xIP.Equal(live[0].xIP) {
		t.Fatalf("snapshot xIP must not alias live xIP after in-place mutation")
	}
	if snap[0].xPort == live[0].xPort {
		t.Fatalf("snapshot xPort must be independent of live xPort")
	}
	if snap[1].epCreated == live[1].epCreated {
		t.Fatalf("snapshot epCreated must be independent of live epCreated")
	}
	// Snapshot must retain the ORIGINAL identity/CT marker for rollback.
	if snap[0].xPort != 8080 || !snap[0].epCreated {
		t.Fatalf("snapshot must preserve the pre-reconcile (xIP,xPort)+CT marker")
	}
}

// TestSnapshotLBEndpointsNil: a nil endpoint slice snapshots to nil (no panic).
func TestSnapshotLBEndpointsNil(t *testing.T) {
	if got := snapshotLBEndpoints(nil); got != nil {
		t.Fatalf("snapshot of nil must be nil, got %v", got)
	}
}

// TestReconcileDiffCTPreserveAddRemove: the declarative diff over a member
// set where one tuple is unchanged, one added, one removed must (a) keep the
// unchanged tuple in retEps with its CT-bearing object identity intact, (b)
// place the new tuple in retEps, and (c) place the removed tuple in delEps. This is
// the diff the atomic reconcile consumes.
func TestReconcileDiffCTPreserveAddRemove(t *testing.T) {
	// Pre-patch member set: A (CT-borne) + B (to be removed).
	oldEps := []ruleLBEp{mkEp("31.31.31.1", 8080, true), mkEp("32.32.32.1", 8080, true)}
	// Desired set: A (unchanged) + C (new). B is dropped.
	newEps := []ruleLBEp{mkEp("31.31.31.1", 8080, false), mkEp("33.33.33.1", 8080, false)}

	ruleChg, retEps, delEps := getLBConsolidatedEPs(oldEps, newEps, cmn.LBOPAdd)

	if !ruleChg {
		t.Fatalf("add+remove must report a rule change")
	}

	// Unchanged tuple A must be retained AND keep its CT-bearing marker (CT preserved).
	var keptA *ruleLBEp
	for i := range retEps {
		if retEps[i].xIP.Equal(net.ParseIP("31.31.31.1")) && retEps[i].xPort == 8080 {
			keptA = &retEps[i]
		}
	}
	if keptA == nil {
		t.Fatalf("unchanged tuple A (31.31.31.1:8080) must be retained in retEps")
	}
	if !keptA.epCreated {
		t.Fatalf("unchanged tuple A must keep its CT-bearing marker (CT preserved)")
	}

	// Removed tuple B must be in delEps.
	foundDelB := false
	for i := range delEps {
		if delEps[i].xIP.Equal(net.ParseIP("32.32.32.1")) {
			foundDelB = true
		}
	}
	if !foundDelB {
		t.Fatalf("removed tuple B (32.32.32.1) must be in delEps")
	}
}

// TestRollbackAddedSubsetSpareUnchanged: WR-02/. On an atomic-reconcile
// rollback, only the members GENUINELY ADDED by the failed reconcile (desired minus the
// pre-reconcile snapshot, by (xIP,xPort) identity) may be detached. An UNCHANGED,
// CT-bearing member present in the snapshot must NEVER appear in the detach set, so its
// probe registration is left continuously attached (no churn). lbEndpointsAddedSince is
// the diff the rollback path uses to compute that detach set.
func TestRollbackAddedSubsetSpareUnchanged(t *testing.T) {
	// Pre-reconcile snapshot: A (CT-borne, unchanged) + B (CT-borne, will be removed).
	snapshot := []ruleLBEp{mkEp("31.31.31.1", 8080, true), mkEp("32.32.32.1", 8080, true)}
	// Desired set the failed reconcile tried to apply: A (unchanged) + C (genuinely new).
	desired := []ruleLBEp{mkEp("31.31.31.1", 8080, true), mkEp("33.33.33.1", 8080, false)}

	added := lbEndpointsAddedSince(snapshot, desired)

	// Only C is genuinely new; A (unchanged) must NOT be in the detach set.
	if len(added) != 1 {
		t.Fatalf("rollback detach set must contain exactly the 1 genuinely-added member, got %d", len(added))
	}
	if !added[0].xIP.Equal(net.ParseIP("33.33.33.1")) || added[0].xPort != 8080 {
		t.Fatalf("rollback detach set must be the new tuple C (33.33.33.1:8080), got %s:%d",
			added[0].xIP, added[0].xPort)
	}
	// Explicit guard: the unchanged CT-bearing member A must never be selected for detach.
	for i := range added {
		if added[i].xIP.Equal(net.ParseIP("31.31.31.1")) && added[i].xPort == 8080 {
			t.Fatalf("unchanged CT-bearing member A (31.31.31.1:8080) must NOT be detached on rollback")
		}
	}
}

// TestRollbackAddedSubsetAllUnchangedDetachesNothing: a no-op reconcile (desired ==
// snapshot by identity) that nonetheless fails the dataplane push must detach NOTHING on
// rollback — every member is unchanged, so the add set is empty (no member churn).
func TestRollbackAddedSubsetAllUnchangedDetachesNothing(t *testing.T) {
	snapshot := []ruleLBEp{mkEp("31.31.31.1", 8080, true), mkEp("32.32.32.1", 8080, true)}
	desired := []ruleLBEp{mkEp("31.31.31.1", 8080, true), mkEp("32.32.32.1", 8080, true)}
	if added := lbEndpointsAddedSince(snapshot, desired); len(added) != 0 {
		t.Fatalf("a no-op reconcile must detach zero members on rollback, got %d", len(added))
	}
}

// TestReconcileDiffNoOpIdenticalArray: a reconcile to an identical member set is a
// no-op — ruleChg must be false and NO existing CT-bearing member may be detached
// (delEps empty), so the atomic reconcile performs no member churn.
func TestReconcileDiffNoOpIdenticalArray(t *testing.T) {
	eps := []ruleLBEp{mkEp("31.31.31.1", 8080, true), mkEp("32.32.32.1", 8080, true)}
	// Identical desired set (same (xIP,xPort) tuples, same weights).
	same := []ruleLBEp{mkEp("31.31.31.1", 8080, false), mkEp("32.32.32.1", 8080, false)}

	ruleChg, retEps, delEps := getLBConsolidatedEPs(eps, same, cmn.LBOPAdd)

	if ruleChg {
		t.Fatalf("identical member set must NOT report a rule change (no-op)")
	}
	if len(delEps) != 0 {
		t.Fatalf("no-op reconcile must not detach any member, got %d delEps", len(delEps))
	}
	if len(retEps) != len(eps) {
		t.Fatalf("no-op reconcile must retain all members, got %d want %d", len(retEps), len(eps))
	}
	// Both unchanged tuples keep their CT-bearing marker.
	for i := range retEps {
		if !retEps[i].epCreated {
			t.Fatalf("no-op reconcile must preserve CT marker for member %s", retEps[i].xIP)
		}
	}
}
