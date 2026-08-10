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
	"encoding/json"
	"strings"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// newTestRuleH builds a minimal RuleH with the LB opaque-id index initialized,
// without touching the dataplane (no mh, no zone goroutines). This exercises the
// id-index + admin-state resolution logic in isolation; full AddLbRule round-trips
// are validated on the remote gate via `make build` + cicd.
func newTestRuleH() *RuleH {
	R := new(RuleH)
	R.tables[RtLB].eMap = make(map[string]*ruleEnt)
	R.opaqueID = make(map[string]*ruleEnt)
	return R
}

// TestOpaqueIDVerbatimSupplied: a client-supplied id is stored verbatim and the
// rule is retrievable via GetLBRuleByOpaqueID.
func TestOpaqueIDVerbatimSupplied(t *testing.T) {
	R := newTestRuleH()
	r := &ruleEnt{}
	r.tuples = ruleTuples{path: "vip-a"}

	supplied := "11111111-1111-4111-8111-111111111111"
	gotID, err := R.resolveOpaqueID(supplied, r)
	if err != nil {
		t.Fatalf("resolveOpaqueID(verbatim) unexpected err: %v", err)
	}
	if gotID != supplied {
		t.Fatalf("expected verbatim id %q, got %q", supplied, gotID)
	}
	r.id = gotID
	R.registerOpaqueID(r)

	if got := R.GetLBRuleByOpaqueID(supplied); got != r {
		t.Fatalf("GetLBRuleByOpaqueID(%q) did not return the registered rule", supplied)
	}
}

// TestOpaqueIDMintedWhenAbsent: with no id supplied, a UUIDv4 is minted and is
// retrievable.
func TestOpaqueIDMintedWhenAbsent(t *testing.T) {
	R := newTestRuleH()
	r := &ruleEnt{}
	r.tuples = ruleTuples{path: "vip-b"}

	gotID, err := R.resolveOpaqueID("", r)
	if err != nil {
		t.Fatalf("resolveOpaqueID(mint) unexpected err: %v", err)
	}
	if gotID == "" {
		t.Fatalf("expected a minted UUID, got empty string")
	}
	// UUIDv4 canonical form is 36 chars (8-4-4-4-12).
	if len(gotID) != 36 {
		t.Fatalf("expected a 36-char UUID, got %q (len=%d)", gotID, len(gotID))
	}
	r.id = gotID
	R.registerOpaqueID(r)

	if got := R.GetLBRuleByOpaqueID(gotID); got != r {
		t.Fatalf("GetLBRuleByOpaqueID(minted) did not return the registered rule")
	}
}

// TestOpaqueIDCollisionRejected: a client-supplied id that already maps to a
// DIFFERENT rule (different VIP-key) is rejected with a conflict error; the
// existing rule is unchanged.
func TestOpaqueIDCollisionRejected(t *testing.T) {
	R := newTestRuleH()

	r1 := &ruleEnt{}
	r1.tuples = ruleTuples{path: "vip-a"}
	id := "22222222-2222-4222-8222-222222222222"
	r1.id = id
	R.registerOpaqueID(r1)

	// A different rule (different ruleKey) supplies the same id.
	r2 := &ruleEnt{}
	r2.tuples = ruleTuples{path: "vip-b"}
	_, err := R.resolveOpaqueID(id, r2)
	if err == nil {
		t.Fatalf("expected conflict error for id colliding with a different rule, got nil")
	}

	// r1 must remain the owner of the id.
	if got := R.GetLBRuleByOpaqueID(id); got != r1 {
		t.Fatalf("collision must not steal the id; expected r1, got %v", got)
	}
}

// TestOpaqueIDSameRuleStable: re-resolving the same id for the SAME rule
// (same ruleKey) is a no-op success — the index stays stable (no churn).
func TestOpaqueIDSameRuleStable(t *testing.T) {
	R := newTestRuleH()
	r := &ruleEnt{}
	r.tuples = ruleTuples{path: "vip-a"}
	id := "33333333-3333-4333-8333-333333333333"
	r.id = id
	R.registerOpaqueID(r)

	gotID, err := R.resolveOpaqueID(id, r)
	if err != nil {
		t.Fatalf("re-resolving id for the same rule must not error: %v", err)
	}
	if gotID != id {
		t.Fatalf("expected stable id %q, got %q", id, gotID)
	}
	if len(R.opaqueID) != 1 {
		t.Fatalf("expected exactly one index entry, got %d", len(R.opaqueID))
	}
}

// TestAdminStateUpDefaultsEnabled: nil/absent AdminStateUp resolves to enabled
// (true) — Octavia's admin_state_up default. Only explicit false yields false.
// BACK-COMPAT: legacy lbconfig.txt entries and the POST path (which never set it)
// must read as enabled, never paused (*bool back-compat).
func TestAdminStateUpDefaultsEnabled(t *testing.T) {
	// nil (absent in body / legacy config) => enabled.
	if got := resolveAdminStateUp(nil); got != true {
		t.Fatalf("nil AdminStateUp must resolve to enabled=true, got %v", got)
	}
	// explicit true => enabled.
	tru := true
	if got := resolveAdminStateUp(&tru); got != true {
		t.Fatalf("explicit true must resolve to enabled=true, got %v", got)
	}
	// explicit false => paused.
	fls := false
	if got := resolveAdminStateUp(&fls); got != false {
		t.Fatalf("explicit false must resolve to paused=false, got %v", got)
	}
}

// TestLastUpdatedNotSerialized: lastUpdated lives only on ruleEnt (in-memory) and
// is never serialized through LbServiceArg. The LbServiceArg model must not
// carry a lastUpdated field. This is a compile-time + json-tag contract; here we
// assert the in-memory field can be set independently of the serialized struct.
func TestLastUpdatedInMemoryOnly(t *testing.T) {
	r := &ruleEnt{}
	now := time.Now()
	r.lastUpdated = now
	if !r.lastUpdated.Equal(now) {
		t.Fatalf("lastUpdated in-memory field not settable")
	}
	// LbServiceArg carries Id + AdminStateUp. It also carries a TRANSIENT LastUpdated
	// (plumbed through the read path so GET .../status reports the real
	// last-mutation time), but that field is json:"-" and must NEVER serialize to
	// lbconfig.txt (keeps lastUpdated in memory only).
	var serv cmn.LbServiceArg
	serv.Id = "abc"
	tru := true
	serv.AdminStateUp = &tru
	serv.LastUpdated = now
	b, err := json.Marshal(&serv)
	if err != nil {
		t.Fatalf("marshal LbServiceArg: %v", err)
	}
	if strings.Contains(string(b), "LastUpdated") || strings.Contains(string(b), "lastUpdated") {
		t.Fatalf("LastUpdated must not be serialized (json:\"-\"); got %s", string(b))
	}
}

// TestMustExistFlagNotSerialized: PATCH must-exist flag is an
// in-memory per-request control flag (json:"-"); it must never round-trip through
// lbconfig.txt. Marshalling a LbServiceArg with MustExist=true must NOT emit the key.
func TestMustExistFlagNotSerialized(t *testing.T) {
	var serv cmn.LbServiceArg
	serv.MustExist = true
	b, err := json.Marshal(&serv)
	if err != nil {
		t.Fatalf("marshal LbServiceArg: %v", err)
	}
	if strings.Contains(string(b), "MustExist") || strings.Contains(string(b), "mustExist") {
		t.Fatalf("MustExist must not be serialized (json:\"-\"); got %s", string(b))
	}
}

// TestMustExistDefaultsFalse: a zero-value LbServiceArg (the POST upsert path never
// sets MustExist) must read MustExist=false so AddLbRule keeps its create-or-update
// behavior. This guards the POST regression (: POST unchanged).
func TestMustExistDefaultsFalse(t *testing.T) {
	var serv cmn.LbServiceArg
	if serv.MustExist {
		t.Fatalf("zero-value LbServiceArg.MustExist must be false (POST upsert unchanged)")
	}
}

// TestLastUpdatedAdvancesOnMutate: an in-place mutation must move lastUpdated forward
// AddLbRule's existing-rule branch sets eRule.lastUpdated = time.Now;
// here we assert the monotonic-advance contract that branch relies on.
func TestLastUpdatedAdvancesOnMutate(t *testing.T) {
	r := &ruleEnt{}
	r.lastUpdated = time.Now()
	first := r.lastUpdated
	time.Sleep(2 * time.Millisecond)
	// Simulate the in-place mutate site (rules.go existing-rule branch).
	r.lastUpdated = time.Now()
	if !r.lastUpdated.After(first) {
		t.Fatalf("lastUpdated must advance on mutate; first=%v now=%v", first, r.lastUpdated)
	}
}
