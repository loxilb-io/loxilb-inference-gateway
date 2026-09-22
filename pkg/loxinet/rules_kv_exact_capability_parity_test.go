/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
	"errors"
	"strconv"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/utils"
)

// TestKvExactCapabilityMatchesAdmission is the reason the seed predicate has
// exactly one definition.
//
// The capability surface exists so a client can stop submitting rules that
// cannot succeed. That is only worth anything if its verdict is the verdict
// admission would reach. A surface that reports ready while admission refuses
// is worse than no surface at all: it turns a loud, explainable refusal into
// a control the operator is invited to use and then denied.
//
// So for each environment, this asserts that what the capability surface
// reads (cmn.KvExactSeedPrecondition) and what a real admission call decides
// agree -- on the verdict, on the stable reason code, and on the sentence.
// It fails the moment someone reintroduces a second copy of the predicate.
func TestKvExactCapabilityMatchesAdmission(t *testing.T) {
	envs := []struct {
		name    string
		seed    string
		present bool
	}{
		{"seed absent", "", false},
		{"seed empty", "", true},
		{"seed valid", "0", true},
		{"seed exactly at the bound", strings.Repeat("s", cmn.KvExactSeedMaxLen), true},
		{"seed one byte over", strings.Repeat("s", cmn.KvExactSeedMaxLen+1), true},
	}

	for _, env := range envs {
		t.Run(env.name, func(t *testing.T) {
			getenv := func(name string) (string, bool) {
				if name != cmn.KvExactSeedEnv {
					return "", false
				}
				return env.seed, env.present
			}

			// What the capability surface would publish.
			surface := cmn.KvExactSeedPrecondition(getenv)

			// What admission actually decides for a vLLM exact rule that is
			// otherwise entirely valid, so the seed is the only variable.
			deps := admissionDeps(func(d *kvExactAdmissionDeps) { d.getenv = getenv })
			_, admitErr := kvExactRuntimeValidate("vllm", 3, "model-a", "", "", deps)

			if surface == nil {
				if admitErr != nil {
					t.Fatalf("capability reports READY but admission refused: %v", admitErr)
				}
				return
			}

			if admitErr == nil {
				t.Fatalf("capability reports NOT ready (%s) but admission accepted the rule", surface.Reason)
			}
			var admitted *cmn.ServerPreconditionError
			if !errors.As(admitErr, &admitted) {
				t.Fatalf("admission refused with a non-precondition error: %#v", admitErr)
			}
			if admitted.Reason != surface.Reason {
				t.Errorf("reason code drift: admission %q, capability %q", admitted.Reason, surface.Reason)
			}
			if admitted.Error() != surface.Error() {
				t.Errorf("message drift:\n admission:  %q\n capability: %q", admitted.Error(), surface.Error())
			}
		})
	}
}

// The tokenizer half of the same contract: the verdict the capability surface
// reaches for a model with cmn.KvExactTokenizerPrecondition must be the
// refusal admission hands out for that model, reason and sentence alike.
func TestKvExactTokenizerCapabilityMatchesAdmission(t *testing.T) {
	for _, loadable := range []bool{true, false} {
		t.Run(map[bool]string{true: "tokenizer loadable", false: "tokenizer unloadable"}[loadable], func(t *testing.T) {
			probe := func(string) bool { return loadable }
			surface := cmn.KvExactTokenizerPrecondition("vllm", "model-a", probe)

			deps := admissionDeps(func(d *kvExactAdmissionDeps) { d.tokenizerReady = probe })
			_, admitErr := kvExactRuntimeValidate("vllm", 3, "model-a", "", "", deps)

			if surface == nil {
				if admitErr != nil {
					t.Fatalf("capability reports READY but admission refused: %v", admitErr)
				}
				return
			}
			if admitErr == nil {
				t.Fatalf("capability reports NOT ready (%s) but admission accepted the rule", surface.Reason)
			}
			var admitted *cmn.ServerPreconditionError
			if !errors.As(admitErr, &admitted) {
				t.Fatalf("admission refused with a non-precondition error: %#v", admitErr)
			}
			if admitted.Reason != surface.Reason || admitted.Error() != surface.Error() {
				t.Errorf("drift:\n admission:  %s %q\n capability: %s %q", admitted.Reason, admitted.Error(), surface.Reason, surface.Error())
			}
		})
	}
}

// The source-check slot budget: the slot the allocator would hand out next
// is what the capability surface scores, and it must be the slot the next
// rule is actually given, so the verdict cannot drift from admission. The
// allocator reuses freed slots first, which is also what the refusal
// sentence tells the operator to rely on.
func TestLbSourceCheckSlotsFollowTheAllocator(t *testing.T) {
	R := &RuleH{}
	R.tables[RtLB].eMap = make(map[string]*ruleEnt)
	R.tables[RtLB].Mark = utils.NewMarker(0, uint64(MaxSrcLBMarkerNum)+8)

	slots := R.LbSourceCheckSlots()
	if slots.Limit != cmn.LbSourceCheckSlotCount || slots.InUse != 0 || slots.NextSlot != 0 {
		t.Fatalf("fresh table: %+v", slots)
	}
	if cmn.LbSourceCheckPrecondition(slots.NextSlot, slots.InUse) != nil {
		t.Fatal("fresh table must be ready for source checks")
	}

	// Fill every source-check-capable slot.
	var taken []uint64
	for i := 0; i <= int(MaxSrcLBMarkerNum); i++ {
		m, err := R.tables[RtLB].Mark.GetMarker()
		if err != nil {
			t.Fatal(err)
		}
		R.tables[RtLB].eMap[strconv.Itoa(i)] = &ruleEnt{ruleNum: m}
		taken = append(taken, m)
	}
	slots = R.LbSourceCheckSlots()
	if slots.InUse != cmn.LbSourceCheckSlotCount || slots.NextSlot != uint64(MaxSrcLBMarkerNum)+1 {
		t.Fatalf("full: %+v", slots)
	}
	perr := cmn.LbSourceCheckPrecondition(slots.NextSlot, slots.InUse)
	if perr == nil || perr.Reason != cmn.ReasonLbSourceCheckSlotsExhausted {
		t.Fatalf("full table must refuse source checks: %v", perr)
	}
	next, _ := R.tables[RtLB].Mark.GetMarker()
	if next != slots.NextSlot {
		t.Fatalf("allocator handed out %d, capability predicted %d", next, slots.NextSlot)
	}
	// That rule (in a slot past the range) does not count against the budget.
	R.tables[RtLB].eMap["over"] = &ruleEnt{ruleNum: next}
	if got := R.LbSourceCheckSlots().InUse; got != cmn.LbSourceCheckSlotCount {
		t.Fatalf("rule past the range counted as in use: %d", got)
	}

	// Freeing a low slot makes it the next one handed out: ready again.
	freed := taken[3]
	delete(R.tables[RtLB].eMap, "3")
	if err := R.tables[RtLB].Mark.ReleaseMarker(freed); err != nil {
		t.Fatal(err)
	}
	slots = R.LbSourceCheckSlots()
	if slots.NextSlot != freed || slots.InUse != cmn.LbSourceCheckSlotCount-1 {
		t.Fatalf("after release: %+v, want next=%d", slots, freed)
	}
	if cmn.LbSourceCheckPrecondition(slots.NextSlot, slots.InUse) != nil {
		t.Fatal("a freed low slot must make source checks admissible again")
	}
	next, _ = R.tables[RtLB].Mark.GetMarker()
	if next != freed {
		t.Fatalf("allocator handed out %d after release, want the freed slot %d", next, freed)
	}
}
