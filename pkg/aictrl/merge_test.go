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

package aictrl

import "testing"

func TestMergeVerdict(t *testing.T) {
	t.Run("healthy passes directive through unchanged", func(t *testing.T) {
		d := EpDirective{ServiceKey: testSvcKey, EpIdx: 2, Weight: 80,
			State: EpState_EP_STATE_ACTIVE}
		apply, overridden := MergeVerdict(d, true)
		if overridden {
			t.Fatal("healthy EP overridden")
		}
		if apply != d {
			t.Fatalf("healthy directive mutated: %+v != %+v", apply, d)
		}
	})

	t.Run("unhealthy is neutered to the no-op zero word", func(t *testing.T) {
		d := EpDirective{ServiceKey: testSvcKey, EpIdx: 2, Weight: 100,
			State: EpState_EP_STATE_ACTIVE}
		apply, overridden := MergeVerdict(d, false)
		if !overridden {
			t.Fatal("unhealthy EP not overridden")
		}
		if apply.Packed() != 0 {
			t.Fatalf("unhealthy verdict not the no-op word: packed=%#x", apply.Packed())
		}
		// Identity preserved for the caller's override accounting.
		if apply.ServiceKey != d.ServiceKey || apply.EpIdx != d.EpIdx {
			t.Fatalf("override verdict lost EP identity: %+v", apply)
		}
	})
}

// TestMergeVerdictNonResurrection — G4 property: for ALL
// states × weights × healthy combos, MergeVerdict NEVER converts an
// unhealthy EP into a selectable one. Concretely: !healthy ⇒ overridden
// AND the apply verdict packs to the no-op word 0 (caller suppresses the
// write entirely — nothing that could widen local eligibility is emitted).
func TestMergeVerdictNonResurrection(t *testing.T) {
	states := []EpState{
		EpState_EP_STATE_UNSPECIFIED,
		EpState_EP_STATE_ACTIVE,
		EpState_EP_STATE_DRAINING,
		EpState_EP_STATE_DISABLED,
	}
	weights := []uint32{0, 1, 25, 50, 99, 100}
	for _, st := range states {
		for _, w := range weights {
			for _, healthy := range []bool{true, false} {
				d := EpDirective{ServiceKey: testSvcKey, EpIdx: 1, Weight: w, State: st}
				apply, overridden := MergeVerdict(d, healthy)
				if healthy {
					if overridden || apply != d {
						t.Fatalf("healthy state=%v w=%d: verdict mutated (%+v, overridden=%v)",
							st, w, apply, overridden)
					}
					continue
				}
				// Unhealthy: pure intersection — must be the suppressed no-op.
				if !overridden {
					t.Fatalf("unhealthy state=%v w=%d: not overridden", st, w)
				}
				if apply.Packed() != 0 {
					t.Fatalf("unhealthy state=%v w=%d: non-no-op verdict packed=%#x (resurrection risk)",
						st, w, apply.Packed())
				}
			}
		}
	}
}

func TestEpDirectivePacked(t *testing.T) {
	// Lockstep with C contract: state bits 31-24, weight bits 7-0.
	d := EpDirective{Weight: 80, State: EpState_EP_STATE_DRAINING}
	if got, want := d.Packed(), uint32(2)<<24|80; got != want {
		t.Fatalf("Packed() = %#x, want %#x", got, want)
	}
	zero := EpDirective{}
	if zero.Packed() != 0 {
		t.Fatalf("zero directive must pack to the no-instruction word, got %#x", zero.Packed())
	}
}
