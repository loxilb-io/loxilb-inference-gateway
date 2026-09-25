//go:build audit_faults

/*
 * Copyright (c) 2026 NetLOX Inc
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

package audit

import "testing"

// A fault's budget is what lets one process both reach the failure and come
// back from it. Without one the only way to release the point is a restart,
// which takes the producers' drop rings with it and destroys the record of
// what was lost.
func TestParseArmedFault(t *testing.T) {
	for _, tt := range []struct {
		in     string
		point  string
		budget int64
	}{
		{"writer.stall", "writer.stall", -1},
		{"writer.stall:2000", "writer.stall", 2000},
		{"writer.stall:0", "writer.stall", -1},
		{"writer.stall:-1", "writer.stall", -1},
		{"writer.stall:abc", "writer.stall", -1},
		{"", "", -1},
	} {
		point, budget := parseArmedFault(tt.in)
		if point != tt.point || budget != tt.budget {
			t.Errorf("parseArmedFault(%q) = %q/%d, want %q/%d",
				tt.in, point, budget, tt.point, tt.budget)
		}
	}
}

// The budget is spent by the selected point and by nothing else, and the
// point releases once it runs out.
func TestBuildFaultArmedSpendsItsBudget(t *testing.T) {
	oldFault, oldBudget := armedFault, armedBudget
	oldLeft := budgetLeft.Load()
	defer func() {
		armedFault, armedBudget = oldFault, oldBudget
		budgetLeft.Store(oldLeft)
	}()

	armedFault, armedBudget = FaultWriterStall, 3
	budgetLeft.Store(3)

	for i := 0; i < 3; i++ {
		if !buildFaultArmed(FaultWriterStall) {
			t.Fatalf("occurrence %d: point released while it still had budget", i+1)
		}
		if buildFaultArmed(FaultWriterPanic) {
			t.Fatal("an unselected point fired")
		}
	}
	if buildFaultArmed(FaultWriterStall) {
		t.Error("the point kept firing past its budget")
	}
}

// A point with no budget behaves as it always has: armed until the process ends.
func TestBuildFaultArmedWithoutBudgetStaysArmed(t *testing.T) {
	oldFault, oldBudget := armedFault, armedBudget
	oldLeft := budgetLeft.Load()
	defer func() {
		armedFault, armedBudget = oldFault, oldBudget
		budgetLeft.Store(oldLeft)
	}()

	armedFault, armedBudget = FaultWriterStall, -1
	for i := 0; i < 100; i++ {
		if !buildFaultArmed(FaultWriterStall) {
			t.Fatalf("occurrence %d: an unbounded point released", i+1)
		}
	}
}
