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

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// FaultsEnabled reports whether fault points were compiled in. This build
// has them; the point is selected at run time by FaultEnv.
const FaultsEnabled = true

// FaultEnv names the environment variable that selects the armed fault
// point in a fault-enabled build.
const FaultEnv = "LOXILB_AUDIT_FAULT"

// A fault may carry a budget: "writer.stall:2000" fires on the first 2000
// occurrences and then releases, while a bare "writer.stall" stays armed for
// the life of the process.
//
// A budget is what makes the stalled-writer failure observable end to end.
// The point is selected from the environment, which is read once at start,
// so the only way to release an unbounded fault is to restart — and a
// restart takes the producers' drop rings with it, destroying the very
// record of what was lost that the gap records are written from. With a
// budget the queue overflows and then drains inside one process, so the
// drops and the gaps that name them can be read from the same boot.
var armedFault, armedBudget = parseArmedFault(os.Getenv(FaultEnv))

// budgetLeft counts down the armed point's remaining occurrences. It is
// meaningless when armedBudget is negative (no budget given).
var budgetLeft atomic.Int64

func init() { budgetLeft.Store(armedBudget) }

// parseArmedFault splits "point[:budget]". A missing or unreadable budget
// means unbounded, which is the behaviour of a plain point name.
func parseArmedFault(v string) (string, int64) {
	point, budget, ok := strings.Cut(v, ":")
	if !ok {
		return v, -1
	}
	n, err := strconv.ParseInt(budget, 10, 64)
	if err != nil || n <= 0 {
		return point, -1
	}
	return point, n
}

// buildFaultArmed reports whether point is the one selected by FaultEnv and
// still has budget. It is called once per occurrence of each point, and only
// the selected point consumes budget.
func buildFaultArmed(point string) bool {
	if armedFault != point {
		return false
	}
	if armedBudget < 0 {
		return true
	}
	return budgetLeft.Add(-1) >= 0
}

// buildFaultClear disarms a one-shot point after it fired.
func buildFaultClear() { armedFault = "" }
