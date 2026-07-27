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

package tools

import "testing"

// finishDiagnose stamps suggested actions with the bridge's
// autopilot status so agents know which follow-ups skip the confirm token.
func TestFinishDiagnoseAutopilotMark(t *testing.T) {
	d := &Deps{Autopilot: func(n string) bool { return n == "endpoint_host_state_set" }}
	o := newDiagnoseOut("t1")
	o.SuggestedActions = []suggestedAction{
		{Tool: "endpoint_host_state_set", Risk: "low"},
		{Tool: "lb_delete", Risk: "high"},
	}
	d.finishDiagnose(&o)
	if !o.SuggestedActions[0].Autopilot {
		t.Error("autopilot-listed suggestion not marked")
	}
	if o.SuggestedActions[1].Autopilot {
		t.Error("non-listed suggestion wrongly marked")
	}

	// nil Autopilot (e.g. direct Deps construction) must not panic and
	// leaves everything unmarked.
	d2 := &Deps{}
	o2 := newDiagnoseOut("t1")
	o2.SuggestedActions = []suggestedAction{{Tool: "lb_delete"}}
	d2.finishDiagnose(&o2)
	if o2.SuggestedActions[0].Autopilot {
		t.Error("nil autopilot func must mark nothing")
	}
}
