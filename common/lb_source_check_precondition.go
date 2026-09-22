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
package common

import "fmt"

// LbSourceCheckMaxSlot is the highest load-balancer rule slot that can carry
// source checks (allowedSources). The data path keys source checks by a
// per-slot bit in a 32-bit mark whose upper bits are reserved, so slots
// above this one exist but cannot be source-checked. Rule slots are handed
// out by the rule engine's allocator, not chosen by the client.
const LbSourceCheckMaxSlot = 28

// LbSourceCheckSlotCount is how many rules can carry source checks at once.
const LbSourceCheckSlotCount = LbSourceCheckMaxSlot + 1

// CapabilityLbAllowedSources names the source-check capability on the
// capability surface. Part of the API contract: clients branch on it.
const CapabilityLbAllowedSources = "lb_allowed_sources"

// LbSourceCheckSlots is the source-check slot budget as the rule engine
// sees it right now: how many rules can ever carry source checks, how many
// of those slots existing rules hold, and which slot the next rule would be
// given. Whether that next slot can carry source checks is the readiness
// verdict, and LbSourceCheckPrecondition decides it from the same numbers
// admission does.
type LbSourceCheckSlots struct {
	Limit    int
	InUse    int
	NextSlot uint64
}

// LbSourceCheckPrecondition reports why a rule in the given slot cannot
// carry source checks, or nil when it can. inUse is how many of the
// source-check-capable slots are held by existing rules; it is carried in
// the sentence so the operator can see the budget, not just the refusal.
//
// ONE definition on purpose, like the KV-exact seed: rule admission calls
// it with the slot it was just allocated, and the capability surface calls
// it with the slot the allocator would hand out next, so the readiness a
// client reads cannot drift from the refusal it would receive.
func LbSourceCheckPrecondition(slot uint64, inUse int) *ServerPreconditionError {
	if slot <= LbSourceCheckMaxSlot {
		return nil
	}
	return &ServerPreconditionError{
		Reason: ReasonLbSourceCheckSlotsExhausted,
		Err: fmt.Errorf("source checks (allowedSources) can be carried by at most %d load-balancer rules (rule slots 0-%d) and all %d of those slots are held by existing rules; this rule was allocated slot %d. Delete a load-balancer rule holding a lower slot and create this one again -- freed slots are reused first",
			LbSourceCheckSlotCount, LbSourceCheckMaxSlot, inUse, slot),
	}
}
