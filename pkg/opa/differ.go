/*
 * Copyright (c) 2025 LoxiLB Authors
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

package opa

import (
	cmn "github.com/loxilb-io/loxilb/common"
)

// DiffResult holds the sets of rules to add and delete based on a state comparison.
type DiffResult struct {
	ToAdd        map[DiffKey]cmn.FwRuleArg
	ToDelete     map[DiffKey]cmn.FwRuleArg
	OptsToAdd    map[DiffKey]cmn.FwOptArg
	OptsToDelete map[DiffKey]cmn.FwOptArg
}

// StateDiffer computes the difference between current and desired firewall rule sets.
type StateDiffer struct{}

// NewStateDiffer creates a StateDiffer.
func NewStateDiffer() *StateDiffer {
	return &StateDiffer{}
}

// Diff computes the set difference between current and desired rule maps.
// ToAdd contains keys present in desired but not in current.
// ToDelete contains keys present in current but not in desired.
// This is pure set arithmetic with no I/O.
func (sd *StateDiffer) Diff(
	currentRules, desiredRules map[DiffKey]cmn.FwRuleArg,
	currentOpts, desiredOpts map[DiffKey]cmn.FwOptArg,
) DiffResult {
	result := DiffResult{
		ToAdd:        make(map[DiffKey]cmn.FwRuleArg),
		ToDelete:     make(map[DiffKey]cmn.FwRuleArg),
		OptsToAdd:    make(map[DiffKey]cmn.FwOptArg),
		OptsToDelete: make(map[DiffKey]cmn.FwOptArg),
	}

	// Keys in desired but not in current → ToAdd
	for key, rule := range desiredRules {
		if _, exists := currentRules[key]; !exists {
			result.ToAdd[key] = rule
			if opt, ok := desiredOpts[key]; ok {
				result.OptsToAdd[key] = opt
			}
		}
	}

	// Keys in current but not in desired → ToDelete
	for key, rule := range currentRules {
		if _, exists := desiredRules[key]; !exists {
			result.ToDelete[key] = rule
			if opt, ok := currentOpts[key]; ok {
				result.OptsToDelete[key] = opt
			}
		}
	}

	return result
}
