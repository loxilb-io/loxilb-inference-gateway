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
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func makeTestRule(srcIP, dstIP string, proto uint8, pref uint32) cmn.FwRuleArg {
	return cmn.FwRuleArg{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Proto:      proto,
		SrcPortMin: 0,
		SrcPortMax: 0,
		DstPortMin: 80,
		DstPortMax: 80,
		Pref:       pref,
	}
}

func makeTestOpt(allow bool) cmn.FwOptArg {
	if allow {
		return cmn.FwOptArg{Allow: true}
	}
	return cmn.FwOptArg{Drop: true}
}

func TestDiff_AddOnly(t *testing.T) {
	sd := NewStateDiffer()
	rn := NewRuleNormalizer()

	rule1 := makeTestRule("10.0.0.0/8", "192.168.1.0/24", 6, 100)
	rule2 := makeTestRule("172.16.0.0/12", "10.0.0.0/8", 17, 200)
	rule3 := makeTestRule("0.0.0.0/0", "0.0.0.0/0", 0, 300)

	key1 := rn.MakeDiffKey(rule1)
	key2 := rn.MakeDiffKey(rule2)
	key3 := rn.MakeDiffKey(rule3)

	currentRules := make(map[DiffKey]cmn.FwRuleArg)
	currentOpts := make(map[DiffKey]cmn.FwOptArg)

	desiredRules := map[DiffKey]cmn.FwRuleArg{
		key1: rule1,
		key2: rule2,
		key3: rule3,
	}
	desiredOpts := map[DiffKey]cmn.FwOptArg{
		key1: makeTestOpt(true),
		key2: makeTestOpt(false),
		key3: makeTestOpt(true),
	}

	result := sd.Diff(currentRules, desiredRules, currentOpts, desiredOpts)

	if len(result.ToAdd) != 3 {
		t.Errorf("expected 3 ToAdd, got %d", len(result.ToAdd))
	}
	if len(result.ToDelete) != 0 {
		t.Errorf("expected 0 ToDelete, got %d", len(result.ToDelete))
	}
	if len(result.OptsToAdd) != 3 {
		t.Errorf("expected 3 OptsToAdd, got %d", len(result.OptsToAdd))
	}
	if len(result.OptsToDelete) != 0 {
		t.Errorf("expected 0 OptsToDelete, got %d", len(result.OptsToDelete))
	}
}

func TestDiff_DeleteOnly(t *testing.T) {
	sd := NewStateDiffer()
	rn := NewRuleNormalizer()

	rule1 := makeTestRule("10.0.0.0/8", "192.168.1.0/24", 6, 100)
	rule2 := makeTestRule("172.16.0.0/12", "10.0.0.0/8", 17, 200)
	rule3 := makeTestRule("0.0.0.0/0", "0.0.0.0/0", 0, 300)

	key1 := rn.MakeDiffKey(rule1)
	key2 := rn.MakeDiffKey(rule2)
	key3 := rn.MakeDiffKey(rule3)

	currentRules := map[DiffKey]cmn.FwRuleArg{
		key1: rule1,
		key2: rule2,
		key3: rule3,
	}
	currentOpts := map[DiffKey]cmn.FwOptArg{
		key1: makeTestOpt(true),
		key2: makeTestOpt(false),
		key3: makeTestOpt(true),
	}

	desiredRules := make(map[DiffKey]cmn.FwRuleArg)
	desiredOpts := make(map[DiffKey]cmn.FwOptArg)

	result := sd.Diff(currentRules, desiredRules, currentOpts, desiredOpts)

	if len(result.ToAdd) != 0 {
		t.Errorf("expected 0 ToAdd, got %d", len(result.ToAdd))
	}
	if len(result.ToDelete) != 3 {
		t.Errorf("expected 3 ToDelete, got %d", len(result.ToDelete))
	}
	if len(result.OptsToAdd) != 0 {
		t.Errorf("expected 0 OptsToAdd, got %d", len(result.OptsToAdd))
	}
	if len(result.OptsToDelete) != 3 {
		t.Errorf("expected 3 OptsToDelete, got %d", len(result.OptsToDelete))
	}
}

func TestDiff_Mixed(t *testing.T) {
	sd := NewStateDiffer()
	rn := NewRuleNormalizer()

	// Shared rule (in both current and desired)
	ruleShared := makeTestRule("10.0.0.0/8", "192.168.1.0/24", 6, 100)
	keyShared := rn.MakeDiffKey(ruleShared)

	// Only in current (should be deleted)
	ruleOld := makeTestRule("172.16.0.0/12", "10.0.0.0/8", 17, 200)
	keyOld := rn.MakeDiffKey(ruleOld)

	// Only in desired (should be added)
	ruleNew := makeTestRule("0.0.0.0/0", "0.0.0.0/0", 0, 300)
	keyNew := rn.MakeDiffKey(ruleNew)

	currentRules := map[DiffKey]cmn.FwRuleArg{
		keyShared: ruleShared,
		keyOld:    ruleOld,
	}
	currentOpts := map[DiffKey]cmn.FwOptArg{
		keyShared: makeTestOpt(true),
		keyOld:    makeTestOpt(false),
	}

	desiredRules := map[DiffKey]cmn.FwRuleArg{
		keyShared: ruleShared,
		keyNew:    ruleNew,
	}
	desiredOpts := map[DiffKey]cmn.FwOptArg{
		keyShared: makeTestOpt(true),
		keyNew:    makeTestOpt(true),
	}

	result := sd.Diff(currentRules, desiredRules, currentOpts, desiredOpts)

	if len(result.ToAdd) != 1 {
		t.Errorf("expected 1 ToAdd, got %d", len(result.ToAdd))
	}
	if _, ok := result.ToAdd[keyNew]; !ok {
		t.Error("expected keyNew in ToAdd")
	}

	if len(result.ToDelete) != 1 {
		t.Errorf("expected 1 ToDelete, got %d", len(result.ToDelete))
	}
	if _, ok := result.ToDelete[keyOld]; !ok {
		t.Error("expected keyOld in ToDelete")
	}

	if len(result.OptsToAdd) != 1 {
		t.Errorf("expected 1 OptsToAdd, got %d", len(result.OptsToAdd))
	}
	if len(result.OptsToDelete) != 1 {
		t.Errorf("expected 1 OptsToDelete, got %d", len(result.OptsToDelete))
	}
}

func TestDiff_IdenticalState(t *testing.T) {
	sd := NewStateDiffer()
	rn := NewRuleNormalizer()

	rule1 := makeTestRule("10.0.0.0/8", "192.168.1.0/24", 6, 100)
	rule2 := makeTestRule("172.16.0.0/12", "10.0.0.0/8", 17, 200)

	key1 := rn.MakeDiffKey(rule1)
	key2 := rn.MakeDiffKey(rule2)

	rules := map[DiffKey]cmn.FwRuleArg{
		key1: rule1,
		key2: rule2,
	}
	opts := map[DiffKey]cmn.FwOptArg{
		key1: makeTestOpt(true),
		key2: makeTestOpt(false),
	}

	result := sd.Diff(rules, rules, opts, opts)

	if len(result.ToAdd) != 0 {
		t.Errorf("expected 0 ToAdd for identical state, got %d", len(result.ToAdd))
	}
	if len(result.ToDelete) != 0 {
		t.Errorf("expected 0 ToDelete for identical state, got %d", len(result.ToDelete))
	}
	if len(result.OptsToAdd) != 0 {
		t.Errorf("expected 0 OptsToAdd for identical state, got %d", len(result.OptsToAdd))
	}
	if len(result.OptsToDelete) != 0 {
		t.Errorf("expected 0 OptsToDelete for identical state, got %d", len(result.OptsToDelete))
	}
}

func TestDiff_EmptyBothSides(t *testing.T) {
	sd := NewStateDiffer()

	currentRules := make(map[DiffKey]cmn.FwRuleArg)
	desiredRules := make(map[DiffKey]cmn.FwRuleArg)
	currentOpts := make(map[DiffKey]cmn.FwOptArg)
	desiredOpts := make(map[DiffKey]cmn.FwOptArg)

	result := sd.Diff(currentRules, desiredRules, currentOpts, desiredOpts)

	if len(result.ToAdd) != 0 {
		t.Errorf("expected 0 ToAdd, got %d", len(result.ToAdd))
	}
	if len(result.ToDelete) != 0 {
		t.Errorf("expected 0 ToDelete, got %d", len(result.ToDelete))
	}
}
