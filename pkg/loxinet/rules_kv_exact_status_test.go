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
	"net"
	"testing"
)

func kvStatusTestRule(id, model, engine, profile, apiMode string, vip string, port uint16, proto uint8, exactMode uint8) *ruleEnt {
	_, cidr, _ := net.ParseCIDR(vip + "/32")
	return &ruleEnt{
		tuples: ruleTuples{
			l3Dst:     ruleIPTuple{addr: *cidr},
			l4Prot:    rule8Tuple{proto, 0xff},
			l4Dst:     rule16RTuple{port, port, true},
			modelName: model,
		},
		id:             id,
		kvExactMode:    exactMode,
		kvEngineType:   engine,
		kvExactApiMode: apiMode,
		kvModelProfile: profile,
	}
}

// TestKvExactStatusReadModel: the resolved-status walk reports legacy rules
// as LEGACY_ACTIVE_UNATTESTED, strict bound rules as PROFILE_VALIDATED with
// their full composed identity, and a strict rule with missing binding state
// as ENFORCEMENT_FAULT — never a silent legacy downgrade.
func TestKvExactStatusReadModel(t *testing.T) {
	KvBindingReset()
	t.Cleanup(KvBindingReset)

	R := &RuleH{}
	R.tables[RtLB].eMap = map[string]*ruleEnt{}

	legacy := kvStatusTestRule("rule-legacy", "model-l", "sglang", "", "", "10.0.0.1", 9000, 6, 3)
	strict := kvStatusTestRule("rule-strict", "model-s", "vllm", "prof-a", KvExactApiCompletions, "10.0.0.1", 9001, 6, 1)
	faulty := kvStatusTestRule("rule-faulty", "model-f", "vllm", "prof-a", "", "10.0.0.1", 9002, 6, 1)
	plain := kvStatusTestRule("rule-plain", "model-p", "vllm", "", "", "10.0.0.1", 9003, 6, 0)
	R.tables[RtLB].eMap["a"] = legacy
	R.tables[RtLB].eMap["b"] = strict
	R.tables[RtLB].eMap["c"] = faulty
	R.tables[RtLB].eMap["d"] = plain

	b, err := KvBindingAllocate("rule-strict", KvExactBindingComponents{
		Profile:               KvModelProfileRef{ID: "prof-a", Gen: 7},
		Contract:              KvEngineContractRef{ID: "vllm-contract-v1", Gen: 2},
		RequiredEvidenceLevel: "validated",
		ConsensusPolicy:       "all_endpoints",
	})
	if err != nil {
		t.Fatalf("binding allocate: %v", err)
	}

	t.Run("legacy rule", func(t *testing.T) {
		res, err := R.GetKvExactStatus("10.0.0.1", 9000, "tcp", "")
		if err != nil || len(res) != 1 {
			t.Fatalf("status = %v, %v", res, err)
		}
		m := res[0]
		if m.DesiredState != KvExactStateLegacyActive || m.EnforcedState != KvExactStateLegacyActive {
			t.Fatalf("legacy states = %s/%s", m.DesiredState, m.EnforcedState)
		}
		if m.ApiMode != KvExactApiBoth {
			t.Fatalf("legacy absent api mode must resolve to both, got %q", m.ApiMode)
		}
		if m.HashContractID != "sha256_sglang" {
			t.Fatalf("hash contract = %q", m.HashContractID)
		}
		if len(m.ReasonCodes) != 1 || m.ReasonCodes[0] != "no_model_profile_bound" {
			t.Fatalf("reasons = %v", m.ReasonCodes)
		}
	})

	t.Run("strict bound rule", func(t *testing.T) {
		res, err := R.GetKvExactStatus("10.0.0.1", 9001, "tcp", "")
		if err != nil || len(res) != 1 {
			t.Fatalf("status = %v, %v", res, err)
		}
		m := res[0]
		if m.DesiredState != KvExactStateProfileValidated || m.EnforcedState != KvExactStatePendingDataplane {
			t.Fatalf("strict states = %s/%s", m.DesiredState, m.EnforcedState)
		}
		if m.ModelProfileID != "prof-a" || m.ModelProfileGen != 7 {
			t.Fatalf("profile ref = %s@%d", m.ModelProfileID, m.ModelProfileGen)
		}
		if m.EngineContractID != "vllm-contract-v1" || m.EngineContractGen != 2 {
			t.Fatalf("contract ref = %s@%d", m.EngineContractID, m.EngineContractGen)
		}
		if m.BindingGen != b.BindingGen || m.BindingDigest != b.Digest {
			t.Fatalf("binding identity = %d/%.12s", m.BindingGen, m.BindingDigest)
		}
		if m.RequiredEvidenceLevel != "validated" {
			t.Fatalf("evidence = %q", m.RequiredEvidenceLevel)
		}
	})

	t.Run("strict rule with missing binding state", func(t *testing.T) {
		res, err := R.GetKvExactStatus("10.0.0.1", 9002, "tcp", "")
		if err != nil || len(res) != 1 {
			t.Fatalf("status = %v, %v", res, err)
		}
		m := res[0]
		if m.EnforcedState != KvExactStateEnforcementFault {
			t.Fatalf("missing binding state must be an enforcement fault, got %s", m.EnforcedState)
		}
		if len(m.ReasonCodes) != 1 || m.ReasonCodes[0] != "binding_state_missing" {
			t.Fatalf("reasons = %v", m.ReasonCodes)
		}
	})

	t.Run("non-exact rules excluded", func(t *testing.T) {
		res, err := R.GetKvExactStatus("10.0.0.1", 9003, "tcp", "")
		if err != nil || len(res) != 0 {
			t.Fatalf("kvExactMode=0 rule must not appear: %v, %v", res, err)
		}
	})

	t.Run("model filter", func(t *testing.T) {
		res, err := R.GetKvExactStatus("10.0.0.1", 9000, "tcp", "model-l")
		if err != nil || len(res) != 1 {
			t.Fatalf("model filter hit = %v, %v", res, err)
		}
		res, err = R.GetKvExactStatus("10.0.0.1", 9000, "tcp", "other-model")
		if err != nil || len(res) != 0 {
			t.Fatalf("model filter miss = %v, %v", res, err)
		}
	})

	t.Run("unsupported protocol", func(t *testing.T) {
		if _, err := R.GetKvExactStatus("10.0.0.1", 9000, "icmp", ""); err == nil {
			t.Fatal("icmp status must be rejected")
		}
	})
}
