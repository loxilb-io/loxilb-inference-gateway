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

// loadbalancer_kvexactstatus_serialization_test.go — golden serialization
// shape of the kvexactstatus contract, one entry per ladder position. What
// the swagger schema promises must hold on the actual wire bytes:
//   - the required field set is present on EVERY entry, legacy and strict;
//   - reasonCodes is always present, [] when empty (never null/absent);
//   - goFenced serializes for BOTH values — a lifted fence (false) must stay
//     distinguishable from an unreported one;
//   - enforcement is absent on legacy entries, present on strict ones.
//
// These tests run on the remote gate: darwin cannot compile this package
// (Linux cgo / regen-dependent).

package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"
	cmn "github.com/loxilb-io/loxilb/common"
)

// ladder-shaped status fixtures. State/reason strings are written literally:
// this test pins the WIRE contract, and importing pkg/loxinet from here is
// neither possible (import direction) nor desirable — drift against the code
// constants is the vocabulary-sync test's job.
func kvStatusLadderFixtures() []cmn.KvExactStatusMod {
	strict := func(desired, enforced string, reasons []string, goFenced bool, fault string) cmn.KvExactStatusMod {
		return cmn.KvExactStatusMod{
			RuleIdentity:   "lb-20.20.20.9:8080-tcp",
			ModelName:      "m",
			EngineFamily:   "vllm",
			ApiMode:        "both",
			ModelProfileID: "prof-1",
			HashContractID: "sha256_cbor",
			DesiredState:   desired,
			EnforcedState:  enforced,
			ReasonCodes:    reasons,
			Enforcement: &cmn.KvExactEnforcement{
				Desired:  desired,
				Enforced: enforced,
				Fault:    fault,
				GoFenced: goFenced,
			},
		}
	}
	return []cmn.KvExactStatusMod{
		// legacy: no profile, no enforcement, says so.
		{
			RuleIdentity:   "lb-legacy",
			ModelName:      "m",
			EngineFamily:   "vllm",
			ApiMode:        "both",
			HashContractID: "sha256_cbor",
			DesiredState:   "LEGACY_ACTIVE_UNATTESTED",
			EnforcedState:  "LEGACY_ACTIVE_UNATTESTED",
			ReasonCodes:    []string{"no_model_profile_bound"},
		},
		strict("PROFILE_VALIDATED", "PENDING_DATAPLANE_CONTRACT",
			[]string{"binding_dataplane_pending", "attestation_pending"}, true, ""),
		strict("READY", "TOKEN_PARITY_VERIFIED",
			[]string{"hash_attestation_pending"}, true, ""),
		// ready: fence lifted, no qualifying reason — the nil that must
		// serialize as [] with goFenced false still present.
		strict("READY", "READY", nil, false, ""),
		strict("REQUIRES_MIGRATION", "REQUIRES_MIGRATION",
			[]string{"restored_profile_less_requires_migration"}, true, ""),
		strict("DEGRADING", "DEGRADING", []string{"attestation_stale"}, true, ""),
		strict("DEGRADED", "DEGRADED", []string{"challenge_failed"}, true, ""),
		strict("READY", "ENFORCEMENT_FAULT",
			[]string{"enforcement_fault"}, true, "enforcement_fault"),
	}
}

// TestKvExactStatusSerializationShape renders the full ladder through the
// real handler + producer and asserts the schema promises on the raw JSON.
func TestKvExactStatusSerializationShape(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	ApiHooks = &stubKvExactStatusHook{mods: kvStatusLadderFixtures()}

	resp := ConfigGetLoadbalancerKvExactStatus(newKvExactStatusParams("20.20.20.9", 8080, "tcp"), nil)
	rec := httptest.NewRecorder()
	resp.WriteResponse(rec, runtime.JSONProducer())
	if rec.Code != 200 {
		t.Fatalf("ladder fixture set answered %d, want 200", rec.Code)
	}

	var body struct {
		KvExactStatusAttr []map[string]json.RawMessage `json:"kvExactStatusAttr"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	fixtures := kvStatusLadderFixtures()
	if len(body.KvExactStatusAttr) != len(fixtures) {
		t.Fatalf("serialized %d entries, want %d", len(body.KvExactStatusAttr), len(fixtures))
	}

	required := []string{"ruleIdentity", "modelName", "engineFamily", "apiMode",
		"desiredState", "enforcedState", "reasonCodes"}
	sawGoFencedTrue, sawGoFencedFalse := false, false

	for i, entry := range body.KvExactStatusAttr {
		fix := fixtures[i]
		for _, k := range required {
			if _, ok := entry[k]; !ok {
				t.Errorf("entry %d (%s): required field %q absent from the wire", i, fix.EnforcedState, k)
			}
		}
		var reasons []string
		if raw, ok := entry["reasonCodes"]; ok {
			if err := json.Unmarshal(raw, &reasons); err != nil || reasons == nil {
				t.Errorf("entry %d (%s): reasonCodes = %s, want a JSON array ([] when empty, never null)", i, fix.EnforcedState, raw)
			}
		}
		rawEnf, hasEnf := entry["enforcement"]
		if fix.Enforcement == nil {
			if hasEnf {
				t.Errorf("entry %d (%s): legacy entry serialized an enforcement block", i, fix.EnforcedState)
			}
			continue
		}
		if !hasEnf {
			t.Errorf("entry %d (%s): strict entry missing enforcement block", i, fix.EnforcedState)
			continue
		}
		var enf map[string]json.RawMessage
		if err := json.Unmarshal(rawEnf, &enf); err != nil {
			t.Fatalf("entry %d: decode enforcement: %v", i, err)
		}
		rawFenced, ok := enf["goFenced"]
		if !ok {
			t.Errorf("entry %d (%s): goFenced absent — a lifted fence must stay distinguishable from an unreported one", i, fix.EnforcedState)
			continue
		}
		var fenced bool
		if err := json.Unmarshal(rawFenced, &fenced); err != nil {
			t.Fatalf("entry %d: decode goFenced: %v", i, err)
		}
		if fenced != fix.Enforcement.GoFenced {
			t.Errorf("entry %d (%s): goFenced = %v, want %v", i, fix.EnforcedState, fenced, fix.Enforcement.GoFenced)
		}
		if fenced {
			sawGoFencedTrue = true
		} else {
			sawGoFencedFalse = true
		}
	}
	if !sawGoFencedTrue || !sawGoFencedFalse {
		t.Fatalf("fixture set must exercise goFenced both ways (true=%v false=%v)", sawGoFencedTrue, sawGoFencedFalse)
	}
}
