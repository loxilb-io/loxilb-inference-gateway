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

package loxinet

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/loxilb-io/loxilb/pkg/audit"
)

// aiRequests reads one series of loxilb_ai_requests_total from the default
// registry, where the family lives; 0 when the series does not exist yet.
func aiRequests(t *testing.T, model, tenant, status, outcome string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "loxilb_ai_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			l := map[string]string{}
			for _, lp := range m.GetLabel() {
				l[lp.GetName()] = lp.GetValue()
			}
			if l["model"] == model && l["tenant"] == tenant && l["status"] == status && l["outcome"] == outcome {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// One gate refusal, end to end through both exports the way the C gate
// drives them: the gate export refuses and counts nothing, and the deny
// record the gate takes at its verdict counts the request once, with the
// status the client got. Before MON-02 the gate export counted it too, and
// the record could not, or every gate refusal would land twice.
func TestGateRefusalIsCountedOnceByTheDenyRecord(t *testing.T) {
	saved := mh.AIKeyService.Load()
	mh.AIKeyService.Store(nil) // no key store: the gate refuses 503
	t.Cleanup(func() { mh.AIKeyService.Store(saved) })

	const model = "m-deny-e2e"
	before := aiRequests(t, model, "", "503", "denied")

	ret, decision, code := aiValidateKeyC("sk-anything", model)
	if ret == 0 || decision != aiDecisionDeny503 || code != aiErrPolicyStoreNA {
		t.Fatalf("validate_key = (%d, %d, %q), want a 503 policy_store_unavailable refusal", ret, decision, code)
	}
	if d := aiRequests(t, model, "", "503", "denied") - before; d != 0 {
		t.Fatalf("the gate export counted its own refusal (delta %v); the deny record is the only writer", d)
	}

	aiRecordDenyC(aiDenyRecord{
		RequestID: "req-e2e", SvcIdent: "10.0.0.1:2040", ModelName: model,
		Stage: aiStageAuth, HTTPStatus: 503, ErrorCode: code, ClientIP: "203.0.113.5",
	})
	if d := aiRequests(t, model, "", "503", "denied") - before; d != 1 {
		t.Fatalf("requests_total{denied,503} delta = %v after one refusal, want exactly 1", d)
	}
	if d := aiRequests(t, model, "", "503", "completed"); d != 0 {
		t.Fatalf("a refusal counted as completed: %v", d)
	}
}

// A routing or framing refusal never registers the model it names: it may
// be one nobody serves, and 64 of them would push every real model to
// "other". A known model keeps its label; a route refusal of a request that
// named no model reads "none", a framing refusal "".
func TestUnservedRefusalLabels(t *testing.T) {
	for _, c := range []struct {
		name  string
		stage int
		model string
		label string
	}{
		{"route, model nobody serves", aiStageRoute, "m-route-unknown-1", "other"},
		{"route, no model", aiStageRoute, "", "none"},
		{"framing, model nobody serves", aiStageFraming, "m-framing-unknown-1", "other"},
		{"framing, no model", aiStageFraming, "", ""},
	} {
		before := aiRequests(t, c.label, "t-unserved", "503", "denied")
		recordAIDeny(aiDenyRecord{Stage: c.stage, ModelName: c.model, TenantID: "t-unserved", HTTPStatus: 503})
		if d := aiRequests(t, c.label, "t-unserved", "503", "denied") - before; d != 1 {
			t.Errorf("%s: series model=%q delta %v, want 1", c.name, c.label, d)
		}
		if c.model != "" && aiRequests(t, c.model, "t-unserved", "503", "denied") != 0 {
			t.Errorf("%s: the unserved model %q took a label of its own", c.name, c.model)
		}
	}

	// A model a backend answered is registered; a route refusal of it keeps it.
	recordAIDeny(aiDenyRecord{Stage: aiStageAuth, ModelName: "m-route-known", TenantID: "t-unserved", HTTPStatus: 401})
	before := aiRequests(t, "m-route-known", "t-unserved", "503", "denied")
	recordAIDeny(aiDenyRecord{Stage: aiStageRoute, ModelName: "m-route-known", TenantID: "t-unserved", HTTPStatus: 503})
	if d := aiRequests(t, "m-route-known", "t-unserved", "503", "denied") - before; d != 1 {
		t.Errorf("route refusal of a registered model: delta %v under its own label, want 1", d)
	}
}

// The stage values mirror ai_gw_admit_stage_t, appended: none moved.
func TestDenyStagesRouteFramingSecurity(t *testing.T) {
	if aiStageObjective != 6 || aiStageRoute != 7 || aiStageFraming != 8 || aiStageSecurity != 9 {
		t.Fatalf("stages moved: objective=%d route=%d framing=%d security=%d, want 6 7 8 9",
			aiStageObjective, aiStageRoute, aiStageFraming, aiStageSecurity)
	}
	for _, c := range []struct {
		stage int
		name  string
	}{{aiStageRoute, "route"}, {aiStageFraming, "framing"}, {aiStageSecurity, "security"}} {
		if got := aiDenyStage(c.stage); got != c.name {
			t.Errorf("aiDenyStage(%d) = %q, want %q", c.stage, got, c.name)
		}
		if got := aiDenyReason(c.stage, "model_unavailable"); got != audit.ReasonAdmission {
			t.Errorf("aiDenyReason(%d) = %q, want admission", c.stage, got)
		}
	}
}
