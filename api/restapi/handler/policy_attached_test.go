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
package handler

// policy_attached_test.go — the policy GET must carry the datapath truth
// about attachment. Before this field existed, a policer whose target never
// materialised (a typo'd VIP) was indistinguishable in every API surface
// from one that is programmed and shaping.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

type stubPolicyGetHook struct {
	cmn.NetHookInterface
	pols []cmn.PolMod
}

func (s *stubPolicyGetHook) NetPolicerGet() ([]cmn.PolMod, error) {
	return s.pols, nil
}

func TestPolicyGetCarriesAttachmentState(t *testing.T) {
	prev := ApiHooks
	ApiHooks = &stubPolicyGetHook{pols: []cmn.PolMod{
		{Ident: "pol-live", Attached: true},
		{Ident: "pol-ghost", Attached: false},
	}}
	defer func() { ApiHooks = prev }()

	req, _ := http.NewRequest("GET", "/config/policy/all", nil)
	resp := ConfigGetPolicy(operations.GetConfigPolicyAllParams{HTTPRequest: req}, nil)

	rec := httptest.NewRecorder()
	resp.(middleware.Responder).WriteResponse(rec, runtime.JSONProducer())
	if rec.Code != 200 {
		t.Fatalf("policy GET answered %d, want 200", rec.Code)
	}

	var body struct {
		PolAttr []struct {
			PolicyIdent *string `json:"policyIdent"`
			Attached    *bool   `json:"attached"`
		} `json:"polAttr"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode policy GET body: %v (%q)", err, rec.Body.String())
	}
	if len(body.PolAttr) != 2 {
		t.Fatalf("policy GET returned %d entries, want 2", len(body.PolAttr))
	}
	want := map[string]bool{"pol-live": true, "pol-ghost": false}
	for _, entry := range body.PolAttr {
		if entry.PolicyIdent == nil {
			t.Fatal("policy entry without an ident")
		}
		attached, ok := want[*entry.PolicyIdent]
		if !ok {
			t.Fatalf("unexpected policy %q in response", *entry.PolicyIdent)
		}
		if entry.Attached == nil {
			t.Fatalf("policy %q: attached is absent from the wire body — the ghost-policer state is invisible again", *entry.PolicyIdent)
		}
		if *entry.Attached != attached {
			t.Fatalf("policy %q: attached=%v, want %v", *entry.PolicyIdent, *entry.Attached, attached)
		}
	}
}
