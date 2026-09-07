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

// loadbalancer_apikeyauth_roundtrip_test.go — the api_key_auth three-state
// contract at the REST boundary. The declaration must survive create → store
// → read-back EXACTLY: an omitted policy stays omitted (nil field, absent in
// JSON), never resolved to "disabled"; the two explicit values round-trip
// verbatim. The rule-layer halves of the contract (preserve-on-omit at
// replace, wire triage) are pinned in pkg/loxinet.
//
// These tests run on the remote gate: darwin cannot compile this package
// (Linux cgo / regen-dependent).

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// stubLbAddHook captures the rule the create handler hands the rule layer and
// answers the /all walk with a canned list. One-method-pair stub over the
// wide (nil-embedded) hook interface.
type stubLbAddHook struct {
	cmn.NetHookInterface
	captured *cmn.LbRuleMod
	rules    []cmn.LbRuleMod
}

func (s *stubLbAddHook) NetLbRuleAdd(m *cmn.LbRuleMod) (int, error) {
	cp := *m
	s.captured = &cp
	return 0, nil
}

func (s *stubLbAddHook) NetLbRuleGet() ([]cmn.LbRuleMod, error) {
	return s.rules, nil
}

func newCreateParams(apiKeyAuth string) operations.PostConfigLoadbalancerParams {
	req, _ := http.NewRequest("POST", "/config/loadbalancer", nil)
	return operations.PostConfigLoadbalancerParams{
		HTTPRequest: req,
		Attr: &models.LoadbalanceEntry{
			ServiceArguments: &models.LoadbalanceEntryServiceArguments{
				ExternalIP: swag.String("20.20.20.5"),
				Port:       swag.Int64(8080),
				Protocol:   "tcp",
				APIKeyAuth: apiKeyAuth,
			},
			Endpoints: []*models.LoadbalanceEntryEndpointsItems0{{
				EndpointIP: swag.String("127.0.0.1"),
				TargetPort: swag.Int64(8081),
				Weight:     swag.Int64(1),
			}},
		},
	}
}

// TestApiKeyAuthCreateMapsDeclaration: the create handler copies the wire
// declaration into the rule verbatim — an omitted field (empty string, the
// schema declares no default that could be materialized) reaches the rule
// layer unset, where the create-time "disabled" resolution lives in exactly
// one place.
func TestApiKeyAuthCreateMapsDeclaration(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"omitted stays unset", "", ""},
		{"explicit disabled copied", "disabled", "disabled"},
		{"explicit required copied", "required", "required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &stubLbAddHook{}
			ApiHooks = stub
			ConfigPostLoadbalancer(newCreateParams(c.in), nil)
			if stub.captured == nil {
				t.Fatal("create handler never reached NetLbRuleAdd")
			}
			if got := stub.captured.Serv.ApiKeyAuth; got != c.want {
				t.Fatalf("declared %q reached the rule layer as %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestApiKeyAuthReadBackPreservesDeclaration: read-back reports the stored
// declaration exactly — an undeclared service reads back with the field
// ABSENT (nil), never resolved to "disabled"; declared values come back
// verbatim.
func TestApiKeyAuthReadBackPreservesDeclaration(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	mkRule := func(apiKeyAuth string) cmn.LbRuleMod {
		lb := cmn.LbRuleMod{}
		lb.Serv.ServIP = "20.20.20.5"
		lb.Serv.ServPort = 8080
		lb.Serv.Proto = "tcp"
		lb.Serv.ApiKeyAuth = apiKeyAuth
		return lb
	}
	cases := []struct {
		name   string
		stored string
		want   string // "" = field must be ABSENT from the wire
	}{
		{"undeclared reads back ABSENT", "", ""},
		{"disabled reads back verbatim", "disabled", "disabled"},
		{"required reads back verbatim", "required", "required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ApiHooks = &stubLbAddHook{rules: []cmn.LbRuleMod{mkRule(c.stored)}}
			req, _ := http.NewRequest("GET", "/config/loadbalancer/all", nil)
			r := ConfigGetLoadbalancer(operations.GetConfigLoadbalancerAllParams{HTTPRequest: req}, nil)
			ok, isOK := r.(*operations.GetConfigLoadbalancerAllOK)
			if !isOK || ok.Payload == nil || len(ok.Payload.LbAttr) != 1 {
				t.Fatalf("expected one-entry OK payload, got %T", r)
			}
			if got := ok.Payload.LbAttr[0].ServiceArguments.APIKeyAuth; got != c.want {
				t.Fatalf("stored %q read back as %q, want %q", c.stored, got, c.want)
			}
			// The wire is the contract: prove absence/presence on the actual
			// serialized bytes, not just the model value.
			rec := httptest.NewRecorder()
			r.WriteResponse(rec, runtime.JSONProducer())
			onWire := strings.Contains(rec.Body.String(), `"api_key_auth"`)
			if c.stored == "" && onWire {
				t.Fatalf("undeclared api_key_auth appeared on the wire — resolution on read is a lossy export: %s", rec.Body.String())
			}
			if c.stored != "" && !onWire {
				t.Fatalf("declared api_key_auth %q missing from the wire: %s", c.stored, rec.Body.String())
			}
		})
	}
}
