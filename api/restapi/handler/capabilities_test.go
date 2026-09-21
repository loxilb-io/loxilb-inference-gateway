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

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// renderCapabilities drives the handler the way the generated server does and
// returns the wire status together with the decoded body.
func renderCapabilities(t *testing.T, seed string, present bool) (int, models.CapabilityStatusList) {
	t.Helper()
	prev := capabilityEnv
	capabilityEnv = func(name string) (string, bool) {
		if name != cmn.KvExactSeedEnv {
			return "", false
		}
		return seed, present
	}
	t.Cleanup(func() { capabilityEnv = prev })

	rec := httptest.NewRecorder()
	ConfigGetStatusCapabilities(operations.GetStatusCapabilitiesParams{}, nil).
		WriteResponse(rec, runtime.JSONProducer())

	var body models.CapabilityStatusList
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return rec.Code, body
}

// boolPtrText renders a required-but-pointer field for a failure message: the
// pointer address is never what a reader needs. Deliberately NOT the package's
// derefBool, which reports nil as false -- here "missing" and "false" are
// different failures and the message has to say which one happened.
func boolPtrText(b *bool) string {
	if b == nil {
		return "<missing>"
	}
	return strconv.FormatBool(*b)
}

func kvExactEntry(t *testing.T, list models.CapabilityStatusList) *models.CapabilityStatus {
	t.Helper()
	for _, c := range list.Capabilities {
		if c != nil && c.Name != nil && *c.Name == cmn.CapabilityKvExactVllm {
			return c
		}
	}
	t.Fatalf("no %q entry in %+v", cmn.CapabilityKvExactVllm, list.Capabilities)
	return nil
}

// TestCapabilitiesReportsKvExactNotReady covers the case the surface exists
// for: a gateway launched without the seed refuses every vLLM KV-exact rule,
// and a client must be able to learn that before submitting one.
func TestCapabilitiesReportsKvExactNotReady(t *testing.T) {
	for _, tc := range []struct {
		name    string
		seed    string
		present bool
		code    string
	}{
		{"seed absent", "", false, cmn.ReasonKvExactSeedUnset},
		{"seed empty", "", true, cmn.ReasonKvExactSeedUnset},
		{"seed too long", strings.Repeat("s", cmn.KvExactSeedMaxLen+1), true, cmn.ReasonKvExactSeedTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := renderCapabilities(t, tc.seed, tc.present)
			// Always 200: an unready OPTIONAL capability is not ill health.
			// A 503 here would tell an operator their gateway is down when
			// it is serving everything it was asked to serve.
			if status != 200 {
				t.Fatalf("HTTP status = %d, want 200", status)
			}
			e := kvExactEntry(t, body)
			if e.Ready == nil || *e.Ready {
				t.Fatalf("ready = %v, want false", boolPtrText(e.Ready))
			}
			if e.ReasonCode != tc.code {
				t.Errorf("reason_code = %q, want %q", e.ReasonCode, tc.code)
			}
			if e.Reason == "" {
				t.Error("reason must carry the operator-facing sentence, got empty")
			}
		})
	}
}

// TestCapabilitiesReportsKvExactReady is the delta-0 half. Without it the
// assertions above would pass against a surface hard-wired to "not ready",
// which would be exactly as useless as no surface: a client would disable the
// control on every gateway, including the ones that can serve it.
func TestCapabilitiesReportsKvExactReady(t *testing.T) {
	status, body := renderCapabilities(t, "0", true)
	if status != 200 {
		t.Fatalf("HTTP status = %d, want 200", status)
	}
	e := kvExactEntry(t, body)
	if e.Ready == nil || !*e.Ready {
		t.Fatalf("ready = %v, want true", boolPtrText(e.Ready))
	}
	if e.ReasonCode != "" || e.Reason != "" {
		t.Errorf("a ready capability must carry no reason, got code=%q reason=%q", e.ReasonCode, e.Reason)
	}
}

// TestCapabilitiesRequiredFieldsAlwaysPresent guards the wire shape. name and
// ready are required by the contract and are pointers in the generated model,
// so a plain-bool mistake would omit ready=false through omitempty -- and an
// unready capability would read to a client exactly like a ready one.
func TestCapabilitiesRequiredFieldsAlwaysPresent(t *testing.T) {
	for _, present := range []bool{true, false} {
		_, body := renderCapabilities(t, "", present)
		if len(body.Capabilities) == 0 {
			t.Fatal("capabilities must never be empty or null while this build gates one")
		}
		for _, c := range body.Capabilities {
			if c.Name == nil || *c.Name == "" {
				t.Error("name missing")
			}
			if c.Ready == nil {
				t.Error("ready missing -- a required field must survive JSON encoding even when false")
			}
		}
	}
}
