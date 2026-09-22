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
	"errors"
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
	// The other verdicts read the rule engine through hooks that are not
	// wired in a unit test; give them a ready budget and a loadable
	// tokenizer so these cases score the seed alone.
	prevTok, prevSlots := capabilityTokenizerReady, capabilitySourceCheckSlots
	capabilityTokenizerReady = func(string) bool { return true }
	capabilitySourceCheckSlots = func() (cmn.LbSourceCheckSlots, error) {
		return cmn.LbSourceCheckSlots{Limit: cmn.LbSourceCheckSlotCount, InUse: 0, NextSlot: 0}, nil
	}
	t.Cleanup(func() { capabilityTokenizerReady, capabilitySourceCheckSlots = prevTok, prevSlots })

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

func renderCapabilitiesFor(t *testing.T, modelName string, tokenizerLoadable bool, slots cmn.LbSourceCheckSlots, slotsErr error) models.CapabilityStatusList {
	t.Helper()
	prevEnv, prevTok, prevSlots := capabilityEnv, capabilityTokenizerReady, capabilitySourceCheckSlots
	capabilityEnv = func(string) (string, bool) { return "0", true }
	asked := ""
	capabilityTokenizerReady = func(m string) bool { asked = m; return tokenizerLoadable }
	capabilitySourceCheckSlots = func() (cmn.LbSourceCheckSlots, error) { return slots, slotsErr }
	t.Cleanup(func() {
		capabilityEnv, capabilityTokenizerReady, capabilitySourceCheckSlots = prevEnv, prevTok, prevSlots
	})

	params := operations.GetStatusCapabilitiesParams{}
	if modelName != "" {
		params.ModelName = &modelName
	}
	rec := httptest.NewRecorder()
	ConfigGetStatusCapabilities(params, nil).WriteResponse(rec, runtime.JSONProducer())
	var body models.CapabilityStatusList
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if modelName != "" && asked != modelName {
		t.Fatalf("tokenizer probe asked about %q, want %q", asked, modelName)
	}
	if modelName == "" && asked != "" {
		t.Fatalf("tokenizer probe ran with no model named (%q)", asked)
	}
	return body
}

func entryNamed(t *testing.T, list models.CapabilityStatusList, name string) *models.CapabilityStatus {
	t.Helper()
	for _, c := range list.Capabilities {
		if c != nil && c.Name != nil && *c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q entry in %+v", name, list.Capabilities)
	return nil
}

var readySlots = cmn.LbSourceCheckSlots{Limit: cmn.LbSourceCheckSlotCount, InUse: 3, NextSlot: 3}

// With a model named, the kv_exact_vllm verdict covers the tokenizer with
// the same code and sentence the 412 refusal carries; without one, the
// tokenizer half is not evaluated and a seed-ready gateway reports ready.
func TestCapabilitiesKvExactCoversTokenizerForNamedModel(t *testing.T) {
	kv := kvExactEntry(t, renderCapabilitiesFor(t, "Qwen/Qwen3-0.6B", false, readySlots, nil))
	if kv.Ready == nil || *kv.Ready {
		t.Fatalf("ready = %s with no loadable tokenizer, want false", boolPtrText(kv.Ready))
	}
	if kv.ReasonCode != cmn.ReasonKvExactTokenizerUnloadable {
		t.Errorf("reason_code = %q", kv.ReasonCode)
	}
	if want := cmn.KvExactTokenizerPrecondition("vllm", "Qwen/Qwen3-0.6B", nil).Error(); kv.Reason != want {
		t.Errorf("reason drifted from the refusal:\n got: %q\nwant: %q", kv.Reason, want)
	}

	kv = kvExactEntry(t, renderCapabilitiesFor(t, "Qwen/Qwen3-0.6B", true, readySlots, nil))
	if kv.Ready == nil || !*kv.Ready || kv.ReasonCode != "" {
		t.Fatalf("loadable tokenizer: ready = %s reason_code = %q", boolPtrText(kv.Ready), kv.ReasonCode)
	}

	kv = kvExactEntry(t, renderCapabilitiesFor(t, "", false, readySlots, nil))
	if kv.Ready == nil || !*kv.Ready {
		t.Fatalf("no model named: ready = %s, want true (tokenizer not evaluated)", boolPtrText(kv.Ready))
	}
}

// The seed outranks the tokenizer: an unseeded gateway reports the seed
// code, and the tokenizer probe is not consulted for it.
func TestCapabilitiesSeedOutranksTokenizer(t *testing.T) {
	prev := capabilityTokenizerReady
	capabilityTokenizerReady = func(string) bool { t.Fatal("tokenizer probed on an unseeded gateway"); return false }
	t.Cleanup(func() { capabilityTokenizerReady = prev })
	prevSlots := capabilitySourceCheckSlots
	capabilitySourceCheckSlots = func() (cmn.LbSourceCheckSlots, error) { return readySlots, nil }
	t.Cleanup(func() { capabilitySourceCheckSlots = prevSlots })

	code, body := renderCapabilities(t, "", false)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	kv := kvExactEntry(t, body)
	if kv.ReasonCode != cmn.ReasonKvExactSeedUnset {
		t.Fatalf("reason_code = %q, want the seed", kv.ReasonCode)
	}
}

// lb_allowed_sources publishes the slot budget and derives its verdict from
// the slot the allocator would hand out next, with the refusal's own code
// and sentence when that slot is past the source-check range.
func TestCapabilitiesLbAllowedSources(t *testing.T) {
	lb := entryNamed(t, renderCapabilitiesFor(t, "", true, readySlots, nil), cmn.CapabilityLbAllowedSources)
	if lb.Ready == nil || !*lb.Ready || lb.ReasonCode != "" {
		t.Fatalf("ready = %s reason_code = %q, want ready", boolPtrText(lb.Ready), lb.ReasonCode)
	}
	if lb.Limit == nil || *lb.Limit != int64(cmn.LbSourceCheckSlotCount) || lb.InUse == nil || *lb.InUse != 3 {
		t.Fatalf("budget not published: limit=%v in_use=%v", lb.Limit, lb.InUse)
	}

	full := cmn.LbSourceCheckSlots{Limit: cmn.LbSourceCheckSlotCount, InUse: cmn.LbSourceCheckSlotCount, NextSlot: cmn.LbSourceCheckMaxSlot + 1}
	lb = entryNamed(t, renderCapabilitiesFor(t, "", true, full, nil), cmn.CapabilityLbAllowedSources)
	if lb.Ready == nil || *lb.Ready {
		t.Fatalf("ready = %s with every slot held, want false", boolPtrText(lb.Ready))
	}
	if lb.ReasonCode != cmn.ReasonLbSourceCheckSlotsExhausted {
		t.Errorf("reason_code = %q", lb.ReasonCode)
	}
	if want := cmn.LbSourceCheckPrecondition(full.NextSlot, full.InUse).Error(); lb.Reason != want {
		t.Errorf("reason drifted from the refusal:\n got: %q\nwant: %q", lb.Reason, want)
	}
	if lb.InUse == nil || *lb.InUse != int64(cmn.LbSourceCheckSlotCount) {
		t.Errorf("in_use = %v", lb.InUse)
	}

	lb = entryNamed(t, renderCapabilitiesFor(t, "", true, cmn.LbSourceCheckSlots{}, errors.New("running in bgp only mode")), cmn.CapabilityLbAllowedSources)
	if lb.Ready == nil || *lb.Ready || lb.ReasonCode != cmn.ReasonLbRulesUnavailable || lb.Limit != nil {
		t.Fatalf("rule engine unavailable: ready = %s reason_code = %q limit = %v", boolPtrText(lb.Ready), lb.ReasonCode, lb.Limit)
	}
}
