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
	"os"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// capabilityEnv is the environment lookup the capability verdicts read. It is
// a var so tests can drive both arms without mutating the process
// environment; production is os.LookupEnv, which is also what rule admission
// is wired to -- the two must read the same source or the surface can report
// ready while admission refuses.
var capabilityEnv = os.LookupEnv

// capabilityTokenizerReady is the tokenizer probe the kv_exact_vllm verdict
// reads when asked about a model. Production is the rule engine's fresh
// load through the hook, the same probe admission calls; tests inject.
var capabilityTokenizerReady = func(modelName string) bool {
	return ApiHooks.NetKvExactTokenizerReady(modelName)
}

// capabilitySourceCheckSlots is the slot budget the lb_allowed_sources
// verdict reads: the rule engine's own numbers through the hook.
var capabilitySourceCheckSlots = func() (cmn.LbSourceCheckSlots, error) {
	return ApiHooks.NetLbSourceCheckSlotsGet()
}

// notReady stamps one precondition onto a capability. The sentence is the
// same one the 412 refusal carries. Repeating it here rather than writing
// a friendlier one is deliberate: an operator who sees it in both places
// is looking at one fact, and a client that surfaces either is telling
// the truth.
func notReady(status *models.CapabilityStatus, perr *cmn.ServerPreconditionError) {
	ready := false
	status.Ready = &ready
	status.ReasonCode = perr.Reason
	status.Reason = perr.Error()
}

// kvExactVllmCapability reports whether this gateway can admit vLLM KV-exact
// rules, deriving the verdict from the predicates admission calls --
// cmn.KvExactSeedPrecondition, and, when the client named the model it
// would use, cmn.KvExactTokenizerPrecondition -- not second copies of them.
// Without a model the tokenizer half cannot be evaluated: it is a per-model
// artifact, and a verdict that pretended otherwise would report ready for
// a model nothing is staged for.
func kvExactVllmCapability(modelName string) *models.CapabilityStatus {
	name := cmn.CapabilityKvExactVllm
	ready := true
	status := &models.CapabilityStatus{Name: &name, Ready: &ready}
	if perr := cmn.KvExactSeedPrecondition(capabilityEnv); perr != nil {
		notReady(status, perr)
		return status
	}
	if modelName != "" {
		if perr := cmn.KvExactTokenizerPrecondition("vllm", modelName, capabilityTokenizerReady); perr != nil {
			notReady(status, perr)
		}
	}
	return status
}

// lbAllowedSourcesCapability reports whether the next load-balancer rule
// created can carry allowedSources, from the slot the rule engine would
// allocate it and the same predicate admission applies to that slot. The
// budget rides along so a client can show remaining capacity instead of
// learning it by submitting.
func lbAllowedSourcesCapability() *models.CapabilityStatus {
	name := cmn.CapabilityLbAllowedSources
	ready := true
	status := &models.CapabilityStatus{Name: &name, Ready: &ready}
	slots, err := capabilitySourceCheckSlots()
	if err != nil {
		notReady(status, &cmn.ServerPreconditionError{Reason: cmn.ReasonLbRulesUnavailable, Err: err})
		return status
	}
	limit, inUse := int64(slots.Limit), int64(slots.InUse)
	status.Limit = &limit
	status.InUse = &inUse
	if perr := cmn.LbSourceCheckPrecondition(slots.NextSlot, slots.InUse); perr != nil {
		notReady(status, perr)
	}
	return status
}

// ConfigGetStatusCapabilities implements GET /status/capabilities: the
// optional capabilities whose availability is decided by this gateway's
// launch environment rather than by a request.
//
// Deliberately separate from /status/ready. That surface answers "did this
// gateway recover its configuration", and its verdict drives a 503. An
// unready OPTIONAL capability is not ill health -- a gateway nobody asked to
// serve vLLM KV-exact is perfectly healthy without the seed -- so folding
// this in would make such a gateway report itself down. This endpoint always
// answers 200; the verdict lives in the body.
func ConfigGetStatusCapabilities(params operations.GetStatusCapabilitiesParams, principal interface{}) middleware.Responder {
	modelName := ""
	if params.ModelName != nil {
		modelName = *params.ModelName
	}
	payload := &models.CapabilityStatusList{
		// Non-nil even when empty: the field is required, and a null here
		// would make a client distinguish "no capabilities gated" from a
		// malformed body.
		Capabilities: []*models.CapabilityStatus{
			kvExactVllmCapability(modelName),
			lbAllowedSourcesCapability(),
		},
	}
	return operations.NewGetStatusCapabilitiesOK().WithPayload(payload)
}
