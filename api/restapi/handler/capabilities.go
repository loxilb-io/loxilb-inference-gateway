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

// kvExactVllmCapability reports whether this gateway can admit vLLM KV-exact
// rules, deriving the verdict from cmn.KvExactSeedPrecondition -- the same
// predicate admission calls, not a second copy of it.
func kvExactVllmCapability() *models.CapabilityStatus {
	name := cmn.CapabilityKvExactVllm
	ready := true
	status := &models.CapabilityStatus{Name: &name, Ready: &ready}
	if perr := cmn.KvExactSeedPrecondition(capabilityEnv); perr != nil {
		ready = false
		status.Ready = &ready
		status.ReasonCode = perr.Reason
		// The same sentence the 412 refusal carries. Repeating it here
		// rather than writing a friendlier one is deliberate: an operator
		// who sees it in both places is looking at one fact, and a client
		// that surfaces either is telling the truth.
		status.Reason = perr.Error()
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
	payload := &models.CapabilityStatusList{
		// Non-nil even when empty: the field is required, and a null here
		// would make a client distinguish "no capabilities gated" from a
		// malformed body.
		Capabilities: []*models.CapabilityStatus{
			kvExactVllmCapability(),
		},
	}
	return operations.NewGetStatusCapabilitiesOK().WithPayload(payload)
}
