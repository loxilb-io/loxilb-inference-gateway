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

package jwtauth

import "fmt"

// Decision values match the AI gateway decision ladder shared with the C
// sockproxy (loxilb-ebpf common/sockproxy_ai_gw.h): 0=allow, 1=deny_401,
// 2=deny_403, 3=deny_429, 4=deny_503. The JWT arm never produces 3 itself
// (rate limiting is a later stage), but the values must stay aligned so the
// export can pass a verdict through unchanged.
const (
	DecisionAllow   = 0
	DecisionDeny401 = 1
	DecisionDeny403 = 2
	DecisionDeny503 = 4
)

// Client-facing error codes. The 401 surface is deliberately coarse: a
// caller learns only that its token is invalid or expired (expiry is safe
// and actionable to reveal — re-authenticate). Everything finer-grained is
// a server-side oracle and lives in Reason, which today reaches logs only —
// loxilb_ai_jwt_validation_total labels its reason with THESE codes (see
// pkg/loxinet/ai_gateway_dp.go), so the metric vocabulary is this one.
const (
	CodeMissingToken     = "missing_token"
	CodeInvalidToken     = "invalid_token"
	CodeTokenExpired     = "token_expired"
	CodeModelNotAllowed  = "model_not_allowed"
	CodeStoreUnavailable = "policy_store_unavailable"
)

// Fine-grained refusal reasons. A closed set, bounded like a label
// vocabulary, but today they reach logs only: the validation metric labels
// its reason with the client-facing codes above. Promoting these to the
// metric (so bad_signature, unknown_kid, and oversize become separately
// countable) is an open product decision — it changes the family's label
// values, so it must land with the dashboards, not before them.
const (
	ReasonOK             = "ok"
	ReasonMissing        = "missing"
	ReasonMalformed      = "malformed"
	ReasonOversize       = "oversize"
	ReasonBadSignature   = "bad_signature"
	ReasonUnknownKid     = "unknown_kid"
	ReasonExpired        = "expired"
	ReasonBadIssuer      = "bad_issuer"
	ReasonBadAudience    = "bad_audience"
	ReasonNoTenant       = "no_tenant"
	ReasonUnsafeIdentity = "unsafe_identity"
	ReasonModelDenied    = "model_denied"
	ReasonNoKeyset       = "no_keyset"
)

// VerdictError is a verification failure carrying its decision-ladder arm.
// Code is what the client may see and what the validation metric counts;
// Reason is the finer log-side taxonomy; detail is for logs only and must
// never reach a response body.
type VerdictError struct {
	Decision int
	Code     string
	Reason   string
	detail   string
}

func (e *VerdictError) Error() string {
	if e.detail == "" {
		return fmt.Sprintf("jwtauth: %s (%s)", e.Code, e.Reason)
	}
	return fmt.Sprintf("jwtauth: %s (%s): %s", e.Code, e.Reason, e.detail)
}

// deny401 builds a 401-class verdict. The client code collapses to
// invalid_token unless the reason is expiry or absence, mirroring the
// no-oracle discipline of the management plane.
func deny401(reason, detail string) *VerdictError {
	code := CodeInvalidToken
	switch reason {
	case ReasonExpired:
		code = CodeTokenExpired
	case ReasonMissing:
		code = CodeMissingToken
	}
	return &VerdictError{Decision: DecisionDeny401, Code: code, Reason: reason, detail: detail}
}

func deny403Model(detail string) *VerdictError {
	return &VerdictError{Decision: DecisionDeny403, Code: CodeModelNotAllowed, Reason: ReasonModelDenied, detail: detail}
}

func deny503(detail string) *VerdictError {
	return &VerdictError{Decision: DecisionDeny503, Code: CodeStoreUnavailable, Reason: ReasonNoKeyset, detail: detail}
}
