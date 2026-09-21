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
package handler

import (
	"errors"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// The refusal a gateway launched without the seed returns for every vLLM
// KV-exact rule. Spelled out here so a reword shows up as a test diff.
const seedRefusal = "vllm kvExactMode requires non-empty Gateway LLB_KV_NONE_HASH_SEED matching engine PYTHONHASHSEED"

// TestServerPreconditionIs412 pins the distinction the type exists for. A
// 400 says "your input was malformed"; the input was well-formed and valid
// and the SERVER is not provisioned to serve it. A client cannot tell those
// two apart from a 400, so it cannot decide whether to tell the operator to
// fix the request or fix the gateway.
func TestServerPreconditionIs412(t *testing.T) {
	err := &cmn.ServerPreconditionError{
		Reason: cmn.ReasonKvExactSeedUnset,
		Err:    errors.New(seedRefusal),
	}
	got := ResultErrorResponseError(err)
	if got.Code != 412 {
		t.Errorf("Code = %d, want 412", got.Code)
	}
	if got.Result != seedRefusal {
		t.Errorf("Result must carry the refusal verbatim:\n got: %q\nwant: %q", got.Result, seedRefusal)
	}
}

// TestPreconditionOutranksEnclosingRefusal is the ordering guard named in
// ResultErrorResponseError's comment, and the case that actually happens in
// production: the KV-exact seed precondition reaches the classifier WRAPPED
// in a cmn.KvAdmissionError by the admission path, and errors.As unwraps.
// If the KvAdmissionError arm is ever moved above the precondition arm this
// answers 400 again -- silently, with every other test still green, which is
// exactly how the defect was shipped the first time.
func TestPreconditionOutranksEnclosingRefusal(t *testing.T) {
	wrapped := &cmn.KvAdmissionError{
		Err: &cmn.ServerPreconditionError{
			Reason: cmn.ReasonKvExactSeedUnset,
			Err:    errors.New(seedRefusal),
		},
	}
	got := ResultErrorResponseError(wrapped)
	if got.Code != 412 {
		t.Fatalf("Code = %d, want 412 -- a precondition wrapped in an admission refusal must still classify as a precondition", got.Code)
	}
	if got.Result != seedRefusal {
		t.Errorf("Result = %q, want the refusal verbatim", got.Result)
	}
}

// TestOrdinaryRefusalsKeepTheirStatus is the control. Typing one refusal as
// a precondition must not reclassify the rest: a KV admission refusal a
// client can fix by sending different fields stays a 400, and a conflict
// stays a 409.
func TestOrdinaryRefusalsKeepTheirStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int32
	}{
		{
			name: "plain KV admission refusal",
			err:  &cmn.KvAdmissionError{Err: errors.New("model_name is required for vllm kvExactMode")},
			want: 400,
		},
		{
			name: "rule argument rejection",
			err:  &cmn.RuleArgumentError{Err: errors.New("invalid external ip address")},
			want: 400,
		},
		{
			name: "conflict",
			err:  &cmn.ConflictError{Err: errors.New("rule already exists")},
			want: 409,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResultErrorResponseError(tc.err); got.Code != tc.want {
				t.Errorf("Code = %d, want %d", got.Code, tc.want)
			}
		})
	}
}

// TestPreconditionStatusReachesTheWire closes the gap between "the payload
// says 412" and "the client receives 412": ErrorResponse writes the status
// from the payload, so a classifier arm that set only Message would answer
// 200 with an error body.
func TestPreconditionStatusReachesTheWire(t *testing.T) {
	payload := ResultErrorResponseError(&cmn.ServerPreconditionError{
		Reason: cmn.ReasonKvExactSeedUnset,
		Err:    errors.New(seedRefusal),
	})
	if got := renderStatus(t, &ErrorResponse{Payload: payload}); got != 412 {
		t.Fatalf("HTTP status written = %d, want 412", got)
	}
}
