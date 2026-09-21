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

package common

// ServerPreconditionError marks a refusal whose cause is the gateway's own
// launch environment rather than anything the client sent. The request was
// well-formed and valid; this server is not provisioned to serve it, and no
// change to the request body can make it succeed.
//
// The API layer classifies it structurally as HTTP 412 so a client can tell
// this apart from a genuine input rejection. That distinction is the whole
// point of the type: rendered as a 400 it says "your input was malformed",
// which is the opposite of the truth, and leaves a UI unable to decide
// whether to tell the operator "fix your request" or "fix your gateway".
//
// Use it only where the refusal is decided by deployment state — an unset
// or malformed environment variable, an absent provisioned artifact. A
// refusal that any client could avoid by sending different fields is an
// input rejection and belongs in ValidationError or KvAdmissionError.
type ServerPreconditionError struct {
	// Reason carries a stable machine-readable code for the precondition,
	// so a client can branch on the class without matching message text.
	Reason string
	// Err is the underlying refusal whose text is the operator-facing
	// answer: it must name the setting and the required relationship.
	Err error
}

func (e *ServerPreconditionError) Error() string { return e.Err.Error() }

// Unwrap exposes the underlying refusal to errors.Is/As chains.
func (e *ServerPreconditionError) Unwrap() error { return e.Err }

// Stable precondition reason codes. These are part of the API contract:
// clients branch on them, so they are append-only and never reworded.
const (
	// ReasonKvExactSeedUnset: vLLM KV-exact routing needs a non-empty
	// LLB_KV_NONE_HASH_SEED in the gateway's environment, matching the
	// engine's PYTHONHASHSEED.
	ReasonKvExactSeedUnset = "KV_EXACT_SEED_UNSET"
	// ReasonKvExactSeedTooLong: the seed is present but longer than the
	// 23-byte bound the hashing data path can represent.
	ReasonKvExactSeedTooLong = "KV_EXACT_SEED_TOO_LONG"
)
