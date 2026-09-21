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

import "errors"

// KvExactSeedEnv is the environment variable a vLLM KV-exact deployment must
// set, matching the engine's PYTHONHASHSEED.
const KvExactSeedEnv = "LLB_KV_NONE_HASH_SEED"

// KvExactSeedMaxLen bounds the seed at the hashing data path's representable
// width.
const KvExactSeedMaxLen = 23

// CapabilityKvExactVllm names the vLLM KV-exact routing capability on the
// capability surface. Part of the API contract: clients branch on it.
const CapabilityKvExactVllm = "kv_exact_vllm"

// KvExactSeedPrecondition reports the vLLM KV-exact seed precondition, or nil
// when the gateway's environment satisfies it.
//
// ONE definition on purpose. Rule admission and the capability surface both
// call it, so the readiness a client queries before submitting cannot drift
// from the refusal it would actually receive. Two copies of this predicate
// would eventually disagree, and the failure mode is the worst kind: a
// capability surface that reports ready while every rule is refused, which is
// less useful than having no surface at all.
//
// getenv is injected rather than read directly so admission stays
// deterministic under test; production passes os.LookupEnv on both paths.
func KvExactSeedPrecondition(getenv func(string) (string, bool)) *ServerPreconditionError {
	seed, present := getenv(KvExactSeedEnv)
	if !present || seed == "" {
		return &ServerPreconditionError{
			Reason: ReasonKvExactSeedUnset,
			Err:    errors.New("vllm kvExactMode requires non-empty Gateway LLB_KV_NONE_HASH_SEED matching engine PYTHONHASHSEED"),
		}
	}
	if len(seed) > KvExactSeedMaxLen {
		return &ServerPreconditionError{
			Reason: ReasonKvExactSeedTooLong,
			Err:    errors.New("LLB_KV_NONE_HASH_SEED must be at most 23 bytes for vllm kvExactMode"),
		}
	}
	return nil
}
