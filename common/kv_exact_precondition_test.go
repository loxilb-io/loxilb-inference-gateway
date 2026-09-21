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

import (
	"strings"
	"testing"
)

func envFunc(value string, present bool) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if name != KvExactSeedEnv {
			return "", false
		}
		return value, present
	}
}

// TestKvExactSeedPrecondition pins the predicate both rule admission and the
// capability surface read. The messages are asserted in full: they are the
// operator-facing answer, they are what the 412 refusal carries, and a
// consumer's readiness gate matches on them, so a reword is a contract change
// and this is where it must be noticed.
func TestKvExactSeedPrecondition(t *testing.T) {
	const unsetMsg = "vllm kvExactMode requires non-empty Gateway LLB_KV_NONE_HASH_SEED matching engine PYTHONHASHSEED"
	const longMsg = "LLB_KV_NONE_HASH_SEED must be at most 23 bytes for vllm kvExactMode"

	cases := []struct {
		name    string
		getenv  func(string) (string, bool)
		reason  string
		message string
	}{
		{"absent from the environment", envFunc("", false), ReasonKvExactSeedUnset, unsetMsg},
		{"present but empty", envFunc("", true), ReasonKvExactSeedUnset, unsetMsg},
		{"one byte over the bound", envFunc(strings.Repeat("s", KvExactSeedMaxLen+1), true), ReasonKvExactSeedTooLong, longMsg},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			perr := KvExactSeedPrecondition(tc.getenv)
			if perr == nil {
				t.Fatal("want a precondition, got nil")
			}
			if perr.Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", perr.Reason, tc.reason)
			}
			if perr.Error() != tc.message {
				t.Errorf("message changed -- this is an API contract change:\n got: %q\nwant: %q", perr.Error(), tc.message)
			}
		})
	}

	// The bound is inclusive, and a satisfied precondition returns nil.
	// Without these the cases above would pass against a predicate that
	// refuses every deployment, including correct ones.
	for _, ok := range []struct {
		name string
		seed string
	}{
		{"a short seed", "abc"},
		{"exactly at the bound", strings.Repeat("s", KvExactSeedMaxLen)},
	} {
		t.Run(ok.name+" is satisfied", func(t *testing.T) {
			if perr := KvExactSeedPrecondition(envFunc(ok.seed, true)); perr != nil {
				t.Fatalf("want nil, got %v (%s)", perr, perr.Reason)
			}
		})
	}
}
