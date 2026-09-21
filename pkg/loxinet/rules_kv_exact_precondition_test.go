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
package loxinet

import (
	"errors"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestKvExactSeedRefusalsAreServerPreconditions: on a gateway launched
// without a usable LLB_KV_NONE_HASH_SEED, EVERY vLLM KV-exact rule is
// refused -- every tenant, every model, every kvExactMode value -- and
// nothing an API client can send will succeed. That is a property of the
// gateway's launch environment, not of the request, so the refusal carries
// cmn.ServerPreconditionError and the API layer answers 412 instead of a
// 400 that tells the client its input was malformed.
//
// The messages are asserted in full, not by substring: they name the
// variable, the required relationship and the counterpart setting, they are
// the only actionable part of the response, and a consumer's readiness gate
// matches on them. Rewording one is a contract change, and this is where it
// has to be noticed.
func TestKvExactSeedRefusalsAreServerPreconditions(t *testing.T) {
	cases := []struct {
		name    string
		getenv  func(string) (string, bool)
		reason  string
		message string
	}{
		{
			name:    "unset",
			getenv:  func(string) (string, bool) { return "", false },
			reason:  cmn.ReasonKvExactSeedUnset,
			message: "vllm kvExactMode requires non-empty Gateway LLB_KV_NONE_HASH_SEED matching engine PYTHONHASHSEED",
		},
		{
			name:    "present but empty",
			getenv:  func(string) (string, bool) { return "", true },
			reason:  cmn.ReasonKvExactSeedUnset,
			message: "vllm kvExactMode requires non-empty Gateway LLB_KV_NONE_HASH_SEED matching engine PYTHONHASHSEED",
		},
		{
			name:    "longer than the representable bound",
			getenv:  func(string) (string, bool) { return strings.Repeat("s", 24), true },
			reason:  cmn.ReasonKvExactSeedTooLong,
			message: "LLB_KV_NONE_HASH_SEED must be at most 23 bytes for vllm kvExactMode",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := admissionDeps(func(d *kvExactAdmissionDeps) { d.getenv = tc.getenv })
			_, err := kvExactRuntimeValidate("vllm", 3, "model-a", "", "", deps)
			if err == nil {
				t.Fatal("want a refusal, got nil")
			}
			var precond *cmn.ServerPreconditionError
			if !errors.As(err, &precond) {
				t.Fatalf("refusal is not a ServerPreconditionError: %#v", err)
			}
			if precond.Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", precond.Reason, tc.reason)
			}
			if err.Error() != tc.message {
				t.Errorf("message changed -- this is an API contract change:\n got: %q\nwant: %q", err.Error(), tc.message)
			}
		})
	}

	// The 23-byte bound is inclusive: a seed exactly at it is serviceable,
	// so it must not be refused at all. Without this the "too long" case
	// above would still pass against an off-by-one that refuses valid
	// deployments with a precondition they cannot satisfy.
	t.Run("exactly at the bound is accepted", func(t *testing.T) {
		deps := admissionDeps(func(d *kvExactAdmissionDeps) {
			d.getenv = func(string) (string, bool) { return strings.Repeat("s", 23), true }
		})
		if _, err := kvExactRuntimeValidate("vllm", 3, "model-a", "", "", deps); err != nil {
			t.Fatalf("a 23-byte seed must be accepted, got %v", err)
		}
	})
}

// TestKvExactClientRefusalsAreNotPreconditions is the control the case above
// needs: a refusal a client CAN fix by sending different fields must stay an
// input rejection and keep its 400. Without this pair, typing every refusal
// as a precondition would pass the test above and silently tell operators to
// go reconfigure their gateway over a typo.
func TestKvExactClientRefusalsAreNotPreconditions(t *testing.T) {
	cases := []struct {
		name string
		run  func() error
	}{
		{"model_name omitted", func() error {
			_, err := kvExactRuntimeValidate("vllm", 3, "", "", "", admissionDeps(nil))
			return err
		}},
		{"tokenizer not loadable", func() error {
			deps := admissionDeps(func(d *kvExactAdmissionDeps) {
				d.tokenizerReady = func(string) bool { return false }
			})
			_, err := kvExactRuntimeValidate("vllm", 3, "model-a", "", "", deps)
			return err
		}},
		{"profile not published", func() error {
			_, err := kvExactRuntimeValidate("vllm", 3, "model-a", "", "prof-missing", admissionDeps(nil))
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil {
				t.Fatal("want a refusal, got nil")
			}
			var precond *cmn.ServerPreconditionError
			if errors.As(err, &precond) {
				t.Fatalf("a client-fixable refusal must NOT be a server precondition: %v", err)
			}
		})
	}
}

// TestKvExactSeedPreconditionIsVllmOnly guards the scope of the change: the
// NONE-hash seed is a vLLM addendum. SGLang hashes parent||tokens raw with
// no seed, so typing this refusal must not start refusing other engines on a
// gateway that has no seed set.
func TestKvExactSeedPreconditionIsVllmOnly(t *testing.T) {
	deps := admissionDeps(func(d *kvExactAdmissionDeps) {
		d.getenv = func(string) (string, bool) { return "", false }
	})
	for _, eng := range []string{"sglang", "trtllm"} {
		if _, err := kvExactRuntimeValidate(eng, 3, "model-a", "", "", deps); err != nil {
			t.Errorf("%s must not carry the vllm seed precondition: %v", eng, err)
		}
	}
}
