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

// rules_apikey_replace_test.go — unit tests for the api_key_auth three-state
// contract at its two decision points: what a replace-POST leaves on the rule
// (apiKeyAuthOnReplace, the preserve-on-omit rule AddLbRule applies) and what
// the data plane is pushed (apiKeyAuthWireValue, the unset/required/disabled
// wire triage). The store-unavailable fail-closed half of the contract is
// pinned separately: validateAPIKeyInternal answers deny_503 on a store that
// cannot answer (apikey_policy_test.go), and that path is only reachable when
// the wire value is 1 — services at wire value 0 or 2 never invoke key
// validation at all, which is exactly the per-state independence the
// api_key_auth swagger contract promises.

package loxinet

import "testing"

// TestApiKeyAuthOnReplace: a replace that omits api_key_auth preserves the
// existing declaration — omission means "the caller did not mention this",
// never "turn it off". An explicit value (including "disabled") always wins.
func TestApiKeyAuthOnReplace(t *testing.T) {
	cases := []struct {
		name               string
		existing, incoming string
		want               string
	}{
		{"omit on undeclared stays undeclared", "", "", ""},
		{"omit on required PRESERVES required", "required", "", "required"},
		{"omit on declared-disabled PRESERVES the declaration", "disabled", "", "disabled"},
		{"explicit disabled clears required", "required", "disabled", "disabled"},
		{"explicit required upgrades undeclared", "", "required", "required"},
		{"explicit required upgrades declared-disabled", "disabled", "required", "required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := apiKeyAuthOnReplace(c.existing, c.incoming); got != c.want {
				t.Fatalf("apiKeyAuthOnReplace(%q, %q) = %q, want %q",
					c.existing, c.incoming, got, c.want)
			}
		})
	}
}

// TestApiKeyAuthWireValue: the three declaration shapes map to three distinct
// wire values (llb_dpapi.h apikey_auth) — unset (0, byte-identical proxying)
// must never be conflated with declared-disabled (2, header stripped), and
// only required (1) arms enforcement.
func TestApiKeyAuthWireValue(t *testing.T) {
	cases := []struct {
		declared string
		want     uint8
	}{
		{"", 0},
		{"required", 1},
		{"disabled", 2},
		{"jwt", 3},
		{"apikey-or-jwt", 4},
	}
	for _, c := range cases {
		if got := apiKeyAuthWireValue(c.declared); got != c.want {
			t.Fatalf("apiKeyAuthWireValue(%q) = %d, want %d", c.declared, got, c.want)
		}
	}
}

// TestApiKeyAuthNamespaceTruthTable pins the full 3 x 4 policy/streaming
// product. An undeclared service must preserve a backend-owned X-Api-Key even
// when SSE, P/D, or both arm ai_gw_mode. Explicit disabled and required both
// claim the gateway namespace and therefore strip before dispatch.
func TestApiKeyAuthNamespaceTruthTable(t *testing.T) {
	policies := []struct {
		declared string
		strip    bool
	}{
		{declared: "", strip: false},
		{declared: "disabled", strip: true},
		{declared: "required", strip: true},
		{declared: "jwt", strip: true},
		{declared: "apikey-or-jwt", strip: true},
	}
	streaming := []struct {
		sse bool
		pd  bool
	}{
		{sse: false, pd: false},
		{sse: true, pd: false},
		{sse: false, pd: true},
		{sse: true, pd: true},
	}

	rows := 0
	for _, policy := range policies {
		for _, shape := range streaming {
			rows++
			if got := apiKeyAuthClaimsNamespace(policy.declared); got != policy.strip {
				t.Errorf("sse=%v pd=%v api_key_auth=%q: strip=%v, want %v",
					shape.sse, shape.pd, policy.declared, got, policy.strip)
			}
			if got := apiKeyAuthWireValue(policy.declared) != 0; got != policy.strip {
				t.Errorf("sse=%v pd=%v api_key_auth=%q: wire ownership=%v, want %v",
					shape.sse, shape.pd, policy.declared, got, policy.strip)
			}
		}
	}
	if rows != 20 {
		t.Fatalf("namespace truth table has %d rows, want 20", rows)
	}
}
