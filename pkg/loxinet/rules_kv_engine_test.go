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

// plan 04 (SGL-03/SGL-04) — regression tests for the per-rule KV
// engine config guards: the ASVS V4/V5 allowlist + bounds validation, the
// engine-immutability rejection (""≡"vllm" equivalence), and the
// same-VIP-different-engine coexistence detection that drives the WARN.
//
// The guards are exercised through the extracted pure helpers
// kvSubscriberTargets precedent): AddLbRule needs a full CGO datapath which
// does not exist under `go test`, while the helpers ARE the production
// decision logic — kvEngineConfigValidate / kvEngineImmutabilityCheck /
// kvEngineMixDetect are called from exactly one AddLbRule site each, so the
// error text and semantics pinned here are the wire-visible ones.
//
// Validated on a remote GPU testbed:
//
//	go test ./pkg/loxinet/ -run 'TestKvEngine' -count=1
package loxinet

import (
	"strings"
	"testing"
)

// TestKvEngineConfigValidateAllowlist — behavior case 1: a rule add with a
// non-allowlisted kvEngineType (e.g. "tensorrt") is rejected with an error
// naming the allowed values; unknown strings are never silently treated as
// vllm.
func TestKvEngineConfigValidateAllowlist(t *testing.T) {
	// Accepted: absent (vllm), explicit vllm, explicit sglang.
	for _, engine := range []string{"", "vllm", "sglang"} {
		if err := kvEngineConfigValidate(engine, 1); err != nil {
			t.Errorf("engine %q: want accept, got %v", engine, err)
		}
	}

	// Rejected: anything else — and the error must NAME the allowed values.
	for _, engine := range []string{"tensorrt", "VLLM", "sglang ", "trtllm", "nats"} {
		err := kvEngineConfigValidate(engine, 1)
		if err == nil {
			t.Fatalf("engine %q: want reject, got nil", engine)
		}
		if !strings.Contains(err.Error(), "vllm") || !strings.Contains(err.Error(), "sglang") {
			t.Errorf("engine %q: rejection must name the allowed values, got %q", engine, err.Error())
		}
	}
}

// TestKvEngineConfigValidateRankBounds — behavior case 2: kvDpRankCount 0 is
// accepted (defaults to 1 downstream); 9 is rejected (bounds 18 —
// rank N subscribes kvZmqPort+N on every EP host, so the cap bounds the
// port-range walk, / ASVS V4).
func TestKvEngineConfigValidateRankBounds(t *testing.T) {
	for _, rank := range []uint16{0, 1, 2, 8} {
		if err := kvEngineConfigValidate("sglang", rank); err != nil {
			t.Errorf("rank %d: want accept, got %v", rank, err)
		}
	}
	for _, rank := range []uint16{9, 16, 65535} {
		err := kvEngineConfigValidate("sglang", rank)
		if err == nil {
			t.Fatalf("rank %d: want reject, got nil", rank)
		}
		if !strings.Contains(err.Error(), "1..8") {
			t.Errorf("rank %d: rejection must state the 1..8 bounds, got %q", rank, err.Error())
		}
	}
}

// TestKvEngineImmutability — behavior cases 3+4: a rule replace changing
// kvEngineType (vllm→sglang or the inverse) is rejected with the exact
// message (paired with RuleExistsErr at the AddLbRule call site); a replace
// with the engine unchanged — INCLUDING absent→"vllm" and "vllm"→absent
// (""≡"vllm": a PUT that starts spelling the default out loud must not brick
// the rule) — proceeds exactly as today.
func TestKvEngineImmutability(t *testing.T) {
	const wantMsg = "lbrule-exist error: cant modify rule kv engine type (delete and recreate)"

	rejected := []struct{ existing, incoming string }{
		{"vllm", "sglang"},
		{"sglang", "vllm"},
		{"", "sglang"}, // absent means vllm — flipping to sglang is a change
		{"sglang", ""}, // and the inverse
	}
	for _, c := range rejected {
		err := kvEngineImmutabilityCheck(c.existing, c.incoming)
		if err == nil {
			t.Fatalf("engine change %q -> %q: want reject, got nil", c.existing, c.incoming)
		}
		if err.Error() != wantMsg {
			t.Errorf("engine change %q -> %q: want exact message %q, got %q",
				c.existing, c.incoming, wantMsg, err.Error())
		}
	}

	accepted := []struct{ existing, incoming string }{
		{"", ""},         // absent -> absent
		{"vllm", "vllm"}, // explicit unchanged
		{"", "vllm"},     // equivalence: spelling the default out loud
		{"vllm", ""},     // and the inverse (GET round-trip of a legacy rule)
		{"sglang", "sglang"},
	}
	for _, c := range accepted {
		if err := kvEngineImmutabilityCheck(c.existing, c.incoming); err != nil {
			t.Errorf("engine unchanged %q -> %q: want accept, got %v", c.existing, c.incoming, err)
		}
	}
}

// TestKvEngineEqualDefaultEquivalence pins the ""≡"vllm" resolution helper the
// immutability guard is built on (default + comparison semantics).
func TestKvEngineEqualDefaultEquivalence(t *testing.T) {
	if got := kvEngineEffective(""); got != "vllm" {
		t.Errorf("kvEngineEffective(\"\") = %q, want \"vllm\"", got)
	}
	if got := kvEngineEffective("sglang"); got != "sglang" {
		t.Errorf("kvEngineEffective(\"sglang\") = %q, want \"sglang\"", got)
	}
	if !kvEngineEqual("", "vllm") || !kvEngineEqual("vllm", "") {
		t.Error("\"\" and \"vllm\" must compare EQUAL in both directions")
	}
	if kvEngineEqual("", "sglang") || kvEngineEqual("sglang", "vllm") {
		t.Error("sglang must NOT compare equal to vllm/absent")
	}
}

// TestKvEngineMixDetect — behavior case 5: two rules on the same VIP IP but
// different ports with different engines are ACCEPTED (— that IS the
// multi-framework coexistence story); the detector returns the differing
// engine so AddLbRule emits one WARN naming both engines. Same-engine and
// ""/"vllm"-only neighbourhoods are NOT a mix.
func TestKvEngineMixDetect(t *testing.T) {
	// sglang rule added beside existing default-vllm rules: mixed, other=vllm.
	if other, mixed := kvEngineMixDetect("sglang", []string{"", "vllm"}); !mixed || other != "vllm" {
		t.Errorf("sglang vs [\"\",\"vllm\"]: want (vllm,true), got (%q,%v)", other, mixed)
	}
	// vllm (spelled or absent) rule added beside an existing sglang rule.
	if other, mixed := kvEngineMixDetect("", []string{"sglang"}); !mixed || other != "sglang" {
		t.Errorf("absent vs [sglang]: want (sglang,true), got (%q,%v)", other, mixed)
	}
	// ""/"vllm" neighbourhood is NOT a mix (equivalence).
	if other, mixed := kvEngineMixDetect("vllm", []string{"", "vllm", ""}); mixed {
		t.Errorf("vllm vs [\"\",\"vllm\",\"\"]: want no mix, got (%q,%v)", other, mixed)
	}
	// Homogeneous sglang VIP is NOT a mix.
	if other, mixed := kvEngineMixDetect("sglang", []string{"sglang", "sglang"}); mixed {
		t.Errorf("sglang vs [sglang,sglang]: want no mix, got (%q,%v)", other, mixed)
	}
	// No co-VIP rules at all.
	if other, mixed := kvEngineMixDetect("sglang", nil); mixed {
		t.Errorf("sglang vs none: want no mix, got (%q,%v)", other, mixed)
	}
}
