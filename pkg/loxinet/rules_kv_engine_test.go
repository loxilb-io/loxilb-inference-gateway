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
	// Accepted: absent (vllm), explicit vllm, explicit sglang, explicit trtllm
	// (plain LB — the per-feature guards live in kvTrtllmFeatureGuard).
	for _, engine := range []string{"", "vllm", "sglang", "trtllm"} {
		if err := kvEngineConfigValidate(engine, 1); err != nil {
			t.Errorf("engine %q: want accept, got %v", engine, err)
		}
	}

	// Rejected: anything else — and the error must NAME the allowed values.
	for _, engine := range []string{"tensorrt", "VLLM", "sglang ", "trtllm ", "tensorrt-llm", "nats"} {
		err := kvEngineConfigValidate(engine, 1)
		if err == nil {
			t.Fatalf("engine %q: want reject, got nil", engine)
		}
		if !strings.Contains(err.Error(), "vllm") || !strings.Contains(err.Error(), "sglang") ||
			!strings.Contains(err.Error(), "trtllm") {
			t.Errorf("engine %q: rejection must name the allowed values, got %q", engine, err.Error())
		}
	}
}

// TestKvTrtllmFeatureGuard — TRT-LLM plain LB is accepted today; the not-yet-
// shipped orchestration modes and the structurally meaningless knobs are
// rejected loudly at config time (the G1-pattern fix: never let a rule shape
// we can't orchestrate reach the data plane).
func TestKvTrtllmFeatureGuard(t *testing.T) {
	// Non-trtllm engines: the guard is a no-op whatever the other fields say.
	for _, engine := range []string{"", "vllm", "sglang"} {
		if err := kvTrtllmFeatureGuard(engine, 3, true, 5561, 4); err != nil {
			t.Errorf("engine %q: guard must be a no-op, got %v", engine, err)
		}
	}

	// trtllm plain LB: accepted, including the swagger-materialized 5557 default.
	for _, zmq := range []uint16{0, 5557} {
		if err := kvTrtllmFeatureGuard("trtllm", 0, false, zmq, 1); err != nil {
			t.Errorf("trtllm plain LB (zmq=%d): want accept, got %v", zmq, err)
		}
	}

	// Rejected shapes, each naming the offending surface.
	reject := []struct {
		name     string
		kvExact  uint8
		pdDisagg bool
		zmqPort  uint16
		dpRank   uint16
		wantIn   string
	}{
		{"kvExactMode=1", 1, false, 0, 0, "kvExactMode"},
		{"kvExactMode=3", 3, false, 0, 0, "kvExactMode"},
		{"pd_disagg", 0, true, 0, 0, "pd_disagg_mode"},
		{"zmq port", 0, false, 5561, 0, "kvZmqPort"},
		{"dp ranks", 0, false, 0, 2, "kvDpRankCount"},
	}
	for _, c := range reject {
		err := kvTrtllmFeatureGuard("trtllm", c.kvExact, c.pdDisagg, c.zmqPort, c.dpRank)
		if err == nil {
			t.Fatalf("%s: want reject, got nil", c.name)
		}
		if !strings.Contains(err.Error(), c.wantIn) {
			t.Errorf("%s: rejection must name %q, got %q", c.name, c.wantIn, err.Error())
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

// TestKvHashAlgoEffective pins the engine⇒hash-algo default resolution against
// dpebpf_linux.go's branch order, which is the single source of truth for what
// the C hasher actually runs. If the two ever drift, an SGLang rule silently
// hashes with the vLLM CBOR contract and Tier 1.5 scores zero forever.
func TestKvHashAlgoEffective(t *testing.T) {
	cases := []struct {
		algo, engine, want string
	}{
		// Absent algo takes the engine default ("" ≡ "vllm").
		{"", "", "sha256_cbor"},
		{"", "vllm", "sha256_cbor"},
		{"", "sglang", "sha256_sglang"},
		{"", "trtllm", "blockhash_trtllm"},
		// An explicit algo always wins over the engine default.
		{"xxhash_cbor", "vllm", "xxhash_cbor"},
		{"sha256_cbor", "", "sha256_cbor"},
		{"sha256_sglang", "sglang", "sha256_sglang"},
		{"blockhash_trtllm", "trtllm", "blockhash_trtllm"},
	}
	for _, c := range cases {
		if got := kvHashAlgoEffective(c.algo, c.engine); got != c.want {
			t.Errorf("kvHashAlgoEffective(%q, %q) = %q, want %q", c.algo, c.engine, got, c.want)
		}
	}
}

// TestKvHashAlgoValidateCoherence — an explicit kvHashAlgo that contradicts
// kvEngineType must be REJECTED at config time. Before this guard the pair was
// accepted and every computed block hash missed the engine-published inventory,
// with no signal until the [KV_ZEROHIT] watchdog fired. The contracts are
// mutually exclusive: sha256_sglang hashes parent||tokens raw and truncates to
// the FIRST 8 digest bytes; the cbor family CBOR-encodes and takes the LAST 8.
func TestKvHashAlgoValidateCoherence(t *testing.T) {
	// Accepted — including every shape the shipped cicd scenarios POST.
	accept := []struct{ algo, engine string }{
		{"", ""},                       // default rule, no KV fields
		{"", "vllm"},                   // explicit vllm, engine default
		{"", "sglang"},                 // cicd/sglang-loxilb-kvcache rule B
		{"sha256_cbor", ""},            // cicd/vllm-kvcache-routing-cpu
		{"sha256_cbor", "vllm"},        // same, engine spelled out
		{"xxhash_cbor", "vllm"},        // vLLM's other contract
		{"sha256_sglang", "sglang"},    // SGLang contract pinned explicitly
		{"", "trtllm"},                 // trtllm rule, engine default
		{"blockhash_trtllm", "trtllm"}, // TRT-LLM contract pinned explicitly
	}
	for _, c := range accept {
		if err := kvHashAlgoValidate(c.algo, c.engine); err != nil {
			t.Errorf("algo=%q engine=%q: want accept, got %v", c.algo, c.engine, err)
		}
	}

	// Rejected — the incoherent pairs, and the rejection must name BOTH the
	// offending algo and the engine so the operator can act on it.
	reject := []struct{ algo, engine string }{
		{"sha256_cbor", "sglang"},      // the API-spec-default trap
		{"xxhash_cbor", "sglang"},      // the other cbor contract
		{"sha256_sglang", "vllm"},      // mirror image
		{"sha256_sglang", ""},          // "" ≡ vllm
		{"blockhash_trtllm", "vllm"},   // trtllm hash on a vllm rule
		{"blockhash_trtllm", "sglang"}, // and on an sglang rule
		{"sha256_cbor", "trtllm"},      // cbor contract on a trtllm rule
		{"sha256_sglang", "trtllm"},    // sglang contract on a trtllm rule
	}
	for _, c := range reject {
		err := kvHashAlgoValidate(c.algo, c.engine)
		if err == nil {
			t.Fatalf("algo=%q engine=%q: want reject, got nil", c.algo, c.engine)
		}
		if !strings.Contains(err.Error(), c.algo) ||
			!strings.Contains(err.Error(), kvEngineEffective(c.engine)) {
			t.Errorf("algo=%q engine=%q: rejection must name both, got %q", c.algo, c.engine, err.Error())
		}
	}
}

// TestKvHashAlgoValidateAllowlist — an unknown kvHashAlgo is rejected outright
// (never silently coerced), mirroring the kvEngineType allowlist.
func TestKvHashAlgoValidateAllowlist(t *testing.T) {
	for _, algo := range []string{"sha256", "SHA256_CBOR", "sha256_cbor ", "md5", "xxhash"} {
		err := kvHashAlgoValidate(algo, "vllm")
		if err == nil {
			t.Fatalf("algo %q: want reject, got nil", algo)
		}
		if !strings.Contains(err.Error(), "sha256_sglang") {
			t.Errorf("algo %q: rejection must name the allowed values, got %q", algo, err.Error())
		}
	}
}
