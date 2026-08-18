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

// Regression tests for the P/D engine-orchestration guard: pd_disagg_mode
// with kvEngineType="sglang" must be a config-time rejection, because the
// P/D state machine speaks the vLLM disaggregation dialect (max_tokens=1
// prefill rewrite + kv_transfer_params relay) which SGLang servers silently
// mis-serve as truncated single-token output.
//
// The guard is exercised through the extracted pure helper (the
// kvEngineConfigValidate precedent): AddLbRule needs a full CGO datapath
// which does not exist under `go test`, while the helper IS the production
// decision logic, called from exactly one AddLbRule site — the error text
// and semantics pinned here are the wire-visible ones.
//
// Validated on a remote GPU testbed:
//
//	go test ./pkg/loxinet/ -run 'TestPdEngine' -count=1
package loxinet

import (
	"strings"
	"testing"
)

// TestPdEngineOrchestrationValidateAccepts — every pair the datapath serves
// today stays accepted: vLLM P/D (explicit or default engine) and any
// non-P/D rule regardless of engine (sglang single-role included).
func TestPdEngineOrchestrationValidateAccepts(t *testing.T) {
	cases := []struct {
		pdDisagg bool
		engine   string
	}{
		{true, ""},        // today's vLLM P/D, default-spelled
		{true, "vllm"},    // today's vLLM P/D, explicit
		{false, ""},       // plain rule
		{false, "vllm"},   // vLLM converged
		{false, "sglang"}, // SGLang single-role pool (kvExactMode=3 shape)
	}
	for _, c := range cases {
		if err := pdEngineOrchestrationValidate(c.pdDisagg, c.engine); err != nil {
			t.Errorf("pdDisagg=%v engine=%q: want accept, got %v", c.pdDisagg, c.engine, err)
		}
	}
}

// TestPdBootstrapPortValidate — pdBootstrapPort is dead config anywhere but
// an sglang P/D rule: absent (0) always passes; a non-zero port passes ONLY
// with pd_disagg_mode=true AND an sglang engine, and every other shape is
// rejected with an error naming both preconditions.
func TestPdBootstrapPortValidate(t *testing.T) {
	// Absent port: accepted on every shape.
	for _, c := range []struct {
		pdDisagg bool
		engine   string
	}{
		{false, ""}, {false, "vllm"}, {false, "sglang"}, {true, ""}, {true, "vllm"}, {true, "sglang"},
	} {
		if err := pdBootstrapPortValidate(0, c.pdDisagg, c.engine); err != nil {
			t.Errorf("port=0 pdDisagg=%v engine=%q: want accept, got %v", c.pdDisagg, c.engine, err)
		}
	}

	// Non-zero port: only the sglang P/D pair accepts.
	if err := pdBootstrapPortValidate(8998, true, "sglang"); err != nil {
		t.Errorf("port=8998 on sglang P/D: want accept, got %v", err)
	}
	for _, c := range []struct {
		pdDisagg bool
		engine   string
	}{
		{false, ""}, {false, "vllm"}, {false, "sglang"}, {true, ""}, {true, "vllm"},
	} {
		err := pdBootstrapPortValidate(8998, c.pdDisagg, c.engine)
		if err == nil {
			t.Fatalf("port=8998 pdDisagg=%v engine=%q: want reject, got nil", c.pdDisagg, c.engine)
		}
		if !strings.Contains(err.Error(), "pd_disagg_mode") || !strings.Contains(err.Error(), "sglang") {
			t.Errorf("rejection must name both preconditions, got %q", err.Error())
		}
	}
}

// TestPdEngineOrchestrationValidateRejectsSglangPD — behavior case: the
// defective pair is rejected, and the error must point the operator at the
// supported SGLang shape (kvExactMode=3) instead of a bare "no".
func TestPdEngineOrchestrationValidateRejectsSglangPD(t *testing.T) {
	err := pdEngineOrchestrationValidate(true, "sglang")
	if err == nil {
		t.Fatal("pd_disagg_mode+sglang: want reject, got nil")
	}
	if !strings.Contains(err.Error(), "kvExactMode=3") {
		t.Errorf("rejection must name the supported alternative (kvExactMode=3), got %q", err.Error())
	}
}
