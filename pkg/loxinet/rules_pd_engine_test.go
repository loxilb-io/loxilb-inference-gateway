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

// Regression tests for the SGLang P/D rule-level config surface.
//
// History note: this file originally pinned a config-time REJECTION of
// pd_disagg_mode + kvEngineType="sglang" (the pre-dual-dispatch guard, when
// the P/D state machine spoke only the vLLM dialect). The SGLang concurrent
// dual-dispatch orchestrator now serves that pair, the guard was removed,
// and acceptance is the absence of any engine/orchestration validator —
// kvEngineConfigValidate's engine allowlist plus pdBootstrapPortValidate
// below are the whole rule-level surface.
//
// The guards are exercised through extracted pure helpers (the
// kvEngineConfigValidate precedent): AddLbRule needs a full CGO datapath
// which does not exist under `go test`, while the helpers ARE the production
// decision logic — the error text and semantics pinned here are the
// wire-visible ones.
//
// Validated on a remote GPU testbed:
//
//	go test ./pkg/loxinet/ -run 'TestPd' -count=1
package loxinet

import (
	"strings"
	"testing"
)

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
