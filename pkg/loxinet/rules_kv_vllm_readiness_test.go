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
	"strings"
	"testing"
)

func TestKvVllmExactRuntimeValidate(t *testing.T) {
	tests := []struct {
		name           string
		engine         string
		mode           uint8
		model          string
		seed           string
		seedPresent    bool
		tokenizerReady bool
		wantErr        string
	}{
		{name: "vllm exact ready", engine: "vllm", mode: 1, model: "Qwen/Qwen2.5-7B-Instruct", seed: "0", seedPresent: true, tokenizerReady: true},
		{name: "implicit vllm exact ready", engine: "", mode: KvExactModeSingleRole, model: "model-a", seed: "seed", seedPresent: true, tokenizerReady: true},
		{name: "exact model required", engine: "vllm", mode: 1, seed: "0", seedPresent: true, tokenizerReady: true, wantErr: "model_name"},
		{name: "seed missing", engine: "vllm", mode: 1, model: "model-a", tokenizerReady: true, wantErr: "LLB_KV_NONE_HASH_SEED"},
		{name: "seed empty", engine: "vllm", mode: 1, model: "model-a", seedPresent: true, tokenizerReady: true, wantErr: "LLB_KV_NONE_HASH_SEED"},
		{name: "seed too long", engine: "vllm", mode: 1, model: "model-a", seed: "123456789012345678901234", seedPresent: true, tokenizerReady: true, wantErr: "23 bytes"},
		{name: "tokenizer missing", engine: "vllm", mode: 1, model: "model-a", seed: "0", seedPresent: true, wantErr: "must be loadable"},
		{name: "vllm exact off", engine: "vllm", mode: 0},
		{name: "sglang does not use vllm parent", engine: "sglang", mode: 1},
		{name: "trtllm does not use vllm parent", engine: "trtllm", mode: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(string) (string, bool) { return tt.seed, tt.seedPresent }
			ready := func(string) bool { return tt.tokenizerReady }
			err := kvVllmExactRuntimeValidate(tt.engine, tt.mode, tt.model, getenv, ready)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want rejection containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestKvVllmExactRuntimeValidateSkipsTokenizerOutsideVllmExact(t *testing.T) {
	called := false
	ready := func(string) bool {
		called = true
		return false
	}
	getenv := func(string) (string, bool) { return "", false }

	for _, tc := range []struct {
		engine string
		mode   uint8
	}{{engine: "vllm", mode: 0}, {engine: "sglang", mode: 1}, {engine: "trtllm", mode: 3}} {
		if err := kvVllmExactRuntimeValidate(tc.engine, tc.mode, "", getenv, ready); err != nil {
			t.Fatalf("engine=%q mode=%d: unexpected error: %v", tc.engine, tc.mode, err)
		}
	}
	if called {
		t.Fatal("tokenizer readiness must not be evaluated outside vllm exact mode")
	}
}
