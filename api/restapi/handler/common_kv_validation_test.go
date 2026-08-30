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

package handler

import "testing"

func TestResultErrorResponseClassifiesKvRuntimePrerequisitesAsBadRequest(t *testing.T) {
	tests := []string{
		"model_name is required for vllm kvExactMode (must equal the served model and staged tokenizer identity)",
		"vllm kvExactMode requires non-empty Gateway LLB_KV_NONE_HASH_SEED matching engine PYTHONHASHSEED",
		"vllm kvExactMode tokenizer is required and must be loadable for model_name (stage /etc/loxilb/tokenizers/<model-slug>/tokenizer.json before retry)",
	}

	for _, msg := range tests {
		got := ResultErrorResponseErrorMessage(msg)
		if got.Code != 400 {
			t.Fatalf("message %q: want HTTP 400 classification, got %d (%s)", msg, got.Code, got.Result)
		}
		if got.Result != msg {
			t.Fatalf("message %q: operator-facing validation detail was not preserved: %q", msg, got.Result)
		}
	}
}
