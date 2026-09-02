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

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	cmn "github.com/loxilb-io/loxilb/common"
)

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

// The refusal wordings below match no phrase in the message classifier — the
// typed cmn.KvAdmissionError wrap is the ONLY thing standing between them and
// an internal 500 that hides the refusal behind a correlation ref (observed
// live: a strict POST naming an unknown kvModelProfile answered 500).
func TestResultErrorResponseTypedKvAdmissionRefusalIsBadRequest(t *testing.T) {
	tests := []string{
		`kvModelProfile "no-such-profile" is not a published model-prompt profile`,
		`model_name "other" is not served by profile "p1" (alias policy base_model_only admits base model "Qwen/Qwen3-0.6B")`,
		`kvExactApiMode "chat" declares a chat surface but profile "p1" does not support chat`,
		"kvZmqPort is meaningless for kv-engine-type llamacpp (no KV event transport)",
		"kvModelProfile is meaningless without kvExactMode (no KV-exact tier; omit it)",
	}

	for _, msg := range tests {
		wrapped := &cmn.KvAdmissionError{Err: errors.New(msg)}
		got := ResultErrorResponseError(wrapped)
		if got.Code != 400 {
			t.Fatalf("typed refusal %q: want HTTP 400, got %d (%s)", msg, got.Code, got.Result)
		}
		if got.Result != msg {
			t.Fatalf("typed refusal %q: operator-facing detail was not preserved: %q", msg, got.Result)
		}

		// Red-twin guard: the same wording WITHOUT the typed wrap must still
		// fall through to 500 — if a future classifier phrase starts matching
		// these, this test flags that the typed path is no longer what this
		// suite proves load-bearing.
		if plain := ResultErrorResponseError(errors.New(msg)); plain.Code != 500 {
			t.Fatalf("unwrapped %q: expected fall-through 500 (typed wrap load-bearing), got %d", msg, plain.Code)
		}
	}
}

// The status sub-resource's goFenced field is the fence verdict: FALSE (the
// fence is lifted, exact routing is eligible) is as load-bearing an answer
// as true, so the field must marshal explicitly — an omitempty regression
// would erase the lifted-fence verdict from every status read and turn a
// suite's goFenced=false assertion vacuous.
func TestKvExactEnforcementMarshalsExplicitGoFenced(t *testing.T) {
	b, err := json.Marshal(&models.KvExactEnforcement{Desired: "READY", GoFenced: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"goFenced":false`) {
		t.Fatalf("goFenced=false must serialize explicitly, got %s", b)
	}
}
