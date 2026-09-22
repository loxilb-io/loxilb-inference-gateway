/*
 * Copyright (c) 2026 LoxiLB Authors
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
package common

import (
	"strings"
	"testing"
)

// Slots 0..max carry source checks; the first slot past them is refused as a
// server precondition whose sentence carries the budget and the way out.
func TestLbSourceCheckPreconditionBoundary(t *testing.T) {
	for slot := uint64(0); slot <= LbSourceCheckMaxSlot; slot++ {
		if perr := LbSourceCheckPrecondition(slot, int(slot)); perr != nil {
			t.Fatalf("slot %d must carry source checks, got %v", slot, perr)
		}
	}
	perr := LbSourceCheckPrecondition(LbSourceCheckMaxSlot+1, LbSourceCheckSlotCount)
	if perr == nil {
		t.Fatal("slot past the range must be refused")
	}
	if perr.Reason != ReasonLbSourceCheckSlotsExhausted {
		t.Errorf("Reason = %q, want %q", perr.Reason, ReasonLbSourceCheckSlotsExhausted)
	}
	for _, want := range []string{"at most 29 load-balancer rules", "slots 0-28", "all 29 of those slots", "allocated slot 29", "Delete a load-balancer rule"} {
		if !strings.Contains(perr.Error(), want) {
			t.Errorf("sentence lacks %q:\n%s", want, perr.Error())
		}
	}
}

// The tokenizer predicate is nil exactly when the probe admits the model,
// and the refusal keeps the sentence and code clients already branch on.
func TestKvExactTokenizerPrecondition(t *testing.T) {
	if perr := KvExactTokenizerPrecondition("vllm", "m", func(string) bool { return true }); perr != nil {
		t.Fatalf("loadable tokenizer refused: %v", perr)
	}
	for name, probe := range map[string]func(string) bool{
		"probe says no": func(string) bool { return false },
		"no probe":      nil,
	} {
		perr := KvExactTokenizerPrecondition("vllm", "m", probe)
		if perr == nil {
			t.Fatalf("%s: want a refusal", name)
		}
		if perr.Reason != ReasonKvExactTokenizerUnloadable {
			t.Errorf("%s: Reason = %q", name, perr.Reason)
		}
		want := "vllm kvExactMode tokenizer is required and must be loadable for model_name (stage /etc/loxilb/tokenizers/<model-slug>/tokenizer.json or bind a model profile before retry)"
		if perr.Error() != want {
			t.Errorf("%s: sentence changed -- API contract:\n got: %q\nwant: %q", name, perr.Error(), want)
		}
	}
	asked := ""
	_ = KvExactTokenizerPrecondition("vllm", "Qwen/Qwen3-0.6B", func(m string) bool { asked = m; return true })
	if asked != "Qwen/Qwen3-0.6B" {
		t.Errorf("probe asked about %q", asked)
	}
}
