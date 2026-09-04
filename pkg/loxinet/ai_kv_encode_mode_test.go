/*
 * Copyright (c) 2025 LoxiLB Authors
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

/*
 * ai_kv_encode_mode_test.go — pins the add_special_tokens contract between
 * the tokenize bridges and the engine.
 *
 * vLLM tokenizes a raw /v1/completions prompt with add_special_tokens=True
 * (BOS-declaring tokenizers such as Llama-3 prepend <|begin_of_text|> to the
 * cached block stream) and a chat-template render with
 * add_special_tokens=False (the render carries its own specials). A bridge
 * that encodes in the wrong mode shifts every block boundary on a BOS model
 * and produces zero inventory matches — observed live as an exact arm with
 * 0 tier-1.5 hits against Llama-3.1 while Qwen (no BOS) was unaffected.
 */

package loxinet

import (
	"testing"
)

// flagRecordingTokenizer records the addSpecialTokens mode of every Encode
// call so a test can assert which mode a caller used.
type flagRecordingTokenizer struct {
	modes []bool
}

func (f *flagRecordingTokenizer) Encode(text string, addSpecialTokens bool) []uint32 {
	f.modes = append(f.modes, addSpecialTokens)
	return []uint32{1, 2, 3}
}

func (f *flagRecordingTokenizer) Close() {}

func kvEncodeModeInstallTokenizer(t *testing.T, modelName string) *flagRecordingTokenizer {
	t.Helper()
	KvTokenCacheReset()
	KvTokenizerPoolReset()
	t.Cleanup(KvTokenCacheReset)
	t.Cleanup(KvTokenizerPoolReset)
	KvRegisterTokenizerBackend(&mockBackend{tokenizers: map[string]*mockTokenizer{}})
	t.Cleanup(func() { KvRegisterTokenizerBackend(nil) })

	rec := &flagRecordingTokenizer{}
	kvTokenizerMu.Lock()
	kvTokenizerPool[kvModelSlug(modelName)] = rec
	kvTokenizerMu.Unlock()
	return rec
}

// TestKvBridgeTokenizeUsesSpecials: the completions bridge must encode with
// specials — the engine tokenized the same raw prompt with its default
// add_special_tokens=True.
func TestKvBridgeTokenizeUsesSpecials(t *testing.T) {
	rec := kvEncodeModeInstallTokenizer(t, "test-model")

	tokens, rc := kvBridgeTokenize(0, 0, "raw completion prompt", "test-model", 100)
	if rc != 0 || len(tokens) != 3 {
		t.Fatalf("bridge tokenize failed: rc=%d tokens=%v", rc, tokens)
	}
	if len(rec.modes) != 1 || rec.modes[0] != true {
		t.Fatalf("completions bridge encoded with modes %v, want [true]", rec.modes)
	}
}

// TestKvBridgeTokenizeChatUsesNoSpecials: the chat bridge tokenizes the
// template render, which already carries its special tokens; vLLM encodes it
// with add_special_tokens=False, so a second BOS must not be prepended.
func TestKvBridgeTokenizeChatUsesNoSpecials(t *testing.T) {
	// Publish a chat profile for the test model explicitly: this test is
	// about the encode mode downstream of the render, not about how the
	// renderer was resolved.
	kvTestPublishChatProfile(t, "Qwen/encode-mode-test",
		"{% for message in messages %}<|im_start|>{{ message.role }}\n{{ message.content }}<|im_end|>\n{% endfor %}<|im_start|>assistant\n",
		KvRenderPolicy{AddGenerationPrompt: true})
	rec := kvEncodeModeInstallTokenizer(t, "Qwen/encode-mode-test")

	body := `{"messages":[{"role":"user","content":"hi"}]}`
	tokens, rc := kvBridgeTokenizeChat(0, 0, body, "Qwen/encode-mode-test", 100)
	if rc != 0 || len(tokens) != 3 {
		t.Fatalf("chat bridge tokenize failed: rc=%d tokens=%v", rc, tokens)
	}
	if len(rec.modes) != 1 || rec.modes[0] != false {
		t.Fatalf("chat bridge encoded with modes %v, want [false]", rec.modes)
	}
}

// TestKvChallengeTokenizeUsesSpecials: the attestation echo challenge posts
// its prompt to /v1/completions with no add_special_tokens override, so the
// expected hash chain must be built from the specials-included encoding.
func TestKvChallengeTokenizeUsesSpecials(t *testing.T) {
	rec := kvEncodeModeInstallTokenizer(t, "test-model")

	ids := kvChallengeTokenizeFn("challenge prompt", "test-model", 100)
	if len(ids) != 3 {
		t.Fatalf("challenge tokenize returned %v", ids)
	}
	if len(rec.modes) != 1 || rec.modes[0] != true {
		t.Fatalf("challenge encoded with modes %v, want [true]", rec.modes)
	}
}

// TestKvTokenCacheEncodeModeIsolation: the encode mode is part of the token
// cache identity. On a BOS tokenizer the two modes yield different id
// streams for identical text; a cache entry shared across modes would hand
// one mode's tokens to the other (exactly the boundary-shift defect this
// file pins, resurrected through the cache).
func TestKvTokenCacheEncodeModeIsolation(t *testing.T) {
	KvTokenCacheReset()
	KvTokenizerPoolReset()
	defer KvTokenCacheReset()
	defer KvTokenizerPoolReset()
	KvRegisterTokenizerBackend(&mockBackend{tokenizers: map[string]*mockTokenizer{}})
	defer KvRegisterTokenizerBackend(nil)

	// contentTokenizer folds the mode into its output the way a BOS
	// tokenizer does, so a mode-blind cache key surfaces as an id mismatch.
	kvTokenizerMu.Lock()
	kvTokenizerPool[kvModelSlug("test-model")] = &contentTokenizer{}
	kvTokenizerMu.Unlock()

	withSpecials := kvTokenizeWithCache("same text", "test-model", 100, true)
	withoutSpecials := kvTokenizeWithCache("same text", "test-model", 100, false)
	if len(withSpecials) == 0 || len(withoutSpecials) == 0 {
		t.Fatal("tokenization failed")
	}
	same := len(withSpecials) == len(withoutSpecials)
	if same {
		for i := range withSpecials {
			if withSpecials[i] != withoutSpecials[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Fatal("modes returned identical ids for a mode-sensitive tokenizer: cache key ignores encode mode")
	}

	// Cached round-trips must stay mode-faithful.
	again := kvTokenizeWithCache("same text", "test-model", 100, true)
	for i := range withSpecials {
		if again[i] != withSpecials[i] {
			t.Fatalf("cached specials encode diverged at %d: %d != %d", i, again[i], withSpecials[i])
		}
	}
}
