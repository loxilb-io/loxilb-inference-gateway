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
 * ai_kv_tokenizer_hf.go — HuggingFace tokenizer backend using daulet/tokenizers.
 *
 * Implements the KvTokenizerBackend and KvTokenizer interfaces defined in
 * ai_kv_router.go using the daulet/tokenizers Rust CGO wrapper.
 * This produces bit-for-bit identical token IDs to Python transformers
 * AutoTokenizer, which is required for correct KV block hash computation
 * (Tier 1.5 routing, TK11 hash parity test).
 *
 * Tokenizer files must be staged at:
 *   /etc/loxilb/tokenizers/<model-slug>/tokenizer.json
 * where model-slug = strings.ReplaceAll(modelName, "/", "__")
 *
 * Usage (called once during loxiNetInit):
 * KvRegisterTokenizerBackend(NewHFTokenizerBackend)
 */

package loxinet

import (
	tk "github.com/loxilb-io/loxilib"

	daul "github.com/daulet/tokenizers"
)

// HFTokenizerBackend implements KvTokenizerBackend using the daulet/tokenizers
// Rust-backed library. Pre-built static libraries are bundled with the Go module.
type HFTokenizerBackend struct{}

// NewHFTokenizerBackend returns a new HuggingFace tokenizer backend.
func NewHFTokenizerBackend() *HFTokenizerBackend {
	return &HFTokenizerBackend{}
}

// Name returns the backend name for logging.
func (b *HFTokenizerBackend) Name() string {
	return "daulet/tokenizers (HuggingFace Rust wrapper)"
}

// LoadModel loads a tokenizer from the given tokenizer.json path.
// Returns nil if the file is missing or cannot be parsed.
//
// Gap-B2 (special-token parity): use daulet's DEFAULT construction
// (FromFile), which maps to HF Rust tokenizers encode_special_tokens=false —
// meaning embedded special-token strings (e.g. the literal "<|im_end|>" that
// mooncake / chat-templated prompts contain) ARE RECOGNIZED as their single
// special IDs (151645 for Qwen2.5), matching vLLM's AutoTokenizer that produces
// the cached block token_ids the KV-exact hashes must match.
//
// IMPORTANT — daulet's WithEncodeSpecialTokens (encode_special_tokens=true) does
// the OPPOSITE: it SPLITS "<|im_end|>" into 6 normal tokens (<,|,im,_end,|,>),
// shifting every 16-token block boundary and yielding zero inventory matches.
// (This is the inverse of transformers' split_special_tokens flag — verified live
// on Qwen2.5-7B: the option produced [27,91,318,6213,91,29,...] = no match;
// the default produces [151645,...] == vLLM.) So we must NOT pass the option.
// See cicd/common/kv_hash/fixtures/kv_special_token_parity.json.
func (b *HFTokenizerBackend) LoadModel(tokenizerPath string) KvTokenizer {
	t, err := daul.FromFile(tokenizerPath)
	if err != nil {
		tk.LogIt(tk.LogDebug, "[KV] tokenizer load failed for %s: %v\n", tokenizerPath, err)
		return nil
	}
	tk.LogIt(tk.LogDebug, "[KV] tokenizer loaded from %s (encode_special_tokens=false: specials recognized)\n", tokenizerPath)
	return &hfTokenizerInstance{t: t}
}

// LoadModelBytes parses a tokenizer from in-memory tokenizer.json contents
// (the digest-verified buffer of a published model profile). Same default
// construction as LoadModel: encode_special_tokens=false, so embedded
// special-token strings are recognized as their single special IDs.
func (b *HFTokenizerBackend) LoadModelBytes(data []byte) KvTokenizer {
	t, err := daul.FromBytes(data)
	if err != nil {
		tk.LogIt(tk.LogDebug, "[KV] tokenizer load from verified bytes failed: %v\n", err)
		return nil
	}
	return &hfTokenizerInstance{t: t}
}

// hfTokenizerInstance wraps a daulet/tokenizers.Tokenizer to implement KvTokenizer.
type hfTokenizerInstance struct {
	t *daul.Tokenizer
}

// Encode tokenizes text and returns the token ID slice. addSpecialTokens maps
// to HF add_special_tokens: it must be true for raw completions prompts (vLLM
// tokenizes those with add_special_tokens=True, so BOS-declaring tokenizers
// like Llama-3 prepend <|begin_of_text|> to the cached block stream) and false
// for chat-template-rendered text (the template supplies the specials and vLLM
// encodes the render with add_special_tokens=False). Passing the wrong mode on
// a BOS model shifts every block boundary and yields zero inventory matches.
func (h *hfTokenizerInstance) Encode(text string, addSpecialTokens bool) []uint32 {
	if h.t == nil {
		return nil
	}
	ids, _ := h.t.Encode(text, addSpecialTokens)
	return ids
}

// Close releases the underlying Rust tokenizer resources.
func (h *hfTokenizerInstance) Close() {
	if h.t != nil {
		// daulet/tokenizers v1.x Close returns an error; ignore on shutdown.
		_ = h.t.Close()
	}
}
