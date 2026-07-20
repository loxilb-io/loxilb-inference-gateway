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
 * ai_kv_router.go — HuggingFace tokenizer pool with LRU token cache.
 *
 * Provides the llb_ai_kv_tokenize CGO export called by sockproxy_kv_exact.c
 * in the Tier 1.5 KV block-hash routing hot path.
 *
 * Tokenizer loading:
 *   Tokenizer files must be pre-staged at /etc/loxilb/tokenizers/<model-slug>/tokenizer.json
 *   where model-slug = strings.ReplaceAll(modelName, "/", "__").
 *   The tokenizer backend is pluggable via KvTokenizerBackend interface.
 *   If no backend is registered or the tokenizer file is missing, returns -1 (silent fallthrough).
 */

package loxinet

/*
#include <stdint.h>
*/
import "C"

import (
	"sync"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// KvTokenizerBackend is the interface for pluggable tokenizer implementations.
// Implementations must produce bit-for-bit identical token IDs as Python HuggingFace.
type KvTokenizerBackend interface {
	// LoadModel loads a tokenizer for the given model from the filesystem.
	// tokenizerPath is the path to tokenizer.json.
	// Returns nil on error (file not found, parse error, etc.)
	LoadModel(tokenizerPath string) KvTokenizer

	// Name returns the backend name for logging.
	Name() string
}

// KvTokenizer is a loaded tokenizer instance for a specific model.
type KvTokenizer interface {
	// Encode tokenizes text and returns token IDs.
	Encode(text string) []uint32

	// Close releases resources.
	Close()
}

// kvRegisteredBackend is the currently registered tokenizer backend.
// Set via KvRegisterTokenizerBackend before any tokenization calls.
// Defaults to nil (no tokenizer available → Tier 1.5 disabled).
var kvRegisteredBackend KvTokenizerBackend

// KvRegisterTokenizerBackend sets the tokenizer backend.
// Must be called during initialization, before any CGO calls.
func KvRegisterTokenizerBackend(backend KvTokenizerBackend) {
	kvRegisteredBackend = backend
	if backend != nil {
		log.Infof("kv-router: registered tokenizer backend: %s", backend.Name())
	}
}

// kvTokenizerPool manages loaded tokenizers keyed by model slug.
var (
	kvTokenizerPool    = make(map[string]KvTokenizer) // model-slug -> tokenizer (nil = failed)
	kvTokenizerMu      sync.RWMutex
	kvTokenizerWarnMap sync.Map // model-slug -> warned (bool)
	kvTokenizerLoaded  sync.Map // model-slug -> attempted (bool) — prevents retry
)

// kvTokenCache implements a per-prefix LRU token ID cache to avoid
// re-tokenizing identical system prompts across multi-turn conversations.
var (
	kvTokenCache    = make(map[tokenCacheKey][]uint32)
	kvTokenCacheMu  sync.RWMutex
	kvLRUOrder      []tokenCacheKey
	kvTokenCacheMax = 4096 // max entries
)

type tokenCacheKey struct {
	modelSlug string
	prefixKey string // first 512 bytes of prompt text
}

// kvModelSlug normalizes a model name for filesystem lookup.
// "meta-llama/Llama-3-8B" becomes "meta-llama__Llama-3-8B"
func kvModelSlug(modelName string) string {
	result := make([]byte, 0, len(modelName))
	for i := 0; i < len(modelName); i++ {
		if modelName[i] == '/' {
			result = append(result, '_', '_')
		} else {
			result = append(result, modelName[i])
		}
	}
	return string(result)
}

// kvTokenizerDir is the base directory for tokenizer files.
const kvTokenizerDir = "/etc/loxilb/tokenizers"

// kvLoadTokenizer loads a tokenizer for the given model.
// Returns nil if no backend, file missing, or parse error.
// Uses warn-once logging and caches failures to avoid retries.
func kvLoadTokenizer(modelName string) KvTokenizer {
	if kvRegisteredBackend == nil {
		return nil
	}

	slug := kvModelSlug(modelName)

	// Fast path: check under read lock
	kvTokenizerMu.RLock()
	if t, ok := kvTokenizerPool[slug]; ok {
		kvTokenizerMu.RUnlock()
		return t // may be nil (cached failure)
	}
	kvTokenizerMu.RUnlock()

	// Check if already attempted (avoids write lock contention)
	if _, attempted := kvTokenizerLoaded.Load(slug); attempted {
		return nil
	}

	// Slow path: acquire write lock, double-check, then load
	kvTokenizerMu.Lock()
	defer kvTokenizerMu.Unlock()

	if t, ok := kvTokenizerPool[slug]; ok {
		return t
	}

	kvTokenizerLoaded.Store(slug, true)

	tokenizerPath := kvTokenizerDir + "/" + slug + "/tokenizer.json"
	tokenizer := kvRegisteredBackend.LoadModel(tokenizerPath)
	if tokenizer == nil {
		kvTokenizerPool[slug] = nil // cache failure
		if _, warned := kvTokenizerWarnMap.LoadOrStore(slug, true); !warned {
			log.Warnf("kv-router: tokenizer not available for model %q at %s", modelName, tokenizerPath)
		}
		return nil
	}

	kvTokenizerPool[slug] = tokenizer
	log.Infof("kv-router: loaded tokenizer for model %q from %s", modelName, tokenizerPath)
	return tokenizer
}

// kvTokenizeWithCache tokenizes text using the model's tokenizer, with LRU caching.
func kvTokenizeWithCache(text, modelName string, maxTokens int) []uint32 {
	slug := kvModelSlug(modelName)

	// Compute cache key: slug + first 512 chars of text
	prefixLen := len(text)
	if prefixLen > 512 {
		prefixLen = 512
	}
	key := tokenCacheKey{modelSlug: slug, prefixKey: text[:prefixLen]}

	// Check cache under read lock
	kvTokenCacheMu.RLock()
	if cached, ok := kvTokenCache[key]; ok {
		kvTokenCacheMu.RUnlock()
		if len(cached) > maxTokens {
			return cached[:maxTokens]
		}
		return cached
	}
	kvTokenCacheMu.RUnlock()

	// Load tokenizer
	tokenizer := kvLoadTokenizer(modelName)
	if tokenizer == nil {
		return nil
	}

	// Tokenize
	ids := tokenizer.Encode(text)
	if len(ids) == 0 {
		return nil
	}

	// Truncate to maxTokens
	if len(ids) > maxTokens {
		ids = ids[:maxTokens]
	}

	// Store in cache under write lock, evict LRU if over capacity
	kvTokenCacheMu.Lock()
	defer kvTokenCacheMu.Unlock()

	// Evict LRU entries if at capacity
	for len(kvTokenCache) >= kvTokenCacheMax && len(kvLRUOrder) > 0 {
		evict := kvLRUOrder[0]
		kvLRUOrder = kvLRUOrder[1:]
		delete(kvTokenCache, evict)
	}

	// Make a copy to store in cache
	cached := make([]uint32, len(ids))
	copy(cached, ids)
	kvTokenCache[key] = cached
	kvLRUOrder = append(kvLRUOrder, key)

	return ids
}

// KvTokenizerClose cleans up all loaded tokenizers for graceful shutdown.
func KvTokenizerClose() {
	kvTokenizerMu.Lock()
	defer kvTokenizerMu.Unlock()
	for slug, t := range kvTokenizerPool {
		if t != nil {
			t.Close()
		}
		delete(kvTokenizerPool, slug)
	}
}

// KvTokenCacheReset clears the token cache (for testing).
func KvTokenCacheReset() {
	kvTokenCacheMu.Lock()
	defer kvTokenCacheMu.Unlock()
	kvTokenCache = make(map[tokenCacheKey][]uint32)
	kvLRUOrder = nil
}

// KvTokenizerPoolReset clears the tokenizer pool (for testing).
func KvTokenizerPoolReset() {
	kvTokenizerMu.Lock()
	defer kvTokenizerMu.Unlock()
	kvTokenizerPool = make(map[string]KvTokenizer)
	kvTokenizerLoaded = sync.Map{}
	kvTokenizerWarnMap = sync.Map{}
}

//export llb_ai_kv_tokenize
func llb_ai_kv_tokenize(text, modelName *C.char, outIDs *C.uint32_t, maxIDs C.int) C.int {
	goText := C.GoString(text)
	goModel := C.GoString(modelName)
	if goText == "" || goModel == "" || maxIDs <= 0 {
		return -1
	}

	tokens := kvTokenizeWithCache(goText, goModel, int(maxIDs))
	if tokens == nil || len(tokens) == 0 {
		return -1
	}

	n := len(tokens)
	if n > int(maxIDs) {
		n = int(maxIDs)
	}
	outSlice := unsafe.Slice(outIDs, maxIDs)
	for i := 0; i < n; i++ {
		outSlice[i] = C.uint32_t(tokens[i])
	}
	return C.int(n)
}

// llb_ai_kv_tokenize_chat tokenizes a /v1/chat/completions request to the same
// token_ids vLLM caches (Gap-B1). The C side passes the raw chat
// request body (which carries the "messages" array); Go applies the model's chat
// template and tokenizes the rendered prompt through the shared
// WithEncodeSpecialTokens Encode path. Returns -1 if the body has no messages,
// no chat template is known for the model, or tokenization fails — the C caller
// should then fall back rather than route a mis-hashed request through KV-exact.
//
//export llb_ai_kv_tokenize_chat
func llb_ai_kv_tokenize_chat(body, modelName *C.char, outIDs *C.uint32_t, maxIDs C.int) C.int {
	goBody := C.GoString(body)
	goModel := C.GoString(modelName)
	if goBody == "" || goModel == "" || maxIDs <= 0 {
		return -1
	}

	tokens := kvTokenizeChatBody(goBody, goModel, int(maxIDs))
	if len(tokens) == 0 {
		return -1
	}

	n := len(tokens)
	if n > int(maxIDs) {
		n = int(maxIDs)
	}
	outSlice := unsafe.Slice(outIDs, maxIDs)
	for i := 0; i < n; i++ {
		outSlice[i] = C.uint32_t(tokens[i])
	}
	return C.int(n)
}
