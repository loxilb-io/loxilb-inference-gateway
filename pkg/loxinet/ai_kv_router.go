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
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"time"
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
	kvTokenizerPool    = make(map[string]KvTokenizer) // model-slug -> successfully loaded tokenizer
	kvTokenizerMu      sync.RWMutex
	kvTokenizerWarnMap sync.Map // model-slug -> warned (bool)

	// kvTokenizerEpoch is the pool generation. Pool reset/close advances it under
	// the pool write lock; a load that started under an older generation discards
	// its result at commit time instead of populating state belonging to a
	// previous pool lifetime.
	kvTokenizerEpoch atomic.Uint64

	// kvTokenizerNeg holds per-slug retry-not-before deadlines for failed loads,
	// under its own lock so a broken-model request storm never touches the pool
	// locks or the filesystem more than once per kvTokenizerNegTTL.
	kvTokenizerNegMu sync.Mutex
	kvTokenizerNeg   = make(map[string]time.Time)

	// kvTokenizerFlight collapses concurrent loads of one (slug, generation)
	// into a single LoadModel call performed with NO pool lock held, so a slow
	// or failing load never stalls lookups of already-loaded tokenizers.
	kvTokenizerFlightMu sync.Mutex
	kvTokenizerFlight   = make(map[kvTokenizerFlightKey]*kvTokenizerLoad)
)

// kvTokenizerNegTTL bounds how often a missing/broken tokenizer is re-probed on
// the data-plane path. Rule admission bypasses it via kvLoadTokenizerFresh so an
// operator's stage-and-retry needs no wait. Variable so tests can compress it.
var kvTokenizerNegTTL = 5 * time.Second

// kvTokenizerWaitTimeout bounds how long a caller waits on another goroutine's
// in-flight load before abandoning it; the shared load itself keeps running and
// commits (or negative-caches) on its own lifecycle.
var kvTokenizerWaitTimeout = 2 * time.Second

type kvTokenizerFlightKey struct {
	slug  string
	epoch uint64
}

type kvTokenizerLoad struct {
	done chan struct{} // closed when the load committed or was discarded
	tok  KvTokenizer   // valid only after done; nil on failure or stale discard
}

// kvTokenCache implements a per-prefix LRU token ID cache to avoid
// re-tokenizing identical system prompts across multi-turn conversations.
var (
	kvTokenCache    = make(map[tokenCacheKey][]uint32)
	kvTokenCacheMu  sync.RWMutex
	kvLRUOrder      []tokenCacheKey
	kvTokenCacheMax = 4096 // max entries
)

// tokenCacheKey identifies a cached tokenization by the FULL text, not a prefix.
// The previous key (modelSlug + first 512 bytes of text) collided for the
// long-context coding-assistant workload: two prompts sharing a >=512-byte
// preamble (same system prompt + repo header, divergent tail — the defining
// shared-prefix shape) returned EACH OTHER's token ids, so the block-hash chain
// hashed the wrong request and Tier-1.5 mis-routed. The chat path feeds the full
// rendered template through this cache (kvTokenizeChatBody), so texts far beyond
// 512 bytes are the NORM there, not the exception. len+sha256 keeps the key
// fixed-size (long prompts must not become map keys) while making a collision
// require a sha256 collision at equal length.
type tokenCacheKey struct {
	modelSlug string
	textLen   int
	textSum   [sha256.Size]byte
}

// kvTokenCacheKeyFor builds the full-text-identity cache key for (text, slug).
func kvTokenCacheKeyFor(slug, text string) tokenCacheKey {
	return tokenCacheKey{modelSlug: slug, textLen: len(text), textSum: sha256.Sum256([]byte(text))}
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

// kvLoadTokenizer loads a tokenizer for the given model (data-plane path).
// Returns nil if no backend, file missing, parse error, or a failed load is
// still inside its negative-cache TTL. Failed loads remain retryable so an
// operator can stage a tokenizer without restarting the Gateway.
func kvLoadTokenizer(modelName string) KvTokenizer {
	return kvLoadTokenizerEx(modelName, false)
}

// kvLoadTokenizerFresh is the admission-path variant: it drops any negative-
// cache entry before probing, so an operator who has just staged or repaired a
// tokenizer gets an immediate authoritative answer on the rule POST retry.
// Rule admission is operator-triggered and low-rate; only the data-plane path
// needs the TTL bound.
func kvLoadTokenizerFresh(modelName string) KvTokenizer {
	return kvLoadTokenizerEx(modelName, true)
}

func kvLoadTokenizerEx(modelName string, freshProbe bool) KvTokenizer {
	backend := kvRegisteredBackend
	if backend == nil {
		return nil
	}
	slug := kvModelSlug(modelName)

	// Two attempts: a load whose result was discarded because the pool
	// generation changed mid-flight re-dispatches once under the new
	// generation instead of reporting a false miss.
	for attempt := 0; attempt < 2; attempt++ {
		kvTokenizerMu.RLock()
		t, ok := kvTokenizerPool[slug]
		kvTokenizerMu.RUnlock()
		if ok {
			return t
		}

		if freshProbe {
			kvTokenizerNegMu.Lock()
			delete(kvTokenizerNeg, slug)
			kvTokenizerNegMu.Unlock()
		} else {
			kvTokenizerNegMu.Lock()
			deadline, failed := kvTokenizerNeg[slug]
			kvTokenizerNegMu.Unlock()
			if failed && time.Now().Before(deadline) {
				return nil
			}
		}

		key := kvTokenizerFlightKey{slug: slug, epoch: kvTokenizerEpoch.Load()}
		kvTokenizerFlightMu.Lock()
		call, joined := kvTokenizerFlight[key]
		if !joined {
			call = &kvTokenizerLoad{done: make(chan struct{})}
			kvTokenizerFlight[key] = call
		}
		kvTokenizerFlightMu.Unlock()

		if !joined {
			tok, stale := kvTokenizerLoadAndCommit(backend, modelName, slug, key.epoch)
			if !stale {
				call.tok = tok
			}
			close(call.done)
			kvTokenizerFlightMu.Lock()
			delete(kvTokenizerFlight, key)
			kvTokenizerFlightMu.Unlock()
			if stale {
				continue
			}
			return tok
		}

		select {
		case <-call.done:
		case <-time.After(kvTokenizerWaitTimeout):
			return nil // abandon; the shared load finishes on its own lifecycle
		}
		if call.tok != nil {
			return call.tok
		}
		// nil is either a genuine failure (now negative-cached; the next
		// iteration returns fast) or a stale-generation discard (the next
		// iteration re-dispatches under the new generation).
	}
	return nil
}

// kvTokenizerLoadAndCommit performs the filesystem load with NO pool lock held,
// then commits the outcome under the pool write lock only if the pool is still
// the generation the load started under. stale=true means a concurrent pool
// reset invalidated the result and nothing was populated — neither the pool nor
// the negative cache may carry state across generations.
func kvTokenizerLoadAndCommit(backend KvTokenizerBackend, modelName, slug string, epoch uint64) (KvTokenizer, bool) {
	tokenizerPath := kvTokenizerDir + "/" + slug + "/tokenizer.json"
	tokenizer := backend.LoadModel(tokenizerPath)

	kvTokenizerMu.Lock()
	if kvTokenizerEpoch.Load() != epoch {
		kvTokenizerMu.Unlock()
		if tokenizer != nil {
			tokenizer.Close()
		}
		return nil, true
	}
	if tokenizer != nil {
		kvTokenizerPool[slug] = tokenizer
	}
	kvTokenizerMu.Unlock()

	if tokenizer == nil {
		// Failure stays retryable (operators stage tokenizers without a
		// restart) but TTL-bounded, so a broken-model request storm cannot
		// become a filesystem probe storm. The warn remains once-per-model so
		// repeated data-plane fallback cannot flood logs.
		kvTokenizerNegMu.Lock()
		kvTokenizerNeg[slug] = time.Now().Add(kvTokenizerNegTTL)
		kvTokenizerNegMu.Unlock()
		if _, warned := kvTokenizerWarnMap.LoadOrStore(slug, true); !warned {
			log.Warnf("kv-router: tokenizer not available for model %q at %s", modelName, tokenizerPath)
		}
		return nil, false
	}

	log.Infof("kv-router: loaded tokenizer for model %q from %s", modelName, tokenizerPath)
	return tokenizer, false
}

// kvTokenizeWithCache tokenizes text using the model's tokenizer, with LRU caching.
func kvTokenizeWithCache(text, modelName string, maxTokens int) []uint32 {
	slug := kvModelSlug(modelName)

	// Cache key = full-text identity (slug + len + sha256) — see tokenCacheKey.
	key := kvTokenCacheKeyFor(slug, text)

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
// The generation bump makes any still-in-flight load discard its result
// instead of resurrecting an entry in the closed pool.
func KvTokenizerClose() {
	kvTokenizerMu.Lock()
	defer kvTokenizerMu.Unlock()
	kvTokenizerEpoch.Add(1)
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

// KvTokenizerPoolReset clears the tokenizer pool, negative cache, and warn
// state, advancing the pool generation so in-flight loads from the previous
// lifetime discard their results (for testing and registry reload).
func KvTokenizerPoolReset() {
	kvTokenizerMu.Lock()
	kvTokenizerEpoch.Add(1)
	kvTokenizerPool = make(map[string]KvTokenizer)
	kvTokenizerWarnMap = sync.Map{}
	kvTokenizerMu.Unlock()

	kvTokenizerNegMu.Lock()
	kvTokenizerNeg = make(map[string]time.Time)
	kvTokenizerNegMu.Unlock()
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
