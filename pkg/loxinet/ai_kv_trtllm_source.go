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

/*
 * ai_kv_trtllm_source.go — HTTP-poll KvEventSource for TensorRT-LLM.
 *
 * TensorRT-LLM publishes KV cache events on `POST /kv_cache_events` at the
 * endpoint's own serving port — a DESTRUCTIVE drain (each event is returned
 * exactly once, to whichever caller drains it first), not a pub/sub stream.
 * Consequences that shape everything below:
 *
 *   - The gateway must be the SOLE consumer of the drain per endpoint. Any
 *     other poller (NVIDIA Dynamo, TRT-LLM's own kv-aware router, debug
 *     curls) splits the stream and both sides silently hold a wrong
 *     inventory. Never scrape /kv_cache_events from monitoring.
 *   - There is no replay channel. On a lost stretch of events the inventory
 *     is rebuilt from the live stream (blocks re-announce as they are
 *     re-stored); a cold window is a perf cost, phantom hashes would be a
 *     correctness bug — so every ambiguity below resolves toward clearing.
 *   - One outstanding request at a time per endpoint: concurrent polls to
 *     one endpoint would each receive a random subset.
 *
 * Wire shape (live-captured from tensorrt_llm 1.3.0rc24; the envelope is
 * self-describing and unknown fields are ignored):
 *
 *   [ {"event_id": N, "window_size": W, "data": {...}}, ... ]
 *
 *   data.type == "stored":  {"parent_hash": H|null, "blocks": [
 *       {"block_hash": H, "tokens": [{"token_id": T, "token_extra_id": E},...],
 *        "cache_salt": S|null, "mm_keys": [...], ...}, ...]}
 *   data.type == "removed": {"block_hashes": [H, ...]}
 *   data.type == "created": {"num_blocks_per_cache_level": [...]} — fresh
 *       engine cache; live-measured restart signature is: first drain after
 *       restart returns [], then the stream restarts at event_id 0 with a
 *       created event.
 *
 * Hashing (the token re-hash design): the engine's block_hash is an
 * unversioned internal value with no cross-release stability promise, so the
 * inventory NEVER stores it as a routing key. Instead each stored block's
 * full token list (always present in the event) is re-hashed with the same
 * self-owned chained-SHA256 contract the C request path computes for this
 * engine (KV_HASH_SHA256_SGLANG: digest_i = SHA256(raw 32-byte parent
 * digest if any || tok0_LE4 || ...), published key = first 8 digest bytes
 * big-endian). Request-side and event-side keys then agree by construction
 * and the engine hash contract exits the critical path entirely. The engine
 * hash is still tracked — but only as a local translation handle so that
 * "removed"/parent references (which speak engine hashes) can be mapped to
 * our keys and digests.
 *
 * Blocks that the request-side hash can never reproduce are not indexed:
 * partial blocks (fewer than kvBlockSize tokens — always the tail),
 * token_extra_id != 0, non-null cache_salt, non-empty mm_keys. The chain
 * walk stops at the first such block; a later event chaining onto an
 * unknown parent is dropped whole. Each is an at-most-one-block granularity
 * cost per prefix and self-heals as blocks are re-stored.
 *
 * Transport adaptation: the subscriber loop (runKvSubscriberLoop) consumes
 * ZMQ-style 3-frame messages, and its seq-gap / seq-regression / KEEP-CLEAR
 * machinery is exactly the resync policy this transport needs. So the poller
 * synthesizes one message per engine event: frame 0 = topic "trtllm",
 * frame 1 = event_id as 8-byte big-endian (the seq), frame 2 = a msgpack
 * KVEventBatch carrying the single translated event. An engine restart then
 * resolves without any new loop code: event_id regression => CLEAR, and the
 * created event maps to AllBlocksCleared. Events that translate to nothing
 * (skipped window, dropped blocks, "updated") still emit a no-op message so
 * the seq advances without a phantom gap.
 *
 * Poll discipline: adaptive backoff — reset to the min interval after a
 * non-empty drain, multiply by 1.5 toward the max on empty ones (defaults
 * 5/20 ms, env-tunable via LOXILB_KV_TRTLLM_POLL_MIN_MS/_MAX_MS; the idle
 * drain measures ~5-6 ms RTT and completion-to-visible staleness 6-8 ms on
 * the live fleet, so this envelope keeps the inventory effectively fresh).
 * Older engine builds (<= 1.3.0rc9 NGC containers) BLOCK ~2 s on an idle
 * poll instead of returning [] — the generous HTTP timeout tolerates that
 * shape; never "optimize" it down to the fast-path RTT.
 */

package loxinet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	// kvTrtllmPollMinDefault / kvTrtllmPollMaxDefault bound the adaptive
	// poll backoff (reset to min on a non-empty drain, *1.5 toward max on
	// empty ones).
	kvTrtllmPollMinDefault = 5 * time.Millisecond
	kvTrtllmPollMaxDefault = 20 * time.Millisecond

	// kvTrtllmPollBackoffNum/Den express the 1.5x backoff factor in integer
	// math (time.Duration multiply).
	kvTrtllmPollBackoffNum = 3
	kvTrtllmPollBackoffDen = 2

	// kvTrtllmHTTPTimeout caps one drain request. Generous on purpose: old
	// engine builds block ~2s on an idle poll instead of returning [], and
	// that shape must read as "no events yet", not as an error.
	kvTrtllmHTTPTimeout = 30 * time.Second

	// kvTrtllmRespCap caps one drain response body. A full drain after a
	// large burst measures ~64 B/token; 64 MiB absorbs any realistic burst
	// while bounding a misbehaving endpoint.
	kvTrtllmRespCap = 64 << 20

	// kvTrtllmChainMapCap bounds the engine-hash translation map. It tracks
	// resident engine blocks (entries are deleted on "removed" and the map
	// is reset on "created"), so in a healthy run it stays near the engine's
	// block count; the cap is a defensive backstop against a pathological
	// publisher. On overflow the map is reset — chains re-anchor as blocks
	// re-store, identical to the no-replay cold-window posture.
	kvTrtllmChainMapCap = 2_000_000

	// kvTrtllmHashAlgoV1 is the engine's default (and only rc24-observed)
	// event hash algorithm tag. The tag is absent from the envelope unless
	// explicitly configured engine-side, so absence means v1.
	kvTrtllmHashAlgoV1 = "v1_block_key"
)

// kvTrtllmResolvePollBounds reads the poll-interval env overrides once at
// poller construction (init-time-only discipline; range 1..10000 ms, min<=max
// enforced by falling back both to defaults on an inverted pair).
func kvTrtllmResolvePollBounds() (time.Duration, time.Duration) {
	minP, maxP := kvTrtllmPollMinDefault, kvTrtllmPollMaxDefault
	if v := os.Getenv("LOXILB_KV_TRTLLM_POLL_MIN_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10000 {
			minP = time.Duration(n) * time.Millisecond
		} else {
			log.Warnf("[KV_TRT] invalid LOXILB_KV_TRTLLM_POLL_MIN_MS=%q (want 1..10000), using %v", v, minP)
		}
	}
	if v := os.Getenv("LOXILB_KV_TRTLLM_POLL_MAX_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10000 {
			maxP = time.Duration(n) * time.Millisecond
		} else {
			log.Warnf("[KV_TRT] invalid LOXILB_KV_TRTLLM_POLL_MAX_MS=%q (want 1..10000), using %v", v, maxP)
		}
	}
	if minP > maxP {
		log.Warnf("[KV_TRT] poll bounds inverted (%v > %v), using defaults", minP, maxP)
		return kvTrtllmPollMinDefault, kvTrtllmPollMaxDefault
	}
	return minP, maxP
}

// trtllmChainEntry is the per-engine-block translation record: the key our
// inventory indexes under, plus the full 32-byte digest child blocks chain
// from. Keyed by the ENGINE's block_hash in trtllmEventPoller.chain, because
// parent references and "removed" events speak engine hashes.
type trtllmChainEntry struct {
	key    uint64
	digest [32]byte
}

// trtllmCounters are poller-local drop/anomaly counters, exposed for tests
// and structured logging. Every skip path is counted — the token re-hash
// design's honesty contract is that unindexed blocks are visible, not silent.
type trtllmCounters struct {
	pollErrors     atomic.Uint64 // failed drain requests (also surfaced as recv errors)
	created        atomic.Uint64 // engine cache (re)creations observed
	windowSkipped  atomic.Uint64 // events skipped on a non-first window_size
	algoAnomaly    atomic.Uint64 // events tagged with a non-v1 hash_algo
	unchained      atomic.Uint64 // stored events dropped on an unknown parent
	blocksSkipped  atomic.Uint64 // blocks not indexed (partial/salt/extra-id/mm)
	removedUnknown atomic.Uint64 // removed hashes with no translation entry
}

// trtllmEventPoller adapts the TensorRT-LLM HTTP event drain to the
// KvEventSource seam. One poller per (service, EP); the subscriber loop's
// dedicated goroutine absorbs the blocking poll cadence, and the loop's
// existing seq machinery consumes the synthesized frames unchanged.
type trtllmEventPoller struct {
	ctx       context.Context
	blockSize int
	pollMin   time.Duration
	pollMax   time.Duration
	client    *http.Client

	mu     sync.Mutex
	url    string     // drain URL, set by Connect
	closed bool       // Close() called; Connect() re-arms
	queue  [][][]byte // decoded-but-undelivered synthesized messages

	// backoff is the current idle-poll sleep (adaptive between pollMin and
	// pollMax). Only touched from RecvMultipart (single consumer).
	backoff time.Duration

	// window is the first-seen window_size; events from other windows are
	// counted and skipped so a variable-window model cannot cross-pollute
	// one inventory keyspace. -1 until the first event.
	window int64

	// chain is the engine-hash translation map (see trtllmChainEntry). It
	// survives Close/Connect rebuilds on purpose: a transient network blip
	// does not invalidate resident engine blocks, and a real engine restart
	// announces itself with a created event, which resets the map.
	chain map[uint64]trtllmChainEntry

	stats trtllmCounters
}

// newTrtllmEventPoller builds the poller. addr is "host:port" (the EP's own
// serving address — events ride the serving port, there is no separate event
// port) or a full http(s) URL. blockSize is the rule's kvBlockSize: blocks
// with fewer tokens are the un-reproducible partial tail and are not indexed.
func newTrtllmEventPoller(ctx context.Context, addr string, blockSize int) *trtllmEventPoller {
	minP, maxP := kvTrtllmResolvePollBounds()
	if blockSize <= 0 {
		blockSize = 16
	}
	return &trtllmEventPoller{
		ctx:       ctx,
		blockSize: blockSize,
		pollMin:   minP,
		pollMax:   maxP,
		backoff:   minP,
		window:    -1,
		chain:     make(map[uint64]trtllmChainEntry),
		client:    &http.Client{Timeout: kvTrtllmHTTPTimeout},
	}
}

// kvTrtllmDrainURL normalizes a subscriber address to the drain URL. The
// spawn path passes ZMQ-style "tcp://ip:port" for the shared code path;
// bare "ip:port" and explicit http(s) URLs are accepted for tests.
func kvTrtllmDrainURL(addr string) string {
	a := strings.TrimPrefix(addr, "tcp://")
	if !strings.HasPrefix(a, "http://") && !strings.HasPrefix(a, "https://") {
		a = "http://" + a
	}
	return strings.TrimSuffix(a, "/") + "/kv_cache_events"
}

// Connect (re)arms the poller. Deliberately does NOT probe the endpoint: the
// engine may boot after the rule lands, and the first failing poll already
// routes through the loop's rebuild/backoff path. The chain map and window
// pin survive reconnects (see the chain field comment).
func (p *trtllmEventPoller) Connect(endpoint string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.url = kvTrtllmDrainURL(endpoint)
	p.closed = false
	p.backoff = p.pollMin
	return nil
}

// Close marks the poller closed. The subscriber loop Close-then-Connects the
// same instance on rebuild, so this must stay re-armable and idempotent.
func (p *trtllmEventPoller) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// RecvMultipart returns the next synthesized 3-frame message, polling the
// drain with adaptive backoff while the queue is empty. It blocks (that is
// the KvEventSource contract — the loop gives it a dedicated goroutine) and
// returns an error on a failed drain request so the loop's rebuild path and
// recv-error counter engage.
func (p *trtllmEventPoller) RecvMultipart() ([][]byte, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, io.EOF
		}
		if len(p.queue) > 0 {
			msg := p.queue[0]
			p.queue = p.queue[1:]
			p.mu.Unlock()
			return msg, nil
		}
		url := p.url
		p.mu.Unlock()

		select {
		case <-p.ctx.Done():
			return nil, p.ctx.Err()
		default:
		}

		envs, err := p.pollOnce(url)
		if err != nil {
			p.stats.pollErrors.Add(1)
			return nil, err
		}

		if len(envs) == 0 {
			// Idle: sleep the current backoff, then widen it toward pollMax.
			select {
			case <-p.ctx.Done():
				return nil, p.ctx.Err()
			case <-time.After(p.backoff):
			}
			p.backoff = p.backoff * kvTrtllmPollBackoffNum / kvTrtllmPollBackoffDen
			if p.backoff > p.pollMax {
				p.backoff = p.pollMax
			}
			continue
		}

		p.backoff = p.pollMin
		p.mu.Lock()
		for i := range envs {
			p.queue = append(p.queue, p.translate(&envs[i]))
		}
		p.mu.Unlock()
	}
}

// ---------- drain request + JSON decode ----------

// trtllmEventEnvelope mirrors the engine's event envelope. Numeric hash
// fields decode via json.Number: v1 block hashes are uint64 values that a
// float64 round-trip would corrupt above 2^53.
type trtllmEventEnvelope struct {
	EventID    uint64          `json:"event_id"`
	WindowSize int64           `json:"window_size"`
	HashAlgo   string          `json:"hash_algo"`
	Data       trtllmEventData `json:"data"`
}

type trtllmEventData struct {
	Type        string              `json:"type"`
	ParentHash  json.Number         `json:"parent_hash"`
	Blocks      []trtllmStoredBlock `json:"blocks"`
	BlockHashes []json.Number       `json:"block_hashes"`
}

type trtllmStoredBlock struct {
	BlockHash json.Number       `json:"block_hash"`
	Tokens    []trtllmToken     `json:"tokens"`
	CacheSalt json.RawMessage   `json:"cache_salt"`
	MmKeys    []json.RawMessage `json:"mm_keys"`
}

type trtllmToken struct {
	TokenID      int64 `json:"token_id"`
	TokenExtraID int64 `json:"token_extra_id"`
}

// kvTrtllmParseU64 parses a JSON number as the engine's uint64 hash. The
// serializer emits unsigned decimals, but a signed representation of the
// same bit pattern is accepted too (the int64->uint64 cast is
// bit-preserving, same contract as extractBlockHashes on the ZMQ wire).
func kvTrtllmParseU64(n json.Number) (uint64, bool) {
	s := n.String()
	if s == "" || s == "null" {
		return 0, false
	}
	if u, err := strconv.ParseUint(s, 10, 64); err == nil {
		return u, true
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return uint64(i), true
	}
	return 0, false
}

// pollOnce drains the endpoint once and decodes the returned envelope array.
func (p *trtllmEventPoller) pollOnce(url string) ([]trtllmEventEnvelope, error) {
	req, err := http.NewRequestWithContext(p.ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("trtllm poll: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trtllm poll: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, kvTrtllmRespCap))
	if err != nil {
		return nil, fmt.Errorf("trtllm poll: read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trtllm poll: status %d", resp.StatusCode)
	}
	var envs []trtllmEventEnvelope
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&envs); err != nil {
		return nil, fmt.Errorf("trtllm poll: decode: %w", err)
	}
	return envs, nil
}

// ---------- event translation ----------

// kvTrtllmTopic is frame 0 of every synthesized message.
var kvTrtllmTopic = []byte("trtllm")

// translate turns one engine event into one synthesized 3-frame message.
// Every event produces exactly one message — events with nothing to publish
// emit a no-op payload — so the loop's seq tracker sees the engine's
// event_id sequence verbatim, gaps included.
func (p *trtllmEventPoller) translate(env *trtllmEventEnvelope) [][]byte {
	// Window pin: index only the first-seen attention window. A model with
	// variable sliding windows stores per-window block sets whose token
	// prefixes collide across windows; keying them into one inventory would
	// manufacture false hits.
	if p.window < 0 {
		p.window = env.WindowSize
	} else if env.WindowSize != p.window && env.Data.Type != "created" {
		p.stats.windowSkipped.Add(1)
		return p.noopMessage(env.EventID)
	}

	// A non-v1 hash_algo tag means the endpoint's configured event hashing
	// changed underneath the rule admission answer. The re-hash keys stay
	// self-consistent (engine hashes are only local translation handles),
	// so this is counted as an anomaly, not dropped.
	if env.HashAlgo != "" && env.HashAlgo != kvTrtllmHashAlgoV1 {
		if p.stats.algoAnomaly.Add(1) == 1 {
			log.Warnf("[KV_TRT] event hash_algo=%q (expected %q) — endpoint config changed under the rule", env.HashAlgo, kvTrtllmHashAlgoV1)
		}
	}

	switch env.Data.Type {
	case "created":
		// Fresh engine cache: every resident block and every translation
		// entry is gone. The window pin resets too — a restart may carry a
		// new engine config.
		p.stats.created.Add(1)
		p.chain = make(map[uint64]trtllmChainEntry)
		p.window = env.WindowSize
		log.Infof("[KV_TRT] created event (event_id=%d) — engine cache is fresh, clearing inventory", env.EventID)
		return p.eventMessage(env.EventID, "AllBlocksCleared", nil)

	case "stored":
		keys := p.translateStored(&env.Data)
		if len(keys) == 0 {
			return p.noopMessage(env.EventID)
		}
		return p.eventMessage(env.EventID, "BlockStored", keys)

	case "removed":
		keys := p.translateRemoved(&env.Data)
		if len(keys) == 0 {
			return p.noopMessage(env.EventID)
		}
		return p.eventMessage(env.EventID, "BlockRemoved", keys)

	default:
		// "updated" (cache-level/priority moves — the block stays reusable)
		// and anything future ride through as seq-advancing no-ops.
		return p.noopMessage(env.EventID)
	}
}

// translateStored re-hashes a stored chain into inventory keys and records
// the engine-hash translation entries. Returns the keys to index (full,
// clean blocks only).
func (p *trtllmEventPoller) translateStored(d *trtllmEventData) []uint64 {
	// Resolve the chain anchor: parent_hash is the ENGINE hash of the block
	// this chain extends (null at a tree root). An unknown parent means the
	// parent was stored before this subscriber connected (no replay
	// channel) or below a block we declined to index — either way none of
	// these blocks can be keyed consistently with the request-side chain,
	// so the whole event is dropped and the inventory self-heals when the
	// blocks are eventually re-stored from an indexable anchor.
	var parentDigest *[32]byte
	if ph, ok := kvTrtllmParseU64(d.ParentHash); ok {
		entry, found := p.chain[ph]
		if !found {
			p.stats.unchained.Add(1)
			return nil
		}
		parentDigest = &entry.digest
	}

	keys := make([]uint64, 0, len(d.Blocks))
	for i := range d.Blocks {
		blk := &d.Blocks[i]
		// Blocks the C request-side hash can never reproduce end the walk:
		// partial tail (short token list), extra-id tokens, salted or
		// multimodal blocks. Blocks after them would chain through them.
		// The length check is EXACT equality: a token count above the
		// rule's kvBlockSize means the rule's block size disagrees with
		// the engine's tokens_per_block, and hashing such a block would
		// produce keys the request-side pager never computes — skipping
		// keeps the mismatch loudly visible in the skip counter instead
		// of silently indexing unmatchable keys.
		if len(blk.Tokens) != p.blockSize || !kvTrtllmBlockClean(blk) {
			p.stats.blocksSkipped.Add(uint64(len(d.Blocks) - i))
			break
		}
		toks := make([]uint32, len(blk.Tokens))
		for j, t := range blk.Tokens {
			toks[j] = uint32(t.TokenID)
		}
		digest, key := kvSglangRehashBlock(parentDigest, toks)

		if eh, ok := kvTrtllmParseU64(blk.BlockHash); ok {
			if len(p.chain) >= kvTrtllmChainMapCap {
				// Defensive backstop only — see kvTrtllmChainMapCap.
				log.Warnf("[KV_TRT] chain map cap %d hit — resetting translation state", kvTrtllmChainMapCap)
				p.chain = make(map[uint64]trtllmChainEntry)
			}
			p.chain[eh] = trtllmChainEntry{key: key, digest: digest}
		}
		keys = append(keys, key)
		pd := digest
		parentDigest = &pd
	}
	return keys
}

// translateRemoved maps removed engine hashes to inventory keys via the
// translation map and drops the used entries (the engine evicts leaves
// before parents, so a dropped entry can no longer be referenced as a
// parent). Hashes with no entry were never indexed — counted, skipped.
func (p *trtllmEventPoller) translateRemoved(d *trtllmEventData) []uint64 {
	keys := make([]uint64, 0, len(d.BlockHashes))
	for _, n := range d.BlockHashes {
		eh, ok := kvTrtllmParseU64(n)
		if !ok {
			continue
		}
		if entry, found := p.chain[eh]; found {
			keys = append(keys, entry.key)
			delete(p.chain, eh)
		} else {
			p.stats.removedUnknown.Add(1)
		}
	}
	return keys
}

// kvTrtllmBlockClean reports whether a stored block is reproducible by the
// request-side hash: no extra-id tokens, no cache salt, no multimodal keys.
func kvTrtllmBlockClean(blk *trtllmStoredBlock) bool {
	for _, t := range blk.Tokens {
		if t.TokenExtraID != 0 {
			return false
		}
	}
	if len(blk.MmKeys) > 0 {
		return false
	}
	salt := string(bytes.TrimSpace(blk.CacheSalt))
	return salt == "" || salt == "null"
}

// ---------- frame synthesis ----------

// eventMessage builds one ZMQ-shaped 3-frame message carrying a single
// translated event in the msgpack KVEventBatch layout the shared decoder
// already speaks: [ts, [[tag, [hash...]]], dp_rank].
func (p *trtllmEventPoller) eventMessage(eventID uint64, tag string, keys []uint64) [][]byte {
	var ev []interface{}
	if tag == "AllBlocksCleared" {
		ev = []interface{}{tag}
	} else {
		hs := make([]interface{}, len(keys))
		for i, k := range keys {
			hs[i] = k
		}
		ev = []interface{}{tag, hs}
	}
	payload, err := msgpack.Marshal([]interface{}{float64(0), []interface{}{ev}, nil})
	if err != nil {
		// Marshal of plain slices cannot realistically fail; degrade to a
		// no-op message so the seq still advances.
		log.Warnf("[KV_TRT] msgpack marshal failed: %v", err)
		return p.noopMessage(eventID)
	}
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, eventID)
	return [][]byte{kvTrtllmTopic, seq, payload}
}

// noopMessage advances the loop's seq tracker without publishing anything:
// the payload's single event decodes to kvEventUnknown, which the loop
// ignores. Skipping the message instead would read as a seq gap.
func (p *trtllmEventPoller) noopMessage(eventID uint64) [][]byte {
	payload, _ := msgpack.Marshal([]interface{}{float64(0), []interface{}{[]interface{}{"KvNoop"}}, nil})
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, eventID)
	return [][]byte{kvTrtllmTopic, seq, payload}
}

// ---------- self-owned block hashing ----------

// kvSglangRehashBlock computes one block of the self-owned chained-SHA256
// contract shared with the C request path (KV_HASH_SHA256_SGLANG):
//
//	digest = SHA256([raw 32-byte parent digest if chained] || tok0_LE4 || tok1_LE4 ...)
//	key    = first 8 digest bytes, big-endian
//
// A root block hashes tokens only (no parent bytes, no seed constant). The
// full digest — not the truncated key — feeds the child block's hash, so
// callers must chain digests.
func kvSglangRehashBlock(parent *[32]byte, tokens []uint32) ([32]byte, uint64) {
	h := sha256.New()
	if parent != nil {
		h.Write(parent[:])
	}
	var le [4]byte
	for _, t := range tokens {
		binary.LittleEndian.PutUint32(le[:], t)
		h.Write(le[:])
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, binary.BigEndian.Uint64(digest[:8])
}
