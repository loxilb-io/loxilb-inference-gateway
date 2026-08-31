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
 * ai_kv_subscriber.go — ZMQ subscriber for vLLM KV cache events.
 *
 * Maintains per-EP KV block inventories and provides llb_ai_kv_best_worker
 * CGO export for the C hot path (sockproxy_kv_exact.c).
 *
 * ZMQ wire format (3-part multipart):
 *   Frame 0: topic bytes
 *   Frame 1: sequence number (8-byte big-endian uint64)
 *   Frame 2: payload (msgpack-encoded KVEventBatch)
 *
 * Event types:
 *   BlockStored:      ["BlockStored", [hash...], parent_hash, [token_id...], block_size, lora_id, medium, lora_name, extra_keys]
 *   BlockRemoved:     ["BlockRemoved", [hash...], medium]
 *   AllBlocksCleared: ["AllBlocksCleared"]
 *
 * By default (VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1), block hashes are uint64.
 */

package loxinet

/*
#include <stdint.h>
*/
import "C"

import (
	"container/list"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/go-zeromq/zmq4"
	prom "github.com/loxilb-io/loxilb/api/prometheus"
	"github.com/loxilb-io/loxilb/api/restapi/handler"
	log "github.com/sirupsen/logrus"
)

// ---------- KV Block Inventory ----------

// kvMaxBlocksDefault is the per-EP block cap. Generous backstop: >1.5×
// the max realistic vLLM num_gpu_blocks (40k–600k), ~48 MB/EP worst case with
// the container/list ordering overhead. It is a defensive limit that never
// fires in a healthy single-publisher run — a nonzero
// loxilb_kv_inv_cap_evictions_total is the authoritative "publisher
// misbehaving" signal.
const kvMaxBlocksDefault = 1_000_000

// kvResolveMaxBlocks reads the LOXILB_KV_MAX_BLOCKS env override ONCE (init-time,
// never per-call — mirrors the bounded-int env idiom in lxb_trace_config.go and
// the dpu_doca_bf2.go init-time-only discipline). An out-of-range or garbage
// value falls back to the compiled default with a warning. Range 1000..100M.
func kvResolveMaxBlocks() int {
	if v := os.Getenv("LOXILB_KV_MAX_BLOCKS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1000 && n <= 100_000_000 {
			log.Infof("[KV_INV] kvMaxBlocks=%d (from LOXILB_KV_MAX_BLOCKS)", n)
			return n
		}
		log.Warnf("[KV_INV] invalid LOXILB_KV_MAX_BLOCKS=%q (want 1000..100000000), using default %d",
			v, kvMaxBlocksDefault)
	}
	return kvMaxBlocksDefault
}

// kvSeqResumeWindow is the forward seq tolerance for the post-reconnect KEEP
// decision. vLLM's ZMQ publisher increments a monotonic per-engine seq on
// every EventBatch; on a transient network blip the engine keeps running so the
// first seq after reconnect resumes at-or-slightly-ahead of our preserved
// lastSeq (a few batches we missed during the gap). A real publisher RESTART
// resets the seq to 0/low. We therefore KEEP the warm inventory only when the
// first post-reconnect seq is within [lastSeq, lastSeq+kvSeqResumeWindow]; any
// reset-to-low or large-forward-jump is treated as a restart/ambiguous signal
// and CLEARS (conservative toward correctness — see kvResyncDecision).
const kvSeqResumeWindow = 64

// kvResyncDecision decides, on the FIRST message after a reconnect, whether the
// warm inventory should be KEPT (transient blip, same running engine) or CLEARED
// (publisher restart, or any ambiguous signal). It returns true to KEEP, false
// to CLEAR.
//
// discriminator: vLLM's seq is monotonic per running engine and resets on
// restart. We KEEP iff the first post-reconnect seq resumes near the preserved
// lastSeq: seq in [lastSeq, lastSeq+kvSeqResumeWindow]. Everything else CLEARS:
//   - seq < lastSeq          → seq went backwards ⇒ publisher restarted (fresh
//     prefix cache, our cached hashes are stale) → CLEAR.
//   - seq > lastSeq+window   → large forward jump ⇒ we missed too much / ambiguous
//     restart → CLEAR (conservative — a stale inventory after a real restart is a
//
// correctness bug; a needless cold window is only a perf cost)
//   - lastSeq < 0            → we never observed a seq before the blip; nothing
//     warm worth preserving ⇒ CLEAR (also conservative).
//
// note: there is NO engine_id on the KV-event wire (the EventBatch carries
// only data_parallel_rank), so seq-reset is the ONLY available restart
// discriminator and is the shipped mechanism — there is no identity field to
// match same-engine reconnect more precisely.
func kvResyncDecision(seq, lastSeq int64) bool {
	if lastSeq < 0 {
		return false // no prior warm state to preserve → CLEAR
	}
	if seq < lastSeq {
		return false // seq went backwards → restart → CLEAR
	}
	if seq > lastSeq+kvSeqResumeWindow {
		return false // large forward jump → ambiguous/restart → CLEAR
	}
	return true // seq resumes near lastSeq → same running engine → KEEP
}

// kvInventory maintains a set of block hashes for one EP.
//
// the inventory is bounded at maxBlocks blocks; when AddBlocks pushes
// it over the cap the OLDEST-inserted (lowest-seq) blocks are evicted FIFO. The
// ordering is tracked by `order` (a container/list in insertion order) with
// `elem` mapping each live hash to its list element for O(1) remove. Eviction
// happens ONLY in AddBlocks under the write Lock (single-writer invariant) — the
// read path (MatchCount/Size) stays RLock-only and never mutates recency, which
// is precisely why LRU is rejected.
type kvInventory struct {
	mu        sync.RWMutex
	blocks    map[uint64]struct{} // flat hash set (membership)
	elem      map[uint64]*list.Element
	order     *list.List // insertion order; Front=oldest, Back=newest. Values are uint64 hashes.
	maxBlocks int        // per-EP cap; <=0 means unbounded (defensive)
	lastSeq   int64      // last seen ZMQ sequence number (1 = none)
	lastRecv  time.Time  // for stale detection

	// svcLabel/epLabel identify this inventory for the cap-hit counter.
	// Set at the production construction site (KvSubscriberStart); empty in unit
	// tests that build a bare inventory (harmless — counter records empty labels).
	svcLabel string
	epLabel  string
}

// AddBlocks adds block hashes to the inventory.
//
// each genuinely-new hash is appended to the insertion-order list;
// re-storing an already-present hash is a no-op for both the set and the
// ordering structure (it must NOT consume a second cap slot or double-append).
// After the insert loop, while the inventory exceeds maxBlocks the oldest
// blocks (Front of `order`) are evicted FIFO. The eviction count is captured
// under the lock and surfaced to the caller via side effects fired OUTSIDE the
// critical section (mirrors the explicit-Unlock log-outside-lock discipline).
func (inv *kvInventory) AddBlocks(hashes []uint64) {
	// Explicit Unlock (not defer): [KV_INV] log + cap-hit counter must run
	// outside the critical section to avoid serializing I/O behind the write lock.
	inv.mu.Lock()
	for _, h := range hashes {
		if _, exists := inv.blocks[h]; exists {
			continue // already present — do not double-append to the ordering structure
		}
		inv.blocks[h] = struct{}{}
		inv.elem[h] = inv.order.PushBack(h)
	}
	evicted := 0
	for inv.maxBlocks > 0 && len(inv.blocks) > inv.maxBlocks {
		front := inv.order.Front()
		if front == nil {
			break // defensive: ordering exhausted (should not happen — set == order)
		}
		oldest := front.Value.(uint64)
		inv.order.Remove(front)
		delete(inv.elem, oldest)
		delete(inv.blocks, oldest)
		evicted++
	}
	inv.lastRecv = time.Now()
	total := len(inv.blocks)
	svcLabel, epLabel := inv.svcLabel, inv.epLabel
	inv.mu.Unlock()

	if evicted > 0 {
		// increment the cap-hit eviction counter OUTSIDE the critical
		// section (mirrors the log-outside-lock discipline). Nonzero is the
		// authoritative "publisher misbehaving" signal.
		prom.IncKvInventoryCapHit(svcLabel, epLabel, evicted)
		log.Warnf("[KV_INV] AddBlocks cap-evicted=%d (service=%s ep=%s cap-hit — publisher may be flooding BlockStored without BlockRemoved)",
			evicted, svcLabel, epLabel)
	}
	// TK11: event-driven gauge — reflect the true post-eviction size immediately
	// (the 10s poll bridge would undercount during cap-hit bursts).
	inv.setBlocksGauge(total)

	var sample uint64
	if len(hashes) > 0 {
		sample = hashes[0]
	}
	log.Debugf("[KV_INV] AddBlocks n_added=%d total=%d evicted=%d sample_hash=0x%016x",
		len(hashes), total, evicted, sample)
}

// setBlocksGauge updates the per-EP block-count gauge event-driven (TK11). Called
// from each mutation AFTER the critical section. Bare unit-test inventories
// (no service/ep labels) are skipped so the metric is not polluted with empty
// label values — the poll bridge still covers any inventory that lacks labels.
func (inv *kvInventory) setBlocksGauge(total int) {
	if inv.svcLabel == "" && inv.epLabel == "" {
		return
	}
	prom.SetKvBlocksGauge(inv.svcLabel, inv.epLabel, float64(total))
}

// RemoveBlocks removes block hashes from the inventory.
func (inv *kvInventory) RemoveBlocks(hashes []uint64) {
	// Explicit Unlock (not defer): see AddBlocks for rationale.
	inv.mu.Lock()
	for _, h := range hashes {
		if e, ok := inv.elem[h]; ok {
			inv.order.Remove(e) // keep the ordering structure in sync (no leaked tombstone)
			delete(inv.elem, h)
		}
		delete(inv.blocks, h)
	}
	inv.lastRecv = time.Now()
	total := len(inv.blocks)
	inv.mu.Unlock()
	inv.setBlocksGauge(total) // TK11: event-driven gauge accuracy
	var sample uint64
	if len(hashes) > 0 {
		sample = hashes[0]
	}
	log.Debugf("[KV_INV] RemoveBlocks n_removed=%d total=%d sample_hash=0x%016x",
		len(hashes), total, sample)
}

// ClearAll empties the inventory.
func (inv *kvInventory) ClearAll() {
	// Explicit Unlock (not defer): see AddBlocks for rationale.
	inv.mu.Lock()
	before := len(inv.blocks)
	inv.blocks = make(map[uint64]struct{})
	inv.elem = make(map[uint64]*list.Element)
	inv.order = list.New() // reset the ordering structure in lockstep with the set
	inv.lastRecv = time.Now()
	inv.mu.Unlock()
	inv.setBlocksGauge(0) // TK11: event-driven gauge accuracy (now empty)
	log.Debugf("[KV_INV] ClearAll cleared=%d total=0", before)
}

// MatchCount returns the number of query hashes present in the inventory.
func (inv *kvInventory) MatchCount(queryHashes []uint64) int {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	count := 0
	for _, h := range queryHashes {
		if _, ok := inv.blocks[h]; ok {
			count++
		}
	}
	return count
}

// Size returns the number of blocks in the inventory.
func (inv *kvInventory) Size() int {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	return len(inv.blocks)
}

func newKvInventory() *kvInventory {
	return &kvInventory{
		blocks:    make(map[uint64]struct{}),
		elem:      make(map[uint64]*list.Element),
		order:     list.New(),
		maxBlocks: kvResolveMaxBlocks(), // env-overridable per-EP cap
		lastSeq:   -1,
	}
}

// ---------- Per-Service KV State ----------

// kvEpRankKey identifies one subscriber goroutine: the (endpoint, DP rank)
// pair (SGL-03). SGLang data-parallel engines publish KV
// events per-rank on consecutive ports (kvZmqPort+rank), so one EP can own N
// subscriber goroutines — the cancel registry must key on BOTH coordinates or
// a rule delete would leak N-1 rank goroutines. The inventory map
// stays keyed by epIdx alone: all ranks of an EP merge (union) into ONE shared
// per-EP inventory.
type kvEpRankKey struct {
	epIdx int
	rank  uint16
}

// kvServiceState manages all KV inventories and subscriber goroutines for one LB service.
type kvServiceState struct {
	mu          sync.RWMutex
	inventories map[int]*kvInventory // ep_index -> inventory (shared across ranks)
	cancelFns   map[kvEpRankKey]context.CancelFunc
	serviceID   uint32
	algo        string // "sha256_cbor" | "xxhash_cbor" | "" (unknown);

	// zero-hit watchdog state (guarded by mu, WRITE lock):
	// consecutive KV-exact lookups that scored zero hits against a non-empty
	// eligible inventory, plus the one-shot WARN arm (transition shape —
	// WARN once per transition into the zero-hit state; the Prometheus counter
	// carries the volume). A single hit resets the streak AND re-arms the WARN.
	zeroHitStreak uint64
	zeroHitWarned bool

	// cold-start seed tick (guarded by mu, WRITE lock): counts Tier-1.5 HITS
	// for this service; every Nth hit (LOXILB_KV_COLDSTART_SEED_N) is diverted
	// to a healthy empty-inventory prefill EP while one exists. Ticks on every
	// hit — cold or not — so the re-admission bound holds from the moment an
	// EP goes cold (worst-case gap ≤ N hits).
	coldSeedTick uint64
}

func newKvServiceState(serviceID uint32) *kvServiceState {
	return &kvServiceState{
		inventories: make(map[int]*kvInventory),
		cancelFns:   make(map[kvEpRankKey]context.CancelFunc),
		serviceID:   serviceID,
		algo:        "",
	}
}

// ---------- Global Registry ----------

var (
	kvServices   = make(map[uint32]*kvServiceState) // service_id -> state
	kvServicesMu sync.RWMutex
)

// kvSvcRef pairs a registry key (the rule number / service ID) with its state
// for one selector scan (SGL-04).
type kvSvcRef struct {
	id  uint32
	svc *kvServiceState
}

// kvSvcScanTargets resolves which services llb_ai_kv_best_worker scores for one
// lookup (SGL-04 / RESEARCH — the cross-VIP contamination
// seam). svcID != 0 ⇒ EXACTLY the calling rule's service via a single
// kvServices[svcID] lookup (unknown ID ⇒ nil ⇒ Tier-1.5 miss; no cross-service
// iteration is reachable). svcID == 0 ⇒ every registered service — today's
// all-services behavior, kept for legacy/uninitialized C structs so the seam is
// independently default-off (the kv_weight nil-guard precedent). LB
// rule markers allocate from 1 (rules.go NewMarker(1, ...)), so 0 can never be
// a real rule's identity. Caller must hold kvServicesMu (read).
func kvSvcScanTargets(svcID uint32) []kvSvcRef {
	if svcID != 0 {
		if svc, ok := kvServices[svcID]; ok {
			return []kvSvcRef{{id: svcID, svc: svc}}
		}
		return nil
	}
	out := make([]kvSvcRef, 0, len(kvServices))
	for id, svc := range kvServices {
		out = append(out, kvSvcRef{id: id, svc: svc})
	}
	return out
}

// ---------- Event Decoding ----------

// kvEventType identifies the type of KV cache event.
type kvEventType int

const (
	kvEventBlockStored kvEventType = iota
	kvEventBlockRemoved
	kvEventAllBlocksCleared
	kvEventUnknown
)

// kvEvent represents a decoded KV cache event.
type kvEvent struct {
	Type   kvEventType
	Hashes []uint64 // block hashes (for BlockStored and BlockRemoved)
	// The remaining fields are decoded from BlockStored only when present,
	// for the §6.2 echo-challenge wire checks (ai_kv_attest_echo.go): the
	// flat token_id list covering the event's blocks in order, and whether
	// the event carries a lora_id / non-empty extra_keys (either fails a
	// challenge block — extraKeyPolicy none_p0 verified on the wire).
	Tokens    []uint32
	Lora      bool
	ExtraKeys bool
}

// decodeKVEventBatch decodes a msgpack-encoded KVEventBatch.
// Format: [ts: float, events: [[tag, ...], ...], dp_rank: int|nil]
//
// Compatibility wrapper over the tagged-array wire binding
// (ai_kv_wire_bindings.go) — the shipped skip semantics for malformed
// events are preserved there, with tagged-map events now surfacing as a
// typed schema-mismatch error instead of a silent debug-level skip.
func decodeKVEventBatch(payload []byte) ([]kvEvent, error) {
	batch, err := kvWireDecodeArrayV1(payload)
	if err != nil {
		return nil, err
	}
	return batch.Events, nil
}

// decodeKVEvent decodes a single tagged event array.
func decodeKVEvent(raw interface{}) (kvEvent, error) {
	arr, ok := raw.([]interface{})
	if !ok || len(arr) == 0 {
		return kvEvent{}, fmt.Errorf("event not array or empty")
	}

	tag, ok := arr[0].(string)
	if !ok {
		return kvEvent{}, fmt.Errorf("event tag not string")
	}

	switch tag {
	case "BlockStored":
		if len(arr) < 2 {
			return kvEvent{}, fmt.Errorf("BlockStored: too few fields")
		}
		hashes, err := extractBlockHashes(arr[1])
		if err != nil {
			return kvEvent{}, fmt.Errorf("BlockStored: %w", err)
		}
		ev := kvEvent{Type: kvEventBlockStored, Hashes: hashes}
		// Optional challenge-check fields (schema at the top of this file:
		// [tag, [hash...], parent, [token_id...], block_size, lora_id,
		// medium, lora_name, extra_keys]). Absence is tolerated — inventory
		// ingest never depends on them; only an armed challenge watch does.
		if len(arr) > 3 {
			ev.Tokens = extractTokenIDs(arr[3])
		}
		if len(arr) > 5 && !kvFieldEmpty(arr[5]) {
			ev.Lora = true
		}
		if len(arr) > 8 && !kvFieldEmpty(arr[8]) {
			ev.ExtraKeys = true
		}
		return ev, nil

	case "BlockRemoved":
		if len(arr) < 2 {
			return kvEvent{}, fmt.Errorf("BlockRemoved: too few fields")
		}
		hashes, err := extractBlockHashes(arr[1])
		if err != nil {
			return kvEvent{}, fmt.Errorf("BlockRemoved: %w", err)
		}
		return kvEvent{Type: kvEventBlockRemoved, Hashes: hashes}, nil

	case "AllBlocksCleared":
		return kvEvent{Type: kvEventAllBlocksCleared}, nil

	default:
		return kvEvent{Type: kvEventUnknown}, nil
	}
}

// extractTokenIDs decodes a flat msgpack token_id array (best-effort: a
// malformed/absent list yields nil, which an armed challenge watch treats as
// a wire-check failure while inventory ingest ignores it).
func extractTokenIDs(raw interface{}) []uint32 {
	arr, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]uint32, 0, len(arr))
	for _, v := range arr {
		switch t := v.(type) {
		case int8:
			out = append(out, uint32(t))
		case int16:
			out = append(out, uint32(t))
		case int32:
			out = append(out, uint32(t))
		case int64:
			out = append(out, uint32(t))
		case uint8:
			out = append(out, uint32(t))
		case uint16:
			out = append(out, uint32(t))
		case uint32:
			out = append(out, t)
		case uint64:
			out = append(out, uint32(t))
		default:
			return nil
		}
	}
	return out
}

// kvFieldEmpty reports whether an optional msgpack field is absent-like
// (nil, empty map, empty array, zero int) — the §6.2 checks require
// lora_id/extra_keys to be EMPTY on challenge blocks.
func kvFieldEmpty(raw interface{}) bool {
	switch t := raw.(type) {
	case nil:
		return true
	case map[string]interface{}:
		return len(t) == 0
	case map[interface{}]interface{}:
		return len(t) == 0
	case []interface{}:
		return len(t) == 0
	case int8:
		return t == 0
	case int16:
		return t == 0
	case int32:
		return t == 0
	case int64:
		return t == 0
	case uint8:
		return t == 0
	case uint16:
		return t == 0
	case uint32:
		return t == 0
	case uint64:
		return t == 0
	case string:
		return t == ""
	default:
		return false
	}
}

// extractBlockHashes extracts uint64 block hashes from a msgpack array.
func extractBlockHashes(raw interface{}) ([]uint64, error) {
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("hashes not array")
	}
	hashes := make([]uint64, 0, len(arr))
	for _, v := range arr {
		switch h := v.(type) {
		case int64:
			hashes = append(hashes, uint64(h))
		case uint64:
			hashes = append(hashes, h)
		case int8:
			hashes = append(hashes, uint64(h))
		case int16:
			hashes = append(hashes, uint64(h))
		case int32:
			hashes = append(hashes, uint64(h))
		case float64:
			hashes = append(hashes, uint64(h))
		default:
			// Skip non-integer hashes
			continue
		}
	}
	return hashes, nil
}

// ---------- ZMQ Subscriber Goroutine ----------

// ZMQ subscriber is implemented as an interface to allow mock injection in tests
// without requiring libzmq at compile time.
type kvZmqSubscriber interface {
	// Connect connects to the ZMQ PUB socket.
	Connect(endpoint string) error
	// RecvMultipart receives a multipart message.
	RecvMultipart() ([][]byte, error)
	// Close closes the socket.
	Close() error
}

// KvEventSource is the transport-agnostic event source the subscriber loop
// consumes (SGL-03). It generalizes the mock-injectable transport
// seam (kvZmqSubscriber) that the reconnect/resync tests already drive: today
// every engine (vllm AND sglang) publishes on the identical ZMQ SUB + msgpack
// wire (scoping-verified — decodeKVEventBatch needs ZERO changes), so the
// interface simply embeds the ZMQ seam. It exists as the named seam a future
// non-ZMQ engine transport (e.g. TensorRT-LLM) plugs into via newKvEventSource
// without touching runKvSubscriberLoop.
type KvEventSource interface {
	kvZmqSubscriber
}

// newKvEventSource is the engine→transport factory (SGL-03). The ZMQ
// engines ("vllm"/"" default and "sglang") share the identical ZMQ SUB
// transport and msgpack KVEventBatch wire format and resolve to the pure-Go
// ZMQ source; "trtllm" resolves to the HTTP drain poller
// (ai_kv_trtllm_source.go), which synthesizes the same 3-frame messages so
// the subscriber loop is transport-blind. blockSize is the rule's
// kvBlockSize, consumed only by the trtllm poller (its event decoder indexes
// exactly full blocks); ZMQ engines carry hashes on the wire and ignore it.
// Unknown engine strings are rejected at config time
// (kvEngineConfigValidate); the defensive default here keeps the subscriber
// alive on the shared transport rather than wedging an EP on a string that
// already passed validation upstream.
func newKvEventSource(ctx context.Context, engine string, addr string, blockSize int) KvEventSource {
	switch engine {
	case "", "vllm", "sglang":
		return newPureGoZmqSubscriber(ctx, addr)
	case "trtllm":
		return newTrtllmEventPoller(ctx, addr, blockSize)
	default:
		log.Warnf("kv-subscriber: unknown engine %q — using default ZMQ event source", engine)
		return newPureGoZmqSubscriber(ctx, addr)
	}
}

// kvZmqReplayRequester is the interface for replay recovery.
type kvZmqReplayRequester interface {
	Connect(endpoint string) error
	SendStartSeq(seq int64) error
	RecvReplay() (seq int64, payload []byte, done bool, err error)
	Close() error
}

// kvReconnectBackoff is the sleep before attempting Connect on a rebuild.
// Gives the kernel time to finish TIME_WAIT cleanup on the old socket.
const kvReconnectBackoff = 500 * time.Millisecond

// kvReconnectFailBackoff is the sleep after a failed Connect before retry.
// Longer to avoid hammering an EP that's genuinely down. Live testbed
// confirms go-zeromq/zmq4 Recv returns a connection-lost error exactly
// once per dead socket (typically io.EOF) and then blocks indefinitely on
// subsequent calls — so rebuild must be triggered on the FIRST error, not
// accumulated over a window.
const kvReconnectFailBackoff = 5 * time.Second

// runKvSubscriberLoop is the main subscriber loop for one EP.
//
// Lifecycle:
//  1. Caller passes in a kvZmqSubscriber already connected to `endpoint`.
//  2. Loop receives multipart messages, decodes events, updates inventory.
//  3. On any recv error (go-zeromq/zmq4 returns connection-lost errors like
//     io.EOF exactly once per dead socket), close+rebuild the socket and
//     increment the reconnect counter. The inventory is NOT blind-cleared
//     anymore: rebuildKvSubscriber preserves lastSeq and the FIRST
//     post-reconnect message decides KEEP (transient blip — warm inventory
//     survives) vs CLEAR (publisher restart — stale hashes dropped) via
//
// kvResyncDecision. Without the rebuild, Recv blocks forever after EOF.
// 4. Exits on ctx.Done.
//
// Metrics:
//
//	loxilb_kv_subscriber_connected{service,ep}     — 1 when connected, 0 during rebuild.
//	loxilb_kv_subscriber_recv_error_total{...}     — every recv error.
//	loxilb_kv_subscriber_reconnect_total{...}      — every successful rebuild.
func runKvSubscriberLoop(ctx context.Context, epIdx int, serviceID uint32, inv *kvInventory,
	sub KvEventSource, replay kvZmqReplayRequester, endpoint string) {
	// thin rank-0 wrapper — every pre- caller and test
	// drives the single-rank path byte-identically through the rank loop.
	runKvSubscriberLoopRank(ctx, epIdx, 0, serviceID, inv, sub, replay, endpoint)
}

// runKvSubscriberLoopRank is the per-(EP, DP rank) subscriber loop body
// (SGL-03). Seq/resync tracking is GOROUTINE-LOCAL per rank
// : SGLang DP ranks publish independent monotonic seq spaces on
// consecutive ports, so a shared gap detector would see rank interleave as
// permanent gaps and thrash the shared inventory with spurious CLEARs.
//   - rank 0 seeds its local seq state from inv.lastSeq (back-compat: the
//     shipped single-rank behavior, and tests pre-seed baselines there) and
//     mirrors its progress back into the field for existing consumers
//     (rebuildKvSubscriber's informational log, seed helpers).
//   - ranks >0 start cold at -1 and never touch inv.lastSeq — their decisions
//     key exclusively on their own stream.
//
// The loop deliberately takes the resolved inventory and the serviceID rather
// than the *kvServiceState it belongs to. It used to do `svcState.inventories[epIdx]`
// here, which is an unsynchronized map read racing `delete(svc.inventories, ...)`
// in KvSubscriberStopAll — the goroutine is SPAWNED under svc.mu but never takes
// the lock itself, so there is no happens-before with a concurrent teardown.
// Resolving the inventory at the call site (which already holds svc.mu and has
// already looked it up) keeps the hot path lock-free and leaves this goroutine
// holding no reference to shared mutable service state at all, so the race is
// structurally impossible rather than merely avoided.
func runKvSubscriberLoopRank(ctx context.Context, epIdx int, rank uint16, serviceID uint32,
	inv *kvInventory, sub KvEventSource, replay kvZmqReplayRequester, endpoint string) {
	// Compatibility wrapper: every pre-binding caller (and the existing
	// test corpus) drives the legacy tagged-array binding byte-identically.
	runKvSubscriberLoopBinding(ctx, epIdx, rank, serviceID, inv, sub, replay, endpoint,
		KvWireVllmArrayV1, 0)
}

// runKvSubscriberLoopBinding is the binding-aware loop body: identical to
// the shipped loop except that payload decoding goes through the resolved
// wire binding (ai_kv_wire_bindings.go) and — on the rank-aware SGLang
// binding — a batch whose declared data_parallel_rank disagrees with this
// stream's socket-derived rank is a typed rejection, never applied.
func runKvSubscriberLoopBinding(ctx context.Context, epIdx int, rank uint16, serviceID uint32,
	inv *kvInventory, sub KvEventSource, replay kvZmqReplayRequester, endpoint string,
	wireSchema string, blockSize int) {
	if inv == nil {
		return
	}

	dec, decErr := kvWireDecoderFor(wireSchema, blockSize)
	if decErr != nil {
		// Fail closed: a stream we cannot decode for must not run at all —
		// a subscriber that connects but silently drops every payload is
		// indistinguishable from a healthy idle publisher.
		log.Warnf("kv-subscriber: ep %d rank %d: %v — subscriber not started", epIdx, rank, decErr)
		return
	}

	svcLabel := fmt.Sprintf("%d", serviceID)
	epLabel := fmt.Sprintf("%d", epIdx)

	// Initial connected state — the caller already dialed successfully.
	setKvConnectedIfLive(ctx, svcLabel, epLabel, 1)
	defer setKvConnectedIfLive(ctx, svcLabel, epLabel, 0)

	// rankLastSeq is the per-rank seq gap detector. It
	// replaces inv.lastSeq as the decision input: the shared field cannot
	// discriminate gaps once N ranks interleave into one inventory. Rank 0
	// seeds from the field so the pre- single-rank semantics (and the
	// pre-seeded reconnect-test baselines) are byte-identical.
	rankLastSeq := int64(-1)
	if rank == 0 {
		inv.mu.RLock()
		rankLastSeq = inv.lastSeq
		inv.mu.RUnlock()
	}

	// resyncPending is the local KEEP/CLEAR decision flag. It is set true
	// right after a successful socket rebuild; the FIRST decoded message after the
	// rebuild then compares its seq against the preserved rank-local lastSeq
	// (kvResyncDecision) to decide whether to KEEP the warm inventory (transient
	// blip) or CLEAR it (publisher restart / ambiguous), exactly ONCE per
	// reconnect. Kept as a local flag (not a kvInventory struct field) so the
	// resync state lives entirely in this rank's goroutine — no cross-goroutine
	// sharing, no extra lock, and a rank reconnect can never KEEP/CLEAR based on
	// another rank's seq (.4).
	resyncPending := false

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frames, err := sub.RecvMultipart()
		if err != nil {
			// Honor cancel even on error path.
			select {
			case <-ctx.Done():
				return
			default:
			}

			incKvRecvErrorIfLive(ctx, svcLabel, epLabel)

			// go-zeromq/zmq4 returns a connection-lost error (typically io.EOF)
			// EXACTLY ONCE when the remote publisher dies — subsequent Recv
			// calls block indefinitely on the dead socket. So we rebuild on
			// the first error rather than accumulating a threshold. Confirmed
			// on the live AWS testbed during TK8 fault injection.
			log.Warnf("kv-subscriber: ep %d rank %d recv error: %v — rebuilding socket", epIdx, rank, err)

			// Retry rebuild until success or ctx cancellation. A single failed
			// Connect (e.g. EP still restarting) must not leave the loop
			// calling Recv on a closed socket — Recv blocks indefinitely
			// on a closed zmq4 socket, which would wedge the subscriber.
			for !rebuildKvSubscriber(ctx, sub, inv, endpoint, epIdx, svcLabel, epLabel) {
				select {
				case <-ctx.Done():
					return
				default:
				}
				// rebuildKvSubscriber already slept kvReconnectFailBackoff on
				// Connect failure. Nothing more to do — try again.
			}
			// Rebuild succeeded. Defer the KEEP/CLEAR resync decision to the first
			// message we decode below: the rank-local lastSeq was preserved
			// rather than blind-cleared, so the seq-reset comparison can run.
			resyncPending = true
			continue
		}

		if len(frames) < 3 {
			log.Debugf("kv-subscriber: ep %d skipping message with %d frames (expected 3)", epIdx, len(frames))
			continue
		}

		// Parse sequence number (frame 1: 8-byte big-endian uint64)
		var seq int64
		if len(frames[1]) >= 8 {
			seq = int64(binary.BigEndian.Uint64(frames[1]))
		}

		// first message after a reconnect — decide KEEP vs CLEAR ONCE.
		// The rebuild preserved the rank-local lastSeq instead of blind-clearing,
		// so we compare this first post-reconnect seq against it: resumes near
		// lastSeq → KEEP the warm inventory (transient blip, same running engine;
		// the live SUB stream re-converges); reset-to-low /
		// large-forward-jump / no-prior-seq → CLEAR (publisher restart or
		// ambiguous — conservative toward correctness). The flag is
		// cleared here so subsequent messages never re-trigger the decision. This
		// message's own events are applied AFTER the decision below, so a CLEAR
		// wipes stale state first and then this message's fresh blocks are added.
		// justResynced suppresses gap decision below for THIS message —
		// the resync decision already ran on the same (seq, rankLastSeq) pair.
		justResynced := false
		if resyncPending {
			resyncPending = false
			justResynced = true
			if kvResyncDecision(seq, rankLastSeq) {
				log.Infof("kv-subscriber: ep %d rank %d resync KEEP — first post-reconnect seq=%d resumes near lastSeq=%d (transient blip; warm inventory retained, size=%d)",
					epIdx, rank, seq, rankLastSeq, inv.Size())
			} else {
				log.Infof("kv-subscriber: ep %d rank %d resync CLEAR — first post-reconnect seq=%d vs lastSeq=%d indicates publisher restart/ambiguous; clearing stale inventory",
					epIdx, rank, seq, rankLastSeq)
				inv.ClearAll()
			}
		}

		// Detect sequence gap on the live stream (rank-local detector).
		if rankLastSeq >= 0 && seq > rankLastSeq+1 {
			gap := seq - rankLastSeq - 1
			if replay != nil {
				// Replay client available — recover the missed events (unchanged
				// pre- path; production passes replay=nil).
				log.Infof("kv-subscriber: ep %d seq gap detected: %d -> %d (missing %d)",
					epIdx, rankLastSeq, seq, gap)
				replayKvEvents(inv, replay, rankLastSeq+1, dec)
			} else if !justResynced {
				// gap with NO replay client is no longer
				// silently ignored — the missed events may include BlockRemoved/
				// AllBlocksCleared, so a large gap means the inventory may hold
				// phantom hashes (stale-inventory mis-route). Run the
				// same conservative KEEP/CLEAR discriminator as the reconnect
				// resync: a small forward hop within kvSeqResumeWindow is a
				// tolerable miss (KEEP — the live stream re-converges); a
				// large forward jump is ambiguous/lossy (CLEAR — a needless cold
				// window is only a perf cost, phantom hashes are a correctness
				// bug). Structured decision= marker is CICD anchor.
				if kvResyncDecision(seq, rankLastSeq) {
					log.Infof("kv-subscriber: ep %d rank %d seq gap %d -> %d (missing %d, no replay) decision=KEEP — small resume within window; warm inventory retained (size=%d)",
						epIdx, rank, rankLastSeq, seq, gap, inv.Size())
				} else {
					log.Infof("kv-subscriber: ep %d rank %d seq gap %d -> %d (missing %d, no replay) decision=CLEAR — large forward jump; clearing stale inventory",
						epIdx, rank, rankLastSeq, seq, gap)
					inv.ClearAll()
				}
			}
		}

		// Live-stream seq REGRESSION — a fast engine restart behind a
		// transparent ZMQ SUB auto-reconnect: Recv never errors, resyncPending
		// never arms, and the fresh publisher process restarts its seq low.
		// Without this branch the regression was silently absorbed by the
		// rankLastSeq = seq update below, so the dead engine's warm inventory
		// survived as phantom hashes and Tier-1.5 kept routing long prompts to
		// the cold restarted EP (herding + stealing traffic from the real cache
		// owners). Same rule kvResyncDecision already encodes for the explicit
		// paths (seq < lastSeq ⇒ restart ⇒ CLEAR), applied per live message.
		// The CLEAR runs BEFORE this message's events so the fresh publisher's
		// first blocks land in a clean inventory. justResynced guards the
		// explicit-reconnect path, whose decision already ran on this pair.
		if rankLastSeq >= 0 && seq < rankLastSeq && !justResynced {
			log.Infof("kv-subscriber: ep %d rank %d live-stream seq REGRESSION %d -> %d decision=CLEAR — publisher restarted behind transparent reconnect; clearing stale inventory (size=%d)",
				epIdx, rank, rankLastSeq, seq, inv.Size())
			inv.ClearAll()
		}

		// Decode and apply events from payload (frame 2) via the resolved
		// wire binding. A typed wire rejection (schema mismatch, strict
		// map-batch failure) is counted — the silent-staleness class this
		// binding layer exists to close — and the batch applies nothing.
		batch, err := dec.Decode(frames[2])
		if err != nil {
			if reason := kvWireReasonOf(err); reason != "" {
				incKvWireRejectIfLive(ctx, svcLabel, epLabel, reason)
			}
			log.Debugf("kv-subscriber: ep %d decode error: %v", epIdx, err)
			continue
		}

		// SGLang rank-aware binding: the payload's declared rank must agree
		// with this stream's socket-derived rank (base port + rank). A
		// disagreement means the endpoint's rank topology is not what the
		// rule declared — applying the batch would corrupt the union
		// inventory with another rank's stream.
		if wireSchema == KvWireSglangRankV1 && batch.DPRank != nil && *batch.DPRank != int64(rank) {
			incKvWireRejectIfLive(ctx, svcLabel, epLabel, KvWireReasonRankMismatch)
			log.Warnf("kv-subscriber: ep %d rank %d: batch declares dp_rank %d — rejected (rank identity mismatch)",
				epIdx, rank, *batch.DPRank)
			continue
		}
		events := batch.Events

		for _, ev := range events {
			switch ev.Type {
			case kvEventBlockStored:
				inv.AddBlocks(ev.Hashes)
				// Echo-challenge watch (ai_kv_attest_echo.go): resolves an
				// armed challenge's expected hashes; no-op otherwise.
				kvHashWatchObserve(serviceID, epIdx, ev)
				log.Infof("kv-subscriber: BlockStored %d block(s) for ep %d (total=%d)", len(ev.Hashes), epIdx, inv.Size())
			case kvEventBlockRemoved:
				inv.RemoveBlocks(ev.Hashes)
			case kvEventAllBlocksCleared:
				// Open Q3 (union semantics): the inventory is a UNION across all
				// DP ranks of the EP, and block hashes carry no rank tag — a
				// Cleared event from ANY rank therefore clears the WHOLE per-EP
				// inventory. This deliberately over-clears (the other ranks'
				// still-warm blocks are dropped, losing cache warmth) because the
				// safe direction is asymmetric: over-clear degrades to the
				// fallback selector for a cold window (perf cost only), while
				// under-clear leaves phantom hashes that mis-route Tier 1.5
				// (correctness bug). Revisit only if wave-4 A/B shows measurable
				// warmth loss from rank-restart churn.
				log.Infof("kv-subscriber: AllBlocksCleared received for ep %d (rank %d) — clearing shared inventory", epIdx, rank)
				inv.ClearAll()
			}
		}

		rankLastSeq = seq
		if rank == 0 {
			// Back-compat mirror only (rebuild log, seed helpers) — never read as
			// the gap detector anymore. Ranks >0 do not write it: interleaved
			// writes would turn the field into cross-rank garbage.
			inv.mu.Lock()
			inv.lastSeq = seq
			inv.mu.Unlock()
		}
	}
}

// kvSeriesMu serializes subscriber-goroutine metric writes against teardown's
// cancel()+ClearKvEpSeries. The bare ctx.Err() guard alone is a TOCTOU: a writer
// that passes the check can be descheduled, teardown cancels AND deletes the
// series, and the write then lands after the delete — resurrecting the child.
// That residual window was real, not theoretical: on an 8-core host the
// lifecycle test leaked 1-4 series in ~80% of runs (first caught by the GPU
// testbed CI 2026-08-07; the original 15/15→0/15 fix had only narrowed the
// race). Both critical sections are short and non-blocking, so the rule-delete
// path stays effectively synchronous. Lock order: svc.mu → kvSeriesMu (writers
// never take svc.mu, so no cycle).
var kvSeriesMu sync.Mutex

// setKvConnectedIfLive writes the subscriber-liveness gauge ONLY while the
// subscriber is still live, i.e. its ctx has not been cancelled.
//
// Teardown (KvSubscriberStopAll / KvSubscriberStop) cancels ctx and then calls
// prom.ClearKvEpSeries, which DELETES this (service, ep) child. cancel() only
// signals — it does not wait — so a write that slips past the ctx check after
// the delete RESURRECTS the child at 0, and nothing ever removes it again:
// `min(loxilb_kv_subscriber_connected)` (the "KV subscribers up" panel) reads 0
// forever once any KV service has been torn down. kvSeriesMu makes the
// check+write atomic against teardown's cancel+delete, closing the window.
//
// Waiting for the goroutine instead (a WaitGroup around ClearKvEpSeries) is NOT
// viable — the loop blocks in sub.RecvMultipart(), which does not observe ctx
// cancellation until a message arrives, so an idle EP would hang rule deletion
// indefinitely.
func setKvConnectedIfLive(ctx context.Context, svcLabel, epLabel string, connected int) {
	kvSeriesMu.Lock()
	defer kvSeriesMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	prom.SetKvSubscriberConnected(svcLabel, epLabel, connected)
}

// incKvReconnectIfLive / incKvRecvErrorIfLive: the counter children
// (kv_subscriber_reconnect_total / kv_subscriber_recv_error_total) have the
// exact same resurrect-after-delete race as the connected gauge — the loop can
// return from RecvMultipart (message or error) AFTER teardown cancelled and
// reaped the series, and a bare Inc() would recreate the child. Same guard.
func incKvReconnectIfLive(ctx context.Context, svcLabel, epLabel string) {
	kvSeriesMu.Lock()
	defer kvSeriesMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	prom.IncKvSubscriberReconnect(svcLabel, epLabel)
}

func incKvRecvErrorIfLive(ctx context.Context, svcLabel, epLabel string) {
	kvSeriesMu.Lock()
	defer kvSeriesMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	prom.IncKvSubscriberRecvError(svcLabel, epLabel)
}

// incKvWireRejectIfLive increments the wire-binding rejection counter under
// the same teardown discipline as the other per-EP KV series (an unguarded
// Inc landing after ClearKvEpSeries would resurrect a deleted child).
func incKvWireRejectIfLive(ctx context.Context, svcLabel, epLabel, reason string) {
	kvSeriesMu.Lock()
	defer kvSeriesMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	prom.IncKvSubscriberWireReject(svcLabel, epLabel, reason)
}

// rebuildKvSubscriber closes the current SUB socket and redials the same
// endpoint. On success it clears the inventory (the remote publisher's block
// IDs are fresh after restart — old hashes would mis-route Tier 1.5) and
// resets lastSeq. Returns true if reconnect succeeded, false otherwise; on
// failure the caller should back off before the next attempt.
//
// Split out of runKvSubscriberLoop for readability and to make the rebuild
// path explicit — the previous code silently ignored recv errors and looped
// forever on a dead socket, which was the root cause of the permanent-stale-
// inventory bug surfaced by TK8.
func rebuildKvSubscriber(ctx context.Context, sub kvZmqSubscriber, inv *kvInventory,
	endpoint string, epIdx int, svcLabel, epLabel string) bool {

	log.Warnf("kv-subscriber: ep %d rebuilding ZMQ socket (endpoint=%s)", epIdx, endpoint)
	setKvConnectedIfLive(ctx, svcLabel, epLabel, 0)

	_ = sub.Close()

	select {
	case <-ctx.Done():
		return false
	case <-time.After(kvReconnectBackoff):
	}

	if err := sub.Connect(endpoint); err != nil {
		log.Warnf("kv-subscriber: ep %d reconnect to %s failed: %v", epIdx, endpoint, err)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(kvReconnectFailBackoff):
		}
		return false
	}

	// Reconnect succeeded. : do NOT blind-clear here. A reconnect can be a
	// transient network blip (the vLLM engine is still running with a warm prefix
	// cache — clearing would throw away a valid inventory and eat a needless cold
	// no_worker window) OR a real publisher restart (fresh prefix cache — our
	// cached hashes are stale and MUST be dropped). We cannot tell which yet:
	// Connect only re-dials, no seq is known until the first recv. So we PRESERVE
	// lastSeq (do NOT reset to -1) and defer the KEEP/CLEAR decision to the first
	// post-reconnect message in runKvSubscriberLoop, which compares the new seq
	// against this preserved lastSeq via kvResyncDecision (seq-reset
	// heuristic). Re-convergence for the KEEP case is re-subscribe-and-converge on
	// the live SUB stream, NOT a replay client.
	//
	// deferral: there is NO engine_id on the KV-event wire — vLLM's EventBatch
	// carries only data_parallel_rank, no per-engine identity. An earlier comment
	// here aspirationally referenced a "new engine_id" to detect restarts; that
	// field does not exist on the wire (research-verified), so no engine_id parse
	// branch is shipped. The seq-reset heuristic is the only available restart
	// discriminator and is the shipped mechanism.
	log.Infof("kv-subscriber: ep %d reconnected to %s — deferring KEEP/CLEAR resync to first post-reconnect message (lastSeq=%d preserved)",
		epIdx, endpoint, inv.lastSeq)

	setKvConnectedIfLive(ctx, svcLabel, epLabel, 1)
	incKvReconnectIfLive(ctx, svcLabel, epLabel)
	return true
}

// replayKvEvents requests missed events from the replay socket. Replayed
// payloads decode through the SAME wire binding as the live stream — a
// replay buffer in a different wire family than the bound contract must
// fail the same way live traffic would.
func replayKvEvents(inv *kvInventory, replay kvZmqReplayRequester, startSeq int64, dec kvWireDecoder) {
	if err := replay.SendStartSeq(startSeq); err != nil {
		log.Warnf("kv-subscriber: replay request failed: %v", err)
		return
	}

	for {
		_, payload, done, err := replay.RecvReplay()
		if err != nil || done {
			if err != nil {
				log.Warnf("kv-subscriber: replay recv error: %v", err)
			}
			break
		}

		batch, err := dec.Decode(payload)
		if err != nil {
			continue
		}
		events := batch.Events
		for _, ev := range events {
			switch ev.Type {
			case kvEventBlockStored:
				inv.AddBlocks(ev.Hashes)
			case kvEventBlockRemoved:
				inv.RemoveBlocks(ev.Hashes)
			case kvEventAllBlocksCleared:
				inv.ClearAll()
			}
		}
	}
}

// ---------- Service Lifecycle ----------

// KvSubscriberStart starts a ZMQ subscriber goroutine for the given EP.
// Called when an EP is added to a service with kv_exact_mode=1.
// algo is the hash algorithm string from the LB service ("sha256_cbor" |
// "xxhash_cbor"); stored on the kvServiceState so Admin API
// (DumpKvInventory) can report it alongside the block hashes.
//
// thin rank-0 wrapper over KvSubscriberStartRank so every
// existing caller and test keeps its shipped single-rank behavior
// byte-identically (: default rank count 1 ≡ today's single-port path).
func KvSubscriberStart(serviceID uint32, epIdx int, epIP string, zmqPort uint16, algo string) {
	KvSubscriberStartRank(serviceID, epIdx, 0, epIP, zmqPort, algo, "", 0, "")
}

// KvSubscriberStartRank starts a ZMQ subscriber goroutine for one (EP, DP
// rank) pair (SGL-03). SGLang data-parallel engines publish
// per-rank on consecutive ports, so the caller passes the rank's own port
// (kvZmqPort+rank). The per-EP inventory is created ONCE (first rank creates,
// later ranks look it up) and SHARED across ranks — all ranks of an EP merge
// (union) into one inventory via the RWMutex-safe AddBlocks/RemoveBlocks.
// Dedup and teardown are keyed by (epIdx, rank) so N rank goroutines can
// coexist per EP and a rule delete cancels ALL of them.
//
// engine selects the event transport via newKvEventSource ("" ≡ the shared
// ZMQ default); for "trtllm" the caller passes the EP's own SERVING port
// (events ride it — there is no separate event port) and blockSize carries
// the rule's kvBlockSize for the poller's full-block decoder.
func KvSubscriberStartRank(serviceID uint32, epIdx int, rank uint16, epIP string, port uint16, algo string,
	engine string, blockSize uint32, contractID string) {
	kvServicesMu.Lock()
	defer kvServicesMu.Unlock()

	svc, ok := kvServices[serviceID]
	if !ok {
		svc = newKvServiceState(serviceID)
		kvServices[serviceID] = svc
	}
	// Record algo on first subscriber start; later starts keep the existing value
	// unless it was empty (defensive — algo is a per-service invariant).
	if svc.algo == "" {
		svc.algo = algo
	}

	svc.mu.Lock()
	defer svc.mu.Unlock()

	// Dedup: already running for this (EP, rank)
	key := kvEpRankKey{epIdx: epIdx, rank: rank}
	if _, ok := svc.cancelFns[key]; ok {
		return
	}

	// Create inventory ONCE per epIdx (first rank creates, later ranks share it —
	// the multi-rank union merges into one per-EP inventory). Stamp the
	// (service, ep) labels so AddBlocks can fire the cap-hit counter
	// without threading labels through every call site. The cap is per-EP
	// (the SHARED inventory), not per-rank — N ranks amplify ingest into the
	// same bounded structure.
	inv, ok := svc.inventories[epIdx]
	if !ok {
		inv = newKvInventory()
		inv.svcLabel = fmt.Sprintf("%d", serviceID)
		inv.epLabel = fmt.Sprintf("%d", epIdx)
		svc.inventories[epIdx] = inv
	}

	// publish the ep_idx->IP identity so the integer-keyed
	// KV per-EP metrics (tier15_hits/spills, subscriber gauges) are joinable to a
	// physical endpoint, and every prefill EP is discoverable even before it emits
	// a (lazy) tier15_hits series. Idempotent across ranks (same IP per EP).
	prom.SetKvEpInfo(inv.svcLabel, inv.epLabel, epIP)

	ctx, cancel := context.WithCancel(context.Background())
	svc.cancelFns[key] = cancel

	addr := fmt.Sprintf("tcp://%s:%d", epIP, port)
	log.Infof("kv-subscriber: starting EP %d rank %d for service %d at %s", epIdx, rank, serviceID, addr)

	// Start Prometheus gauge bridge (once)
	// thread the mh-owned shutdown ctx so the
	// metrics-bridge ticker exits when the workers stage cancels.
	StartKvMetricsBridge(mh.shutdownCtx)

	// Start the subscriber goroutine using the interface-based subscriber loop.
	// The engine→transport factory (newKvEventSource) resolves the ZMQ
	// engines (vllm, sglang, "" default) to the pure-Go ZMQ source and
	// trtllm to the HTTP drain poller; both speak the same 3-frame message
	// shape to the loop.
	go func() {
		// TRT-LLM endpoints pass the /server_info admission gate BEFORE the
		// event poller exists: a contract-mismatched endpoint (wrong
		// tokens_per_block, non-v1 event hashing) gets no poller — its
		// inventory stays empty and Tier-1.5 can never route to it — and
		// never touches the sole-consumer event drain either. The gate
		// blocks through boot-time unreachability and re-checks refusals,
		// so it only returns false on teardown.
		if engine == "trtllm" {
			if !kvTrtllmAdmissionGate(ctx, addr, serviceID, epIdx, int(blockSize)) {
				return
			}
		}

		sub := newKvEventSource(ctx, engine, addr, int(blockSize))
		defer sub.Close()

		// KV-12/: the publisher may not be bound yet when the rule lands (a
		// vLLM that boots after the LB rule is configured, or is down/restarting
		// at rule-create). A failed initial Dial must NOT kill the subscriber
		// forever — retry with the same backoff discipline as the post-connect
		// rebuild path (rebuildKvSubscriber) until the EP is removed (ctx cancel).
		// Connect builds a fresh zmq4 socket per call, so Close-then-Connect on
		// the same wrapper is safe (the rebuild path relies on the same property).
		for {
			err := sub.Connect(addr)
			if err == nil {
				break
			}
			log.Warnf("kv-subscriber: ep %d rank %d initial connect to %s failed: %v — retrying in %s",
				epIdx, rank, addr, err, kvReconnectFailBackoff)
			_ = sub.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(kvReconnectFailBackoff):
			}
		}

		// Inventory replay on fresh subscribe: engine prefix caches survive a
		// gateway restart, but engines publish BlockStored only on NEW stores,
		// so a fresh subscriber stays blind to every block cached before it
		// connected (cold-herding until natural churn). When the publisher
		// exposes a replay endpoint (fixed port offset from the PUB endpoint),
		// request the buffered event history once before entering the live
		// loop. Fail-open on every edge: no replay listener (engines without
		// replay_endpoint configured), parse failure, or a hung replay (the
		// bounded context unblocks Recv) all leave the inventory to warm
		// organically, exactly as before. The live loop still gets replay=nil
		// — its KEEP/CLEAR gap heuristics stay the shipped behavior.
		// The ZMQ replay port-offset probe only makes sense for ZMQ engines;
		// the trtllm drain has no replay channel at all, so its cold-start
		// posture is always organic warmup.
		// Resolve the stream's wire binding through the compiled
		// engine-contract registry (legacy policy table preserves shipped
		// behavior per engine; see kvLegacyWireProfile). Fail closed: no
		// binding, no subscriber.
		wireSchema, wErr := kvResolveWireSchema(engine, contractID)
		if wErr != nil {
			log.Warnf("kv-subscriber: ep %d rank %d: %v — subscriber not started", epIdx, rank, wErr)
			return
		}

		if raddr := kvReplayEndpoint(addr); raddr != "" && engine != "trtllm" {
			rctx, rcancel := context.WithTimeout(ctx, 15*time.Second)
			rc := newPureGoZmqReplayClient(rctx)
			if err := rc.Connect(raddr); err != nil {
				log.Infof("kv-subscriber: ep %d rank %d no replay listener at %s (%v) — inventory warms organically",
					epIdx, rank, raddr, err)
			} else if rdec, derr := kvWireDecoderFor(wireSchema, int(blockSize)); derr == nil {
				replayKvEvents(inv, rc, 0, rdec)
				log.Infof("kv-subscriber: ep %d rank %d replayed buffered KV events from %s (inventory size=%d)",
					epIdx, rank, raddr, inv.Size())
			}
			_ = rc.Close()
			rcancel()
		}

		// Run the subscriber loop (reuses existing tested logic).
		// `addr` is passed for on-recv-error socket rebuild — go-zeromq/zmq4
		// does not auto-reconnect after publisher restart, so the loop needs
		// the endpoint to redial when it detects a dead socket.
		// inv was resolved above under svc.mu, before this goroutine was
		// spawned — passing it in keeps the teardown-racy map read out of here.
		runKvSubscriberLoopBinding(ctx, epIdx, rank, serviceID, inv, sub, nil, addr,
			wireSchema, int(blockSize))
	}()
}

// KvSubscriberStop stops the ZMQ subscriber(s) for the given EP — ALL rank
// goroutines of the EP are cancelled (SGL-03: cancelFns is keyed by
// (epIdx, rank); a per-EP stop must iterate the composite keys or rank>0
// goroutines would leak).
func KvSubscriberStop(serviceID uint32, epIdx int) {
	kvServicesMu.RLock()
	svc, ok := kvServices[serviceID]
	kvServicesMu.RUnlock()
	if !ok {
		return
	}

	svc.mu.Lock()
	defer svc.mu.Unlock()

	// cancel+clear must be atomic against the guarded writers (kvSeriesMu):
	// otherwise a writer that already passed its ctx check re-creates the
	// series right after the delete (the ghost-series TOCTOU).
	kvSeriesMu.Lock()
	for key, cancel := range svc.cancelFns {
		if key.epIdx == epIdx {
			cancel()
			delete(svc.cancelFns, key)
		}
	}
	delete(svc.inventories, epIdx)

	// Drop ALL of the EP's per-series children (blocks gauge, subscriber
	// liveness/reconnect/error, tier15 hit/spill, ep_idx->IP identity) so a
	// decommissioned EP does not linger as stale series on /metrics.
	prom.ClearKvEpSeries(fmt.Sprintf("%d", serviceID), fmt.Sprintf("%d", epIdx))
	kvSeriesMu.Unlock()

	// Drop the EP's trtllm admission verdict (no-op for ZMQ engines) so the
	// audit API never shows a stale verdict for a decommissioned EP.
	kvTrtllmAdmissionForget(serviceID, epIdx)
}

// KvSubscriberStopAll stops all ZMQ subscribers for the given service.
func KvSubscriberStopAll(serviceID uint32) {
	kvServicesMu.Lock()
	svc, ok := kvServices[serviceID]
	if ok {
		delete(kvServices, serviceID)
	}
	kvServicesMu.Unlock()

	if svc == nil {
		return
	}

	svc.mu.Lock()
	defer svc.mu.Unlock()

	// cancel+clear under kvSeriesMu: atomic against the guarded writers, so a
	// writer that raced past its ctx check cannot resurrect a reaped series
	// (the ghost-series TOCTOU — see kvSeriesMu doc).
	kvSeriesMu.Lock()
	// cancelFns is keyed by (epIdx, rank) — ranging over the
	// composite keys cancels EVERY rank goroutine of every EP (: a
	// multi-rank EP owns N entries; the single service-scoped call must tear
	// down all of them). rules.go teardown stays this one unchanged call.
	for key, cancel := range svc.cancelFns {
		cancel()
		delete(svc.cancelFns, key)
	}

	// Reap every EP's per-series children plus the service-scoped watchdog
	// counter so a torn-down service leaves no stale series on /metrics.
	svcLabel := fmt.Sprintf("%d", serviceID)
	for epIdx := range svc.inventories {
		prom.ClearKvEpSeries(svcLabel, fmt.Sprintf("%d", epIdx))
		delete(svc.inventories, epIdx)
	}
	prom.ClearKvServiceSeries(svcLabel)
	kvSeriesMu.Unlock()

	// Drop the service's trtllm admission verdicts (no-op for ZMQ engines).
	kvTrtllmAdmissionForgetAll(serviceID)
}

// ---------- : Tier-1.5 zero-hit watchdog ----------

// kvZeroHitNDefault is the consecutive-zero-hit threshold (Open Q4 resolved:
// N=50). At-or-past N consecutive KV-exact lookups that scored ZERO hits
// against a service whose eligible inventory is non-empty, the watchdog fires:
// ONE WARN on the transition edge (shape — never a log flood,
// plus a Prometheus counter increment on EVERY occurrence at-or-
// past the threshold (the counter carries the volume). This makes the silent
// kvBlockSize≠page-size / hash-algo parity failure loudly visible: the
// inventory fills, yet no live request ever matches — Tier-1.5 is effectively
// OFF while everything else looks healthy.
const kvZeroHitNDefault = 50

// kvZeroHitEnvWarnOnce rate-limits the invalid-env WARN to one shot (the
// threshold accessor runs on the lookup hot path).
var kvZeroHitEnvWarnOnce sync.Once

// kvZeroHitN resolves the watchdog threshold: LOXILB_KV_ZERO_HIT_N
// parse-or-default (invalid/non-positive ⇒ default 50 — the watchdog can be
// tuned but NEVER disabled via a bad value).
func kvZeroHitN() uint64 {
	if v := os.Getenv("LOXILB_KV_ZERO_HIT_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return uint64(n)
		}
		kvZeroHitEnvWarnOnce.Do(func() {
			log.Warnf("[KV_ZEROHIT] invalid LOXILB_KV_ZERO_HIT_N=%q (want positive int), using default %d (watchdog is never disabled)",
				v, kvZeroHitNDefault)
		})
	}
	return kvZeroHitNDefault
}

// ---------- Tier-1.5 cold-start seeding ----------
//
// With small block sizes (SGLang page_size=1 ⇒ kvBlockSize=1) any prompt that
// shares a deep-enough head with cached traffic is a Tier-1.5 HIT, and the
// selector only ever ranks positive-overlap candidates — an EMPTY-inventory
// (flushed/rebooted) EP has overlap 0 for every request, never enters the
// candidate set, and is starved of exact-mode traffic indefinitely at low
// concurrency (live evidence: 0/160 probes to a 0-block EP; the spill/relief
// paths need over-cap load that never materializes when load ≈ 0-1).
//
// The compensation is a deterministic bounded seed, applied AFTER the normal
// selection so the warm path is untouched: every Nth Tier-1.5 hit per service
// is diverted to the lowest-index healthy (prefill-mask, not excluded)
// empty-inventory EP while one exists. The diverted request prefills there,
// its BlockStored events fill the inventory, the EP stops being cold and the
// diversion stops — self-limiting, so steady-state warm traffic is
// byte-identical. The returned score is the DISPLACED hit's depth, so the
// C-side GUARD_H/GUARD_G post-checks accept the seed exactly when they would
// have accepted the hit (a cb-open/invalid seed target falls back to a
// Tier-2 miss C-side, which is safe).

// kvColdSeedNDefault: divert 1 of every 16 Tier-1.5 hits while a cold EP
// exists — ≤6.25% short-lived diversion, and a cold EP is re-admitted within
// 16 exact-mode hits even at concurrency 1.
const kvColdSeedNDefault = 16

// kvColdSeedMinBlocksDefault: an inventory BELOW this many blocks counts as
// cold. Strictly-empty is too brittle on real engines — a flushed SGLang
// engine leaves/re-publishes a trace block (live evidence: 1 of 12062 blocks
// back within seconds of the flush, with zero requests served), and one
// stray block must not disqualify a starved EP. 16 matches the default
// minimum-match depth in tokens: at block size 1 an inventory under 16
// blocks can never score past the shallow-match guard, so the EP is
// provably unselectable — cold in the exact sense that matters.
const kvColdSeedMinBlocksDefault = 16

// kvColdSeedMinBlocksEnvWarnOnce rate-limits the invalid-env WARN.
var kvColdSeedMinBlocksEnvWarnOnce sync.Once

// kvColdSeedMinBlocks resolves LOXILB_KV_COLDSTART_MIN_BLOCKS: unset ⇒
// default 16; explicit 0 ⇒ strict empty-only; invalid ⇒ default + WARN.
func kvColdSeedMinBlocks() int {
	if v := os.Getenv("LOXILB_KV_COLDSTART_MIN_BLOCKS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
		kvColdSeedMinBlocksEnvWarnOnce.Do(func() {
			log.Warnf("[KV_COLDSEED] invalid LOXILB_KV_COLDSTART_MIN_BLOCKS=%q (want int >= 0), using default %d",
				v, kvColdSeedMinBlocksDefault)
		})
	}
	return kvColdSeedMinBlocksDefault
}

// kvColdSeedEnvWarnOnce rate-limits the invalid-env WARN to one shot (the
// accessor runs on the lookup hot path).
var kvColdSeedEnvWarnOnce sync.Once

// kvColdSeedN resolves LOXILB_KV_COLDSTART_SEED_N: unset/empty ⇒ default 16
// (compensation ON, conservative); explicit 0 ⇒ disabled (pure-selector A/B
// runs); invalid/negative ⇒ default + one-shot WARN.
func kvColdSeedN() uint64 {
	if v := os.Getenv("LOXILB_KV_COLDSTART_SEED_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return uint64(n)
		}
		kvColdSeedEnvWarnOnce.Do(func() {
			log.Warnf("[KV_COLDSEED] invalid LOXILB_KV_COLDSTART_SEED_N=%q (want int >= 0, 0=off), using default %d",
				v, kvColdSeedNDefault)
		})
	}
	return kvColdSeedNDefault
}

// kvColdSeedCounterFn is the Prometheus seam for the cold-seed counter
// (loxilb_pd_kv_tier15_cold_seeds_total{ep_idx}). Default = the real counter;
// unit tests override it (kvZeroHitCounterFn precedent).
var kvColdSeedCounterFn = prom.IncKvTier15ColdSeedCounter

// kvColdStartSeed evaluates the cold-start seed for ONE Tier-1.5 hit about to
// be returned as bestEp. It ticks the per-service hit counter and, on every
// Nth tick, returns (seedEp, true) for the lowest-index healthy
// empty-inventory prefill EP — (bestEp, false) otherwise. svcID==0 (the
// legacy all-services scan) is skipped: the tick and the cold scan are
// per-service state. An EP with NO inventory entry at all counts as cold
// (a just-registered or flushed-and-quiet EP has no map entry yet).
func kvColdStartSeed(svcID uint32, prefillMask, excludedMask uint32, bestEp int) (int, bool) {
	n := kvColdSeedN()
	if n == 0 || svcID == 0 {
		return bestEp, false
	}
	kvServicesMu.RLock()
	svc := kvServices[svcID]
	kvServicesMu.RUnlock()
	if svc == nil {
		return bestEp, false
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	svc.coldSeedTick++
	if svc.coldSeedTick%n != 0 {
		return bestEp, false
	}
	// warm floor: an inventory at/above this size disqualifies the EP as a
	// seed target. Explicit 0 degrades to 1 (strict empty-only) — a floor of
	// 0 would mark every EP warm and silently disable seeding.
	floor := kvColdSeedMinBlocks()
	if floor < 1 {
		floor = 1
	}
	for ep := 0; ep < 32; ep++ {
		bit := uint32(1) << uint(ep)
		if prefillMask&bit == 0 || excludedMask&bit != 0 {
			continue
		}
		if inv, ok := svc.inventories[ep]; ok && inv.Size() >= floor {
			continue // warm — enough published blocks to be selectable
		}
		if ep == bestEp {
			continue // defensive: a cold EP can never be the positive-score winner
		}
		return ep, true
	}
	return bestEp, false
}

// kvZeroHitCounterFn is the Prometheus seam for the watchdog counter
// (loxilb_pd_kv_zero_hit_watchdog_total{service_id}). Default = the real
// counter; unit tests override it to count occurrences (the kvWorkerMetricsFn
// seam precedent). Data-path-only observability — the watchdog performs NO
// backend HTTP call anywhere (rejected alternative).
var kvZeroHitCounterFn = prom.IncKvZeroHitWatchdog

// kvZeroHitWatchdog evaluates one lookup's outcome for one scanned service on
// the llb_ai_kv_best_worker exit path (via kvSvcScanInventories — the only
// place that sees (eligible inventory non-empty) ∧ (per-service best score)
// per lookup). Engine-agnostic and per-service (labeled by service ID):
//   - hadInv == false     ⇒ no-op (an empty/ineligible inventory is an expected
//     miss, not a parity signal — the streak is neither grown nor reset).
//   - svcBest > 0 (hit)   ⇒ streak resets to 0 and the one-shot WARN re-arms.
//   - zero hit, non-empty ⇒ streak++; at streak == N WARN once ([KV_ZEROHIT]
//
// transition edge, shape); at streak >= N increment the counter on
//
//	EVERY occurrence (100 consecutive zero-hits at N=50 ⇒ 1 WARN, 51
//	counter increments — streaks 50..100 inclusive).
func kvZeroHitWatchdog(svcID uint32, svc *kvServiceState, hadInv bool, svcBest, invBlocks int) {
	if !hadInv {
		return
	}
	n := kvZeroHitN()
	svc.mu.Lock()
	if svcBest > 0 {
		svc.zeroHitStreak = 0
		svc.zeroHitWarned = false // re-arm the one-shot WARN
		svc.mu.Unlock()
		return
	}
	svc.zeroHitStreak++
	streak := svc.zeroHitStreak
	fire := streak >= n
	warnEdge := fire && !svc.zeroHitWarned
	if fire {
		svc.zeroHitWarned = true
	}
	svc.mu.Unlock()
	if !fire {
		return
	}
	if warnEdge {
		log.Warnf("[KV_ZEROHIT] service %d: %d consecutive KV-exact lookups scored ZERO hits against a non-empty inventory (%d eligible blocks) — probable cause: kvBlockSize/page-size mismatch or hash-algo drift; Tier-1.5 is effectively OFF for this service",
			svcID, streak, invBlocks)
	}
	kvZeroHitCounterFn(svcID)
}

// kvSvcScanInventories scans the target services' inventories for one Tier-1.5
// lookup and returns the pure overlap-argmax winner plus the load-aware
// candidate sets. Extracted verbatim from llb_ai_kv_best_worker
// kvSubscriberTargets helper-extraction precedent) so the
// SGL-04 service-identity filter and zero-hit watchdog are
// unit-testable without the CGO shim. svcID semantics: see kvSvcScanTargets
// (0 ⇒ legacy all-services scan; non-zero ⇒ exactly that service). On the exit
// path it evaluates kvZeroHitWatchdog once per scanned service with that
// service's OWN best score (per-service parity signal — in a legacy svcID==0
// scan another service's hit must not mask a broken service's zero-streak).
func kvSvcScanInventories(svcID uint32, goHashes []uint64,
	prefillMask, excludedMask uint32,
	loadArr, capArr, weightArr []uint32,
	loadAware, spillRelief bool) (bestEp, bestScore int, cands, fleetCands []kvCandidate, totalLoad uint64) {

	bestEp = -1

	kvServicesMu.RLock()
	defer kvServicesMu.RUnlock()

	// svcID != 0 narrows the scan to the calling rule's
	// service (single-map lookup); svcID == 0 iterates every service exactly
	// as before (the loop body below is byte-identical to the legacy path
	// modulo signal lines and the C.uint32_t→uint32 mask type).
	for _, sref := range kvSvcScanTargets(svcID) {
		svc := sref.svc
		// per-service watchdog signals, gathered over the
		// ELIGIBLE (mask-passing) inventories only — a service whose EPs are
		// all excluded/non-prefill this lookup is an expected miss.
		svcHadInv := false
		svcBest := 0
		svcInvBlocks := 0
		svc.mu.RLock()
		for epIdx, inv := range svc.inventories {
			// epIdx is the ABSOLUTE endpoint index in lBActs.endPoints
			// (matches sockproxy tepval->ep_role[] index).
			if epIdx < 0 || epIdx >= 32 {
				continue
			}
			bit := uint32(1) << uint(epIdx)
			if prefillMask&bit == 0 {
				continue // not a prefill EP — skip
			}
			if excludedMask&bit != 0 {
				continue // excluded upstream
			}
			// eligible-inventory signal for the watchdog.
			if sz := inv.Size(); sz > 0 {
				svcHadInv = true
				svcInvBlocks += sz
			}
			score := inv.MatchCount(goHashes)
			if score > svcBest {
				svcBest = score // per-service best (watchdog reset signal)
			}
			// Pure overlap-argmax (unchanged path; also the unified fallback
			// signal for outScore).
			if score > bestScore {
				bestScore = score
				bestEp = epIdx
			}
			if loadAware && (score > 0 || spillRelief) {
				// read loxilb's OWN per-EP load+cap from
				// the passed pd_ep_loads arrays by absolute epIdx (bounds-
				// checked) — NOT the dead workerMetrics scraper. This is what
				// gives the hard/soft selector real load to spill/penalize on.
				capacity, load := kvWorkerMetricsFor(epIdx, loadArr, capArr)
				// controller weight scales the effective
				// capacity BEFORE kvClampCapacity runs downstream (the ≥1
				// clamp floor means weight=0+ACTIVE degrades to the smallest
				// positive share, never zero — true removal is a STATE, not a
				// weight). weight==100 / nil weightArr are arithmetic no-ops
				// (G3). Applied here so BOTH cands and fleetCands see the
				// same scaled capacity.
				capacity = kvWeightedCapacity(capacity, kvCtrlWeightAt(weightArr, epIdx))
				if score > 0 {
					cands = append(cands, kvCandidate{
						epIdx:    epIdx,
						overlap:  score,
						capacity: capacity,
						load:     load,
					})
					totalLoad += uint64(load) // explicit candidate-set Σ active_conns (positive-overlap set only)
				}
				if spillRelief {
					// the FULL healthy-prefill fleet (overlap incl. 0) for the
					// post-selection pressure-relief pass — does NOT affect the primary
					// selection's cands/totalLoad (the tuned §0.1 law stays byte-identical).
					fleetCands = append(fleetCands, kvCandidate{
						epIdx:    epIdx,
						overlap:  score,
						capacity: capacity,
						load:     load,
					})
				}
			}
		}
		svc.mu.RUnlock()
		// the per-lookup watchdog evaluation — the exit path
		// that uniquely sees (eligible inventory non-empty) ∧ (zero hits).
		kvZeroHitWatchdog(sref.id, svc, svcHadInv, svcBest, svcInvBlocks)
	}
	return bestEp, bestScore, cands, fleetCands, totalLoad
}

// ---------- CGO Export: llb_ai_kv_best_worker ----------

// epLoad/epCap carry loxilb's OWN balancer-tracked per-EP
// live load (active_conns) and advertised capacity (num_gpu_blocks) from the C
// dataplane (tepval->pd_ep_loads[i]), indexed by the ABSOLUTE epIdx — the SAME
// index space as prefillMask/excludedMask and svc.inventories. This REPLACES the
// dead workerMetrics/workerIndexMap scraper resolution for the Tier-1.5 path
// (rules.go:3423 built the scraper with updateFn=nil, so workerMetrics stayed
// empty → the blend ran BLIND → single-EP prefill hot-spot, root cause
// a417f037). nEpSlots = number of valid entries in epLoad/epCap; every epIdx is
// bounds-checked against it.
//
// The selector arm is chosen by kvLbMode (LOXILB_KV_LB_MODE ∈ {off, hard,
// soft}, with the legacy LOXILB_KV_UNIFIED_MODE mapping for back-compat):
//   - off  — pure overlap-argmax (the blind A/B baseline). Candidates are NOT
//     collected; the path is byte-identical to the W3 baseline.
//   - hard — capacity-weighted CHWBL bounded-load cap + negligible-cache
//     refinement (kvUnifiedSelect), fed loxilb's own active_conns.
//   - soft — continuous penalty-score blend (kvSoftBlendSelect).
//
// svcID threads the calling rule's identity across the CGO
// seam (tepval->kv_svc_id, stamped from the rule number at proxy_add_entry).
// Non-zero ⇒ score ONLY that rule's inventories (kvSvcScanTargets single-map
// lookup — the cross-VIP contamination fix, RESEARCH). Zero ⇒ the
// legacy all-services loop, VERBATIM (independently default-off). Twin-lockstep
// discipline: this signature, the C prototype (sockproxy_ai_gw.h) and the C
// call site (sockproxy_kv_exact.c) change in the SAME commit.
//
// kvExactMode rides the same seam
// (tepval->kv_exact_mode). Only the single-role predicate (3) is consumed:
// it gates fleet-relief pass by default via kvSpillReliefFor
// (unset env ⇒ relief ON for single-role, OFF for P/D; explicit env wins
// globally). 0 (legacy/uninitialized) ⇒ not single-role ⇒ byte-identical
// pre-99 behavior.
//
//export llb_ai_kv_best_worker
func llb_ai_kv_best_worker(blockHashes *C.uint8_t, hashSize C.int,
	nHashes C.int, modelName *C.char,
	prefillMask C.uint32_t, excludedMask C.uint32_t,
	epLoad *C.uint32_t, epCap *C.uint32_t, epWeight *C.uint32_t,
	nEpSlots C.int, svcID C.uint32_t, kvExactMode C.uint32_t,
	outScore *C.int) C.int {

	if nHashes <= 0 || hashSize <= 0 || blockHashes == nil {
		return -1
	}

	// materialize the per-EP load/cap C arrays as Go slices once, up
	// front, nil/zero-guarded (matching the blockHashes nil guard above). A nil
	// or zero-length array degrades to (0,0) for every EP — Tier-2-safe.
	var loadArr, capArr []uint32
	if epLoad != nil && nEpSlots > 0 {
		loadArr = unsafe.Slice((*uint32)(unsafe.Pointer(epLoad)), int(nEpSlots))
	}
	if epCap != nil && nEpSlots > 0 {
		capArr = unsafe.Slice((*uint32)(unsafe.Pointer(epCap)), int(nEpSlots))
	}
	// per-EP controller weights, same nil/zero-guarded idiom.
	// The C caller passes NULL when pd_ctrl_mode==0 (controller absent) — a nil
	// weightArr reads as all-100 via kvCtrlWeightAt, the byte-identical G3 path.
	// Provenance: weights come from the C pd_ctrl_ep[] atomics (Go-applier
	// written), NOT the scraper map — the same rule that keeps load/cap on
	// loxilb's OWN pd_ep_loads (blind-blend root cause a417f037).
	var weightArr []uint32
	if epWeight != nil && nEpSlots > 0 {
		weightArr = unsafe.Slice((*uint32)(unsafe.Pointer(epWeight)), int(nEpSlots))
	}

	// Convert C block hashes to Go []uint64
	// Each hash is hash_size bytes; take first 8 bytes as big-endian uint64
	// (matches VLLM_KV_EVENTS_USE_INT_BLOCK_HASHES=1 where vLLM truncates
	// the full hash to int via int.from_bytes(hash[:8], 'big'))
	goHashes := cBlockHashesToUint64(blockHashes, int(hashSize), int(nHashes))
	if len(goHashes) == 0 {
		return -1
	}

	// the selector mode in {off, hard, soft} (kvLbMode,
	// LOXILB_KV_LB_MODE with the legacy LOXILB_KV_UNIFIED_MODE mapping). For
	// hard|soft we collect every eligible candidate's overlap + loxilb's OWN
	// per-EP capacity + live load (from the pd_ep_loads arrays) so the
	// load-aware selector can apply its cap/penalty. For "off" this slice is
	// never populated and the pure overlap-argmax below runs UNCHANGED
	// (byte-identical to the W3 baseline —).
	mode := kvLbMode()
	loadAware := mode != "off"
	// hot-prefix pressure-relief: when enabled, ALSO gather the full healthy-
	// prefill fleet (overlap incl. 0) into fleetCands for the post-selection relief pass.
	// gated per-rule — single-role (kvExactMode==3) defaults ON, P/D
	// defaults OFF; an explicit LOXILB_KV_SPILL_RELIEF env wins globally.
	spillRelief := loadAware && kvSpillReliefFor(uint32(kvExactMode) == uint32(KvExactModeSingleRole))

	// the scan itself lives in kvSvcScanInventories — a pure-Go
	// helper (helper-extraction precedent) so the service-identity filter
	// and zero-hit watchdog on its exit path are unit-testable without
	// the CGO shim. Selection semantics are a verbatim move.
	bestEp, bestScore, cands, fleetCands, totalLoad := kvSvcScanInventories(
		uint32(svcID), goHashes, uint32(prefillMask), uint32(excludedMask),
		loadArr, capArr, weightArr, loadAware, spillRelief)

	if bestEp < 0 || bestScore <= 0 {
		return -1 // Tier-1.5 miss (identical to argmax in both modes)
	}

	if outScore != nil {
		*outScore = C.int(bestScore)
	}

	if loadAware {
		// delegate to the mode-aware arm seam. hard =
		// capacity-weighted CHWBL bounded-load cap (+ negligible-cache
		// refinement); soft = continuous penalty-score blend. Either may move the
		// winner off the pure-argmax EP when that EP is loaded, fed loxilb's OWN
		// per-EP active_conns. When mode == "off" this branch is never
		// entered and bestEp above is the pure overlap-argmax, byte-identical to
		// the W3 baseline.
		// for the adaptive modes feed the per-call §0.1 load-
		// scaled ε/λ (derived from the candidate-set Σ active_conns) instead of the
		// static env knobs. For off|hard|soft keep the existing static args
		// untouched (back-compat). EWMA hysteresis (kvAdaptiveEwmaLoad) is exposed
		// and unit-tested independently; the wiring here feeds the RAW per-request
		// totalLoad to the accessors (the §0.1 anchors were calibrated on the raw
		// steadyMean Σ-inflight, and the accessors take raw L) — smoothing can be
		// layered in a later plan once re-confirm freezes coefficients.
		eps := kvMeanLoadFactor()
		lambda := kvLoadPenalty()
		if mode == "adaptive" || mode == "adaptive-soft" {
			eps = kvAdaptiveMeanLoadFactor(cands)
			lambda = kvAdaptiveLoadPenalty(cands)
		}
		// §0.1 re-confirm diagnostic: per-selection totalLoad (loxilb's TRUE
		// Σ active_conns) + the resolved ε/λ. Debug by default (SILENT in prod — the
		// hot path must not log per request at Info); promoted to Info when
		// LOXILB_KV_TLOAD_LOG=1 so the Plan-03 re-confirm can read it from docker logs
		// (logrus runs at Info, so a plain Debugf would otherwise be invisible).
		if kvAdaptiveTLoadLogEnabled() {
			log.Infof("[KV_INV] totalLoad=%d cands=%d mode=%s eps=%d lambda=%d",
				totalLoad, len(cands), mode, eps, lambda)
		} else {
			log.Debugf("[KV_INV] totalLoad=%d cands=%d mode=%s eps=%d lambda=%d",
				totalLoad, len(cands), mode, eps, lambda)
		}
		selEp, spilled := kvSelectArm(cands, mode, eps, lambda)
		if selEp >= 0 {
			bestEp = selEp
			// hot-prefix pressure-relief (LOXILB_KV_SPILL_RELIEF): if the
			// affinity selection PINNED (did not spill within its positive-overlap set)
			// to an EP that is over its FLEET-WIDE cap while a less-loaded EP exists,
			// spill to that EP. Applied post-selection over fleetCands so the tuned
			// primary cap/ε-λ math (over the positive-overlap cands) is untouched. This
			// is what relieves a hot SINGLE-cached prefix (cands=1, pins to one EP).
			if spillRelief && !spilled {
				if rEp, rSpilled := kvSpillReliefTarget(fleetCands, selEp, eps); rSpilled {
					bestEp = rEp
					spilled = true
				}
			}
			if spilled {
				// Nonzero spill counter == the load-aware selector moved off the
				// pure-overlap argmax (cap enforcement / penalty / relief fired).
				prom.IncKvTier15SpillCounter(fmt.Sprintf("%d", bestEp))
			}
		}
	}

	// bounded cold-start seeding (all modes — the starvation is
	// mode-independent): every Nth per-service hit is diverted to a healthy
	// empty-inventory prefill EP while one exists. outScore keeps the
	// DISPLACED hit's depth so the C-side guards treat the seed exactly like
	// the hit they displaced. Disable with LOXILB_KV_COLDSTART_SEED_N=0.
	if seedEp, seeded := kvColdStartSeed(uint32(svcID), uint32(prefillMask),
		uint32(excludedMask), bestEp); seeded {
		log.Infof("[KV_COLDSEED] svc=%d seeding cold ep=%d (displaced hit ep=%d score=%d)",
			uint32(svcID), seedEp, bestEp, bestScore)
		bestEp = seedEp
		kvColdSeedCounterFn(fmt.Sprintf("%d", seedEp))
	}

	// Phase K: Increment Tier-1.5 cache-hit counter (makes TK17/TK21 assert-able).
	prom.IncKvTier15HitCounter(fmt.Sprintf("%d", bestEp))

	return C.int(bestEp)
}

// kvLoadCapFromArrays reads an EP's advertised capacity + live in-flight load
// from the per-EP arrays passed across cgo by llb_ai_kv_best_worker
// Option B: loxilb's OWN tepval->pd_ep_loads[i].num_gpu_blocks / .active_conns).
// It bounds-checks epIdx against EACH slice independently and returns (0,0) for
// a nil/short array or an out-of-range index — no panic, no OOB. A
// (0,0) result is Tier-2-safe: capacity 0 clamps to 1 downstream (kvClampCapacity,
// never divide-by-zero) and load 0 reads as fully-available.
func kvLoadCapFromArrays(load, capacity []uint32, epIdx int) (capOut uint32, loadOut uint32) {
	// A nil load[] or capacity[] means Option-B plumbing delivered no per-EP
	// signal at all (e.g. the cgo arrays were not passed) — treat it as "no
	// data" and return the Tier-2-safe (0,0) rather than a half-populated
	// reading from whichever slice happens to be present. (Non-nil but short
	// slices still get independent per-index bounds-checks below.)
	if epIdx < 0 || load == nil || capacity == nil {
		return 0, 0
	}
	if epIdx < len(capacity) {
		capOut = capacity[epIdx]
	}
	if epIdx < len(load) {
		loadOut = load[epIdx]
	}
	return capOut, loadOut
}

// kvWorkerMetricsFn is the test seam llb_ai_kv_best_worker resolves per-EP
// capacity+load through. retired the dead production resolver
// (kvWorkerMetricsProd against the never-populated workerMetrics/workerIndexMap
// scraper sync.Map — rules.go built it with updateFn=nil, so it returned (0,0)
// for every EP, blind-blend root cause). The production path now reads
// loxilb's OWN pd_ep_loads via the C arrays (kvLoadCapFromArrays). The seam is
// retained (default nil) so / unit tests can override per-EP resolution
// without standing up the datapath; when nil the array reader is used.
var kvWorkerMetricsFn func(epIdx int) (capacity uint32, load uint32)

// kvWorkerMetricsFor resolves an EP's capacity+load for the Tier-1.5 candidate
// loop. If the test seam kvWorkerMetricsFn is set it wins (unit-test / Plan-02
// override); otherwise it reads the per-call pd_ep_loads arrays passed from C.
func kvWorkerMetricsFor(epIdx int, load, capacity []uint32) (capOut uint32, loadOut uint32) {
	if kvWorkerMetricsFn != nil {
		return kvWorkerMetricsFn(epIdx)
	}
	return kvLoadCapFromArrays(load, capacity, epIdx)
}

// cBlockHashesToUint64 converts C block hash bytes to Go []uint64.
// Takes first 8 bytes of each hash as big-endian uint64.
func cBlockHashesToUint64(blockHashes *C.uint8_t, hashSize int, nHashes int) []uint64 {
	if hashSize < 8 {
		return nil
	}

	totalBytes := hashSize * nHashes
	raw := unsafe.Slice((*byte)(unsafe.Pointer(blockHashes)), totalBytes)

	result := make([]uint64, nHashes)
	for i := 0; i < nHashes; i++ {
		offset := i * hashSize
		result[i] = binary.BigEndian.Uint64(raw[offset : offset+8])
	}
	return result
}

// ---------- Test Helpers ----------

// KvGetInventory returns the inventory for testing (nil if not found).
func KvGetInventory(serviceID uint32, epIdx int) *kvInventory {
	kvServicesMu.RLock()
	svc, ok := kvServices[serviceID]
	kvServicesMu.RUnlock()
	if !ok {
		return nil
	}
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	return svc.inventories[epIdx]
}

// ---------- Pure-Go ZMQ Subscriber ----------

// pureGoZmqSubscriber wraps go-zeromq/zmq4 SUB socket to implement kvZmqSubscriber.
type pureGoZmqSubscriber struct {
	ctx  context.Context
	addr string
	sub  zmq4.Socket
}

func newPureGoZmqSubscriber(ctx context.Context, addr string) *pureGoZmqSubscriber {
	return &pureGoZmqSubscriber{
		ctx:  ctx,
		addr: addr,
	}
}

func (s *pureGoZmqSubscriber) Connect(endpoint string) error {
	s.sub = zmq4.NewSub(s.ctx)
	// Subscribe to all topics BEFORE dialing (standard ZMQ convention)
	if err := s.sub.SetOption(zmq4.OptionSubscribe, ""); err != nil {
		return fmt.Errorf("zmq subscribe: %w", err)
	}
	if err := s.sub.Dial(endpoint); err != nil {
		return fmt.Errorf("zmq dial %s: %w", endpoint, err)
	}
	log.Infof("kv-subscriber: zmq connected to %s", endpoint)
	return nil
}

func (s *pureGoZmqSubscriber) RecvMultipart() ([][]byte, error) {
	msg, err := s.sub.Recv()
	if err != nil {
		return nil, err
	}
	return msg.Frames, nil
}

func (s *pureGoZmqSubscriber) Close() error {
	if s.sub != nil {
		return s.sub.Close()
	}
	return nil
}

// kvReplayPortOffset is the fixed port offset between an engine's KV-event
// PUB endpoint and its replay endpoint: PUB on port P ⇒ replay on P+offset.
// +1000 (5557 → 6557) keeps clear of SGLang data-parallel rank ports, which
// occupy P+1..P+rankCount on the PUB side. Override with
// LLB_KV_REPLAY_PORT_OFFSET; 0 disables replay entirely.
const kvReplayPortOffsetDefault = 1000

func kvReplayPortOffset() int {
	if v := os.Getenv("LLB_KV_REPLAY_PORT_OFFSET"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return kvReplayPortOffsetDefault
}

// kvReplayEndpoint derives the replay endpoint from a PUB endpoint
// ("tcp://host:port"). Returns "" when replay is disabled or the address
// cannot be parsed (caller skips replay — fail-open).
func kvReplayEndpoint(addr string) string {
	off := kvReplayPortOffset()
	if off == 0 {
		return ""
	}
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return ""
	}
	port, err := strconv.Atoi(addr[i+1:])
	if err != nil || port+off <= 0 || port+off > 65535 {
		return ""
	}
	return fmt.Sprintf("%s:%d", addr[:i], port+off)
}

// pureGoZmqReplayClient implements kvZmqReplayRequester over a DEALER socket
// against the engine publisher's ROUTER replay endpoint (vLLM
// KVEventsConfig.replay_endpoint). Wire format: request is a single 8-byte
// big-endian start sequence (preceded by the explicit empty delimiter a
// DEALER must send to a ROUTER peer); each reply is (seq, payload) frames,
// terminated by a marker whose seq is negative or whose payload is empty.
type pureGoZmqReplayClient struct {
	ctx    context.Context
	dealer zmq4.Socket
}

func newPureGoZmqReplayClient(ctx context.Context) *pureGoZmqReplayClient {
	return &pureGoZmqReplayClient{ctx: ctx}
}

func (r *pureGoZmqReplayClient) Connect(endpoint string) error {
	r.dealer = zmq4.NewDealer(r.ctx)
	if err := r.dealer.Dial(endpoint); err != nil {
		return fmt.Errorf("zmq replay dial %s: %w", endpoint, err)
	}
	return nil
}

func (r *pureGoZmqReplayClient) SendStartSeq(seq int64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(seq))
	return r.dealer.SendMulti(zmq4.NewMsgFrom([]byte{}, b[:]))
}

func (r *pureGoZmqReplayClient) RecvReplay() (int64, []byte, bool, error) {
	msg, err := r.dealer.Recv()
	if err != nil {
		return 0, nil, false, err
	}
	frames := msg.Frames
	// Strip the ROUTER-side empty delimiter when present.
	if len(frames) > 0 && len(frames[0]) == 0 {
		frames = frames[1:]
	}
	if len(frames) < 1 || len(frames[0]) < 8 {
		return 0, nil, true, nil // malformed — treat as end of replay
	}
	seq := int64(binary.BigEndian.Uint64(frames[0]))
	if seq < 0 || len(frames) < 2 || len(frames[1]) == 0 {
		return seq, nil, true, nil // end-of-replay marker
	}
	return seq, frames[1], false, nil
}

func (r *pureGoZmqReplayClient) Close() error {
	if r.dealer != nil {
		return r.dealer.Close()
	}
	return nil
}

// KvEpKey identifies one endpoint inventory (service ID and endpoint index,
// both formatted as decimal strings — the label values used on the KV gauges).
type KvEpKey struct {
	Service string
	EpIdx   string
}

// KvInventorySizes returns block counts for all active inventories, keyed by
// (service, ep_idx). Used by the Prometheus bridge.
func KvInventorySizes() map[KvEpKey]int {
	result := make(map[KvEpKey]int)
	kvServicesMu.RLock()
	defer kvServicesMu.RUnlock()
	for svcID, svc := range kvServices {
		svc.mu.RLock()
		for epIdx, inv := range svc.inventories {
			key := KvEpKey{Service: strconv.Itoa(int(svcID)), EpIdx: strconv.Itoa(int(epIdx))}
			result[key] = inv.Size()
		}
		svc.mu.RUnlock()
	}
	return result
}

// KvResetAll clears all service state (for testing).
func KvResetAll() {
	kvServicesMu.Lock()
	defer kvServicesMu.Unlock()
	for id, svc := range kvServices {
		svc.mu.Lock()
		for _, cancel := range svc.cancelFns {
			cancel()
		}
		svc.mu.Unlock()
		delete(kvServices, id)
	}
}

// kvMetricsBridgeOnce ensures only one bridge goroutine runs.
var kvMetricsBridgeOnce sync.Once

// StartKvMetricsBridge starts a background goroutine that periodically
// publishes KV inventory sizes to the loxilb_pd_kv_blocks Prometheus gauge.
// Safe to call multiple times — only the first call starts the goroutine.
func StartKvMetricsBridge(ctx context.Context) {
	kvMetricsBridgeOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					sizes := KvInventorySizes()
					for key, size := range sizes {
						prom.SetKvBlocksGauge(key.Service, key.EpIdx, float64(size))
					}
				}
			}
		}()
	})
}

// ---------- : Admin API Provider ----------

// kvInventoryProviderImpl implements handler.KvInventoryProvider so the
// REST handler (api/restapi/handler/ai_kv_inventory.go) can dump the Go-side
// KV block inventory for hash-parity audit harness.
//
// Note: block_idx in the returned response is a *synthetic sequence index*
// from Go map iteration order — it is NOT a semantic block position. The
// underlying kvInventory.blocks is map[uint64]struct{}, so tokens and
// parent_hash are not stored and are not returned. The parity
// harness sorts by hash_uint64 and does multiset (sorted-list) equality.
type kvInventoryProviderImpl struct{}

// DumpKvInventory returns the KV block inventory for (serviceID, epIdx).
// Returns (nil, false) when the service or endpoint is unknown so the
// handler can emit HTTP 404. An empty but registered inventory returns
// (resp, true) with resp.Blocks=[] and resp.Total=0.
func (p *kvInventoryProviderImpl) DumpKvInventory(serviceID uint32, epIdx int) (*handler.KvInventoryResponse, bool) {
	kvServicesMu.RLock()
	svc, ok := kvServices[serviceID]
	algo := ""
	if ok {
		algo = svc.algo
	}
	kvServicesMu.RUnlock()
	if !ok {
		return nil, false
	}

	svc.mu.RLock()
	inv, ok := svc.inventories[epIdx]
	svc.mu.RUnlock()
	if !ok {
		return nil, false
	}

	// Default algo is sha256_cbor, vLLM v0.17.0's own default. Empty only
	// happens when the subscriber started without algo propagated — harmless
	// for parity tests because the harness also defaults when the field is
	// missing, but we surface our best guess here so the Admin API response
	// is self-describing.
	if algo == "" {
		algo = "sha256_cbor"
	}

	resp := &handler.KvInventoryResponse{
		ServiceID: serviceID,
		EpIdx:     epIdx,
		HashAlgo:  algo,
		// TRT-LLM /server_info admission verdict for this EP — "" (omitted)
		// for ZMQ engines and for gates that haven't reached a first
		// /server_info answer; "admitted..." or a refusal reason otherwise.
		// This is the operator's "why is Tier-1.5 off for this EP" answer.
		Admission: kvTrtllmAdmissionVerdict(serviceID, epIdx),
		Blocks:    make([]handler.KvInventoryBlock, 0),
	}

	inv.mu.RLock()
	idx := 0
	for h := range inv.blocks {
		resp.Blocks = append(resp.Blocks, handler.KvInventoryBlock{
			BlockIdx:   idx,
			HashUint64: h,
		})
		idx++
	}
	resp.Total = idx
	inv.mu.RUnlock()

	return resp, true
}

// RegisterKvInventoryProvider wires Admin API provider into the
// REST handler. Called from loxinet.go at init time, matching the placement
// of handler.SetDpuDebugProvider.
func RegisterKvInventoryProvider() {
	handler.SetKvInventoryProvider(&kvInventoryProviderImpl{})
}
