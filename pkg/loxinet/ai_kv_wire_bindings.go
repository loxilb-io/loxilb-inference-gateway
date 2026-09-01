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

// ai_kv_wire_bindings.go — contract-aware KV event wire bindings.
//
// A wire binding is the decoder for one declared event wire schema
// (engine-contracts/contracts.yaml, bindings.wireSchemas). The subscriber
// loop resolves its binding through the compiled engine-contract registry
// and consumes kvWireBatch values; it never inspects payload bytes itself.
//
// Two decode disciplines coexist deliberately:
//
//   - The LEGACY tagged-array binding (vllm-kv-tagged-array-v1, and its
//     rank-aware SGLang sibling) keeps the shipped skip-and-continue
//     semantics for malformed events — existing deployments keep byte-
//     identical behavior — with ONE addition: an event that decodes as a
//     msgpack MAP is the tagged-map wire family arriving on an array
//     binding (engine upgraded past its declared contract). That exact
//     mismatch used to be silently skipped at debug level, leaving a
//     healthy-looking but permanently stale inventory; it now returns a
//     typed schema-mismatch error and is counted.
//
//   - The NATIVE tagged-map binding (vllm-kv-tagged-map-v2) is strict and
//     batch-atomic: any invalid event rejects the whole batch and applies
//     nothing (the accepted batch-error policy for native profiles).
//
// The TensorRT-LLM JSON binding lives with its transport in
// ai_kv_trtllm_source.go (it is stateful — engine-hash translation chain);
// this file owns its resolution ID.

import (
	"fmt"

	"github.com/loxilb-io/loxilb/pkg/enginecontract"
	log "github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
)

// Wire binding IDs. These mirror engine-contracts/contracts.yaml — the
// registry parity test pins every ID here to a compiled profile.
const (
	KvWireVllmArrayV1  = "vllm-kv-tagged-array-v1"
	KvWireVllmMapV2    = "vllm-kv-tagged-map-v2"
	KvWireSglangRankV1 = "sglang-kv-tagged-array-rank-v1"
	KvWireTrtllmJSONV1 = "trtllm-kv-json-v1"
)

// Wire rejection reasons — the bounded label set of
// loxilb_kv_subscriber_wire_reject_total{reason}.
const (
	KvWireReasonSchemaMismatch = "schema_mismatch"
	KvWireReasonDecodeError    = "decode_error"
	KvWireReasonRankMismatch   = "rank_mismatch"
)

// kvWireError is a typed wire-level rejection. Reason is one of the
// KvWireReason* constants (bounded — it becomes a metric label).
type kvWireError struct {
	Reason string
	msg    string
}

func (e *kvWireError) Error() string { return e.msg }

func kvWireErrf(reason, format string, args ...interface{}) *kvWireError {
	return &kvWireError{Reason: reason, msg: fmt.Sprintf(format, args...)}
}

// kvWireBatch is one decoded event batch. DPRank carries the batch's
// data-parallel rank when the wire declares one (nil otherwise); the
// SGLang binding's consumer cross-checks it against the socket's rank.
type kvWireBatch struct {
	Events []kvEvent
	DPRank *int64
}

// kvWireDecoder decodes one wire payload into a batch. Implementations may
// be stateful per source (the TRT translation chain); the subscriber loop
// owns exactly one decoder instance per (EP, rank) stream.
type kvWireDecoder interface {
	Decode(payload []byte) (kvWireBatch, error)
}

type kvWireDecoderFunc func(payload []byte) (kvWireBatch, error)

func (f kvWireDecoderFunc) Decode(payload []byte) (kvWireBatch, error) { return f(payload) }

// kvWireDecoderFor builds the decoder instance for a wire schema ID.
// blockSize parameterizes the stateful TRT translation. Unknown schemas
// fail closed — the caller must not start a subscriber it cannot decode
// for.
func kvWireDecoderFor(wireSchema string, blockSize int) (kvWireDecoder, error) {
	switch wireSchema {
	case KvWireVllmArrayV1, KvWireSglangRankV1:
		return kvWireDecoderFunc(kvWireDecodeArrayV1), nil
	case KvWireVllmMapV2:
		return kvWireDecoderFunc(kvWireDecodeMapV2), nil
	case KvWireTrtllmJSONV1:
		return newTrtllmWireDecoder(blockSize), nil
	default:
		return nil, fmt.Errorf("kv-wire: unknown wire schema %q", wireSchema)
	}
}

// kvLegacyWireProfile maps a legacy engine string (the flat kvEngineType
// field) to the compiled contract profile that preserves today's shipped
// behavior. This is the explicit legacy policy table: notably, "vllm"
// stays on the tagged-ARRAY profile even though the registry's family
// default is the map family — flipping legacy rules onto the native map
// decoder is a migration-epic decision, not a side effect of this layer.
// Strict rules that carry a resolved contract reference bind their wire
// schema through that reference instead (kvResolveWireSchema).
var kvLegacyWireProfile = map[string]string{
	"":       "vllm-kv-array-v1",
	"vllm":   "vllm-kv-array-v1",
	"sglang": "sglang-kv-rank-v1",
	"trtllm": "trtllm-kv-http-v1",
}

// kvResolveWireSchema resolves the wire schema for a subscriber stream
// through the compiled engine-contract registry. A rule whose composed
// binding carries a contract reference binds its wire schema THROUGH that
// reference — a strict vllm rule bound to the native map profile must get
// the map decoder, or every native event is rejected as schema_mismatch
// and the rule can never attest (observed live against the v0.28.0 wire).
// Only profile-less rules take the legacy policy table, which preserves
// shipped behavior per engine (vllm stays tagged-ARRAY until the migration
// epic). Unknown engines/contracts fail closed (admission already rejects
// them; this is the last line).
func kvResolveWireSchema(engine, contractID string) (string, error) {
	profID := contractID
	if profID == "" {
		legacyID, ok := kvLegacyWireProfile[engine]
		if !ok {
			return "", fmt.Errorf("kv-wire: no contract profile for engine %q", engine)
		}
		profID = legacyID
	}
	prof, ok := enginecontract.ProfileByID(profID)
	if !ok {
		return "", fmt.Errorf("kv-wire: compiled registry is missing profile %q", profID)
	}
	if prof.WireSchema == "none" {
		return "", fmt.Errorf("kv-wire: profile %q declares no event wire schema", profID)
	}
	return prof.WireSchema, nil
}

// ---------- tagged-array binding (legacy family) ----------

// kvWireDecodeArrayV1 decodes a msgpack KVEventBatch in the tagged-array
// family: outer array [ts, events, dp_rank], each event a tagged array
// [tag, ...fields]. Malformed events keep the shipped skip semantics —
// EXCEPT a map-shaped event, which is the tagged-map family on the wrong
// binding and returns a typed schema mismatch (never a silent skip).
func kvWireDecodeArrayV1(payload []byte) (kvWireBatch, error) {
	var raw []interface{}
	if err := msgpack.Unmarshal(payload, &raw); err != nil {
		return kvWireBatch{}, kvWireErrf(KvWireReasonDecodeError, "msgpack unmarshal: %v", err)
	}
	if len(raw) < 2 {
		return kvWireBatch{}, kvWireErrf(KvWireReasonDecodeError, "batch too short: %d elements", len(raw))
	}
	eventsRaw, ok := raw[1].([]interface{})
	if !ok {
		return kvWireBatch{}, kvWireErrf(KvWireReasonDecodeError, "events field not array")
	}
	batch := kvWireBatch{DPRank: kvWireDecodeRank(raw)}
	for _, evRaw := range eventsRaw {
		if kvWireEventIsMap(evRaw) {
			return kvWireBatch{}, kvWireErrf(KvWireReasonSchemaMismatch,
				"tagged-map event on the tagged-array binding — engine wire family is newer than the bound contract")
		}
		ev, err := decodeKVEvent(evRaw)
		if err != nil {
			log.Debugf("kv-subscriber: skip event: %v", err)
			continue
		}
		batch.Events = append(batch.Events, ev)
	}
	return batch, nil
}

func kvWireEventIsMap(raw interface{}) bool {
	switch raw.(type) {
	case map[string]interface{}, map[interface{}]interface{}:
		return true
	}
	return false
}

// kvWireDecodeRank extracts the batch's optional data_parallel_rank
// (outer array index 2; the batch struct omits defaults, so a two-element
// batch simply has no rank claim).
func kvWireDecodeRank(raw []interface{}) *int64 {
	if len(raw) < 3 || raw[2] == nil {
		return nil
	}
	var r int64
	switch t := raw[2].(type) {
	case int8:
		r = int64(t)
	case int16:
		r = int64(t)
	case int32:
		r = int64(t)
	case int64:
		r = t
	case uint8:
		r = int64(t)
	case uint16:
		r = int64(t)
	case uint32:
		r = int64(t)
	case uint64:
		r = int64(t)
	default:
		return nil
	}
	return &r
}

// ---------- tagged-map binding (native, v0.24.0+) ----------

// kvWireDecodeMapV2 decodes a msgpack KVEventBatch in the tagged-map
// family: outer array [ts, events, dp_rank] (the batch stayed array-like
// upstream — only the per-event representation changed), each event a map
// keyed by field name with the tag under "type". Strict and batch-atomic:
// any invalid event — including an array-shaped event (the OLD family on
// the map binding) or an unknown tag — rejects the whole batch.
func kvWireDecodeMapV2(payload []byte) (kvWireBatch, error) {
	var raw []interface{}
	if err := msgpack.Unmarshal(payload, &raw); err != nil {
		return kvWireBatch{}, kvWireErrf(KvWireReasonDecodeError, "msgpack unmarshal: %v", err)
	}
	if len(raw) < 2 {
		return kvWireBatch{}, kvWireErrf(KvWireReasonDecodeError, "batch too short: %d elements", len(raw))
	}
	eventsRaw, ok := raw[1].([]interface{})
	if !ok {
		return kvWireBatch{}, kvWireErrf(KvWireReasonDecodeError, "events field not array")
	}
	batch := kvWireBatch{DPRank: kvWireDecodeRank(raw)}
	for i, evRaw := range eventsRaw {
		ev, err := kvWireDecodeMapEvent(evRaw)
		if err != nil {
			// Reject the whole batch: partial application of a batch the
			// binding cannot fully decode is exactly the silent-staleness
			// class this decoder exists to close.
			return kvWireBatch{}, kvWireErrf(kvWireReasonOf(err), "event %d: %v", i, err)
		}
		batch.Events = append(batch.Events, ev)
	}
	return batch, nil
}

func kvWireReasonOf(err error) string {
	if we, ok := err.(*kvWireError); ok {
		return we.Reason
	}
	return KvWireReasonDecodeError
}

func kvWireDecodeMapEvent(raw interface{}) (kvEvent, error) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		if m2, ok2 := raw.(map[interface{}]interface{}); ok2 {
			m = make(map[string]interface{}, len(m2))
			for k, v := range m2 {
				ks, ok3 := k.(string)
				if !ok3 {
					return kvEvent{}, kvWireErrf(KvWireReasonDecodeError, "non-string map key")
				}
				m[ks] = v
			}
		} else if _, isArr := raw.([]interface{}); isArr {
			return kvEvent{}, kvWireErrf(KvWireReasonSchemaMismatch,
				"tagged-array event on the tagged-map binding — engine wire family is older than the bound contract")
		} else {
			return kvEvent{}, kvWireErrf(KvWireReasonDecodeError, "event neither map nor array")
		}
	}
	tag, _ := m["type"].(string)
	switch tag {
	case "BlockStored":
		hashes, err := extractBlockHashes(m["block_hashes"])
		if err != nil {
			return kvEvent{}, kvWireErrf(KvWireReasonDecodeError, "BlockStored: %v", err)
		}
		if len(hashes) == 0 {
			return kvEvent{}, kvWireErrf(KvWireReasonDecodeError, "BlockStored: empty block_hashes")
		}
		ev := kvEvent{Type: kvEventBlockStored, Hashes: hashes}
		if tok, present := m["token_ids"]; present {
			ev.Tokens = extractTokenIDs(tok)
		}
		if v, present := m["lora_id"]; present && !kvFieldEmpty(v) {
			ev.Lora = true
		}
		if v, present := m["extra_keys"]; present && !kvPerBlockFieldEmpty(v) {
			ev.ExtraKeys = true
		}
		return ev, nil
	case "BlockRemoved":
		hashes, err := extractBlockHashes(m["block_hashes"])
		if err != nil {
			return kvEvent{}, kvWireErrf(KvWireReasonDecodeError, "BlockRemoved: %v", err)
		}
		return kvEvent{Type: kvEventBlockRemoved, Hashes: hashes}, nil
	case "AllBlocksCleared":
		return kvEvent{Type: kvEventAllBlocksCleared}, nil
	case "":
		return kvEvent{}, kvWireErrf(KvWireReasonDecodeError, "event map has no type tag")
	default:
		// The map family's selector pins exactly these event types; a new
		// tag is wire drift and must be loud, not skipped.
		return kvEvent{}, kvWireErrf(KvWireReasonSchemaMismatch, "unknown event type %q", tag)
	}
}
