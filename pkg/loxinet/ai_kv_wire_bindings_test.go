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

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/enginecontract"
	ecschema "github.com/loxilb-io/loxilb/pkg/enginecontract/schema"
	"github.com/vmihailenco/msgpack/v5"
)

// ---------- fixtures ----------

func kvWireMustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := msgpack.Marshal(v)
	if err != nil {
		t.Fatalf("msgpack marshal: %v", err)
	}
	return data
}

// kvWireBatchFixture builds the outer KVEventBatch array [ts, events, dp_rank].
func kvWireBatchFixture(dpRank interface{}, events ...interface{}) []interface{} {
	return []interface{}{1234567890.0, events, dpRank}
}

// kvWireMapStored builds a tagged-map BlockStored event with the full
// upstream v0.28.0 key set (block_hashes, parent_block_hash, token_ids,
// block_size, lora_id, medium, lora_name).
func kvWireMapStored(hashes []interface{}, tokens []interface{}) map[string]interface{} {
	return map[string]interface{}{
		"type":              "BlockStored",
		"block_hashes":      hashes,
		"parent_block_hash": nil,
		"token_ids":         tokens,
		"block_size":        int64(16),
		"lora_id":           nil,
		"medium":            nil,
		"lora_name":         nil,
	}
}

func kvWireAsWireErr(t *testing.T, err error, wantReason string) *kvWireError {
	t.Helper()
	if err == nil {
		t.Fatal("expected a wire error, got nil")
	}
	we, ok := err.(*kvWireError)
	if !ok {
		t.Fatalf("error is %T, want *kvWireError: %v", err, err)
	}
	if we.Reason != wantReason {
		t.Fatalf("wire reason = %q, want %q (err: %v)", we.Reason, wantReason, err)
	}
	return we
}

// ---------- tagged-map (native v2) decode ----------

func TestKvWireMapV2DecodeBlockStored(t *testing.T) {
	payload := kvWireMustMarshal(t, kvWireBatchFixture(nil,
		kvWireMapStored(
			[]interface{}{int64(42), int64(43)},
			[]interface{}{int64(7), int64(8), int64(9)},
		),
	))

	batch, err := kvWireDecodeMapV2(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(batch.Events))
	}
	ev := batch.Events[0]
	if ev.Type != kvEventBlockStored {
		t.Errorf("event type = %d, want BlockStored", ev.Type)
	}
	if len(ev.Hashes) != 2 || ev.Hashes[0] != 42 || ev.Hashes[1] != 43 {
		t.Errorf("hashes = %v, want [42 43]", ev.Hashes)
	}
	if len(ev.Tokens) != 3 || ev.Tokens[0] != 7 || ev.Tokens[2] != 9 {
		t.Errorf("tokens = %v, want [7 8 9]", ev.Tokens)
	}
	if ev.Lora || ev.ExtraKeys {
		t.Errorf("lora=%v extraKeys=%v, want false/false for nil fields", ev.Lora, ev.ExtraKeys)
	}
}

func TestKvWireMapV2LoraAndExtraKeys(t *testing.T) {
	stored := kvWireMapStored([]interface{}{int64(1)}, nil)
	stored["lora_id"] = int64(5)
	stored["extra_keys"] = map[string]interface{}{"mm_hash": "abc"}
	payload := kvWireMustMarshal(t, kvWireBatchFixture(nil, stored))

	batch, err := kvWireDecodeMapV2(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(batch.Events))
	}
	if !batch.Events[0].Lora {
		t.Error("lora_id=5 must set Lora")
	}
	if !batch.Events[0].ExtraKeys {
		t.Error("non-empty extra_keys must set ExtraKeys")
	}
}

func TestKvWireMapV2DecodeRemovedAndCleared(t *testing.T) {
	payload := kvWireMustMarshal(t, kvWireBatchFixture(nil,
		map[string]interface{}{"type": "BlockRemoved", "block_hashes": []interface{}{int64(42)}, "medium": nil},
		map[string]interface{}{"type": "AllBlocksCleared"},
	))

	batch, err := kvWireDecodeMapV2(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(batch.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(batch.Events))
	}
	if batch.Events[0].Type != kvEventBlockRemoved || batch.Events[0].Hashes[0] != 42 {
		t.Errorf("event 0 = %+v, want BlockRemoved [42]", batch.Events[0])
	}
	if batch.Events[1].Type != kvEventAllBlocksCleared {
		t.Errorf("event 1 type = %d, want AllBlocksCleared", batch.Events[1].Type)
	}
}

// One invalid event must reject the WHOLE batch: zero events applied, not a
// partial prefix (silent-staleness class the native binding exists to close).
func TestKvWireMapV2BatchAtomicity(t *testing.T) {
	payload := kvWireMustMarshal(t, kvWireBatchFixture(nil,
		kvWireMapStored([]interface{}{int64(1)}, nil),                                  // good
		map[string]interface{}{"type": "BlockStored", "block_hashes": []interface{}{}}, // bad: empty hashes
		kvWireMapStored([]interface{}{int64(2)}, nil),                                  // good, after the bad one
	))

	batch, err := kvWireDecodeMapV2(payload)
	kvWireAsWireErr(t, err, KvWireReasonDecodeError)
	if len(batch.Events) != 0 {
		t.Fatalf("batch-atomicity violated: %d events survived a rejected batch", len(batch.Events))
	}
}

// Cross-family detection, direction 1: an array-shaped event arriving on the
// tagged-map binding is the OLD wire family — typed schema mismatch.
func TestKvWireMapV2ArrayEventRejected(t *testing.T) {
	payload := kvWireMustMarshal(t, kvWireBatchFixture(nil,
		[]interface{}{"BlockStored", []interface{}{int64(42)}, int64(0)},
	))

	batch, err := kvWireDecodeMapV2(payload)
	kvWireAsWireErr(t, err, KvWireReasonSchemaMismatch)
	if len(batch.Events) != 0 {
		t.Fatalf("%d events survived a schema-mismatch batch", len(batch.Events))
	}
}

// Cross-family detection, direction 2: a map-shaped event arriving on the
// tagged-array binding is the NEW wire family — typed schema mismatch, never
// the legacy silent skip (that skip is the silent-stale-inventory defect).
func TestKvWireArrayV1MapEventRejected(t *testing.T) {
	payload := kvWireMustMarshal(t, kvWireBatchFixture(nil,
		[]interface{}{"BlockStored", []interface{}{int64(41)}, int64(0)}, // good array event first
		kvWireMapStored([]interface{}{int64(42)}, nil),                   // map event ⇒ reject
	))

	batch, err := kvWireDecodeArrayV1(payload)
	kvWireAsWireErr(t, err, KvWireReasonSchemaMismatch)
	if len(batch.Events) != 0 {
		t.Fatalf("%d events survived a schema-mismatch batch", len(batch.Events))
	}
}

// The legacy skip semantics themselves must survive: a malformed ARRAY event
// (not a family mismatch) is skipped and the rest of the batch applies.
func TestKvWireArrayV1MalformedEventStillSkips(t *testing.T) {
	payload := kvWireMustMarshal(t, kvWireBatchFixture(nil,
		[]interface{}{int64(99)}, // tag not a string ⇒ shipped skip semantics
		[]interface{}{"BlockStored", []interface{}{int64(42)}, int64(0)},
	))

	batch, err := kvWireDecodeArrayV1(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(batch.Events) != 1 || batch.Events[0].Hashes[0] != 42 {
		t.Fatalf("events = %+v, want the single good BlockStored", batch.Events)
	}
}

func TestKvWireMapV2UnknownTagRejected(t *testing.T) {
	payload := kvWireMustMarshal(t, kvWireBatchFixture(nil,
		map[string]interface{}{"type": "BlockUpgraded", "block_hashes": []interface{}{int64(1)}},
	))

	_, err := kvWireDecodeMapV2(payload)
	kvWireAsWireErr(t, err, KvWireReasonSchemaMismatch)
}

func TestKvWireMapV2MissingTypeTag(t *testing.T) {
	payload := kvWireMustMarshal(t, kvWireBatchFixture(nil,
		map[string]interface{}{"block_hashes": []interface{}{int64(1)}},
	))

	_, err := kvWireDecodeMapV2(payload)
	kvWireAsWireErr(t, err, KvWireReasonDecodeError)
}

func TestKvWireMapV2GarbagePayload(t *testing.T) {
	_, err := kvWireDecodeMapV2([]byte{0xc1, 0xff, 0x00})
	kvWireAsWireErr(t, err, KvWireReasonDecodeError)
}

// ---------- dp_rank extraction ----------

func TestKvWireDPRankExtraction(t *testing.T) {
	stored := kvWireMapStored([]interface{}{int64(1)}, nil)

	withRank := kvWireMustMarshal(t, kvWireBatchFixture(int64(3), stored))
	batch, err := kvWireDecodeMapV2(withRank)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if batch.DPRank == nil || *batch.DPRank != 3 {
		t.Fatalf("DPRank = %v, want 3", batch.DPRank)
	}

	arrEv := []interface{}{"BlockStored", []interface{}{int64(1)}, int64(0)}
	arrWithRank := kvWireMustMarshal(t, kvWireBatchFixture(int64(2), arrEv))
	batch, err = kvWireDecodeArrayV1(arrWithRank)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if batch.DPRank == nil || *batch.DPRank != 2 {
		t.Fatalf("array DPRank = %v, want 2", batch.DPRank)
	}

	nilRank := kvWireMustMarshal(t, kvWireBatchFixture(nil, stored))
	batch, err = kvWireDecodeMapV2(nilRank)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if batch.DPRank != nil {
		t.Fatalf("DPRank = %v, want nil for nil wire rank", *batch.DPRank)
	}

	twoEl := kvWireMustMarshal(t, []interface{}{1234567890.0, []interface{}{stored}})
	batch, err = kvWireDecodeMapV2(twoEl)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if batch.DPRank != nil {
		t.Fatalf("DPRank = %v, want nil for a two-element batch", *batch.DPRank)
	}
}

// ---------- decoder / schema resolution ----------

func TestKvWireDecoderForUnknownFails(t *testing.T) {
	if _, err := kvWireDecoderFor("no-such-wire-schema", 16); err == nil {
		t.Fatal("unknown wire schema must fail closed")
	}
	for _, ws := range []string{KvWireVllmArrayV1, KvWireVllmMapV2, KvWireSglangRankV1, KvWireTrtllmJSONV1} {
		if _, err := kvWireDecoderFor(ws, 16); err != nil {
			t.Errorf("declared wire schema %q has no decoder: %v", ws, err)
		}
	}
}

// The KvWire* binding IDs and the legacy policy table must stay pinned to
// the compiled engine-contract registry: every legacy profile exists, its
// declared wire schema is one this file can decode, and the vllm legacy
// entry stays on the ARRAY family (the map flip is a migration-epic
// decision, not a side effect).
func TestKvWireLegacyProfilePins(t *testing.T) {
	wantSchema := map[string]string{
		"":       KvWireVllmArrayV1,
		"vllm":   KvWireVllmArrayV1,
		"sglang": KvWireSglangRankV1,
		"trtllm": KvWireTrtllmJSONV1,
	}
	for engine, want := range wantSchema {
		got, err := kvResolveWireSchema(engine)
		if err != nil {
			t.Errorf("engine %q: %v", engine, err)
			continue
		}
		if got != want {
			t.Errorf("engine %q wire schema = %q, want %q", engine, got, want)
		}
	}
	for engine, profID := range kvLegacyWireProfile {
		prof, ok := enginecontract.ProfileByID(profID)
		if !ok {
			t.Errorf("legacy profile %q (engine %q) missing from compiled registry", profID, engine)
			continue
		}
		if _, err := kvWireDecoderFor(prof.WireSchema, 16); err != nil {
			t.Errorf("legacy profile %q declares undecodable wire schema %q", profID, prof.WireSchema)
		}
	}
	// Engines without an event plane, or unknown engines, must fail closed.
	for _, engine := range []string{"llamacpp", "bogus-engine"} {
		if _, err := kvResolveWireSchema(engine); err == nil {
			t.Errorf("engine %q must not resolve a wire schema", engine)
		}
	}
}

// KvWire* constants mirror contracts.yaml through the compiled registry —
// registry parity for every profile that declares an event wire schema.
func TestKvWireConstRegistryParity(t *testing.T) {
	wantWire := map[string]string{
		"vllm-kv-array-v1":          KvWireVllmArrayV1,
		"vllm-kv-map-v2":            KvWireVllmMapV2,
		"sglang-kv-rank-v1":         KvWireSglangRankV1,
		"trtllm-kv-http-v1":         KvWireTrtllmJSONV1,
		"trtllm-kv-http-preview-v1": KvWireTrtllmJSONV1,
	}
	seen := 0
	for i := range enginecontract.Profiles {
		p := &enginecontract.Profiles[i]
		want, pinned := wantWire[p.ID]
		if p.WireSchema == "none" {
			if pinned {
				t.Errorf("profile %q pinned here but declares no wire schema", p.ID)
			}
			continue
		}
		seen++
		if !pinned {
			t.Errorf("profile %q declares wire schema %q but has no KvWire* pin in this test", p.ID, p.WireSchema)
			continue
		}
		if p.WireSchema != want {
			t.Errorf("profile %q wire schema = %q, want %q", p.ID, p.WireSchema, want)
		}
	}
	if seen == 0 {
		t.Fatal("no event-wire profiles in the compiled registry — parity test is vacuous")
	}
}

// ---------- SGLang rank gate (loop-level) ----------

// TestKvSubscriberSglangRankGate drives the binding-aware subscriber loop on
// the rank-aware SGLang binding: a batch whose declared dp_rank disagrees
// with the stream's socket-derived rank must never reach the inventory,
// while the matching-rank batch on the same stream applies normally.
func TestKvSubscriberSglangRankGate(t *testing.T) {
	inv := newKvInventory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mismatch := kvWireMustMarshal(t, kvWireBatchFixture(int64(0),
		[]interface{}{"BlockStored", []interface{}{int64(111)}, int64(0)}))
	match := kvWireMustMarshal(t, kvWireBatchFixture(int64(1),
		[]interface{}{"BlockStored", []interface{}{int64(222)}, int64(0)}))

	fake := &fakeKvSub{t: t, steps: []recvStep{
		{frames: kvFrames(1, mismatch)},
		{frames: kvFrames(2, match), cancel: true},
	}, cancel: cancel}

	done := make(chan struct{})
	go func() {
		runKvSubscriberLoopBinding(ctx, 0, 1, 77, inv, fake, nil, "inproc://rank-gate-test",
			KvWireSglangRankV1, 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("subscriber loop did not exit — possible wedge")
	}

	if inv.MatchCount([]uint64{111}) != 0 {
		t.Fatal("mismatched-rank batch was applied — the rank gate is dead")
	}
	if inv.MatchCount([]uint64{222}) != 1 {
		t.Fatal("matching-rank batch was not applied")
	}
}

// ---------- compiled contract-source adapter ----------

func TestKvCompiledContractSourceCurrentRef(t *testing.T) {
	src := kvCompiledContractSource{}

	ref, err := src.CurrentRef("vllm")
	if err != nil {
		t.Fatalf("CurrentRef(vllm): %v", err)
	}
	if ref.ID != "vllm-kv-map-v2" || ref.Gen != enginecontract.Generation {
		t.Fatalf("CurrentRef(vllm) = %+v, want vllm-kv-map-v2@%d", ref, enginecontract.Generation)
	}

	// Absent engine string resolves through kvEngineEffective to vllm.
	refEmpty, err := src.CurrentRef("")
	if err != nil {
		t.Fatalf("CurrentRef(\"\"): %v", err)
	}
	if refEmpty != ref {
		t.Fatalf("CurrentRef(\"\") = %+v, want the vllm default %+v", refEmpty, ref)
	}

	// llamacpp has no family default (no KV contract) — fail closed.
	if _, err := src.CurrentRef("llamacpp"); err == nil {
		t.Fatal("CurrentRef(llamacpp) must fail closed")
	}
	if _, err := src.CurrentRef("bogus-engine"); err == nil {
		t.Fatal("CurrentRef(bogus-engine) must fail closed")
	}
}

func TestKvCompiledContractSourceResolveDigest(t *testing.T) {
	src := kvCompiledContractSource{}

	ref, err := src.CurrentRef("vllm")
	if err != nil {
		t.Fatalf("CurrentRef(vllm): %v", err)
	}
	d, err := src.ResolveDigest(ref)
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if want := enginecontract.ProfileDigests[ref.ID]; d != want || d == "" {
		t.Fatalf("digest = %q, want %q", d, want)
	}

	// A reference minted against another manifest generation never resolves.
	stale := KvEngineContractRef{ID: ref.ID, Gen: ref.Gen + 1}
	if _, err := src.ResolveDigest(stale); err == nil {
		t.Fatal("stale-generation reference must fail closed")
	}

	unknown := KvEngineContractRef{ID: "no-such-profile", Gen: enginecontract.Generation}
	if _, err := src.ResolveDigest(unknown); err == nil {
		t.Fatal("unknown-profile reference must fail closed")
	}
}

func TestKvContractSourceInitPins(t *testing.T) {
	t.Cleanup(func() { KvRegisterEngineContractSource(nil) })
	if err := KvContractSourceInit(); err != nil {
		t.Fatalf("KvContractSourceInit against the compiled registry: %v", err)
	}
}

// ---------- llamacpp typed refusals ----------

func TestKvLlamacppGuardTypedCode(t *testing.T) {
	cases := []struct {
		name                 string
		kvExactMode          uint8
		pdDisagg             bool
		zmqPort, dpRankCount uint16
		blockSize            uint32
		wantRefusal          bool
	}{
		{name: "plain LB passes", wantRefusal: false},
		{name: "swagger defaults pass", zmqPort: 5557, blockSize: 16, dpRankCount: 1, wantRefusal: false},
		{name: "kvExactMode refused", kvExactMode: 1, wantRefusal: true},
		{name: "pdDisagg refused", pdDisagg: true, wantRefusal: true},
		{name: "zmqPort refused", zmqPort: 9999, wantRefusal: true},
		{name: "dpRankCount refused", dpRankCount: 2, wantRefusal: true},
		{name: "blockSize refused", blockSize: 32, wantRefusal: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := kvLlamacppFeatureGuard("llamacpp", tc.kvExactMode, tc.pdDisagg, tc.zmqPort, tc.dpRankCount, tc.blockSize)
			if !tc.wantRefusal {
				if err != nil {
					t.Fatalf("unexpected refusal: %v", err)
				}
				return
			}
			var ce *KvContractError
			if !errors.As(err, &ce) {
				t.Fatalf("error is %T, want *KvContractError: %v", err, err)
			}
			if ce.Code != KvReasonCapabilityUnavailable {
				t.Fatalf("code = %q, want %q", ce.Code, KvReasonCapabilityUnavailable)
			}
		})
	}

	// Non-llamacpp engines never trip the guard.
	if err := kvLlamacppFeatureGuard("vllm", 2, true, 9999, 4, 32); err != nil {
		t.Fatalf("guard fired for vllm: %v", err)
	}
}

// The refusals are the compiled profile's capability answers — the profile
// must exist and declare the two capabilities the guard consults as "none".
func TestKvLlamacppProfileCapabilities(t *testing.T) {
	p, ok := enginecontract.ProfileByID(kvLlamacppProfileID)
	if !ok {
		t.Fatalf("compiled registry is missing %q", kvLlamacppProfileID)
	}
	if p.Capabilities[ecschema.CapKvEvents] != ecschema.CapNone {
		t.Errorf("%s kvEvents = %q, want none", kvLlamacppProfileID, p.Capabilities[ecschema.CapKvEvents])
	}
	if p.Capabilities[ecschema.CapPdRouting] != ecschema.CapNone {
		t.Errorf("%s pdRouting = %q, want none", kvLlamacppProfileID, p.Capabilities[ecschema.CapPdRouting])
	}
}

// ---------- HA capability carries registry identity ----------

func TestKvLocalCapabilityRegistryConstants(t *testing.T) {
	c := kvLocalCapability()
	if c.ContractRegistryDigest != enginecontract.ManifestDigest {
		t.Errorf("ContractRegistryDigest = %q, want %q", c.ContractRegistryDigest, enginecontract.ManifestDigest)
	}
	if c.SupportCatalogDigest != enginecontract.SupportCatalogDigest {
		t.Errorf("SupportCatalogDigest = %q, want %q", c.SupportCatalogDigest, enginecontract.SupportCatalogDigest)
	}
	if c.ContractSchemaVer != enginecontract.SchemaVersion {
		t.Errorf("ContractSchemaVer = %q, want %q", c.ContractSchemaVer, enginecontract.SchemaVersion)
	}
	if c.ContractRegistryDigest == "" || c.SupportCatalogDigest == "" || c.ContractSchemaVer == "" {
		t.Error("registry identity constants must be non-empty")
	}
}
