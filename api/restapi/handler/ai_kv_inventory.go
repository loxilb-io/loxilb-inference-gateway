/*
 * Copyright (c) 2026 NetLOX Inc
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

// ai_kv_inventory.go — Admin API handler for KV hash parity audit.
//
// Exposes GET /netlox/v1/config/ai/kv/inventory?service_id=<id>&ep_idx=<idx>
// so the client-side parity harness can fetch per-block uint64 keys
// without scraping Prometheus. Read-only, no Swagger, no side-effects.
//
// block_idx is a *synthetic sequence index* from Go map iteration order — it is
// NOT a semantic block position. The underlying kvInventory is
// map[uint64]struct{}, so tokens and parent_hash are NOT stored and NOT returned.
// The parity harness sorts by hash_uint64 and does multiset equality.

package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	tk "github.com/loxilb-io/loxilib"
)

// KvInventoryBlock is one block entry in the AdminDumpKvInventory response.
// BlockIdx is synthetic (Go map iteration order) — not a semantic position.
type KvInventoryBlock struct {
	BlockIdx   int    `json:"block_idx"`
	HashUint64 uint64 `json:"hash_uint64"`
}

// KvInventoryResponse is the GET response for
// /netlox/v1/config/ai/kv/inventory?service_id=<id>&ep_idx=<idx>.
// HashAlgo is a top-level field (single algo per service), not repeated per-block.
type KvInventoryResponse struct {
	ServiceID uint32 `json:"service_id"`
	EpIdx     int    `json:"ep_idx"`
	HashAlgo  string `json:"hash_algo"`
	// Admission is the TRT-LLM /server_info admission verdict for this EP:
	// omitted for ZMQ engines, "admitted..." or a refusal reason otherwise.
	Admission string             `json:"admission,omitempty"`
	Blocks    []KvInventoryBlock `json:"blocks"`
	Total     int                `json:"total"`
}

// KvInventoryProvider abstracts pkg/loxinet access to avoid circular imports.
// Implemented by pkg/loxinet and registered via SetKvInventoryProvider.
type KvInventoryProvider interface {
	DumpKvInventory(serviceID uint32, epIdx int) (*KvInventoryResponse, bool)
}

var kvInventoryProvider KvInventoryProvider

// SetKvInventoryProvider registers the KV inventory provider.
// Called from pkg/loxinet during initialization.
func SetKvInventoryProvider(p KvInventoryProvider) {
	kvInventoryProvider = p
}

// HandleKvInventory handles GET /netlox/v1/config/ai/kv/inventory.
// Query params: service_id (uint32), ep_idx (int).
func HandleKvInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tk.LogIt(tk.LogTrace, "api: KV inventory GET called by IP: %s\n", r.RemoteAddr)

	if kvInventoryProvider == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "kv inventory provider not registered",
		})
		return
	}

	q := r.URL.Query()
	svcStr := q.Get("service_id")
	epStr := q.Get("ep_idx")

	svcID64, err := strconv.ParseUint(svcStr, 10, 32)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid service_id: " + err.Error(),
		})
		return
	}

	epIdx, err := strconv.Atoi(epStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid ep_idx: " + err.Error(),
		})
		return
	}

	resp, ok := kvInventoryProvider.DumpKvInventory(uint32(svcID64), epIdx)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "service or endpoint not found",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
