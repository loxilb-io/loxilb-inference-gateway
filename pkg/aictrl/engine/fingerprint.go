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

// fingerprint.go: config-fingerprint library (TTFT-01).
// Canonical serialization + SHA-256 identity hash for a per-EP calibration
// configuration, plus field-wise verification against the live-discovered
// subset (semantics: mismatch ⇒ report-only record; the CALLER falls
// back to serving_throughput_prior — availability/eligibility never changes
// in this library).
//
// Like the rest of package engine it must build and test with CGO_ENABLED=0
// on darwin: stdlib only here (crypto/sha256 — never a hand-rolled or
// third-party hash, security V6), no logging, no metrics (report-only
// contract; the binary owns the WARN log and the
// aictrl_fingerprint_mismatch_total counter).

package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Canonical field names of fingerprint tuple. The calibration
// harness and the controller's live verify both key on
// these EXACT strings — never restate the literals at a call site.
const (
	FpGpuSku       = "gpu_sku"
	FpModelID      = "model_id"
	FpMaxModelLen  = "max_model_len"
	FpVllmImage    = "vllm_image"
	FpBlockSize    = "block_size"
	FpNumGpuBlocks = "num_gpu_blocks"
	FpRole         = "role"
	FpKvConnector  = "kv_connector"
)

// FingerprintHash computes config-fingerprint over the given
// fields: keys sorted bytewise, serialized as `key=value` lines joined by
// LF with NO trailing newline (UTF-8), then hex(sha256(serialized))[:16]
// — 16 lowercase hex chars (64 bits: a config-identity key, not a
// cryptographic commitment; the explicit fields stay in the YAML as the
// auditable record).
func FingerprintHash(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys) // bytewise: sort.Strings is a byte-lexicographic sort
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+"="+fields[k])
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// FieldMismatch is one fingerprint-field disagreement between a host's
// committed calibration declaration and the live-discovered configuration.
// It is a REPORT record only: this library never logs, never counts, never
// touches eligibility — the binary logs the WARN and increments
// aictrl_fingerprint_mismatch_total; the consumer's ONLY reaction is the
// fallback to serving_throughput_prior.
type FieldMismatch struct {
	IP         string // host the calibration belongs to
	Field      string // canonical field name (Fp* consts)
	Expected   string // value in calibration.fingerprint_fields ("" if absent)
	Discovered string // live-discovered value
}

// VerifyFingerprint compares decl.FingerprintFields against the
// live-discovered subset, field-wise, over ONLY the keys present in
// discovered — the live-discoverable fields per the RQ2 verification split
// (num_gpu_blocks, block_size, model_id, and max_model_len when available).
// Non-discoverable fields (vllm_image, gpu_sku, kv_connector, role via SSH)
// are harness-verified at calibration time and are simply not passed here.
//
// Nil/empty decl, empty decl.FingerprintFields, or empty discovered map ⇒
// nil result: nothing to verify is NOT a mismatch (the caller then treats
// the calibration as unverified and stays on the prior).
//
// Results are ordered by field name (deterministic for tests and stable
// WARN output). Report-only: see FieldMismatch.
func VerifyFingerprint(ip string, decl *CalibrationDecl, discovered map[string]string) []FieldMismatch {
	if decl == nil || len(decl.FingerprintFields) == 0 || len(discovered) == 0 {
		return nil
	}
	keys := make([]string, 0, len(discovered))
	for k := range discovered {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []FieldMismatch
	for _, k := range keys {
		expected := decl.FingerprintFields[k] // "" when the decl lacks the key
		if expected != discovered[k] {
			out = append(out, FieldMismatch{
				IP:         ip,
				Field:      k,
				Expected:   expected,
				Discovered: discovered[k],
			})
		}
	}
	return out
}
