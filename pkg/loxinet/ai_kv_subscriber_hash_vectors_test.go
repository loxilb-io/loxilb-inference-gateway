// SPDX-License-Identifier: Apache-2.0
//
// ai_kv_subscriber_hash_vectors_test.go — Go-side guard for the KV-hash
// uint64 truncation semantics used by cBlockHashesToUint64 in combination
// with the loxilb-C 44-04 output layout.
//
// Source of truth: cicd/common/kv_hash/fixtures/kv_hash_vectors.json
// (computed from vLLM v0.17.0 BlockHasher.hash_block_with_parent +
// maybe_convert_block_hash reference — kv_cache_utils.py:71-74). Shared
// with C (test_kv_exact) and Python (kv_hash_parity.py) to guarantee
// single-fixture/three-layer regression gate.
//
// The Go layer NEVER hashes — it only decodes raw bytes from the C emit
// buffer (or the ZMQ wire) into uint64 via binary.BigEndian on the first
// 8 bytes of each stride-aligned slot. Post-44-04 the C side writes the
// LOW 64 bits of the full digest (digest[-8:] BE) into those 8 bytes
// to match vLLM's maybe_convert_block_hash:
//
//     hash_u64 == int.from_bytes(digest, 'big') & ((1 << 64) - 1)
//              == int.from_bytes(digest[-8:], 'big')
//
// This test reconstructs the digest from cbor_hex → sha256, slices the
// LAST 8 bytes, and asserts the BE uint64 of that slice equals the
// fixture's expected_hash_uint64. xxhash fixtures are skipped here (Go
// has no xxhash dep; the C test covers that path).

package loxinet

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type hashFixture struct {
	Name               string `json:"name"`
	HashAlgo           string `json:"hash_algo"`
	ParentHashHex      string `json:"parent_hash_hex"`
	Tokens             []int  `json:"tokens"`
	CborHex            string `json:"cbor_hex"`
	ExpectedDigestHex  string `json:"expected_digest_hex"`
	ExpectedHashUint64 uint64 `json:"expected_hash_uint64"`
}

type hashFixtureFile struct {
	Fixtures []hashFixture `json:"fixtures"`
}

// loadHashFixtures resolves the shared JSON fixture relative to this file.
// pkg/loxinet/ai_kv_subscriber_hash_vectors_test.go → ../../cicd/...
// Cleanly skips (not fails) if the fixture is missing — keeps this test
// harmless on checkouts without the testbed dir.
func loadHashFixtures(t *testing.T) *hashFixtureFile {
	t.Helper()
	wd, _ := os.Getwd()
	path := filepath.Join(wd, "..", "..", "cicd", "common", "kv_hash",
		"fixtures", "kv_hash_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s: %v", path, err)
	}
	var f hashFixtureFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(f.Fixtures) == 0 {
		t.Fatal("fixture file has zero entries")
	}
	return &f
}

// TestHashVectors_BigEndianTruncation_SHA256 asserts that reconstructing the
// SHA256 digest of each fixture's CBOR payload, taking the LAST 8 bytes, and
// interpreting them as a big-endian uint64 yields the fixture's recorded
// expected_hash_uint64. This is the exact semantic that cBlockHashesToUint64
// receives after the 44-04 C-side fix: the C layer writes digest[-8:] into
// the first 8 bytes of each stride-aligned slot, and Go reads those 8 bytes
// as BE uint64.
//
// Pre-44-04 this test asserted on digest[:8] BE — which silently disagreed
// with vLLM's maybe_convert_block_hash publisher contract (kv_cache_utils.py
// :71-74) and caused TK27 parity to fail with 0% inventory overlap.
func TestHashVectors_BigEndianTruncation_SHA256(t *testing.T) {
	f := loadHashFixtures(t)
	matched := 0
	for _, fx := range f.Fixtures {
		if fx.HashAlgo != "sha256_cbor" {
			continue
		}
		fx := fx // capture for subtest
		t.Run(fx.Name, func(t *testing.T) {
			cbor, err := hex.DecodeString(fx.CborHex)
			if err != nil {
				t.Fatalf("bad cbor_hex: %v", err)
			}
			digest := sha256.Sum256(cbor)
			// Cross-check: the fixture's recorded expected_digest_hex must match
			// what we recompute (guards against fixture corruption).
			if got := hex.EncodeToString(digest[:]); got != fx.ExpectedDigestHex {
				t.Fatalf("digest mismatch: recomputed=%s fixture=%s", got, fx.ExpectedDigestHex)
			}
			// vLLM maybe_convert_block_hash semantic: low 64 bits of the full
			// digest, big-endian — equivalently BE(digest[-8:]).
			got := binary.BigEndian.Uint64(digest[len(digest)-8:])
			if got != fx.ExpectedHashUint64 {
				t.Errorf("algo=%s fixture=%s: got 0x%016x, want 0x%016x",
					fx.HashAlgo, fx.Name, got, fx.ExpectedHashUint64)
			}
			matched++
		})
	}
	if matched == 0 {
		t.Skip("no sha256_cbor fixtures in the shared JSON file")
	}
}

// ==========================================================================
// SGLang parity vectors — int64→uint64 contract.
//
// SGLang publishes hash_str_to_int64 values: SIGNED int64 of the FIRST 16
// hex chars of the block digest (== FIRST 8 digest bytes big-endian — NOT
// vLLM's last-8 slice; the TK27 drift class inverted). The wire carries the
// signed value; Go's extractBlockHashes casts int64→uint64 bit-preserving;
// the C KV_HASH_SHA256_SGLANG arm computes the identical uint64 from the
// request tokens (memcpy of digest[0..7], read BE). This test pins the
// cross-language contract end-to-end on the SAME committed constants the C
// side asserts (test_kv_exact.c): published int64 → uint64 == C first-8-BE.
// ==========================================================================

type sglangHashVector struct {
	name      string
	blockSize int
	published []int64
	expected  []uint64
}

// ==== SGLang parity vectors (SGL-02) ====
// regenerated by scripts/compute_sglang_hash_refs.py from sglang d8ef76682e — do not hand-edit
// source of record: python/sglang/srt/mem_cache/cpp_utils/hash_binding.cpp @ d8ef76682e
var sglangHashVectors = []sglangHashVector{
	{
		name:      "single_block_bs16_noparent",
		blockSize: 16,
		published: []int64{5512803222912486454},
		expected:  []uint64{0x4c816952ba53cc36},
	},
	{
		name:      "chain3_bs16",
		blockSize: 16,
		published: []int64{8635429971592222890, 1256577331724852459, 5689809685380680247},
		expected:  []uint64{0x77d735ce838418aa, 0x1170426cf2449ceb, 0x4ef643c350b14a37},
	},
	{
		name:      "le_teeth_bs16",
		blockSize: 16,
		published: []int64{4839613804615831846},
		expected:  []uint64{0x4329c31d2a341126},
	},
	{
		name:      "negative_int64_bs16",
		blockSize: 16,
		published: []int64{-2360060374177730597},
		expected:  []uint64{0xdf3f619804a92fdb},
	},
	{
		name:      "chain2_bs32",
		blockSize: 32,
		published: []int64{476924988540955187, -5051416816229475950},
		expected:  []uint64{0x069e60c00e7daa33, 0xb9e5c32b50351992},
	},
}

// TestKvSGLangHashVectors_Int64ToUint64 feeds each vector's SIGNED published
// values through extractBlockHashes exactly as a decoded SGLang KV-event
// batch would arrive (msgpack ints decode to int64), and asserts the stored
// uint64s equal the C-side first-8-BE reference values. The negative-int64
// vectors are the signed-wrap teeth: uint64(int64(2360060374177730597)) must
// be exactly 0xdf3f619804a92fdb, or Tier-1.5 silently never intersects.
func TestKvSGLangHashVectors_Int64ToUint64(t *testing.T) {
	if len(sglangHashVectors) < 5 {
		t.Fatalf("committed SGLang vector set shrank: %d < 5", len(sglangHashVectors))
	}
	sawNegative := false
	sawBs32 := false
	for _, v := range sglangHashVectors {
		v := v // capture for subtest
		if v.blockSize == 32 {
			sawBs32 = true
		}
		t.Run(v.name, func(t *testing.T) {
			if len(v.published) != len(v.expected) {
				t.Fatalf("vector corrupt: %d published vs %d expected",
					len(v.published), len(v.expected))
			}
			raw := make([]interface{}, len(v.published))
			for i, p := range v.published {
				if p < 0 {
					sawNegative = true
				}
				raw[i] = p // int64 — the msgpack decode type for wire ints
			}
			got, err := extractBlockHashes(raw)
			if err != nil {
				t.Fatalf("extractBlockHashes: %v", err)
			}
			if len(got) != len(v.expected) {
				t.Fatalf("got %d hashes, want %d", len(got), len(v.expected))
			}
			for i := range got {
				if got[i] != v.expected[i] {
					t.Errorf("blk %d: got 0x%016x, want 0x%016x (published %d)",
						i, got[i], v.expected[i], v.published[i])
				}
			}
		})
	}
	if !sawNegative {
		t.Error("vector set lost its negative-int64 signed-wrap teeth")
	}
	if !sawBs32 {
		t.Error("vector set lost its block-size-32 coverage")
	}
}
