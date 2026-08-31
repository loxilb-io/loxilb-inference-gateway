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

// ai_kv_attest_hasher_test.go — pins the challenge hasher
// (DpKvComputeChallengeHashes → C kv_compute_block_hashes) to the shared
// cross-language fixture vectors: the echo challenge's expected chain MUST
// be byte-identical to what the tier15 data plane computes, or the
// challenge would agree with itself while disagreeing with production.

import (
	"strings"
	"testing"
)

// TestKvChallengeHasherMatchesFixtureVectors: every sha256_cbor fixture with
// a ZERO parent (a chain's first block) must reproduce through the CGO
// challenge hasher with blockSize == len(tokens).
func TestKvChallengeHasherMatchesFixtureVectors(t *testing.T) {
	fixtures := loadHashFixtures(t)
	ran := 0
	for _, fx := range fixtures.Fixtures {
		if fx.HashAlgo != "sha256_cbor" {
			continue
		}
		if strings.Trim(fx.ParentHashHex, "0") != "" {
			continue // chained-parent vectors need the full-sequence form below
		}
		if len(fx.Tokens) == 0 {
			continue
		}
		tokens := make([]uint32, len(fx.Tokens))
		for i, tok := range fx.Tokens {
			tokens[i] = uint32(tok)
		}
		got, ok := DpKvComputeChallengeHashes("sha256_cbor", uint32(len(tokens)), tokens)
		if !ok || len(got) != 1 {
			t.Fatalf("fixture %s: hasher returned ok=%v n=%d", fx.Name, ok, len(got))
		}
		if got[0] != fx.ExpectedHashUint64 {
			t.Fatalf("fixture %s: hash %d != expected %d — challenge chain has drifted from the data-plane implementation",
				fx.Name, got[0], fx.ExpectedHashUint64)
		}
		ran++
	}
	if ran == 0 {
		t.Skip("no zero-parent sha256_cbor fixtures in the shared JSON file")
	}
}

// TestKvChallengeHasherChains: a 2-block sequence chains (block 2's hash
// depends on block 1), and the uint64 forms are the big-endian first 8
// digest bytes — the same rule cBlockHashesToUint64 applies to C emissions.
func TestKvChallengeHasherChains(t *testing.T) {
	tokens := []uint32{1, 2, 3, 4, 5, 6, 7, 8}
	h2, ok := DpKvComputeChallengeHashes("sha256_cbor", 4, tokens)
	if !ok || len(h2) != 2 {
		t.Fatalf("hasher: ok=%v n=%d", ok, len(h2))
	}
	// Recompute block 1 alone: must equal the sequence's first hash.
	h1, ok := DpKvComputeChallengeHashes("sha256_cbor", 4, tokens[:4])
	if !ok || len(h1) != 1 || h1[0] != h2[0] {
		t.Fatalf("first-block hash unstable: %v vs %v", h1, h2)
	}
	// Different first block ⇒ different SECOND hash (chaining).
	tokens2 := append([]uint32{9, 9, 9, 9}, tokens[4:]...)
	h3, ok := DpKvComputeChallengeHashes("sha256_cbor", 4, tokens2)
	if !ok || len(h3) != 2 {
		t.Fatalf("hasher: ok=%v n=%d", ok, len(h3))
	}
	if h3[1] == h2[1] {
		t.Fatalf("second block's hash ignored its parent — chain broken")
	}
	// Partial trailing block is never hashed.
	hp, ok := DpKvComputeChallengeHashes("sha256_cbor", 4, tokens[:6])
	if !ok || len(hp) != 1 {
		t.Fatalf("partial block hashed: n=%d", len(hp))
	}
}
