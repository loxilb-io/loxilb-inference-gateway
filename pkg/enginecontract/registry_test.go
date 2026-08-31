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

package enginecontract

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/pkg/enginecontract/schema"
)

func TestCurrentRefResolution(t *testing.T) {
	for family, wantID := range map[string]string{
		"vllm":   "vllm-kv-map-v2",
		"sglang": "sglang-kv-rank-v1",
		"trtllm": "trtllm-kv-http-v1",
	} {
		ref, err := CurrentRef(family)
		if err != nil || ref.ID != wantID || ref.Gen != Generation {
			t.Fatalf("CurrentRef(%s) = %+v, %v (want %s@%d)", family, ref, err, wantID, Generation)
		}
		d, err := ResolveDigest(ref)
		if err != nil || !strings.HasPrefix(d, "sha256:") {
			t.Fatalf("ResolveDigest(%+v) = %q, %v", ref, d, err)
		}
	}
	// llamacpp has no KV contract — family resolution fails closed.
	if _, err := CurrentRef("llamacpp"); err == nil {
		t.Fatalf("CurrentRef(llamacpp) resolved; want fail-closed")
	}
	if _, err := CurrentRef("unknown-engine"); err == nil {
		t.Fatalf("CurrentRef(unknown) resolved")
	}
}

func TestResolveDigestFailsClosed(t *testing.T) {
	ref, _ := CurrentRef("vllm")
	stale := Ref{ID: ref.ID, Gen: ref.Gen + 1}
	if _, err := ResolveDigest(stale); err == nil {
		t.Fatalf("stale generation resolved")
	}
	if _, err := ResolveDigest(Ref{ID: "no-such-profile", Gen: Generation}); err == nil {
		t.Fatalf("unknown profile resolved")
	}
}

func TestResolveVersionAgainstCompiledTable(t *testing.T) {
	for _, tc := range []struct{ engine, version, want string }{
		{"vllm", "v0.23.0", "vllm-kv-array-v1"},
		{"vllm", "v0.27.1", "vllm-kv-map-v2"},
		{"trtllm", "v1.2.1", "trtllm-kv-http-v1"},
		{"trtllm", "1.3.0rc24", "trtllm-kv-http-preview-v1"},
		{"sglang", "v0.5.18", "sglang-kv-rank-v1"},
		{"llamacpp", "v0.3.0", "llamacpp-nokv-v1"},
	} {
		p, err := ResolveVersion(tc.engine, tc.version)
		if err != nil || p.ID != tc.want {
			t.Fatalf("ResolveVersion(%s, %s) = %v, %v (want %s)", tc.engine, tc.version, p, err, tc.want)
		}
	}
	// Preview evidence never back-infers the stable tuple and vice versa.
	if _, err := ResolveVersion("trtllm", "v1.2.0"); err == nil {
		t.Fatalf("unlisted TRT version resolved")
	}
}

// TestGeneratedMatchesManifest pins zz_generated_registry.go to the
// manifest: the compiled table, generation, and digest must equal a fresh
// parse of the committed contracts.yaml (the no-drift invariant CI also
// enforces via `ecgen -check`).
func TestGeneratedMatchesManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "engine-contracts", "contracts.yaml"))
	if err != nil {
		t.Fatalf("read contracts.yaml: %v", err)
	}
	m, err := schema.ParseContracts(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Generation != Generation {
		t.Fatalf("generated Generation %d != manifest %d — rerun ecgen", Generation, m.Generation)
	}
	sum := sha256.Sum256(raw)
	if ManifestDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("ManifestDigest stale — rerun ecgen")
	}
	if len(Profiles) != len(m.Profiles) {
		t.Fatalf("compiled %d profiles, manifest has %d — rerun ecgen", len(Profiles), len(m.Profiles))
	}
	for i := range Profiles {
		mp, ok := m.ProfileByID(Profiles[i].ID)
		if !ok {
			t.Fatalf("compiled profile %q not in manifest", Profiles[i].ID)
		}
		if Profiles[i].Engine != mp.Engine || Profiles[i].WireSchema != mp.WireSchema ||
			Profiles[i].Transport != mp.Transport || Profiles[i].HashBinding != mp.HashBinding ||
			Profiles[i].PDDialect != mp.PDDialect || Profiles[i].FamilyDefault != mp.FamilyDefault {
			t.Fatalf("compiled profile %q drifted from manifest — rerun ecgen", Profiles[i].ID)
		}
	}
}

// TestCHeaderParity parses the generated C header and requires the
// PD_ENGINE_* values to equal EngineWireIDs one-to-one — the Go/C
// registry-parity acceptance gate, runnable without CGO.
func TestCHeaderParity(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "loxilb-ebpf", "common", "sockproxy_pd_ids.h"))
	if err != nil {
		t.Fatalf("open generated header: %v", err)
	}
	defer f.Close()
	got := map[string]uint8{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 3 && fields[0] == "#define" && strings.HasPrefix(fields[1], "PD_ENGINE_") &&
			fields[1] != "PD_ENGINE_ID_MAX" {
			n, err := strconv.ParseUint(fields[2], 10, 8)
			if err != nil {
				t.Fatalf("header line %q: %v", sc.Text(), err)
			}
			engine := strings.ToLower(strings.TrimPrefix(fields[1], "PD_ENGINE_"))
			got[engine] = uint8(n)
		}
	}
	if len(got) != len(EngineWireIDs) {
		t.Fatalf("header declares %d engines, registry %d", len(got), len(EngineWireIDs))
	}
	for eng, id := range EngineWireIDs {
		if got[eng] != id {
			t.Fatalf("engine %q: header ID %d != registry ID %d", eng, got[eng], id)
		}
	}
	// ABI freeze: the historic hand-maintained values must never move.
	for eng, want := range map[string]uint8{"vllm": 0, "sglang": 1, "trtllm": 2} {
		if got[eng] != want {
			t.Fatalf("engine %q renumbered to %d (ABI-frozen at %d)", eng, got[eng], want)
		}
	}
}
