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

// ai_kv_profile_discovery_test.go — the discovery projection's contract:
// deterministic ordering, the documented empty state, the typed not-found,
// no host-filesystem leakage on the wire, and the discovery-is-cache /
// admission-is-authority race across a registry reload.

package loxinet

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestKvProfileDiscoveryEmpty: no published registry answers generation 0
// with an EMPTY, NON-NIL profile set — on the wire that must serialize as
// "profiles":[] (a documented legacy-mode answer), never null ("unknown").
func TestKvProfileDiscoveryEmpty(t *testing.T) {
	KvProfileRegistryReset()
	t.Cleanup(KvProfileRegistryReset)

	reg := KvProfileDiscovery()
	if reg.RegistryGeneration != 0 || reg.SetDigest != "" {
		t.Fatalf("empty registry answered gen=%d digest=%q, want 0/\"\"", reg.RegistryGeneration, reg.SetDigest)
	}
	if reg.Profiles == nil {
		t.Fatal("empty registry answered a nil profile set — [] and null are different wire answers")
	}
	js, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"profiles":[]`) {
		t.Fatalf("empty set did not serialize as []: %s", js)
	}

	if _, err := KvProfileDiscoveryByID("any"); !errors.Is(err, cmn.ErrAiModelProfileNotFound) {
		t.Fatalf("detail on empty registry = %v, want ErrAiModelProfileNotFound", err)
	}
}

// TestKvProfileDiscoveryOrderingAndContent: profiles come back ordered by
// ProfileID ascending regardless of map iteration order, each entry carries
// the envelope's generation, and the projected fields match the published
// profile document.
func TestKvProfileDiscoveryOrderingAndContent(t *testing.T) {
	root := kvRegistryTestSetup(t)
	// Deliberately created in non-lexicographic order.
	kvWriteProfileFixture(t, root, "p-zulu", "acme/disc-m3", []byte("tok-z"))
	kvWriteProfileFixture(t, root, "p-alpha", "acme/disc-m1", []byte("tok-a"), "disc-alias-1")
	kvWriteProfileFixture(t, root, "p-mike", "acme/disc-m2", []byte("tok-m"))

	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}
	g := kvProfileCurrent()

	reg := KvProfileDiscovery()
	if reg.RegistryGeneration != g.Gen {
		t.Fatalf("envelope gen %d, registry gen %d", reg.RegistryGeneration, g.Gen)
	}
	if reg.SetDigest != g.SetDigest || reg.SetDigest == "" {
		t.Fatalf("envelope digest %q, registry digest %q", reg.SetDigest, g.SetDigest)
	}
	if len(reg.Profiles) != 3 {
		t.Fatalf("got %d profiles, want 3", len(reg.Profiles))
	}
	ids := []string{reg.Profiles[0].ProfileID, reg.Profiles[1].ProfileID, reg.Profiles[2].ProfileID}
	if !sort.StringsAreSorted(ids) || ids[0] != "p-alpha" || ids[2] != "p-zulu" {
		t.Fatalf("profiles not ordered by profileId asc: %v", ids)
	}
	for _, p := range reg.Profiles {
		if p.Gen != g.Gen {
			t.Fatalf("entry %s gen %d, want envelope gen %d", p.ProfileID, p.Gen, g.Gen)
		}
		if p.TokenizerSha256 == "" {
			t.Fatalf("entry %s has no tokenizer digest — publication requires one", p.ProfileID)
		}
	}
	alpha := reg.Profiles[0]
	if alpha.BaseModel != "acme/disc-m1" || alpha.AliasPolicy != KvAliasPolicyList ||
		len(alpha.AllowedAliases) != 1 || alpha.AllowedAliases[0] != "disc-alias-1" {
		t.Fatalf("p-alpha projected wrong: %+v", alpha)
	}
	if len(alpha.SupportedApis) != 1 || alpha.SupportedApis[0] != "completions" {
		t.Fatalf("p-alpha supportedApis projected wrong: %v", alpha.SupportedApis)
	}

	// The projection must hand out copies: mutating a returned slice must
	// never reach the published (immutable, serving-path-shared) entry.
	alpha.AllowedAliases[0] = "mutated"
	if e, ok := kvProfileByID("p-alpha"); !ok || e.Profile.AllowedAliases[0] != "disc-alias-1" {
		t.Fatal("caller mutation of a discovery slice reached the published registry entry")
	}
}

// TestKvProfileDiscoveryByID: the detail lookup answers the same projection
// as the list, and an unknown id answers the typed not-found.
func TestKvProfileDiscoveryByID(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-solo", "acme/disc-solo", []byte("tok-s"))
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}

	m, err := KvProfileDiscoveryByID("p-solo")
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if m.ProfileID != "p-solo" || m.BaseModel != "acme/disc-solo" || m.Gen != kvProfileCurrent().Gen {
		t.Fatalf("detail projected wrong: %+v", m)
	}
	if _, err := KvProfileDiscoveryByID("p-ghost"); !errors.Is(err, cmn.ErrAiModelProfileNotFound) {
		t.Fatalf("unknown id = %v, want ErrAiModelProfileNotFound", err)
	}
}

// TestKvProfileDiscoveryNoArtifactLeak: the serialized discovery envelope
// must carry NO host-filesystem information — not the registry root the
// generation was loaded from, not the artifact locators the profile document
// names, not the receipt paths. The sha256 digests are the only artifact
// identities a client gets.
func TestKvProfileDiscoveryNoArtifactLeak(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-leak", "acme/disc-leak", []byte("tok-l"))
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}

	js, err := json.Marshal(KvProfileDiscovery())
	if err != nil {
		t.Fatal(err)
	}
	body := string(js)
	// The generation's source root (and with it any absolute host path).
	if strings.Contains(body, root) {
		t.Fatalf("discovery response leaks the registry root %q: %s", root, body)
	}
	// The artifact locator value (fixture pins "<slug>/tokenizer.json").
	if strings.Contains(body, "tokenizer.json") {
		t.Fatalf("discovery response leaks an artifact locator: %s", body)
	}
	// The artifact subtree receipts resolve beneath.
	if strings.Contains(body, kvProfileArtifactSubdir+"/") {
		t.Fatalf("discovery response leaks a receipt path: %s", body)
	}
	// The compiled-in default registry root.
	if strings.Contains(body, KvProfileDir) {
		t.Fatalf("discovery response leaks the default registry dir: %s", body)
	}
}

// TestKvProfileDiscoveryReloadRace: discovery is a cache, admission is the
// authority. A profile listed by discovery and then dropped by a reload must
// be REFUSED at rule admission (which reads the registry pointer current at
// POST time), and a profile published by the reload admits at the NEW
// generation — the generation a status read-back would then expose.
func TestKvProfileDiscoveryReloadRace(t *testing.T) {
	rootOld := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, rootOld, "p-old", "acme/race-m1", []byte("tok-old"))
	if err := KvProfileRegistryLoadFrom(rootOld); err != nil {
		t.Fatalf("load gen1: %v", err)
	}

	stale := KvProfileDiscovery()
	if len(stale.Profiles) != 1 || stale.Profiles[0].ProfileID != "p-old" {
		t.Fatalf("discovery before reload: %+v", stale.Profiles)
	}

	// Reload swaps the generation: p-old disappears, p-new appears.
	rootNew := t.TempDir()
	kvWriteProfileFixture(t, rootNew, "p-new", "acme/race-m2", []byte("tok-new"))
	if err := KvProfileRegistryLoadFrom(rootNew); err != nil {
		t.Fatalf("load gen2: %v", err)
	}
	fresh := KvProfileDiscovery()
	if fresh.RegistryGeneration <= stale.RegistryGeneration {
		t.Fatalf("reload did not advance the generation: %d -> %d",
			stale.RegistryGeneration, fresh.RegistryGeneration)
	}
	if fresh.SetDigest == stale.SetDigest {
		t.Fatal("reload with different content kept the set digest")
	}

	// Admission wired to the LIVE registry pointer, exactly as production
	// wires it (rules.go AddLbRule kvExactAdmissionDeps).
	liveDeps := admissionDeps(func(d *kvExactAdmissionDeps) {
		d.profileByID = func(id string) (*ModelPromptProfile, uint64, bool) {
			e, ok := kvProfileByID(id)
			if !ok {
				return nil, 0, false
			}
			return &e.Profile, e.Gen, true
		}
	})

	// The stale discovery's profile must refuse — never admit off the cache.
	_, err := kvExactRuntimeValidate("vllm", 1, "acme/race-m1", "", "p-old", liveDeps)
	if err == nil || !strings.Contains(err.Error(), "not a published") {
		t.Fatalf("stale-discovered profile p-old: got %v, want not-a-published-profile refusal", err)
	}

	// The reloaded profile admits, composed at the NEW generation.
	res, err := kvExactRuntimeValidate("vllm", 1, "acme/race-m2", "", "p-new", liveDeps)
	if err != nil {
		t.Fatalf("freshly published profile refused: %v", err)
	}
	if res.Comps.Profile.Gen != fresh.RegistryGeneration {
		t.Fatalf("admitted at gen %d, want the reloaded generation %d",
			res.Comps.Profile.Gen, fresh.RegistryGeneration)
	}
}
