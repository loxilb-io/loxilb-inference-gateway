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

package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validManifest is the minimal well-formed contracts fixture the invalid
// variants below are derived from by a single mutation each.
const validManifest = `
schemaVersion: engine-contracts.loxilb.io/v1alpha1
generation: 1
engineIds:
  vllm: 0
  sglang: 1
bindings:
  transports: [zmq-multipart-v1]
  wireSchemas: [vllm-kv-tagged-array-v1, vllm-kv-tagged-map-v2]
  hashBindings: [vllm-block-hash-v1]
  pdDialects: [vllm-nixl-v1]
  probes: [vllm-runtime-info-v1]
profiles:
  - id: vllm-kv-array-v1
    engine: vllm
    versions: {scheme: semver, minInclusive: v0.17.0, maxInclusive: v0.23.0}
    transport: zmq-multipart-v1
    wireSchema: vllm-kv-tagged-array-v1
    hashBinding: vllm-block-hash-v1
    pdDialect: vllm-nixl-v1
    probe: vllm-runtime-info-v1
    capabilities: {kvEvents: implemented, prefixRouting: implemented, pdRouting: implemented, runtimeProbe: implemented}
  - id: vllm-kv-map-v2
    engine: vllm
    familyDefault: true
    versions: {scheme: semver, minInclusive: v0.24.0, maxInclusive: v0.28.0}
    transport: zmq-multipart-v1
    wireSchema: vllm-kv-tagged-map-v2
    hashBinding: vllm-block-hash-v1
    pdDialect: vllm-nixl-v1
    probe: vllm-runtime-info-v1
    capabilities: {kvEvents: implemented, prefixRouting: implemented, pdRouting: implemented, runtimeProbe: implemented}
`

func mustParse(t *testing.T, doc string) *ContractsManifest {
	t.Helper()
	m, err := ParseContracts([]byte(doc))
	if err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	return m
}

func TestContractsValidRoundTrip(t *testing.T) {
	m := mustParse(t, validManifest)
	if m.Generation != 1 || len(m.Profiles) != 2 {
		t.Fatalf("unexpected parse result: gen=%d profiles=%d", m.Generation, len(m.Profiles))
	}
	if p, ok := m.FamilyDefault("vllm"); !ok || p.ID != "vllm-kv-map-v2" {
		t.Fatalf("familyDefault(vllm) = %v, %v", p, ok)
	}
	if _, ok := m.FamilyDefault("sglang"); ok {
		t.Fatalf("familyDefault(sglang) should not resolve")
	}
}

// mut applies one textual mutation to the valid fixture and asserts the
// parse fails mentioning want.
func mut(t *testing.T, old, new, want string) {
	t.Helper()
	doc := strings.Replace(validManifest, old, new, 1)
	if doc == validManifest {
		t.Fatalf("mutation anchor %q not found", old)
	}
	_, err := ParseContracts([]byte(doc))
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("mutation %q: err=%v (want containing %q)", new, err, want)
	}
}

func TestContractsInvalid(t *testing.T) {
	mut(t, "engine-contracts.loxilb.io/v1alpha1", "engine-contracts.loxilb.io/v2", "schemaVersion")
	mut(t, "generation: 1", "generation: 0", "generation")
	// Overlapping selectors: array family widened over the map family's floor.
	mut(t, "maxInclusive: v0.23.0", "maxInclusive: v0.24.0", "overlapping version selectors")
	// Dangling binding reference (first profile's hash binding).
	mut(t, "hashBinding: vllm-block-hash-v1", "hashBinding: vllm-block-hash-v9", "dangling")
	// Duplicate profile ID.
	mut(t, "id: vllm-kv-map-v2", "id: vllm-kv-array-v1", "duplicate profile ID")
	// Unknown capability key / value (first profile's capabilities line).
	mut(t, "runtimeProbe: implemented}", "runtimeProbe: implemented, teleport: implemented}", "unknown capability")
	mut(t, "runtimeProbe: implemented}", "runtimeProbe: maybe}", "unknown value")
	// Reserved vocab entry.
	mut(t, "transports: [zmq-multipart-v1]", "transports: [zmq-multipart-v1, none]", "reserved")
	// Duplicate engine wire ID.
	mut(t, "sglang: 1", "sglang: 0", "share wire ID")
	// Unknown engine in engineIds.
	mut(t, "sglang: 1", "warpdrive: 1", "unknown engine")
	// Selector shape errors.
	mut(t, "{scheme: semver, minInclusive: v0.24.0, maxInclusive: v0.28.0}",
		"{scheme: semver, minInclusive: v0.29.0, maxInclusive: v0.28.0}", "minInclusive")
	mut(t, "{scheme: semver, minInclusive: v0.24.0, maxInclusive: v0.28.0}",
		"{scheme: exact}", "exact selector requires")
	mut(t, "{scheme: semver, minInclusive: v0.24.0, maxInclusive: v0.28.0}",
		"{scheme: fuzzy, exact: v1}", "selector scheme")
	// Unknown top-level field (strict decode).
	mut(t, "generation: 1", "generation: 1\nsurprise: true", "field surprise not found")
}

func TestContractsCoherence(t *testing.T) {
	// kvEvents=none must zero the event-plane bindings.
	doc := strings.Replace(validManifest,
		"capabilities: {kvEvents: implemented, prefixRouting: implemented, pdRouting: implemented, runtimeProbe: implemented}",
		"capabilities: {kvEvents: none, prefixRouting: implemented, pdRouting: implemented, runtimeProbe: implemented}", 1)
	if _, err := ParseContracts([]byte(doc)); err == nil || !strings.Contains(err.Error(), "kvEvents=none") {
		t.Fatalf("kvEvents=none with live transport accepted: %v", err)
	}
	// pdRouting declared but engine lacks a wire ID.
	doc = strings.Replace(validManifest, "engineIds:\n  vllm: 0\n  sglang: 1", "engineIds:\n  sglang: 1", 1)
	if _, err := ParseContracts([]byte(doc)); err == nil || !strings.Contains(err.Error(), "no wire ID") {
		t.Fatalf("pd profile without engine wire ID accepted: %v", err)
	}
	// Two familyDefaults on one engine.
	doc = strings.Replace(validManifest, "id: vllm-kv-array-v1\n    engine: vllm",
		"id: vllm-kv-array-v1\n    engine: vllm\n    familyDefault: true", 1)
	if _, err := ParseContracts([]byte(doc)); err == nil || !strings.Contains(err.Error(), "two familyDefault") {
		t.Fatalf("double familyDefault accepted: %v", err)
	}
}

func TestResolveVersionDeterministic(t *testing.T) {
	m := mustParse(t, validManifest)
	for version, want := range map[string]string{
		"v0.17.0": "vllm-kv-array-v1",
		"v0.23.0": "vllm-kv-array-v1",
		"v0.24.0": "vllm-kv-map-v2",
		"v0.28.0": "vllm-kv-map-v2",
	} {
		p, err := m.ResolveVersion("vllm", version)
		if err != nil || p.ID != want {
			t.Fatalf("ResolveVersion(vllm, %s) = %v, %v (want %s)", version, p, err, want)
		}
	}
	// The gap between families and anything outside them fails closed.
	for _, version := range []string{"v0.23.1", "v0.16.9", "v0.29.0", "not-a-version"} {
		if _, err := m.ResolveVersion("vllm", version); err == nil {
			t.Fatalf("ResolveVersion(vllm, %s) resolved; want fail-closed error", version)
		}
	}
	if _, err := m.ResolveVersion("sglang", "v0.24.0"); err == nil {
		t.Fatalf("ResolveVersion(sglang, ...) resolved against vllm profiles")
	}
}

func TestSemverOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"v0.23.0", "v0.24.0", -1},
		{"1.2.3", "v1.2.3", 0},
		{"1.3.0-rc24", "1.3.0", -1},
		{"1.3.0-rc24", "1.3.0-rc25", -1},
		{"2.0.0", "1.99.99", 1},
	} {
		a, err1 := parseSemver(tc.a)
		b, err2 := parseSemver(tc.b)
		if err1 != nil || err2 != nil {
			t.Fatalf("parse %s/%s: %v %v", tc.a, tc.b, err1, err2)
		}
		if got := compareSemver(a, b); got != tc.want {
			t.Fatalf("compare(%s, %s) = %d want %d", tc.a, tc.b, got, tc.want)
		}
	}
	// Non-semver identities (the TRT preview tag) must not parse — they
	// belong in exact selectors.
	if _, err := parseSemver("1.3.0rc24"); err == nil {
		t.Fatalf("1.3.0rc24 parsed as semver; must require exact selector")
	}
	if _, err := parseSemver("1.2"); err == nil {
		t.Fatalf("two-component version parsed")
	}
}

const validCatalog = `
schemaVersion: engine-support.loxilb.io/v1alpha1
entries:
  - engine: vllm
    version: v0.24.0
    revision: ""
    gatewayRelease: v0.9.8.9-rc.1
    profile: vllm-kv-map-v2
    promotion: candidate
    capabilities:
      kvEvents:
        implementation: native
        evidence: {source: pass, fixture: pass, synthetic: not_run, realEngine: not_run}
`

func TestCatalogValidation(t *testing.T) {
	m := mustParse(t, validManifest)
	if _, err := ParseCatalog([]byte(validCatalog), m); err != nil {
		t.Fatalf("valid catalog rejected: %v", err)
	}
	catMut := func(old, new, want string) {
		t.Helper()
		doc := strings.Replace(validCatalog, old, new, 1)
		if doc == validCatalog {
			t.Fatalf("anchor %q not found", old)
		}
		_, err := ParseCatalog([]byte(doc), m)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("catalog mutation %q: err=%v (want %q)", new, err, want)
		}
	}
	catMut("profile: vllm-kv-map-v2", "profile: vllm-kv-map-v9", "unknown profile")
	catMut("version: v0.24.0", "version: v0.23.0", "outside profile")
	catMut("promotion: candidate", "promotion: shipped", "unknown promotion")
	catMut("implementation: native", "implementation: telepathic", "not in {native, adapter, none}")
	catMut("synthetic: not_run", "synthetic: skipped", "invalid")
	// implementation none demands all-n_a evidence.
	catMut("implementation: native", "implementation: none", "requires all-n_a")
	// validated without the exact tuple + bundle + real-engine pass.
	catMut("promotion: candidate", "promotion: validated", "requires an exact upstream revision")
	doc := strings.Replace(validCatalog, "promotion: candidate", "promotion: validated", 1)
	doc = strings.Replace(doc, `revision: ""`, `revision: "abcdef1234"`, 1)
	if _, err := ParseCatalog([]byte(doc), m); err == nil || !strings.Contains(err.Error(), "platformDigest") {
		t.Fatalf("validated without image digest accepted: %v", err)
	}
}

func TestCatalogNotRunNeverPasses(t *testing.T) {
	m := mustParse(t, validManifest)
	doc := strings.Replace(validCatalog, "promotion: candidate", "promotion: validated", 1)
	doc = strings.Replace(doc, `revision: ""`, `revision: "deadbeef"`, 1)
	doc = strings.Replace(doc, "capabilities:", `image:
      platformDigest: "sha256:`+strings.Repeat("ab", 32)+`"
    evidenceBundle: "evidence://x"
    capabilities:`, 1)
	// realEngine is still not_run — validated must be refused (contract gate:
	// not_run and n_a never count as pass).
	if _, err := ParseCatalog([]byte(doc), m); err == nil || !strings.Contains(err.Error(), "realEngine") {
		t.Fatalf("validated with realEngine=not_run accepted: %v", err)
	}
}

func TestObservedValidation(t *testing.T) {
	valid := `{"schemaVersion":"engine-observation.loxilb.io/v1alpha1","observedAt":"2026-08-30T00:00:00Z","releases":[{"engine":"vllm","version":"v0.28.0","releaseUrl":"https://example.invalid/r","classification":"review-required"}]}`
	if _, err := ParseObserved([]byte(valid)); err != nil {
		t.Fatalf("valid observation rejected: %v", err)
	}
	for _, tc := range []struct{ old, new, want string }{
		{"review-required", "auto-promote", "classification"},
		{"2026-08-30T00:00:00Z", "yesterday", "observedAt"},
		{`"engine":"vllm"`, `"engine":"gptx"`, "unknown engine"},
		{`"version":"v0.28.0",`, ``, "version and releaseUrl"},
	} {
		doc := strings.Replace(valid, tc.old, tc.new, 1)
		if _, err := ParseObserved([]byte(doc)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("observed mutation %q: err=%v (want %q)", tc.new, err, tc.want)
		}
	}
}

// TestRepoArtifactsValid pins the committed trust artifacts themselves:
// the shipping manifest, catalog, and observation must always parse clean
// against this validator.
func TestRepoArtifactsValid(t *testing.T) {
	root := filepath.Join("..", "..", "..", "engine-contracts")
	cb, err := os.ReadFile(filepath.Join(root, "contracts.yaml"))
	if err != nil {
		t.Fatalf("read contracts.yaml: %v", err)
	}
	m, err := ParseContracts(cb)
	if err != nil {
		t.Fatalf("repo contracts.yaml invalid: %v", err)
	}
	for _, want := range []string{"vllm-kv-array-v1", "vllm-kv-map-v2", "sglang-kv-rank-v1",
		"trtllm-kv-http-v1", "trtllm-kv-http-preview-v1", "llamacpp-nokv-v1"} {
		if _, ok := m.ProfileByID(want); !ok {
			t.Fatalf("repo contracts.yaml missing profile %q", want)
		}
	}
	// Wire IDs are ABI-frozen (DEC-008) — a renumbering must fail here
	// before it ever reaches the generated C header.
	for eng, want := range map[string]uint8{"vllm": 0, "sglang": 1, "trtllm": 2} {
		if got, ok := m.EngineIDs[eng]; !ok || got != want {
			t.Fatalf("engine %q wire ID = %d,%v (ABI-frozen at %d)", eng, got, ok, want)
		}
	}
	// The preview and stable TRT tuples must stay separate profiles.
	if p, _ := m.ProfileByID("trtllm-kv-http-preview-v1"); p.FamilyDefault {
		t.Fatalf("preview TRT profile must not be the family default")
	}
	sb, err := os.ReadFile(filepath.Join(root, "support-catalog.yaml"))
	if err != nil {
		t.Fatalf("read support-catalog.yaml: %v", err)
	}
	cat, err := ParseCatalog(sb, m)
	if err != nil {
		t.Fatalf("repo support-catalog.yaml invalid: %v", err)
	}
	// Promotion pipeline invariants: a validated tuple must have earned
	// its word through the evidence rules ParseCatalog enforces (exact
	// revision, image digest, bundle reference, real-engine passes — each
	// with its own red-path test above). Pin here that no validated entry
	// re-widens: the identity fields a promotion recorded must never be
	// blanked while the word stays validated (ParseCatalog would catch
	// blanking too; this guard keeps the intent readable at the seed).
	for _, e := range cat.Entries {
		if e.Promotion != PromotionValidated {
			continue
		}
		if e.Revision == "" || e.Image.PlatformDigest == "" || e.EvidenceBundle == "" {
			t.Fatalf("validated tuple (%s/%s) lost its promotion evidence fields", e.Engine, e.Version)
		}
	}
	ob, err := os.ReadFile(filepath.Join(root, "observed-releases.json"))
	if err != nil {
		t.Fatalf("read observed-releases.json: %v", err)
	}
	if _, err := ParseObserved(ob); err != nil {
		t.Fatalf("repo observed-releases.json invalid: %v", err)
	}
}
