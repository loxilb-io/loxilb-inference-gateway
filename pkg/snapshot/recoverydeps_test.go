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

// recoverydeps_test.go — the recovery_dependencies manifest (schema 1.4):
// capture-side construction (required-flag ownership, cert-store summary,
// determinism), restore-side validation (unknown REQUIRED type fails
// closed per FR-class "unknown required dependency"), the 1.3->1.4
// migration (must not invent a manifest), and checksum coverage.

package snapshot

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// depHooks is a mockHooks wired the way a KV-serving gateway with both
// databases configured would answer NetRecoveryDepsGet.
func depHooks() *mockHooks {
	hooks := newMockHooks()
	hooks.recoveryDeps = []cmn.RecoveryDependency{
		{Type: cmn.RecoveryDepEngineContracts, ID: "engine-contracts.loxilb.io/v1alpha1",
			Generation: "1", Digest: "sha256:aaaa"},
		{Type: cmn.RecoveryDepKvModelProfiles, ID: "/etc/loxilb/kvprofiles",
			Generation: "7", Digest: "sha256:bbbb"},
		{Type: cmn.RecoveryDepAPIKeyDB, ID: "aigw_dp_keys", Required: true},
		{Type: cmn.RecoveryDepAuthDB, ID: "aigw_mgmt", Required: true},
	}
	return hooks
}

func manifestByType(doc *Document, typ string) (cmn.RecoveryDependency, bool) {
	for _, d := range doc.RecoveryDependencies {
		if d.Type == typ {
			return d, true
		}
	}
	return cmn.RecoveryDependency{}, false
}

func TestCaptureBuildsRecoveryManifest(t *testing.T) {
	hooks := depHooks()
	hooks.kvBinds = []cmn.KvExactBindingMod{{RuleIdent: "r1", ModelProfileID: "p1"}}
	hooks.certMetas = []cmn.CertMeta{
		{CertId: "b-cert", Digest: "sha256:2222"},
		{CertId: "a-cert", Digest: "sha256:1111"},
	}

	doc, err := Capture(hooks, "v-test", "host", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if len(doc.RecoveryDependencies) != 5 {
		t.Fatalf("manifest has %d entries, want 5: %+v", len(doc.RecoveryDependencies), doc.RecoveryDependencies)
	}
	if !sort.SliceIsSorted(doc.RecoveryDependencies, func(i, j int) bool {
		a, b := doc.RecoveryDependencies[i], doc.RecoveryDependencies[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.ID < b.ID
	}) {
		t.Fatalf("manifest not sorted by (type, id): %+v", doc.RecoveryDependencies)
	}

	// Bindings captured -> both registries are required.
	for _, typ := range []string{cmn.RecoveryDepEngineContracts, cmn.RecoveryDepKvModelProfiles} {
		d, ok := manifestByType(doc, typ)
		if !ok {
			t.Fatalf("manifest lacks %s", typ)
		}
		if !d.Required {
			t.Errorf("%s not required despite captured kvexactbinding entries", typ)
		}
	}
	// The producer's own required flags survive untouched.
	for _, typ := range []string{cmn.RecoveryDepAPIKeyDB, cmn.RecoveryDepAuthDB} {
		if d, ok := manifestByType(doc, typ); !ok || !d.Required {
			t.Errorf("%s entry missing or lost its producer-set required flag: %+v ok=%v", typ, d, ok)
		}
	}
	// Cert domain captured -> summary entry, digest independent of the
	// enumeration order the mock returned (NormalizeDomains sorts, and
	// certSetDigest sorts again on its own).
	d, ok := manifestByType(doc, cmn.RecoveryDepCertStore)
	if !ok || !d.Required {
		t.Fatalf("cert-store entry missing or not required: %+v ok=%v", d, ok)
	}
	want := certSetDigest([]cmn.CertMeta{
		{CertId: "a-cert", Digest: "sha256:1111"},
		{CertId: "b-cert", Digest: "sha256:2222"},
	})
	if d.Digest != want {
		t.Fatalf("cert-store digest %q, want order-independent %q", d.Digest, want)
	}
	if !strings.HasPrefix(d.Digest, "sha256:") {
		t.Fatalf("cert-store digest lacks algorithm prefix: %q", d.Digest)
	}
}

func TestCaptureManifestWithoutBindingsOrCerts(t *testing.T) {
	hooks := depHooks()

	doc, err := Capture(hooks, "v-test", "host", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	// No bindings captured -> the registries are recorded (identity is a
	// process fact) but not required.
	for _, typ := range []string{cmn.RecoveryDepEngineContracts, cmn.RecoveryDepKvModelProfiles} {
		d, ok := manifestByType(doc, typ)
		if !ok {
			t.Fatalf("manifest lacks %s", typ)
		}
		if d.Required {
			t.Errorf("%s required despite no captured kvexactbinding entries", typ)
		}
	}
	// No certs captured -> no cert-store summary.
	if d, ok := manifestByType(doc, cmn.RecoveryDepCertStore); ok {
		t.Fatalf("cert-store entry present without captured certs: %+v", d)
	}
}

// A components-filtered capture that excludes kvexactbinding must not mark
// the registries required off content it never read.
func TestCaptureFilteredManifestRequiredness(t *testing.T) {
	hooks := depHooks()
	hooks.kvBinds = []cmn.KvExactBindingMod{{RuleIdent: "r1", ModelProfileID: "p1"}}

	doc, err := Capture(hooks, "v-test", "host", TriggerManual, []string{DomainEndpoint})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	d, ok := manifestByType(doc, cmn.RecoveryDepEngineContracts)
	if !ok {
		t.Fatalf("manifest lacks engine-contracts")
	}
	if d.Required {
		t.Fatalf("engine-contracts required in a capture that excluded kvexactbinding")
	}
}

func TestCaptureFailsWhenDepsUnavailable(t *testing.T) {
	hooks := depHooks()
	hooks.failOn = map[string]error{"NetRecoveryDepsGet": errors.New("store identity unavailable")}

	if _, err := Capture(hooks, "v-test", "host", TriggerManual, nil); err == nil {
		t.Fatalf("Capture succeeded with unavailable dependency identities -- would have recorded a dishonest manifest")
	}
}

func TestValidateManifest(t *testing.T) {
	base := func() *Document {
		doc := sampleDocument()
		return doc
	}

	t.Run("known types pass", func(t *testing.T) {
		doc := base()
		if compatible, errs := stageValidate(doc); !compatible || len(errs) > 0 {
			t.Fatalf("sampleDocument manifest failed validation: compatible=%v errs=%v", compatible, errs)
		}
	})

	t.Run("unknown required type fails closed", func(t *testing.T) {
		doc := base()
		doc.RecoveryDependencies = append(doc.RecoveryDependencies,
			cmn.RecoveryDependency{Type: "quantum-ledger", Required: true})
		compatible, errs := stageValidate(doc)
		if !compatible {
			t.Fatalf("schema gate tripped instead of the manifest check")
		}
		if len(errs) == 0 || !strings.Contains(errs[0], "unknown type") {
			t.Fatalf("unknown REQUIRED dependency type not refused: %v", errs)
		}
	})

	t.Run("unknown optional type tolerated", func(t *testing.T) {
		doc := base()
		doc.RecoveryDependencies = append(doc.RecoveryDependencies,
			cmn.RecoveryDependency{Type: "quantum-ledger", Required: false})
		if compatible, errs := stageValidate(doc); !compatible || len(errs) > 0 {
			t.Fatalf("unknown OPTIONAL dependency type refused: compatible=%v errs=%v", compatible, errs)
		}
	})

	t.Run("empty type refused", func(t *testing.T) {
		doc := base()
		doc.RecoveryDependencies = append(doc.RecoveryDependencies, cmn.RecoveryDependency{})
		if _, errs := stageValidate(doc); len(errs) == 0 {
			t.Fatalf("empty dependency type passed validation")
		}
	})

	t.Run("duplicate (type,id) refused", func(t *testing.T) {
		doc := base()
		doc.RecoveryDependencies = append(doc.RecoveryDependencies, doc.RecoveryDependencies[0])
		if _, errs := stageValidate(doc); len(errs) == 0 {
			t.Fatalf("duplicate dependency entry passed validation")
		}
	})

	t.Run("nil manifest valid", func(t *testing.T) {
		doc := base()
		doc.RecoveryDependencies = nil
		if compatible, errs := stageValidate(doc); !compatible || len(errs) > 0 {
			t.Fatalf("nil manifest refused: compatible=%v errs=%v", compatible, errs)
		}
	})
}

// The 1.3->1.4 migration restamps only: a document captured by a build
// that never recorded dependency identities must not gain an invented
// manifest.
func TestMigration13To14KeepsManifestAbsent(t *testing.T) {
	doc := sampleDocument()
	doc.SchemaVersion = "1.3"
	doc.RecoveryDependencies = nil
	if err := ApplyMigrations(doc); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("migration chain stopped at %q, want %q", doc.SchemaVersion, SchemaVersion)
	}
	if doc.RecoveryDependencies != nil {
		t.Fatalf("migration invented a manifest: %+v", doc.RecoveryDependencies)
	}
}

// The manifest is inside the document checksum: post-encode tampering with
// a dependency's identity must fail verification like any domain edit.
func TestManifestIsChecksumCovered(t *testing.T) {
	doc := sampleDocument()
	enc, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	tampered := bytes.Replace(enc, []byte(`"generation":"1"`), []byte(`"generation":"9"`), 1)
	if bytes.Equal(tampered, enc) {
		t.Fatalf("fixture lost the generation field this test tampers with")
	}
	got, err := Decode(bytes.NewReader(tampered))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := VerifyChecksum(got); err == nil {
		t.Fatalf("tampered recovery_dependencies passed checksum verification")
	}
}

// ---------------------------------------------------------------------
// Restore-side: stageVerifyDeps (dependency verification before PLAN)
// ---------------------------------------------------------------------

// capturedRaw builds an encoded document from a fully wired source
// gateway: required db entries, required registries (bindings present)
// and a cert-store entry.
func capturedRaw(t *testing.T) []byte {
	t.Helper()
	src := depHooks()
	src.kvBinds = []cmn.KvExactBindingMod{{RuleIdent: "r1", ModelProfileID: "p1"}}
	src.certMetas = []cmn.CertMeta{{CertId: "edge", Digest: "sha256:1111"}}
	doc, err := Capture(src, "v-test", "src-host", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return raw
}

func TestRestoreFailsClosedOnMissingRequiredDep(t *testing.T) {
	raw := capturedRaw(t)
	hooks := newMockHooks()
	hooks.depVerifyFail = map[string]error{
		cmn.RecoveryDepAuthDB: errors.New("user service is not enabled on this node"),
	}
	e := newTestEngine(hooks, t.TempDir())

	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result == ResultOK {
		t.Fatalf("restore succeeded with a missing required dependency")
	}
	found := false
	for _, msg := range res.Errors {
		if strings.Contains(msg, "dependency auth-db") {
			found = true
		}
	}
	if !found {
		t.Fatalf("errors do not name the failing dependency: %v", res.Errors)
	}
	// Fail closed means fail BEFORE anything is planned, wiped or
	// applied: the only hook traffic allowed is the verification itself.
	for _, call := range hooks.Calls {
		if !strings.HasPrefix(call, "NetRecoveryDepVerify:") {
			t.Fatalf("hook %q ran after a dependency verification failure (must stop before PLAN): all=%v", call, hooks.Calls)
		}
	}
}

func TestRestoreDepWarningDoesNotBlock(t *testing.T) {
	raw := capturedRaw(t)
	hooks := newMockHooks()
	hooks.depVerifyWarn = map[string]string{
		cmn.RecoveryDepEngineContracts: "captured under an older generation",
	}
	e := newTestEngine(hooks, t.TempDir())

	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result != ResultOK {
		t.Fatalf("degraded-store warning blocked the restore: %+v", res)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "dependency engine-contracts") && strings.Contains(w, "older generation") {
			found = true
		}
	}
	if !found {
		t.Fatalf("dependency warning not surfaced: %v", res.Warnings)
	}
}

func TestRestoreVerifiesOnlyRequiredDeps(t *testing.T) {
	src := depHooks()
	doc, err := Capture(src, "v-test", "src-host", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	// No bindings captured -> registries are optional entries; add an
	// unknown OPTIONAL type on top (VALIDATE tolerates it, and verify
	// must never be asked about it).
	doc.RecoveryDependencies = append(doc.RecoveryDependencies,
		cmn.RecoveryDependency{Type: "quantum-ledger", Required: false})
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	hooks := newMockHooks()
	e := newTestEngine(hooks, t.TempDir())
	res, rerr := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if rerr != nil || res.Result != ResultOK {
		t.Fatalf("restore failed: err=%v res=%+v", rerr, res)
	}
	verified := map[string]bool{}
	for _, call := range hooks.Calls {
		if strings.HasPrefix(call, "NetRecoveryDepVerify:") {
			verified[strings.TrimPrefix(call, "NetRecoveryDepVerify:")] = true
		}
	}
	for _, typ := range []string{cmn.RecoveryDepAPIKeyDB, cmn.RecoveryDepAuthDB} {
		if !verified[typ] {
			t.Errorf("required dependency %s was never verified", typ)
		}
	}
	for _, typ := range []string{cmn.RecoveryDepEngineContracts, cmn.RecoveryDepKvModelProfiles, "quantum-ledger"} {
		if verified[typ] {
			t.Errorf("optional dependency %s was verified (informational entries must not gate)", typ)
		}
	}
}

func TestDryRunVerifiesDeps(t *testing.T) {
	raw := capturedRaw(t)
	hooks := newMockHooks()
	hooks.depVerifyFail = map[string]error{
		cmn.RecoveryDepAPIKeyDB: errors.New("no api-key store configured"),
	}
	e := newTestEngine(hooks, t.TempDir())

	res, err := e.Restore(raw, RestoreOptions{Mode: ModeDryRun})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Result == ResultOK || len(res.Errors) == 0 {
		t.Fatalf("dry-run did not preflight dependency verification: %+v", res)
	}
}
