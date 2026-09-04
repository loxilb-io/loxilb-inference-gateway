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

package loxinet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// kvWriteProfileFixture writes one profile document plus its tokenizer
// artifact (content tok) under root, with the digest computed from the real
// bytes. aliases empty => base_model_only.
func kvWriteProfileFixture(t *testing.T, root, id, model string, tok []byte, aliases ...string) {
	t.Helper()
	slug := kvModelSlug(model)
	artDir := filepath.Join(root, kvProfileArtifactSubdir, slug)
	if err := os.MkdirAll(artDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artDir, "tokenizer.json"), tok, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tok)
	doc := fmt.Sprintf("profileId: %s\nbaseModel: %s\ntokenizerArtifact: %s/tokenizer.json\ntokenizerSha256: %s\nsupportedApis: [completions]\n",
		id, model, slug, hex.EncodeToString(sum[:]))
	if len(aliases) > 0 {
		doc += "aliasPolicy: list\nallowedAliases: ["
		for i, a := range aliases {
			if i > 0 {
				doc += ", "
			}
			doc += a
		}
		doc += "]\n"
	} else {
		doc += "aliasPolicy: base_model_only\n"
	}
	if err := os.WriteFile(filepath.Join(root, id+".yaml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

func kvRegistryTestSetup(t *testing.T) string {
	t.Helper()
	KvProfileRegistryReset()
	t.Cleanup(KvProfileRegistryReset)
	return t.TempDir()
}

// kvWriteChatProfileFixture writes one chat-declaring profile document plus
// its tokenizer and template artifacts under root, digests computed from the
// real bytes.
func kvWriteChatProfileFixture(t *testing.T, root, id, model string, tok, tpl []byte) {
	t.Helper()
	slug := kvModelSlug(model)
	artDir := filepath.Join(root, kvProfileArtifactSubdir, slug)
	if err := os.MkdirAll(artDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artDir, "tokenizer.json"), tok, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artDir, "template.jinja"), tpl, 0o644); err != nil {
		t.Fatal(err)
	}
	tokSum := sha256.Sum256(tok)
	tplSum := sha256.Sum256(tpl)
	doc := fmt.Sprintf("profileId: %s\nbaseModel: %s\n"+
		"tokenizerArtifact: %s/tokenizer.json\ntokenizerSha256: %s\n"+
		"templateArtifact: %s/template.jinja\ntemplateSha256: %s\n"+
		"templateContentFormat: string\nrenderPolicy:\n  addGenerationPrompt: true\n"+
		"supportedApis: [chat, completions]\naliasPolicy: base_model_only\n",
		id, model, slug, hex.EncodeToString(tokSum[:]), slug, hex.EncodeToString(tplSum[:]))
	if err := os.WriteFile(filepath.Join(root, id+".yaml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestKvProfileRegistryTemplateCompileGate: a digest-valid template artifact
// the executor cannot compile refuses the WHOLE generation at publish time
// (all-or-nothing), leaving the previous generation serving; the same
// profile with a compilable template publishes and reports chat support
// through the real on-disk trust path.
func TestKvProfileRegistryTemplateCompileGate(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-base", "acme/reg-base", []byte("tok-base"))
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("baseline publish: %v", err)
	}
	prevGen := kvProfileCurrent().Gen

	badRoot := t.TempDir()
	kvWriteChatProfileFixture(t, badRoot, "p-chat", "acme/reg-chat",
		[]byte("tok-chat"), []byte("{% bogus %}"))
	if err := KvProfileRegistryLoadFrom(badRoot); err == nil {
		t.Fatal("uncompilable template artifact published")
	}
	if g := kvProfileCurrent(); g == nil || g.Gen != prevGen {
		t.Fatal("failed publish must leave the previous generation serving")
	}

	goodRoot := t.TempDir()
	kvWriteChatProfileFixture(t, goodRoot, "p-chat", "acme/reg-chat",
		[]byte("tok-chat"), []byte("{{ messages[0].content }}"))
	if err := KvProfileRegistryLoadFrom(goodRoot); err != nil {
		t.Fatalf("compilable chat profile refused: %v", err)
	}
	if !kvChatTemplateSupported("acme/reg-chat") {
		t.Fatal("published chat profile must report a renderer")
	}
	if out, ok := kvRenderChatTemplate("acme/reg-chat",
		[]kvChatMessage{{Role: "user", Content: "hello-trust-path"}}); !ok || out != "hello-trust-path" {
		t.Fatalf("on-disk trust-path render wrong: ok=%v out=%q", ok, out)
	}
}

func TestKvProfileRegistryPublishAndLookup(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-one", "acme/reg-m1", []byte("tok-one"))
	kvWriteProfileFixture(t, root, "p-two", "acme/reg-m2", []byte("tok-two"), "m2-alias")

	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}
	g := kvProfileCurrent()
	if g == nil || len(g.Profiles) != 2 {
		t.Fatalf("expected 2 published profiles, got %+v", g)
	}
	if g.SetDigest == "" {
		t.Fatal("set digest empty")
	}
	e, ok := kvProfileByModel("acme/reg-m1")
	if !ok || string(e.TokenizerBytes) != "tok-one" {
		t.Fatalf("base-model lookup failed: ok=%v", ok)
	}
	if _, ok := kvProfileByModel("m2-alias"); !ok {
		t.Fatal("alias lookup failed")
	}
	if _, ok := kvProfileByModel("acme/unknown"); ok {
		t.Fatal("unknown model resolved to a profile")
	}
	if _, ok := kvProfileByID("p-two"); !ok {
		t.Fatal("id lookup failed")
	}

	// Identical reload publishes a new generation with the same set digest.
	firstGen, firstDigest := g.Gen, g.SetDigest
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("reload: %v", err)
	}
	g2 := kvProfileCurrent()
	if g2.Gen <= firstGen {
		t.Fatalf("generation did not advance: %d -> %d", firstGen, g2.Gen)
	}
	if g2.SetDigest != firstDigest {
		t.Fatalf("identical content changed set digest: %s -> %s", firstDigest, g2.SetDigest)
	}
}

// TestKvProfileRegistryFailureKeepsPreviousGeneration is the
// replace-during-reload guarantee: a failing reload must leave the previous
// generation fully serving, including its verified artifact bytes.
// TestKvProfileVerifyDiskDetectsDrift: the freshness re-read must accept an
// untouched registry, reject a flipped artifact byte with the pinned-vs-disk
// digests named, and accept the registry again once the bytes are restored.
func TestKvProfileVerifyDiskDetectsDrift(t *testing.T) {
	root := kvRegistryTestSetup(t)
	tok := []byte("tok-drift-corpus")
	kvWriteProfileFixture(t, root, "p-drift", "acme/drift-m1", tok)
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}

	if err := KvProfileVerifyDisk("p-drift"); err != nil {
		t.Fatalf("verify on untouched registry: %v", err)
	}
	if err := KvProfileVerifyDisk("p-none"); err == nil {
		t.Fatal("unknown profile must not verify")
	}

	art := filepath.Join(root, kvProfileArtifactSubdir, kvModelSlug("acme/drift-m1"), "tokenizer.json")
	drifted := append([]byte(nil), tok...)
	drifted[0] ^= 0xff
	if err := os.WriteFile(art, drifted, 0o644); err != nil {
		t.Fatal(err)
	}
	err := KvProfileVerifyDisk("p-drift")
	if err == nil {
		t.Fatal("byte-flipped artifact must fail verification")
	}
	// The loaded generation keeps serving the attested bytes meanwhile.
	if e, ok := kvProfileByID("p-drift"); !ok || string(e.TokenizerBytes) != string(tok) {
		t.Fatalf("in-memory generation changed under drift: %v", ok)
	}

	if err := os.WriteFile(art, tok, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := KvProfileVerifyDisk("p-drift"); err != nil {
		t.Fatalf("verify after restore: %v", err)
	}
}

func TestKvProfileRegistryFailureKeepsPreviousGeneration(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-keep", "acme/reg-keep", []byte("good-bytes"))
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	gBefore := kvProfileCurrent()

	// Corrupt the artifact on disk: bytes no longer match the pinned digest.
	art := filepath.Join(root, kvProfileArtifactSubdir, "acme__reg-keep", "tokenizer.json")
	if err := os.WriteFile(art, []byte("tampered!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := KvProfileRegistryLoadFrom(root)
	if err == nil {
		t.Fatal("reload with digest-mismatching artifact succeeded")
	}
	gAfter := kvProfileCurrent()
	if gAfter != gBefore {
		t.Fatal("failed reload replaced the published generation")
	}
	e, ok := kvProfileByModel("acme/reg-keep")
	if !ok || string(e.TokenizerBytes) != "good-bytes" {
		t.Fatal("previous generation no longer serves its verified bytes")
	}
}

func TestKvProfileRegistryDigestMismatchRejected(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-bad", "acme/reg-bad", []byte("content"))
	// Break the pinned digest in the document (keep it well-formed hex).
	doc, err := os.ReadFile(filepath.Join(root, "p-bad.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("different-content"))
	fresh := kvSha256Hex([]byte("content"))
	bad := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(root, "p-bad.yaml"),
		[]byte(replaceOnce(t, string(doc), fresh, bad)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := KvProfileRegistryLoadFrom(root); err == nil {
		t.Fatal("digest mismatch accepted")
	}
}

func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	i := len(s)
	for j := 0; j+len(old) <= len(s); j++ {
		if s[j:j+len(old)] == old {
			i = j
			break
		}
	}
	if i == len(s) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return s[:i] + new + s[i+len(old):]
}

func TestKvProfileRegistrySymlinkArtifactRejected(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-sym", "acme/reg-sym", []byte("real-bytes"))
	art := filepath.Join(root, kvProfileArtifactSubdir, "acme__reg-sym", "tokenizer.json")
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("real-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(art); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, art); err != nil {
		t.Fatal(err)
	}
	// Same bytes, same digest — but reached through a symlink. The open must
	// refuse the link itself; content equality is irrelevant.
	if err := KvProfileRegistryLoadFrom(root); err == nil {
		t.Fatal("symlinked artifact accepted")
	}
}

func TestKvProfileRegistryWritableParentRejected(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-wr", "acme/reg-wr", []byte("bytes"))
	artDir := filepath.Join(root, kvProfileArtifactSubdir, "acme__reg-wr")
	if err := os.Chmod(artDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := KvProfileRegistryLoadFrom(root); err == nil {
		t.Fatal("world-writable artifact directory accepted")
	}
	if err := os.Chmod(artDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load after tightening dir mode: %v", err)
	}
}

func TestKvProfileRegistryGroupWritableFileRejected(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-mode", "acme/reg-mode", []byte("bytes"))
	art := filepath.Join(root, kvProfileArtifactSubdir, "acme__reg-mode", "tokenizer.json")
	if err := os.Chmod(art, 0o664); err != nil {
		t.Fatal(err)
	}
	if err := KvProfileRegistryLoadFrom(root); err == nil {
		t.Fatal("group-writable artifact accepted")
	}
}

func TestKvProfileRegistryWrongOwnerRejected(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown the fixture")
	}
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-own", "acme/reg-own", []byte("bytes"))
	art := filepath.Join(root, kvProfileArtifactSubdir, "acme__reg-own", "tokenizer.json")
	if err := os.Chown(art, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := KvProfileRegistryLoadFrom(root); err == nil {
		t.Fatal("artifact owned by untrusted uid accepted")
	}
}

func TestKvProfileRegistryOversizeArtifactRejected(t *testing.T) {
	root := kvRegistryTestSetup(t)
	oldCap := kvProfileArtifactMaxBytes
	kvProfileArtifactMaxBytes = 8
	t.Cleanup(func() { kvProfileArtifactMaxBytes = oldCap })
	kvWriteProfileFixture(t, root, "p-big", "acme/reg-big", []byte("more-than-eight-bytes"))
	if err := KvProfileRegistryLoadFrom(root); err == nil {
		t.Fatal("oversize artifact accepted")
	}
}

func TestKvProfileRegistryDuplicateModelClaimRejected(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-a", "acme/reg-dup", []byte("bytes-a"))
	kvWriteProfileFixture(t, root, "p-b", "acme/other", []byte("bytes-b"), "acme/reg-dup")
	if err := KvProfileRegistryLoadFrom(root); err == nil {
		t.Fatal("two profiles claiming one served model accepted")
	}
}

func TestKvProfileRegistryPublishResetsTokenizerPool(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-epoch", "acme/reg-epoch", []byte("bytes"))
	before := kvTokenizerEpoch.Load()
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}
	if kvTokenizerEpoch.Load() == before {
		t.Fatal("publish did not advance the tokenizer pool generation")
	}
}

// --- verified-bytes tokenizer loading -------------------------------------

// kvProfTestTok is a trivial KvTokenizer for backend fakes.
type kvProfTestTok struct{}

func (kvProfTestTok) Encode(string, bool) []uint32 { return []uint32{1} }
func (kvProfTestTok) Close()                       {}

// kvBytesRecBackend records which load path served each request.
type kvBytesRecBackend struct {
	pathCalls  atomic.Int32
	bytesCalls atomic.Int32
	lastBytes  atomic.Value // []byte
}

func (b *kvBytesRecBackend) LoadModel(string) KvTokenizer {
	b.pathCalls.Add(1)
	return nil // no filesystem fixture exists in these tests
}
func (b *kvBytesRecBackend) Name() string { return "bytes-recording-fake" }
func (b *kvBytesRecBackend) LoadModelBytes(data []byte) KvTokenizer {
	b.bytesCalls.Add(1)
	b.lastBytes.Store(append([]byte(nil), data...))
	return kvProfTestTok{}
}

// kvPathOnlyBackend has no in-memory loading capability.
type kvPathOnlyBackend struct{ pathCalls atomic.Int32 }

func (b *kvPathOnlyBackend) LoadModel(string) KvTokenizer {
	b.pathCalls.Add(1)
	return kvProfTestTok{}
}
func (b *kvPathOnlyBackend) Name() string { return "path-only-fake" }

func kvSwapBackend(t *testing.T, b KvTokenizerBackend) {
	t.Helper()
	old := kvRegisteredBackend
	kvRegisteredBackend = b
	KvTokenizerPoolReset()
	t.Cleanup(func() {
		kvRegisteredBackend = old
		KvTokenizerPoolReset()
	})
}

// TestKvTokenizerLoadUsesVerifiedProfileBytes: a model covered by a published
// profile tokenizes the registry's digest-verified buffer — the filesystem
// path is never opened, for the base model and for every allowed alias.
func TestKvTokenizerLoadUsesVerifiedProfileBytes(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-bytes", "acme/bytes-m1", []byte("VERIFIED-TOKENIZER"), "bytes-m1-alias")
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}
	backend := &kvBytesRecBackend{}
	kvSwapBackend(t, backend)

	if tok := kvLoadTokenizer("acme/bytes-m1"); tok == nil {
		t.Fatal("profiled model failed to load")
	}
	if tok := kvLoadTokenizer("bytes-m1-alias"); tok == nil {
		t.Fatal("profiled alias failed to load")
	}
	if got := backend.pathCalls.Load(); got != 0 {
		t.Fatalf("filesystem path opened %d times for a profiled model", got)
	}
	if got := backend.bytesCalls.Load(); got == 0 {
		t.Fatal("verified bytes never consumed")
	}
	if last, _ := backend.lastBytes.Load().([]byte); string(last) != "VERIFIED-TOKENIZER" {
		t.Fatalf("backend received %q, want the registry's verified bytes", last)
	}
}

// TestKvTokenizerProfiledModelNeverFallsBackToPath: when the backend cannot
// load from memory, a profiled model FAILS rather than opening an unverified
// filesystem path.
func TestKvTokenizerProfiledModelNeverFallsBackToPath(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-nofall", "acme/nofall-m1", []byte("bytes"))
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}
	backend := &kvPathOnlyBackend{}
	kvSwapBackend(t, backend)

	if tok := kvLoadTokenizer("acme/nofall-m1"); tok != nil {
		t.Fatal("profiled model loaded through a backend that cannot verify bytes")
	}
	if got := backend.pathCalls.Load(); got != 0 {
		t.Fatalf("unverified filesystem path opened %d times", got)
	}
	// Unprofiled models keep the legacy path behavior.
	if tok := kvLoadTokenizer("acme/legacy-model"); tok == nil {
		t.Fatal("legacy path load broken")
	}
	if got := backend.pathCalls.Load(); got != 1 {
		t.Fatalf("legacy model path calls = %d, want 1", got)
	}
}

// TestKvTokenizerFlightIdentity: the singleflight identity is the
// profile-pinned artifact digest for profiled models (so a profile update
// re-keys in-flight collapsing) and slug-scoped for legacy models.
func TestKvTokenizerFlightIdentity(t *testing.T) {
	root := kvRegistryTestSetup(t)
	kvWriteProfileFixture(t, root, "p-ident", "acme/ident-m1", []byte("first"))
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("load: %v", err)
	}
	slug := kvModelSlug("acme/ident-m1")
	id1, e1 := kvTokenizerLoadIdentity(slug)
	if e1 == nil {
		t.Fatal("profiled slug resolved no entry")
	}
	wantDigest := kvSha256Hex([]byte("first"))
	if id1 != "sha256:"+wantDigest {
		t.Fatalf("identity %q, want pinned digest form", id1)
	}
	legacyID, eNil := kvTokenizerLoadIdentity("acme__no-profile")
	if eNil != nil || legacyID != "slug:acme__no-profile" {
		t.Fatalf("legacy identity %q", legacyID)
	}

	// Republish with a changed artifact: identity must change with it.
	kvWriteProfileFixture(t, root, "p-ident", "acme/ident-m1", []byte("second"))
	if err := KvProfileRegistryLoadFrom(root); err != nil {
		t.Fatalf("reload: %v", err)
	}
	id2, _ := kvTokenizerLoadIdentity(slug)
	if id2 == id1 {
		t.Fatal("artifact change did not change the flight identity")
	}
}
