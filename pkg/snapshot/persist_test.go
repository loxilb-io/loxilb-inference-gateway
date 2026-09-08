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
package snapshot

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// swapSyncSeams replaces the fileSync/dirSync durability seams for one test
// and restores the real implementations afterwards. The package's tests do
// not run in parallel, so mutating the package vars is safe.
func swapSyncSeams(t *testing.T, fs func(*os.File) error, ds func(string) error) {
	t.Helper()
	origFile, origDir := fileSync, dirSync
	if fs != nil {
		fileSync = fs
	}
	if ds != nil {
		dirSync = ds
	}
	t.Cleanup(func() {
		fileSync = origFile
		dirSync = origDir
	})
}

// dirEntries returns the basenames present in dir, for orphan checks.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// TestWriteAtomicDurabilityOrder pins the crash-consistency ordering: the
// temp file content is fsynced BEFORE the rename publishes it, and the
// directory is fsynced AFTER the rename. Both observations are made from
// inside the seams while writeAtomic runs, so reordering either call (or
// dropping one) fails this test.
func TestWriteAtomicDurabilityOrder(t *testing.T) {
	dir := t.TempDir()
	finalPath := filepath.Join(dir, "snapshot.json")
	oldContent := []byte(`{"old":true}`)
	newContent := []byte(`{"new":true}`)
	if err := os.WriteFile(finalPath, oldContent, 0o600); err != nil {
		t.Fatalf("seed old file: %v", err)
	}

	var fileSyncs, dirSyncs int
	swapSyncSeams(t,
		func(f *os.File) error {
			fileSyncs++
			// The rename must not have happened yet: the published
			// name still carries the previous complete document.
			got, err := os.ReadFile(finalPath)
			if err != nil || string(got) != string(oldContent) {
				t.Errorf("fileSync ran after publish: final=%q err=%v", got, err)
			}
			return f.Sync()
		},
		func(d string) error {
			dirSyncs++
			if fileSyncs == 0 {
				t.Error("dirSync ran before fileSync")
			}
			// The rename must already have happened: the directory
			// fsync is what makes it durable.
			got, err := os.ReadFile(finalPath)
			if err != nil || string(got) != string(newContent) {
				t.Errorf("dirSync ran before rename: final=%q err=%v", got, err)
			}
			return syncDir(d)
		})

	path, err := writeAtomic(dir, "snapshot.json", newContent)
	if err != nil {
		t.Fatalf("writeAtomic: %v", err)
	}
	if path != finalPath {
		t.Fatalf("path = %q, want %q", path, finalPath)
	}
	if fileSyncs != 1 || dirSyncs != 1 {
		t.Fatalf("fileSyncs=%d dirSyncs=%d, want exactly 1 each", fileSyncs, dirSyncs)
	}
	if got, _ := os.ReadFile(finalPath); string(got) != string(newContent) {
		t.Fatalf("final content = %q, want %q", got, newContent)
	}
}

// TestWriteAtomicFileSyncFailureKeepsExisting injects a content-fsync fault:
// writeAtomic must fail, the previously published document must stay
// byte-identical, and no temp orphan may remain.
func TestWriteAtomicFileSyncFailureKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	finalPath := filepath.Join(dir, "snapshot.json")
	oldContent := []byte(`{"old":true}`)
	if err := os.WriteFile(finalPath, oldContent, 0o600); err != nil {
		t.Fatalf("seed old file: %v", err)
	}

	injected := errors.New("injected content-fsync fault")
	swapSyncSeams(t, func(*os.File) error { return injected }, nil)

	if _, err := writeAtomic(dir, "snapshot.json", []byte(`{"new":true}`)); !errors.Is(err, injected) {
		t.Fatalf("writeAtomic err = %v, want injected fault", err)
	} else if !strings.Contains(err.Error(), "sync temp file") {
		t.Fatalf("err %q does not name the sync-temp-file step", err)
	}
	if got, _ := os.ReadFile(finalPath); string(got) != string(oldContent) {
		t.Fatalf("published document changed on failed persist: %q", got)
	}
	if names := dirEntries(t, dir); len(names) != 1 || names[0] != "snapshot.json" {
		t.Fatalf("temp orphan left behind: %v", names)
	}
}

// TestWriteAtomicDirSyncFailureSurfaces injects a directory-fsync fault
// after the rename: the new document is visible in the namespace, but
// durability is unconfirmed, so writeAtomic must still report failure
// (callers must not answer "persisted" for a write that may not survive a
// crash).
func TestWriteAtomicDirSyncFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	injected := errors.New("injected dir-fsync fault")
	swapSyncSeams(t, nil, func(string) error { return injected })

	_, err := writeAtomic(dir, "snapshot.json", []byte(`{"new":true}`))
	if !errors.Is(err, injected) {
		t.Fatalf("writeAtomic err = %v, want injected fault", err)
	}
	if !strings.Contains(err.Error(), "sync directory after rename") {
		t.Fatalf("err %q does not name the dir-sync step", err)
	}
}

// TestQuarantinePersistedDirSyncFailureSurfaces pins the same fail-closed
// semantic on the quarantine rename: if the directory fsync fails, the
// quarantine may not survive a crash (snapshot.json would resurrect and the
// next boot would retry a known-bad document), so the caller must be told.
func TestQuarantinePersistedDirSyncFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PersistFileName), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	injected := errors.New("injected dir-fsync fault")
	swapSyncSeams(t, nil, func(string) error { return injected })

	if _, err := QuarantinePersisted(dir, time.Now()); !errors.Is(err, injected) {
		t.Fatalf("QuarantinePersisted err = %v, want injected fault", err)
	}
}

// TestPersistStampsMonotonicGeneration pins the lineage semantics: a fresh
// directory starts at generation 1, each persist increments, and a
// quarantine does NOT reset the counter -- the quarantined file's
// generation is already spent, so the next persist continues past it
// instead of restarting at 1 (which would make the older quarantined
// document look newer than the current state).
func TestPersistStampsMonotonicGeneration(t *testing.T) {
	dir := t.TempDir()

	doc := goldenDocument()
	doc.Generation = 0
	path, sum, gen, err := Persist(doc, dir)
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if gen != 1 || doc.Generation != 1 {
		t.Fatalf("first persist gen = %d (doc %d), want 1", gen, doc.Generation)
	}
	if sum == "" || path != filepath.Join(dir, PersistFileName) {
		t.Fatalf("path/checksum missing: %q %q", path, sum)
	}
	// The persisted bytes must carry the stamped generation (and a
	// checksum computed over it): re-decode from disk.
	raw, err := LoadPersisted(dir)
	if err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	ondisk, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Decode persisted: %v", err)
	}
	if ondisk.Generation != 1 {
		t.Fatalf("on-disk generation = %d, want 1", ondisk.Generation)
	}
	if err := VerifyChecksum(ondisk); err != nil {
		t.Fatalf("persisted checksum does not cover generation: %v", err)
	}

	if _, _, gen, err = Persist(doc, dir); err != nil || gen != 2 {
		t.Fatalf("second persist gen = %d err = %v, want 2", gen, err)
	}

	// Quarantine the gen-2 snapshot, then persist again: generation must
	// continue at 3, not restart at 1.
	if _, err := QuarantinePersisted(dir, time.Now()); err != nil {
		t.Fatalf("QuarantinePersisted: %v", err)
	}
	if _, _, gen, err = Persist(doc, dir); err != nil || gen != 3 {
		t.Fatalf("post-quarantine persist gen = %d err = %v, want 3 (lineage must not restart)", gen, err)
	}
}

// TestNextGenerationIgnoresCorruptLineageFiles pins that a truncated or
// non-JSON quarantine file (quarantined snapshots are often quarantined
// BECAUSE they are corrupt) does not break the lineage scan.
func TestNextGenerationIgnoresCorruptLineageFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PersistFileName+".failed-20260904-000000.000000000"),
		[]byte(`{"generation": 41, "domains": {truncated`), 0o600); err != nil {
		t.Fatalf("seed corrupt quarantine: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, PersistFileName+".failed-20260904-000000.000000001"),
		[]byte(`{"generation": 5}`), 0o600); err != nil {
		t.Fatalf("seed parseable quarantine: %v", err)
	}
	if got := nextGeneration(dir); got != 6 {
		t.Fatalf("nextGeneration = %d, want 6 (max parseable lineage gen 5 + 1; corrupt file ignored)", got)
	}
}

// TestCaptureDoesNotStampGeneration pins that a bare capture (the GET
// /config/snapshot path) has no lineage position: only Persist assigns
// generations, and the encoded document omits the field entirely.
func TestCaptureDoesNotStampGeneration(t *testing.T) {
	hooks := newMockHooks()
	doc, err := Capture(hooks, "v-test", "host-test", TriggerManual, nil)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if doc.Generation != 0 {
		t.Fatalf("capture stamped generation %d, want 0", doc.Generation)
	}
	enc, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.Contains(string(enc), `"generation"`) {
		t.Fatalf("bare capture encodes a generation field")
	}
}

// TestQuarantinePersistedSyncsDirectory pins that a successful quarantine
// fsyncs the directory holding the rename.
func TestQuarantinePersistedSyncsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PersistFileName), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	var dirSyncs int
	swapSyncSeams(t, nil, func(d string) error {
		dirSyncs++
		return syncDir(d)
	})

	path, err := QuarantinePersisted(dir, time.Now())
	if err != nil {
		t.Fatalf("QuarantinePersisted: %v", err)
	}
	if dirSyncs != 1 {
		t.Fatalf("dirSyncs = %d, want 1", dirSyncs)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("quarantine file missing: %v", err)
	}
}
