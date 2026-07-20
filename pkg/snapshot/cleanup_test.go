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

package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func writeFileT(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestPruneArtifactsKeepsNewestPreRestoresAndStaleTemps(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	// 8 name-sortable pre-restore snapshots; keep=5 must drop the 3 oldest.
	for i := 0; i < 8; i++ {
		writeFileT(t, dir, fmt.Sprintf("pre-restore-20260720-1000%02d.000000000.json", i))
	}
	// A stale writeAtomic orphan (older than staleTempAge) and a fresh one
	// (a concurrent in-flight write) -- only the stale one may go.
	stale := writeFileT(t, dir, ".snapshot.json-123.tmp")
	if err := os.Chtimes(stale, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	fresh := writeFileT(t, dir, ".snapshot.json-456.tmp")
	if err := os.Chtimes(fresh, now.Add(-time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	// Bystanders that must never be touched.
	writeFileT(t, dir, "snapshot.json")
	writeFileT(t, dir, "lbconfig.txt")

	removed := PruneArtifacts(dir, 5, now)
	if len(removed) != 4 { // 3 old pre-restores + 1 stale tmp
		t.Fatalf("removed %d files (%v), want 4", len(removed), removed)
	}

	want := []string{
		".snapshot.json-456.tmp",
		"lbconfig.txt",
		"pre-restore-20260720-100003.000000000.json",
		"pre-restore-20260720-100004.000000000.json",
		"pre-restore-20260720-100005.000000000.json",
		"pre-restore-20260720-100006.000000000.json",
		"pre-restore-20260720-100007.000000000.json",
		"snapshot.json",
	}
	got := dirNames(t, dir)
	if len(got) != len(want) {
		t.Fatalf("surviving files = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("surviving files = %v, want %v", got, want)
		}
	}
}

func TestPruneArtifactsNoOpUnderLimit(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFileT(t, dir, "pre-restore-20260720-100000.000000000.json")
	if removed := PruneArtifacts(dir, 5, now); len(removed) != 0 {
		t.Errorf("removed %v from an under-limit dir, want nothing", removed)
	}
	if removed := PruneArtifacts(t.TempDir(), 5, now); len(removed) != 0 {
		t.Errorf("removed %v from an empty dir, want nothing", removed)
	}
}

// A committed restore writes one pre-restore snapshot and must leave at most
// PreRestoreKeep behind (defect #6: they used to accumulate forever).
func TestRestoreCommitBoundsPreRestoreBacklog(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < PreRestoreKeep+3; i++ {
		writeFileT(t, dir, fmt.Sprintf("pre-restore-20260719-2000%02d.000000000.json", i))
	}

	hooks := newMockHooks()
	raw := encodeDoc(t, restoreDoc("0.9.8.6-beta"))
	engine := newTestEngine(hooks, dir)
	result, err := engine.Restore(raw, RestoreOptions{Mode: ModeCommit, Components: fixtureComponents})
	if err != nil || result.Result != ResultOK {
		t.Fatalf("commit failed: err=%v result=%+v", err, result)
	}

	count := 0
	for _, name := range dirNames(t, dir) {
		if len(name) > 12 && name[:12] == "pre-restore-" {
			count++
		}
	}
	if count != PreRestoreKeep {
		t.Errorf("pre-restore files after commit = %d, want exactly PreRestoreKeep (%d)", count, PreRestoreKeep)
	}
	// The newest one must be the file this commit just wrote (2026-07-20 >
	// the seeded 2026-07-19 names), i.e. pruning kept the fresh PRESERVE.
	if result.PreRestoreSnapshotPersisted == "" {
		t.Fatal("commit did not report a pre-restore snapshot path")
	}
	if _, err := os.Stat(result.PreRestoreSnapshotPersisted); err != nil {
		t.Errorf("fresh pre-restore snapshot was pruned away: %v", err)
	}
}
