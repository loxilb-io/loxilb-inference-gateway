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
	"encoding/json"
	"testing"
)

// resetBootState restores the package-level record after a test (the
// package's tests do not run in parallel).
func resetBootState(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { RecordBootRestoreState(BootRestoreState{}) })
}

func TestBootRestoreStateRecord(t *testing.T) {
	resetBootState(t)

	// Baseline record, then a failure overwrite, then the fallback flag
	// -- the sequence the boot loader actually performs.
	RecordBootRestoreState(BootRestoreState{Profile: "compat", SnapshotFound: true})
	reasons := []string{"dependency kv-model-profiles: no registry"}
	RecordBootRestoreState(BootRestoreState{
		Profile:        "compat",
		SnapshotFound:  true,
		Degraded:       true,
		QuarantinePath: "/etc/loxilb/snapshot.json.failed-x",
		Reasons:        reasons,
	})
	RecordBootLegacyFallback()

	got := BootRestoreStateGet()
	if !got.Degraded || !got.LegacyFallback || got.Succeeded {
		t.Fatalf("degraded fallback state wrong: %+v", got)
	}
	if got.QuarantinePath == "" || len(got.Reasons) != 1 {
		t.Fatalf("failure detail lost: %+v", got)
	}

	// The record must be insulated from caller-side mutation in BOTH
	// directions (recorded slice and returned slice).
	reasons[0] = "mutated"
	if BootRestoreStateGet().Reasons[0] == "mutated" {
		t.Fatalf("recorded reasons alias the caller's slice")
	}
	out := BootRestoreStateGet()
	out.Reasons[0] = "mutated-out"
	if BootRestoreStateGet().Reasons[0] == "mutated-out" {
		t.Fatalf("returned reasons alias the stored slice")
	}
}

// TestRestoreReportsSnapshotGeneration pins that a restored 1.5 document's
// lineage generation is reported in the result (the boot loader records it
// as the applied boot generation), and that older documents report zero.
func TestRestoreReportsSnapshotGeneration(t *testing.T) {
	// The golden document carries encrypted secret values; restoring it
	// needs the (pinned) node secret installed.
	defer withTestNodeSecret(t)()
	dir := t.TempDir()
	doc := goldenDocument()
	doc.RecoveryDependencies = nil
	if _, _, gen, err := Persist(doc, dir); err != nil || gen != 1 {
		t.Fatalf("Persist: gen=%d err=%v", gen, err)
	}
	raw, err := LoadPersisted(dir)
	if err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}

	e := newTestEngine(newMockHooks(), t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeDryRun})
	if err != nil || res.Result != ResultOK {
		t.Fatalf("dry-run failed: err=%v res=%+v", err, res)
	}
	if res.SnapshotGeneration != 1 {
		t.Fatalf("SnapshotGeneration = %d, want 1", res.SnapshotGeneration)
	}

	// A pre-generation document reports zero (absent on the wire).
	legacy := legacyGoldenDocument("1.4")
	legacyRaw, err := Encode(legacy)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	res, err = e.Restore(legacyRaw, RestoreOptions{Mode: ModeDryRun})
	if err != nil || res.Result != ResultOK {
		t.Fatalf("legacy dry-run failed: err=%v res=%+v", err, res)
	}
	if res.SnapshotGeneration != 0 {
		t.Fatalf("pre-1.5 document reported generation %d, want 0", res.SnapshotGeneration)
	}
	if bytes.Contains(mustMarshal(t, res), []byte("snapshot_generation")) {
		t.Fatalf("zero generation leaked onto the wire")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
