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
	"fmt"
	"strings"
	"testing"
)

func resetOpState(t *testing.T) {
	t.Helper()
	opStateMu.Lock()
	p, r := lastPersist, lastRestore
	opStateMu.Unlock()
	t.Cleanup(func() {
		opStateMu.Lock()
		lastPersist, lastRestore = p, r
		opStateMu.Unlock()
	})
}

// TestPersistAndRestoreRecordOpState pins FR-class "most recent successful
// persist/restore generation and checksum through a status API": Persist
// and a committed restore record their identities; dry-run records
// nothing.
func TestPersistAndRestoreRecordOpState(t *testing.T) {
	resetOpState(t)
	// The golden document carries encrypted secret values (pinned under
	// goldenNodeSecret == the test secret) -- restoring it needs the
	// node secret installed.
	defer withTestNodeSecret(t)()
	dir := t.TempDir()

	doc := goldenDocument()
	doc.RecoveryDependencies = nil
	path, sum, gen, err := Persist(doc, dir)
	if err != nil {
		t.Fatalf("Persist: %v (path=%s)", err, path)
	}
	lp := LastPersist()
	if lp == nil || lp.Generation != gen || lp.Checksum != sum {
		t.Fatalf("persist not recorded: %+v (want gen=%d sum=%s)", lp, gen, sum)
	}

	raw, err := LoadPersisted(dir)
	if err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	e := newTestEngine(newMockHooks(), t.TempDir())

	// Dry-run must NOT touch the restore record.
	before := LastRestore()
	if res, rerr := e.Restore(raw, RestoreOptions{Mode: ModeDryRun}); rerr != nil || res.Result != ResultOK {
		t.Fatalf("dry-run: err=%v res=%+v", rerr, res)
	}
	if after := LastRestore(); (before == nil) != (after == nil) {
		t.Fatalf("dry-run recorded a restore: %+v", after)
	}

	if res, rerr := e.Restore(raw, RestoreOptions{Mode: ModeCommit}); rerr != nil || res.Result != ResultOK {
		t.Fatalf("commit: err=%v res=%+v", rerr, res)
	}
	lr := LastRestore()
	if lr == nil || lr.Mode != string(ModeCommit) || lr.Generation != gen {
		t.Fatalf("commit restore not recorded: %+v (want mode=commit gen=%d)", lr, gen)
	}
}

// TestReadinessReasons pins the readiness policy: degraded boot blocks
// READY until a commit restore recovers it; a boot-mode restore or nothing
// does not; dependency failures always surface; a clean boot is ready.
func TestReadinessReasons(t *testing.T) {
	cleanBoot := BootRestoreState{Profile: "compat", SnapshotFound: true, Succeeded: true}
	degraded := BootRestoreState{Profile: "strict", SnapshotFound: true, Degraded: true}

	if r := ReadinessReasons(true, cleanBoot, nil, AutoPersistState{}, nil); len(r) != 0 {
		t.Fatalf("clean settled boot not ready: %v", r)
	}
	if r := ReadinessReasons(false, cleanBoot, nil, AutoPersistState{}, nil); len(r) != 1 || !strings.Contains(r[0], "not settled") {
		t.Fatalf("unsettled boot verdict wrong: %v", r)
	}
	if r := ReadinessReasons(true, degraded, nil, AutoPersistState{}, nil); len(r) != 1 || !strings.Contains(r[0], "restore failed") {
		t.Fatalf("degraded boot verdict wrong: %v", r)
	}
	// A BOOT-mode restore record is the failed boot's own history -- it
	// must not count as recovery.
	bootRec := &OpRecord{Mode: "boot", Generation: 3}
	if r := ReadinessReasons(true, degraded, bootRec, AutoPersistState{}, nil); len(r) != 1 {
		t.Fatalf("boot-mode record cleared degraded: %v", r)
	}
	// An operator's commit restore is the designed recovery.
	commitRec := &OpRecord{Mode: string(ModeCommit), Generation: 4}
	if r := ReadinessReasons(true, degraded, commitRec, AutoPersistState{}, nil); len(r) != 0 {
		t.Fatalf("commit recovery did not clear degraded: %v", r)
	}
	// Dependency failures surface regardless.
	if r := ReadinessReasons(true, cleanBoot, nil, AutoPersistState{}, []string{"dependency api-key-db: down"}); len(r) != 1 {
		t.Fatalf("dep failure not surfaced: %v", r)
	}
	// Compat fallback names the legacy-replay degradation.
	fallback := degraded
	fallback.Profile = "compat"
	fallback.LegacyFallback = true
	if r := ReadinessReasons(true, fallback, nil, AutoPersistState{}, nil); len(r) != 1 || !strings.Contains(r[0], "legacy-replayed") {
		t.Fatalf("fallback verdict wrong: %v", r)
	}
	// An auto-persist failure streak blocks READY (config changes not
	// reaching disk is the silent-degradation class this surface exists
	// to expose).
	apFail := AutoPersistState{ConsecutiveFailures: 2, LastError: "capture failed: firewall get: boom"}
	if r := ReadinessReasons(true, cleanBoot, nil, apFail, nil); len(r) != 1 || !strings.Contains(r[0], "auto-persist failing") {
		t.Fatalf("auto-persist failure verdict wrong: %v", r)
	}
}

// TestAutoPersistFailureRecord pins the F-class auto-persist signal: the
// streak counts up, retry budget bounds self-rescheduling, and ANY
// successful persist clears it.
func TestAutoPersistFailureRecord(t *testing.T) {
	resetOpState(t)

	for i := 1; i < AutoPersistRetryBudget; i++ {
		if !RecordAutoPersistFailure(errStoreProbe(i)) {
			t.Fatalf("retry budget exhausted early at failure %d", i)
		}
	}
	if RecordAutoPersistFailure(errStoreProbe(AutoPersistRetryBudget)) {
		t.Fatalf("retry allowed past the budget (%d)", AutoPersistRetryBudget)
	}
	st := AutoPersistStateGet()
	if st.ConsecutiveFailures != AutoPersistRetryBudget || st.LastError == "" {
		t.Fatalf("failure state wrong: %+v", st)
	}

	// Any successful persist clears the streak.
	dir := t.TempDir()
	doc := goldenDocument()
	doc.RecoveryDependencies = nil
	if _, _, _, err := Persist(doc, dir); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if st := AutoPersistStateGet(); st.ConsecutiveFailures != 0 || st.LastError != "" {
		t.Fatalf("successful persist did not clear the streak: %+v", st)
	}
}

func errStoreProbe(i int) error { return fmt.Errorf("capture failed: attempt %d", i) }
