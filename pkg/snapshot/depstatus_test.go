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

// depstatus_test.go — the §9 external_dependencies response surface:
// capture-side status mapping (persist responses) and restore-side
// per-entry dispositions, plus the explicit write-through marker
// semantics on Result.

package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestCaptureDependencyStatuses(t *testing.T) {
	deps := []cmn.RecoveryDependency{
		{Type: cmn.RecoveryDepEngineContracts, ID: "ec.v1", Generation: "2", Digest: "sha256:aa", Required: true},
		{Type: cmn.RecoveryDepKvModelProfiles, ID: "/etc/loxilb/kvprofiles", Generation: "7", Required: true},
		{Type: cmn.RecoveryDepCertStore, Digest: "sha256:bb", Required: true},
		{Type: cmn.RecoveryDepAPIKeyDB, ID: "dpkeys", Required: true},
		{Type: cmn.RecoveryDepAuthDB, ID: "mgmt", Required: false},
	}
	statuses := CaptureDependencyStatuses(deps)
	if len(statuses) != len(deps) {
		t.Fatalf("got %d statuses for %d deps", len(statuses), len(deps))
	}
	want := map[string]string{
		cmn.RecoveryDepEngineContracts: DepStatusReady,
		cmn.RecoveryDepKvModelProfiles: DepStatusReady,
		cmn.RecoveryDepCertStore:       DepStatusReady,
		// The DB stores dial in the background by design: identity is
		// recorded, reachability deliberately unclaimed.
		cmn.RecoveryDepAPIKeyDB: DepStatusConfigured,
		cmn.RecoveryDepAuthDB:   DepStatusConfigured,
	}
	for i, s := range statuses {
		if s.Status != want[s.Type] {
			t.Errorf("%s: status %q, want %q", s.Type, s.Status, want[s.Type])
		}
		// Identity fields must mirror the manifest entry exactly.
		d := deps[i]
		if s.Type != d.Type || s.ID != d.ID || s.Generation != d.Generation ||
			s.Digest != d.Digest || s.Required != d.Required {
			t.Errorf("identity fields diverged: %+v vs %+v", s, d)
		}
	}
	if CaptureDependencyStatuses(nil) != nil {
		t.Fatalf("nil manifest must map to nil statuses")
	}
}

// TestRestoreReportsDependencyStatuses pins the restore response's
// external_dependencies dispositions: required entries report verified /
// warning / failed, optional entries report declared (and are never
// verified), and the surface is populated on dry-run too (preflighting is
// what dry-run is for).
func TestRestoreReportsDependencyStatuses(t *testing.T) {
	raw := capturedRaw(t) // required: api-key-db, auth-db; optional: the registries

	statusByType := func(res *Result) map[string]string {
		out := map[string]string{}
		for _, s := range res.ExternalDependencies {
			out[s.Type] = s.Status
		}
		return out
	}

	t.Run("verified, warning and declared", func(t *testing.T) {
		// The captured fixture carries a KV binding, so both registries
		// are REQUIRED there; add an unknown OPTIONAL entry to pin the
		// declared disposition (VALIDATE tolerates it, verify never runs
		// on it).
		doc, err := Decode(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		doc.RecoveryDependencies = append(doc.RecoveryDependencies,
			cmn.RecoveryDependency{Type: "quantum-ledger", Required: false})
		withOptional, err := Encode(doc)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}

		hooks := newMockHooks()
		hooks.depVerifyWarn = map[string]string{
			cmn.RecoveryDepAPIKeyDB: "store wired but not yet dialed",
		}
		e := newTestEngine(hooks, t.TempDir())
		res, rerr := e.Restore(withOptional, RestoreOptions{Mode: ModeDryRun})
		if rerr != nil || res.Result != ResultOK {
			t.Fatalf("dry-run failed: err=%v res=%+v", rerr, res)
		}
		got := statusByType(res)
		want := map[string]string{
			cmn.RecoveryDepAPIKeyDB:        DepStatusWarning,
			cmn.RecoveryDepAuthDB:          DepStatusVerified,
			cmn.RecoveryDepEngineContracts: DepStatusVerified,
			cmn.RecoveryDepKvModelProfiles: DepStatusVerified,
			"quantum-ledger":               DepStatusDeclared,
		}
		for typ, status := range want {
			if got[typ] != status {
				t.Errorf("%s: status %q, want %q (all: %v)", typ, got[typ], status, got)
			}
		}
	})

	t.Run("failed entry reported alongside the error", func(t *testing.T) {
		hooks := newMockHooks()
		hooks.depVerifyFail = map[string]error{
			cmn.RecoveryDepAuthDB: errors.New("user service is not enabled"),
		}
		e := newTestEngine(hooks, t.TempDir())
		res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
		if err != nil {
			t.Fatalf("Restore: %v", err)
		}
		if res.Result == ResultOK || len(res.Errors) == 0 {
			t.Fatalf("failed dependency did not stop the restore: %+v", res)
		}
		got := statusByType(res)
		if got[cmn.RecoveryDepAuthDB] != DepStatusFailed {
			t.Fatalf("failing dependency status %q, want %q", got[cmn.RecoveryDepAuthDB], DepStatusFailed)
		}
		// The other required entry still shows its own disposition -- the
		// response reports the whole manifest, not just the first failure.
		if got[cmn.RecoveryDepAPIKeyDB] != DepStatusVerified {
			t.Fatalf("co-listed dependency status %q, want %q", got[cmn.RecoveryDepAPIKeyDB], DepStatusVerified)
		}
	})

	t.Run("no manifest, no surface", func(t *testing.T) {
		hooks := newMockHooks()
		doc, err := Capture(hooks, "v-test", "host", TriggerManual, nil)
		if err != nil {
			t.Fatalf("Capture: %v", err)
		}
		bare, err := Encode(doc)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		e := newTestEngine(newMockHooks(), t.TempDir())
		res, rerr := e.Restore(bare, RestoreOptions{Mode: ModeDryRun})
		if rerr != nil || res.Result != ResultOK {
			t.Fatalf("dry-run failed: err=%v res=%+v", rerr, res)
		}
		if len(res.ExternalDependencies) != 0 {
			t.Fatalf("manifest-less document grew dependency statuses: %+v", res.ExternalDependencies)
		}
	})
}

// TestResultPersistedMarkerEncoding pins the F-CP-13 wire contract: the
// persisted marker is absent unless the write-through disposition is
// known, and an explicit false (restore applied, persist FAILED) survives
// encoding -- that explicit false is what keeps a degraded commit from
// reading as a bare "ok".
func TestResultPersistedMarkerEncoding(t *testing.T) {
	var res Result
	res.Result = ResultOK
	plain, err := json.Marshal(&res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(plain), "persisted") {
		t.Fatalf("persisted marker leaked into a result without a write-through disposition: %s", plain)
	}

	degraded := false
	res.Persisted = &degraded
	enc, err := json.Marshal(&res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(enc), `"persisted":false`) {
		t.Fatalf("explicit degraded marker lost in encoding: %s", enc)
	}

	ok := true
	res.Persisted = &ok
	res.PersistedGeneration = 42
	enc, err = json.Marshal(&res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(enc), `"persisted":true`) ||
		!strings.Contains(string(enc), `"persisted_generation":42`) {
		t.Fatalf("persisted disposition incomplete: %s", enc)
	}
}
