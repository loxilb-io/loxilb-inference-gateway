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

// Config-durability regression tests, from a live incident: a container
// restart of a serving gateway hit an idempotent "lbrule-exists" during
// the boot snapshot restore, rolled back the ENTIRE loadbalancer domain
// (deleting rules that were serving seconds earlier), and the next
// auto-persist then overwrote snapshot.json with the empty post-rollback
// state -- durable config loss plus destroyed forensics. These tests pin
// the engine-side fixes: boot applies tolerate idempotent duplicates
// instead of rolling back, rollback tolerance is per-item (not
// domain-aborting), domain deletes attempt every item, rule-managed
// endpoints are never deleted directly, and a failing boot snapshot is
// quarantined rather than left in place to be overwritten.
package snapshot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A boot restore that hits the backend's idempotent identical-item
// sentinel must skip that item and commit, not roll back the domain.
func TestBootApplyToleratesIdempotentDuplicate(t *testing.T) {
	hooks := newMockHooks()
	doc := restoreDoc("0.9.8.6-beta")
	// Duplicate document entry for the same LB rule: the second Add hits
	// the identical-exists sentinel (the mock stands in for AddLbRule's
	// short-circuit on a byte-identical rule).
	doc.Domains.LoadBalancer = append(doc.Domains.LoadBalancer, doc.Domains.LoadBalancer[0])
	hooks.failOnNthCall("NetLbRuleAdd", 2, errors.New("lbrule-exists error"))

	e := newTestEngine(hooks, t.TempDir())
	result, err := e.Restore(encodeDoc(t, doc), RestoreOptions{Boot: true})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if result.Result != ResultOK {
		t.Fatalf("boot restore must tolerate an idempotent duplicate, got result=%q errors=%v",
			result.Result, result.Errors)
	}
	if len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "loadbalancer") {
		t.Fatalf("expected a loadbalancer skip warning, got %v", result.Warnings)
	}
	if len(hooks.lbRules) != 1 {
		t.Fatalf("expected exactly 1 live rule after the duplicate skip, got %d", len(hooks.lbRules))
	}
}

// A boot restore where an apply error is NOT the idempotent sentinel must
// still roll back (tolerance is narrow, not a blanket ignore).
func TestBootApplyStillRollsBackOnRealConflict(t *testing.T) {
	hooks := newMockHooks()
	doc := restoreDoc("0.9.8.6-beta")
	hooks.failNext("NetLbRuleAdd", errors.New("lbrule-exist error: cant modify rule security mode"))

	e := newTestEngine(hooks, t.TempDir())
	result, err := e.Restore(encodeDoc(t, doc), RestoreOptions{Boot: true})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if result.Result != ResultRolledBack {
		t.Fatalf("a same-key-different-config conflict must roll back, got result=%q errors=%v",
			result.Result, result.Errors)
	}
}

// A non-boot commit runs after a wipe, so an "exists" there means the wipe
// failed -- it must stay fatal (roll back), not be skipped.
func TestCommitApplyStaysStrictOnExists(t *testing.T) {
	hooks := newMockHooks()
	doc := restoreDoc("0.9.8.6-beta")
	hooks.failNext("NetLbRuleAdd", errors.New("lbrule-exists error"))

	e := newTestEngine(hooks, t.TempDir())
	result, err := e.Restore(encodeDoc(t, doc), RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if result.Result != ResultRolledBack {
		t.Fatalf("post-wipe exists must stay fatal on commit, got result=%q errors=%v",
			result.Result, result.Errors)
	}
}

// Rollback tolerance is per ITEM: one still-live duplicate must not abort
// the re-apply of the rest of its domain (previously the whole domain's
// remaining items were silently dropped).
func TestRollbackToleratesExistsPerItem(t *testing.T) {
	hooks := newMockHooks()
	preDoc := NewDocument("0.9.8.6-beta", "test-host", TriggerPreRestore)
	preDoc.Domains.Endpoint = []cmn.EndPointMod{
		{HostName: "10.0.0.1", Name: "ep1"},
		{HostName: "10.0.0.2", Name: "ep2"},
	}
	selected, serr := Select([]string{DomainEndpoint})
	if serr != nil {
		t.Fatalf("Select: %v", serr)
	}

	e := newTestEngine(hooks, t.TempDir())
	hooks.failOnNthCall("NetEpHostAdd", 1, errors.New("ep-host already exists"))
	errs := e.rollback(preDoc, selected)
	if len(errs) != 0 {
		t.Fatalf("idempotent-exists during rollback must be tolerated, got %v", errs)
	}
	if len(hooks.endpoints) != 1 || hooks.endpoints[0].Name != "ep2" {
		t.Fatalf("the item AFTER the tolerated duplicate must still be re-applied, got %+v", hooks.endpoints)
	}
}

// Domain deletes attempt every item: a failing delete mid-domain must not
// leave the remaining items live (that partial state poisons re-applies
// and dependent-domain deletes).
func TestDeleteAttemptsEveryItem(t *testing.T) {
	hooks := newMockHooks()
	hooks.lbRules = []cmn.LbRuleMod{
		{Serv: cmn.LbServiceArg{ServIP: "1.1.1.1", ServPort: 80, Proto: "tcp"}},
		{Serv: cmn.LbServiceArg{ServIP: "2.2.2.2", ServPort: 80, Proto: "tcp"}},
		{Serv: cmn.LbServiceArg{ServIP: "3.3.3.3", ServPort: 80, Proto: "tcp"}},
	}
	hooks.failOnNthCall("NetLbRuleDel", 1, errors.New("some datapath failure"))

	n, err := deleteLoadBalancer(hooks)
	if err == nil {
		t.Fatalf("the failing item's error must still be reported")
	}
	if n != 2 {
		t.Fatalf("expected the 2 items after the failure to still be deleted, got %d", n)
	}
	if len(hooks.lbRules) != 1 || hooks.lbRules[0].Serv.ServIP != "1.1.1.1" {
		t.Fatalf("expected only the failed item to remain live, got %+v", hooks.lbRules)
	}
}

// Rule-managed endpoints live and die with their LB rule; deleting them
// directly fails ("rule-referred") while the rule exists and previously
// aborted the whole endpoint teardown at the first such entry.
func TestDeleteEndpointSkipsRuleManaged(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{
		{HostName: "10.0.0.1", Name: "managed-ep", RuleManaged: true},
		{HostName: "10.0.0.2", Name: "standalone-ep"},
	}

	n, err := deleteEndpoint(hooks)
	if err != nil {
		t.Fatalf("deleteEndpoint: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected only the standalone endpoint deleted, got %d", n)
	}
	for _, c := range hooks.Calls {
		if c == "NetEpHostDel:managed-ep" {
			t.Fatalf("rule-managed endpoint must never be deleted directly, calls: %v", hooks.Calls)
		}
	}
}

// A failing boot snapshot is renamed aside, preserving forensics and
// keeping later persists from overwriting it; the quarantine backlog is
// bounded by the same artifact pruning as pre-restore snapshots.
func TestQuarantinePersistedAndPrune(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PersistFileName), []byte(`{"broken":true}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	path, err := QuarantinePersisted(dir, now)
	if err != nil {
		t.Fatalf("QuarantinePersisted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, PersistFileName)); !os.IsNotExist(err) {
		t.Fatalf("snapshot.json must be gone after quarantine")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"broken":true}` {
		t.Fatalf("quarantined content must be preserved verbatim at %s: %v", path, err)
	}

	// Seed more quarantined files than the keep bound and prune.
	for i := 0; i < PreRestoreKeep+3; i++ {
		name := PersistFileName + ".failed-" + time.Date(2026, 8, 1+i, 0, 0, 0, 0, time.UTC).Format("20060102-150405.000000000")
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("seed quarantine %d: %v", i, err)
		}
	}
	PruneArtifacts(dir, PreRestoreKeep, now)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), PersistFileName+".failed-") {
			count++
		}
	}
	if count != PreRestoreKeep {
		t.Fatalf("expected the quarantine backlog pruned to %d, found %d", PreRestoreKeep, count)
	}
}

// The boot-config gate defaults closed and opens exactly once.
func TestBootConfigGate(t *testing.T) {
	t.Cleanup(func() { bootConfigSettled.Store(false) })
	bootConfigSettled.Store(false)
	if BootConfigSettled() {
		t.Fatalf("gate must start closed")
	}
	MarkBootConfigSettled()
	if !BootConfigSettled() {
		t.Fatalf("gate must be open after MarkBootConfigSettled")
	}
}
