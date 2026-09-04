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
	"os"
	"path/filepath"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// captureFaultExit swaps the crash primitive for a recording panic so a
// crash point can be observed in-process; returns (points-hit, restore).
func captureFaultExit() (*[]string, func()) {
	var hits []string
	prev := faultExit
	faultExit = func(point string) {
		hits = append(hits, point)
		panic("fault-exit:" + point)
	}
	return &hits, func() { faultExit = prev }
}

func TestFaultPlanComesFromEnvOnly(t *testing.T) {
	// The production-safety pin: the fault plan's ONLY source is the env
	// var. An unset env means an empty plan -- a hard-wired or defaulted
	// plan would arm fault points in production builds.
	t.Setenv(testFaultEnv, "")
	if got := readFaultPlan(); got != "" {
		t.Fatalf("unset env must mean an empty fault plan, got %q", got)
	}
	t.Setenv(testFaultEnv, "persist-before-rename")
	if got := readFaultPlan(); got != "persist-before-rename" {
		t.Fatalf("fault plan must come from the env var, got %q", got)
	}
}

func TestFaultHookInertWithoutEnv(t *testing.T) {
	defer setTestFaultForTest("")()
	hits, restoreExit := captureFaultExit()
	defer restoreExit()

	dir := t.TempDir()
	doc := NewDocument("v", "h", TriggerManual)
	doc.IncludedDomains = DomainNames()
	if _, _, _, err := Persist(doc, dir); err != nil {
		t.Fatalf("persist with inert hook: %v", err)
	}
	if len(*hits) != 0 {
		t.Fatalf("fault exit fired without env: %v", *hits)
	}
	if err := faultApplyError(DomainFirewall, false); err != nil {
		t.Fatalf("apply fault fired without env: %v", err)
	}
	if err := faultCaptureError(DomainFirewall); err != nil {
		t.Fatalf("capture fault fired without env: %v", err)
	}
}

func TestFaultPersistCrashPointsLeaveOldSnapshot(t *testing.T) {
	// Both crash points must leave the PREVIOUS snapshot.json untouched
	// and the temp file unconsumed -- the exact NG-09 on-disk contract.
	for _, point := range []string{"persist-after-temp-write", "persist-before-rename"} {
		t.Run(point, func(t *testing.T) {
			dir := t.TempDir()
			doc := NewDocument("v", "h", TriggerManual)
			doc.IncludedDomains = DomainNames()
			if _, _, _, err := Persist(doc, dir); err != nil {
				t.Fatalf("baseline persist: %v", err)
			}
			before, err := os.ReadFile(filepath.Join(dir, PersistFileName))
			if err != nil {
				t.Fatalf("read baseline: %v", err)
			}

			defer setTestFaultForTest(point)()
			hits, restoreExit := captureFaultExit()
			defer restoreExit()
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Fatalf("crash point %s did not fire", point)
					}
				}()
				_, _, _, _ = Persist(doc, dir)
			}()
			if len(*hits) != 1 || (*hits)[0] != point {
				t.Fatalf("expected exactly one crash at %s, got %v", point, *hits)
			}
			after, err := os.ReadFile(filepath.Join(dir, PersistFileName))
			if err != nil || string(after) != string(before) {
				t.Fatalf("previous snapshot must survive the crash untouched (err=%v)", err)
			}
			// NOTE: the orphan temp file cannot be asserted here -- the
			// panic-based crash simulation unwinds writeAtomic's deferred
			// cleanup, which a real os.Exit crash never runs. The live
			// suite leg (real process kill) owns that assert.
		})
	}
}

func TestFaultRestoreMidApplyRollsBack(t *testing.T) {
	// NG-10 first half: an injected apply failure on one domain rolls the
	// whole restore back to the preserved pre-state.
	defer setTestFaultForTest("restore-mid-apply:" + DomainFirewall)()
	hooks := newMockHooks()
	hooks.fwRules = []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "9.9.9.9/32", DstIP: "8.8.8.8/32"}}}

	doc := NewDocument("v", "h", TriggerManual)
	doc.IncludedDomains = []string{DomainFirewall}
	doc.Domains.Firewall = []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "1.1.1.1/32", DstIP: "2.2.2.2/32"}}}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	eng := NewEngine(hooks, "v", "h", t.TempDir())
	res, err := eng.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Result != ResultRolledBack {
		t.Fatalf("expected rolled-back, got %+v", res)
	}
	if len(hooks.fwRules) != 1 || hooks.fwRules[0].Rule.SrcIP != "9.9.9.9/32" {
		t.Fatalf("rollback did not restore the pre-state: %+v", hooks.fwRules)
	}
}

func TestFaultRestoreDoubleFaultSurfacesRollbackFailed(t *testing.T) {
	// NG-10 second half: the same domain failing during the rollback
	// re-apply too must surface ROLLBACK-FAILED -- never a silent ok, and
	// never a quiet rolled-back that claims a recovery it did not make.
	defer setTestFaultForTest("restore-mid-apply-double:" + DomainFirewall)()
	hooks := newMockHooks()
	hooks.fwRules = []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "9.9.9.9/32", DstIP: "8.8.8.8/32"}}}

	doc := NewDocument("v", "h", TriggerManual)
	doc.IncludedDomains = []string{DomainFirewall}
	doc.Domains.Firewall = []cmn.FwRuleMod{{Rule: cmn.FwRuleArg{SrcIP: "1.1.1.1/32", DstIP: "2.2.2.2/32"}}}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	eng := NewEngine(hooks, "v", "h", t.TempDir())
	res, err := eng.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Result != ResultRollbackFailed {
		t.Fatalf("expected ROLLBACK-FAILED on the double fault, got %+v", res)
	}
	joined := strings.Join(res.Errors, " ")
	if !strings.Contains(joined, "rollback apply "+DomainFirewall) {
		t.Fatalf("errors must name the failed rollback domain: %v", res.Errors)
	}
}

func TestFaultCaptureDomainErrorFailsPersistKeepsOld(t *testing.T) {
	// NG-06 core: a failing domain Get fails the capture loudly and the
	// previous snapshot.json survives.
	hooks := newMockHooks()
	dir := t.TempDir()
	if _, _, err := WriteThrough(hooks, "v", "h", dir); err != nil {
		t.Fatalf("baseline write-through: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, PersistFileName))
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}

	defer setTestFaultForTest("capture-domain-error:" + DomainFirewall)()
	if _, err := Capture(hooks, "v", "h", TriggerManual, nil); err == nil {
		t.Fatalf("capture must fail on the injected domain error")
	} else if !strings.Contains(err.Error(), "capture "+DomainFirewall) {
		t.Fatalf("capture error must name the domain: %v", err)
	}
	if _, _, err := WriteThrough(hooks, "v", "h", dir); err == nil {
		t.Fatalf("write-through must fail when capture fails")
	}
	after, err := os.ReadFile(filepath.Join(dir, PersistFileName))
	if err != nil || string(after) != string(before) {
		t.Fatalf("previous snapshot must survive a failed capture (err=%v)", err)
	}
}
