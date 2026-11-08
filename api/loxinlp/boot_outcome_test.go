/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package loxinlp

import (
	"errors"
	cmn "github.com/loxilb-io/loxilb/common"
	opt "github.com/loxilb-io/loxilb/options"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPartialBootSkipsLegacyReplay(t *testing.T) {
	for _, tc := range []struct {
		outcome snapshotBootOutcome
		handled bool
	}{{bootUnhandled, false}, {bootComplete, true}, {bootPartial, true}} {
		if got := tc.outcome.handled(); got != tc.handled {
			t.Fatalf("outcome %v: handled=%v", tc.outcome, got)
		}
	}
}

func TestEarlyBFDLegacyUsesSnapshotAuthority(t *testing.T) {
	old := opt.Opts.ConfigPath
	opt.Opts.ConfigPath = t.TempDir()
	defer func() { opt.Opts.ConfigPath = old }()
	if SnapshotBootSelected() {
		t.Fatal("absent snapshot selected")
	}
	snap := filepath.Join(opt.Opts.ConfigPath, "snapshot.json")
	legacy := filepath.Join(opt.Opts.ConfigPath, "BFDconfig.txt")
	if err := os.WriteFile(snap, []byte(`{"generation":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"Attr":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(legacy, future, future); err != nil {
		t.Fatal(err)
	}
	if !SnapshotBootSelected() {
		t.Fatal("newer legacy BFD overrode persisted snapshot lineage")
	}
	if err := os.WriteFile(snap, []byte(`{"generation":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if SnapshotBootSelected() {
		t.Fatal("pre-lineage newest-wins legacy selection changed")
	}
	later := future.Add(time.Hour)
	if err := os.Chtimes(snap, later, later); err != nil {
		t.Fatal(err)
	}
	if !SnapshotBootSelected() {
		t.Fatal("newer bare snapshot not selected")
	}
}

type fallbackBFDHook struct {
	cmn.NetHookInterface
	reads, adds int
	refuse      bool
}

func (h *fallbackBFDHook) NetBFDGet() ([]cmn.BFDMod, error) {
	h.reads++
	if h.reads == 1 {
		return nil, cmn.ErrBFDUnavailable
	}
	return nil, nil
}
func (h *fallbackBFDHook) NetBFDAdd(*cmn.BFDMod) (int, error) {
	h.adds++
	if h.refuse {
		return -1, errors.New("refused BFD")
	}
	return 0, nil
}
func TestCompatFallbackBFDWaitsForStoreAndReportsRefusal(t *testing.T) {
	oldHooks, oldPath := hooks, opt.Opts.ConfigPath
	defer func() { hooks, opt.Opts.ConfigPath = oldHooks, oldPath }()
	opt.Opts.ConfigPath = t.TempDir()
	h := &fallbackBFDHook{}
	hooks = h
	if err := os.WriteFile(filepath.Join(opt.Opts.ConfigPath, "BFDconfig.txt"), []byte(`{"Attr":[{"instance":"llb-inst0","remoteIp":"127.0.88.2","sourceIp":"127.0.0.1","interval":1000000,"retryCount":3}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	applyFallbackBFDConfig()
	if h.reads != 2 || h.adds != 1 {
		t.Fatalf("BFD fallback before store ready: %+v", h)
	}
	h.refuse = true
	if ApplyBFDConfig() {
		t.Fatal("legacy BFD refusal was silently reported as success")
	}
}
