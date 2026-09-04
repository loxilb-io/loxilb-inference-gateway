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

// recoverydeps_test.go — the NetRecoveryDepsGet producer: entries must
// mirror the compiled engine-contract registry constants (never artifact
// files), appear only for stores that are actually wired, and carry the
// producer-owned required flags for the databases.

package loxinet

import (
	"strconv"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/enginecontract"
	"github.com/loxilb-io/loxilb/pkg/user"
)

func depByType(deps []cmn.RecoveryDependency, typ string) (cmn.RecoveryDependency, bool) {
	for _, d := range deps {
		if d.Type == typ {
			return d, true
		}
	}
	return cmn.RecoveryDependency{}, false
}

func TestNetRecoveryDepsUnwiredGateway(t *testing.T) {
	KvProfileRegistryReset()
	t.Cleanup(KvProfileRegistryReset)
	savedHost, savedUser := opts.Opts.AIKeyDBHost, opts.Opts.UserServiceEnable
	opts.Opts.AIKeyDBHost, opts.Opts.UserServiceEnable = "", false
	t.Cleanup(func() { opts.Opts.AIKeyDBHost, opts.Opts.UserServiceEnable = savedHost, savedUser })

	na := &NetAPIStruct{}
	deps, err := na.NetRecoveryDepsGet()
	if err != nil {
		t.Fatalf("NetRecoveryDepsGet: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("unwired gateway reports %d deps, want only the compiled contract registry: %+v", len(deps), deps)
	}
	d := deps[0]
	if d.Type != cmn.RecoveryDepEngineContracts {
		t.Fatalf("lone entry is %q, want %q", d.Type, cmn.RecoveryDepEngineContracts)
	}
	// The identity must come from the compiled registry constants -- the
	// artifact files on disk are NOT the registry the binary runs.
	if d.ID != enginecontract.SchemaVersion ||
		d.Generation != strconv.FormatUint(enginecontract.Generation, 10) ||
		d.Digest != enginecontract.ManifestDigest {
		t.Fatalf("engine-contracts identity diverges from compiled constants: %+v", d)
	}
	if d.Required {
		t.Fatalf("producer set Required on engine-contracts -- that flag belongs to the capture path")
	}
}

func TestNetRecoveryDepsWiredStores(t *testing.T) {
	KvProfileRegistryReset()
	t.Cleanup(KvProfileRegistryReset)
	kvProfileReg.Store(&kvProfileGeneration{
		Gen:        7,
		SetDigest:  "0123abcd",
		SourceRoot: "/etc/loxilb/kvprofiles",
	})
	saved := opts.Opts
	opts.Opts.AIKeyDBHost = "127.0.0.1"
	opts.Opts.AIKeyDBName = "aigw_keys"
	opts.Opts.UserServiceEnable = true
	t.Cleanup(func() { opts.Opts = saved })

	na := &NetAPIStruct{}
	deps, err := na.NetRecoveryDepsGet()
	if err != nil {
		t.Fatalf("NetRecoveryDepsGet: %v", err)
	}
	if len(deps) != 4 {
		t.Fatalf("fully wired gateway reports %d deps, want 4: %+v", len(deps), deps)
	}

	kv, ok := depByType(deps, cmn.RecoveryDepKvModelProfiles)
	if !ok {
		t.Fatalf("published kv-profile generation not reported")
	}
	if kv.ID != "/etc/loxilb/kvprofiles" || kv.Generation != "7" || kv.Digest != "sha256:0123abcd" {
		t.Fatalf("kv-model-profiles identity wrong (digest must gain the sha256: prefix): %+v", kv)
	}

	ak, ok := depByType(deps, cmn.RecoveryDepAPIKeyDB)
	if !ok || !ak.Required || ak.ID != "aigw_keys" {
		t.Fatalf("configured api-key store not reported as required with its database name: %+v ok=%v", ak, ok)
	}
	au, ok := depByType(deps, cmn.RecoveryDepAuthDB)
	if !ok || !au.Required || au.ID != user.Schema {
		t.Fatalf("enabled user service not reported as required with its schema id: %+v ok=%v", au, ok)
	}
	for _, d := range deps {
		if d.Digest != "" && len(d.Digest) < len("sha256:")+1 {
			t.Fatalf("degenerate digest on %s: %q", d.Type, d.Digest)
		}
	}
}

func TestNetRecoveryDepVerifyEngineContracts(t *testing.T) {
	na := &NetAPIStruct{}
	gen := strconv.FormatUint(enginecontract.Generation, 10)
	newer := strconv.FormatUint(enginecontract.Generation+1, 10)

	cases := []struct {
		name     string
		dep      cmn.RecoveryDependency
		wantErr  bool
		wantWarn bool
	}{
		{"same generation matching digest", cmn.RecoveryDependency{
			Type: cmn.RecoveryDepEngineContracts, Generation: gen,
			Digest: enginecontract.ManifestDigest, Required: true}, false, false},
		{"newer generation than binary", cmn.RecoveryDependency{
			Type: cmn.RecoveryDepEngineContracts, Generation: newer,
			Digest: enginecontract.ManifestDigest, Required: true}, true, false},
		{"same generation divergent digest", cmn.RecoveryDependency{
			Type: cmn.RecoveryDepEngineContracts, Generation: gen,
			Digest: "sha256:deadbeef", Required: true}, true, false},
		{"malformed generation", cmn.RecoveryDependency{
			Type: cmn.RecoveryDepEngineContracts, Generation: "not-a-number", Required: true}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warn, err := na.NetRecoveryDepVerify(tc.dep)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if (warn != "") != tc.wantWarn {
				t.Fatalf("warn=%q wantWarn=%v", warn, tc.wantWarn)
			}
		})
	}
}

// An older-generation document warns rather than fails: bindings re-earn
// attestation against the current registry. Compiled Generation is 1
// today, so the "older" case only becomes constructible when the real
// registry moves past it; this guard keeps the semantic pinned from that
// moment on without fabricating registry state now.
func TestNetRecoveryDepVerifyOlderContractGeneration(t *testing.T) {
	if enginecontract.Generation < 2 {
		t.Skip("compiled registry still at generation 1; no older generation exists to verify")
	}
	na := &NetAPIStruct{}
	warn, err := na.NetRecoveryDepVerify(cmn.RecoveryDependency{
		Type: cmn.RecoveryDepEngineContracts, Generation: "1", Required: true})
	if err != nil || warn == "" {
		t.Fatalf("older generation must warn-and-pass: warn=%q err=%v", warn, err)
	}
}

func TestNetRecoveryDepVerifyKvProfiles(t *testing.T) {
	na := &NetAPIStruct{}
	KvProfileRegistryReset()
	t.Cleanup(KvProfileRegistryReset)

	t.Run("unpublished registry fails closed", func(t *testing.T) {
		_, err := na.NetRecoveryDepVerify(cmn.RecoveryDependency{
			Type: cmn.RecoveryDepKvModelProfiles, Generation: "7", Digest: "sha256:bbbb", Required: true})
		if err == nil {
			t.Fatalf("no published generation but verification passed")
		}
	})

	t.Run("different set digest warns not fails", func(t *testing.T) {
		kvProfileReg.Store(&kvProfileGeneration{
			Gen: 9, Profiles: map[string]*kvProfileEntry{}, SetDigest: "cccc",
			SourceRoot: "/nonexistent-root",
		})
		t.Cleanup(KvProfileRegistryReset)
		warn, err := na.NetRecoveryDepVerify(cmn.RecoveryDependency{
			Type: cmn.RecoveryDepKvModelProfiles, Generation: "7", Digest: "sha256:bbbb", Required: true})
		if err != nil {
			t.Fatalf("cross-node digest difference failed instead of warning: %v", err)
		}
		if warn == "" {
			t.Fatalf("cross-node digest difference passed silently")
		}
	})

	t.Run("on-disk drift fails closed", func(t *testing.T) {
		// A published profile whose source root is gone is the extreme
		// form of drift: the receipts no longer trace to any bytes.
		kvProfileReg.Store(&kvProfileGeneration{
			Gen: 9, SetDigest: "cccc", SourceRoot: "/nonexistent-root",
			Profiles: map[string]*kvProfileEntry{"p1": {}},
		})
		t.Cleanup(KvProfileRegistryReset)
		_, err := na.NetRecoveryDepVerify(cmn.RecoveryDependency{
			Type: cmn.RecoveryDepKvModelProfiles, Generation: "9", Required: true})
		if err == nil {
			t.Fatalf("published profile with unverifiable artifacts passed")
		}
	})
}

func TestNetRecoveryDepVerifyDatabases(t *testing.T) {
	na := &NetAPIStruct{}
	saved := opts.Opts
	t.Cleanup(func() { opts.Opts = saved })

	opts.Opts.AIKeyDBHost, opts.Opts.UserServiceEnable = "", false
	if _, err := na.NetRecoveryDepVerify(cmn.RecoveryDependency{
		Type: cmn.RecoveryDepAPIKeyDB, Required: true}); err == nil {
		t.Fatalf("required api-key store passed on a node with none configured")
	}
	if _, err := na.NetRecoveryDepVerify(cmn.RecoveryDependency{
		Type: cmn.RecoveryDepAuthDB, Required: true}); err == nil {
		t.Fatalf("required auth store passed on a node with the user service disabled")
	}

	opts.Opts.AIKeyDBHost, opts.Opts.UserServiceEnable = "127.0.0.1", true
	for _, typ := range []string{cmn.RecoveryDepAPIKeyDB, cmn.RecoveryDepAuthDB} {
		warn, err := na.NetRecoveryDepVerify(cmn.RecoveryDependency{Type: typ, Required: true})
		if err != nil || warn != "" {
			t.Fatalf("configured store %s did not verify clean: warn=%q err=%v", typ, warn, err)
		}
	}
}

func TestNetRecoveryDepVerifyUnknownAndCertStore(t *testing.T) {
	na := &NetAPIStruct{}
	if _, err := na.NetRecoveryDepVerify(cmn.RecoveryDependency{Type: "quantum-ledger", Required: true}); err == nil {
		t.Fatalf("verifier accepted a type it has no check for")
	}
	// cert-store: the cert domain apply owns per-cert digest verification.
	if warn, err := na.NetRecoveryDepVerify(cmn.RecoveryDependency{
		Type: cmn.RecoveryDepCertStore, Digest: "sha256:1111", Required: true}); err != nil || warn != "" {
		t.Fatalf("cert-store manifest entry must defer to the domain apply: warn=%q err=%v", warn, err)
	}
}
