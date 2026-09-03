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
