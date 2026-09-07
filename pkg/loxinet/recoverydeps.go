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

// recoverydeps.go — NetHookInterface producer for the snapshot document's
// recovery_dependencies manifest (common/recoverydep.go): the identity of
// every external store this gateway is wired to, read at capture time.
// Identity only — generations and digests, never store content or
// credentials. Required flags for the environment-scoped stores (the
// databases) are decided here, where the wiring is known; the
// document-content-scoped flags (contracts/profiles, needed only when the
// captured document carries kvexactbinding entries) are decided by the
// capture path, which sees the document.

package loxinet

import (
	"fmt"
	"sort"
	"strconv"

	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/enginecontract"
	"github.com/loxilb-io/loxilb/pkg/user"
)

// NetRecoveryDepsGet - the external-store identities of this gateway. The
// engine-contract registry is compiled into the binary, so its entry is
// unconditional; the others appear only when the corresponding store is
// actually wired (a published kv-profile generation, a configured
// database). No BgpPeerMode guard: the identities are process facts, and
// capture never runs in peer mode anyway.
func (na *NetAPIStruct) NetRecoveryDepsGet() ([]cmn.RecoveryDependency, error) {
	deps := []cmn.RecoveryDependency{{
		Type:       cmn.RecoveryDepEngineContracts,
		ID:         enginecontract.SchemaVersion,
		Generation: strconv.FormatUint(enginecontract.Generation, 10),
		Digest:     enginecontract.ManifestDigest,
	}}
	if g := kvProfileCurrent(); g != nil {
		deps = append(deps, cmn.RecoveryDependency{
			Type:       cmn.RecoveryDepKvModelProfiles,
			ID:         g.SourceRoot,
			Generation: strconv.FormatUint(g.Gen, 10),
			// kvProfileSetDigest is bare hex; the manifest carries the
			// algorithm-prefixed form every other digest field uses.
			Digest: "sha256:" + g.SetDigest,
		})
	}
	if opts.Opts.AIKeyDBHost != "" {
		deps = append(deps, cmn.RecoveryDependency{
			Type:     cmn.RecoveryDepAPIKeyDB,
			ID:       opts.Opts.AIKeyDBName,
			Required: true,
		})
	}
	if opts.Opts.UserServiceEnable {
		deps = append(deps, cmn.RecoveryDependency{
			Type:     cmn.RecoveryDepAuthDB,
			ID:       user.Schema,
			Required: true,
		})
	}
	return deps, nil
}

// NetRecoveryDepVerify - check one REQUIRED recovery dependency against
// this node's actual stores, before the restore engine plans or wipes
// anything. Error = the declared-load-bearing store is genuinely absent or
// incompatible: fail the restore closed. Warning = wired but currently
// degraded, or a difference the per-item apply re-verifies anyway: surface
// it, do not block.
//
// The database checks are deliberately configuration-only. Both stores
// dial in the background ON PURPOSE (loxinet.go: a store that is down
// blocks for over a minute, and the boot snapshot restore must not
// inherit the management store's outage -- auth answers 503 and the
// reconnect tick heals it). Gating restore on live reachability would
// re-create exactly that hostage-taking; what restore needs to know is
// whether the store exists at all on this node. Reachability/readiness
// get their own surface with the boot status API.
func (na *NetAPIStruct) NetRecoveryDepVerify(dep cmn.RecoveryDependency) (string, error) {
	switch dep.Type {
	case cmn.RecoveryDepEngineContracts:
		docGen, err := strconv.ParseUint(dep.Generation, 10, 64)
		if err != nil {
			return "", fmt.Errorf("malformed generation %q: %v", dep.Generation, err)
		}
		if docGen > enginecontract.Generation {
			return "", fmt.Errorf("document requires engine-contract generation %d; this build compiles generation %d -- upgrade the gateway or re-capture",
				docGen, enginecontract.Generation)
		}
		if docGen == enginecontract.Generation && dep.Digest != "" && dep.Digest != enginecontract.ManifestDigest {
			return "", fmt.Errorf("engine-contract generation %d digest %s does not match this build's %s -- the registry was rebuilt without a generation bump",
				docGen, dep.Digest, enginecontract.ManifestDigest)
		}
		if docGen < enginecontract.Generation {
			return fmt.Sprintf("captured under engine-contract generation %d, this build compiles %d; restored bindings re-earn attestation against the current registry",
				docGen, enginecontract.Generation), nil
		}
		return "", nil

	case cmn.RecoveryDepKvModelProfiles:
		g := kvProfileCurrent()
		if g == nil {
			return "", fmt.Errorf("no model-profile registry generation is published on this node; provision the profile directory before restoring KV-bound configuration")
		}
		// Re-verify the published generation's artifacts against disk:
		// the registry serves from memory, so this is the moment silent
		// on-disk drift would otherwise ride into a restored config.
		for _, id := range kvProfileSortedIDs(g) {
			if err := KvProfileVerifyDisk(id); err != nil {
				return "", fmt.Errorf("published profile %q no longer matches its on-disk artifacts: %v", id, err)
			}
		}
		// A different set digest is NOT a failure: a legitimate restore
		// target may carry more (or newer) profiles than the capture
		// node. Per-binding references verify individually at apply.
		if dep.Digest != "" && dep.Digest != "sha256:"+g.SetDigest {
			return fmt.Sprintf("profile set digest differs from capture (%s vs sha256:%s); per-binding verification decides compatibility",
				dep.Digest, g.SetDigest), nil
		}
		return "", nil

	case cmn.RecoveryDepAPIKeyDB:
		if opts.Opts.AIKeyDBHost == "" {
			return "", fmt.Errorf("document requires the data-plane API-key store but none is configured on this node")
		}
		return "", nil

	case cmn.RecoveryDepAuthDB:
		if !opts.Opts.UserServiceEnable {
			return "", fmt.Errorf("document requires the management user/auth store but the user service is not enabled on this node")
		}
		return "", nil

	case cmn.RecoveryDepCertStore:
		// Verified where the authority is: the cert domain apply
		// re-registers each certificate only after checking the managed
		// on-disk material against the captured per-cert digest, failing
		// loudly on missing or divergent material. The manifest's set
		// digest adds nothing that check does not already prove.
		return "", nil

	default:
		// VALIDATE already refused unknown REQUIRED types; reaching here
		// means the engine and the vocabulary disagree -- fail closed.
		return "", fmt.Errorf("no verifier for dependency type %q", dep.Type)
	}
}

// NetRecoveryDepReady - one dependency type's LIVE availability, for the
// readiness surface (GET /status/ready). This is where reachability
// belongs: NetRecoveryDepVerify keeps its configured-only database checks
// so a store outage never holds a restore hostage, while readiness
// truthfully reports that same outage.
func (na *NetAPIStruct) NetRecoveryDepReady(depType string) error {
	switch depType {
	case cmn.RecoveryDepEngineContracts:
		// Compiled into the binary: present by construction.
		return nil

	case cmn.RecoveryDepKvModelProfiles:
		if kvProfileCurrent() == nil {
			return fmt.Errorf("no model-profile registry generation is published")
		}
		return nil

	case cmn.RecoveryDepAPIKeyDB:
		if mh.AIKeyService == nil {
			return fmt.Errorf("data-plane API-key store not initialized")
		}
		if err := mh.AIKeyService.Ready(); err != nil {
			return fmt.Errorf("data-plane API-key store not answering: %v", err)
		}
		return nil

	case cmn.RecoveryDepAuthDB:
		if mh.UserService == nil {
			return fmt.Errorf("management auth store not initialized")
		}
		if err := mh.UserService.Ready(); err != nil {
			return fmt.Errorf("management auth store not answering: %v", err)
		}
		return nil

	case cmn.RecoveryDepCertStore:
		// Node-local directory; per-cert digests are the apply-time
		// authority and there is no liveness to probe.
		return nil

	default:
		return fmt.Errorf("no readiness probe for dependency type %q", depType)
	}
}

// kvProfileSortedIDs returns the generation's profile IDs sorted, so
// verification failures report deterministically.
func kvProfileSortedIDs(g *kvProfileGeneration) []string {
	ids := make([]string, 0, len(g.Profiles))
	for id := range g.Profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
