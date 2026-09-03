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
