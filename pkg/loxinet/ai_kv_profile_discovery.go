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

/*
 * ai_kv_profile_discovery.go — read-only discovery projection of the
 * published model-profile registry (served by the REST discovery API).
 *
 * The projection deliberately excludes every host-filesystem detail of a
 * profile: KvProfileDir, the generation's source root, and the
 * TokenizerArtifact/TemplateArtifact locators never leave this process —
 * the pinned sha256 digests are the only artifact identities a client gets.
 *
 * Discovery is a CACHE, never an admission authority: lookups ride the same
 * lock-free kvProfileReg.Load() the serving path uses, and a registry reload
 * can swap the generation between a discovery read and a rule POST. Rule
 * admission re-validates against the generation current at POST time; clients
 * detect the swap by comparing registryGeneration/setDigest with the
 * kvexactstatus read-back after create.
 */

package loxinet

import (
	"sort"

	cmn "github.com/loxilb-io/loxilb/common"
)

// kvProfileDiscoveryEntry projects one published entry onto the wire read
// model. Slices are copied: published entries are immutable and shared with
// the serving path, so the projection must never hand a caller an aliased
// slice it could mutate.
func kvProfileDiscoveryEntry(e *kvProfileEntry) cmn.AiModelProfileMod {
	p := &e.Profile
	m := cmn.AiModelProfileMod{
		ProfileID:             p.ProfileID,
		Gen:                   e.Gen,
		BaseModel:             p.BaseModel,
		AliasPolicy:           p.AliasPolicy,
		TokenizerRevision:     p.TokenizerRevision,
		TokenizerSha256:       p.TokenizerSha256,
		TemplateSha256:        p.TemplateSha256,
		TemplateContentFormat: p.TemplateContentFormat,
		RendererEngine:        p.RendererEngine,
		RendererVersion:       p.RendererVersion,
		OracleEngine:          p.OracleEngine,
		OracleVersion:         p.OracleVersion,
	}
	if len(p.AllowedAliases) > 0 {
		m.AllowedAliases = append([]string(nil), p.AllowedAliases...)
	}
	if len(p.SupportedApis) > 0 {
		m.SupportedApis = append([]string(nil), p.SupportedApis...)
	}
	if len(p.SupportedFeatures) > 0 {
		m.SupportedFeatures = append([]string(nil), p.SupportedFeatures...)
	}
	if len(p.ExcludedFeatures) > 0 {
		m.ExcludedFeatures = append([]string(nil), p.ExcludedFeatures...)
	}
	return m
}

// KvProfileDiscovery returns the currently published registry generation as
// the discovery envelope: profiles ordered by ProfileID ascending, generation
// 0 with an empty (non-nil) set when no registry is published — the
// documented legacy-mode answer, not an error.
func KvProfileDiscovery() cmn.AiModelProfileRegistryMod {
	res := cmn.AiModelProfileRegistryMod{
		Profiles: []cmn.AiModelProfileMod{},
	}
	g := kvProfileReg.Load()
	if g == nil {
		return res
	}
	res.RegistryGeneration = g.Gen
	res.SetDigest = g.SetDigest
	ids := make([]string, 0, len(g.Profiles))
	for id := range g.Profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		res.Profiles = append(res.Profiles, kvProfileDiscoveryEntry(g.Profiles[id]))
	}
	return res
}

// KvProfileDiscoveryByID returns one published profile by id;
// cmn.ErrAiModelProfileNotFound when the id is absent from the published
// generation or no generation is published.
func KvProfileDiscoveryByID(profileID string) (cmn.AiModelProfileMod, error) {
	e, ok := kvProfileByID(profileID)
	if !ok {
		return cmn.AiModelProfileMod{}, cmn.ErrAiModelProfileNotFound
	}
	return kvProfileDiscoveryEntry(e), nil
}
