/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package schema defines the typed models and semantic validators for the
// three engine-contract trust artifacts:
//
//   - engine-contracts/contracts.yaml       (code-owned protocol profiles)
//   - engine-contracts/support-catalog.yaml (approval-owned support status)
//   - engine-contracts/observed-releases.json (bot-owned watcher snapshots)
//
// The three artifacts have deliberately different trust boundaries and
// never substitute for one another: a contract profile declares what is
// implementable, a catalog entry declares what a human approved for an
// exact identity tuple, and an observation records what upstream published.
//
// Parsing is strict (unknown fields are errors) and validation is
// deterministic: the same bytes always produce the same result. This
// package is pure Go with no CGO so it runs on every platform, including
// the generator (cmd/ecgen) and CI.
package schema

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"

	yaml "gopkg.in/yaml.v3"
)

// Schema version strings pinned by the artifacts.
const (
	ContractsSchemaVersion   = "engine-contracts.loxilb.io/v1alpha1"
	CatalogSchemaVersion     = "engine-support.loxilb.io/v1alpha1"
	ObservationSchemaVersion = "engine-observation.loxilb.io/v1alpha1"
)

// BindingNone is the reserved binding ID meaning "this engine has no such
// plane". It is always resolvable and must not be declared in the binding
// vocabularies.
const BindingNone = "none"

// Version selector schemes (DEC-002): typed min/max for semver identities,
// exact match for everything else (previews, build IDs, non-semver tags).
const (
	SelectorSemver = "semver"
	SelectorExact  = "exact"
)

// Capability keys form a closed set; an unknown capability is a validation
// error, never a silent no-op.
const (
	CapKvEvents     = "kvEvents"
	CapPrefixRoute  = "prefixRouting"
	CapPdRouting    = "pdRouting"
	CapRuntimeProbe = "runtimeProbe"
)

// Capability implementation values.
const (
	CapImplemented = "implemented"
	CapAdapter     = "adapter"
	CapNone        = "none"
)

// Promotion states (support catalog).
const (
	PromotionObserved   = "observed"
	PromotionCandidate  = "candidate"
	PromotionValidated  = "validated"
	PromotionBlocked    = "blocked"
	PromotionDeprecated = "deprecated"
)

// Evidence gate values. NotRun and NA never count as a pass.
const (
	EvidencePass   = "pass"
	EvidenceFail   = "fail"
	EvidenceNotRun = "not_run"
	EvidenceNA     = "n_a"
)

var knownEngines = map[string]bool{
	"vllm": true, "sglang": true, "trtllm": true, "llamacpp": true,
}

var knownCapabilities = map[string]bool{
	CapKvEvents: true, CapPrefixRoute: true, CapPdRouting: true, CapRuntimeProbe: true,
}

var knownCapValues = map[string]bool{
	CapImplemented: true, CapAdapter: true, CapNone: true,
}

var knownPromotions = map[string]bool{
	PromotionObserved: true, PromotionCandidate: true, PromotionValidated: true,
	PromotionBlocked: true, PromotionDeprecated: true,
}

var knownEvidence = map[string]bool{
	EvidencePass: true, EvidenceFail: true, EvidenceNotRun: true, EvidenceNA: true,
}

// idRe constrains profile and binding IDs: lowercase, digits, dot and
// hyphen, starting alphanumeric — stable, human-readable, and safe in
// metrics labels, file names, and generated identifiers.
var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)

// VersionSelector selects the engine versions a profile speaks for
// (DEC-002). Exactly one shape is valid per scheme: semver requires the
// inclusive bounds and forbids Exact; exact requires Exact and forbids the
// bounds.
type VersionSelector struct {
	Scheme       string `yaml:"scheme" json:"scheme"`
	MinInclusive string `yaml:"minInclusive,omitempty" json:"minInclusive,omitempty"`
	MaxInclusive string `yaml:"maxInclusive,omitempty" json:"maxInclusive,omitempty"`
	Exact        string `yaml:"exact,omitempty" json:"exact,omitempty"`
}

// Profile is one composed engine-contract profile: the unit a rule's
// engine-contract reference resolves to.
type Profile struct {
	ID            string            `yaml:"id" json:"id"`
	Engine        string            `yaml:"engine" json:"engine"`
	FamilyDefault bool              `yaml:"familyDefault,omitempty" json:"familyDefault,omitempty"`
	Versions      VersionSelector   `yaml:"versions" json:"versions"`
	Transport     string            `yaml:"transport" json:"transport"`
	WireSchema    string            `yaml:"wireSchema" json:"wireSchema"`
	HashBinding   string            `yaml:"hashBinding" json:"hashBinding"`
	PDDialect     string            `yaml:"pdDialect" json:"pdDialect"`
	Probe         string            `yaml:"probe" json:"probe"`
	Capabilities  map[string]string `yaml:"capabilities" json:"capabilities"`
}

// BindingVocab declares the closed binding vocabularies profiles may
// reference. The reserved ID "none" is implicit and must not appear here.
type BindingVocab struct {
	Transports   []string `yaml:"transports" json:"transports"`
	WireSchemas  []string `yaml:"wireSchemas" json:"wireSchemas"`
	HashBindings []string `yaml:"hashBindings" json:"hashBindings"`
	PDDialects   []string `yaml:"pdDialects" json:"pdDialects"`
	Probes       []string `yaml:"probes" json:"probes"`
}

// ContractsManifest is the parsed contracts.yaml.
type ContractsManifest struct {
	SchemaVersion string           `yaml:"schemaVersion" json:"schemaVersion"`
	Generation    uint64           `yaml:"generation" json:"generation"`
	EngineIDs     map[string]uint8 `yaml:"engineIds" json:"engineIds"`
	Bindings      BindingVocab     `yaml:"bindings" json:"bindings"`
	Profiles      []Profile        `yaml:"profiles" json:"profiles"`
}

// ParseContracts strictly decodes and semantically validates contracts.yaml.
func ParseContracts(doc []byte) (*ContractsManifest, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	dec.KnownFields(true)
	var m ContractsManifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("contracts: parse: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks the manifest's semantic invariants: schema version,
// generation, ID shapes and uniqueness, binding-reference resolution,
// selector validity, per-engine selector overlap, capability coherence,
// engine-ID coverage, and family-default uniqueness.
func (m *ContractsManifest) Validate() error {
	if m.SchemaVersion != ContractsSchemaVersion {
		return fmt.Errorf("contracts: schemaVersion %q (want %q)", m.SchemaVersion, ContractsSchemaVersion)
	}
	if m.Generation == 0 {
		return fmt.Errorf("contracts: generation must be >= 1")
	}
	seenID := map[string]uint8{}
	for eng, id := range m.EngineIDs {
		if !knownEngines[eng] {
			return fmt.Errorf("contracts: engineIds: unknown engine %q", eng)
		}
		for other, oid := range seenID {
			if oid == id {
				return fmt.Errorf("contracts: engineIds: %q and %q share wire ID %d", eng, other, id)
			}
		}
		seenID[eng] = id
	}
	vocab := map[string]map[string]bool{}
	for axis, ids := range map[string][]string{
		"transports": m.Bindings.Transports, "wireSchemas": m.Bindings.WireSchemas,
		"hashBindings": m.Bindings.HashBindings, "pdDialects": m.Bindings.PDDialects,
		"probes": m.Bindings.Probes,
	} {
		set := map[string]bool{}
		for _, id := range ids {
			if id == BindingNone {
				return fmt.Errorf("contracts: bindings.%s: %q is reserved", axis, BindingNone)
			}
			if !idRe.MatchString(id) {
				return fmt.Errorf("contracts: bindings.%s: invalid ID %q", axis, id)
			}
			if set[id] {
				return fmt.Errorf("contracts: bindings.%s: duplicate ID %q", axis, id)
			}
			set[id] = true
		}
		vocab[axis] = set
	}
	if len(m.Profiles) == 0 {
		return fmt.Errorf("contracts: no profiles declared")
	}
	profIDs := map[string]bool{}
	familyDefault := map[string]string{}
	byEngine := map[string][]*Profile{}
	for i := range m.Profiles {
		p := &m.Profiles[i]
		if err := p.validate(vocab); err != nil {
			return err
		}
		if profIDs[p.ID] {
			return fmt.Errorf("contracts: duplicate profile ID %q", p.ID)
		}
		profIDs[p.ID] = true
		if p.FamilyDefault {
			if prev, dup := familyDefault[p.Engine]; dup {
				return fmt.Errorf("contracts: engine %q has two familyDefault profiles (%q, %q)",
					p.Engine, prev, p.ID)
			}
			familyDefault[p.Engine] = p.ID
		}
		if p.Capabilities[CapPdRouting] != CapNone {
			if _, ok := m.EngineIDs[p.Engine]; !ok {
				return fmt.Errorf("contracts: profile %q routes P/D but engine %q has no wire ID", p.ID, p.Engine)
			}
		}
		byEngine[p.Engine] = append(byEngine[p.Engine], p)
	}
	for eng, profs := range byEngine {
		for i := 0; i < len(profs); i++ {
			for j := i + 1; j < len(profs); j++ {
				overlap, err := selectorsOverlap(profs[i].Versions, profs[j].Versions)
				if err != nil {
					return fmt.Errorf("contracts: engine %q: %w", eng, err)
				}
				if overlap {
					return fmt.Errorf("contracts: engine %q: profiles %q and %q have overlapping version selectors",
						eng, profs[i].ID, profs[j].ID)
				}
			}
		}
	}
	return nil
}

func (p *Profile) validate(vocab map[string]map[string]bool) error {
	if !idRe.MatchString(p.ID) {
		return fmt.Errorf("contracts: invalid profile ID %q", p.ID)
	}
	if !knownEngines[p.Engine] {
		return fmt.Errorf("contracts: profile %q: unknown engine %q", p.ID, p.Engine)
	}
	if err := p.Versions.validate(); err != nil {
		return fmt.Errorf("contracts: profile %q: %w", p.ID, err)
	}
	for axis, ref := range map[string]string{
		"transports": p.Transport, "wireSchemas": p.WireSchema,
		"hashBindings": p.HashBinding, "pdDialects": p.PDDialect, "probes": p.Probe,
	} {
		if ref == BindingNone {
			continue
		}
		if !vocab[axis][ref] {
			return fmt.Errorf("contracts: profile %q: dangling %s reference %q", p.ID, axis, ref)
		}
	}
	if len(p.Capabilities) == 0 {
		return fmt.Errorf("contracts: profile %q: capabilities required", p.ID)
	}
	for cap, val := range p.Capabilities {
		if !knownCapabilities[cap] {
			return fmt.Errorf("contracts: profile %q: unknown capability %q", p.ID, cap)
		}
		if !knownCapValues[val] {
			return fmt.Errorf("contracts: profile %q: capability %q has unknown value %q", p.ID, cap, val)
		}
	}
	for _, cap := range []string{CapKvEvents, CapPrefixRoute, CapPdRouting, CapRuntimeProbe} {
		if _, ok := p.Capabilities[cap]; !ok {
			return fmt.Errorf("contracts: profile %q: capability %q must be declared explicitly", p.ID, cap)
		}
	}
	// Coherence: the event/hash planes exist together or not at all, and a
	// declared plane needs its bindings (an absent plane forbids them).
	kvNone := p.Capabilities[CapKvEvents] == CapNone
	for name, ref := range map[string]string{
		"transport": p.Transport, "wireSchema": p.WireSchema, "hashBinding": p.HashBinding,
	} {
		if kvNone && ref != BindingNone {
			return fmt.Errorf("contracts: profile %q: kvEvents=none but %s=%q", p.ID, name, ref)
		}
		if !kvNone && ref == BindingNone {
			return fmt.Errorf("contracts: profile %q: kvEvents declared but %s=none", p.ID, name)
		}
	}
	pdNone := p.Capabilities[CapPdRouting] == CapNone
	if pdNone && p.PDDialect != BindingNone {
		return fmt.Errorf("contracts: profile %q: pdRouting=none but pdDialect=%q", p.ID, p.PDDialect)
	}
	if !pdNone && p.PDDialect == BindingNone {
		return fmt.Errorf("contracts: profile %q: pdRouting declared but pdDialect=none", p.ID)
	}
	probeNone := p.Capabilities[CapRuntimeProbe] == CapNone
	if probeNone && p.Probe != BindingNone {
		return fmt.Errorf("contracts: profile %q: runtimeProbe=none but probe=%q", p.ID, p.Probe)
	}
	if !probeNone && p.Probe == BindingNone {
		return fmt.Errorf("contracts: profile %q: runtimeProbe declared but probe=none", p.ID)
	}
	return nil
}

func (v *VersionSelector) validate() error {
	switch v.Scheme {
	case SelectorSemver:
		if v.Exact != "" {
			return fmt.Errorf("semver selector must not set exact")
		}
		if v.MinInclusive == "" || v.MaxInclusive == "" {
			return fmt.Errorf("semver selector requires minInclusive and maxInclusive")
		}
		lo, err := parseSemver(v.MinInclusive)
		if err != nil {
			return fmt.Errorf("minInclusive: %w", err)
		}
		hi, err := parseSemver(v.MaxInclusive)
		if err != nil {
			return fmt.Errorf("maxInclusive: %w", err)
		}
		if compareSemver(lo, hi) > 0 {
			return fmt.Errorf("minInclusive %s > maxInclusive %s", v.MinInclusive, v.MaxInclusive)
		}
		return nil
	case SelectorExact:
		if v.MinInclusive != "" || v.MaxInclusive != "" {
			return fmt.Errorf("exact selector must not set min/max")
		}
		if v.Exact == "" {
			return fmt.Errorf("exact selector requires exact")
		}
		return nil
	default:
		return fmt.Errorf("selector scheme %q must be %q or %q", v.Scheme, SelectorSemver, SelectorExact)
	}
}

// Matches reports whether a version string satisfies the selector. For a
// semver selector, an unparseable candidate never matches (fail closed).
func (v *VersionSelector) Matches(version string) bool {
	switch v.Scheme {
	case SelectorExact:
		return version == v.Exact
	case SelectorSemver:
		c, err := parseSemver(version)
		if err != nil {
			return false
		}
		lo, err1 := parseSemver(v.MinInclusive)
		hi, err2 := parseSemver(v.MaxInclusive)
		if err1 != nil || err2 != nil {
			return false
		}
		return compareSemver(c, lo) >= 0 && compareSemver(c, hi) <= 0
	default:
		return false
	}
}

// selectorsOverlap reports whether two validated selectors can match the
// same version — forbidden within one engine so resolution stays
// deterministic (the same identity always resolves to one profile).
func selectorsOverlap(a, b VersionSelector) (bool, error) {
	if a.Scheme == SelectorExact && b.Scheme == SelectorExact {
		return a.Exact == b.Exact, nil
	}
	if a.Scheme == SelectorExact {
		return b.Matches(a.Exact), nil
	}
	if b.Scheme == SelectorExact {
		return a.Matches(b.Exact), nil
	}
	aLo, err := parseSemver(a.MinInclusive)
	if err != nil {
		return false, err
	}
	aHi, _ := parseSemver(a.MaxInclusive)
	bLo, err := parseSemver(b.MinInclusive)
	if err != nil {
		return false, err
	}
	bHi, _ := parseSemver(b.MaxInclusive)
	return compareSemver(aLo, bHi) <= 0 && compareSemver(bLo, aHi) <= 0, nil
}

// ProfileByID returns the named profile.
func (m *ContractsManifest) ProfileByID(id string) (*Profile, bool) {
	for i := range m.Profiles {
		if m.Profiles[i].ID == id {
			return &m.Profiles[i], true
		}
	}
	return nil, false
}

// FamilyDefault returns the engine family's default profile — the profile
// a contract reference resolved by family alone binds to. Engines whose
// profiles all lack familyDefault (e.g. a no-KV engine) return false.
func (m *ContractsManifest) FamilyDefault(engine string) (*Profile, bool) {
	for i := range m.Profiles {
		if m.Profiles[i].Engine == engine && m.Profiles[i].FamilyDefault {
			return &m.Profiles[i], true
		}
	}
	return nil, false
}

// ResolveVersion deterministically resolves (engine, version) to the single
// profile whose selector matches. Zero matches is an error (fail closed;
// DEC-004) and — with overlap validation — more than one is impossible.
func (m *ContractsManifest) ResolveVersion(engine, version string) (*Profile, error) {
	var found *Profile
	for i := range m.Profiles {
		p := &m.Profiles[i]
		if p.Engine == engine && p.Versions.Matches(version) {
			found = p
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no contract profile for engine %q version %q", engine, version)
	}
	return found, nil
}

// SortedProfileIDs returns the profile IDs in sorted order (deterministic
// generation and digesting).
func (m *ContractsManifest) SortedProfileIDs() []string {
	ids := make([]string, 0, len(m.Profiles))
	for i := range m.Profiles {
		ids = append(ids, m.Profiles[i].ID)
	}
	sort.Strings(ids)
	return ids
}
