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

package schema

// catalog.go — the approval-owned support catalog and the bot-owned
// observed-releases artifacts. Both are parsed strictly; the catalog is
// additionally cross-validated against the contracts manifest so a support
// claim can never reference a profile that does not exist or a version its
// profile does not select.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	yaml "gopkg.in/yaml.v3"
)

// CatalogImage pins the engine artifact identity (OCI digests).
type CatalogImage struct {
	IndexDigest    string `yaml:"indexDigest,omitempty" json:"indexDigest,omitempty"`
	PlatformDigest string `yaml:"platformDigest,omitempty" json:"platformDigest,omitempty"`
}

// EvidenceGates records the four evidence classes per capability
// (source, fixture, synthetic, real engine). not_run and n_a never count
// as pass.
type EvidenceGates struct {
	Source     string `yaml:"source" json:"source"`
	Fixture    string `yaml:"fixture" json:"fixture"`
	Synthetic  string `yaml:"synthetic" json:"synthetic"`
	RealEngine string `yaml:"realEngine" json:"realEngine"`
}

// CapabilitySupport is one capability's implementation kind plus its
// evidence gates.
type CapabilitySupport struct {
	Implementation string        `yaml:"implementation" json:"implementation"`
	Evidence       EvidenceGates `yaml:"evidence" json:"evidence"`
}

// CatalogEntry is one exact identity tuple's approved support state.
type CatalogEntry struct {
	Engine         string                       `yaml:"engine" json:"engine"`
	Version        string                       `yaml:"version" json:"version"`
	Revision       string                       `yaml:"revision" json:"revision"`
	Image          CatalogImage                 `yaml:"image,omitempty" json:"image,omitempty"`
	GatewayRelease string                       `yaml:"gatewayRelease" json:"gatewayRelease"`
	Profile        string                       `yaml:"profile" json:"profile"`
	Promotion      string                       `yaml:"promotion" json:"promotion"`
	Capabilities   map[string]CapabilitySupport `yaml:"capabilities" json:"capabilities"`
	EvidenceBundle string                       `yaml:"evidenceBundle,omitempty" json:"evidenceBundle,omitempty"`
}

// SupportCatalog is the parsed support-catalog.yaml.
type SupportCatalog struct {
	SchemaVersion string         `yaml:"schemaVersion" json:"schemaVersion"`
	Entries       []CatalogEntry `yaml:"entries" json:"entries"`
}

var sha256DigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ParseCatalog strictly decodes and validates support-catalog.yaml against
// its contracts manifest.
func ParseCatalog(doc []byte, contracts *ContractsManifest) (*SupportCatalog, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	dec.KnownFields(true)
	var c SupportCatalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("catalog: parse: %w", err)
	}
	if err := c.Validate(contracts); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks catalog invariants and cross-references every entry
// against the contracts manifest.
func (c *SupportCatalog) Validate(contracts *ContractsManifest) error {
	if c.SchemaVersion != CatalogSchemaVersion {
		return fmt.Errorf("catalog: schemaVersion %q (want %q)", c.SchemaVersion, CatalogSchemaVersion)
	}
	seen := map[string]bool{}
	for i := range c.Entries {
		e := &c.Entries[i]
		if !knownEngines[e.Engine] {
			return fmt.Errorf("catalog: entry %d: unknown engine %q", i, e.Engine)
		}
		if e.Version == "" {
			return fmt.Errorf("catalog: entry %d: version required", i)
		}
		if !knownPromotions[e.Promotion] {
			return fmt.Errorf("catalog: %s/%s: unknown promotion %q", e.Engine, e.Version, e.Promotion)
		}
		p, ok := contracts.ProfileByID(e.Profile)
		if !ok {
			return fmt.Errorf("catalog: %s/%s: unknown profile %q", e.Engine, e.Version, e.Profile)
		}
		if p.Engine != e.Engine {
			return fmt.Errorf("catalog: %s/%s: profile %q belongs to engine %q", e.Engine, e.Version, e.Profile, p.Engine)
		}
		if !p.Versions.Matches(e.Version) {
			return fmt.Errorf("catalog: %s/%s: version outside profile %q selector", e.Engine, e.Version, e.Profile)
		}
		key := e.Engine + "\x00" + e.Version + "\x00" + e.Revision + "\x00" + e.Profile
		if seen[key] {
			return fmt.Errorf("catalog: duplicate tuple %s/%s profile %q", e.Engine, e.Version, e.Profile)
		}
		seen[key] = true
		if len(e.Capabilities) == 0 {
			return fmt.Errorf("catalog: %s/%s: capabilities required", e.Engine, e.Version)
		}
		for cap, cs := range e.Capabilities {
			if !knownCapabilities[cap] {
				return fmt.Errorf("catalog: %s/%s: unknown capability %q", e.Engine, e.Version, cap)
			}
			if cs.Implementation != "native" && cs.Implementation != CapAdapter && cs.Implementation != CapNone {
				return fmt.Errorf("catalog: %s/%s: capability %q implementation %q not in {native, adapter, none}",
					e.Engine, e.Version, cap, cs.Implementation)
			}
			for gate, val := range map[string]string{
				"source": cs.Evidence.Source, "fixture": cs.Evidence.Fixture,
				"synthetic": cs.Evidence.Synthetic, "realEngine": cs.Evidence.RealEngine,
			} {
				if !knownEvidence[val] {
					return fmt.Errorf("catalog: %s/%s: capability %q evidence %s=%q invalid",
						e.Engine, e.Version, cap, gate, val)
				}
			}
			// A declared implementation must not carry n_a gates, and an
			// absent one must carry ONLY n_a — evidence for a plane that
			// does not exist would be a fabricated claim.
			if cs.Implementation == CapNone {
				if cs.Evidence != (EvidenceGates{EvidenceNA, EvidenceNA, EvidenceNA, EvidenceNA}) {
					return fmt.Errorf("catalog: %s/%s: capability %q implementation none requires all-n_a evidence",
						e.Engine, e.Version, cap)
				}
			}
		}
		if e.Promotion == PromotionValidated {
			if e.Revision == "" {
				return fmt.Errorf("catalog: %s/%s: validated requires an exact upstream revision", e.Engine, e.Version)
			}
			if !sha256DigestRe.MatchString(e.Image.PlatformDigest) {
				return fmt.Errorf("catalog: %s/%s: validated requires an image platformDigest", e.Engine, e.Version)
			}
			if e.EvidenceBundle == "" {
				return fmt.Errorf("catalog: %s/%s: validated requires an evidence bundle reference", e.Engine, e.Version)
			}
			for cap, cs := range e.Capabilities {
				if cs.Implementation == CapNone {
					continue
				}
				if cs.Evidence.RealEngine != EvidencePass {
					return fmt.Errorf("catalog: %s/%s: validated but capability %q realEngine=%q (not pass)",
						e.Engine, e.Version, cap, cs.Evidence.RealEngine)
				}
			}
		}
	}
	return nil
}

// ObservedRelease is one watcher observation. Observations are never
// compiled and never used for admission.
type ObservedRelease struct {
	Engine               string            `json:"engine"`
	Version              string            `json:"version"`
	Revision             string            `json:"revision,omitempty"`
	ReleaseURL           string            `json:"releaseUrl"`
	ContractFingerprints map[string]string `json:"contractFingerprints,omitempty"`
	Classification       string            `json:"classification"`
}

// ObservedReleases is the parsed observed-releases.json.
type ObservedReleases struct {
	SchemaVersion string            `json:"schemaVersion"`
	ObservedAt    string            `json:"observedAt"`
	Releases      []ObservedRelease `json:"releases"`
}

var knownClassifications = map[string]bool{
	"review-required": true, "informational": true,
}

// ParseObserved strictly decodes and validates observed-releases.json.
func ParseObserved(doc []byte) (*ObservedReleases, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var o ObservedReleases
	if err := dec.Decode(&o); err != nil {
		return nil, fmt.Errorf("observed: parse: %w", err)
	}
	if o.SchemaVersion != ObservationSchemaVersion {
		return nil, fmt.Errorf("observed: schemaVersion %q (want %q)", o.SchemaVersion, ObservationSchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339, o.ObservedAt); err != nil {
		return nil, fmt.Errorf("observed: observedAt: %w", err)
	}
	for i, r := range o.Releases {
		if !knownEngines[r.Engine] {
			return nil, fmt.Errorf("observed: release %d: unknown engine %q", i, r.Engine)
		}
		if r.Version == "" || r.ReleaseURL == "" {
			return nil, fmt.Errorf("observed: release %d: version and releaseUrl required", i)
		}
		if !knownClassifications[r.Classification] {
			return nil, fmt.Errorf("observed: release %d: unknown classification %q", i, r.Classification)
		}
	}
	return &o, nil
}
