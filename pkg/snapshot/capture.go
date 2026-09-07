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
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	cmn "github.com/loxilb-io/loxilb/common"
)

// Capture builds a snapshot Document of the live configuration for the
// selected components (nil/empty = every v1 domain), in registry apply
// order. It is the GET /config/snapshot capture path (task G-3) and the
// write-through persist source (task G-5); the restore engine's PRESERVE
// stage does the same walk internally over its own selection.
//
// The returned document's Checksum is unset -- Encode computes it while
// producing the canonical wire form.
func Capture(hooks Hooks, gatewayVersion, hostname string, trigger Trigger, components []string) (*Document, error) {
	selected, err := Select(components)
	if err != nil {
		return nil, err
	}
	doc := NewDocument(gatewayVersion, hostname, trigger)
	// Declare exactly what this document covers: restore selection is
	// derived from included_domains, so a components-filtered capture must
	// not claim (and a later restore must not wipe) domains it never read.
	doc.IncludedDomains = entryNames(selected)
	for _, entry := range selected {
		if err := entry.Get(hooks, doc); err != nil {
			return nil, fmt.Errorf("capture %s: %w", entry.Name, err)
		}
	}
	// Canonicalize (digest.go): strip runtime measurement fields and sort
	// every list, so a captured document carries desired state only and
	// an unchanged gateway always captures the identical payload --
	// map-ordered backend enumeration must not churn persisted checksums.
	if err := NormalizeDomains(&doc.Domains); err != nil {
		return nil, fmt.Errorf("capture: normalize: %w", err)
	}
	// Declare the §6 recovery_dependencies manifest (schema 1.4). A
	// capture that cannot determine its dependency identities would
	// produce a document claiming independence it does not have -- fail
	// the capture rather than record a dishonest manifest.
	deps, err := hooks.NetRecoveryDepsGet()
	if err != nil {
		return nil, fmt.Errorf("capture: recovery dependencies: %w", err)
	}
	doc.RecoveryDependencies = buildRecoveryManifest(doc, deps)
	snapshotTotal.WithLabelValues(string(trigger)).Inc()
	return doc, nil
}

// buildRecoveryManifest turns the hooks' store identities into the
// document's recovery_dependencies manifest. The hooks own the
// environment-scoped required flags (a configured database is required by
// virtue of being wired); this function owns the document-content-scoped
// ones -- the contract/profile registries are required exactly when the
// captured document carries kvexactbinding entries that reference their
// generations -- and derives the cert-store summary entry from the
// captured cert domain. Entries are sorted by (type, id) so an unchanged
// gateway captures an identical manifest (same determinism contract as
// NormalizeDomains).
func buildRecoveryManifest(doc *Document, deps []cmn.RecoveryDependency) []cmn.RecoveryDependency {
	out := make([]cmn.RecoveryDependency, 0, len(deps)+1)
	bindingsCaptured := len(doc.Domains.KvExactBinding) > 0
	for _, d := range deps {
		switch d.Type {
		case cmn.RecoveryDepEngineContracts, cmn.RecoveryDepKvModelProfiles:
			d.Required = bindingsCaptured
		}
		out = append(out, d)
	}
	if len(doc.Domains.Cert) > 0 {
		out = append(out, cmn.RecoveryDependency{
			Type:     cmn.RecoveryDepCertStore,
			Digest:   certSetDigest(doc.Domains.Cert),
			Required: true,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// certSetDigest summarizes the captured cert domain for the manifest:
// sha256 over the sorted (id, digest) pairs. The domain entries carry the
// authoritative per-cert digests restore verifies against disk; this is
// the set-level identity a manifest reader compares.
func certSetDigest(certs []cmn.CertMeta) string {
	ids := make([]string, 0, len(certs))
	byID := make(map[string]string, len(certs))
	for _, c := range certs {
		ids = append(ids, c.CertId)
		byID[c.CertId] = c.Digest
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		fmt.Fprintf(h, "%s\x00%s\x00", id, byID[id])
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
