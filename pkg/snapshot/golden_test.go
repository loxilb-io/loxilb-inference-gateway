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

// Byte-golden on-disk snapshot fixtures, one per schema version
// (testdata/snapshot-v*.json). Two guarantees:
//
//  1. The CURRENT schema's golden must byte-equal Encode() of the pinned
//     fixture document -- any canonical-encoding drift (field order,
//     checksum recipe, added field) turns the diff into a reviewed,
//     deliberate `go test -run TestGolden -update` regeneration instead
//     of a silent format change that strands existing snapshot.json files.
//  2. OLDER schemas' goldens are decoded, checksum-verified, migrated and
//     dry-run-restored on every run -- the files a gateway wrote last year
//     must keep restoring on today's build.

package snapshot

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

var updateGolden = flag.Bool("update", false, "regenerate golden snapshot fixtures in testdata/")

// goldenDocument is the deterministic fixture: pinned timestamp, pinned
// identity, at least one item in every domain (kvexactbinding included).
func goldenDocument() *Document {
	doc := sampleDocument()
	doc.CreatedAt = time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	doc.GatewayVersion = "golden-fixture"
	doc.Hostname = "golden-host"
	return doc
}

// legacyGoldenDocument reshapes the fixture into what a gateway of the
// given older schema actually wrote: no fields the schema predates, and
// the excluded_domains honesty list of that era.
func legacyGoldenDocument(schemaVersion string) *Document {
	doc := goldenDocument()
	doc.SchemaVersion = schemaVersion
	doc.Domains.L7Policy = nil // predates 1.3
	doc.Domains.CORS = nil     // predates 1.3
	doc.Domains.Tracing = nil  // predates 1.3
	doc.Domains.Cert = nil     // predates 1.3
	if schemaVersion == "1.2" {
		// 1.2 declared coverage explicitly (the 13 pre-1.3 domains) and
		// derived its exclusion list at a time l7policy was unpersisted.
		doc.IncludedDomains = []string{
			DomainEndpoint, DomainLoadBalancer, DomainKvExactBinding,
			DomainFirewall, DomainPolicy, DomainMirror, DomainSession,
			DomainSessionUlCl, DomainIPFilter, DomainSecurityRate,
			DomainBFD, DomainBGP, DomainIPsec,
		}
		doc.ExcludedDomains = []string{
			"ai_keys", "ai_ratelimit", "auth_users", "cert", "cluster",
			"cors", "gpu_mode", "interface", "l7policy", "llamafirewall",
			"metrics", "opa", "params", "pii", "tracing",
		}
		return doc
	}
	doc.IncludedDomains = nil // predates 1.2
	doc.ExcludedDomains = []string{"cluster", "conntrack", "ai_keys", "interface"}
	if schemaVersion == "1.0" {
		doc.Domains.KvExactBinding = nil // predates 1.1
	}
	return doc
}

func goldenPath(version string) string {
	return filepath.Join("testdata", "snapshot-v"+version+".json")
}

func writeOrCompareGolden(t *testing.T, doc *Document, version string) {
	t.Helper()
	enc, err := Encode(doc)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	path := goldenPath(version)
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, enc, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("regenerated %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (regenerate with -update after a DELIBERATE schema/encoding change): %v", path, err)
	}
	if !bytes.Equal(enc, want) {
		t.Fatalf("canonical encoding drifted from golden %s -- if the change is deliberate (schema bump, field addition), regenerate with -update and review the diff", path)
	}
}

// TestGoldenCurrentSchema pins the current schema's byte encoding.
func TestGoldenCurrentSchema(t *testing.T) {
	writeOrCompareGolden(t, goldenDocument(), SchemaVersion)
}

// TestGoldenLegacySchemas: every older-schema golden still decodes,
// verifies, migrates to the current schema, and passes a dry-run restore.
func TestGoldenLegacySchemas(t *testing.T) {
	legacy := []string{"1.0", "1.1", "1.2"}
	for _, version := range legacy {
		version := version
		t.Run("v"+version, func(t *testing.T) {
			writeOrCompareGolden(t, legacyGoldenDocument(version), version)
			if *updateGolden {
				return
			}
			raw, err := os.ReadFile(goldenPath(version))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}

			doc, err := Decode(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if err := VerifyChecksum(doc); err != nil {
				t.Fatalf("checksum: %v", err)
			}
			if err := ApplyMigrations(doc); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			if doc.SchemaVersion != SchemaVersion {
				t.Fatalf("migration chain stopped at %q, want %q", doc.SchemaVersion, SchemaVersion)
			}
			if doc.Domains.KvExactBinding == nil {
				t.Fatalf("migration left kvexactbinding nil")
			}
			if doc.Domains.L7Policy == nil {
				t.Fatalf("migration left l7policy nil (want normalized empty)")
			}
			if version == "1.2" {
				// 1.2 declared its coverage; migration must keep the 1.3
				// domains OUT of it (an old document must not wipe live
				// L7 policies or CORS config).
				for _, name := range doc.IncludedDomains {
					if name == DomainL7Policy || name == DomainCORS ||
						name == DomainTracing || name == DomainCert {
						t.Fatalf("1.2 golden gained %q coverage through migration: %v", name, doc.IncludedDomains)
					}
				}
			} else if len(doc.IncludedDomains) != len(Registry) {
				t.Fatalf("migration did not stamp full coverage: %v", doc.IncludedDomains)
			}

			hooks := newMockHooks()
			e := newTestEngine(hooks, t.TempDir())
			res, rerr := e.Restore(raw, RestoreOptions{Mode: ModeDryRun})
			if rerr != nil {
				t.Fatalf("Restore: %v", rerr)
			}
			if len(res.Errors) > 0 || res.Result != ResultOK || !res.Compatible {
				t.Fatalf("legacy golden no longer dry-run-restores: %+v", res)
			}
		})
	}
}

// TestSampleDocumentCoversEveryDomain guards the shared fixture itself: a
// new registry domain must appear in sampleDocument (and so in every
// golden), or capture/restore coverage quietly shrinks.
func TestSampleDocumentCoversEveryDomain(t *testing.T) {
	doc := sampleDocument()
	for _, name := range DomainNames() {
		if countDomain(name, &doc.Domains) == 0 {
			t.Errorf("sampleDocument carries no %s content -- goldens and round-trip fixtures skip the domain", name)
		}
	}
	var zero time.Time
	if doc.CreatedAt.Equal(zero) {
		t.Fatalf("sampleDocument must set CreatedAt")
	}
	_ = cmn.KvExactBindingMod{} // fixture type anchored here on purpose
}
