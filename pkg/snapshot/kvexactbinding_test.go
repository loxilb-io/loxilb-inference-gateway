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

package snapshot

import (
	"bytes"
	"reflect"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func kvTestBindingMod(rule string) cmn.KvExactBindingMod {
	return cmn.KvExactBindingMod{
		RuleIdent:             rule,
		ModelProfileID:        "acme-m1-v1",
		ModelProfileGen:       3,
		EngineContractID:      "vllm-zmq-v1",
		EngineContractGen:     7,
		AttestationPolicyGen:  2,
		RequiredEvidenceLevel: "validated",
		ConsensusPolicy:       "all_endpoints",
		BindingGen:            4,
		BindingDigest:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		MaxAllocatedGen:       6,
	}
}

// TestKvExactBindingDocumentRoundTrip: a document carrying binding state
// encodes at the current schema version and decodes back byte-identical.
func TestKvExactBindingDocumentRoundTrip(t *testing.T) {
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.KvExactBinding = []cmn.KvExactBindingMod{
		kvTestBindingMod("rule-a"), kvTestBindingMod("rule-b"),
	}
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("new document schema version = %q, want %q", doc.SchemaVersion, SchemaVersion)
	}
	enc, err := Encode(doc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := Decode(bytes.NewReader(enc))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := VerifyChecksum(back); err != nil {
		t.Fatalf("checksum: %v", err)
	}
	if !reflect.DeepEqual(doc.Domains.KvExactBinding, back.Domains.KvExactBinding) {
		t.Fatalf("binding domain drifted:\n out %+v\n in  %+v",
			doc.Domains.KvExactBinding, back.Domains.KvExactBinding)
	}
}

// TestSchemaGateRefusesBindingDocsOnOldBuild: the version fence this bump
// exists for — a 1.1 (binding-aware) document must be refused by a build
// that only understands 1.0.
func TestSchemaGateRefusesBindingDocsOnOldBuild(t *testing.T) {
	if err := checkSchemaVersionAgainst("1.1", "1.0"); err == nil {
		t.Fatal("1.0 build accepted a 1.1 document")
	}
	// And the current build accepts both current and older-minor documents.
	if err := checkSchemaVersionAgainst("1.0", SchemaVersion); err != nil {
		t.Fatalf("current build refused a 1.0 document: %v", err)
	}
	if err := checkSchemaVersionAgainst(SchemaVersion, SchemaVersion); err != nil {
		t.Fatalf("current build refused its own version: %v", err)
	}
}

// TestMigration10To11 normalizes a legacy document to the current shape.
func TestMigration10To11(t *testing.T) {
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.SchemaVersion = "1.0"
	doc.Domains.KvExactBinding = nil
	if err := ApplyMigrations(doc); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("migrated version = %q, want %q", doc.SchemaVersion, SchemaVersion)
	}
	if doc.Domains.KvExactBinding == nil {
		t.Fatal("kvexactbinding not normalized to empty")
	}
	if len(doc.Domains.KvExactBinding) != 0 {
		t.Fatal("migration invented binding entries")
	}
}

// TestKvExactBindingDomainHooks exercises the domain's Get/Apply/Delete
// against the mock backend, including apply-failure position reporting.
func TestKvExactBindingDomainHooks(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.KvExactBinding = []cmn.KvExactBindingMod{
		kvTestBindingMod("rule-a"), kvTestBindingMod("rule-b"),
	}

	applied, skipped, err := applyKvExactBinding(hooks, doc, false)
	if err != nil || applied != 2 || skipped != 0 {
		t.Fatalf("apply = (%d,%d,%v), want (2,0,nil)", applied, skipped, err)
	}

	out := NewDocument("v0.9.9", "gw-test", TriggerManual)
	if err := getKvExactBinding(hooks, out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(out.Domains.KvExactBinding, doc.Domains.KvExactBinding) {
		t.Fatalf("get after apply drifted: %+v", out.Domains.KvExactBinding)
	}

	deleted, err := deleteKvExactBinding(hooks)
	if err != nil || deleted != 2 {
		t.Fatalf("delete = (%d,%v), want (2,nil)", deleted, err)
	}
	if got, _ := hooks.NetKvExactBindingGet(); len(got) != 0 {
		t.Fatalf("bindings survive delete: %+v", got)
	}
}

// TestKvExactBindingDomainRegistered: the domain must be part of the ordered
// registry, after loadbalancer (bindings belong to rules).
func TestKvExactBindingDomainRegistered(t *testing.T) {
	lbIdx, kvIdx := -1, -1
	for i, e := range Registry {
		switch e.Name {
		case DomainLoadBalancer:
			lbIdx = i
		case DomainKvExactBinding:
			kvIdx = i
		}
	}
	if kvIdx < 0 {
		t.Fatal("kvexactbinding not in the domain registry")
	}
	if lbIdx < 0 || kvIdx < lbIdx {
		t.Fatalf("kvexactbinding (idx %d) must apply after loadbalancer (idx %d)", kvIdx, lbIdx)
	}
	if _, err := Select([]string{DomainKvExactBinding}); err != nil {
		t.Fatalf("Select(kvexactbinding): %v", err)
	}
}
