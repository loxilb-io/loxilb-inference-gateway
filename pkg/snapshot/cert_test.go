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

// Unit tests for the cert snapshot domain (schema 1.3): registry
// Get/Apply/Delete plumbing, boot-retry idempotency, and the
// divergent-material fail-closed semantics.

package snapshot

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func certTestMeta(id, digest string) cmn.CertMeta {
	return cmn.CertMeta{CertId: id, Digest: "sha256:" + digest}
}

// TestCertDomainHooks exercises the domain's Get/Apply/Delete against the
// mock backend.
func TestCertDomainHooks(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.Cert = []cmn.CertMeta{
		certTestMeta("edge-a", "aa"), certTestMeta("edge-b", "bb"),
	}

	applied, skipped, err := applyCert(hooks, doc, false)
	if err != nil || applied != 2 || skipped != 0 {
		t.Fatalf("apply = (%d,%d,%v), want (2,0,nil)", applied, skipped, err)
	}

	out := NewDocument("v0.9.9", "gw-test", TriggerManual)
	if err := getCert(hooks, out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(out.Domains.Cert, doc.Domains.Cert) {
		t.Fatalf("get after apply drifted: %+v", out.Domains.Cert)
	}

	deleted, err := deleteCert(hooks)
	if err != nil || deleted != 2 {
		t.Fatalf("delete = (%d,%v), want (2,nil)", deleted, err)
	}
	if got, _ := hooks.NetCertGet(); len(got) != 0 {
		t.Fatalf("certs survive delete: %+v", got)
	}
}

// TestCertApplyIdempotencyAndDivergence: identical re-apply is skipped
// under tolerateExists (boot replay); the same id with a DIFFERENT digest
// is fatal in both modes -- silently keeping divergent TLS material live
// is exactly the defect the digest exists to catch.
func TestCertApplyIdempotencyAndDivergence(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.Cert = []cmn.CertMeta{certTestMeta("edge-a", "aa")}

	if _, _, err := applyCert(hooks, doc, false); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	applied, skipped, err := applyCert(hooks, doc, true)
	if err != nil || applied != 0 || skipped != 1 {
		t.Fatalf("tolerant re-apply = (%d,%d,%v), want (0,1,nil)", applied, skipped, err)
	}
	if _, _, err := applyCert(hooks, doc, false); err == nil {
		t.Fatalf("intolerant re-apply must surface the exists error")
	}

	diverged := NewDocument("v0.9.9", "gw-test", TriggerManual)
	diverged.Domains.Cert = []cmn.CertMeta{certTestMeta("edge-a", "ff")}
	if _, _, err := applyCert(hooks, diverged, true); err == nil ||
		!strings.Contains(err.Error(), "diverges") {
		t.Fatalf("divergent material must be fatal even with tolerateExists, got %v", err)
	}
}

// TestCertCaptureSubsystemUnavailable: BGP-only nodes run no sockproxy;
// capture treats the domain as empty instead of failing the snapshot.
func TestCertCaptureSubsystemUnavailable(t *testing.T) {
	hooks := newMockHooks()
	hooks.failNext("NetCertGet", errors.New("running in bgp only mode"))
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.Cert = []cmn.CertMeta{certTestMeta("stale", "aa")}
	if err := getCert(hooks, doc); err != nil {
		t.Fatalf("get with unavailable subsystem: %v", err)
	}
	if doc.Domains.Cert != nil {
		t.Fatalf("unavailable subsystem must capture as empty, got %+v", doc.Domains.Cert)
	}
}

// TestCertDocumentNeverCarriesKeyMaterial pins the secret split at the
// schema level: CertMeta is {id, digest} only -- no field can carry PEM
// or key bytes.
func TestCertDocumentNeverCarriesKeyMaterial(t *testing.T) {
	typ := reflect.TypeOf(cmn.CertMeta{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		if strings.Contains(name, "pem") || strings.Contains(name, "key") ||
			strings.Contains(name, "material") {
			t.Fatalf("CertMeta gained a material-bearing field %q -- PEM/keys must never enter the snapshot document", typ.Field(i).Name)
		}
	}
	if typ.NumField() != 2 {
		t.Fatalf("CertMeta grew to %d fields -- review that no TLS material can ride the document, then update this pin", typ.NumField())
	}
}
