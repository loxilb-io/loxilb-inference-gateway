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

// Unit tests for the cors snapshot domain (schema 1.3): singleton
// get/apply/delete plumbing and the unconfigured-vs-configured-empty
// distinction the fail-open fix rests on.

package snapshot

import (
	"reflect"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestCORSDomainRoundTrip: apply a configured allowlist, capture it back
// field-identical, then wipe back to the unconfigured factory default.
func TestCORSDomainRoundTrip(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.CORS = &cmn.CORSConfig{Origins: []string{"https://a.example", "https://b.example"}}

	applied, skipped, err := applyCORS(hooks, doc, false)
	if err != nil || applied != 1 || skipped != 0 {
		t.Fatalf("apply = (%d,%d,%v), want (1,0,nil)", applied, skipped, err)
	}

	out := NewDocument("v0.9.9", "gw-test", TriggerManual)
	if err := getCORS(hooks, out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(out.Domains.CORS, doc.Domains.CORS) {
		t.Fatalf("cors config drifted through round-trip: %+v", out.Domains.CORS)
	}

	if deleted, err := deleteCORS(hooks); err != nil || deleted != 1 {
		t.Fatalf("delete = (%d,%v), want (1,nil)", deleted, err)
	}
	after := NewDocument("v0.9.9", "gw-test", TriggerManual)
	if err := getCORS(hooks, after); err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if after.Domains.CORS != nil {
		t.Fatalf("wipe must return cors to the unconfigured default (nil), got %+v", after.Domains.CORS)
	}
}

// TestCORSConfiguredEmptyIsNotUnconfigured: an explicitly-empty allowlist
// (deny-all) is real configuration -- it round-trips, counts as one item,
// and digests differently from the unconfigured default. Collapsing the
// two is the fail-open bug class this domain closes.
func TestCORSConfiguredEmptyIsNotUnconfigured(t *testing.T) {
	denyAll := &cmn.CORSConfig{Origins: []string{}}

	if got := countDomain(DomainCORS, &Domains{CORS: denyAll}); got != 1 {
		t.Fatalf("configured-empty counts %d, want 1", got)
	}
	if got := countDomain(DomainCORS, &Domains{}); got != 0 {
		t.Fatalf("unconfigured counts %d, want 0", got)
	}

	cfgItems, err := domainItemJSONs(DomainCORS, &Domains{CORS: denyAll})
	if err != nil {
		t.Fatalf("digest configured-empty: %v", err)
	}
	nilItems, err := domainItemJSONs(DomainCORS, &Domains{})
	if err != nil {
		t.Fatalf("digest unconfigured: %v", err)
	}
	if len(cfgItems) != 1 || len(nilItems) != 0 {
		t.Fatalf("digest collapses configured-empty (%d items) and unconfigured (%d items)", len(cfgItems), len(nilItems))
	}

	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.CORS = denyAll
	if _, _, err := applyCORS(hooks, doc, false); err != nil {
		t.Fatalf("apply deny-all: %v", err)
	}
	out := NewDocument("v0.9.9", "gw-test", TriggerManual)
	if err := getCORS(hooks, out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if out.Domains.CORS == nil || len(out.Domains.CORS.Origins) != 0 || out.Domains.CORS.Wildcard {
		t.Fatalf("deny-all did not round-trip: %+v", out.Domains.CORS)
	}
}

// TestCORSApplyNilIsNoop: a document captured from an unconfigured
// gateway applies nothing -- the target keeps (or, post-wipe, returns to)
// its own factory default.
func TestCORSApplyNilIsNoop(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	applied, skipped, err := applyCORS(hooks, doc, false)
	if err != nil || applied != 0 || skipped != 0 {
		t.Fatalf("apply nil = (%d,%d,%v), want (0,0,nil)", applied, skipped, err)
	}
	if got := len(hooks.Calls); got != 0 {
		t.Fatalf("apply nil made %d hook calls, want 0: %v", got, hooks.Calls)
	}
}
