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

// Unit tests for the tracing snapshot domain (schema 1.3): singleton
// get/apply/delete plumbing and the secret-split invariant (header names
// only, never values).

package snapshot

import (
	"reflect"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestTracingDomainRoundTrip: apply an explicit OTLP config, capture it
// back field-identical, then wipe back to the boot default.
func TestTracingDomainRoundTrip(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.Tracing = &cmn.TracingConfig{
		Endpoint:    "collector.example.com:4317",
		Protocol:    "grpc",
		UseTLS:      true,
		HeaderNames: []string{"x-otlp-api-key"},
	}

	applied, skipped, err := applyTracing(hooks, doc, false)
	if err != nil || applied != 1 || skipped != 0 {
		t.Fatalf("apply = (%d,%d,%v), want (1,0,nil)", applied, skipped, err)
	}

	out := NewDocument("v0.9.9", "gw-test", TriggerManual)
	if err := getTracing(hooks, out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(out.Domains.Tracing, doc.Domains.Tracing) {
		t.Fatalf("tracing config drifted through round-trip: %+v", out.Domains.Tracing)
	}

	if deleted, err := deleteTracing(hooks); err != nil || deleted != 1 {
		t.Fatalf("delete = (%d,%v), want (1,nil)", deleted, err)
	}
	after := NewDocument("v0.9.9", "gw-test", TriggerManual)
	if err := getTracing(hooks, after); err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if after.Domains.Tracing != nil {
		t.Fatalf("wipe must return tracing to the boot default (nil), got %+v", after.Domains.Tracing)
	}
}

// TestTracingApplyNilIsNoop: a document captured while only the boot
// default was in effect applies nothing.
func TestTracingApplyNilIsNoop(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	applied, skipped, err := applyTracing(hooks, doc, false)
	if err != nil || applied != 0 || skipped != 0 {
		t.Fatalf("apply nil = (%d,%d,%v), want (0,0,nil)", applied, skipped, err)
	}
	if got := len(hooks.Calls); got != 0 {
		t.Fatalf("apply nil made %d hook calls, want 0: %v", got, hooks.Calls)
	}
}

// TestTracingDocumentNeverCarriesHeaderValues pins the secret split at
// the schema level: the TracingConfig payload has no field that could
// carry a header VALUE, and its canonical JSON for a config with header
// names contains only the names. If someone adds a value-bearing field,
// this test forces the conversation.
func TestTracingDocumentNeverCarriesHeaderValues(t *testing.T) {
	typ := reflect.TypeOf(cmn.TracingConfig{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if strings.Contains(strings.ToLower(f.Name), "value") ||
			f.Type.Kind() == reflect.Map {
			t.Fatalf("TracingConfig gained a value-bearing field %q -- header values must never enter the snapshot document", f.Name)
		}
	}
	items, err := domainItemJSONs(DomainTracing, &Domains{Tracing: &cmn.TracingConfig{
		Endpoint:    "collector.example.com:4317",
		Protocol:    "grpc",
		HeaderNames: []string{"authorization"},
	}})
	if err != nil || len(items) != 1 {
		t.Fatalf("digest: (%v, %d items)", err, len(items))
	}
	if !strings.Contains(items[0], "authorization") {
		t.Fatalf("header names must ride the document, got %s", items[0])
	}
}
