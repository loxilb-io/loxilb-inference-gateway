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

// Regression tests for the CORS manager's fail-open fixes: an explicitly
// emptied allowlist must never silently re-seed the wildcard, and the
// configured state must export/restore faithfully.

package common

import (
	"reflect"
	"testing"
)

// freshCORS returns a manager in the unconfigured factory-default state.
func freshCORS() *CORSManager {
	m := &CORSManager{}
	return m
}

func TestCORSUnconfiguredDefaultsOpen(t *testing.T) {
	m := freshCORS()
	if !m.WildcardActive() {
		t.Fatalf("fresh manager must default to wildcard behavior")
	}
	if !m.IsAllowed("https://anything.example") {
		t.Fatalf("fresh manager must allow any origin (factory default)")
	}
	if got := m.GetOrigin(); !got["*"] || len(got) != 1 {
		t.Fatalf("fresh GetOrigin = %v, want {\"*\":true}", got)
	}
	if m.ExportConfig() != nil {
		t.Fatalf("factory default must export nil (it is not configuration)")
	}
}

func TestCORSAddEndsWildcardBehavior(t *testing.T) {
	m := freshCORS()
	if err := m.AddOrigin("https://ui.example.com"); err != nil {
		t.Fatalf("AddOrigin: %v", err)
	}
	if m.WildcardActive() {
		t.Fatalf("adding an origin must end wildcard behavior")
	}
	if m.IsAllowed("https://evil.example") {
		t.Fatalf("unlisted origin allowed after explicit configuration")
	}
	if !m.IsAllowed("https://ui.example.com") {
		t.Fatalf("listed origin refused")
	}
	if err := m.AddOrigin("https://ui.example.com"); err == nil {
		t.Fatalf("duplicate AddOrigin must error")
	}
	if err := m.AddOrigin("*"); err == nil {
		t.Fatalf("bare wildcard must be rejected as an origin")
	}
}

// TestCORSRemoveLastOriginStaysClosed is the fail-open regression pin:
// deleting the last origin used to re-seed the wildcard, silently turning
// an operator lockdown into allow-all (with credentials).
func TestCORSRemoveLastOriginStaysClosed(t *testing.T) {
	m := freshCORS()
	if err := m.AddOrigin("https://only.example.com"); err != nil {
		t.Fatalf("AddOrigin: %v", err)
	}
	if err := m.RemoveOrigin("https://only.example.com"); err != nil {
		t.Fatalf("RemoveOrigin: %v", err)
	}
	if m.WildcardActive() {
		t.Fatalf("removing the last origin re-seeded the wildcard (fail-open)")
	}
	if m.IsAllowed("https://anything.example") {
		t.Fatalf("empty configured allowlist must deny all cross-origin callers")
	}
	if got := m.GetOrigin(); len(got) != 0 {
		t.Fatalf("empty configured allowlist GetOrigin = %v, want empty", got)
	}
	cfg := m.ExportConfig()
	if cfg == nil || len(cfg.Origins) != 0 || cfg.Wildcard {
		t.Fatalf("configured-empty must export as explicit deny-all, got %+v", cfg)
	}
}

func TestCORSSetExportRoundTrip(t *testing.T) {
	m := freshCORS()
	want := &CORSConfig{Origins: []string{"https://a.example", "https://b.example"}}
	if err := m.SetConfig(want); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if got := m.ExportConfig(); !reflect.DeepEqual(got, want) {
		t.Fatalf("export = %+v, want %+v", got, want)
	}
	if m.IsAllowed("https://c.example") || !m.IsAllowed("https://a.example") {
		t.Fatalf("allowlist semantics wrong after SetConfig")
	}

	// Explicit wildcard opt-in round-trips too.
	if err := m.SetConfig(&CORSConfig{Wildcard: true}); err != nil {
		t.Fatalf("SetConfig wildcard: %v", err)
	}
	if !m.WildcardActive() || !m.IsAllowed("https://c.example") {
		t.Fatalf("explicit wildcard opt-in not effective")
	}
	if got := m.ExportConfig(); got == nil || !got.Wildcard {
		t.Fatalf("explicit wildcard must export as configuration, got %+v", got)
	}

	// Invalid configs are refused loudly.
	if err := m.SetConfig(nil); err == nil {
		t.Fatalf("nil config must be rejected (reset is explicit)")
	}
	if err := m.SetConfig(&CORSConfig{Wildcard: true, Origins: []string{"https://a.example"}}); err == nil {
		t.Fatalf("wildcard + origins must be rejected as contradictory")
	}
	if err := m.SetConfig(&CORSConfig{Origins: []string{"*"}}); err == nil {
		t.Fatalf("\"*\" inside the origin list must be rejected")
	}

	m.ResetConfig()
	if m.ExportConfig() != nil || !m.WildcardActive() {
		t.Fatalf("reset must return to the unconfigured factory default")
	}
}
