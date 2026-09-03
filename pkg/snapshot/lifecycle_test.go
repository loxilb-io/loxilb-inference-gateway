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

// Lifecycle-registry guard: parses api/swagger.yml and enforces that every
// mutating route is classified in RouteLifecycles (lifecycle.go), in both
// directions. A new mutating API cannot merge without an explicit
// persistence-lifecycle decision, and a removed API cannot leave a stale
// classification behind.

package snapshot

import (
	"os"
	"reflect"
	"sort"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

// swaggerSpecPath is relative to this package directory (go test runs
// with the package directory as working directory).
const swaggerSpecPath = "../../api/swagger.yml"

var mutatingMethods = map[string]bool{
	"post":   true,
	"put":    true,
	"patch":  true,
	"delete": true,
}

// swaggerMutatingRoutes extracts every "<method> <path>" mutating route
// declared in api/swagger.yml.
func swaggerMutatingRoutes(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(swaggerSpecPath)
	if err != nil {
		t.Fatalf("reading swagger spec: %v", err)
	}
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parsing swagger spec: %v", err)
	}
	if len(spec.Paths) == 0 {
		t.Fatalf("swagger spec has no paths -- wrong file or format drift")
	}
	routes := map[string]bool{}
	for path, ops := range spec.Paths {
		for method := range ops {
			if mutatingMethods[method] {
				routes[RouteKey(method, path)] = true
			}
		}
	}
	if len(routes) == 0 {
		t.Fatalf("no mutating routes found in swagger spec -- parser drift")
	}
	return routes
}

// TestLifecycleRegistryCoversAllMutatingRoutes is the CI guard: a mutating
// swagger route without a lifecycle classification fails here, forcing the
// author to decide (and reviewers to see) how the new configuration
// survives a reboot.
func TestLifecycleRegistryCoversAllMutatingRoutes(t *testing.T) {
	swagger := swaggerMutatingRoutes(t)
	idx := RouteLifecycleIndex()

	var unclassified []string
	for key := range swagger {
		if _, ok := idx[key]; !ok {
			unclassified = append(unclassified, key)
		}
	}
	sort.Strings(unclassified)
	for _, key := range unclassified {
		t.Errorf("mutating route %q has no lifecycle classification; add it to RouteLifecycles in pkg/snapshot/lifecycle.go with an explicit persistence decision", key)
	}

	var stale []string
	for key := range idx {
		if !swagger[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("lifecycle registry entry %q matches no mutating route in api/swagger.yml; remove or fix it", key)
	}
}

// TestLifecycleRegistryEntriesWellFormed checks per-entry invariants: no
// duplicates, valid class, lower-case swagger method, area discipline
// (snapshot-classed entries name a real snapshot domain; entries of other
// classes never claim one, except runtime actions on a captured domain,
// which must not be desired state).
func TestLifecycleRegistryEntriesWellFormed(t *testing.T) {
	validClasses := map[LifecycleClass]bool{
		ClassSnapshot:           true,
		ClassExternalStore:      true,
		ClassRuntimeRebuilt:     true,
		ClassLifecycleOperation: true,
		ClassOutOfScope:         true,
	}
	seen := map[string]bool{}
	for _, rl := range RouteLifecycles {
		key := RouteKey(rl.Method, rl.Path)
		if seen[key] {
			t.Errorf("duplicate lifecycle entry %q", key)
		}
		seen[key] = true
		if !mutatingMethods[rl.Method] {
			t.Errorf("entry %q: method must be a lower-case mutating swagger method", key)
		}
		if !validClasses[rl.Class] {
			t.Errorf("entry %q: unknown class %q", key, rl.Class)
		}
		if rl.Area == "" {
			t.Errorf("entry %q: empty area", key)
		}
		isDomain := snapshotDomainSet[rl.Area]
		switch {
		case rl.Class == ClassSnapshot && !isDomain:
			t.Errorf("entry %q: snapshot class requires a snapshot domain area, got %q", key, rl.Area)
		case rl.Class == ClassSnapshot && !rl.DesiredState:
			t.Errorf("entry %q: snapshot-classed routes carry desired state by definition", key)
		case rl.Class != ClassSnapshot && isDomain && rl.DesiredState:
			t.Errorf("entry %q: desired-state route on snapshot domain %q must be classified snapshot", key, rl.Area)
		}
	}
}

// TestSnapshotDomainSetMatchesRegistry pins snapshotDomainSet to the
// domain registry (registry.go ApplyOrder), so a new snapshot domain
// cannot be added without the lifecycle table learning about it.
func TestSnapshotDomainSetMatchesRegistry(t *testing.T) {
	fromRegistry := map[string]bool{}
	for _, e := range ApplyOrder() {
		fromRegistry[e.Name] = true
	}
	if !reflect.DeepEqual(fromRegistry, snapshotDomainSet) {
		t.Fatalf("snapshotDomainSet (lifecycle.go) diverges from the domain registry:\nregistry: %v\nlifecycle: %v", fromRegistry, snapshotDomainSet)
	}
}

// TestExcludedDomainsDerivation pins the derived excluded_domains honesty
// list. This golden changes exactly when a route classification changes
// (an area gains persistence, or a new unpersisted area appears) -- which
// is the point: the diff surfaces in review instead of the marker rotting.
func TestExcludedDomainsDerivation(t *testing.T) {
	want := []string{
		AreaAIKeys,
		AreaAIRateLimit,
		AreaAuthUsers,
		AreaCert,
		AreaCluster,
		AreaGPUMode,
		AreaInterface,
		AreaLlamaFW,
		AreaMetrics,
		AreaOPA,
		AreaParams,
		AreaPII,
	}
	sort.Strings(want)
	got := ExcludedDomainsFromLifecycle()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("excluded_domains derivation drifted:\n got %v\nwant %v", got, want)
	}
	for _, a := range got {
		if snapshotDomainSet[a] {
			t.Errorf("excluded_domains lists captured snapshot domain %q", a)
		}
	}
	doc := NewDocument("v-test", "host-test", TriggerManual)
	if !reflect.DeepEqual(doc.ExcludedDomains, want) {
		t.Fatalf("NewDocument excluded_domains = %v, want derived list %v", doc.ExcludedDomains, want)
	}
}
