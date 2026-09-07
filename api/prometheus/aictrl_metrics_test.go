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
package prometheus

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func gatheredFamilies(t *testing.T) map[string]bool {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := make(map[string]bool, len(mfs))
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	return names
}

// The pd_ctrl_* families are outside the default package profile: they must
// be ABSENT from the default registry until the applier's start path calls
// EnsureAictrlMetricsRegistered, and present (idempotently) afterwards.
// Nothing else in this package calls Ensure, so the before-state is
// deterministic regardless of test order.
func TestAictrlMetricsRegistrationDeferred(t *testing.T) {
	unlabeled := []string{
		"loxilb_pd_ctrl_mode",
		"loxilb_pd_ctrl_alpha",
		"loxilb_pd_ctrl_override_events_total",
		"loxilb_pd_ctrl_nacks_total",
		"loxilb_pd_ctrl_snapshots_applied_total",
	}

	before := gatheredFamilies(t)
	for _, name := range unlabeled {
		if before[name] {
			t.Fatalf("%s exposed before EnsureAictrlMetricsRegistered — the default build leaks an excluded family", name)
		}
	}

	EnsureAictrlMetricsRegistered()
	EnsureAictrlMetricsRegistered() // second call must not panic (sync.Once)

	after := gatheredFamilies(t)
	for _, name := range unlabeled {
		if !after[name] {
			t.Fatalf("%s absent after EnsureAictrlMetricsRegistered", name)
		}
	}

	// Labeled vecs surface once a child is set — the applier's normal path.
	SetAictrlEpWeight("svc-a", 3, 100)
	if !gatheredFamilies(t)["loxilb_pd_ctrl_effective_weight"] {
		t.Fatalf("loxilb_pd_ctrl_effective_weight absent after registration + first Set")
	}
	DeleteAictrlEpSeries("svc-a", 3)
}
