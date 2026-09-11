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

package prometheus

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// tierFamilySnapshot returns the child count and value sum of the
// loxilb_ai_pd_tier_selected_total family as currently registered, so a test
// can assert that a call recorded nothing without minting the very child it
// is checking for (WithLabelValues would instantiate it).
func tierFamilySnapshot(t *testing.T) (children int, sum float64) {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "loxilb_ai_pd_tier_selected_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			children++
			sum += m.GetCounter().GetValue()
		}
	}
	return children, sum
}

// RecordPDTierSelected's tier argument arrives from the C datapath, and the
// switch is the only thing keeping the tier label a closed enum. Each valid
// encoding must land on exactly its own child, and any other value must
// record nothing at all — a value minted straight into the label would hand
// a single misbehaving caller unbounded series cardinality.
func TestRecordPDTierSelected(t *testing.T) {
	model := "tiermodel"
	encodings := map[int]string{0: "tier0", 1: "tier1", 15: "tier15", 2: "tier2"}

	for tier, label := range encodings {
		before := getCounterValue(aiPDTierSelectedTotal, label, model)
		RecordPDTierSelected(model, tier)
		if v := getCounterValue(aiPDTierSelectedTotal, label, model); v != before+1 {
			t.Fatalf("tier %d: child %q = %f, want %f", tier, label, v, before+1)
		}
	}

	// One call per valid encoding: exactly one child moved each time, so the
	// family sum equals the four increments above.
	children, sum := tierFamilySnapshot(t)

	for _, tier := range []int{-1, 3, 14, 16, 150} {
		RecordPDTierSelected(model, tier)
	}

	afterChildren, afterSum := tierFamilySnapshot(t)
	if afterChildren != children || afterSum != sum {
		t.Fatalf("unknown tier encodings changed the family: children %d -> %d, sum %f -> %f",
			children, afterChildren, sum, afterSum)
	}
}
