/*
 * Copyright (c) 2025 LoxiLB Authors
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

// ai_worker_scrape_test.go — loxilb_ai_worker_scrape_total.
//
// The family reports the health of the vLLM /metrics scraper that feeds P/D
// load-aware prefill selection. Two properties carry the whole point of it and
// are asserted here: it is PRESENT AT ZERO before anything is recorded, and
// its label set is CLOSED.

package prometheus

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// workerScrapeChildren returns the label->value map of the family as
// registered, without minting children (WithLabelValues would create the very
// child the test is looking for).
func workerScrapeChildren(t *testing.T) map[string]float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "loxilb_ai_worker_scrape_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "result" {
					out[lp.GetValue()] = m.GetCounter().GetValue()
				}
			}
		}
	}
	return out
}

// TestWorkerScrapePresentAtZero is the load-bearing one.
//
// The condition this family exists to report is "the scraper produced no
// sample". A lazily-created CounterVec is ABSENT in exactly that state, which
// to an alerting rule is indistinguishable from a healthy gateway — the same
// false reassurance that makes an absent series worse than a zero one. The
// init pre-create is what makes "no P/D rule, so no scraper" read as flat
// zeros, and what gives result="ok" a denominator before anything succeeds.
func TestWorkerScrapePresentAtZero(t *testing.T) {
	children := workerScrapeChildren(t)
	if len(children) == 0 {
		t.Fatal("loxilb_ai_worker_scrape_total is ABSENT from the registry: a " +
			"vector that only appears once something has been recorded cannot " +
			"report that nothing is being recorded")
	}
	for _, want := range aiWorkerScrapeResults {
		if _, ok := children[want]; !ok {
			t.Errorf("result=%q child missing; pre-create must cover every "+
				"value in aiWorkerScrapeResults", want)
		}
	}
	if len(children) != len(aiWorkerScrapeResults) {
		t.Errorf("family has %d children, want exactly %d — an extra child "+
			"means a label value escaped the closed set",
			len(children), len(aiWorkerScrapeResults))
	}
}

// TestRecordWorkerScrapeCountsPerResult: each known outcome lands on its own
// child and moves nothing else.
func TestRecordWorkerScrapeCountsPerResult(t *testing.T) {
	for _, result := range []string{"ok", "unreachable", "http_error",
		"body_error", "unparseable", "bad_request"} {
		before := workerScrapeChildren(t)
		RecordWorkerScrape(result)
		after := workerScrapeChildren(t)

		if got := after[result] - before[result]; got != 1 {
			t.Errorf("result=%q moved by %v, want 1", result, got)
		}
		for label, v := range after {
			if label == result {
				continue
			}
			if v != before[label] {
				t.Errorf("recording %q also moved %q (%v -> %v)",
					result, label, before[label], v)
			}
		}
	}
}

// TestRecordWorkerScrapeFoldsUnknown: the result string crosses a package
// boundary from the scraper, so an unrecognised value must be folded rather
// than admitted. Minting it straight into the label would hand one typo — or
// one future outcome added upstream without review here — unbounded series
// cardinality on a vector that is supposed to have a closed set.
func TestRecordWorkerScrapeFoldsUnknown(t *testing.T) {
	before := workerScrapeChildren(t)
	RecordWorkerScrape("no_such_outcome")
	RecordWorkerScrape("")
	after := workerScrapeChildren(t)

	if got := after["unknown"] - before["unknown"]; got != 2 {
		t.Errorf("unknown moved by %v, want 2", got)
	}
	if len(after) != len(before) {
		t.Errorf("cardinality grew from %d to %d: an unrecognised result was "+
			"admitted as a label value", len(before), len(after))
	}
}

// TestRecordWorkerScrapeUnknownIsNotSelfAliasing: "unknown" is in the
// pre-create list so the child exists from init, but it must not be
// reachable as a *known* outcome — otherwise a caller passing it directly
// would be indistinguishable from the fold, and the fold is a defect signal.
func TestRecordWorkerScrapeUnknownIsNotSelfAliasing(t *testing.T) {
	before := workerScrapeChildren(t)
	RecordWorkerScrape("unknown")
	after := workerScrapeChildren(t)
	if got := after["unknown"] - before["unknown"]; got != 1 {
		t.Errorf("unknown moved by %v, want 1 (folded, not rejected)", got)
	}
	if len(after) != len(before) {
		t.Errorf("cardinality changed: %d -> %d", len(before), len(after))
	}
}
