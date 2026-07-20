/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 */

package client

import "testing"

const sampleExposition = `# HELP loxilb_ai_requests_total AI requests processed.
# TYPE loxilb_ai_requests_total counter
loxilb_ai_requests_total{model="llama3",tenant="t1"} 42
loxilb_ai_requests_total{model="llama3",tenant="t2"} 7
# HELP loxilb_active_conntracks Active conntrack entries.
# TYPE loxilb_active_conntracks gauge
loxilb_active_conntracks 128
# HELP loxilb_ai_ttfb_seconds Time to first byte.
# TYPE loxilb_ai_ttfb_seconds histogram
loxilb_ai_ttfb_seconds_bucket{le="0.1"} 3
loxilb_ai_ttfb_seconds_bucket{le="1"} 9
loxilb_ai_ttfb_seconds_bucket{le="+Inf"} 10
loxilb_ai_ttfb_seconds_sum 12.5
loxilb_ai_ttfb_seconds_count 10
`

func TestParseFamiliesAll(t *testing.T) {
	fams, err := ParseFamilies(sampleExposition, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fams) != 3 {
		t.Fatalf("got %d families, want 3", len(fams))
	}
}

func TestParseFamiliesGlobFilter(t *testing.T) {
	fams, err := ParseFamilies(sampleExposition, []string{"loxilb_ai_*"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fams) != 2 {
		t.Fatalf("got %d families, want 2 (ai glob)", len(fams))
	}
	for _, f := range fams {
		if f.Name == "loxilb_active_conntracks" {
			t.Error("glob filter leaked non-matching family")
		}
	}
}

func TestParseFamiliesCounterAndHistogram(t *testing.T) {
	fams, err := ParseFamilies(sampleExposition, []string{"loxilb_ai_requests_total"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fams) != 1 || fams[0].Type != "counter" || len(fams[0].Samples) != 2 {
		t.Fatalf("counter family wrong: %+v", fams)
	}
	if fams[0].Samples[0].Value+fams[0].Samples[1].Value != 49 {
		t.Errorf("counter values wrong: %+v", fams[0].Samples)
	}

	hist, err := ParseFamilies(sampleExposition, []string{"loxilb_ai_ttfb_seconds"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// count + sum + 3 buckets
	if hist[0].TotalSamples != 5 {
		t.Errorf("histogram flattening wrong, got %d samples: %+v", hist[0].TotalSamples, hist[0].Samples)
	}
}

func TestParseFamiliesSampleCap(t *testing.T) {
	fams, err := ParseFamilies(sampleExposition, []string{"loxilb_ai_requests_total"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if fams[0].TotalSamples != 2 || len(fams[0].Samples) != 1 {
		t.Errorf("cap not applied: total=%d returned=%d", fams[0].TotalSamples, len(fams[0].Samples))
	}
}
