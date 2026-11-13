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
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// No AI-gateway pool, no band series.
func TestFcBandCollectorEmptyStore(t *testing.T) {
	withAdmissionStore(t, nil, [5]float64{})
	if n := testutil.CollectAndCount(fcBandCollector{}); n != 0 {
		t.Errorf("collected %d band series with no pool, want 0", n)
	}
}

// Fifteen series per service, zero included; a service's pools are summed;
// the band index names its class (0 standard, 1 critical, 2 sheddable) and
// the outcome index follows enum fc_band_outcome.
func TestFcBandCollectorSumsPoolsPerService(t *testing.T) {
	withAdmissionStore(t, []admissionSample{
		{service: "10.0.0.1:8080", pool: "a", bandOutcome: [3][5]float64{
			{10, 2, 0, 1, 0}, // standard
			{5, 1, 0, 0, 1},  // critical
			{0, 3, 4, 0, 0},  // sheddable
		}},
		{service: "10.0.0.1:8080", pool: "b", bandOutcome: [3][5]float64{
			{1, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 2, 0, 0},
		}},
		{service: "10.0.0.2:8080", pool: "-"},
	}, [5]float64{})

	if n := testutil.CollectAndCount(fcBandCollector{}); n != 30 {
		t.Errorf("collected %d band series for two services, want 30", n)
	}
	want := `
# HELP loxilb_ai_fc_band_total Inference requests of the capacity gate per service, by priority band (the request's class: critical, standard, sheddable) and outcome. Four outcomes are terminal, one per request: admitted (took a capacity unit), shed (429 admission_shed: a sheddable request refused at a ceiling, or evicted from the queue for a higher band, by band policy), expired (504 admission_queue_timeout: its wait window ended), cancelled (its client left while it waited). queued is not an end: it counts parks, once per park (a woken request that goes back to its place is the same park). A request refused for another reason (queue full, tenant share, no healthy capacity, a drain) is counted in loxilb_ai_admission_decisions_total only. Fifteen series for every service with an AI-gateway pool, zero included.
# TYPE loxilb_ai_fc_band_total counter
loxilb_ai_fc_band_total{band="critical",outcome="admitted",service="10.0.0.1:8080"} 5
loxilb_ai_fc_band_total{band="critical",outcome="cancelled",service="10.0.0.1:8080"} 1
loxilb_ai_fc_band_total{band="critical",outcome="expired",service="10.0.0.1:8080"} 0
loxilb_ai_fc_band_total{band="critical",outcome="queued",service="10.0.0.1:8080"} 1
loxilb_ai_fc_band_total{band="critical",outcome="shed",service="10.0.0.1:8080"} 0
loxilb_ai_fc_band_total{band="critical",outcome="admitted",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="critical",outcome="cancelled",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="critical",outcome="expired",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="critical",outcome="queued",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="critical",outcome="shed",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="sheddable",outcome="admitted",service="10.0.0.1:8080"} 0
loxilb_ai_fc_band_total{band="sheddable",outcome="cancelled",service="10.0.0.1:8080"} 0
loxilb_ai_fc_band_total{band="sheddable",outcome="expired",service="10.0.0.1:8080"} 0
loxilb_ai_fc_band_total{band="sheddable",outcome="queued",service="10.0.0.1:8080"} 3
loxilb_ai_fc_band_total{band="sheddable",outcome="shed",service="10.0.0.1:8080"} 6
loxilb_ai_fc_band_total{band="sheddable",outcome="admitted",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="sheddable",outcome="cancelled",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="sheddable",outcome="expired",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="sheddable",outcome="queued",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="sheddable",outcome="shed",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="standard",outcome="admitted",service="10.0.0.1:8080"} 11
loxilb_ai_fc_band_total{band="standard",outcome="cancelled",service="10.0.0.1:8080"} 0
loxilb_ai_fc_band_total{band="standard",outcome="expired",service="10.0.0.1:8080"} 1
loxilb_ai_fc_band_total{band="standard",outcome="queued",service="10.0.0.1:8080"} 2
loxilb_ai_fc_band_total{band="standard",outcome="shed",service="10.0.0.1:8080"} 0
loxilb_ai_fc_band_total{band="standard",outcome="admitted",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="standard",outcome="cancelled",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="standard",outcome="expired",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="standard",outcome="queued",service="10.0.0.2:8080"} 0
loxilb_ai_fc_band_total{band="standard",outcome="shed",service="10.0.0.2:8080"} 0
`
	if err := testutil.CollectAndCompare(fcBandCollector{}, strings.NewReader(want),
		"loxilb_ai_fc_band_total"); err != nil {
		t.Errorf("band series mismatch: %v", err)
	}
}
