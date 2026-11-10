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
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/prometheus/client_golang/prometheus"
)

// How the requests of each priority band of the capacity gate ended, per
// service. It is the per-band split of five decisions of
// loxilb_ai_admission_decisions_total, counted where those are counted, and
// it rides on the same per-pool row (admissionStore): a service's pools are
// summed. Indexed as the gate's enum fc_band_outcome.
var fcBandOutcomeLabels = [5]string{"admitted", "queued", "shed", "expired", "cancelled"}

var fcBandTotalDesc = prometheus.NewDesc(
	"loxilb_ai_fc_band_total",
	"Inference requests of the capacity gate per service, by priority band (the request's class: critical, standard, sheddable) and outcome. Four outcomes are terminal, one per request: admitted (took a capacity unit), shed (429 admission_shed: a sheddable request refused at a ceiling, or evicted from the queue for a higher band, by band policy), expired (504 admission_queue_timeout: its wait window ended), cancelled (its client left while it waited). queued is not an end: it counts parks, once per park (a woken request that goes back to its place is the same park). A request refused for another reason (queue full, tenant share, no healthy capacity, a drain) is counted in loxilb_ai_admission_decisions_total only. Fifteen series for every service with an AI-gateway pool, zero included.",
	[]string{"service", "band", "outcome"}, nil,
)

// fcBandCollector emits loxilb_ai_fc_band_total from admissionStore on
// scrape.
type fcBandCollector struct{}

// Describe implements prometheus.Collector.
func (fcBandCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- fcBandTotalDesc
}

// Collect implements prometheus.Collector.
func (fcBandCollector) Collect(ch chan<- prometheus.Metric) {
	admissionStoreMutex.Lock()
	samples := admissionStore
	admissionStoreMutex.Unlock()

	for _, sv := range fcBandByService(samples) {
		for b := 0; b < cmn.FcBands; b++ {
			for o, outcome := range fcBandOutcomeLabels {
				ch <- prometheus.MustNewConstMetric(fcBandTotalDesc, prometheus.CounterValue,
					sv.outcome[b][o], sv.service, cmn.FcBandName(b), outcome)
			}
		}
	}
}

func init() {
	datapathRegisterer{}.MustRegister(fcBandCollector{})
}

// fcBandService is one service's band outcomes, summed over its pools.
type fcBandService struct {
	service string
	outcome [3][5]float64
}

// fcBandByService folds the pools of each service into one row, in the
// order the services first appear. Pure Go.
func fcBandByService(samples []admissionSample) []fcBandService {
	out := make([]fcBandService, 0, len(samples))
	at := make(map[string]int, len(samples))
	for _, s := range samples {
		i, seen := at[s.service]
		if !seen {
			i = len(out)
			at[s.service] = i
			out = append(out, fcBandService{service: s.service})
		}
		for b := range s.bandOutcome {
			for o := range s.bandOutcome[b] {
				out[i].outcome[b][o] += s.bandOutcome[b][o]
			}
		}
	}
	return out
}
