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
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

const lbConnCountCorrectionsHelp = "Times the data plane corrected a load-balancer rule's live connection count or per-endpoint session counts after comparing them with the connections that exist, summed over all rules."

var lbConnCountCorrectionsDesc = prometheus.NewDesc(
	"loxilb_lb_conn_count_corrections_total",
	lbConnCountCorrectionsHelp,
	nil, nil)

// lbConnCountCorrectionsSource returns the corrections made since start. It
// is read at scrape time.
var lbConnCountCorrectionsSource atomic.Pointer[func() uint64]

// SetLBConnCountCorrectionsSource sets where
// loxilb_lb_conn_count_corrections_total reads its value. Until it is called
// the counter reads zero.
func SetLBConnCountCorrectionsSource(fn func() uint64) {
	lbConnCountCorrectionsSource.Store(&fn)
}

type lbConnCountCorrectionsCollector struct{}

func (lbConnCountCorrectionsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- lbConnCountCorrectionsDesc
}

func (lbConnCountCorrectionsCollector) Collect(ch chan<- prometheus.Metric) {
	var got uint64
	if fn := lbConnCountCorrectionsSource.Load(); fn != nil {
		got = (*fn)()
	}
	ch <- prometheus.MustNewConstMetric(lbConnCountCorrectionsDesc, prometheus.CounterValue, float64(got))
}

func init() {
	prometheus.MustRegister(lbConnCountCorrectionsCollector{})
}
