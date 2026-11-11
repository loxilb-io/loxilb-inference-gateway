/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// Half-close holds
// ============================================================================
// On a service whose half_close_mode is hold, a client that half-closes after
// its request is kept open until its answer is out (loxilb-ebpf/common/
// sockproxy_hold.c). These families export the holds' state and how they
// ended, from the metrics snapshot. The settings they report are the ones at
// /config/halfclose.
//
// The label values below are the C enums' order: sp_hold_end in
// sockproxy_hold_core.h, hc_stream in sockproxy_hc_core.h.
// ============================================================================

const holdEndReasons = 7 // enum sp_hold_end, none (0) included

var holdEndLabels = [holdEndReasons]string{"", "answered", "backend_first", "expired",
	"released", "reset", "other"}

// holdSnapshot is the hold state taken from one C snapshot.
type holdSnapshot struct {
	held           uint64 // gauge
	oldestMs       uint64 // gauge, as of the data path's last pass
	allowed        uint64 // gauge, the switch
	capSec         uint64 // gauge, the bound
	begun          uint64
	ended          [holdEndReasons]uint64
	expired        [2][hcStreams]uint64 // [answer had begun][stream]
	refusedResidue uint64
	reentry        uint64
	emptyOut       uint64
	accelSkipped   uint64
	defaultMode    uint64 // gauge, enum sp_hold_mode: the mode of a rule that leaves its own unset
}

// mergeHold takes the gauges as read and keeps the counters from going
// backwards, as mergeHalfClose does. Each counter is a single atomic on the C
// side and cannot tear.
func mergeHold(prev, next holdSnapshot) holdSnapshot {
	m := next
	m.begun = maxU64(prev.begun, next.begun)
	for r := range m.ended {
		m.ended[r] = maxU64(prev.ended[r], next.ended[r])
	}
	for b := range m.expired {
		for s := range m.expired[b] {
			m.expired[b][s] = maxU64(prev.expired[b][s], next.expired[b][s])
		}
	}
	m.refusedResidue = maxU64(prev.refusedResidue, next.refusedResidue)
	m.reentry = maxU64(prev.reentry, next.reentry)
	m.emptyOut = maxU64(prev.emptyOut, next.emptyOut)
	m.accelSkipped = maxU64(prev.accelSkipped, next.accelSkipped)
	return m
}

var (
	holdStoreMutex sync.Mutex
	holdStore      holdSnapshot
)

// updateHoldStore merges a raw snapshot into the store. Called once per
// collection cycle by RunSockproxyMetrics.
func updateHoldStore(raw holdSnapshot) {
	holdStoreMutex.Lock()
	holdStore = mergeHold(holdStore, raw)
	holdStoreMutex.Unlock()
}

var halfCloseHeldDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_held",
	"Clients held open now after a half-close, waiting for their answers to go out, on services whose half_close_mode is hold.",
	nil, nil,
)

var halfCloseHeldOldestDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_held_oldest_seconds",
	"How long the oldest client held now has been held, as of the data path's last pass (each second while any is held); 0 when none is. A hold ends on idleness, not age, so a long answer that keeps coming can hold a client well past the bound: this is where that shows.",
	nil, nil,
)

var halfCloseHoldAllowedDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_hold_allowed",
	"1 while new holds may be taken, 0 while they are blocked (/config/halfclose). Blocking leaves the clients already held to finish.",
	nil, nil,
)

var halfCloseHoldCapDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_hold_cap_seconds",
	"The idle bound on a hold: a held client to which no answer byte has been written for this long is closed (/config/halfclose).",
	nil, nil,
)

var halfCloseHoldDefaultModeDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_hold_default_mode",
	"1 while the default half-close mode is hold, 0 while it is off (/config/halfclose defaultMode): the mode of the fullproxy services that leave their own half_close_mode unset and could take hold. A change applies to half-closes from then on.",
	nil, nil,
)

// spHoldModeHold is enum sp_hold_mode's hold.
const spHoldModeHold = 2

var halfCloseHoldDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_hold_total",
	"Clients held after a half-close instead of being cut at their FIN: an answer was owed, the connection was plaintext and the kernel had never been given a direction of it, on a service whose half_close_mode is hold, while holds were allowed.",
	nil, nil,
)

var halfCloseHoldEndedDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_hold_ended_total",
	"Holds ended, once each, by why: answered (every answer owed went out), backend_first (the connection carrying the answer ended first; what it had sent went out), expired (no answer byte reached the client for the bound), released (/config/halfclose/release), reset (the client reset while held: a cancel that was waited on as a half-close), other (torn down for another reason).",
	[]string{"reason"}, nil,
)

var halfCloseHoldExpiredDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_hold_expired_total",
	"Holds ended by the bound, by whether the answer had begun reaching the client and by the request's stream field (as in loxilb_proxy_halfclose_fin_gap_seconds). Not begun is a slow first byte or a cancel taken for a half-close; begun is a backend that stopped, or an answer slower than the bound - cut short.",
	[]string{"answer_started", "stream"}, nil,
)

var halfCloseHoldRefusedDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_hold_refused_total",
	"Half-closes that would have been held but were not, cut at their FIN as before. reason pipeline_residue: the next request was still arriving.",
	[]string{"reason"}, nil,
)

var halfCloseHoldSpuriousDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_hold_spurious_wakeups_total",
	"Wake-ups of a held client that had nothing to do. kind eof_reentry: its EOF was handled again; it should stay 0. kind empty_out: it was woken to write with nothing to write; about one each time its answer queue fills and empties is expected, growth with the time held is a busy loop.",
	[]string{"kind"}, nil,
)

var halfCloseAccelSkippedDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_accel_skipped_total",
	"Connections not accelerated because the client had already sent its FIN when the pairing would have been installed, on services whose half_close_mode is hold. Each kept its answer by giving up acceleration.",
	nil, nil,
)

// halfCloseHoldCollector emits the hold families from holdStore on every
// scrape. Every series is present from the start, at zero.
type halfCloseHoldCollector struct{}

// Describe implements prometheus.Collector.
func (halfCloseHoldCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- halfCloseHeldDesc
	ch <- halfCloseHeldOldestDesc
	ch <- halfCloseHoldAllowedDesc
	ch <- halfCloseHoldCapDesc
	ch <- halfCloseHoldDefaultModeDesc
	ch <- halfCloseHoldDesc
	ch <- halfCloseHoldEndedDesc
	ch <- halfCloseHoldExpiredDesc
	ch <- halfCloseHoldRefusedDesc
	ch <- halfCloseHoldSpuriousDesc
	ch <- halfCloseAccelSkippedDesc
}

// Collect implements prometheus.Collector.
func (halfCloseHoldCollector) Collect(ch chan<- prometheus.Metric) {
	holdStoreMutex.Lock()
	s := holdStore
	holdStoreMutex.Unlock()

	ch <- prometheus.MustNewConstMetric(halfCloseHeldDesc, prometheus.GaugeValue, float64(s.held))
	ch <- prometheus.MustNewConstMetric(halfCloseHeldOldestDesc, prometheus.GaugeValue,
		float64(s.oldestMs)/1000)
	ch <- prometheus.MustNewConstMetric(halfCloseHoldAllowedDesc, prometheus.GaugeValue, float64(s.allowed))
	ch <- prometheus.MustNewConstMetric(halfCloseHoldCapDesc, prometheus.GaugeValue, float64(s.capSec))
	defaultHold := 0.0
	if s.defaultMode == spHoldModeHold {
		defaultHold = 1
	}
	ch <- prometheus.MustNewConstMetric(halfCloseHoldDefaultModeDesc, prometheus.GaugeValue, defaultHold)
	ch <- prometheus.MustNewConstMetric(halfCloseHoldDesc, prometheus.CounterValue, float64(s.begun))
	for r := 1; r < holdEndReasons; r++ {
		ch <- prometheus.MustNewConstMetric(halfCloseHoldEndedDesc, prometheus.CounterValue,
			float64(s.ended[r]), holdEndLabels[r])
	}
	for b := 0; b < 2; b++ {
		for st := 0; st < hcStreams; st++ {
			ch <- prometheus.MustNewConstMetric(halfCloseHoldExpiredDesc, prometheus.CounterValue,
				float64(s.expired[b][st]), hcBool(b), hcStreamLabels[st])
		}
	}
	ch <- prometheus.MustNewConstMetric(halfCloseHoldRefusedDesc, prometheus.CounterValue,
		float64(s.refusedResidue), "pipeline_residue")
	ch <- prometheus.MustNewConstMetric(halfCloseHoldSpuriousDesc, prometheus.CounterValue,
		float64(s.reentry), "eof_reentry")
	ch <- prometheus.MustNewConstMetric(halfCloseHoldSpuriousDesc, prometheus.CounterValue,
		float64(s.emptyOut), "empty_out")
	ch <- prometheus.MustNewConstMetric(halfCloseAccelSkippedDesc, prometheus.CounterValue,
		float64(s.accelSkipped))
}

func init() {
	datapathRegisterer{}.MustRegister(halfCloseHoldCollector{})
}
