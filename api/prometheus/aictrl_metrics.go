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

// AI-controller applier observability. Every
// series is set from the Go applier (pkg/loxinet/ai_ctrl_applier.go), which
// knows the effective post-α values — NOT from the C snapshot. Controller
// influence is fully reconstructable from /metrics: who weighs what, which
// epoch, which mode, how decayed, how often vetoed.
//
// Pure promauto file — no C bridge of any kind (auto-registers at import;
// a zero-valued series is NOT a behavior change; gauge REFRESH only happens
// while the env-gated applier is running, so G3 default-OFF is unaffected).
//
// Per-EP series are keyed by the opaque ep_idx label and join to endpoint
// IPs via the EXISTING loxilb_pd_ep_info info-metric:
//
//	loxilb_pd_ctrl_effective_weight * on(ep_idx) group_left(ep) loxilb_pd_ep_info
//
// (the tier15_hits labeling lesson —).
package prometheus

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// #1: per-EP effective routing weight actually written to C.
	aictrlEpEffectiveWeight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "loxilb_pd_ctrl_effective_weight",
			Help: "AI-controller effective per-EP routing weight (post-alpha, the value written to the data plane). Join ep_idx to an IP via: * on(ep_idx) group_left(ep) loxilb_pd_ep_info.",
		},
		[]string{"service", "ep_idx"},
	)

	// #2: per-EP controller lifecycle state.
	aictrlEpState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "loxilb_pd_ctrl_state",
			Help: "AI-controller per-EP state instruction: 0 none / 1 ACTIVE / 2 DRAINING / 3 DISABLED. Join ep_idx to an IP via: * on(ep_idx) group_left(ep) loxilb_pd_ep_info.",
		},
		[]string{"service", "ep_idx"},
	)

	// #3: last applied snapshot epoch per service.
	aictrlAppliedEpoch = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "loxilb_pd_ctrl_applied_epoch",
			Help: "Epoch of the last successfully applied AI-controller snapshot for the service.",
		},
		[]string{"service"},
	)

	// #4: applier mode ladder position (derived from alpha).
	aictrlMode = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_pd_ctrl_mode",
			Help: "AI-controller applier mode: 0 autonomous / 1 stale / 2 smart (a derived label of alpha — one continuous mechanism, not code paths).",
		},
	)

	// #5: the continuous controller-influence decay scalar.
	aictrlAlpha = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "loxilb_pd_ctrl_alpha",
			Help: "AI-controller influence scalar alpha(t) in [0,1]: 1 Smart, linear decay over the staleness window, 0 Autonomous.",
		},
	)

	// local-health veto counter — every suppressed controller write.
	aictrlOverrideEventsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_pd_ctrl_override_events_total",
			Help: "Total controller directives vetoed by LOCAL health (pure-intersection merge; local health always wins — G4 non-resurrection).",
		},
	)

	// NACKed (rejected) snapshots.
	aictrlNacksTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_pd_ctrl_nacks_total",
			Help: "Total AI-controller snapshots rejected by V5 validation (NACK ACK_STATUS_REJECTED; last-good kept, staleness clock keeps running).",
		},
	)

	// Successfully applied snapshots.
	aictrlSnapshotsAppliedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_pd_ctrl_snapshots_applied_total",
			Help: "Total AI-controller snapshots validated and applied (ACK ACK_STATUS_APPLIED).",
		},
	)
)

// SetAictrlEpWeight updates loxilb_pd_ctrl_effective_weight for one EP.
// Called from the applier's recording Sink on every C write (and by the
// pre-warm block with the neutral value 100 — lazy-vec guard).
func SetAictrlEpWeight(service string, epIdx int, w float64) {
	aictrlEpEffectiveWeight.WithLabelValues(service, strconv.Itoa(epIdx)).Set(w)
}

// SetAictrlEpState updates loxilb_pd_ctrl_state for one EP (0 none /
// 1 ACTIVE / 2 DRAINING / 3 DISABLED).
func SetAictrlEpState(service string, epIdx int, st float64) {
	aictrlEpState.WithLabelValues(service, strconv.Itoa(epIdx)).Set(st)
}

// SetAictrlEpoch records the applied snapshot epoch for a service.
func SetAictrlEpoch(service string, e float64) {
	aictrlAppliedEpoch.WithLabelValues(service).Set(e)
}

// DeleteAictrlEpSeries removes the per-EP weight/state series for a
// decommissioned endpoint so stale children do not linger on /metrics
// (series lifecycle, metrics audit). Called from the applier's reconcile
// sweep when an EP leaves the locally-known set.
func DeleteAictrlEpSeries(service string, epIdx int) {
	idx := strconv.Itoa(epIdx)
	aictrlEpEffectiveWeight.DeleteLabelValues(service, idx)
	aictrlEpState.DeleteLabelValues(service, idx)
}

// DeleteAictrlEpochSeries removes a removed service's applied-epoch series.
func DeleteAictrlEpochSeries(service string) {
	aictrlAppliedEpoch.DeleteLabelValues(service)
}

// SetAictrlMode records the mode ladder position (0/1/2).
func SetAictrlMode(m float64) {
	aictrlMode.Set(m)
}

// SetAictrlAlpha records the decay scalar alpha(t).
func SetAictrlAlpha(a float64) {
	aictrlAlpha.Set(a)
}

// IncAictrlOverride counts one local-health veto.
func IncAictrlOverride() {
	aictrlOverrideEventsTotal.Inc()
}

// IncAictrlNack counts one rejected snapshot.
func IncAictrlNack() {
	aictrlNacksTotal.Inc()
}

// IncAictrlApplied counts one applied snapshot.
func IncAictrlApplied() {
	aictrlSnapshotsAppliedTotal.Inc()
}
