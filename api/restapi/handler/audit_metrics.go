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
package handler

import (
	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/prometheus/client_golang/prometheus"
)

// The audit trail's own metrics. They are the independent witness to the
// writer's failure: when the writer cannot write, the record of that
// fact cannot be in the trail, so it is here and in the ordinary log. The
// families are read from the writer's counters at scrape time — nothing on
// the write path touches a metric — and every counter is emitted from
// start, at zero, so an absent series is never mistaken for a quiet one.
var (
	auditWriterUpDesc = prometheus.NewDesc(
		"loxilb_audit_writer_up",
		"1 while the audit writer goroutine is running; 0 while it restarts after a failure, and 0 when no writer was configured because the audit directory was unusable at start. Every audited management call is refused while this is 0.",
		nil, nil)
	auditRecordsWrittenDesc = prometheus.NewDesc(
		"loxilb_audit_records_written_total",
		"Audit records appended to the trail, by stream (mgmt, data, audit_system).",
		[]string{"stream"}, nil)
	auditRecordsDroppedDesc = prometheus.NewDesc(
		"loxilb_audit_records_dropped_total",
		"Audit records the writer could not accept, by stream and reason (queue_full, writer_down, invalid, disk_reserve). A management drop refused the call; a data or system drop is a record that does not exist.",
		[]string{"stream", "reason"}, nil)
	auditResultWriteFailuresDesc = prometheus.NewDesc(
		"loxilb_audit_result_write_failures_total",
		"Management result records lost after the change had been applied; the durable intent stays in the trail without its outcome.",
		nil, nil)
	auditWriteFailuresDesc = prometheus.NewDesc(
		"loxilb_audit_write_failures_total",
		"Appends to the active segment that failed. The writer records the failure interval in the trail once writing resumes; until then this counter and the log are the only evidence.",
		nil, nil)
	auditSyncFailuresDesc = prometheus.NewDesc(
		"loxilb_audit_sync_failures_total",
		"fsyncs of the active segment that failed; a durable management write that hit one was refused.",
		nil, nil)
	auditMgmtTimeoutsDesc = prometheus.NewDesc(
		"loxilb_audit_mgmt_timeouts_total",
		"Durable management writes that missed the request's deadline; each one refused a management call.",
		nil, nil)
	auditWriterPanicsDesc = prometheus.NewDesc(
		"loxilb_audit_writer_panics_total",
		"Writer goroutine panics caught by the supervisor.",
		nil, nil)
	auditWriterRestartsDesc = prometheus.NewDesc(
		"loxilb_audit_writer_restarts_total",
		"Writer goroutine restarts by the supervisor; each one is a gap during which audited management calls were refused.",
		nil, nil)
	auditLastWriteDesc = prometheus.NewDesc(
		"loxilb_audit_last_write_timestamp_seconds",
		"Unix time of the last durable audit write; 0 until the first.",
		nil, nil)
	auditLastHeartbeatDesc = prometheus.NewDesc(
		"loxilb_audit_last_heartbeat_timestamp_seconds",
		"Unix time of the writer's last liveness record; a value that stops advancing is a writer that is not running, whatever the counters say.",
		nil, nil)
	auditUnattributedDesc = prometheus.NewDesc(
		"loxilb_audit_records_unattributed_total",
		"Records that reached the writer without a producer identity; a producer-side loss of such a record cannot be reconciled.",
		nil, nil)
	auditOrphanedIntentsDesc = prometheus.NewDesc(
		"loxilb_audit_orphaned_intents_total",
		"Management intents of the previous boot found without a result at this writer's start: changes whose outcome is unknown, each reported in the trail as an orphaned intent.",
		nil, nil)
	auditSealFailuresDesc = prometheus.NewDesc(
		"loxilb_audit_segment_seal_failures_total",
		"Segment rotations that failed to seal the active segment; the writer keeps appending to it and retries at the next rotation.",
		nil, nil)
	auditSegmentsPrunedDesc = prometheus.NewDesc(
		"loxilb_audit_segments_pruned_total",
		"Sealed segments deleted by the retention policy, each announced in the trail before deletion.",
		nil, nil)
	auditReserveBreachedDesc = prometheus.NewDesc(
		"loxilb_audit_reserve_breached",
		"1 while the audit filesystem is below its configured free-space reserve; durable management writes are refused until space is recovered.",
		nil, nil)
	auditOriginatorDroppedDesc = prometheus.NewDesc(
		"loxilb_audit_originator_dropped_total",
		"X-Loxilb-Originator headers that did not parse and were dropped rather than recorded in part.",
		nil, nil)
	auditDelegationLookupsDesc = prometheus.NewDesc(
		"loxilb_audit_delegation_lookups_total",
		"Account lookups made to decide whether a named originator is trusted; a request without the header makes none.",
		nil, nil)
)

// auditCollector emits the audit families from the writer's snapshot on
// every scrape. It is registered at package init, before any writer exists,
// so the up gauge is 0 and the gate's own counters are visible from the
// first scrape of a gateway whose audit directory was unusable.
type auditCollector struct{}

// Describe implements prometheus.Collector.
func (auditCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		auditWriterUpDesc, auditRecordsWrittenDesc, auditRecordsDroppedDesc,
		auditResultWriteFailuresDesc, auditWriteFailuresDesc, auditSyncFailuresDesc,
		auditMgmtTimeoutsDesc, auditWriterPanicsDesc, auditWriterRestartsDesc,
		auditLastWriteDesc, auditLastHeartbeatDesc, auditUnattributedDesc,
		auditOrphanedIntentsDesc, auditSealFailuresDesc, auditSegmentsPrunedDesc,
		auditReserveBreachedDesc, auditOriginatorDroppedDesc, auditDelegationLookupsDesc,
	} {
		ch <- d
	}
}

// Collect implements prometheus.Collector. Each family is emitted at its
// own constructor call, so the runtime type is readable from the source.
func (auditCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(auditResultWriteFailuresDesc, prometheus.CounterValue, float64(AuditResultDrops()))
	ch <- prometheus.MustNewConstMetric(auditOriginatorDroppedDesc, prometheus.CounterValue, float64(AuditOriginatorDropped()))
	ch <- prometheus.MustNewConstMetric(auditDelegationLookupsDesc, prometheus.CounterValue, float64(AuditDelegationLookups()))

	w := AuditWriter()
	if w == nil {
		ch <- prometheus.MustNewConstMetric(auditWriterUpDesc, prometheus.GaugeValue, 0)
		return
	}
	st := w.Stats()
	up := 0.0
	if st.Running {
		up = 1
	}
	ch <- prometheus.MustNewConstMetric(auditWriterUpDesc, prometheus.GaugeValue, up)
	dropped := map[audit.Stream]map[string]uint64{}
	for _, d := range st.Dropped {
		if dropped[d.Stream] == nil {
			dropped[d.Stream] = map[string]uint64{}
		}
		dropped[d.Stream][d.Reason] = d.Count
	}
	for _, stream := range audit.Streams() {
		ch <- prometheus.MustNewConstMetric(auditRecordsWrittenDesc, prometheus.CounterValue, float64(st.Accepted[stream]), string(stream))
		for _, reason := range audit.DropReasons() {
			ch <- prometheus.MustNewConstMetric(auditRecordsDroppedDesc, prometheus.CounterValue, float64(dropped[stream][reason]), string(stream), reason)
		}
	}
	ch <- prometheus.MustNewConstMetric(auditWriteFailuresDesc, prometheus.CounterValue, float64(st.WriteFailures))
	ch <- prometheus.MustNewConstMetric(auditSyncFailuresDesc, prometheus.CounterValue, float64(st.SyncFailures))
	ch <- prometheus.MustNewConstMetric(auditMgmtTimeoutsDesc, prometheus.CounterValue, float64(st.MgmtTimeouts))
	ch <- prometheus.MustNewConstMetric(auditWriterPanicsDesc, prometheus.CounterValue, float64(st.Panics))
	ch <- prometheus.MustNewConstMetric(auditWriterRestartsDesc, prometheus.CounterValue, float64(st.Restarts))
	ch <- prometheus.MustNewConstMetric(auditLastWriteDesc, prometheus.GaugeValue, float64(st.LastWriteUnix))
	ch <- prometheus.MustNewConstMetric(auditLastHeartbeatDesc, prometheus.GaugeValue, float64(st.LastHeartbeatUnix))
	ch <- prometheus.MustNewConstMetric(auditUnattributedDesc, prometheus.CounterValue, float64(st.Unattributed))
	ch <- prometheus.MustNewConstMetric(auditOrphanedIntentsDesc, prometheus.CounterValue, float64(st.OrphanedIntents))
	ch <- prometheus.MustNewConstMetric(auditSealFailuresDesc, prometheus.CounterValue, float64(st.RotationFailed))
	ch <- prometheus.MustNewConstMetric(auditSegmentsPrunedDesc, prometheus.CounterValue, float64(st.Pruned))
	breached := 0.0
	if st.ReserveBreached {
		breached = 1
	}
	ch <- prometheus.MustNewConstMetric(auditReserveBreachedDesc, prometheus.GaugeValue, breached)
}

func init() {
	prometheus.MustRegister(auditCollector{})
}
