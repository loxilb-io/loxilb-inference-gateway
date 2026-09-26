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
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	auditops "github.com/loxilb-io/loxilb/api/restapi/operations/audit"
	"github.com/loxilb-io/loxilb/pkg/audit"
	tk "github.com/loxilb-io/loxilib"
)

// AuditGetStatus answers GET /audit/status: the writer's counters, the
// active segment, the retention it projects and the intents left without
// a result by the previous boot. It serves status and never content — the
// management API is the surface the trail exists to watch, so the trail
// is read by the SIEM and the on-host verifier, not through here. The
// read is not gated: it is designed to be polled, and a record per poll
// would bury the records that matter.
func AuditGetStatus(params auditops.GetAuditStatusParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Audit status %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	return auditops.NewGetAuditStatusOK().WithPayload(auditStatusModel(AuditWriter(), time.Now()))
}

// auditStatusModel maps the writer's snapshot onto the wire model. A nil
// writer is the deployment whose audit directory was unusable at start:
// the answer says so and carries the result-drop count, which the gate
// keeps outside the writer.
func auditStatusModel(w *audit.Writer, now time.Time) *models.AuditStatus {
	out := &models.AuditStatus{
		ResultDrops:       int64(AuditResultDrops()),
		OriginatorDropped: int64(AuditOriginatorDropped()),
		DelegationLookups: int64(AuditDelegationLookups()),
	}
	if w == nil {
		return out
	}
	st := w.Stats()
	out.Available = true
	out.Running = st.Running
	out.BootID = st.BootID
	out.SeqHigh = int64(st.SeqHigh)
	if st.LastWriteUnix != 0 {
		out.LastWrite = time.Unix(st.LastWriteUnix, 0).UTC().Format(time.RFC3339)
	}
	out.Accepted = make(map[string]int64, len(st.Accepted))
	for stream, n := range st.Accepted {
		out.Accepted[string(stream)] = int64(n)
	}
	for _, d := range st.Dropped {
		out.Dropped = append(out.Dropped, &models.AuditDropCount{
			Stream: string(d.Stream), Reason: d.Reason, Count: int64(d.Count),
		})
	}
	out.QueueDepth = make(map[string]int64, len(st.QueueDepth))
	for q, n := range st.QueueDepth {
		out.QueueDepth[q] = int64(n)
	}
	out.QueueHwm = make(map[string]int64, len(st.QueueHWM))
	for q, n := range st.QueueHWM {
		out.QueueHwm[q] = int64(n)
	}
	out.WriteFailures = int64(st.WriteFailures)
	out.SyncFailures = int64(st.SyncFailures)
	out.MgmtTimeouts = int64(st.MgmtTimeouts)
	out.Panics = int64(st.Panics)
	out.Restarts = int64(st.Restarts)
	out.Heartbeats = int64(st.Heartbeats)
	out.Rotations = int64(st.Rotations)
	out.PathSanitized = int64(st.PathSanitized)
	out.Unattributed = int64(st.Unattributed)
	out.PermRepaired = int64(st.PermRepaired)
	out.RotationFailed = int64(st.RotationFailed)
	out.CompressFailed = int64(st.CompressFailed)
	out.CompressSkipped = int64(st.CompressSkipped)
	out.Pruned = int64(st.Pruned)
	out.ReserveBreaches = int64(st.ReserveBreaches)
	out.ReserveBreached = st.ReserveBreached
	out.SealedBytes = st.SealedBytes
	out.OrphanedIntents = int64(st.OrphanedIntents)
	out.LastOrphanEventID = st.LastOrphanEventID
	out.Segment = &models.AuditSegmentStatus{
		UUID:    st.SegmentUUID,
		Records: int64(st.SegmentRecords),
		Bytes:   st.SegmentBytes,
	}
	if st.SegmentOpenedUnix != 0 {
		out.Segment.Opened = time.Unix(st.SegmentOpenedUnix, 0).UTC().Format(time.RFC3339)
	}
	out.Retention = &models.AuditRetentionPolicy{
		MaxAgeSeconds: int64(st.Retention.MaxAge / time.Second),
		MaxBytes:      st.Retention.MaxBytes,
		ReserveBytes:  st.Retention.ReserveBytes,
	}
	out.ProjectedRetentionDays = st.ProjectedRetentionDays(now)
	for _, p := range st.Producers {
		ps := &models.AuditProducerStatus{
			ID:                p.ID,
			Stream:            string(p.Stream),
			PseqHigh:          int64(p.PseqHigh),
			Accepted:          int64(p.Accepted),
			DropRingOverflows: int64(p.DropRingOverflows),
			Dropped:           make(map[string]int64, len(p.Dropped)),
		}
		for reason, n := range p.Dropped {
			ps.Dropped[reason] = int64(n)
		}
		out.Producers = append(out.Producers, ps)
	}
	return out
}
