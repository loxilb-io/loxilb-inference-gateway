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
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/api/models"
	auditops "github.com/loxilb-io/loxilb/api/restapi/operations/audit"
	"github.com/loxilb-io/loxilb/pkg/audit"
)

// getAuditStatus serves the status handler and returns the decoded
// payload with the bytes it was decoded from.
func getAuditStatus(t *testing.T, f *gateFixture, r *http.Request) (*models.AuditStatus, string) {
	t.Helper()
	rec := f.serve(AuditGetStatus(auditops.GetAuditStatusParams{HTTPRequest: r}, "alice|admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status answered %d: %s", rec.Code, rec.Body.String())
	}
	var st models.AuditStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("status body: %v: %s", err, rec.Body.String())
	}
	return &st, rec.Body.String()
}

// The status read reports the writer that the gate is using, is served
// through the gate without producing a record of its own, and carries no
// record content: a value written into the trail must not come back out
// of the status endpoint.
func TestAuditStatusReportsTheWriterAndIsNotAudited(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	canary := "canary-resource-7f3a"
	var st *models.AuditStatus
	var raw string
	f.inside = func(r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/audit/status") {
			RecordAuditPrincipal(r, "alice|admin")
			st, raw = getAuditStatus(t, f, r)
		}
	}
	// One gated mutation, whose body names the canary.
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"name":"`+canary+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("mutation answered %d", rec.Code)
	}
	// The result is appended after the response; wait for it so the
	// counters below are settled.
	var want audit.Stats
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if want = f.w.Stats(); want.Accepted[audit.StreamMgmt] >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the mutation's pair never landed: %v", want.Accepted)
		}
	}
	if rec := f.do(http.MethodGet, "/netlox/v1/audit/status", ""); rec.Code != http.StatusOK {
		t.Fatalf("status answered %d", rec.Code)
	}
	if !st.Available || !st.Running {
		t.Fatalf("available=%v running=%v, want both", st.Available, st.Running)
	}
	if st.BootID != f.w.BootID() {
		t.Fatalf("boot_id %q, want %q", st.BootID, f.w.BootID())
	}
	if st.SeqHigh < 2 || st.Accepted["mgmt"] < 2 {
		t.Fatalf("intent and result not counted: seq_high=%d accepted=%v", st.SeqHigh, st.Accepted)
	}
	if st.LastWrite == "" {
		t.Fatal("last_write empty after a write")
	}
	if _, err := time.Parse(time.RFC3339, st.LastWrite); err != nil {
		t.Fatalf("last_write %q: %v", st.LastWrite, err)
	}
	if st.Segment == nil || st.Segment.UUID != want.SegmentUUID || st.Segment.Records < 2 || st.Segment.Bytes == 0 || st.Segment.Opened == "" {
		t.Fatalf("segment %+v, want uuid %s with the records in it", st.Segment, want.SegmentUUID)
	}
	if st.Retention == nil {
		t.Fatal("retention policy absent")
	}
	if st.ProjectedRetentionDays != 0 {
		t.Fatalf("an unbounded policy projects %v days, want 0", st.ProjectedRetentionDays)
	}
	if st.OrphanedIntents != 0 || st.LastOrphanEventID != "" {
		t.Fatalf("a clean start reports orphans: %d %q", st.OrphanedIntents, st.LastOrphanEventID)
	}
	if st.ResultDrops != int64(AuditResultDrops()) {
		t.Fatalf("result_drops %d, want %d", st.ResultDrops, AuditResultDrops())
	}
	if strings.Contains(raw, canary) {
		t.Fatalf("record content served through the status endpoint: %s", raw)
	}

	// The status read left no record behind: only the mutation's pair.
	recs := f.records()
	if len(recs) != 2 {
		t.Fatalf("got %d records, want the mutation's intent and result only", len(recs))
	}
	for _, r := range recs {
		if p, _ := r["mgmt"].(map[string]any); p != nil && strings.Contains(p["path"].(string), "audit") {
			t.Fatalf("the status read was recorded: %v", r)
		}
	}
}

// Without a writer the endpoint still answers, so an operator can see why
// every audited call is being refused, and the result-drop counter the
// gate keeps outside the writer is still reported.
func TestAuditStatusWithoutWriter(t *testing.T) {
	SetAuditWriter(nil)
	st := auditStatusModel(nil, time.Now())
	if st.Available || st.Running {
		t.Fatalf("available=%v running=%v without a writer", st.Available, st.Running)
	}
	if st.ResultDrops != int64(AuditResultDrops()) {
		t.Fatalf("result_drops %d, want %d", st.ResultDrops, AuditResultDrops())
	}
	if st.Segment != nil || st.Retention != nil || st.BootID != "" {
		t.Fatalf("a missing writer described: %+v", st)
	}
}

// A retention policy is projected from the age bound; the writer under
// the gate carries the policy it was given.
func TestAuditStatusProjectsRetention(t *testing.T) {
	f := newGateFixture(t)
	f.w.SetRetention(audit.Retention{MaxAge: 72 * time.Hour})
	st := auditStatusModel(f.w, time.Now())
	if st.Retention.MaxAgeSeconds != 72*3600 {
		t.Fatalf("max_age_seconds %d", st.Retention.MaxAgeSeconds)
	}
	if st.ProjectedRetentionDays != 3 {
		t.Fatalf("projected_retention_days %v, want 3", st.ProjectedRetentionDays)
	}
}
