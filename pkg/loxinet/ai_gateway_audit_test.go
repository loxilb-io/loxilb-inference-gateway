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

package loxinet

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/audit"
)

// auditLine is one decoded record read back from a segment.
type auditLine map[string]any

func (l auditLine) str(k string) string {
	v, _ := l[k].(string)
	return v
}

func (l auditLine) num(k string) float64 {
	v, _ := l[k].(float64)
	return v
}

func (l auditLine) obj(k string) map[string]any {
	v, _ := l[k].(map[string]any)
	return v
}

func (l auditLine) detail() auditLine { return auditLine(l.obj("detail")) }

func (l auditLine) actor() auditLine { return auditLine(l.obj("actor")) }

func (l auditLine) outcome() auditLine { return auditLine(l.obj("outcome")) }

// startTrail installs a real writer over a temporary directory and returns
// a function that closes it and hands back every record written. The
// producer cache is reset with it, so one test's producers never answer
// for another's writer.
func startTrail(t *testing.T) (dir string, drain func() []auditLine) {
	t.Helper()
	dir = t.TempDir()
	// The writer refuses a directory it does not own exclusively, and the
	// test framework's temporary directory is group- and world-readable.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := audit.New(audit.Config{
		Dir:               dir,
		CreateDir:         true,
		InstanceID:        "test",
		HeartbeatInterval: time.Hour,
		Logf:              func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	// Start only launches the writer goroutine; until it marks itself
	// running every emit is correctly dropped as "writer down". Waiting
	// here keeps that from reading as a defect in what is being tested.
	deadline := time.Now().Add(10 * time.Second)
	for !w.Running() {
		if time.Now().After(deadline) {
			t.Fatal("writer did not start")
		}
		time.Sleep(time.Millisecond)
	}
	audit.SetGlobal(w)
	aiAuditProdCache.Store(nil)
	t.Cleanup(func() {
		audit.SetGlobal(nil)
		aiAuditProdCache.Store(nil)
	})

	return dir, func() []auditLine {
		// The writer must be closed before the directory is read: a record
		// is durable only once the segment is flushed and sealed.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := w.Close(ctx); err != nil {
			t.Fatalf("close: %v", err)
		}
		audit.SetGlobal(nil)
		return readTrail(t, dir)
	}
}

// readTrail decodes every record in the audit directory, skipping the
// segment header and footer lines, which carry "kind" instead of a record.
func readTrail(t *testing.T, dir string) []auditLine {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []auditLine
	for _, e := range entries {
		out = append(out, readTrailFile(t, filepath.Join(dir, e.Name()))...)
	}
	return out
}

// readTrailFile decodes one segment, sealed-and-compressed or active.
func readTrailFile(t *testing.T, path string) []auditLine {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer zr.Close()
		r = zr
	}

	var out []auditLine
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var m auditLine
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue
		}
		if _, isMeta := m["kind"]; isMeta {
			continue
		}
		out = append(out, m)
	}
	return out
}

// ofEvent returns the records of one event type.
func ofEvent(ls []auditLine, eventType string) []auditLine {
	var out []auditLine
	for _, l := range ls {
		if l.str("event_type") == eventType {
			out = append(out, l)
		}
	}
	return out
}

// only returns the single record of an event type, failing when the count
// is anything but one. "Exactly one record per event" is the property most
// of these tests are really asserting, so it is checked in one place.
func only(t *testing.T, ls []auditLine, eventType string) auditLine {
	t.Helper()
	got := ofEvent(ls, eventType)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 %s record, got %d", eventType, len(got))
	}
	return got[0]
}

func TestEmitAICompleteRecordsTheRequest(t *testing.T) {
	_, drain := startTrail(t)

	if !emitAIComplete(aiCompleteRecord{
		RequestID:  "req-1",
		TenantID:   "acme",
		UserID:     "u-1",
		KeyID:      "k-1",
		SvcIdent:   "10.0.0.1:8080",
		ModelName:  "llama-3",
		StatusCode: 200,
		LatencyMs:  42,
		TokensIn:   11,
		TokensOut:  22,
		IsStream:   true,
		WorkerID:   3,
	}) {
		t.Fatal("emit refused")
	}

	r := only(t, drain(), eventAIComplete)
	if got := r.str("stream"); got != "data" {
		t.Errorf("stream = %q, want data", got)
	}
	if got := r.str("request_id"); got != "req-1" {
		t.Errorf("request_id = %q, want req-1", got)
	}
	if got := r.str("class"); got != "" {
		t.Errorf("class = %q, want empty: a completion is not a security record", got)
	}
	a := r.actor()
	if a.str("tenant") != "acme" || a.str("user") != "u-1" || a.str("key_id") != "k-1" {
		t.Errorf("actor = %v, want the admitted identity", a)
	}
	if got := a.str("auth"); got != string(audit.AuthAPIKey) {
		t.Errorf("auth = %q, want apikey", got)
	}
	o := r.outcome()
	if o.num("status") != 200 || o.str("reason") != string(audit.ReasonOK) {
		t.Errorf("outcome = %v, want 200/ok", o)
	}
	if ok, _ := o["ok"].(bool); !ok {
		t.Error("ok = false, want true for a 200")
	}
	d := r.detail()
	if d.str("service") != "10.0.0.1:8080" || d.str("model") != "llama-3" {
		t.Errorf("detail = %v, want the service and model", d)
	}
	if d.num("tokens_in") != 11 || d.num("tokens_out") != 22 || d.num("latency_ms") != 42 {
		t.Errorf("detail = %v, want the reported usage and latency", d)
	}
	if isStream, _ := d["stream"].(bool); !isStream {
		t.Error("detail.stream = false, want true")
	}
}

// A completion record has nowhere to put a prompt or a response, and this
// test is the assertion of that rather than a reading of the struct: a
// field added later that could carry body bytes fails here.
func TestEmitAICompleteCarriesNoBody(t *testing.T) {
	_, drain := startTrail(t)

	emitAIComplete(aiCompleteRecord{
		RequestID: "req-1", TenantID: "acme", ModelName: "llama-3",
		StatusCode: 200, WorkerID: 0,
	})

	d := only(t, drain(), eventAIComplete).detail()
	for _, forbidden := range []string{"body", "prompt", "response", "messages", "content", "completion"} {
		if _, found := d[forbidden]; found {
			t.Errorf("detail carries %q; the data record has no field for request or response bytes", forbidden)
		}
	}
}

func TestEmitAICompleteReasonFollowsTheDatapath(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		errorCode string
		want      audit.Reason
		wantOK    bool
	}{
		{"ok", 200, "", audit.ReasonOK, true},
		{"client walked away", 0, "client_abort", audit.ReasonClientAbort, false},
		{"backend timed out", 504, "timeout", audit.ReasonTimeout, false},
		{"backend refused the connection", 502, "backend_conn", audit.ReasonBackendConn, false},
		{"backend TLS failed", 502, "backend_tls", audit.ReasonBackendTLS, false},
		// A bad status with no error code is still not an OK response, and
		// the record says so rather than reporting a successful request.
		{"backend 500 with no code", 500, "", audit.ReasonUpstreamError, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, drain := startTrail(t)
			emitAIComplete(aiCompleteRecord{
				RequestID: "req-1", TenantID: "acme",
				StatusCode: tc.status, ErrorCode: tc.errorCode, WorkerID: 0,
			})
			o := only(t, drain(), eventAIComplete).outcome()
			if got := o.str("reason"); got != string(tc.want) {
				t.Errorf("reason = %q, want %q", got, tc.want)
			}
			if ok, _ := o["ok"].(bool); ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
		})
	}
}

func TestEmitAISettleRecordsTheCharge(t *testing.T) {
	_, drain := startTrail(t)

	if !emitAISettle(aiSettleRecord{
		RequestID: "req-1",
		TenantID:  "acme",
		UserID:    "u-1",
		KeyID:     "k-1",
		SvcIdent:  "10.0.0.1:8080",
		ModelName: "llama-3",
		TokensIn:  11,
		TokensOut: 22,
		Reserved:  100,
		ResEpoch:  7,
		Allowed:   true,
		WorkerID:  3,
	}) {
		t.Fatal("emit refused")
	}

	r := only(t, drain(), eventAISettle)
	if got := r.str("request_id"); got != "req-1" {
		t.Errorf("request_id = %q, want req-1: the settle joins the completion by key", got)
	}
	d := r.detail()
	if d.num("tokens_in") != 11 || d.num("tokens_out") != 22 {
		t.Errorf("detail = %v, want the charged tokens", d)
	}
	if d.num("reserved") != 100 || d.num("res_epoch") != 7 {
		t.Errorf("detail = %v, want the reservation it closes", d)
	}
	if got := r.outcome().str("reason"); got != string(audit.ReasonOK) {
		t.Errorf("reason = %q, want ok", got)
	}
}

// Releasing an unspent reservation charges nothing, and is still the event
// that explains why a tenant's headroom came back.
func TestEmitAISettleRecordsAPureRelease(t *testing.T) {
	_, drain := startTrail(t)

	emitAISettle(aiSettleRecord{
		RequestID: "req-1", TenantID: "acme",
		Reserved: 500, ResEpoch: 9, Allowed: true, WorkerID: -1,
	})

	d := only(t, drain(), eventAISettle).detail()
	if d.num("tokens_in") != 0 || d.num("tokens_out") != 0 {
		t.Errorf("detail = %v, want no tokens charged", d)
	}
	if d.num("reserved") != 500 {
		t.Errorf("detail = %v, want the released reservation", d)
	}
}

func TestEmitAISettleOverQuotaSaysSo(t *testing.T) {
	_, drain := startTrail(t)

	emitAISettle(aiSettleRecord{
		RequestID: "req-1", TenantID: "acme",
		TokensIn: 10, TokensOut: 10, Allowed: false, WorkerID: 0,
	})

	o := only(t, drain(), eventAISettle).outcome()
	if got := o.str("reason"); got != string(audit.ReasonQuota) {
		t.Errorf("reason = %q, want quota", got)
	}
	if ok, _ := o["ok"].(bool); ok {
		t.Error("ok = true, want false on a refused charge")
	}
}

func TestEmitAIDenyIsASecurityRecord(t *testing.T) {
	_, drain := startTrail(t)

	if !emitAIDeny(aiDenyRecord{
		RequestID:  "req-1",
		TenantID:   "acme",
		KeyID:      "k-1",
		SvcIdent:   "10.0.0.1:8080",
		ModelName:  "llama-3",
		Stage:      aiStageAuth,
		HTTPStatus: 403,
		ErrorCode:  "model_not_allowed",
		WorkerID:   2,
	}) {
		t.Fatal("emit refused")
	}

	r := only(t, drain(), eventAIDeny)
	if got := r.str("class"); got != string(audit.ClassSecurity) {
		t.Errorf("class = %q, want security: a refusal leaves on the security queue", got)
	}
	if got := r.str("stream"); got != "data" {
		t.Errorf("stream = %q, want data", got)
	}
	// The 403 arm resolved an identity before refusing, and the record has
	// to carry it: a refusal that names nobody cannot be investigated.
	if got := r.actor().str("tenant"); got != "acme" {
		t.Errorf("actor.tenant = %q, want acme on the 403 arm", got)
	}
	if got := r.actor().str("key_id"); got != "k-1" {
		t.Errorf("actor.key_id = %q, want k-1", got)
	}
	o := r.outcome()
	if o.num("status") != 403 || o.str("reason") != string(audit.ReasonAuthz) {
		t.Errorf("outcome = %v, want 403/authz", o)
	}
	d := r.detail()
	if d.str("stage") != "auth" || d.str("decision") != "model_not_allowed" {
		t.Errorf("detail = %v, want the refusing stage and its code", d)
	}
}

// The credential never reaches the record, whatever the arm was told.
func TestEmitAIDenyCarriesNoCredential(t *testing.T) {
	_, drain := startTrail(t)

	emitAIDeny(aiDenyRecord{
		RequestID: "req-1", Stage: aiStageAuth,
		HTTPStatus: 401, ErrorCode: "invalid_api_key", WorkerID: 0,
	})

	r := only(t, drain(), eventAIDeny)
	if got := r.actor().str("tenant"); got != "" {
		t.Errorf("actor.tenant = %q, want empty: an unrecognised credential names nobody", got)
	}
	if got := r.actor().str("auth"); got != string(audit.AuthNone) {
		t.Errorf("auth = %q, want none when no key was resolved", got)
	}
	for _, forbidden := range []string{"api_key", "key", "bearer", "token", "authorization", "secret"} {
		if _, found := r.actor()[forbidden]; found {
			t.Errorf("actor carries %q", forbidden)
		}
		if _, found := r.detail()[forbidden]; found {
			t.Errorf("detail carries %q", forbidden)
		}
	}
}

func TestAIDenyReasonPerStage(t *testing.T) {
	cases := []struct {
		name      string
		stage     int
		errorCode string
		wantStage string
		want      audit.Reason
	}{
		{"bad credential", aiStageAuth, "invalid_api_key", "auth", audit.ReasonAuth},
		{"bad bearer", aiStageAuth, "invalid_token", "auth", audit.ReasonAuth},
		{"model refused a valid key", aiStageAuth, "model_not_allowed", "auth", audit.ReasonAuthz},
		// A store that cannot answer is an infrastructure fault, not a
		// break-in attempt, and must not be filed as one.
		{"policy store down", aiStageAuth, "policy_store_unavailable", "auth", audit.ReasonAdmission},
		{"model conflict", aiStageConflict, "model_conflict", "conflict", audit.ReasonAdmission},
		{"rate limited", aiStageRateLimit, "rate_limit_exceeded", "ratelimit", audit.ReasonRateLimit},
		{"tenant rate limited", aiStageRateLimit, "tenant_quota_exceeded", "ratelimit", audit.ReasonRateLimit},
		// The rate-limit stage also answers a spent token budget. That is a
		// different resource with a different remedy, so it must not read
		// as throttling.
		{"token budget already spent", aiStageRateLimit, "token_quota_exceeded", "ratelimit", audit.ReasonQuota},
		{"token budget would be exceeded", aiStageRateLimit, "token_quota_would_exceed", "ratelimit", audit.ReasonQuota},
		{"reservation refused", aiStageReserve, "token_quota_exceeded", "reserve", audit.ReasonQuota},
		{"no stage reported", aiStageNone, "", "keyless", audit.ReasonAdmission},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aiDenyReason(tc.stage, tc.errorCode); got != tc.want {
				t.Errorf("reason = %q, want %q", got, tc.want)
			}
			if got := aiDenyStage(tc.stage); got != tc.wantStage {
				t.Errorf("stage = %q, want %q", got, tc.wantStage)
			}
		})
	}
}

// Every reason this file can produce must be in the envelope's closed
// vocabulary, or the record is dropped as invalid at Validate and the
// refusal goes unrecorded — the one outcome this whole path exists to
// prevent.
func TestAIReasonsAreInTheVocabulary(t *testing.T) {
	for _, stage := range []int{aiStageNone, aiStageAuth, aiStageConflict, aiStageRateLimit, aiStageReserve, 99} {
		for _, code := range []string{"", "invalid_api_key", "invalid_token", "model_not_allowed",
			"policy_store_unavailable", "model_conflict", "rate_limit_exceeded",
			"tenant_quota_exceeded", "token_quota_exceeded", "token_quota_would_exceed"} {
			if r := aiDenyReason(stage, code); !audit.ValidReason(r) {
				t.Errorf("aiDenyReason(%d, %q) = %q, not in the vocabulary", stage, code, r)
			}
		}
	}
	for _, code := range []string{"", "client_abort", "timeout", "backend_conn", "backend_tls", "upstream_error", "nonsense"} {
		for _, status := range []int{0, 200, 404, 500} {
			if r := aiCompleteReason(status, code); !audit.ValidReason(r) {
				t.Errorf("aiCompleteReason(%d, %q) = %q, not in the vocabulary", status, code, r)
			}
		}
	}
}

// Each worker emits through its own producer, so a hole in one worker's
// sequence is reported as that worker's hole and not smeared across the
// others. The producer identity is not a record field — the writer tracks
// it per producer and reports it at the heartbeat — so the mapping is
// asserted where it is made.
func TestProducerIdentityPerWorker(t *testing.T) {
	_, drain := startTrail(t)

	w := audit.Global()
	seen := map[*audit.Producer]int{}
	for _, id := range []int{0, 1, 7} {
		p := aiDataProducer(w, id)
		if p == nil {
			t.Fatalf("worker %d got no producer", id)
		}
		if prev, dup := seen[p]; dup {
			t.Fatalf("workers %d and %d share a producer", prev, id)
		}
		seen[p] = id
		emitAIComplete(aiCompleteRecord{
			RequestID: "req", TenantID: "acme", StatusCode: 200, WorkerID: id,
		})
	}

	if got := len(ofEvent(drain(), eventAIComplete)); got != 3 {
		t.Fatalf("want 3 completion records, got %d", got)
	}
}

// A record emitted off a relay worker is attributed to the control side by
// name. It must never fall to the unattributed identity: that counter is
// the signal for attribution genuinely lost, and spending it on a caller
// we can name would leave it permanently non-zero.
func TestNonWorkerProducerIsNamedNotUnattributed(t *testing.T) {
	_, drain := startTrail(t)

	emitAISettle(aiSettleRecord{
		RequestID: "req-1", TenantID: "acme", Reserved: 10, Allowed: true, WorkerID: -1,
	})

	ls := drain()
	if got := len(ofEvent(ls, eventAISettle)); got != 1 {
		t.Fatalf("want 1 settle record, got %d", got)
	}

	// The heartbeat is the only place the writer reports its unattributed
	// count, and the identity itself is the thing under test, so assert on
	// the mapping directly as well.
	if got := aiWorkerProducerID(4); got != "w4" {
		t.Errorf("worker producer id = %q, want w4", got)
	}
	if ctlProducerID == audit.UnattributedProducer {
		t.Fatal("the control producer must not be the unattributed identity")
	}
	if ctlProducerID == "" {
		t.Fatal("the control producer must have a name")
	}
}

// The producer for a given thread is resolved once and reused; a second
// lookup must not build a second producer, or every request would pay for
// a locked walk of the producer list.
func TestProducerCacheReusesProducers(t *testing.T) {
	_, drain := startTrail(t)
	defer drain()

	w := audit.Global()
	first := aiDataProducer(w, 2)
	second := aiDataProducer(w, 2)
	if first == nil || first != second {
		t.Fatalf("producer lookup returned %p then %p, want one cached producer", first, second)
	}
	ctlFirst := aiDataProducer(w, -1)
	ctlSecond := aiDataProducer(w, -3)
	if ctlFirst == nil || ctlFirst != ctlSecond {
		t.Fatal("every non-worker caller shares one control producer")
	}
	if ctlFirst == first {
		t.Fatal("the control producer must be distinct from a worker's")
	}
}

// With no trail running the data path carries on: the emitters report that
// nothing was written and never panic, because a gateway without an audit
// directory still has to answer inference requests.
func TestEmittersAreSafeWithNoTrail(t *testing.T) {
	audit.SetGlobal(nil)
	aiAuditProdCache.Store(nil)
	t.Cleanup(func() { aiAuditProdCache.Store(nil) })

	if emitAIComplete(aiCompleteRecord{RequestID: "r", WorkerID: 0}) {
		t.Error("complete reported a write with no writer")
	}
	if emitAISettle(aiSettleRecord{RequestID: "r", WorkerID: 0}) {
		t.Error("settle reported a write with no writer")
	}
	if emitAIDeny(aiDenyRecord{RequestID: "r", WorkerID: 0}) {
		t.Error("deny reported a write with no writer")
	}
	if p := aiDataProducer(nil, 0); p != nil {
		t.Error("producer lookup invented a producer with no writer")
	}
}
