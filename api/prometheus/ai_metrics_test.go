/*
 * Copyright (c) 2025 LoxiLB Authors
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
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// getGaugeValue reads the current value of the aiActiveStreams gauge for the
// given model label. It returns 0.0 if the label combination has not been set.
func getGaugeValue(model string) float64 {
	m := &dto.Metric{}
	gauge := aiActiveStreams.WithLabelValues(sanitizeLabel(model))
	if err := gauge.(interface{ Write(*dto.Metric) error }).Write(m); err != nil {
		return 0.0
	}
	return m.GetGauge().GetValue()
}

// TestAdjustActiveStreams verifies the open/close stream lifecycle through
// AdjustActiveStreams, the single authoritative path for the gauge.
func TestAdjustActiveStreams(t *testing.T) {
	model := "test-model-streams"

	AdjustActiveStreams(model, +1.0)
	if v := getGaugeValue(model); v != 1.0 {
		t.Fatalf("expected gauge=1.0 after stream open, got %f", v)
	}

	AdjustActiveStreams(model, -1.0)
	if v := getGaugeValue(model); v != 0.0 {
		t.Fatalf("expected gauge=0.0 after stream close, got %f", v)
	}
}

// getCounterValue reads the current value of a CounterVec for the given label
// values. It returns 0.0 if the label combination has not been set.
func getCounterValue(cv *prometheus.CounterVec, lvs ...string) float64 {
	m := &dto.Metric{}
	counter := cv.WithLabelValues(lvs...)
	if err := counter.(interface{ Write(*dto.Metric) error }).Write(m); err != nil {
		return 0.0
	}
	return m.GetCounter().GetValue()
}

// tokensMissingAllReasons sums loxilb_ai_tokens_missing_total across every
// accepted reason for one model/tenant. Assertions that care "did anything
// land in this family at all" use this rather than one reason, so a recorder
// that starts writing a DIFFERENT reason than the test expects still fails
// the zero checks instead of sliding past them into an unread series.
func tokensMissingAllReasons(model, tenant string) float64 {
	var sum float64
	for _, r := range []string{
		TokenMissingReasonResponseComplete,
		TokenMissingReasonH2StreamClose,
		TokenMissingReasonConnectionClose,
		TokenMissingReasonStreamEstimated,
		TokenMissingReasonUnknown,
	} {
		sum += getCounterValue(aiTokensMissingTotal, model, tenant, r)
	}
	return sum
}

// TestRecordAIRequest verifies that RecordAIRequest increments the request
// counter with the status label and does not touch the rate-limit counter
// (429 accounting is owned by RecordRateLimitHit at the point of denial).
func TestRecordAIRequest(t *testing.T) {
	tenant := "test-tenant-record"

	beforeOK := getCounterValue(aiRequestsTotal, "m1", tenant, "200", AIOutcomeCompleted)
	before429 := getCounterValue(aiRequestsTotal, "m1", tenant, "429", AIOutcomeCompleted)
	beforeRL := getCounterValue(aiRateLimitHitsTotal, tenant, "rate_limit_exceeded")

	RecordAIRequest(tenant, "m1", 200, 42)
	RecordAIRequest(tenant, "m1", 429, 0)

	if d := getCounterValue(aiRequestsTotal, "m1", tenant, "200", AIOutcomeCompleted) - beforeOK; d != 1.0 {
		t.Fatalf("expected requests_total{status=200} +1, got delta %f", d)
	}
	// A backend can answer 429 itself. This one is completed, not denied --
	// which is precisely why status alone cannot carry the distinction.
	if d := getCounterValue(aiRequestsTotal, "m1", tenant, "429", AIOutcomeCompleted) - before429; d != 1.0 {
		t.Fatalf("expected requests_total{status=429} +1, got delta %f", d)
	}
	if d := getCounterValue(aiRequestsTotal, "m1", tenant, "429", AIOutcomeDenied); d != 0.0 {
		t.Fatalf("RecordAIRequest must never write outcome=denied, got %f", d)
	}
	if d := getCounterValue(aiRateLimitHitsTotal, tenant, "rate_limit_exceeded") - beforeRL; d != 0.0 {
		t.Fatalf("RecordAIRequest must not touch rate_limit_hits_total, got delta %f", d)
	}
}

// TestRecordRateLimitHit verifies that the dedicated RecordRateLimitHit helper
// increments aiRateLimitHitsTotal with the supplied reason label.
func TestRecordRateLimitHit(t *testing.T) {
	tenant := "acme"
	reason := "tenant_quota_exceeded"

	before := getCounterValue(aiRateLimitHitsTotal, tenant, reason)
	RecordRateLimitHit(tenant, reason)
	after := getCounterValue(aiRateLimitHitsTotal, tenant, reason)

	if after-before != 1.0 {
		t.Fatalf("expected %s to increment by 1, got delta %f", reason, after-before)
	}
}

// TestRecordRateLimitHit_EmptyReasonFallback verifies that RecordRateLimitHit
// falls back to "rate_limit_exceeded" when the reason parameter is empty.
func TestRecordRateLimitHit_EmptyReasonFallback(t *testing.T) {
	tenant := "acme-fallback"

	before := getCounterValue(aiRateLimitHitsTotal, tenant, "rate_limit_exceeded")
	RecordRateLimitHit(tenant, "")
	after := getCounterValue(aiRateLimitHitsTotal, tenant, "rate_limit_exceeded")

	if after-before != 1.0 {
		t.Fatalf("expected rate_limit_exceeded to increment by 1 on empty reason, got delta %f", after-before)
	}
}

// TestRecordModelNotAllowed verifies that RecordModelNotAllowed increments
// aiModelNotAllowedTotal with the correct model and tenant labels.
func TestRecordModelNotAllowed(t *testing.T) {
	tenant := "acme-model"
	model := "gpt-4"

	before := getCounterValue(aiModelNotAllowedTotal, model, tenant)
	RecordModelNotAllowed(tenant, model)
	after := getCounterValue(aiModelNotAllowedTotal, model, tenant)

	if after-before != 1.0 {
		t.Fatalf("expected model_not_allowed to increment by 1, got delta %f", after-before)
	}
}

// ============================================================================
// P/D DISAGGREGATION METRICS TESTS (/)
// ============================================================================

// getHistogramSampleCount reads the sample count from a HistogramVec for the
// given label values.
func getHistogramSampleCount(hv *prometheus.HistogramVec, lvs ...string) uint64 {
	m := &dto.Metric{}
	obs := hv.WithLabelValues(lvs...)
	if err := obs.(interface{ Write(*dto.Metric) error }).Write(m); err != nil {
		return 0
	}
	return m.GetHistogram().GetSampleCount()
}

// TestRecordPDRequest_Success verifies that RecordPDRequest with errorPhase=0
// increments the success counter and records both histograms.
func TestRecordPDRequest_Success(t *testing.T) {
	model := "pd-test-success"

	beforeReqs := getCounterValue(aiPDRequestsTotal, model, "complete", "success")
	beforePrefill := getHistogramSampleCount(aiPDPrefillDuration, model)
	beforeDecode := getHistogramSampleCount(aiPDDecodeTTFT, model)
	beforeKvFound := getCounterValue(aiPDKvParamsFound, model)

	RecordPDRequest(model, 150, 50, 1, 0) // 150ms prefill, 50ms decode, kv found, success

	afterReqs := getCounterValue(aiPDRequestsTotal, model, "complete", "success")
	afterPrefill := getHistogramSampleCount(aiPDPrefillDuration, model)
	afterDecode := getHistogramSampleCount(aiPDDecodeTTFT, model)
	afterKvFound := getCounterValue(aiPDKvParamsFound, model)

	if afterReqs-beforeReqs != 1.0 {
		t.Errorf("expected pd_requests_total{complete,success} +1, got delta %f", afterReqs-beforeReqs)
	}
	if afterPrefill-beforePrefill != 1 {
		t.Errorf("expected prefill histogram +1 sample, got delta %d", afterPrefill-beforePrefill)
	}
	if afterDecode-beforeDecode != 1 {
		t.Errorf("expected decode histogram +1 sample, got delta %d", afterDecode-beforeDecode)
	}
	if afterKvFound-beforeKvFound != 1.0 {
		t.Errorf("expected kv_params_found +1, got delta %f", afterKvFound-beforeKvFound)
	}
}

// TestRecordPDRequest_PrefillTimeout verifies that errorPhase=1 records a
// prefill timeout with only prefill latency — and does NOT count toward
// kv_params_missing (a timed-out prefill never produced a response to
// inspect; conflating the two was a metrics-audit finding).
func TestRecordPDRequest_PrefillTimeout(t *testing.T) {
	model := "pd-test-timeout"

	beforeReqs := getCounterValue(aiPDRequestsTotal, model, "prefill", "timeout")
	beforeKvMissing := getCounterValue(aiPDKvParamsMissing, model)

	RecordPDRequest(model, 5000, 0, 0, 1) // 5s prefill timeout, no decode, no kv

	afterReqs := getCounterValue(aiPDRequestsTotal, model, "prefill", "timeout")
	afterKvMissing := getCounterValue(aiPDKvParamsMissing, model)

	if afterReqs-beforeReqs != 1.0 {
		t.Errorf("expected pd_requests_total{prefill,timeout} +1, got delta %f", afterReqs-beforeReqs)
	}
	if afterKvMissing != beforeKvMissing {
		t.Errorf("prefill timeout must NOT count as kv_params_missing, got delta %f", afterKvMissing-beforeKvMissing)
	}
}

// TestRecordPDRequest_KvMissingOnCompletedRequest verifies kv_params_missing
// still fires when a COMPLETED request genuinely lacked kv_transfer_params.
func TestRecordPDRequest_KvMissingOnCompletedRequest(t *testing.T) {
	model := "pd-test-kv-missing"

	before := getCounterValue(aiPDKvParamsMissing, model)
	RecordPDRequest(model, 150, 50, 0, 0) // success, kv absent
	after := getCounterValue(aiPDKvParamsMissing, model)

	if after-before != 1.0 {
		t.Errorf("expected kv_params_missing +1 on completed kv-less request, got delta %f", after-before)
	}
}

// TestBoundModelLabel (H-11): the client-controlled model label collapses to
// "other" once the distinct-model registry is full, and an admitted name
// keeps its label (paired open/close events must agree).
func TestBoundModelLabel(t *testing.T) {
	// The registry is process-global; reset it afterwards so later tests'
	// fresh model names are not collapsed by this test's deliberate fill.
	t.Cleanup(func() {
		modelLabelMu.Lock()
		modelLabels = make(map[string]struct{}, maxModelLabels)
		modelLabelMu.Unlock()
	})
	early := boundModelLabel("bound-test-early")
	if early != "bound-test-early" {
		t.Fatalf("boundModelLabel(early) = %q, want identity", early)
	}
	// Fill the registry past the cap.
	for i := 0; i < maxModelLabels+8; i++ {
		boundModelLabel("bound-test-fill-" + strconv.Itoa(i))
	}
	if got := boundModelLabel("bound-test-unseen"); got != modelLabelOther {
		t.Errorf("boundModelLabel(unseen, full registry) = %q, want %q", got, modelLabelOther)
	}
	// A name admitted before the registry filled keeps its identity label.
	if got := boundModelLabel("bound-test-early"); got != "bound-test-early" {
		t.Errorf("boundModelLabel(admitted) = %q, want identity after fill", got)
	}
	if got := boundModelLabel(""); got != "" {
		t.Errorf("boundModelLabel(empty) = %q, want empty passthrough", got)
	}
}

// TestRecordPDRequest_DecodeError verifies that errorPhase=2 records a decode
// error.
func TestRecordPDRequest_DecodeError(t *testing.T) {
	model := "pd-test-decode-err"

	beforeReqs := getCounterValue(aiPDRequestsTotal, model, "decode", "error")

	RecordPDRequest(model, 200, 0, 1, 2) // 200ms prefill, decode failed, kv was found

	afterReqs := getCounterValue(aiPDRequestsTotal, model, "decode", "error")

	if afterReqs-beforeReqs != 1.0 {
		t.Errorf("expected pd_requests_total{decode,error} +1, got delta %f", afterReqs-beforeReqs)
	}
}

// TestRecordPDRequest_ZeroLatencySkipsHistograms verifies that latency=0 does
// not record histogram samples (only the counter is incremented).
func TestRecordPDRequest_ZeroLatencySkipsHistograms(t *testing.T) {
	model := "pd-test-zero-latency"

	beforePrefill := getHistogramSampleCount(aiPDPrefillDuration, model)
	beforeDecode := getHistogramSampleCount(aiPDDecodeTTFT, model)

	RecordPDRequest(model, 0, 0, 0, 0) // all zeros

	afterPrefill := getHistogramSampleCount(aiPDPrefillDuration, model)
	afterDecode := getHistogramSampleCount(aiPDDecodeTTFT, model)

	if afterPrefill != beforePrefill {
		t.Errorf("expected no prefill histogram sample when latency=0, got +%d", afterPrefill-beforePrefill)
	}
	if afterDecode != beforeDecode {
		t.Errorf("expected no decode histogram sample when latency=0, got +%d", afterDecode-beforeDecode)
	}
}

// TestRecordTokenUsage_KindSplit verifies the prompt/completion kind split on
// the consumed counter and that an exact (non-estimated) charge leaves the
// estimated/missing counters untouched.
func TestRecordTokenUsage_KindSplit(t *testing.T) {
	model, tenant := "tok-model-a", "tok-tenant-a"

	RecordTokenUsage(model, tenant, 100, 40, false)

	if v := getCounterValue(aiTokensConsumedTotal, model, tenant, "prompt"); v != 100 {
		t.Fatalf("expected prompt consumed=100, got %f", v)
	}
	if v := getCounterValue(aiTokensConsumedTotal, model, tenant, "completion"); v != 40 {
		t.Fatalf("expected completion consumed=40, got %f", v)
	}
	if v := getCounterValue(aiTokensEstimatedTotal, model, tenant); v != 0 {
		t.Fatalf("exact charge must not feed estimated counter, got %f", v)
	}
	if v := tokensMissingAllReasons(model, tenant); v != 0 {
		t.Fatalf("exact charge must not feed missing counter, got %f", v)
	}
}

// TestRecordTokenUsage_EstimatedFeedsSplitCounters verifies an estimate-net
// charge lands in consumed (kind-split), estimated (token-weighted), and
// missing (response-weighted) simultaneously.
func TestRecordTokenUsage_EstimatedFeedsSplitCounters(t *testing.T) {
	model, tenant := "tok-model-b", "tok-tenant-b"

	RecordTokenUsage(model, tenant, 10, 5, true)

	if v := getCounterValue(aiTokensConsumedTotal, model, tenant, "prompt"); v != 10 {
		t.Fatalf("expected prompt consumed=10, got %f", v)
	}
	if v := getCounterValue(aiTokensConsumedTotal, model, tenant, "completion"); v != 5 {
		t.Fatalf("expected completion consumed=5, got %f", v)
	}
	if v := getCounterValue(aiTokensEstimatedTotal, model, tenant); v != 15 {
		t.Fatalf("expected estimated=15, got %f", v)
	}
	if v := getCounterValue(aiTokensMissingTotal, model, tenant,
		TokenMissingReasonStreamEstimated); v != 1 {
		t.Fatalf("expected missing{reason=stream_estimated}=1, got %f", v)
	}
	// The estimate net is the one arm of this family that WAS charged, so it
	// must never land in a free bucket: an operator comparing tenants on
	// connection_close is looking for uncharged work, and a charged response
	// leaking into that series would answer the wrong question.
	if v := tokensMissingAllReasons(model, tenant); v != 1 {
		t.Fatalf("a charged estimate must occupy exactly the stream_estimated "+
			"series, total across reasons=%f", v)
	}
}

// TestRecordTokenUsageMissing_ReportsWithoutCharging verifies the
// accounting-only path: a completed response with no readable usage object
// moves the missing counter and NOTHING else.
//
// The two halves are separable on purpose. Reporting the condition is an
// observability fix; charging an estimate for it would debit tenants for
// responses that are free today, which is a quota-policy decision nobody has
// taken. If this recorder is ever folded back into RecordTokenUsage, or grows
// a charge of its own, the consumed/estimated assertions below turn red.
func TestRecordTokenUsageMissing_ReportsWithoutCharging(t *testing.T) {
	model, tenant := "tok-model-missing", "tok-tenant-missing"

	RecordTokenUsageMissing(model, tenant, TokenMissingReasonResponseComplete)

	if v := getCounterValue(aiTokensMissingTotal, model, tenant,
		TokenMissingReasonResponseComplete); v != 1 {
		t.Fatalf("expected missing{reason=response_complete}=1, got %f", v)
	}
	if v := getCounterValue(aiTokensConsumedTotal, model, tenant, "prompt"); v != 0 {
		t.Fatalf("reporting a missing usage object must charge nothing, prompt consumed=%f", v)
	}
	if v := getCounterValue(aiTokensConsumedTotal, model, tenant, "completion"); v != 0 {
		t.Fatalf("reporting a missing usage object must charge nothing, completion consumed=%f", v)
	}
	if v := getCounterValue(aiTokensEstimatedTotal, model, tenant); v != 0 {
		t.Fatalf("reporting a missing usage object must not price an estimate, estimated=%f", v)
	}

	// Response-weighted: a second completed response is a second tick, not a
	// token sum.
	RecordTokenUsageMissing(model, tenant, TokenMissingReasonResponseComplete)
	if v := getCounterValue(aiTokensMissingTotal, model, tenant,
		TokenMissingReasonResponseComplete); v != 2 {
		t.Fatalf("expected missing=2 after a second response, got %f", v)
	}
}

// TestRecordTokenUsageMissing_KeylessIsNotLabelled pins the attributed-only
// invariant this family shares with the rest of the per-tenant usage series.
//
// The reporting call sites are response boundaries, not the gate: an
// api_key_auth=disabled service reaches them with a completed AI response and
// no tenant, so without a guard here a keyless deployment mints
// loxilb_ai_tokens_missing_total{tenant=""} — the empty label value that
// llb_ai_token_quota_consume refuses to emit for RecordTokenUsage on the very
// same grounds ("an empty label value reads as a scrape bug"). Keyless volume
// is attributable per VIP in loxilb_ai_unmetered_requests_total instead.
//
// Scoped to the unset tenant, which is the condition the data plane actually
// presents (tenant_id[0] == '\0' on a keyless connection). A whitespace-only
// tenant sanitises to "_" and is labelled, exactly as RecordTokenUsage labels
// it — same family, same rule, and not this recorder's to change.
func TestRecordTokenUsageMissing_KeylessIsNotLabelled(t *testing.T) {
	model := "tok-model-keyless"

	before := tokensMissingAllReasons(model, "")
	RecordTokenUsageMissing(model, "", TokenMissingReasonConnectionClose)
	if d := tokensMissingAllReasons(model, "") - before; d != 0 {
		t.Fatalf("a keyless response must not be labelled into a per-tenant "+
			"usage family, got delta %f", d)
	}

	// The guard must not swallow attributed reports: the same model with a
	// real tenant still counts, so a green result above cannot come from the
	// recorder having stopped working altogether.
	beforeCtl := tokensMissingAllReasons(model, "tok-tenant-keyless-control")
	RecordTokenUsageMissing(model, "tok-tenant-keyless-control",
		TokenMissingReasonConnectionClose)
	if d := tokensMissingAllReasons(model, "tok-tenant-keyless-control") - beforeCtl; d != 1 {
		t.Fatalf("control: an attributed response must still count, got delta %f", d)
	}
}

// TestRecordTokenUsageMissing_ReasonIsAllowListed pins the reason label's
// closed vocabulary and the separation the label exists to provide.
//
// The reason arrives from the data plane over cgo as a C string, from a repo
// that versions independently of this one, so "whatever the caller sent" is
// not a safe label value: a pin skew, or a future call site spelling its own
// reason, would mint unbounded series on a per-tenant family. The recorder
// therefore maps onto a fixed set and collapses everything else.
//
// Collapsing rather than dropping is deliberate. A report on an unrecognised
// reason still happened — the accounting hole is real — and dropping it would
// under-report the very condition the family exists to expose, silently. It
// lands on "unknown", which is a series nobody expects and so reads as the
// drift signal it is.
func TestRecordTokenUsageMissing_ReasonIsAllowListed(t *testing.T) {
	model := "tok-model-reason"

	// Every accepted reason keeps its own identity, and lands ONLY there.
	for _, reason := range []string{
		TokenMissingReasonResponseComplete,
		TokenMissingReasonH2StreamClose,
		TokenMissingReasonConnectionClose,
		TokenMissingReasonStreamEstimated,
	} {
		tenant := "tok-tenant-reason-" + reason
		RecordTokenUsageMissing(model, tenant, reason)
		if v := getCounterValue(aiTokensMissingTotal, model, tenant, reason); v != 1 {
			t.Fatalf("reason %q must keep its own series, got %f", reason, v)
		}
		if v := tokensMissingAllReasons(model, tenant); v != 1 {
			t.Fatalf("reason %q must not also increment another series, "+
				"total across reasons=%f", reason, v)
		}
	}

	// Anything else — a reason this build does not know, or none at all —
	// collapses onto "unknown" rather than opening a new series.
	for _, bogus := range []string{"", "client_cut", "RESPONSE_COMPLETE", "response complete"} {
		tenant := "tok-tenant-reason-bogus"
		before := getCounterValue(aiTokensMissingTotal, model, tenant,
			TokenMissingReasonUnknown)
		RecordTokenUsageMissing(model, tenant, bogus)
		if d := getCounterValue(aiTokensMissingTotal, model, tenant,
			TokenMissingReasonUnknown) - before; d != 1 {
			t.Fatalf("unrecognised reason %q must land on %q, got delta %f",
				bogus, TokenMissingReasonUnknown, d)
		}
		// ... and the report is not lost on the way: the total moved too.
		if v := tokensMissingAllReasons(model, tenant); v != before+1 {
			t.Fatalf("unrecognised reason %q must still be counted once, "+
				"total across reasons=%f want %f", bogus, v, before+1)
		}
	}
}

// TestRecordTokenUsage_ClampsNegativeAndSkipsZero verifies negative counts
// clamp to zero and an all-zero charge records nothing at all.
func TestRecordTokenUsage_ClampsNegativeAndSkipsZero(t *testing.T) {
	model, tenant := "tok-model-c", "tok-tenant-c"

	RecordTokenUsage(model, tenant, -5, 0, true)
	if v := tokensMissingAllReasons(model, tenant); v != 0 {
		t.Fatalf("all-zero charge must record nothing, missing=%f", v)
	}

	RecordTokenUsage(model, tenant, 7, -3, false)
	if v := getCounterValue(aiTokensConsumedTotal, model, tenant, "prompt"); v != 7 {
		t.Fatalf("expected prompt consumed=7, got %f", v)
	}
	if v := getCounterValue(aiTokensConsumedTotal, model, tenant, "completion"); v != 0 {
		t.Fatalf("negative completion must clamp to 0, got %f", v)
	}
}

// TestRecordTokenQuotaDenied verifies the dedicated gate-denial counter.
func TestRecordTokenQuotaDenied(t *testing.T) {
	tenant := "tok-tenant-d"
	RecordTokenQuotaDenied(tenant)
	RecordTokenQuotaDenied(tenant)
	if v := getCounterValue(aiTokenQuotaDeniedTotal, tenant); v != 2 {
		t.Fatalf("expected denied=2, got %f", v)
	}
}

// TestTokenQuotaCollector gathers the scrape-time collector against a fake
// snapshot source and checks utilization math (including >1.0 overshoot),
// zero-limit skipping, and duplicate-sanitized-label suppression.
func TestTokenQuotaCollector(t *testing.T) {
	c := &tokenQuotaCollector{snapshot: func() []TokenQuotaState {
		return []TokenQuotaState{
			{Tenant: "t-one", Consumed: 50, Limit: 200},
			{Tenant: "t-two", Consumed: 300, Limit: 200}, // overshoot: 1.5
			{Tenant: "t-nolimit", Consumed: 5, Limit: 0}, // must be skipped
			{Tenant: "dup a", Consumed: 1, Limit: 10},    // sanitizes to dup_a
			{Tenant: "dup_a", Consumed: 9, Limit: 10},    // duplicate label, dropped
		}
	}}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}

	util := map[string]float64{}
	limit := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			var tenant string
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "tenant" {
					tenant = lp.GetValue()
				}
			}
			switch mf.GetName() {
			case "loxilb_ai_token_quota_utilization":
				util[tenant] = m.GetGauge().GetValue()
			case "loxilb_ai_token_quota_limit_tokens":
				limit[tenant] = m.GetGauge().GetValue()
			}
		}
	}

	if v := util["t-one"]; v != 0.25 {
		t.Fatalf("expected utilization 0.25 for t-one, got %f", v)
	}
	if v := util["t-two"]; v != 1.5 {
		t.Fatalf("expected overshoot utilization 1.5 for t-two, got %f", v)
	}
	if _, ok := util["t-nolimit"]; ok {
		t.Fatal("zero-limit tenant must not be exported")
	}
	if v := util["dup_a"]; v != 0.1 {
		t.Fatalf("expected first-wins utilization 0.1 for dup_a, got %f", v)
	}
	if v := limit["t-one"]; v != 200 {
		t.Fatalf("expected limit 200 for t-one, got %f", v)
	}
}

// TestTokenQuotaCollectorScopedSeries — each identity scope lands on its own
// family with its own labels, and the tenant families stay EMPTY.
//
// The flat assertion is the load-bearing half. The defect these series
// replace was a per-key bucket published as a tenant, and a per-family
// oracle cannot see a wrong label: a mislabelled row moves the tenant family
// by exactly as much as a real tenant would. So this snapshot contains no
// tenant rows at all, and any sample on a tenant family is a routing bug
// naming itself.
func TestTokenQuotaCollectorScopedSeries(t *testing.T) {
	c := &tokenQuotaCollector{snapshot: func() []TokenQuotaState {
		return []TokenQuotaState{
			{Scope: "user", Tenant: "acme", User: "bob", Consumed: 30, Limit: 300},
			{Scope: "user_model", Tenant: "acme", User: "bob", Model: "gpt-4", Consumed: 100, Limit: 400},
			{Scope: "key", KeyID: "ak-123", Consumed: 250, Limit: 500},
			{Scope: "vip", Service: "10.0.0.1:8080", Consumed: 900, Limit: 600}, // overshoot: 1.5
			{Scope: "key", KeyID: "ak-nolimit", Consumed: 5, Limit: 0},          // skipped
			{Scope: "key", KeyID: "dup a", Consumed: 1, Limit: 10},              // sanitizes to dup_a
			{Scope: "key", KeyID: "dup_a", Consumed: 9, Limit: 10},              // duplicate, dropped
			{Scope: "nonsense", Tenant: "acme", Consumed: 1, Limit: 10},         // unknown scope, dropped
		}
	}}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather failed: %v", err)
	}

	// family -> joined label values -> value.
	got := map[string]map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			var parts []string
			for _, lp := range m.GetLabel() {
				parts = append(parts, lp.GetName()+"="+lp.GetValue())
			}
			if got[mf.GetName()] == nil {
				got[mf.GetName()] = map[string]float64{}
			}
			got[mf.GetName()][strings.Join(parts, ",")] = m.GetGauge().GetValue()
		}
	}

	for _, want := range []struct {
		family string
		labels string
		value  float64
	}{
		{"loxilb_ai_user_token_quota_utilization", "tenant=acme,user=bob", 0.1},
		{"loxilb_ai_user_token_quota_limit_tokens", "tenant=acme,user=bob", 300},
		{"loxilb_ai_user_model_token_quota_utilization", "model=gpt-4,tenant=acme,user=bob", 0.25},
		{"loxilb_ai_user_model_token_quota_limit_tokens", "model=gpt-4,tenant=acme,user=bob", 400},
		{"loxilb_ai_key_token_quota_utilization", "key_id=ak-123", 0.5},
		{"loxilb_ai_key_token_quota_limit_tokens", "key_id=ak-123", 500},
		// The colon is sanitized to an underscore on the way to the label;
		// the expectation carries the sanitized form deliberately.
		{"loxilb_ai_vip_token_quota_utilization", "service=10.0.0.1_8080", 1.5},
		{"loxilb_ai_vip_token_quota_limit_tokens", "service=10.0.0.1_8080", 600},
		{"loxilb_ai_key_token_quota_utilization", "key_id=dup_a", 0.1}, // first wins
	} {
		if v, ok := got[want.family][want.labels]; !ok {
			t.Errorf("%s{%s} missing; family has %v", want.family, want.labels, got[want.family])
		} else if v != want.value {
			t.Errorf("%s{%s} = %f, want %f", want.family, want.labels, v, want.value)
		}
	}

	if _, ok := got["loxilb_ai_key_token_quota_utilization"]["key_id=ak-nolimit"]; ok {
		t.Error("a zero-limit bucket must not be exported: there is no denominator")
	}

	// The flats. Not "the tenant family has no acme" — the family must have
	// no samples at all, because nothing in the snapshot is a tenant.
	for _, flat := range []string{
		"loxilb_ai_token_quota_utilization",
		"loxilb_ai_token_quota_limit_tokens",
		"loxilb_ai_token_quota_model_utilization",
		"loxilb_ai_token_quota_model_limit_tokens",
	} {
		if n := len(got[flat]); n != 0 {
			t.Errorf("%s emitted %d samples (%v) from a snapshot with no tenant rows; an identity scope is being published as a tenant", flat, n, got[flat])
		}
	}
}

// TestRecordPDRequest_PhaseTaxonomy pins the whole errorPhase -> {phase,status}
// contract in one place, because the defect this table exists to prevent is not
// a wrong line of code but a wrong MAPPING: the C datapath distinguishes a
// prefill timeout, a decode wedge, a prefill-side death and an origin reject in
// its logs and its response bodies, and for a long time reported all four on
// loxilb_ai_pd_requests_total{phase="prefill",status="timeout"}. An operator
// following that series was sent to the wrong tier.
//
// Each row also pins whether the lifecycle may contribute to kv_params_missing.
// Only a lifecycle that actually parsed a prefill response can report that
// kv_transfer_params was absent from it.
func TestRecordPDRequest_PhaseTaxonomy(t *testing.T) {
	cases := []struct {
		name          string
		errorPhase    int
		wantPhase     string
		wantStatus    string
		wantKvMissing bool
	}{
		{"success", 0, "complete", "success", true},
		{"prefill timeout", 1, "prefill", "timeout", false},
		{"decode error", 2, "decode", "error", true},
		{"decode timeout", 3, "decode", "timeout", true},
		{"prefill error", 4, "prefill", "error", false},
		{"prefill rejected", 5, "prefill", "rejected", false},
		{"unknown phase", 99, "unknown", "error", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// No spaces: sanitizeLabel rewrites them, so a model name built
			// from tc.name would be REGISTERED under one string and looked up
			// under another, and every delta would read zero.
			model := "pd-tax-" + strconv.Itoa(tc.errorPhase)

			beforeReqs := getCounterValue(aiPDRequestsTotal, model, tc.wantPhase, tc.wantStatus)
			beforeKvMissing := getCounterValue(aiPDKvParamsMissing, model)

			// kvParamsFound=0 throughout so the guard, not the found-path, decides.
			RecordPDRequest(model, 0, 0, 0, tc.errorPhase)

			afterReqs := getCounterValue(aiPDRequestsTotal, model, tc.wantPhase, tc.wantStatus)
			afterKvMissing := getCounterValue(aiPDKvParamsMissing, model)

			if afterReqs-beforeReqs != 1.0 {
				t.Errorf("errorPhase=%d: expected pd_requests_total{phase=%q,status=%q} +1, got delta %f",
					tc.errorPhase, tc.wantPhase, tc.wantStatus, afterReqs-beforeReqs)
			}

			gotKvMissing := afterKvMissing-beforeKvMissing == 1.0
			if gotKvMissing != tc.wantKvMissing {
				t.Errorf("errorPhase=%d: kv_params_missing fired=%v, want %v (delta %f)",
					tc.errorPhase, gotKvMissing, tc.wantKvMissing, afterKvMissing-beforeKvMissing)
			}
		})
	}
}

// TestRecordPDRequest_TimeoutLegsAreSeparable is the direct regression guard for
// the conflation: a prefill timeout and a decode first-byte wedge are distinct
// failures of distinct tiers, so they must not share a series. Before the fix
// both recorded errorPhase=1 and {phase="decode"} stayed flat forever, so a
// wedged decode fleet was indistinguishable from a slow prefill fleet.
func TestRecordPDRequest_TimeoutLegsAreSeparable(t *testing.T) {
	model := "pd-timeout-legs"

	beforePrefill := getCounterValue(aiPDRequestsTotal, model, "prefill", "timeout")
	beforeDecode := getCounterValue(aiPDRequestsTotal, model, "decode", "timeout")

	RecordPDRequest(model, 5000, 0, 0, 1) // prefill leg ran out of time
	RecordPDRequest(model, 0, 0, 0, 3)    // decode leg never produced a byte

	afterPrefill := getCounterValue(aiPDRequestsTotal, model, "prefill", "timeout")
	afterDecode := getCounterValue(aiPDRequestsTotal, model, "decode", "timeout")

	if afterPrefill-beforePrefill != 1.0 {
		t.Errorf("prefill timeout must land on {prefill,timeout} exactly once, got delta %f",
			afterPrefill-beforePrefill)
	}
	if afterDecode-beforeDecode != 1.0 {
		t.Errorf("decode wedge must land on {decode,timeout} exactly once, got delta %f",
			afterDecode-beforeDecode)
	}
}

// TestRecordPDRequest_DecodeWedgeReportsKnownKv covers the sub-defect the phase
// change exposed. The decode first-byte wedge happens AFTER prefill completed,
// so the proxy already holds the kv_transfer_params answer. The C site used to
// hardcode kvParamsFound=0, which was invisible only because errorPhase=1
// suppressed both kv counters; once the wedge became phase 3 that hardcoded 0
// would have reported a false "missing" for every wedge whose prefill DID carry
// kv params.
func TestRecordPDRequest_DecodeWedgeReportsKnownKv(t *testing.T) {
	model := "pd-wedge-kv"

	beforeFound := getCounterValue(aiPDKvParamsFound, model)
	beforeMissing := getCounterValue(aiPDKvParamsMissing, model)

	RecordPDRequest(model, 0, 0, 1, 3) // decode wedge, prefill HAD kv params

	afterFound := getCounterValue(aiPDKvParamsFound, model)
	afterMissing := getCounterValue(aiPDKvParamsMissing, model)

	if afterFound-beforeFound != 1.0 {
		t.Errorf("a decode wedge whose prefill carried kv params must count as found, got delta %f",
			afterFound-beforeFound)
	}
	if afterMissing != beforeMissing {
		t.Errorf("it must NOT also count as missing, got delta %f", afterMissing-beforeMissing)
	}
}
