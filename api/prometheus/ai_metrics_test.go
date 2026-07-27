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

// TestRecordAIRequest verifies that RecordAIRequest increments the request
// counter with the status label and does not touch the rate-limit counter
// (429 accounting is owned by RecordRateLimitHit at the point of denial).
func TestRecordAIRequest(t *testing.T) {
	tenant := "test-tenant-record"

	beforeOK := getCounterValue(aiRequestsTotal, "m1", tenant, "200")
	before429 := getCounterValue(aiRequestsTotal, "m1", tenant, "429")
	beforeRL := getCounterValue(aiRateLimitHitsTotal, tenant, "rate_limit_exceeded")

	RecordAIRequest(tenant, "m1", 200, 42)
	RecordAIRequest(tenant, "m1", 429, 0)

	if d := getCounterValue(aiRequestsTotal, "m1", tenant, "200") - beforeOK; d != 1.0 {
		t.Fatalf("expected requests_total{status=200} +1, got delta %f", d)
	}
	if d := getCounterValue(aiRequestsTotal, "m1", tenant, "429") - before429; d != 1.0 {
		t.Fatalf("expected requests_total{status=429} +1, got delta %f", d)
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
