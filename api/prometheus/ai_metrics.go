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
	"regexp"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ============================================================================
// AI GATEWAY METRICS - Per-model and per-tenant Prometheus metrics
// ============================================================================
// These metrics are populated by the CGO export llb_ai_record_request defined
// in pkg/loxinet/ai_gateway_dp.go. C sockproxy calls that export once per
// completed request (or on SSE stream open/close events).
//
// Label sanitisation prevents cardinality explosion: characters outside
// [a-zA-Z0-9._-] are replaced with '_' and values are truncated to 64 chars.
// ============================================================================

// labelSanitizeRe matches characters that are not safe Prometheus label values.
var labelSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._\-]`)

const labelMaxLen = 64

// sanitizeLabel replaces invalid chars with '_' and truncates to labelMaxLen.
func sanitizeLabel(s string) string {
	s = labelSanitizeRe.ReplaceAllString(s, "_")
	if len(s) > labelMaxLen {
		s = s[:labelMaxLen]
	}
	return s
}

// Model-label cardinality bound (metrics audit H-11). The model name is
// client-controlled (X-Model header / JSON body field): sanitisation bounds
// the alphabet and length but NOT the number of distinct values, so a hostile
// client could mint unbounded series against Prometheus. The registry caps
// distinct model label values; once full, unseen names collapse to "other".
// No eviction — a name once admitted keeps its label for process lifetime, so
// paired events (stream open/close) always agree on the label.
const (
	maxModelLabels  = 64
	modelLabelOther = "other"
)

var (
	modelLabelMu sync.RWMutex
	modelLabels  = make(map[string]struct{}, maxModelLabels)
)

// boundModelLabel sanitises a model name and collapses it to "other" when the
// distinct-model registry is full (H-11 series-mint DoS guard).
func boundModelLabel(modelName string) string {
	model := sanitizeLabel(modelName)
	if model == "" {
		return model
	}
	modelLabelMu.RLock()
	_, known := modelLabels[model]
	full := len(modelLabels) >= maxModelLabels
	modelLabelMu.RUnlock()
	if known {
		return model
	}
	if full {
		return modelLabelOther
	}
	modelLabelMu.Lock()
	defer modelLabelMu.Unlock()
	if _, known := modelLabels[model]; known {
		return model
	}
	if len(modelLabels) >= maxModelLabels {
		return modelLabelOther
	}
	modelLabels[model] = struct{}{}
	return model
}

var (
	// aiRequestsTotal counts completed AI Gateway requests per model, tenant, and
	// HTTP status. The data plane records a request when its SSE stream completes
	// (data:[DONE]); non-streaming responses are not counted here — denials are
	// covered by the point-of-denial counters (rate limit hits, model-not-allowed).
	aiRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_requests_total",
			Help: "Total AI Gateway requests by model, tenant, and HTTP status code (recorded at SSE stream completion).",
		},
		[]string{"model", "tenant", "status"},
	)

	// aiRequestDurationSeconds tracks per-model, per-tenant request latency as
	// a histogram. Buckets extend to 300s: SSE/streaming completions routinely
	// run minutes — a 10s top bucket would blind-spot the entire tail.
	aiRequestDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "loxilb_ai_request_duration_seconds",
			Help:    "AI Gateway request duration in seconds, SSE activation to stream completion (monotonic clock at data plane).",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0},
		},
		[]string{"model", "tenant"},
	)

	// aiRateLimitHitsTotal counts rate-limit denials per tenant and reason.
	aiRateLimitHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_rate_limit_hits_total",
			Help: "Total AI Gateway requests denied by rate limiting, by tenant and reason.",
		},
		[]string{"tenant", "reason"},
	)

	// aiActiveStreams tracks currently open SSE/streaming sessions per model.
	aiActiveStreams = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "loxilb_ai_active_streams",
			Help: "Current number of active AI streaming (SSE) sessions per model.",
		},
		[]string{"model"},
	)

	// aiModelNotAllowedTotal counts model-access-denied events (HTTP 403) per model and tenant.
	aiModelNotAllowedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_model_not_allowed_total",
			Help: "Total AI Gateway requests denied because the model is not in the key's allowed list, by model and tenant.",
		},
		[]string{"model", "tenant"},
	)

	// ============================================================================
	// P/D DISAGGREGATION METRICS (US-509)
	// ============================================================================

	// aiPDPrefillDuration tracks prefill phase latency as a histogram.
	aiPDPrefillDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "loxilb_ai_pd_prefill_duration_seconds",
			Help:    "P/D prefill phase duration in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"model"},
	)

	// aiPDDecodeTTFT tracks decode time-to-first-token as a histogram.
	aiPDDecodeTTFT = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "loxilb_ai_pd_decode_ttft_seconds",
			Help:    "P/D decode time-to-first-token in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"model"},
	)

	// aiPDRequestsTotal counts P/D disaggregation requests by model, phase, and status.
	aiPDRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_pd_requests_total",
			Help: "Total P/D disaggregation requests by model, phase, and status.",
		},
		[]string{"model", "phase", "status"},
	)

	// aiPDKvParamsFound counts P/D requests where kv_transfer_params was found.
	aiPDKvParamsFound = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_pd_kv_params_found_total",
			Help: "Total P/D requests where kv_transfer_params was found in prefill response.",
		},
		[]string{"model"},
	)

	// aiPDKvParamsMissing counts P/D requests where kv_transfer_params was missing.
	aiPDKvParamsMissing = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_pd_kv_params_missing_total",
			Help: "Total P/D requests where kv_transfer_params was missing from prefill response.",
		},
		[]string{"model"},
	)

	// aiPDSessionHitsTotal counts P/D Tier-0 session-stickiness cache hits per model.
	aiPDSessionHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_pd_session_hits_total",
			Help: "Total P/D disaggregation requests where Tier-0 session stickiness directed the request to a pinned EP pair.",
		},
		[]string{"model"},
	)

	// aiNormalSessionHitsTotal counts normal-mode session-stickiness cache hits per model.
	aiNormalSessionHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_normal_session_hits_total",
			Help: "Total non-P/D AI gateway requests where session stickiness (X-Conversation-Id or user field) directed the request to a previously pinned backend EP.",
		},
		[]string{"model"},
	)
)

// AdjustActiveStreams adjusts the loxilb_ai_active_streams gauge by delta for
// the given model. Call with delta=+1.0 on stream open and delta=-1.0 on close.
// The caller is responsible for ensuring the gauge does not go below zero;
// see the atomic guard in pkg/loxinet/ai_gateway_dp.go::llb_ai_stream_end.
func AdjustActiveStreams(model string, delta float64) {
	aiActiveStreams.WithLabelValues(boundModelLabel(model)).Add(delta)
}

// RecordRateLimitHit increments the loxilb_ai_rate_limit_hits_total counter
// directly from the Go rate-limit decision path. Call this from
// llb_ai_ratelimit_check when a request is denied (decision != 0).
// If reason is empty it falls back to "rate_limit_exceeded".
func RecordRateLimitHit(tenantID, reason string) {
	if reason == "" {
		reason = "rate_limit_exceeded"
	}
	aiRateLimitHitsTotal.WithLabelValues(sanitizeLabel(tenantID), reason).Inc()
}

// RecordModelNotAllowed increments the loxilb_ai_model_not_allowed_total counter
// directly from the Go key-validation path. Call this from llb_ai_validate_key
// when decision == 2 (HTTP 403 / model not in key's allowed list).
func RecordModelNotAllowed(tenantID, model string) {
	aiModelNotAllowedTotal.WithLabelValues(boundModelLabel(model), sanitizeLabel(tenantID)).Inc()
}

// RecordPDRequest records a P/D disaggregation lifecycle event for Prometheus metrics.
//
// Parameters:
//
//	modelName:        the effective model name
//	prefillLatencyMs: prefill phase duration in milliseconds; 0 when unknown
//	decodeLatencyMs:  decode phase duration (TTFT) in milliseconds; 0 when unknown
//	kvParamsFound:    1 when kv_transfer_params was found in prefill response, 0 otherwise
//	errorPhase:       0=success, 1=prefill_timeout, 2=decode_error
func RecordPDRequest(modelName string, prefillLatencyMs, decodeLatencyMs int64, kvParamsFound, errorPhase int) {
	model := boundModelLabel(modelName)

	var phase, status string
	switch errorPhase {
	case 0:
		phase = "complete"
		status = "success"
	case 1:
		phase = "prefill"
		status = "timeout"
	case 2:
		phase = "decode"
		status = "error"
	default:
		phase = "unknown"
		status = "error"
	}

	aiPDRequestsTotal.WithLabelValues(model, phase, status).Inc()

	if prefillLatencyMs > 0 {
		aiPDPrefillDuration.WithLabelValues(model).Observe(float64(prefillLatencyMs) / 1000.0)
	}
	if decodeLatencyMs > 0 {
		aiPDDecodeTTFT.WithLabelValues(model).Observe(float64(decodeLatencyMs) / 1000.0)
	}

	if kvParamsFound == 1 {
		aiPDKvParamsFound.WithLabelValues(model).Inc()
	} else if errorPhase != 1 {
		// A prefill timeout never produced a response to inspect — counting it
		// as "kv_transfer_params missing" conflated transport failure with the
		// usage-absent signal this counter documents.
		aiPDKvParamsMissing.WithLabelValues(model).Inc()
	}
}

// RecordPDSessionHit increments the loxilb_ai_pd_session_hits_total counter for
// the given model. Called by llb_ai_pd_session_hit when Tier-0 session stickiness
// routes a P/D request to a previously pinned EP pair.
func RecordPDSessionHit(modelName string) {
	aiPDSessionHitsTotal.WithLabelValues(boundModelLabel(modelName)).Inc()
}

// RecordNormalSessionHit increments the loxilb_ai_normal_session_hits_total counter
// for the given model. Called by llb_ai_normal_session_hit when PRIORITY 0 (learned
// conv_map lookup) succeeds in PROXY_SEL_STICKY mode (non-P/D AI GW normal mode).
func RecordNormalSessionHit(modelName string) {
	aiNormalSessionHitsTotal.WithLabelValues(boundModelLabel(modelName)).Inc()
}

// RecordAIRequest is the Go entry point called by the CGO export llb_ai_record_request.
//
// C sockproxy calls this once on response completion. The function sanitises
// label values and updates the request counter and latency histogram.
//
// Rate-limit (429) and model-not-allowed (403) denials are NOT derived here:
// the point-of-denial helpers RecordRateLimitHit and RecordModelNotAllowed are
// authoritative. SSE stream lifecycle is tracked via AdjustActiveStreams from
// llb_ai_stream_start/llb_ai_stream_end.
//
// Parameters:
//
//	tenantID:  tenant identifier from the validated API key
//	modelName: effective model name (X-Model header > JSON body field > "")
//	statusCode: HTTP response status code (200, 401, 403, 429, 500, …)
//	latencyMs: request latency in milliseconds; 0 when unknown
func RecordAIRequest(tenantID, modelName string, statusCode int, latencyMs int64) {
	model := boundModelLabel(modelName)
	tenant := sanitizeLabel(tenantID)
	status := strconv.Itoa(statusCode)

	// Increment request counter for every completed request.
	aiRequestsTotal.WithLabelValues(model, tenant, status).Inc()

	// Record latency when available.
	if latencyMs > 0 {
		aiRequestDurationSeconds.WithLabelValues(model, tenant).Observe(float64(latencyMs) / 1000.0)
	}
}
