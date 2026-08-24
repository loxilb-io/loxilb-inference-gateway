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

	// aiTokensConsumedTotal counts tokens metered from completed AI
	// responses, split prompt/completion via the kind label. Fed from the
	// quota-charge path (llb_ai_token_quota_consume), so the counts are
	// byte-identical to what the tenant quota was charged — including
	// estimate-net charges, which the estimated/missing counters below keep
	// distinguishable. The response-complete recorder is NOT used here: its
	// non-streaming leg can observe zero counts when the usage object
	// arrives in a later TCP segment than the response headers.
	aiTokensConsumedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_tokens_consumed_total",
			Help: "Total tokens metered against completed AI Gateway responses, by model, tenant, and kind (prompt|completion).",
		},
		[]string{"model", "tenant", "kind"},
	)

	// aiTokensEstimatedTotal counts quota-charged tokens whose counts came
	// from the data plane's estimate net (request-size prompt estimate +
	// SSE chunk count) rather than an extracted usage object. A non-zero
	// rate means some responses complete without a readable usage chunk —
	// the split keeps estimated accounting distinguishable from exact.
	aiTokensEstimatedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_tokens_estimated_total",
			Help: "Total tokens charged against tenant quotas from the estimate net (no usage object in the response), by model and tenant.",
		},
		[]string{"model", "tenant"},
	)

	// aiTokensMissingTotal counts completed responses that produced no
	// readable usage object, so the estimate net had to price the charge.
	// Counts responses (not tokens); pair with aiTokensEstimatedTotal for
	// the token-weighted view.
	aiTokensMissingTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_tokens_missing_total",
			Help: "Total completed AI Gateway responses with no readable usage object (charge fell back to the estimate net), by model and tenant.",
		},
		[]string{"model", "tenant"},
	)

	// aiTokenQuotaDeniedTotal counts requests denied 429 at the rate-limit
	// gate because the tenant's token-quota latch was set. Numerically a
	// subset of loxilb_ai_rate_limit_hits_total{reason="token_quota_exceeded"},
	// kept as its own series so quota alerting does not depend on a reason
	// string, and as the anchor for per-model quota labels when quota keying
	// grows a model dimension.
	aiTokenQuotaDeniedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_token_quota_denied_total",
			Help: "Total AI Gateway requests denied at the gate because the tenant token quota was exhausted, by tenant.",
		},
		[]string{"tenant"},
	)

	// aiTokenQuotaColdOpenTotal marks cold fail-open windows: the node began
	// serving quota-limited traffic with empty in-memory quota state and no
	// peer re-taught it in time (or no peers exist). Without this series a
	// freshly restarted node that under-enforces for up to one window is
	// indistinguishable from a healthy one.
	aiTokenQuotaColdOpenTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_ai_token_quota_cold_open_total",
			Help: "Total times this node started serving token-quota traffic fail-open with cold (empty) quota state, without peer warm-up.",
		},
	)

	// ============================================================================
	// P/D DISAGGREGATION METRICS 
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

// RecordTokenUsage feeds the token-accounting series from the quota-charge
// path (llb_ai_token_quota_consume). promptTokens/completionTokens are the
// counts the tenant quota was charged for one completed response. estimated
// marks a charge priced by the data plane's estimate net — no usage object
// materialized in the response — which additionally feeds the estimated-token
// and missing-usage counters.
func RecordTokenUsage(modelName, tenantID string, promptTokens, completionTokens int, estimated bool) {
	promptTokens = max(promptTokens, 0)
	completionTokens = max(completionTokens, 0)
	if promptTokens+completionTokens == 0 {
		return
	}
	model := boundModelLabel(modelName)
	tenant := sanitizeLabel(tenantID)
	if promptTokens > 0 {
		aiTokensConsumedTotal.WithLabelValues(model, tenant, "prompt").Add(float64(promptTokens))
	}
	if completionTokens > 0 {
		aiTokensConsumedTotal.WithLabelValues(model, tenant, "completion").Add(float64(completionTokens))
	}
	if estimated {
		aiTokensEstimatedTotal.WithLabelValues(model, tenant).Add(float64(promptTokens + completionTokens))
		aiTokensMissingTotal.WithLabelValues(model, tenant).Inc()
	}
}

// RecordTokenQuotaColdOpen increments loxilb_ai_token_quota_cold_open_total.
// Call once per cold fail-open transition: quota enforcement is now running
// on empty state that no peer warmed up.
func RecordTokenQuotaColdOpen() {
	aiTokenQuotaColdOpenTotal.Inc()
}

// RecordTokenQuotaDenied increments the loxilb_ai_token_quota_denied_total
// counter. Call this from llb_ai_ratelimit_check when the denial reason is
// the tenant token-quota latch (error code "token_quota_exceeded").
func RecordTokenQuotaDenied(tenantID string) {
	aiTokenQuotaDeniedTotal.WithLabelValues(sanitizeLabel(tenantID)).Inc()
}

// TokenQuotaState is one tenant's live quota-window state as supplied by the
// snapshot source registered via RegisterTokenQuotaSource (the rate-limiter
// store, adapted in pkg/loxinet).
type TokenQuotaState struct {
	Tenant   string
	Consumed int64
	Limit    int64
}

var (
	tokenQuotaUtilizationDesc = prometheus.NewDesc(
		"loxilb_ai_token_quota_utilization",
		"Fraction of the per-tenant tokens-per-minute quota consumed in the current window, computed at scrape time. May exceed 1.0 when the tipping charge overshoots the limit; reads 0 after a window rollover.",
		[]string{"tenant"}, nil,
	)
	tokenQuotaLimitDesc = prometheus.NewDesc(
		"loxilb_ai_token_quota_limit_tokens",
		"Per-tenant tokens-per-minute quota as of the tenant's most recent charge. Headroom in tokens = limit * (1 - utilization).",
		[]string{"tenant"}, nil,
	)
)

// tokenQuotaCollector exports quota utilization at scrape time by reading the
// live rate-limiter state. A gauge SET on the charge path would freeze at its
// last written value: a tenant denied at the gate never completes a response,
// so no charge runs to move the gauge back down after the window refills —
// the tenant would read permanently over-quota while actually admitted again.
// Scrape-time computation keeps the series truthful for throttled and idle
// tenants alike.
type tokenQuotaCollector struct {
	snapshot func() []TokenQuotaState
}

func (c *tokenQuotaCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- tokenQuotaUtilizationDesc
	ch <- tokenQuotaLimitDesc
}

func (c *tokenQuotaCollector) Collect(ch chan<- prometheus.Metric) {
	// Distinct tenant IDs can sanitize to the same label value; emitting
	// both would fail the scrape with a duplicate-series error, so only the
	// first snapshot entry per sanitized label is exported.
	seen := make(map[string]struct{})
	for _, st := range c.snapshot() {
		if st.Limit <= 0 {
			continue
		}
		tenant := sanitizeLabel(st.Tenant)
		if _, dup := seen[tenant]; dup {
			continue
		}
		seen[tenant] = struct{}{}
		ch <- prometheus.MustNewConstMetric(tokenQuotaUtilizationDesc,
			prometheus.GaugeValue, float64(st.Consumed)/float64(st.Limit), tenant)
		ch <- prometheus.MustNewConstMetric(tokenQuotaLimitDesc,
			prometheus.GaugeValue, float64(st.Limit), tenant)
	}
}

var tokenQuotaSourceOnce sync.Once

// RegisterTokenQuotaSource registers the scrape-time token-quota collector
// backed by fn. Call it when the rate-limiter store is initialised; only the
// first registration takes effect.
func RegisterTokenQuotaSource(fn func() []TokenQuotaState) {
	tokenQuotaSourceOnce.Do(func() {
		prometheus.MustRegister(&tokenQuotaCollector{snapshot: fn})
	})
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
