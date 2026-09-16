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
	"strings"
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

// Values of the outcome label on loxilb_ai_requests_total. Exported because a
// consumer of this package should select on the same constant the recorder
// writes, not on a string literal that can drift from it.
const (
	// AIOutcomeCompleted marks a request a backend answered.
	AIOutcomeCompleted = "completed"
	// AIOutcomeDenied marks a request the gateway policy gate refused, so no
	// backend was ever asked.
	AIOutcomeDenied = "denied"
)

var (
	// aiRequestsTotal counts AI Gateway requests that reached a response, per
	// model, tenant and HTTP status.
	//
	// The data plane has TWO recording sites, not one, and the difference is
	// load-bearing for anyone computing a rate from this family:
	//
	//   - a streaming response is recorded when its SSE stream terminates
	//     (data:[DONE]);
	//   - a non-streaming response is recorded once its header block arrives
	//     with no stream active. That covers plain-JSON 200s AND the common
	//     error shape, since OpenAI-compatible backends answer errors as plain
	//     JSON even for streaming requests.
	//
	// Both sites share one per-request dedup guard, so a request is counted
	// exactly once whichever way it completed.
	//
	// A third site records the requests the policy gate refuses itself. Those
	// never reach a backend, so neither response-completion site can see them,
	// and without them this family counted served traffic rather than offered
	// load — no combination of the exported families yielded a total request
	// denominator.
	//
	// The outcome label is what makes that safe to add rather than a silent
	// re-definition. status alone cannot carry it: a backend may answer 429 or
	// 503 itself, so a status-only reading cannot tell a gate denial from an
	// overloaded upstream, and folding denials into an unlabelled family would
	// have changed what every existing ratio over it means. With outcome:
	//
	//	sum(rate(loxilb_ai_requests_total[5m]))                     offered load
	//	...{outcome="completed"}                                    served traffic
	//	...{outcome="denied"}                                       gate refusals
	//
	// The two values are mutually exclusive per request, so summing by outcome
	// reproduces the unfiltered total. Existing error-ratio semantics are
	// preserved exactly by selecting outcome="completed".
	//
	// The point-of-denial counters stay: they partition denials by REASON,
	// which neither status nor outcome carries. They are not a second copy of
	// the same number — one request trips one gate but several reason counters
	// exist, so the relation is
	// rate_limit_hits_total <= requests_total{outcome="denied",status="429"}.
	aiRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_requests_total",
			Help: "Total AI Gateway requests by model, tenant, HTTP status code, and outcome (completed = answered by a backend, recorded at SSE stream completion or at response headers; denied = refused by the gateway policy gate).",
		},
		[]string{"model", "tenant", "status", "outcome"},
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

	// aiTokensMissingTotal counts SUCCESSFUL responses that produced no
	// readable usage object. Two writers reach it and they charge
	// differently, so it is NOT a subset of the estimated series: a streamed
	// response falls back to the estimate net (RecordTokenUsage's estimated
	// arm, which also feeds aiTokensEstimatedTotal), while a non-streamed one
	// is charged nothing at all (RecordTokenUsageMissing). Counts responses,
	// not tokens — missing >= the number of responses in
	// aiTokensEstimatedTotal, and the gap is the uncharged non-streamed half.
	//
	// The reason label splits that gap further, because one counter was
	// covering two opposite policy cases. A backend answering 2xx with no
	// usage object is a conformance problem and the response staying free is
	// the right answer; a connection that ended after the 2xx before any
	// usage was read is not that at all — the work was done — yet both looked
	// identical in the series. See TokenMissingReason* for the accepted
	// values and what each one proves.
	//
	// An error response is NOT counted. The family reports an accounting hole
	// — work that should have been charged and could not be — and a backend
	// answering 4xx/5xx completed no work, so carrying no usage is correct
	// rather than missing. Counting it would let a backend outage drive the
	// series harder than the condition it exists to report.
	aiTokensMissingTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_tokens_missing_total",
			Help: "Total successful (2xx) AI Gateway responses with no readable usage object, by model, tenant and reason. reason names the boundary the report fired at: response_complete (the exchange demonstrably finished, so the backend omitted usage), h2_stream_close (an HTTP/2 stream closed; finished and aborted-after-headers are not distinguishable there), connection_close (the connection ended with a 2xx seen and no usage read) or stream_estimated (a stream charged from the estimate net). Only stream_estimated was charged. Error responses are excluded -- they completed no work, so carrying no usage is correct rather than missing.",
		},
		[]string{"model", "tenant", "reason"},
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

	// aiPDTierSelectedTotal counts terminal P/D routing-tier decisions per model.
	// One increment per successful prefill selection, at the terminal return of
	// the tier that produced the endpoint. Admission outcomes (parked,
	// no-capacity) and pre-routing failures increment nothing, so per window:
	// accepted P/D selections == sum over the four tier label values. The
	// existing Tier-0 (pd_session_hits) and Tier-1.5 counters remain for one
	// release and must reconcile with this family.
	aiPDTierSelectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_pd_tier_selected_total",
			Help: "Total P/D prefill selections by terminal routing tier (tier0 session, tier1 prefix trie, tier15 KV-exact, tier2 min-load).",
		},
		[]string{"tier", "model"},
	)

	// aiNormalSessionHitsTotal counts normal-mode session-stickiness cache hits per model.
	aiNormalSessionHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_normal_session_hits_total",
			Help: "Total non-P/D AI gateway requests where session stickiness (X-Conversation-Id or user field) directed the request to a previously pinned backend EP.",
		},
		[]string{"model"},
	)

	// aiUnmeteredRequestsTotal counts AI requests served without a credential,
	// because the service's api_key_auth policy resolved to "disabled".
	//
	// It exists because the default is "disabled": an operator who never sets
	// the field gets AI traffic that nobody is billed for and no key is
	// checked on, and that is a choice they should be able to SEE rather than
	// discover from a bill. It reports the consequence of the configuration,
	// not a fault — a steady non-zero rate here is normal on a deliberately
	// open gateway and alarming on one believed to be enforcing.
	aiUnmeteredRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_unmetered_requests_total",
			Help: "Total AI gateway requests admitted without X-Api-Key validation because the service's api_key_auth policy is disabled. Not an error: it quantifies AI traffic that is neither authenticated nor metered.",
		},
		[]string{"vip"},
	)

	// aiPolicyStoreUnavailableTotal counts requests refused with 503 because a
	// service required an API key and the key store could not answer.
	//
	// It exists so the fail-closed condition is ALERTABLE rather than inferred.
	// Without it the only symptom is a change in denial volume, and denials are
	// indistinguishable at the counter level from ordinary bad keys — an
	// operator watching 401s cannot tell "someone is probing us" from "our
	// store is down and we are refusing legitimate traffic". Those need
	// opposite responses, so they get separate counters.
	aiPolicyStoreUnavailableTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_ai_policy_store_unavailable_total",
			Help: "Total AI gateway requests refused with 503 because the service's api_key_auth policy requires a key and the API-key store is unconfigured or unreachable. Non-zero means the gateway is failing closed and legitimate traffic is being refused.",
		},
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
		aiTokensMissingTotal.WithLabelValues(model, tenant, TokenMissingReasonStreamEstimated).Inc()
	}
}

// Accepted values for the reason label on loxilb_ai_tokens_missing_total.
//
// Each names the BOUNDARY the report fired at, not a diagnosis of why the
// usage object was absent, because the boundary is the only thing the
// reporter actually knows. The data plane spells the first three in
// common/sockproxy_ai_gw.h (LLB_AI_UMISS_*) and they must stay in step with
// these; the fourth is written here, on the streamed path that never crosses
// the cgo boundary.
//
// The split exists to make one operational question answerable. Missing-usage
// responses are free (see RecordTokenUsageMissing), which is the right answer
// when a backend simply omits the usage object and the wrong answer if a
// tenant learns to induce the free path on purpose. Those two look identical
// in an unlabelled counter. Compared against the fleet baseline they do not:
//
//   - elevated on every tenant at once  => a backend conformance problem,
//     and leaving it free is correct;
//   - one tenant materially above baseline on ConnectionClose => behavioural,
//     and that is the signal worth acting on.
//
// Only TokenMissingReasonResponseComplete proves the exchange finished. The
// other two are honestly ambiguous and are named so nobody reads more into
// them than the code can support.
const (
	// TokenMissingReasonResponseComplete: the HTTP/1.1 keep-alive reset. The
	// client sent the NEXT request on the same connection, so the previous
	// response demonstrably completed and the backend simply put no usage
	// object in it. The strongest of the four.
	TokenMissingReasonResponseComplete = "response_complete"
	// TokenMissingReasonH2StreamClose: an HTTP/2 client stream closed. The
	// same close runs for a finished response and for one aborted after its
	// 2xx headers, and nghttp2's error code is not plumbed to the reporter,
	// so completion is NOT established here.
	TokenMissingReasonH2StreamClose = "h2_stream_close"
	// TokenMissingReasonConnectionClose: the connection was destroyed with a
	// 2xx status seen and no usage read — the H1 teardown and the H2
	// in-flight sweep both land here. A non-conforming backend closing the
	// connection and a client that took the 2xx and cut are indistinguishable
	// from this side; this is the bucket the per-tenant comparison watches.
	TokenMissingReasonConnectionClose = "connection_close"
	// TokenMissingReasonStreamEstimated: a streamed response reached its
	// terminator with no usage object and was charged from the estimate net
	// (RecordTokenUsage's estimated arm). The ONE value on this family that
	// was charged for, which is why it is labelled rather than merged into
	// the free ones.
	TokenMissingReasonStreamEstimated = "stream_estimated"
	// TokenMissingReasonUnknown absorbs anything else, as a runtime backstop
	// rather than as the primary detector.
	//
	// It is NOT reachable by a version skew between the two repos: the data
	// plane is linked statically (-l:libloxilbdp.a, pkg/loxinet/dpebpf_linux.go),
	// so a mismatched build fails to build — the C compiler rejects an argument
	// the header does not declare, and check-source-invariants.sh §9 rejects a
	// Go signature that moves without it. What a skew cannot do is reach
	// runtime.
	//
	// What could is a reason VALUE added on one side only, which changes no
	// signature and so compiles clean on both. That is what §10 of the same
	// script now checks, by comparing the LLB_AI_UMISS_* literals against these
	// constants and requiring every call site to use a define rather than a
	// bare string. So the drift this once absorbed silently now fails a gate.
	//
	// This stays because a gate reads the source it is pointed at: a reason
	// built at runtime instead of passed as a literal, a call site in a file
	// §10 does not scan, or an empty string (C.GoString of a NULL reason) all
	// still arrive here. Collapsing keeps the label's cardinality closed — the
	// point of an allow-list — and leaves anything unforeseen visible as a
	// series nobody expects, instead of as a new one nobody bounded.
	TokenMissingReasonUnknown = "unknown"
)

// boundTokenMissingReason maps a data-plane reason onto the accepted set,
// collapsing anything unrecognised (including the empty string) onto
// TokenMissingReasonUnknown.
//
// An allow-list rather than sanitizeLabel, because the two are not the same
// kind of guard. sanitizeLabel bounds the ALPHABET of a label value; it does
// nothing about how many distinct values exist. This label is per-tenant on a
// counter vector, so an unbounded set of values is an unbounded set of series,
// and the values originate in a different repository's source. A closed set is
// the only guard that holds.
func boundTokenMissingReason(reason string) string {
	switch reason {
	case TokenMissingReasonResponseComplete,
		TokenMissingReasonH2StreamClose,
		TokenMissingReasonConnectionClose,
		TokenMissingReasonStreamEstimated:
		return reason
	default:
		return TokenMissingReasonUnknown
	}
}

// RecordTokenUsageMissing counts ONE completed response that produced no
// readable usage object, and charges nothing.
//
// loxilb_ai_tokens_missing_total documents itself as counting completed AI
// Gateway responses with no readable usage object — every such response, not
// only the streaming ones. It was reachable solely through RecordTokenUsage's
// estimated arm, which the data plane sets exclusively on the SSE terminator,
// so a non-streamed response whose body carried no usage object incremented
// nothing at all: the one condition the counter exists to expose was invisible
// for that shape.
//
// Deliberately separate from RecordTokenUsage rather than folded into it, and
// charging nothing is a SETTLED decision rather than an unfinished one: these
// responses stay free. Charging is not reversible the way reporting is — an
// estimate can trip the quota latch and deny the tenant's NEXT request, for
// traffic that costs them nothing today — and the estimate available here is
// weaker than the streaming one anyway: a non-streamed response has no chunk
// count, so there is no completion-side signal at all, only the prompt.
// Revisit if loxilb_ai_tokens_missing_total shows real volume in production;
// that counter exists precisely so the question can be reopened with data
// instead of a guess. It therefore touches neither the consumed nor the
// estimated series.
//
// Attributed-only, like every other per-tenant usage family: a keyless
// response has no tenant to label it with, and llb_ai_token_quota_consume
// already skips RecordTokenUsage on exactly that condition because an empty
// tenant label reads as a scrape bug. The data plane cannot make that call for
// us — it reports from the response boundary, where an api_key_auth=disabled
// service has a completed AI response and no tenant — so the guard lives here,
// once, for both call sites. Keyless volume stays visible per VIP in
// loxilb_ai_unmetered_requests_total.
//
// reason is the boundary the data plane reported from, one of the
// TokenMissingReason* values above; anything else collapses onto "unknown"
// rather than minting a series. It records where the report came from, never
// a verdict on the tenant — see boundTokenMissingReason. The values are held
// in step with the data plane's LLB_AI_UMISS_* defines by
// check-source-invariants.sh §10, because a value that drifts does not crash
// and does not fail a unit test: it just stops splitting.
func RecordTokenUsageMissing(modelName, tenantID, reason string) {
	tenant := sanitizeLabel(tenantID)
	if tenant == "" {
		return
	}
	aiTokensMissingTotal.WithLabelValues(boundModelLabel(modelName), tenant,
		boundTokenMissingReason(reason)).Inc()
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

// TokenQuotaState is one quota bucket's live state as supplied by the
// snapshot source registered via RegisterTokenQuotaSource (the rate-limiter
// store, adapted in pkg/loxinet). Model is empty for the tenant aggregate
// bucket and set for a tenant|model bucket; the collector routes the two to
// separate series so the aggregate's labels stay unchanged.
type TokenQuotaState struct {
	Tenant   string
	Model    string
	Consumed int64
	Limit    int64

	// Scope selects which series this bucket belongs on. Empty is the
	// tenant ladder: the aggregate when Model is empty, the tenant|model
	// bucket otherwise. The rest are the identity scopes, which were
	// exported nowhere until this field existed — the tenant series had to
	// drop them, because a per-key bucket published as {tenant="kq:<id>"}
	// moves a saturation alert by exactly as much as a real tenant would
	// and a wrong label is worse than a missing one.
	//
	// Each scope gets a series with its OWN name and its own labels, which
	// is the whole point: "user" is not a spelling of "tenant".
	//
	//   ""           tenant aggregate, or tenant|model when Model is set
	//   "user"       per-user quota          — Tenant + User
	//   "user_model" per-user-per-model      — Tenant + User + Model
	//   "key"        per-API-key token quota — KeyID
	//   "vip"        per-VIP keyless bucket  — Service
	Scope   string
	User    string
	KeyID   string
	Service string
}

var (
	tokenQuotaUtilizationDesc = prometheus.NewDesc(
		"loxilb_ai_token_quota_utilization",
		"Fraction of the per-tenant tokens-per-minute quota currently spent and not yet refilled, computed at scrape time. May exceed 1.0 while the bucket is in post-hoc debt; decays continuously as the bucket refills.",
		[]string{"tenant"}, nil,
	)
	tokenQuotaLimitDesc = prometheus.NewDesc(
		"loxilb_ai_token_quota_limit_tokens",
		"Per-tenant tokens-per-minute quota as of the tenant's most recent charge. Headroom in tokens = limit * (1 - utilization).",
		[]string{"tenant"}, nil,
	)
	tokenQuotaModelUtilizationDesc = prometheus.NewDesc(
		"loxilb_ai_token_quota_model_utilization",
		"Fraction of a tenant's per-model tokens-per-minute quota currently spent and not yet refilled, computed at scrape time. Same semantics as loxilb_ai_token_quota_utilization, keyed tenant+model.",
		[]string{"tenant", "model"}, nil,
	)
	tokenQuotaModelLimitDesc = prometheus.NewDesc(
		"loxilb_ai_token_quota_model_limit_tokens",
		"Per-model tokens-per-minute quota for a tenant as of the pair's most recent charge.",
		[]string{"tenant", "model"}, nil,
	)

	// The identity scopes. Same scrape-time semantics as the tenant pair
	// above — utilization may exceed 1.0 while a bucket is in post-hoc debt
	// and decays as it refills — on series named for what they actually
	// key on.
	//
	// Cardinality is bounded by ACTIVE buckets, not by configured
	// identities: a bucket exists only once the identity has a quota bound
	// AND has been charged, and the store's Cleanup removes it again after
	// its inactivity window. A fleet with many API keys therefore exports
	// children for the keys currently spending, not for every key on file.
	userTokenQuotaUtilizationDesc = prometheus.NewDesc(
		"loxilb_ai_user_token_quota_utilization",
		"Fraction of a user's per-minute token quota currently spent and not yet refilled, computed at scrape time. Same semantics as loxilb_ai_token_quota_utilization, keyed tenant+user.",
		[]string{"tenant", "user"}, nil,
	)
	userTokenQuotaLimitDesc = prometheus.NewDesc(
		"loxilb_ai_user_token_quota_limit_tokens",
		"Per-user tokens-per-minute quota as of that user's most recent charge. Headroom in tokens = limit * (1 - utilization).",
		[]string{"tenant", "user"}, nil,
	)
	userModelTokenQuotaUtilizationDesc = prometheus.NewDesc(
		"loxilb_ai_user_model_token_quota_utilization",
		"Fraction of a user's per-model per-minute token quota currently spent and not yet refilled, computed at scrape time. Keyed tenant+user+model.",
		[]string{"tenant", "user", "model"}, nil,
	)
	userModelTokenQuotaLimitDesc = prometheus.NewDesc(
		"loxilb_ai_user_model_token_quota_limit_tokens",
		"Per-user-per-model tokens-per-minute quota as of that pair's most recent charge.",
		[]string{"tenant", "user", "model"}, nil,
	)
	keyTokenQuotaUtilizationDesc = prometheus.NewDesc(
		"loxilb_ai_key_token_quota_utilization",
		"Fraction of an API key's own per-minute token quota currently spent and not yet refilled, computed at scrape time. Keyed by key_id — the store's opaque identifier, never the key material.",
		[]string{"key_id"}, nil,
	)
	keyTokenQuotaLimitDesc = prometheus.NewDesc(
		"loxilb_ai_key_token_quota_limit_tokens",
		"Per-API-key tokens-per-minute quota as of that key's most recent charge.",
		[]string{"key_id"}, nil,
	)
	vipTokenQuotaUtilizationDesc = prometheus.NewDesc(
		"loxilb_ai_vip_token_quota_utilization",
		"Fraction of a keyless service's shared per-minute token quota currently spent and not yet refilled, computed at scrape time. Keyed by the service ident the VIP bucket is configured on.",
		[]string{"service"}, nil,
	)
	vipTokenQuotaLimitDesc = prometheus.NewDesc(
		"loxilb_ai_vip_token_quota_limit_tokens",
		"Per-VIP shared keyless tokens-per-minute quota as of that service's most recent charge.",
		[]string{"service"}, nil,
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
	ch <- tokenQuotaModelUtilizationDesc
	ch <- tokenQuotaModelLimitDesc
	ch <- userTokenQuotaUtilizationDesc
	ch <- userTokenQuotaLimitDesc
	ch <- userModelTokenQuotaUtilizationDesc
	ch <- userModelTokenQuotaLimitDesc
	ch <- keyTokenQuotaUtilizationDesc
	ch <- keyTokenQuotaLimitDesc
	ch <- vipTokenQuotaUtilizationDesc
	ch <- vipTokenQuotaLimitDesc
}

func (c *tokenQuotaCollector) Collect(ch chan<- prometheus.Metric) {
	// Distinct tenant/model IDs can sanitize to the same label value;
	// emitting both would fail the scrape with a duplicate-series error, so
	// only the first snapshot entry per sanitized label set is exported.
	seen := make(map[string]struct{})
	for _, st := range c.snapshot() {
		if st.Limit <= 0 {
			continue
		}
		// The identity scopes route first: each has its own Desc, so the
		// dedupe key is namespaced by scope and a user called "x" can
		// never collide with a tenant called "x".
		if st.Scope != "" {
			util := float64(st.Consumed) / float64(st.Limit)
			limit := float64(st.Limit)
			// firstOf keys the dedupe by scope as well as by labels, so a
			// user called "x" can never collide with a tenant called "x".
			firstOf := func(labels ...string) bool {
				k := st.Scope + "\x00" + strings.Join(labels, "\x00")
				if _, dup := seen[k]; dup {
					return false
				}
				seen[k] = struct{}{}
				return true
			}
			// Each Desc is named at its own MustNewConstMetric call rather
			// than reached through a variable, and that is a requirement
			// and not a style: the metric extractor resolves a family's
			// runtime type by reading this call, and a Desc arriving as an
			// identifier it cannot follow becomes a family typed "desc" —
			// which is how a family ends up reported absent and a panel
			// built on it looks broken.
			switch st.Scope {
			case "user":
				tenant, user := sanitizeLabel(st.Tenant), sanitizeLabel(st.User)
				if !firstOf(tenant, user) {
					continue
				}
				ch <- prometheus.MustNewConstMetric(userTokenQuotaUtilizationDesc,
					prometheus.GaugeValue, util, tenant, user)
				ch <- prometheus.MustNewConstMetric(userTokenQuotaLimitDesc,
					prometheus.GaugeValue, limit, tenant, user)
			case "user_model":
				tenant, user := sanitizeLabel(st.Tenant), sanitizeLabel(st.User)
				model := sanitizeLabel(st.Model)
				if !firstOf(tenant, user, model) {
					continue
				}
				ch <- prometheus.MustNewConstMetric(userModelTokenQuotaUtilizationDesc,
					prometheus.GaugeValue, util, tenant, user, model)
				ch <- prometheus.MustNewConstMetric(userModelTokenQuotaLimitDesc,
					prometheus.GaugeValue, limit, tenant, user, model)
			case "key":
				keyID := sanitizeLabel(st.KeyID)
				if !firstOf(keyID) {
					continue
				}
				ch <- prometheus.MustNewConstMetric(keyTokenQuotaUtilizationDesc,
					prometheus.GaugeValue, util, keyID)
				ch <- prometheus.MustNewConstMetric(keyTokenQuotaLimitDesc,
					prometheus.GaugeValue, limit, keyID)
			case "vip":
				service := sanitizeLabel(st.Service)
				if !firstOf(service) {
					continue
				}
				ch <- prometheus.MustNewConstMetric(vipTokenQuotaUtilizationDesc,
					prometheus.GaugeValue, util, service)
				ch <- prometheus.MustNewConstMetric(vipTokenQuotaLimitDesc,
					prometheus.GaugeValue, limit, service)
			}
			// An unknown scope falls through here having emitted nothing:
			// dropped rather than guessed onto a series, because
			// mislabelling is the defect this whole split exists to undo.
			continue
		}
		tenant := sanitizeLabel(st.Tenant)
		if st.Model != "" {
			model := sanitizeLabel(st.Model)
			if _, dup := seen[tenant+"|"+model]; dup {
				continue
			}
			seen[tenant+"|"+model] = struct{}{}
			ch <- prometheus.MustNewConstMetric(tokenQuotaModelUtilizationDesc,
				prometheus.GaugeValue, float64(st.Consumed)/float64(st.Limit), tenant, model)
			ch <- prometheus.MustNewConstMetric(tokenQuotaModelLimitDesc,
				prometheus.GaugeValue, float64(st.Limit), tenant, model)
			continue
		}
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
//	errorPhase:       the lifecycle outcome, naming the leg that failed AND how
//	                  it failed. The pair is exported verbatim as {phase,status}
//	                  on loxilb_ai_pd_requests_total, so a value naming the wrong
//	                  leg or the wrong failure mode is an operator-visible lie:
//	                    0 = complete / success
//	                    1 = prefill  / timeout   (prefill leg ran out of time)
//	                    2 = decode   / error     (decode leg failed or died)
//	                    3 = decode   / timeout   (decode leg produced no byte)
//	                    4 = prefill  / error     (prefill leg failed or died)
//	                    5 = prefill  / rejected  (origin refused; relayed verbatim)
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
	case 3:
		phase = "decode"
		status = "timeout"
	case 4:
		phase = "prefill"
		status = "error"
	case 5:
		phase = "prefill"
		status = "rejected"
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
	} else if pdPrefillResponseInspected(errorPhase) {
		// Only a lifecycle that actually parsed a prefill response can say
		// kv_transfer_params was absent from it. Counting the others conflates
		// transport failure with the usage-absent signal this counter
		// documents.
		aiPDKvParamsMissing.WithLabelValues(model).Inc()
	}
}

// pdPrefillResponseInspected reports whether a lifecycle with the given
// errorPhase got far enough to parse a prefill response, and therefore whether
// the absence of kv_transfer_params in it is a real observation.
//
// Phases 0, 2 and 3 all completed prefill: the request either finished, or
// failed on the decode leg afterwards. Phases 1, 4 and 5 did not — a prefill
// timeout, a prefill-side death and an origin reject each leave nothing whose
// kv_transfer_params could have been read, so counting them as "missing" would
// report a measurement that was never taken.
func pdPrefillResponseInspected(errorPhase int) bool {
	switch errorPhase {
	case 0, 2, 3:
		return true
	default:
		return false
	}
}

// RecordPDSessionHit increments the loxilb_ai_pd_session_hits_total counter for
// the given model. Called by llb_ai_pd_session_hit when Tier-0 session stickiness
// routes a P/D request to a previously pinned EP pair.
func RecordPDSessionHit(modelName string) {
	aiPDSessionHitsTotal.WithLabelValues(boundModelLabel(modelName)).Inc()
}

// RecordPDTierSelected increments loxilb_ai_pd_tier_selected_total for the
// tier that terminally selected the prefill endpoint. Called by
// llb_ai_pd_tier_selected from the four terminal selection returns in
// pd_select_prefill. The tier integer encoding matches the C caller:
// 0=Tier-0 session, 1=Tier-1 trie, 15=Tier-1.5 KV-exact, 2=Tier-2 min-load.
// Any other value is dropped so the tier label stays a closed enum.
func RecordPDTierSelected(modelName string, tier int) {
	var tierLabel string
	switch tier {
	case 0:
		tierLabel = "tier0"
	case 1:
		tierLabel = "tier1"
	case 15:
		tierLabel = "tier15"
	case 2:
		tierLabel = "tier2"
	default:
		return
	}
	aiPDTierSelectedTotal.WithLabelValues(tierLabel, boundModelLabel(modelName)).Inc()
}

// RecordNormalSessionHit increments the loxilb_ai_normal_session_hits_total counter
// for the given model. Called by llb_ai_normal_session_hit when PRIORITY 0 (learned
// conv_map lookup) succeeds in PROXY_SEL_STICKY mode (non-P/D AI GW normal mode).
func RecordNormalSessionHit(modelName string) {
	aiNormalSessionHitsTotal.WithLabelValues(boundModelLabel(modelName)).Inc()
}

// RecordUnmeteredRequest increments loxilb_ai_unmetered_requests_total for the
// service VIP that admitted an AI request without checking a key. Called by
// llb_ai_record_unmetered from the data-plane gate when a connection has
// ai_gw_mode=1 and apikey_auth=0.
func RecordUnmeteredRequest(vip string) {
	aiUnmeteredRequestsTotal.WithLabelValues(vip).Inc()
}

// RecordPolicyStoreUnavailable increments
// loxilb_ai_policy_store_unavailable_total. Called from the data-plane key
// validation path when the policy requires a key and no store can answer.
//
// Deliberately unlabelled: the condition is a property of the gateway, not of
// any one tenant or VIP, and there is no authenticated tenant to attribute it
// to — that is precisely the condition being reported.
func RecordPolicyStoreUnavailable() {
	aiPolicyStoreUnavailableTotal.Inc()
}

// RecordAIRequest is the Go entry point called by the CGO export llb_ai_record_request.
//
// C sockproxy calls this once on response completion, so every request it
// records was answered by a backend and carries outcome="completed".
// Gate denials arrive through RecordAIRequestDenied instead.
//
// The point-of-denial helpers RecordRateLimitHit and RecordModelNotAllowed
// remain authoritative for the REASON a request was denied; this family
// carries the request itself. SSE stream lifecycle is tracked via
// AdjustActiveStreams from llb_ai_stream_start/llb_ai_stream_end.
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
	aiRequestsTotal.WithLabelValues(model, tenant, status, AIOutcomeCompleted).Inc()

	// Record latency when available.
	if latencyMs > 0 {
		aiRequestDurationSeconds.WithLabelValues(model, tenant).Observe(float64(latencyMs) / 1000.0)
	}
}

// RecordAIRequestDenied counts a request the AI Gateway policy gate refused
// before any backend was asked, under outcome="denied".
//
// The gate answers the client from inside the data plane's request-complete
// callback and tears the connection down, so no backend response ever reaches
// RecordAIRequest. Recording here is what makes loxilb_ai_requests_total a
// denominator for offered load rather than for served traffic.
//
// statusCode must be the status the client actually received, which is not
// derivable from the denial reason alone: the rate-limit stage answers 503, not
// 429, when it finds a keyed identity with no policy store behind it. Callers
// map the gate's decision code, not its error string.
//
// Deliberately does NOT observe the duration histogram. That histogram measures
// SSE activation to stream completion; a denial has no such interval, and
// feeding it a gate-decision latency would pull the served-latency quantiles
// toward zero exactly when denials spike.
//
// tenantID is empty on the arms that deny before a credential resolves (a
// missing or unknown key, and a policy store that cannot answer). That is
// reported as the empty label value rather than a placeholder, so
// tenant="" reads as "denied before the tenant was known".
func RecordAIRequestDenied(tenantID, modelName string, statusCode int) {
	model := boundModelLabel(modelName)
	tenant := sanitizeLabel(tenantID)
	status := strconv.Itoa(statusCode)

	aiRequestsTotal.WithLabelValues(model, tenant, status, AIOutcomeDenied).Inc()
}
