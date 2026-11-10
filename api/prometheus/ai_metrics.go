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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// =====================================================================// AI GATEWAY METRICS - Per-model and per-tenant Prometheus metrics
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
	// ModelLabelNone is the model label of a refusal for a request that named
	// no model and matched no route: distinct from "other" (a model past the
	// label bound) and from "" (a refusal before any model was read).
	ModelLabelNone = "none"
)

var (
	modelLabelMu sync.RWMutex
	modelLabels  = make(map[string]struct{}, maxModelLabels)
)

// boundModelLabel sanitises a model name and collapses it to "other" when the
// distinct-model registry is full (H-11 series-mint DoS guard). A name it
// registers has its P/D series seeded (seedPDModel).
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
	if !registerModelLabel(model) {
		return modelLabelOther
	}
	return model
}

// registerModelLabel admits model to the registry, and seeds its P/D
// series the first time; false when the registry is full. The seeding runs
// outside the registry lock.
func registerModelLabel(model string) bool {
	modelLabelMu.Lock()
	_, known := modelLabels[model]
	if !known {
		if len(modelLabels) >= maxModelLabels {
			modelLabelMu.Unlock()
			return false
		}
		modelLabels[model] = struct{}{}
	}
	modelLabelMu.Unlock()
	if !known {
		seedPDModel(model)
	}
	return true
}

// MON-04: a counter series that does not exist until its first increment
// hides that increment from increase() and rate(): the first error a
// window sees reads as nothing. The families panels and alerts count are
// therefore seeded at zero, within a fixed bound.
//
//   - P/D families, per model, at registration (and "other" at init):
//     every {phase,status} of loxilb_ai_pd_requests_total (10), every
//     reason of loxilb_ai_pd_prefill_fallback_total (6), every path of
//     loxilb_ai_pd_decode_selected_total (3) and
//     loxilb_ai_pd_decode_kv_fill_total (1). 20 series per model label, at
//     most 65 labels.
//   - loxilb_ai_requests_total, per (model, tenant) pair, on the pair's
//     first record, for a keyed tenant only (tenant="" is a refusal before
//     the key resolved, and is never seeded): every combination whose status
//     the gateway decides, plus the common error statuses. 31 series per pair
//     seen; only pairs that record are seeded:
//
//	completed  aiSeedStatuses (10), the redirects 301 302 303 307 308 (5)   15
//	denied     aiSeedStatuses (10), 413 (framing: request too large)       11
//	aborted    200 for client, engine and gateway; none for client, engine  5
//
//     aborted/200 is a cut stream; aborted/none a request that ended before
//     any answer (the client left; the engine closed and the client could not
//     be told its 502). aborted/none for the gateway (the rule's listener
//     going before any answer) is not seeded: nothing in the product tears a
//     listener down with requests on it (F-17). Not seeded, being open sets:
//     any other backend status (completed, and aborted for a cut non-200
//     stream or 2xx body), and an operator's L7 REJECT code (denied, 4xx).
//     HTTP/2 writes no aborted record (#415).

// aiSeedStatuses are the error statuses seeded under completed and denied.
var aiSeedStatuses = []string{"400", "401", "403", "404", "408", "429", "500", "502", "503", "504"}

// aiSeedRedirects are the L7 redirect statuses the gateway answers with
// (completed): the five an operator may choose, 302 by default.
var aiSeedRedirects = []string{"301", "302", "303", "307", "308"}

// aiSeededPairs holds the (model, tenant) pairs already seeded.
var aiSeededPairs sync.Map

// seedAIRequestPair seeds loxilb_ai_requests_total for a (model, tenant)
// pair, once.
func seedAIRequestPair(model, tenant string) {
	if tenant == "" {
		return
	}
	if _, seen := aiSeededPairs.LoadOrStore(model+"\x00"+tenant, struct{}{}); seen {
		return
	}
	for _, st := range aiSeedStatuses {
		aiRequestsTotal.WithLabelValues(model, tenant, st, AIOutcomeCompleted, "").Add(0)
		aiRequestsTotal.WithLabelValues(model, tenant, st, AIOutcomeDenied, "").Add(0)
	}
	for _, st := range aiSeedRedirects {
		aiRequestsTotal.WithLabelValues(model, tenant, st, AIOutcomeCompleted, "").Add(0)
	}
	aiRequestsTotal.WithLabelValues(model, tenant, "413", AIOutcomeDenied, "").Add(0)
	for _, cause := range []string{AICauseClient, AICauseEngine, AICauseGateway} {
		aiRequestsTotal.WithLabelValues(model, tenant, "200", AIOutcomeAborted, cause).Add(0)
	}
	for _, cause := range []string{AICauseClient, AICauseEngine} {
		aiRequestsTotal.WithLabelValues(model, tenant, AIStatusNone, AIOutcomeAborted, cause).Add(0)
	}
}

// seedPDModel seeds the P/D families for a model label.
func seedPDModel(model string) {
	for ph := 0; ph < pdPhaseCount; ph++ {
		phase, status := pdPhaseLabels(ph)
		aiPDRequestsTotal.WithLabelValues(model, phase, status).Add(0)
	}
	for _, reason := range pdFallbackReasons {
		aiPDPrefillFallbackTotal.WithLabelValues(model, reason).Add(0)
	}
	for _, path := range pdDecodePathLabels {
		aiPDDecodeSelectedTotal.WithLabelValues(path, model).Add(0)
	}
	aiPDDecodeKVFillTotal.WithLabelValues(model).Add(0)
}

func init() {
	seedPDModel(modelLabelOther)
}

// knownModelLabel is boundModelLabel for a name that may be one nobody
// serves: the sanitised name when the registry already holds it, else
// "other". It never registers a name, so a stream of requests for models
// that do not exist cannot fill the 64 slots and push real models to
// "other". "" stays "".
func knownModelLabel(modelName string) string {
	model := sanitizeLabel(modelName)
	if model == "" {
		return model
	}
	modelLabelMu.RLock()
	_, known := modelLabels[model]
	modelLabelMu.RUnlock()
	if known {
		return model
	}
	return modelLabelOther
}

// Values of the outcome label on loxilb_ai_requests_total. Exported because a
// consumer of this package should select on the same constant the recorder
// writes, not on a string literal that can drift from it.
const (
	// AIOutcomeCompleted marks a request a backend answered.
	AIOutcomeCompleted = "completed"
	// AIOutcomeDenied marks a request the gateway refused before any backend
	// was chosen (policy gate, capacity, routing, framing), so no backend was
	// ever asked.
	AIOutcomeDenied = "denied"
	// AIOutcomeAborted marks a request whose client did not receive a
	// complete response: the client left or stopped reading, the engine died
	// under the answer, or the gateway cut it. The cause label says which.
	AIOutcomeAborted = "aborted"
)

// Values of the cause label on loxilb_ai_requests_total: set on
// outcome="aborted" only, "" on every other outcome. A client cause is
// traffic, not an error; engine and gateway causes are errors.
const (
	AICauseClient  = "client"
	AICauseEngine  = "engine"
	AICauseGateway = "gateway"
)

// AIStatusNone is the status label of a request no status was ever sent
// for (status 0 from the data plane): a client that left before any
// answer, P/D or not; or a backend off P/D that closed before it when its
// client could not be told (it is otherwise answered 502, completed).
const AIStatusNone = "none"

// aiEndCauses maps the data plane's end codes, the error_code of a request
// whose answer the client did not get whole, to their cause. It is the Go
// half of sp_end_codes in loxilb-ebpf common/sockproxy_end_cause.h, held in
// lockstep with it by scripts/check-source-invariants.sh. A code not here
// ("", a deny reason, a code from a newer data plane) is not an end:
// the request is completed, so an older or newer data plane never turns
// completions into aborts by accident.
var aiEndCauses = map[string]string{
	"client_abort":                 AICauseClient,
	"client_stall":                 AICauseClient,
	"client_abort_before_answer":   AICauseClient,
	"backend_died":                 AICauseEngine,
	"max_stream_duration_exceeded": AICauseGateway,
	"pd_decode_stream_timeout":     AICauseGateway,
	"pd_idle_timeout":              AICauseGateway,
	"listener_closed":              AICauseGateway,
}

// AIEndCause is the cause of an end code, "" when errorCode is not one
// (the request completed).
func AIEndCause(errorCode string) string {
	return aiEndCauses[errorCode]
}

// AIEndCodes lists the end codes AIEndCause knows, sorted.
func AIEndCodes() []string {
	codes := make([]string, 0, len(aiEndCauses))
	for c := range aiEndCauses {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return codes
}

// aiStatusLabel is the status label of a request record: the HTTP status,
// or AIStatusNone when none was sent.
func aiStatusLabel(statusCode int) string {
	if statusCode == 0 {
		return AIStatusNone
	}
	return strconv.Itoa(statusCode)
}

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
	// A third site records the requests the gateway refuses itself: the
	// deny record (llb_ai_record_deny), once per refusal whatever stage made
	// it (policy gate, capacity, routing, framing). Those never reach a
	// backend, so neither response-completion site can see them, and without
	// them this family counted served traffic rather than offered load — no
	// combination of the exported families yielded a total request
	// denominator. An answer the gateway writes when no backend can take the
	// request (an outage, a P/D timeout) is a completion with the status it
	// wrote, so the error ratio sees it.
	//
	// The outcome label is what makes that safe to add rather than a silent
	// re-definition. status alone cannot carry it: a backend may answer 429 or
	// 503 itself, so a status-only reading cannot tell a gate denial from an
	// overloaded upstream, and folding denials into an unlabelled family would
	// have changed what every existing ratio over it means. With outcome:
	//
	//	sum(rate(loxilb_ai_requests_total[5m]))                     offered load
	//	...{outcome="completed"}                                    served traffic
	//	...{outcome="aborted"}                                      answers the client did not get whole
	//	...{outcome="denied"}                                       gate refusals
	//
	// The three values are mutually exclusive per request, so summing by
	// outcome reproduces the unfiltered total. An aborted request carries the
	// cause of its end (cause: client, engine or gateway; "" on the other
	// outcomes) and the status the client got, or status="none" when it
	// ended before any was sent. The error ratio is
	//
	//	(completed 5xx + aborted{cause=~"engine|gateway"}) / (completed + aborted)
	//
	// A client cause is traffic, not an error.
	//
	// The point-of-denial counters stay: they partition denials by REASON,
	// which neither status nor outcome carries. They are not a second copy of
	// the same number — one request trips one gate but several reason counters
	// exist, so the relation is
	// rate_limit_hits_total <= requests_total{outcome="denied",status="429"}.
	aiRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_requests_total",
			Help: "Total AI Gateway requests by model, tenant, HTTP status code, outcome and cause (completed = answered whole, by a backend or by the gateway's own outage, timeout or redirect answer, with the status the client got; aborted = the client did not get a complete response, cause client (it left or stopped reading), engine (the backend died under the answer) or gateway (a cap, a reaper or the listener cut it), status none when no status was sent; denied = refused by the gateway before any backend was chosen: policy gate, capacity, routing, framing). cause is empty unless outcome is aborted.",
		},
		[]string{"model", "tenant", "status", "outcome", "cause"},
	)

	// aiRequestDurationSeconds tracks per-model, per-tenant request latency as
	// a histogram. Buckets extend to 300s: SSE/streaming completions routinely
	// run minutes — a 10s top bucket would blind-spot the entire tail. It
	// observes completed requests only (see RecordAIRequest); TTFT
	// (aiPDDecodeTTFT) does sample an aborted stream that reached its first
	// event.
	aiRequestDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "loxilb_ai_request_duration_seconds",
			Help:    "AI Gateway request duration in seconds, SSE activation to stream completion (monotonic clock at data plane). Completed requests only: an aborted request adds no sample.",
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

	// aiTokenQuotaDeniedTotal counts requests a token quota refused, by
	// tenant. It is kept as its own series so quota alerting does not depend
	// on a reason string, and as the anchor for per-model quota labels when
	// quota keying grows a model dimension.
	//
	// It has TWO increment sites, and they are not the same condition:
	//
	//   - the gate's post-hoc latch (error code "token_quota_exceeded"):
	//     the tenant is over budget and every request is refused until the
	//     bucket refills;
	//   - the pre-admission reservation (error code
	//     "token_quota_would_exceed"): THIS request's worst case does not
	//     fit the headroom left. The bucket is not put in debt and a smaller
	//     request from the same tenant is still admitted.
	//
	// So this series is the UNION of both refusal modes, not a subset of
	// loxilb_ai_rate_limit_hits_total{reason="token_quota_exceeded"} — it
	// equals that reason plus reason="token_quota_would_exceed". An alert
	// that needs "the tenant is exhausted" rather than "a large request was
	// turned away" must read the reason label on the hits counter; this
	// series alone cannot tell the two apart.
	aiTokenQuotaDeniedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_token_quota_denied_total",
			Help: "Total AI Gateway requests refused by a token quota, by tenant. Union of both refusal modes: the post-hoc latch (tenant over budget) and the pre-admission reservation (this request did not fit the remaining headroom). Split them with the reason label on loxilb_ai_rate_limit_hits_total.",
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

	// aiPDDecodeTTFT tracks the decode leg's time to its first streamed event.
	// Written by the second half of a lifecycle record (RecordPDRecordExtra);
	// a request whose answer streamed no event adds no sample. Every
	// lifecycle record carries it, aborted included: a stream the client or
	// the gateway cut after its first event is sampled, though the request
	// duration histogram skips it.
	aiPDDecodeTTFT = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "loxilb_ai_pd_decode_ttft_seconds",
			Help:    "P/D decode leg: dispatch to the first streamed event (the first SSE data object, a role-only delta included), in seconds. Streamed requests only; an aborted stream that reached its first event is sampled.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"model"},
	)

	// aiPDDecodeDuration tracks the whole decode leg. Its buckets reach
	// minutes, because a long completion streams for that long.
	aiPDDecodeDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "loxilb_ai_pd_decode_duration_seconds",
			Help:    "P/D decode leg: dispatch to the end of its response, in seconds. Not sampled for a request a reaper ended.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0},
		},
		[]string{"model"},
	)

	// aiPDPrefillFallbackTotal counts prefills recomputed on the decode leg,
	// by the condition that forced it (pdFallbackReasonLabel).
	aiPDPrefillFallbackTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_pd_prefill_fallback_total",
			Help: "P/D requests whose prefill was recomputed on the decode leg, by model and reason. The reason is the condition that forced the fallback, in verdict order: if the status alone forces it, the status is the reason (origin_5xx, origin_408, origin_429), whether or not the body was cut; if the status would have been relayed and the fallback happened only because the reply was cut, the reason is truncated (a cut 2xx; a cut 4xx is relayed with its status as prefill/rejected, with no fallback); an unreadable status is no_status; a 1xx/3xx is other.",
		},
		[]string{"model", "reason"},
	)

	// aiPDRequestsTotal counts P/D disaggregation requests by model, phase, and status.
	aiPDRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_pd_requests_total",
			Help: "Total P/D disaggregation requests by model, phase, and status. phase=\"complete\",status=\"success\" is a decode answer the engine ended at the HTTP level (its last chunk, its Content-Length satisfied, or its EOF on an unframed answer) and the client received whole: HTTP completion, not semantic completion of the stream. The gateway does not require a finish_reason, a usage object or the SSE [DONE] event, and a stream the engine ended cleanly without them is a success here; a stream the gateway ended is decode/truncated, one the engine broke is decode/error.",
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

	// aiEppRequestsTotal counts requests a rule handed to its Endpoint
	// Picker (EPP) by how the request phase ended: ok (a decision with
	// candidates was applied), immediate (the EPP answered the client),
	// error (deadline, gRPC error, NOT_SERVING), refused (the submit was
	// refused before a stream opened), no_endpoint (no candidate usable),
	// body_too_large (decision D5), evicted (shed during the response).
	aiEppRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_epp_requests_total",
			Help: "Total requests handed to an Endpoint Picker (EPP), by outcome of the request phase (ok, immediate, error, refused, no_endpoint, body_too_large, evicted).",
		},
		[]string{"outcome"},
	)

	// aiEppDurationSeconds is the EPP's request-phase latency: from the
	// submit to the decision (or its failure), the time the client waits
	// parked before the backend is chosen.
	aiEppDurationSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "loxilb_ai_epp_duration_seconds",
			Help:    "Endpoint Picker request-phase duration in seconds, submit to decision.",
			Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
	)

	// aiEppCandidatesRejectedTotal counts the endpoints an EPP named that
	// the data plane could not use, by reason: unknown (not an endpoint of
	// the rule), down, disabled (controller), unhealthy (prober or breaker),
	// capacity (endpoint ceiling), connect (refused the connection).
	aiEppCandidatesRejectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_epp_candidates_rejected_total",
			Help: "Total Endpoint Picker candidates the data plane skipped, by reason (unknown, down, disabled, unhealthy, capacity, connect).",
		},
		[]string{"reason"},
	)

	// aiEppInflight and aiEppPending expose the EPP state the data plane
	// holds right now, so a failover can be checked to have drained: requests
	// between submit and their last report (the EPP's view of in-flight
	// load), and decisions the C side table still holds. Both read the
	// provider loxinet installs (SetEppStateProvider) at scrape time.
	aiEppInflight = datapathMetrics.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "loxilb_ai_epp_inflight",
			Help: "Requests currently handed to an Endpoint Picker and not yet reported finished (the EPP's in-flight view).",
		},
		func() float64 { a, _ := eppState(); return float64(a) },
	)
	aiEppPending = datapathMetrics.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "loxilb_ai_epp_pending",
			Help: "Endpoint Picker decisions the data plane side table still holds (parked or being applied).",
		},
		func() float64 { _, p := eppState(); return float64(p) },
	)
	// aiPDDecodeSelectedTotal counts terminal P/D decode selections per model
	// by the path that produced the endpoint: hint (the session-pinned decode
	// EP was kept), score (the min-load scorer picked; with
	// LLB_PD_DECODE_KV_WEIGHT unset, every scored pick) or score_kv (the
	// weight is set and the KV-pressure term changed the set of minimum-score
	// candidates, so the pick is one the shipped scorer would not have made).
	// One increment per successful pd_select_decode (admission, mid-cycle
	// prefill-connect failover, SGLang pair retry); the vLLM connect-time
	// re-read of the admission choice records nothing. Admission outcomes
	// (parked, no-capacity) and a selector that found no decode EP increment
	// nothing, so per window: decode selections == sum over the three paths.
	// Seeded at zero per model label (seedPDModel).
	aiPDDecodeSelectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_pd_decode_selected_total",
			Help: "Total P/D decode selections by path (hint = session-pinned decode kept, score = min-load pick, score_kv = the KV-pressure term changed the min-load candidate set).",
		},
		[]string{"path", "model"},
	)

	// aiPDDecodeKVFillTotal counts, per model, the scored decode selections
	// made with LLB_PD_DECODE_KV_WEIGHT set in which at least one candidate
	// had no fresh KV-usage reading (never reported, no usage family on its
	// /metrics, or older than the telemetry window) and took the neutral
	// fill instead. It is the "signal is broken" indicator for the weight:
	// a pool whose every selection lands here is being scored without the
	// signal the operator switched on. A subset of
	// loxilb_ai_pd_decode_selected_total{path=~"score|score_kv"}. Seeded at
	// zero per model label.
	aiPDDecodeKVFillTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_pd_decode_kv_fill_total",
			Help: "Total P/D decode selections scored with LLB_PD_DECODE_KV_WEIGHT set in which at least one candidate's KV-usage reading was unknown or stale and took the neutral fill.",
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

	// aiWorkerScrapeTotal counts every vLLM /metrics scrape attempt by outcome.
	//
	// The scraper feeds the live load signals that P/D prefill selection scores
	// on -- queued_requests and the advertised KV capacity. When an endpoint
	// stops answering /metrics the pushes simply stop, and the datapath handles
	// that correctly but SILENTLY: a queue depth nobody has refreshed for
	// PD_QUEUE_STALE_SEC is dropped and the fleet average substituted, so
	// selection keeps working on a fill-in. Before this counter there was no
	// exported signal anywhere that it had happened. Measured on the P/D bed:
	// a 45s blackout of every prefill endpoint's /metrics moved NO loxilb
	// family and logged nothing, because the transport failure is Debugf.
	//
	// "Routing on live load" and "routing on a fill-in because every scrape has
	// failed for ten minutes" look identical from outside and need opposite
	// responses, which is what makes this alertable rather than diagnostic.
	//
	// SUCCESS IS COUNTED TOO. A counter that moves only on failure cannot
	// distinguish "nothing is failing" from "the scraper is not running at
	// all" -- the same false reassurance an eager zero gives. result="ok" is
	// the non-vacuity witness and the denominator of any failure ratio.
	//
	// Labelled by outcome only, not by endpoint: this is a per-service health
	// question and the closed result set keeps cardinality bounded. Which
	// endpoint went dark is a follow-up question, answered by correlating with
	// the per-EP surfaces rather than by multiplying series here.
	aiWorkerScrapeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loxilb_ai_worker_scrape_total",
			Help: "Total vLLM worker /metrics scrape attempts by outcome (ok, unreachable, http_error, body_error, unparseable, bad_request). Anything other than ok means P/D load-aware selection is scoring on a stale or substituted signal for that endpoint.",
		},
		[]string{"result"},
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
// directly from the Go rate-limit decision path: llb_ai_ratelimit_check when
// a request is denied (decision != 0), and llb_ai_token_quota_reserve when
// the pre-admission reservation refuses one.
// If reason is empty it falls back to "rate_limit_exceeded".
// eppStateProvider is installed by loxinet; nil reads as zero.
var eppStateProvider atomic.Pointer[func() (inflight, pending int)]

// SetEppStateProvider installs the function the EPP in-flight/pending
// gauges read at scrape time.
func SetEppStateProvider(fn func() (inflight, pending int)) {
	eppStateProvider.Store(&fn)
}

func eppState() (int, int) {
	if f := eppStateProvider.Load(); f != nil {
		return (*f)()
	}
	return 0, 0
}

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
// counter. Both token-quota refusal paths call it: llb_ai_ratelimit_check
// when the post-hoc latch is set (error code "token_quota_exceeded"), and
// llb_ai_token_quota_reserve when the request's worst case does not fit the
// remaining headroom (error code "token_quota_would_exceed"). The series
// therefore counts both, and only the reason label on
// loxilb_ai_rate_limit_hits_total says which site wrote a given increment.
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

// pdPhaseLabels is the {phase,status} pair of loxilb_ai_pd_requests_total
// for an errorPhase (RecordPDRequest documents the values); anything else
// is {unknown,error}.
func pdPhaseLabels(errorPhase int) (phase, status string) {
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
	case 6:
		phase = "decode"
		status = "rejected"
	case 7:
		phase = "decode"
		status = "unknown"
	case 8:
		phase = "decode"
		status = "truncated"
	case 9:
		phase = "aborted"
		status = "client"
	default:
		phase = "unknown"
		status = "error"
	}
	return phase, status
}

// pdPhaseCount is the number of errorPhase values with a label pair of
// their own (0..9): the ones seeded at model registration.
const pdPhaseCount = 10

// RecordPDRequest records a P/D disaggregation lifecycle event for Prometheus metrics.
//
// Parameters:
//
//	modelName:        the effective model name
//	prefillLatencyMs: prefill phase duration in milliseconds; 0 when unknown
//	decodeLatencyMs:  the decode leg, dispatch to the end of its response, in
//	                  milliseconds; 0 when unknown or not sampled (a reaped
//	                  request). The time to the first streamed event comes in
//	                  the record's second half (RecordPDRecordExtra).
//	kvParamsFound:    1 when kv_transfer_params was found in prefill response, 0 otherwise
//	errorPhase:       the lifecycle outcome, naming the leg that failed AND how
//	                  it failed. The pair is exported verbatim as {phase,status}
//	                  on loxilb_ai_pd_requests_total, so a value naming the wrong
//	                  leg or the wrong failure mode is an operator-visible lie:
//	                    0 = complete / success
//	                    1 = prefill  / timeout   (prefill leg ran out of time)
//	                    2 = decode   / error     (the engine died: it closed its
//	                                              connection or the decode leg
//	                                              broke before its answer was
//	                                              complete; never a reaper's)
//	                    3 = decode   / timeout   (decode leg produced no byte)
//	                    4 = prefill  / error     (prefill leg failed or died)
//	                    5 = prefill  / rejected  (origin refused; relayed verbatim)
//	                    6 = decode   / rejected  (origin refused; relayed verbatim)
//	                    7 = decode   / unknown   (decode completed; its status
//	                                              line was never read)
//	                    8 = decode   / truncated (the gateway ended or cut an
//	                                              in-progress answer for a cause
//	                                              other than engine death: engine
//	                                              silence or a policy cap)
//	                    9 = aborted  / client    (the client left, at any stage:
//	                                              before any answer, with its
//	                                              answer open, or it stopped
//	                                              reading; requests_total
//	                                              outcome="aborted", cause="client")
func RecordPDRequest(modelName string, prefillLatencyMs, decodeLatencyMs int64, kvParamsFound, errorPhase int) {
	model := boundModelLabel(modelName)

	phase, status := pdPhaseLabels(errorPhase)

	aiPDRequestsTotal.WithLabelValues(model, phase, status).Inc()

	if prefillLatencyMs > 0 {
		aiPDPrefillDuration.WithLabelValues(model).Observe(float64(prefillLatencyMs) / 1000.0)
	}
	if decodeLatencyMs > 0 {
		aiPDDecodeDuration.WithLabelValues(model).Observe(float64(decodeLatencyMs) / 1000.0)
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

// Values of the reason label on loxilb_ai_pd_prefill_fallback_total, by the
// C code (PD_FB_* in loxilb-ebpf common/sockproxy_pd_leak.h). The label is a
// closed set: any other code is "other".
var pdFallbackReasons = map[int]string{
	1: "origin_5xx",
	2: "origin_408",
	3: "origin_429",
	4: "no_status",
	5: "truncated",
	6: "other",
}

// pdFallbackReasonLabel maps a C fallback code to its reason label; "" for 0
// (no fallback).
func pdFallbackReasonLabel(code int) string {
	if code == 0 {
		return ""
	}
	if r, ok := pdFallbackReasons[code]; ok {
		return r
	}
	return "other"
}

// RecordPDRecordExtra records the second half of one P/D lifecycle record,
// made by the data plane right after RecordPDRequest for the same request and
// the same completion event: the decode leg's time to its first streamed event
// (0 when none) and why the prefill was recomputed on the decode leg (0 when
// it was not). The model label is the one RecordPDRequest registered for the
// request (knownModelLabel): this half never mints a series of its own.
func RecordPDRecordExtra(modelName string, decodeTTFTUs int64, fallbackReason int) {
	model := knownModelLabel(modelName)
	if decodeTTFTUs > 0 {
		aiPDDecodeTTFT.WithLabelValues(model).Observe(float64(decodeTTFTUs) / 1e6)
	}
	if r := pdFallbackReasonLabel(fallbackReason); r != "" {
		aiPDPrefillFallbackTotal.WithLabelValues(model, r).Inc()
	}
}

// pdPrefillResponseInspected reports whether a lifecycle with the given
// errorPhase got far enough to parse a prefill response, and therefore whether
// the absence of kv_transfer_params in it is a real observation.
//
// Phases 0, 2, 3, 6, 7 and 8 all completed prefill: the request either
// finished, or ended on the decode leg afterwards. Phases 1, 4 and 5 did not — a prefill
// timeout, a prefill-side death and an origin reject each leave nothing whose
// kv_transfer_params could have been read, so counting them as "missing" would
// report a measurement that was never taken. errorPhase 9 (the client left) is not
// listed either: it can come before the prefill response was read.
func pdPrefillResponseInspected(errorPhase int) bool {
	switch errorPhase {
	case 0, 2, 3, 6, 7, 8:
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

// Path encodings of llb_ai_pd_decode_selected, as the C selector passes them
// (PD_DEC_PATH_* in loxilb-ebpf common/sockproxy_pd.c).
const (
	pdDecodePathHint    = 0
	pdDecodePathScore   = 1
	pdDecodePathScoreKV = 2
)

// pdDecodePathLabels is the closed path enum of
// loxilb_ai_pd_decode_selected_total, by C encoding.
var pdDecodePathLabels = map[int]string{
	pdDecodePathHint:    "hint",
	pdDecodePathScore:   "score",
	pdDecodePathScoreKV: "score_kv",
}

// RecordPDDecodeSelected increments loxilb_ai_pd_decode_selected_total for
// the path that terminally selected the decode endpoint and, when kvFill is
// set, loxilb_ai_pd_decode_kv_fill_total for the same model. Called by
// llb_ai_pd_decode_selected once per successful pd_select_decode. Any path
// value outside the enum records nothing in either family, so the label
// stays closed whatever the caller sends.
func RecordPDDecodeSelected(modelName string, path int, kvFill bool) {
	pathLabel, ok := pdDecodePathLabels[path]
	if !ok {
		return
	}
	model := boundModelLabel(modelName)
	aiPDDecodeSelectedTotal.WithLabelValues(pathLabel, model).Inc()
	if kvFill {
		aiPDDecodeKVFillTotal.WithLabelValues(model).Inc()
	}
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

// aiWorkerScrapeResults is the closed label set of aiWorkerScrapeTotal, and the
// single source of truth for both the pre-create loop and the recorder's
// validation. Adding a value here is an API change to the metric.
var aiWorkerScrapeResults = []string{
	"ok", "unreachable", "http_error", "body_error", "unparseable",
	"bad_request", "unknown",
}

// init pre-creates every result child so the vector is present at zero in the
// very first scrape, before anything has been recorded.
//
// This is not cosmetic. The condition this family exists to report is "the
// scraper has stopped producing samples", and a lazily-created vector is
// ABSENT in exactly that state if the scraper never got as far as one attempt
// -- indistinguishable, to an alert, from a healthy gateway. Present-at-zero
// makes "no P/D rule, so no scraper" read as six flat zeros, and gives
// result="ok" an existing denominator from the start rather than one that
// appears only once something has already succeeded.
func init() {
	for _, r := range aiWorkerScrapeResults {
		aiWorkerScrapeTotal.WithLabelValues(r)
	}
}

// RecordWorkerScrape increments loxilb_ai_worker_scrape_total{result}. Called
// once per vLLM /metrics scrape attempt from the scraper's result sink,
// including on success -- see the counter's declaration for why the success
// arm is not optional.
//
// The result string comes from the aimetrics.Scrape* closed set. An unknown
// value is folded to "unknown" rather than admitted as a label, so a typo
// upstream cannot silently open the cardinality of this vector.
func RecordWorkerScrape(result string) {
	known := false
	for _, r := range aiWorkerScrapeResults {
		if r == result && r != "unknown" {
			known = true
			break
		}
	}
	if !known {
		result = "unknown"
	}
	aiWorkerScrapeTotal.WithLabelValues(result).Inc()
}

// RecordAIRequest is the Go entry point called by the CGO export llb_ai_record_request.
//
// C sockproxy calls this once per request it answered or began to answer.
// errorCode decides the outcome: an end code (AIEndCause) is
// outcome="aborted" with its cause, anything else outcome="completed".
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
//	statusCode: HTTP response status code (200, 401, 403, 429, 500, …); 0
//	            when none was sent (status="none")
//	latencyMs: request latency in milliseconds; 0 when unknown
//	errorCode: the data plane's error_code; an end code makes it aborted
//
// The duration histogram observes completed requests only: an aborted
// request's latency is the time to its cut, which would pull the served
// quantiles toward wherever the cuts land.
func RecordAIRequest(tenantID, modelName string, statusCode int, latencyMs int64, errorCode string) {
	model := boundModelLabel(modelName)
	tenant := sanitizeLabel(tenantID)
	status := aiStatusLabel(statusCode)
	seedAIRequestPair(model, tenant)

	if cause := AIEndCause(errorCode); cause != "" {
		aiRequestsTotal.WithLabelValues(model, tenant, status, AIOutcomeAborted, cause).Inc()
		return
	}
	aiRequestsTotal.WithLabelValues(model, tenant, status, AIOutcomeCompleted, "").Inc()

	// Record latency when available.
	if latencyMs > 0 {
		aiRequestDurationSeconds.WithLabelValues(model, tenant).Observe(float64(latencyMs) / 1000.0)
	}
}

// RecordAIRequestDenied counts a request the AI Gateway refused before any
// backend was asked, under outcome="denied". Its one caller is the deny
// record (pkg/loxinet recordAIDeny), reached once per refusal from the data
// plane whatever stage refused.
//
// The gate answers the client from inside the data plane's request-complete
// callback and tears the connection down, so no backend response ever reaches
// RecordAIRequest. Recording here is what makes loxilb_ai_requests_total a
// denominator for offered load rather than for served traffic.
//
// statusCode must be the status the client actually received, which is not
// derivable from the denial reason alone: the rate-limit stage answers 503, not
// 429, when it finds a keyed identity with no policy store behind it. Callers
// pass the status the data plane wrote, not one derived from the stage.
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
	status := aiStatusLabel(statusCode)
	seedAIRequestPair(model, tenant)

	aiRequestsTotal.WithLabelValues(model, tenant, status, AIOutcomeDenied, "").Inc()
}

// RecordAIRequestDeniedUnserved counts a refusal of a request no pool may
// serve (a routing or framing refusal), under outcome="denied". The model it
// names may be one nobody serves, so the label is the model only when the
// registry already holds it, else "other" (knownModelLabel): an unknown-model
// storm cannot take the 64 slots from real models. A request that named no
// model reads noModelLabel (ModelLabelNone for a request no route matched).
func RecordAIRequestDeniedUnserved(tenantID, modelName, noModelLabel string, statusCode int) {
	model := knownModelLabel(modelName)
	if model == "" {
		model = noModelLabel
	}
	tenant := sanitizeLabel(tenantID)
	status := aiStatusLabel(statusCode)
	seedAIRequestPair(model, tenant)

	aiRequestsTotal.WithLabelValues(model, tenant, status, AIOutcomeDenied, "").Inc()
}

// RecordEppOutcome counts one request handed to an Endpoint Picker by how
// its request phase ended, and its duration when known (seconds > 0).
func RecordEppOutcome(outcome string, seconds float64) {
	if outcome != "" {
		aiEppRequestsTotal.WithLabelValues(sanitizeLabel(outcome)).Inc()
	}
	if seconds > 0 {
		aiEppDurationSeconds.Observe(seconds)
	}
}

// RecordEppCandidateRejected counts one EPP candidate the data plane skipped.
func RecordEppCandidateRejected(reason string) {
	aiEppCandidatesRejectedTotal.WithLabelValues(sanitizeLabel(reason)).Inc()
}
