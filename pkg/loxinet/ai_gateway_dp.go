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

package loxinet

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// AI Gateway decision structure (must match sockproxy_ai_gw.h)
// decision values: 0=allow, 1=deny_401, 2=deny_403, 3=deny_429
typedef struct {
    int  decision;
    int  retry_after;
    char tenant_id[128];
    char model_name[128];
    char key_id[64];
    char error_code[64];
} ai_gw_decision_t;
*/
import "C"

import (
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	tk "github.com/loxilb-io/loxilib"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	cmn "github.com/loxilb-io/loxilb/common"
	rl "github.com/loxilb-io/loxilb/pkg/ratelimit"
)

// apiKeyValidator is the subset of *user.UserService used by the AI Gateway bridge.
// It is satisfied by *user.UserService and by test mocks.
type apiKeyValidator interface {
	ValidateAPIKey(rawKey string) (*cmn.ApiKeyEntry, error)
}

// rateLimitService is the subset of *user.UserService used by the rate-limit bridge.
// It is satisfied by *user.UserService and by test mocks.
type rateLimitService interface {
	GetTenantRateLimit(tenantID string) (rps, tokensPerMin int)
	GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error)
}

// rateLimitCheckInternal is the pure-Go rate limit logic, separated from the
// CGO export so that unit tests can exercise it without going through C types.
//
// Returns (decision, retrySecs, errorCode):
//   - decision 0 = allow
//   - decision 3 = deny_429 (rate limited)
//
// error codes:
//   - "rate_limit_exceeded"   – per-key token bucket denied
//   - "tenant_quota_exceeded" – per-tenant token bucket denied
//   - "token_quota_exceeded"  – per-tenant token quota flag set
func rateLimitCheckInternal(svc rateLimitService, store *rl.RateLimiterStore, keyIDStr, tenantIDStr string) (decision, retrySecs int, errorCode string) {
	// Stage 1: per-key check with key-specific RPS and burst values.
	if keyIDStr != "" {
		keyRPS := 0
		keyBurst := 0
		if svc != nil {
			if key, err := svc.GetAPIKeyByID(keyIDStr); err == nil {
				keyRPS = key.RateLimitRPS
				keyBurst = key.BurstSize
			}
		}
		// BurstSize=0 falls back to RateLimitRPS (consistent with CheckKey semantics).
		if keyBurst <= 0 {
			keyBurst = keyRPS
		}
		allowed, retrySec := store.CheckKey(keyIDStr, keyRPS, keyBurst)
		if !allowed {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: key %s rate-limited (retry %ds)\n", keyIDStr, retrySec)
			return 3, retrySec, "rate_limit_exceeded"
		}
	}

	// Stage 2: per-tenant check with tenant-level RPS.
	if tenantIDStr != "" {
		tenantRPS := 0
		if svc != nil {
			tenantRPS, _ = svc.GetTenantRateLimit(tenantIDStr)
		}
		allowed, retrySec := store.CheckTenant(tenantIDStr, tenantRPS)
		if !allowed {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: tenant %s rate-limited (retry %ds)\n", tenantIDStr, retrySec)
			return 3, retrySec, "tenant_quota_exceeded"
		}

		// Stage 3: per-tenant token quota exceeded check.
		if store.IsTokenQuotaExceeded(tenantIDStr) {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: tenant %s token quota exceeded\n", tenantIDStr)
			return 3, 60, "token_quota_exceeded"
		}
	}

	return 0, 0, ""
}

// validateAPIKeyInternal is the pure-Go validation logic.
// It is separated from the CGO export so that unit tests can exercise it
// without going through C types.
//
// Return values:
//
//	decision   – 0=allow, 1=deny_401, 2=deny_403
//	tenantID   – populated on allow and deny_403 (for metric recording)
//	keyID      – populated on allow
//	modelOut   – model name echoed back on allow
//	errorCode  – "invalid_api_key" or "model_not_allowed" on deny
func validateAPIKeyInternal(svc apiKeyValidator, rawKey, modelName string) (decision int, tenantID, keyID, modelOut, errorCode string) {
	if rawKey == "" {
		tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_validate_key: empty raw key\n")
		return 1, "", "", "", "invalid_api_key"
	}

	entry, err := svc.ValidateAPIKey(rawKey)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_validate_key: key validation failed: %v\n", err)
		return 1, "", "", "", "invalid_api_key"
	}

	// Check expiry (ValidateAPIKey only filters on enabled=1, not expires_at).
	if entry.ExpiresAt != nil && time.Now().After(*entry.ExpiresAt) {
		tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_validate_key: key %s has expired\n", entry.KeyID)
		return 1, "", "", "", "invalid_api_key"
	}

	// Check model allowance when the key restricts which models may be used.
	if len(entry.AllowedModels) > 0 {
		allowed := false
		for _, m := range entry.AllowedModels {
			if m == modelName {
				allowed = true
				break
			}
		}
		if !allowed {
			tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_validate_key: model %q not allowed for key %s\n", modelName, entry.KeyID)
			// return tenantID on deny_403 so the caller can record
			// the metric with the correct tenant label.
			return 2, entry.TenantID, "", "", "model_not_allowed"
		}
	}

	tk.LogIt(tk.LogInfo, "[AIGateway] llb_ai_validate_key: key %s validated for tenant %s\n", entry.KeyID, entry.TenantID)
	return 0, entry.TenantID, entry.KeyID, modelName, ""
}

// cCopyStr safely copies a Go string into a fixed-size C char array.
// At most maxLen-1 bytes are written; the destination is always NUL-terminated.
func cCopyStr(dst *C.char, src string, maxLen int) {
	if src == "" || maxLen <= 0 {
		return
	}
	cs := C.CString(src)
	C.strncpy(dst, cs, C.size_t(maxLen-1))
	C.free(unsafe.Pointer(cs))
}

// llb_ai_validate_key validates the X-API-Key header for an incoming AI Gateway request.
//
// Parameters:
//
//	rawKey    – value from the X-API-Key HTTP header
//	modelName – model name parsed from the request body (empty string if absent)
//	result    – output decision structure filled by this function
//
// Returns 0 when the request is allowed; -1 when it must be rejected.
// The caller must inspect result->decision for the specific HTTP status to return:
//
//	0 – allow
//	1 – deny with 401 (missing/disabled/expired key)
//	2 – deny with 403 (model not allowed)
//
//export llb_ai_validate_key
func llb_ai_validate_key(rawKey *C.char, modelName *C.char, result *C.ai_gw_decision_t) C.int {
	if result == nil {
		tk.LogIt(tk.LogError, "[AIGateway] llb_ai_validate_key: nil result pointer\n")
		return -1
	}

	// Zero out the result struct before writing.
	*result = C.ai_gw_decision_t{}

	// Guard: user service must be initialised before data-plane calls arrive.
	us := mh.UserService
	if us == nil {
		// User service not initialised (userservice not enabled).
		// API key enforcement requires a running user service; without it there
		// are no keys to validate against, so all requests are allowed.
		result.decision = 0
		return 0
	}

	rawKeyStr := C.GoString(rawKey)
	modelNameStr := C.GoString(modelName)

	decision, tenantID, keyID, modelOut, errorCode := validateAPIKeyInternal(us, rawKeyStr, modelNameStr)

	result.decision = C.int(decision)

	if decision == 0 {
		cCopyStr((*C.char)(unsafe.Pointer(&result.tenant_id[0])), tenantID, 128)
		cCopyStr((*C.char)(unsafe.Pointer(&result.key_id[0])), keyID, 64)
		cCopyStr((*C.char)(unsafe.Pointer(&result.model_name[0])), modelOut, 128)
		return 0
	}

	cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), errorCode, 64)
	// record 403 metric directly at the point of denial.
	if decision == 2 {
		prom.RecordModelNotAllowed(tenantID, modelNameStr)
	}
	return -1
}

// globalRL is the singleton RateLimiterStore shared across all CGO rate limit calls.
// It is initialised lazily via globalRLOnce to avoid init-ordering issues.
var (
	globalRL     *rl.RateLimiterStore
	globalRLOnce sync.Once
)

func getGlobalRL() *rl.RateLimiterStore {
	globalRLOnce.Do(func() {
		globalRL = rl.New()
		// -B: register the shared store with the sockproxy HA
		// coordinator so the per-peer push goroutines can call
		// ExportState / ExportDelta on it. NewSockproxySync is the
		// singleton accessor — safe to call before the coordinator is
		// fully bootstrapped because SetRateLimiterStore is an atomic
		// pointer swap. The push goroutines (spawned via
		// StartRateLimiterPushLoop on each peer-add event) sleep on
		// their ticker until rlStore is non-nil, so this registration
		// can happen at any point in the loxilb startup sequence.
		NewSockproxySync().SetRateLimiterStore(globalRL)
	})
	return globalRL
}

// llb_ai_ratelimit_check enforces per-key and per-tenant RPS limits for an
// incoming AI Gateway request.
//
// The check is performed in two stages:
//  1. Per-key: uses the key's own token bucket (burst = rps).
//  2. Per-tenant: uses the tenant's shared token bucket (burst = rps).
//
// The RPS limit is fetched from the control-plane rate-limit config via the
// UserService. If no limit is configured (rps=0) the request is allowed.
//
// Parameters:
//
//	keyID    – the validated API key's key_id string
//	tenantID – the validated API key's tenant_id string
//	result   – output decision structure; decision is set to 3 on denial
//
// Returns 0 when allowed; -1 when rate-limited (result->decision == 3 and
// result->retry_after is set to the recommended retry delay in seconds).
//
//export llb_ai_ratelimit_check
func llb_ai_ratelimit_check(keyID *C.char, tenantID *C.char, result *C.ai_gw_decision_t) C.int {
	if result == nil {
		tk.LogIt(tk.LogError, "[AIGateway] llb_ai_ratelimit_check: nil result pointer\n")
		return -1
	}

	keyIDStr := C.GoString(keyID)
	tenantIDStr := C.GoString(tenantID)

	var svc rateLimitService
	if us := mh.UserService; us != nil {
		svc = us
	}

	store := getGlobalRL()
	decision, retrySecs, errorCode := rateLimitCheckInternal(svc, store, keyIDStr, tenantIDStr)
	if decision != 0 {
		result.decision = C.int(decision)
		result.retry_after = C.int(retrySecs)
		cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), errorCode, 64)
		// record the 429 metric directly at the point of denial.
		// RecordAIRequest is NOT called here — it is for response-complete events.
		prom.RecordRateLimitHit(tenantIDStr, errorCode)
		tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_ratelimit_check: denied key=%s tenant=%s error=%s\n", keyIDStr, tenantIDStr, errorCode)
		return -1
	}

	return 0
}

// llb_ai_token_quota_consume is a retained ABI stub for the C sockproxy call
// site (sockproxy_http.c). The C side does not extract token counts yet — it
// always passes promptTokens=0 and completTokens=0 — so the token metrics and
// the per-minute token quota path built on them were removed (metrics audit
// D3/D4). When real token extraction lands in C (Phase E), token accounting
// and quota enforcement can be rebuilt here on top of real counts.
//
// Returns 0 always; never sets result->decision.
//
//export llb_ai_token_quota_consume
func llb_ai_token_quota_consume(tenantID *C.char, modelName *C.char, promptTokens C.int, completTokens C.int, result *C.ai_gw_decision_t) C.int {
	return 0
}

// llb_ai_ratelimit_update synchronously refreshes the in-memory rate-limit
// buckets for the specified key and/or tenant. Call this from the control plane
// whenever the operator changes the rate-limit configuration so that the data
// plane applies the new limits immediately without waiting for the next check.
//
// Parameters:
//
//	keyID    – the API key's key_id; pass empty string to skip key update
//	tenantID – the tenant ID; pass empty string to skip tenant update
//	rps      – new rate in requests per second (0 removes the limit)
//	burst    – new burst size; if <= 0 defaults to rps
//
// Returns 0 on success.
//
//export llb_ai_ratelimit_update
func llb_ai_ratelimit_update(keyID *C.char, tenantID *C.char, rps C.int, burst C.int) C.int {
	keyIDStr := C.GoString(keyID)
	tenantIDStr := C.GoString(tenantID)
	rpsInt := int(rps)
	burstInt := int(burst)

	store := getGlobalRL()

	if keyIDStr != "" {
		store.UpdateKey(keyIDStr, rpsInt, burstInt)
		tk.LogIt(tk.LogInfo, "[AIGateway] llb_ai_ratelimit_update: key %s rps=%d burst=%d\n", keyIDStr, rpsInt, burstInt)
	}
	if tenantIDStr != "" {
		store.UpdateTenant(tenantIDStr, rpsInt)
		tk.LogIt(tk.LogInfo, "[AIGateway] llb_ai_ratelimit_update: tenant %s rps=%d\n", tenantIDStr, rpsInt)
	}
	return 0
}

// activeSSECounters tracks in-flight SSE streams per model for idempotency.
// Values are *int64 managed via sync/atomic operations stored in the sync.Map.
var activeSSECounters sync.Map

// getSSECounter returns the per-model in-flight counter, creating it on first use.
func getSSECounter(model string) *int64 {
	v, _ := activeSSECounters.LoadOrStore(model, new(int64))
	return v.(*int64)
}

// llb_ai_stream_start records the opening of an SSE stream for Prometheus tracking.
//
// Call once from sockproxy when the Content-Type: text/event-stream response
// header is observed. Increments the loxilb_ai_active_streams gauge and the
// per-model in-flight counter.
//
// Parameters:
//
//	tenantID  – the validated tenant identifier (NUL-terminated)
//	modelName – the effective model name (NUL-terminated)
//
// Returns 0 on success.
//
//export llb_ai_stream_start
func llb_ai_stream_start(tenantID *C.char, modelName *C.char) C.int {
	modelStr := C.GoString(modelName)
	tenantStr := C.GoString(tenantID)

	// Increment per-model in-flight counter unconditionally.
	atomic.AddInt64(getSSECounter(modelStr), 1)

	prom.AdjustActiveStreams(modelStr, 1.0)

	tk.LogIt(tk.LogInfo, "[AIGateway] llb_ai_stream_start: tenant=%s model=%s\n", tenantStr, modelStr)
	return 0
}

// llb_ai_stream_end records the closing of an SSE stream for Prometheus tracking.
//
// Call once from sockproxy when data:[DONE] is observed or the stream is
// terminated. Decrements the loxilb_ai_active_streams gauge only when the
// per-model in-flight counter is > 0, preventing the gauge from going negative.
//
// Parameters:
//
//	tenantID  – the validated tenant identifier (NUL-terminated)
//	modelName – the effective model name (NUL-terminated)
//
// Returns 0 when the gauge was decremented; 1 when the call was spurious.
//
//export llb_ai_stream_end
func llb_ai_stream_end(tenantID *C.char, modelName *C.char) C.int {
	modelStr := C.GoString(modelName)
	tenantStr := C.GoString(tenantID)

	ctr := getSSECounter(modelStr)
	for {
		cur := atomic.LoadInt64(ctr)
		if cur <= 0 {
			tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_stream_end: spurious call for model=%s (count already 0)\n", modelStr)
			return 1
		}
		if atomic.CompareAndSwapInt64(ctr, cur, cur-1) {
			break
		}
	}

	prom.AdjustActiveStreams(modelStr, -1.0)

	tk.LogIt(tk.LogInfo, "[AIGateway] llb_ai_stream_end: tenant=%s model=%s\n", tenantStr, modelStr)
	return 0
}

// llb_ai_record_request records a completed AI Gateway request for Prometheus metrics.
//
// C sockproxy calls this once on response completion. It translates C types to
// Go and delegates to prom.RecordAIRequest (request counter + latency
// histogram). The token, stream-lifecycle, and errorCode parameters are kept
// for C ABI compatibility but are unused: token metrics were removed (metrics
// audit D3), stream lifecycle is tracked by llb_ai_stream_start/_end, and
// 429/403 denials are recorded at the point of denial.
//
// Parameters:
//
//	tenantID:   tenant identifier from the validated API key (NUL-terminated)
//	modelName:  effective model name extracted from X-Model header or JSON body
//	statusCode: HTTP response status code (200, 401, 403, 429, 500, …)
//	latencyMs:  request latency in milliseconds; 0 when unknown
//
//export llb_ai_record_request
func llb_ai_record_request(tenantID *C.char, modelName *C.char, statusCode C.int, latencyMs C.int64_t, promptTokens C.int, completTokens C.int, streamStart C.int, streamEnd C.int, errorCode *C.char) {
	tenantIDStr := C.GoString(tenantID)
	modelNameStr := C.GoString(modelName)

	prom.RecordAIRequest(tenantIDStr, modelNameStr, int(statusCode), int64(latencyMs))
}

// llb_ai_pd_record records a P/D disaggregation lifecycle event for Prometheus metrics.
//
// C sockproxy calls this at P/D completion (success or error). It translates
// C types to Go and delegates to prom.RecordPDRequest.
//
// Parameters:
//
//	modelName:        effective model name (NUL-terminated)
//	prefillLatencyMs: prefill phase duration in milliseconds; 0 when unknown
//	decodeLatencyMs:  decode phase TTFT in milliseconds; 0 when unknown
//	kvParamsFound:    1 when kv_transfer_params was found, 0 otherwise
//	errorPhase:       0=success, 1=prefill_timeout, 2=decode_error
//
//export llb_ai_pd_record
func llb_ai_pd_record(modelName *C.char, prefillLatencyMs C.int64_t, decodeLatencyMs C.int64_t, kvParamsFound C.int, errorPhase C.int) {
	modelNameStr := C.GoString(modelName)
	prom.RecordPDRequest(modelNameStr, int64(prefillLatencyMs), int64(decodeLatencyMs), int(kvParamsFound), int(errorPhase))
}

// llb_ai_pd_session_hit records a P/D Tier-0 session-stickiness cache hit.
//
// C sockproxy calls this when pd_select_prefill finds the request in the
// session map, pinning it to a previously used prefill/decode EP pair.
//
//export llb_ai_pd_session_hit
func llb_ai_pd_session_hit(modelName *C.char) {
	modelNameStr := C.GoString(modelName)
	prom.RecordPDSessionHit(modelNameStr)
}

// llb_ai_normal_session_hit records a normal-mode session-stickiness cache hit.
//
// C sockproxy calls this when PRIORITY 0 (learned conv_map lookup) succeeds in
// PROXY_SEL_STICKY mode, pinning a returning conversation to the same backend EP.
//
//export llb_ai_normal_session_hit
func llb_ai_normal_session_hit(modelName *C.char) {
	modelNameStr := C.GoString(modelName)
	prom.RecordNormalSessionHit(modelNameStr)
}
