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
// decision values: 0=allow, 1=deny_401, 2=deny_403, 3=deny_429, 4=deny_503
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
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	tk "github.com/loxilb-io/loxilib"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	cmn "github.com/loxilb-io/loxilb/common"
	rl "github.com/loxilb-io/loxilb/pkg/ratelimit"
)

// apiKeyValidator is the subset of the data-plane key store used by the AI
// Gateway bridge. It is satisfied by *aikey.Service and by test mocks.
type apiKeyValidator interface {
	ValidateAPIKey(rawKey string) (*cmn.ApiKeyEntry, error)
}

// rateLimitService is the subset of the data-plane key store used by the
// rate-limit bridge. It is satisfied by *aikey.Service and by test mocks.
type rateLimitService interface {
	GetTenantRateLimit(tenantID string) (rps, tokensPerMin, burstPct int)
	GetTenantModelRateLimit(tenantID, model string) (tokensPerMin int)
	GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error)
}

// noKeyStoreOnce keeps the "no key store configured" notice to one line per
// process. The condition is per-gateway configuration, not per-request, so
// repeating it once per admitted request would bury the log it belongs in.
var noKeyStoreOnce sync.Once

// modelQuotaKey is the composite quota-map key for a tenant's per-model
// token bucket. The "|" delimiter matches the sync layer's "tm:" wire-scope
// convention (rl.QuotaWireKey); tenant and model names containing "|" are
// rejected at config time so the key can never alias another pair.
func modelQuotaKey(tenantID, model string) string {
	return tenantID + "|" + model
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
//   - "token_quota_warming"   – quota state cold after restart; peer warm-up
//     still inside its bounded deadline
//   - "token_quota_exceeded"  – tenant aggregate or tenant|model token bucket
//     in debt
func rateLimitCheckInternal(svc rateLimitService, store *rl.RateLimiterStore, keyIDStr, tenantIDStr, modelName string) (decision, retrySecs int, errorCode string) {
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
		tenantTPM := 0
		if svc != nil {
			tenantRPS, tenantTPM, _ = svc.GetTenantRateLimit(tenantIDStr)
		}
		allowed, retrySec := store.CheckTenant(tenantIDStr, tenantRPS)
		if !allowed {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: tenant %s rate-limited (retry %ds)\n", tenantIDStr, retrySec)
			return 3, retrySec, "tenant_quota_exceeded"
		}

		// Stage 3: token quota checks — only meaningful for tenants that
		// HAVE a token quota configured, at the aggregate level or for the
		// request's model.
		modelTPM := 0
		if svc != nil && modelName != "" {
			modelTPM = svc.GetTenantModelRateLimit(tenantIDStr, modelName)
		}

		// Warming gate first: after a cold start the consumed counters are
		// empty until a peer re-teaches them, so neither the debt check
		// nor a pre-admission reservation can be decided truthfully yet.
		// Deny with a short retry for the bounded warmup window rather than
		// silently admitting against a zeroed quota.
		if (tenantTPM > 0 || modelTPM > 0) && store.QuotaWarming() {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: tenant %s denied during token-quota warmup\n", tenantIDStr)
			return 3, 1, "token_quota_warming"
		}
		if store.IsTokenQuotaExceeded(tenantIDStr) {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: tenant %s token quota exceeded\n", tenantIDStr)
			return 3, 60, "token_quota_exceeded"
		}
		if modelTPM > 0 && store.IsTokenQuotaExceeded(modelQuotaKey(tenantIDStr, modelName)) {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: tenant %s model %s token quota exceeded\n", tenantIDStr, modelName)
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
//	decision   – 0=allow, 1=deny_401, 2=deny_403, 3=deny_429, 4=deny_503
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

// cgoRecover logs and absorbs a panic at a CGO export boundary. A Go panic
// unwinding into the C sockproxy thread aborts the whole process, so every
// //export below defers either this or a fail-closed variant of it.
func cgoRecover(fn string) {
	if r := recover(); r != nil {
		tk.LogIt(tk.LogCritical, "[AIGateway] %s: recovered panic: %v\n", fn, r)
	}
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
//	3 – deny with 429 (rate limit or token quota; retry_after set)
//	4 – deny with 503 (policy store unavailable — the policy requires a key
//	    and the store cannot answer; distinct from 401 on purpose)
//
//export llb_ai_validate_key
func llb_ai_validate_key(rawKey *C.char, modelName *C.char, result *C.ai_gw_decision_t) (ret C.int) {
	// Fail closed on panic: deny with 401 rather than crashing the datapath.
	defer func() {
		if r := recover(); r != nil {
			tk.LogIt(tk.LogCritical, "[AIGateway] llb_ai_validate_key: recovered panic: %v\n", r)
			if result != nil {
				result.decision = 1
				cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), "internal_error", 64)
			}
			ret = -1
		}
	}()
	if result == nil {
		tk.LogIt(tk.LogError, "[AIGateway] llb_ai_validate_key: nil result pointer\n")
		return -1
	}

	// Zero out the result struct before writing.
	*result = C.ai_gw_decision_t{}

	// Guard: the key store must exist before data-plane calls arrive.
	us := mh.AIKeyService
	if us == nil {
		// Reaching here now MEANS something specific. The data-plane gate only
		// calls this function when the service's api_key_auth policy is
		// "required", so a nil store is not "nobody asked for auth" — it is
		// "the operator asked for auth and the store cannot answer".
		//
		// That is a policy-store outage, and it fails CLOSED. Admitting the
		// request would serve unauthenticated traffic on a service explicitly
		// configured to require a credential, which is the one outcome the
		// policy exists to prevent.
		//
		// It is deliberately NOT a 401. A client must be able to tell "your
		// key is wrong" from "the gateway cannot tell right now": the first is
		// the client's problem and permanent, the second is the operator's and
		// transient, and a client that retries is right in the second case and
		// wrong in the first.
		noKeyStoreOnce.Do(func() {
			tk.LogIt(tk.LogCritical,
				"[AIGateway] No API-key store configured (--aikey-db-host unset): services with api_key_auth=required are refusing requests with 503\n")
		})
		prom.RecordPolicyStoreUnavailable()
		result.decision = 4
		cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), "policy_store_unavailable", 64)
		return -1
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

// quotaWarmupTimeout resolves the cold-start warm-from-peers deadline from
// the LLB_AI_QUOTA_WARMUP_MS environment knob (0 disables the bounded wait).
func quotaWarmupTimeout() time.Duration {
	const defaultWarmupMs = 3000
	ms := defaultWarmupMs
	if v := os.Getenv("LLB_AI_QUOTA_WARMUP_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ms = n
		}
	}
	return time.Duration(ms) * time.Millisecond
}

func getGlobalRL() *rl.RateLimiterStore {
	globalRLOnce.Do(func() {
		globalRL = rl.New()
		// Cold-start posture (design decision: warm from peers with a
		// bounded timeout, then fail-open — never silently). The store
		// starts empty on every process start; with sync peers configured
		// we hold quota-limited admissions until the first peer batch
		// re-teaches the counters or the deadline passes. Without peers
		// (single-node edge) there is nothing to warm from: serve
		// immediately, but mark the cold fail-open window with the metric.
		// Must run BEFORE SetRateLimiterStore — a peer batch that landed
		// between registration and a later warmup arm would have its
		// warm signal dropped.
		warmup := quotaWarmupTimeout()
		if warmup > 0 && mh.dp != nil && len(mh.dp.Peers) > 0 {
			tk.LogIt(tk.LogInfo, "[AIGateway] token-quota cold-start: warming from peers (deadline %v)\n", warmup)
			globalRL.StartQuotaWarmup(warmup, func(failOpen bool) {
				if failOpen {
					prom.RecordTokenQuotaColdOpen()
					tk.LogIt(tk.LogWarning, "[AIGateway] token-quota cold-start fail-open: no peer state within %v\n", warmup)
					return
				}
				tk.LogIt(tk.LogInfo, "[AIGateway] token-quota cold-start: warmed from peer state\n")
			})
		} else {
			prom.RecordTokenQuotaColdOpen()
			tk.LogIt(tk.LogWarning, "[AIGateway] token-quota cold-start fail-open: cold quota state (no sync peers or warmup disabled)\n")
		}
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
		// Back the scrape-time token-quota utilization/limit series with
		// the shared store. Registered here (not init) so the collector
		// can never observe a nil store.
		prom.RegisterTokenQuotaSource(func() []prom.TokenQuotaState {
			usages := globalRL.TokenQuotaSnapshot()
			out := make([]prom.TokenQuotaState, 0, len(usages))
			for _, u := range usages {
				// Composite tenant|model keys carry the per-model buckets;
				// split them so the collector can export them on the
				// model-labelled series instead of mangling the tenant label.
				tenant, model := u.TenantID, ""
				if i := strings.IndexByte(u.TenantID, '|'); i >= 0 {
					tenant, model = u.TenantID[:i], u.TenantID[i+1:]
				}
				out = append(out, prom.TokenQuotaState{
					Tenant:   tenant,
					Model:    model,
					Consumed: u.Consumed,
					Limit:    u.Limit,
				})
			}
			return out
		})
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
// key store. If no limit is configured (rps=0) the request is allowed.
//
// Parameters:
//
//	keyID    – the validated API key's key_id string
//	tenantID – the validated API key's tenant_id string
//	model    – the request's body-bound model name (may be empty); selects
//	           the tenant|model token bucket for the stage-3 debt check
//	result   – output decision structure; decision is set to 3 on denial
//
// Returns 0 when allowed; -1 when rate-limited (result->decision == 3 and
// result->retry_after is set to the recommended retry delay in seconds).
//
//export llb_ai_ratelimit_check
func llb_ai_ratelimit_check(keyID *C.char, tenantID *C.char, model *C.char, result *C.ai_gw_decision_t) (ret C.int) {
	// Fail closed on panic: deny with a short retry rather than crashing the
	// datapath or silently disabling the limiter.
	defer func() {
		if r := recover(); r != nil {
			tk.LogIt(tk.LogCritical, "[AIGateway] llb_ai_ratelimit_check: recovered panic: %v\n", r)
			if result != nil {
				result.decision = 3
				result.retry_after = 1
				cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), "internal_error", 64)
			}
			ret = -1
		}
	}()
	if result == nil {
		tk.LogIt(tk.LogError, "[AIGateway] llb_ai_ratelimit_check: nil result pointer\n")
		return -1
	}

	keyIDStr := C.GoString(keyID)
	tenantIDStr := C.GoString(tenantID)
	modelStr := C.GoString(model)

	var svc rateLimitService
	if us := mh.AIKeyService; us != nil {
		svc = us
	}

	store := getGlobalRL()
	decision, retrySecs, errorCode := rateLimitCheckInternal(svc, store, keyIDStr, tenantIDStr, modelStr)
	if decision != 0 {
		result.decision = C.int(decision)
		result.retry_after = C.int(retrySecs)
		cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), errorCode, 64)
		// record the 429 metric directly at the point of denial.
		// RecordAIRequest is NOT called here — it is for response-complete events.
		prom.RecordRateLimitHit(tenantIDStr, errorCode)
		if errorCode == "token_quota_exceeded" {
			prom.RecordTokenQuotaDenied(tenantIDStr)
		}
		tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_ratelimit_check: denied key=%s tenant=%s error=%s\n", keyIDStr, tenantIDStr, errorCode)
		return -1
	}

	return 0
}

// tokenQuotaReserveInternal is the pure-Go pre-admission logic, separated
// from the CGO export so that unit tests can exercise it without C types.
// It claims want tokens (the request's prompt estimate + declared max_tokens
// ceiling) against the tenant's aggregate per-minute quota AND, when one is
// configured, the tenant|model quota — both must admit, so a model with a
// tight budget cannot ride the tenant's generous ceiling. A claim admitted
// by the first bucket is rolled back when the second denies: a half-held
// reservation would leak headroom until the epoch expires it.
//
// Returns (allowed, retrySecs, resEpoch). resEpoch tags the reservation's
// epoch and must travel with the request to settlement; 0 means nothing was
// reserved (no quota configured) and settlement is a plain charge. Both
// buckets share one epoch tag: reservations are taken back-to-back, so they
// land in the same minute except across a boundary race, where the stale
// tag makes settlement skip a release the epoch advance already performed —
// the standard orphan self-heal.
func tokenQuotaReserveInternal(svc rateLimitService, store *rl.RateLimiterStore, tenantID, modelName string, want int) (allowed bool, retrySecs int, resEpoch int64) {
	if want <= 0 || tenantID == "" {
		return true, 0, 0
	}
	tenantTPM := 0
	modelTPM := 0
	// burstPct is the tenant's bucket-capacity override. The per-model bucket
	// deliberately shares it: it is a property of how bursty the TENANT is
	// allowed to be, and giving a model bucket its own capacity would let a
	// tenant widen its aggregate burst by splitting spend across models.
	burstPct := 0
	if svc != nil {
		_, tenantTPM, burstPct = svc.GetTenantRateLimit(tenantID)
		if modelName != "" {
			modelTPM = svc.GetTenantModelRateLimit(tenantID, modelName)
		}
	}
	if tenantTPM <= 0 && modelTPM <= 0 {
		return true, 0, 0
	}

	allowed, retrySecs, resEpoch = store.ReserveTokens(tenantID, want, tenantTPM, burstPct)
	if !allowed {
		return false, retrySecs, 0
	}
	if modelTPM > 0 {
		mAllowed, mRetry, mEpoch := store.ReserveTokens(modelQuotaKey(tenantID, modelName), want, modelTPM, burstPct)
		if !mAllowed {
			// Give the aggregate claim back (epoch-tagged, clamped release;
			// nothing charged).
			if resEpoch != 0 {
				store.SettleTokens(tenantID, 0, want, resEpoch, tenantTPM, burstPct)
			}
			return false, mRetry, 0
		}
		if resEpoch == 0 {
			resEpoch = mEpoch
		}
	}
	return true, 0, resEpoch
}

// tokenQuotaConsumeInternal is the pure-Go token accounting logic, separated
// from the CGO export so that unit tests can exercise it without C types.
// It settles the request's admission-time reservation (reservedAmt tagged
// with resEpoch; 0/0 when none was made) and charges count tokens against
// the tenant's per-minute quota (tokens_per_min from the tenant's rate-limit
// config; 0 = unlimited).
//
// The reservation must be released even when the response produced no
// countable tokens (count 0) or the quota config was removed mid-flight —
// an unreleased claim denies the tenant's admissions until the epoch
// expires it. Settlement mirrors reservation's dual-bucket shape: the
// charge lands on the tenant aggregate AND, when configured, the
// tenant|model bucket, and the claim is released from both.
//
// Returns (allowed, retrySecs). allowed=false means the charge put either
// bucket into debt: the NEXT request's rateLimitCheckInternal stage 3
// returns deny_429 ("token_quota_exceeded") — the already-served response
// is never affected.
func tokenQuotaConsumeInternal(svc rateLimitService, store *rl.RateLimiterStore, tenantID, modelName string, count, reservedAmt int, resEpoch int64) (allowed bool, retrySecs int) {
	if tenantID == "" {
		return true, 0
	}
	tenantTPM := 0
	modelTPM := 0
	burstPct := 0
	if svc != nil {
		_, tenantTPM, burstPct = svc.GetTenantRateLimit(tenantID)
		if modelName != "" {
			modelTPM = svc.GetTenantModelRateLimit(tenantID, modelName)
		}
	}
	if reservedAmt <= 0 && (count <= 0 || (tenantTPM <= 0 && modelTPM <= 0)) {
		return true, 0
	}
	allowed, retrySecs = store.SettleTokens(tenantID, count, reservedAmt, resEpoch, tenantTPM, burstPct)
	if modelTPM > 0 {
		mAllowed, mRetry := store.SettleTokens(modelQuotaKey(tenantID, modelName), count, reservedAmt, resEpoch, modelTPM, burstPct)
		if !mAllowed {
			allowed = false
			retrySecs = max(retrySecs, mRetry)
		}
	}
	return allowed, retrySecs
}

// llb_ai_token_quota_reserve claims a request's worst-case token spend
// (prompt estimate + declared max_tokens ceiling) against the tenant's
// per-minute quota at the admission gate, BEFORE the request is dispatched
// to a backend — an over-quota request is denied as a cheap 429 instead of
// burning GPU prefill and then tripping the post-hoc latch.
//
// The C caller stashes *resEpoch and the reserved amount on the connection
// and echoes them to llb_ai_token_quota_consume, which releases the claim
// and replaces it with the real extracted charge. A denial does NOT latch
// the tenant's exceeded flag: it is sized to THIS request, and a smaller
// request may still fit the window.
//
// Returns 0 when admitted (*resEpoch tags the reservation window; 0 = no
// quota configured, nothing reserved). Returns -1 on denial with
// result->decision=3, retry_after set and error_code
// "token_quota_would_exceed" — distinguishable from the post-hoc
// "token_quota_exceeded" so operators (and the acceptance harness) can tell
// a pre-admission deny from a latched one.
//
//export llb_ai_token_quota_reserve
func llb_ai_token_quota_reserve(tenantID *C.char, modelName *C.char, promptEst C.int, maxTokens C.int, resEpoch *C.longlong, result *C.ai_gw_decision_t) (ret C.int) {
	// Fail closed on panic, matching the other gate decisions: deny with a
	// short retry rather than crashing the datapath or silently admitting.
	defer func() {
		if r := recover(); r != nil {
			tk.LogIt(tk.LogCritical, "[AIGateway] llb_ai_token_quota_reserve: recovered panic: %v\n", r)
			if result != nil {
				result.decision = 3
				result.retry_after = 1
				cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), "internal_error", 64)
			}
			ret = -1
		}
	}()

	if resEpoch != nil {
		*resEpoch = 0
	}

	tenant := C.GoString(tenantID)
	want := 0
	if promptEst > 0 {
		want += int(promptEst)
	}
	if maxTokens > 0 {
		want += int(maxTokens)
	}
	if tenant == "" || want <= 0 {
		return 0
	}

	var svc rateLimitService
	if us := mh.AIKeyService; us != nil {
		svc = us
	}

	store := getGlobalRL()
	allowed, retrySecs, epoch := tokenQuotaReserveInternal(svc, store, tenant, C.GoString(modelName), want)
	if !allowed {
		if result != nil {
			result.decision = 3
			result.retry_after = C.int(retrySecs)
			cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), "token_quota_would_exceed", 64)
		}
		prom.RecordRateLimitHit(tenant, "token_quota_would_exceed")
		prom.RecordTokenQuotaDenied(tenant)
		tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_token_quota_reserve: tenant %s denied pre-admission (want %d, model %s)\n",
			tenant, want, C.GoString(modelName))
		return -1
	}
	if resEpoch != nil {
		*resEpoch = C.longlong(epoch)
	}
	return 0
}

// llb_ai_token_quota_consume charges a completed response's token usage
// (extracted by the C sockproxy from the final SSE chunk or the JSON body)
// against the tenant's per-minute token quota.
//
// The C caller invokes this at response completion with result=NULL: the
// served response is never interrupted. When the charge exceeds
// tokens_per_min the quota's exceeded flag latches and the NEXT request is
// denied 429 at the rate-limit gate.
//
// This is also the feed for the token-accounting Prometheus series
// (loxilb_ai_tokens_consumed_total and friends): the counts recorded there
// are exactly the counts charged, which the response-complete recorder
// cannot guarantee (its non-streaming leg misses usage objects that arrive
// after the response headers' segment).
//
// estimated=1 marks counts from the data plane's estimate net (request-size
// prompt estimate + SSE chunk count; no usage object materialized): the
// charge proceeds identically but the tokens also feed the
// loxilb_ai_tokens_estimated_total / loxilb_ai_tokens_missing_total split so
// estimated accounting stays distinguishable from exact.
//
// reservedToks/resEpoch echo the request's admission-time reservation
// (llb_ai_token_quota_reserve) so settlement can credit the pessimistic
// prompt+max_tokens claim back and replace it with the real charge; pass
// 0/0 when no reservation was made.
//
//export llb_ai_token_quota_consume
func llb_ai_token_quota_consume(tenantID *C.char, modelName *C.char, promptTokens C.int, completTokens C.int, estimated C.int, reservedToks C.int, resEpoch C.longlong, result *C.ai_gw_decision_t) (ret C.int) {
	// Fail-open on panic: the response is already served, so accounting must
	// never take down the datapath — the quota simply misses this response.
	defer func() {
		if r := recover(); r != nil {
			tk.LogIt(tk.LogCritical, "[AIGateway] llb_ai_token_quota_consume: recovered panic: %v\n", r)
			ret = 0
		}
	}()

	count := int(promptTokens) + int(completTokens)
	tenant := C.GoString(tenantID)
	// A zero count no longer short-circuits when a reservation rides along:
	// the claim must be released even for an uncounted response, or the
	// tenant's admissions stay blocked until the window rolls over.
	if tenant == "" || (count <= 0 && reservedToks <= 0) {
		return 0
	}

	if count > 0 {
		prom.RecordTokenUsage(C.GoString(modelName), tenant, int(promptTokens),
			int(completTokens), estimated != 0)
	}

	var svc rateLimitService
	if us := mh.AIKeyService; us != nil {
		svc = us
	}

	store := getGlobalRL()
	allowed, retrySecs := tokenQuotaConsumeInternal(svc, store, tenant, C.GoString(modelName), count,
		int(reservedToks), int64(resEpoch))
	if !allowed {
		if result != nil {
			result.decision = 3
			result.retry_after = C.int(retrySecs)
			cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), "token_quota_exceeded", 64)
		}
		tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_token_quota_consume: tenant %s over token quota (charged %d, model %s)\n",
			tenant, count, C.GoString(modelName))
		return -1
	}
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
	defer cgoRecover("llb_ai_ratelimit_update")
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
	defer cgoRecover("llb_ai_stream_start")
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
	defer cgoRecover("llb_ai_stream_end")
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
// for C ABI compatibility but are unused: token series are fed from
// llb_ai_token_quota_consume (whose counts always match the charge — the
// counts passed here can lag on split non-streaming bodies), stream lifecycle
// is tracked by llb_ai_stream_start/_end, and 429/403 denials are recorded at
// the point of denial.
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
	defer cgoRecover("llb_ai_record_request")
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
	defer cgoRecover("llb_ai_pd_record")
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
	defer cgoRecover("llb_ai_pd_session_hit")
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
	defer cgoRecover("llb_ai_normal_session_hit")
	modelNameStr := C.GoString(modelName)
	prom.RecordNormalSessionHit(modelNameStr)
}

// llb_ai_record_unmetered records an AI request that was admitted without any
// X-Api-Key validation, because the service's api_key_auth policy resolved to
// "disabled".
//
// C sockproxy calls this from the gate on connections with ai_gw_mode=1 and
// apikey_auth=0 — AI traffic that is accounted for streaming purposes but is
// neither authenticated nor attributable to a tenant. Keyed by VIP because
// that is the identity the operator configured the policy on; there is no
// tenant to key it by, which is precisely the condition being reported.
//
//export llb_ai_record_unmetered
func llb_ai_record_unmetered(vip *C.char) {
	defer cgoRecover("llb_ai_record_unmetered")
	prom.RecordUnmeteredRequest(C.GoString(vip))
}
