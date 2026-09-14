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
    char user_id[128];
    int  auth_flags;
} ai_gw_decision_t;
*/
import "C"

import (
	"errors"
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
	"github.com/loxilb-io/loxilb/pkg/aikey"
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
	// Both quota reads answer from cache, then the store, then the last
	// store-confirmed value during an outage. A non-nil error means none of
	// those exist — the zeroes are not "unlimited" and the admission path
	// must fail closed on them.
	GetTenantRateLimit(tenantID string) (rps, tokensPerMin, burstPct int, err error)
	GetTenantModelRateLimit(tenantID, model string) (tokensPerMin int, err error)
	GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error)
	// The ladder reads (level 1 explicit user rows, level 3 defaults) carry
	// the same cache/outage/error contract as the tenant reads above.
	GetUserRateLimit(tenantID, userID string) (rps, burstSize, tokensPerMin int, err error)
	GetUserModelRateLimit(tenantID, userID, model string) (tokensPerMin int, err error)
	GetRateLimitDefaults(scope, ruleIdent string) (entry cmn.RateLimitDefaultsEntry, exists bool, err error)
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

// qosDefaults is the field-wise merge of the rule-scope defaults row over
// the global one (QoS ladder level 3): a zero field in the rule row falls
// through to the global row's field, and a zero there falls through to
// unlimited: zero is the sentinel for "no bound", per dimension.
type qosDefaults struct {
	userRPS, userTPM     int
	tenantRPS, tenantTPM int
	vipRPS, vipTPM       int
}

// resolveQoSDefaults reads the level-3 rows for a request. A store error
// (unreachable AND never answered) propagates so the caller can pick the
// posture: fail closed for identity-bearing traffic, fail open for keyless
// traffic whose bucket is opt-in.
func resolveQoSDefaults(svc rateLimitService, svcIdent string) (qosDefaults, error) {
	var d qosDefaults
	if svc == nil {
		return d, nil
	}
	g, gOK, gErr := svc.GetRateLimitDefaults(cmn.RateLimitScopeGlobal, "")
	if gErr != nil {
		return d, gErr
	}
	if gOK {
		d = qosDefaults{
			userRPS: g.DefaultUserRPS, userTPM: g.DefaultUserTPM,
			tenantRPS: g.DefaultTenantRPS, tenantTPM: g.DefaultTenantTPM,
			vipRPS: g.VipSharedRPS, vipTPM: g.VipSharedTPM,
		}
	}
	if svcIdent == "" {
		return d, nil
	}
	r, rOK, rErr := svc.GetRateLimitDefaults(cmn.RateLimitScopeRule, svcIdent)
	if rErr != nil {
		return d, rErr
	}
	if rOK {
		override := func(dst *int, v int) {
			if v > 0 {
				*dst = v
			}
		}
		override(&d.userRPS, r.DefaultUserRPS)
		override(&d.userTPM, r.DefaultUserTPM)
		override(&d.tenantRPS, r.DefaultTenantRPS)
		override(&d.tenantTPM, r.DefaultTenantTPM)
		override(&d.vipRPS, r.VipSharedRPS)
		override(&d.vipTPM, r.VipSharedTPM)
	}
	return d, nil
}

// rateLimitCheckInternal is the pure-Go rate limit logic, separated from the
// CGO export so that unit tests can exercise it without going through C types.
//
// The QoS ladder resolves each dimension's limit as: explicit row
// → configured default (rule scope over global) → unlimited; a zero field
// falls through, so an operator states only what they mean to bound. The
// enforcement stages then run most-specific first — key RPS, key TPM latch,
// user RPS, user TPM latches, tenant RPS, tenant TPM latches — and every
// bucket must admit: a user inside its own budget is still stopped by its
// tenant's ceiling, which is what makes the tenant limit a cap on the SUM
// of its users. Keyless requests (no key, no tenant, no user) consult only
// the opt-in per-VIP shared bucket, and only when svcIdent names the
// service.
//
// userID and svcIdent arrive empty from data planes that pre-date the
// identity-forwarding ABI (the CGO exports pass what the C caller gives
// them); every user/VIP stage degrades to a no-op then, and the ladder is
// exercised end-to-end by the unit corpus until the ABI lands.
//
// Returns (decision, retrySecs, errorCode):
//   - decision 0 = allow
//   - decision 3 = deny_429 (rate limited)
//   - decision 4 = deny_503 (limits unknowable — the store's outage)
//
// error codes:
//   - "rate_limit_exceeded"       – per-key token bucket denied
//   - "user_rate_limit_exceeded"  – per-user token bucket denied
//   - "tenant_quota_exceeded"     – per-tenant token bucket denied
//   - "token_quota_warming"       – quota state cold after restart; peer
//     warm-up still inside its bounded deadline
//   - "token_quota_exceeded"      – a token bucket (key, user, user|model,
//     tenant, tenant|model or VIP) in debt
func rateLimitCheckInternal(svc rateLimitService, store *rl.RateLimiterStore, keyIDStr, tenantIDStr, userIDStr, svcIdent, modelName string) (decision, retrySecs int, errorCode string) {
	// A keyed identity with no service behind it is an invariant violation,
	// not a configuration: the gate only calls this stage with a key_id or
	// tenant_id it got from a SUCCESSFUL validation, and validation cannot
	// succeed without a service. If the identity is real and the service is
	// gone anyway, every limit below would read as zero — "no limit
	// configured" — and the whole QoS plane would silently switch off for
	// exactly the traffic it was configured to bound. Fail closed
	// with the store's own error code; the C arm maps decision 4 to a 503.
	//
	// An EMPTY identity with a nil service is different and stays allowed:
	// that is ordinary traffic on a service whose policy does not attribute
	// tenants, and there is nothing to enforce against.
	if svc == nil && (keyIDStr != "" || tenantIDStr != "" || userIDStr != "") {
		tk.LogIt(tk.LogCritical,
			"[AIGateway] rateLimitCheckInternal: keyed identity (key=%s tenant=%s user=%s) with NO key service — failing closed\n",
			keyIDStr, tenantIDStr, userIDStr)
		return 4, 5, "policy_store_unavailable"
	}

	// Keyless traffic: no credential decided, so there is no identity to
	// enforce against — except the opt-in per-VIP shared bucket, when the
	// defaults name one for this service. An unknowable defaults row fails
	// OPEN here, alone among the arms: the bucket is opt-in, and giving
	// none-mode services a brand-new outage mode for a feature they may
	// never have enabled would be the wrong side of that trade. (Every
	// identity-bearing arm below still fails closed.)
	if keyIDStr == "" && tenantIDStr == "" && userIDStr == "" {
		if svcIdent == "" || svc == nil {
			return 0, 0, ""
		}
		d, dErr := resolveQoSDefaults(svc, svcIdent)
		if dErr != nil {
			tk.LogIt(tk.LogWarning,
				"[AIGateway] rateLimitCheckInternal: keyless defaults for %s unknowable — shared bucket skipped (opt-in, fail-open)\n",
				svcIdent)
			return 0, 0, ""
		}
		if d.vipRPS > 0 {
			if allowed, retrySec := store.CheckVipShared(svcIdent, d.vipRPS); !allowed {
				tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: service %s keyless bucket rate-limited (retry %ds)\n", svcIdent, retrySec)
				return 3, retrySec, "rate_limit_exceeded"
			}
		}
		// The token side of the shared bucket. The latch reads debt that
		// SETTLES put there: attributed traffic sharing the service charges
		// it, and the data plane settles keyless responses into the same
		// bucket through the service-only consume path — exact usage, no
		// pre-admission reservation, so the bound is enforced by denying
		// the NEXT keyless admission once spend crosses it (H1 and H2
		// relays both meter keyless).
		if d.vipTPM > 0 {
			if store.QuotaWarming() {
				return 3, 1, "token_quota_warming"
			}
			if store.IsTokenQuotaExceeded(rl.VipSharedQuotaKey(svcIdent)) {
				tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: service %s keyless bucket token quota exceeded\n", svcIdent)
				return 3, 60, "token_quota_exceeded"
			}
		}
		return 0, 0, ""
	}

	// Level-3 defaults for the identity-bearing arms. Unknowable defaults
	// fail closed exactly as an unknowable tenant row does: the identities
	// are real, and admitting on zeroes would switch off the very limits an
	// operator configured a default to guarantee.
	defaults, dErr := resolveQoSDefaults(svc, svcIdent)
	if dErr != nil {
		tk.LogIt(tk.LogWarning,
			"[AIGateway] rateLimitCheckInternal: rate-limit defaults unknowable (store outage, nothing cached) — failing closed\n")
		return 4, 5, "policy_store_unavailable"
	}

	// Stage 1: per-key RPS with key-specific burst, then the key's own
	// tokens-per-min debt latch (ladder level 1.5 — the field was stored
	// and never enforced; now it is a bucket like every other).
	keyTPM := 0
	if keyIDStr != "" {
		keyRPS := 0
		keyBurst := 0
		if svc != nil {
			if key, err := svc.GetAPIKeyByID(keyIDStr); err == nil {
				keyRPS = key.RateLimitRPS
				keyBurst = key.BurstSize
				keyTPM = key.TokensPerMin
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

	// Stage 1.7: per-user RPS. The limit is the ladder's: the explicit user
	// row's rps, else the configured default-user rps, else nothing.
	userTPM := 0
	if userIDStr != "" && tenantIDStr != "" {
		userRPS, userBurst := 0, 0
		if svc != nil {
			r, b, t, uErr := svc.GetUserRateLimit(tenantIDStr, userIDStr)
			if uErr != nil {
				tk.LogIt(tk.LogWarning,
					"[AIGateway] rateLimitCheckInternal: user %s/%s limits unknowable (store outage, nothing cached) — failing closed\n",
					tenantIDStr, userIDStr)
				return 4, 5, "policy_store_unavailable"
			}
			userRPS, userBurst, userTPM = r, b, t
		}
		if userRPS <= 0 {
			userRPS = defaults.userRPS
			userBurst = 0
		}
		if userTPM <= 0 {
			userTPM = defaults.userTPM
		}
		allowed, retrySec := store.CheckUser(tenantIDStr, userIDStr, userRPS, userBurst)
		if !allowed {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: user %s/%s rate-limited (retry %ds)\n", tenantIDStr, userIDStr, retrySec)
			return 3, retrySec, "user_rate_limit_exceeded"
		}
	}

	// Stage 2: per-tenant RPS — explicit row, else the default-tenant rps.
	// The tenant bucket runs for EVERY attributed request, which is what
	// makes it a cap on the sum of the tenant's users and keys.
	if tenantIDStr != "" {
		tenantRPS := 0
		tenantTPM := 0
		if svc != nil {
			var rlErr error
			tenantRPS, tenantTPM, _, rlErr = svc.GetTenantRateLimit(tenantIDStr)
			if rlErr != nil {
				// The store is unreachable and has never answered for this
				// tenant: admitting on the zeroes would run the request with
				// every quota off. Same decision as the nil-service guard —
				// the outage's own code, not a "slow down".
				tk.LogIt(tk.LogWarning,
					"[AIGateway] rateLimitCheckInternal: tenant %s limits unknowable (store outage, nothing cached) — failing closed\n",
					tenantIDStr)
				return 4, 5, "policy_store_unavailable"
			}
		}
		if tenantRPS <= 0 {
			tenantRPS = defaults.tenantRPS
		}
		if tenantTPM <= 0 {
			tenantTPM = defaults.tenantTPM
		}
		allowed, retrySec := store.CheckTenant(tenantIDStr, tenantRPS)
		if !allowed {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: tenant %s rate-limited (retry %ds)\n", tenantIDStr, retrySec)
			return 3, retrySec, "tenant_quota_exceeded"
		}

		// Stage 3: token-quota debt latches. Every bucket the settle path
		// charges is consulted — key, user, user|model, tenant aggregate,
		// tenant|model — because a latch nobody reads is a quota nobody
		// has.
		modelTPM := 0
		userModelTPM := 0
		if svc != nil && modelName != "" {
			var mErr error
			modelTPM, mErr = svc.GetTenantModelRateLimit(tenantIDStr, modelName)
			if mErr != nil {
				tk.LogIt(tk.LogWarning,
					"[AIGateway] rateLimitCheckInternal: tenant %s model %s limits unknowable (store outage, nothing cached) — failing closed\n",
					tenantIDStr, modelName)
				return 4, 5, "policy_store_unavailable"
			}
			if userIDStr != "" {
				userModelTPM, mErr = svc.GetUserModelRateLimit(tenantIDStr, userIDStr, modelName)
				if mErr != nil {
					tk.LogIt(tk.LogWarning,
						"[AIGateway] rateLimitCheckInternal: user %s/%s model %s limits unknowable (store outage, nothing cached) — failing closed\n",
						tenantIDStr, userIDStr, modelName)
					return 4, 5, "policy_store_unavailable"
				}
			}
		}

		// Warming gate first: after a cold start the consumed counters are
		// empty until a peer re-teaches them, so neither the debt check
		// nor a pre-admission reservation can be decided truthfully yet.
		// Deny with a short retry for the bounded warmup window rather than
		// silently admitting against a zeroed quota.
		anyTPM := tenantTPM > 0 || modelTPM > 0 || userTPM > 0 || userModelTPM > 0 || keyTPM > 0
		if anyTPM && store.QuotaWarming() {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: tenant %s denied during token-quota warmup\n", tenantIDStr)
			return 3, 1, "token_quota_warming"
		}
		if keyTPM > 0 && store.IsTokenQuotaExceeded(rl.KeyQuotaKey(keyIDStr)) {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: key %s token quota exceeded\n", keyIDStr)
			return 3, 60, "token_quota_exceeded"
		}
		if userTPM > 0 && store.IsTokenQuotaExceeded(rl.UserQuotaKey(tenantIDStr, userIDStr)) {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: user %s/%s token quota exceeded\n", tenantIDStr, userIDStr)
			return 3, 60, "token_quota_exceeded"
		}
		if userModelTPM > 0 && store.IsTokenQuotaExceeded(rl.UserModelQuotaKey(tenantIDStr, userIDStr, modelName)) {
			tk.LogIt(tk.LogWarning, "[AIGateway] rateLimitCheckInternal: user %s/%s model %s token quota exceeded\n", tenantIDStr, userIDStr, modelName)
			return 3, 60, "token_quota_exceeded"
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
		// Two different failures arrive on this one error path, and they must
		// not share a verdict. ErrInvalidKey is a verdict on the credential:
		// the store answered and the key is unknown, disabled or malformed —
		// the client's problem, permanent, 401. Every other error means the
		// store could NOT answer — a degraded pool, a dial that failed, a
		// query cut off mid-outage — and answering 401 there tells a client
		// with a perfectly good key that its credential is bad, which is both
		// false and permanent-sounding. The management plane had this same
		// defect and had it fixed; this is its data-plane twin.
		if errors.Is(err, aikey.ErrInvalidKey) {
			tk.LogIt(tk.LogWarning, "[AIGateway] llb_ai_validate_key: key validation failed: %v\n", err)
			return 1, "", "", "", "invalid_api_key"
		}
		tk.LogIt(tk.LogError, "[AIGateway] llb_ai_validate_key: key store could not answer: %v\n", err)
		prom.RecordPolicyStoreUnavailable()
		return 4, "", "", "", "policy_store_unavailable"
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

// recordGateDenial counts a request the AI Gateway policy gate refused. It is
// called from the deferred tail of every gate export, after that export's
// recover() has settled the final return value.
//
// It reads the export's own outputs rather than being told what happened: ret
// is what the C gate branches on and result.decision is the arm it takes, so
// this records exactly what the client is about to receive. A non-zero ret
// means the gate writes the response itself and tears the connection down —
// no backend is dialled, so no response-completion recorder can ever see the
// request, and this is its only chance to enter loxilb_ai_requests_total.
//
// result is nil only when the export could not fill a decision in at all. C
// dereferences that same pointer for the status it sends, so there is no
// client-visible outcome to attribute and nothing to count.
func recordGateDenial(ret C.int, result *C.ai_gw_decision_t, tenantID, modelName string) {
	if ret == 0 || result == nil {
		return
	}
	prom.RecordAIRequestDenied(tenantID, modelName, gateDenialStatus(int(result.decision)))
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
	// Label values for the denial recorder below, kept out here so the deferred
	// function can read whatever was resolved before an early return or a panic.
	var metricTenant, metricModel string

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
		// Count the denial here rather than at each deny arm. A non-zero return
		// means the C gate writes the response itself and drops the connection,
		// so no backend response will ever reach llb_ai_record_request; this is
		// the only place the request can enter the total. Doing it in the
		// deferred function makes that structural: every arm, including the
		// panic arm above, passes through exactly once, so a new deny arm cannot
		// be added without being counted and no arm can be counted twice.
		recordGateDenial(ret, result, metricTenant, metricModel)
	}()
	if result == nil {
		tk.LogIt(tk.LogError, "[AIGateway] llb_ai_validate_key: nil result pointer\n")
		return -1
	}
	metricModel = C.GoString(modelName)

	// Zero out the result struct before writing.
	*result = C.ai_gw_decision_t{}

	// Guard: the key store must exist before data-plane calls arrive. The
	// verdict itself is decided in keyStoreVerdict, which is plain Go and
	// therefore unit-testable; only the reporting stays here.
	us := mh.AIKeyService
	if decision, errorCode, haveStore := keyStoreVerdict(us); !haveStore {
		noKeyStoreOnce.Do(func() {
			tk.LogIt(tk.LogCritical,
				"[AIGateway] No API-key store configured (--aikey-db-host unset): services with api_key_auth=required are refusing requests with 503\n")
		})
		prom.RecordPolicyStoreUnavailable()
		result.decision = C.int(decision)
		cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), errorCode, 64)
		return -1
	}

	rawKeyStr := C.GoString(rawKey)
	modelNameStr := metricModel

	decision, tenantID, keyID, modelOut, errorCode := validateAPIKeyInternal(us, rawKeyStr, modelNameStr)

	// Known only on the 403 arm; empty elsewhere, which is the documented
	// "denied before the tenant resolved" label value.
	metricTenant = tenantID
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

// llb_ai_validate_bearer validates an Authorization: Bearer JWT for an
// incoming AI Gateway request — the JWT sibling of llb_ai_validate_key,
// deciding the Bearer arm of api_key_auth modes "jwt" and "apikey-or-jwt".
//
// Parameters:
//
//	bearer      – compact JWS from the Authorization header, scheme stripped
//	modelName   – effective model from the request (empty string if absent)
//	profileName – the rule's jwt_auth_profile name
//	bearerFlags – AI_GW_BEARERF_* capture flags (oversize → 401)
//	result      – output decision structure filled by this function
//
// Returns 0 when the request is allowed; -1 when it must be rejected.
// The caller inspects result->decision for the HTTP status:
//
//	0 – allow (tenant_id, user_id, auth_flags populated)
//	1 – deny with 401 (missing/malformed/expired/oversize token)
//	2 – deny with 403 (model not in the token's allowed set)
//	4 – deny with 503 (keyset never fetched / profile missing — the
//	    gateway's outage, distinct from 401 on purpose)
//
//export llb_ai_validate_bearer
func llb_ai_validate_bearer(bearer *C.char, modelName *C.char, profileName *C.char, bearerFlags C.int, result *C.ai_gw_decision_t) (ret C.int) {
	var metricTenant, metricModel string
	// The verdict reason for loxilb_ai_jwt_validation_total, recorded once in
	// the defer below so every arm counts -- including the two that leave
	// before a verdict is reached. It starts at internal_error because the
	// paths that cannot set it are exactly the ones that are.
	metricJWTReason := "internal_error"

	// Fail closed on panic: deny with 401 rather than crashing the datapath.
	defer func() {
		if r := recover(); r != nil {
			tk.LogIt(tk.LogCritical, "[AIGateway] llb_ai_validate_bearer: recovered panic: %v\n", r)
			if result != nil {
				result.decision = 1
				cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), "internal_error", 64)
			}
			ret = -1
			metricJWTReason = "internal_error"
		}
		// Structural denial accounting, same shape as llb_ai_validate_key:
		// a non-zero return means the C gate answers and tears the
		// connection down, so this is the request's only entry into
		// loxilb_ai_requests_total.
		recordGateDenial(ret, result, metricTenant, metricModel)
		// The bearer arm's own verdict counter. Here rather than at each
		// return so that adding an arm cannot forget to count it, and so a
		// panic is counted as the internal error it is instead of vanishing.
		prom.RecordJWTValidation(metricTenant, metricJWTReason)
	}()
	if result == nil {
		tk.LogIt(tk.LogError, "[AIGateway] llb_ai_validate_bearer: nil result pointer\n")
		return -1
	}
	metricModel = C.GoString(modelName)

	*result = C.ai_gw_decision_t{}

	h := mh.JWTAuthProfiles
	if h == nil {
		// Init order violation: the holder exists before the API surface
		// comes up. Seeing nil here means a data-plane call raced process
		// bootstrap — refuse as an outage, never admit.
		prom.RecordPolicyStoreUnavailable()
		result.decision = 4
		metricJWTReason = "policy_store_unavailable"
		cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), "policy_store_unavailable", 64)
		return -1
	}

	decision, tenantID, userID, errorCode, authFlags := validateBearerInternal(
		h.Manager(), h.ProfileUpstreamPolicy,
		C.GoString(bearer), metricModel, C.GoString(profileName), int(bearerFlags))

	// Known on the 403 arm; empty elsewhere ("denied before the tenant
	// resolved"), mirroring the API-key arm's label discipline.
	metricTenant = tenantID
	result.decision = C.int(decision)

	// The refusal's own error_code is the reason, so the counter's label set
	// stays closed: the codes are a fixed vocabulary and no request can
	// invent one.
	metricJWTReason = errorCode
	if decision == 0 {
		metricJWTReason = prom.JWTReasonAllowed
	}

	if decision == 0 {
		cCopyStr((*C.char)(unsafe.Pointer(&result.tenant_id[0])), tenantID, 128)
		cCopyStr((*C.char)(unsafe.Pointer(&result.user_id[0])), userID, 128)
		cCopyStr((*C.char)(unsafe.Pointer(&result.model_name[0])), metricModel, 128)
		result.auth_flags = C.int(authFlags)
		return 0
	}

	cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), errorCode, 64)
	switch decision {
	case 2:
		prom.RecordModelNotAllowed(tenantID, metricModel)
	case 4:
		// Same condition the API-key arm records: the credential policy
		// store cannot answer, so the request is refused as an outage. It
		// is the one denial an operator is expected to act on, and leaving
		// it off this counter here made a JWKS outage invisible on the
		// metric that exists to show it while the other arm reported it.
		prom.RecordPolicyStoreUnavailable()
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
//	keyID    – the validated API key's key_id string ("" on the JWT arm)
//	tenantID – the deciding credential arm's tenant_id string
//	userID   – the deciding arm's per-user identity ("" when none)
//	svcIdent – the service identity "VIP:port" ("" when unknown); selects
//	           the rule-scope defaults row and, when the whole identity is
//	           empty, the opt-in keyless per-VIP shared bucket
//	model    – the request's body-bound model name (may be empty); selects
//	           the tenant|model token bucket for the stage-3 debt check
//	result   – output decision structure; decision is set to 3 on denial
//
// Parameter order mirrors rateLimitCheckInternal — the C header
// (sockproxy_ai_gw.h) is kept position-for-position with it.
//
// Returns 0 when allowed; -1 when rate-limited (result->decision == 3 and
// result->retry_after is set to the recommended retry delay in seconds).
//
//export llb_ai_ratelimit_check
func llb_ai_ratelimit_check(keyID *C.char, tenantID *C.char, userID *C.char, svcIdent *C.char, model *C.char, result *C.ai_gw_decision_t) (ret C.int) {
	// See llb_ai_validate_key for why the denial is recorded in the deferred
	// function rather than at each deny arm.
	var metricTenant, metricModel string

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
		recordGateDenial(ret, result, metricTenant, metricModel)
	}()
	if result == nil {
		tk.LogIt(tk.LogError, "[AIGateway] llb_ai_ratelimit_check: nil result pointer\n")
		return -1
	}

	keyIDStr := C.GoString(keyID)
	tenantIDStr := C.GoString(tenantID)
	modelStr := C.GoString(model)
	metricTenant, metricModel = tenantIDStr, modelStr

	var svc rateLimitService
	if us := mh.AIKeyService; us != nil {
		svc = us
	}

	store := getGlobalRL()
	decision, retrySecs, errorCode := rateLimitCheckInternal(svc, store, keyIDStr, tenantIDStr, C.GoString(userID), C.GoString(svcIdent), modelStr)
	if decision != 0 {
		result.decision = C.int(decision)
		result.retry_after = C.int(retrySecs)
		cCopyStr((*C.char)(unsafe.Pointer(&result.error_code[0])), errorCode, 64)
		// Record the REASON at the point of denial; the request itself is
		// counted once, in the deferred recorder above.
		//
		// Not every denial from this stage is a rate decision. The stage also
		// returns deny_503 when it finds a keyed identity with no policy store
		// behind it, and that arm used to increment rate_limit_hits_total with
		// reason="policy_store_unavailable": a store outage was reported as a
		// throttling spike (it raises LoxilbAIRateLimitSpike, whose whole
		// premise is that a tenant is sending too fast), while
		// policy_store_unavailable_total — the family that exists to make
		// exactly this visible — stayed blind to an entire arm. The two other
		// sites that produce deny_503 have always reported it correctly.
		if decision == aiDecisionDeny503 {
			prom.RecordPolicyStoreUnavailable()
		} else {
			prom.RecordRateLimitHit(tenantIDStr, errorCode)
			if errorCode == "token_quota_exceeded" {
				prom.RecordTokenQuotaDenied(tenantIDStr)
			}
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
func tokenQuotaReserveInternal(svc rateLimitService, store *rl.RateLimiterStore, tenantID, modelName, userID, keyID, svcIdent string, want int) (allowed bool, retrySecs int, resEpoch int64) {
	// A keyless request (no tenant) can still hold a claim: the per-VIP
	// shared bucket is keyed on the service alone. With neither identity
	// there is nothing to reserve against.
	if want <= 0 || (tenantID == "" && svcIdent == "") {
		return true, 0, 0
	}
	buckets := quotaBucketsFor(svc, tenantID, modelName, userID, keyID, svcIdent)
	if len(buckets) == 0 {
		return true, 0, 0
	}

	// Claim every bucket in ladder order; a later denial gives back every
	// claim already taken (epoch-tagged, clamped release; nothing charged)
	// — a half-held reservation would leak headroom until the epoch
	// expires it.
	taken := 0
	for i, b := range buckets {
		bAllowed, bRetry, bEpoch := store.ReserveTokens(b.key, want, b.tpm, b.burstPct)
		if !bAllowed {
			for j := range taken {
				p := buckets[j]
				if resEpoch != 0 {
					store.SettleTokens(p.key, 0, want, resEpoch, p.tpm, p.burstPct)
				}
			}
			return false, bRetry, 0
		}
		taken = i + 1
		if resEpoch == 0 {
			resEpoch = bEpoch
		}
	}
	return true, 0, resEpoch
}

// quotaBucket names one token-quota bucket a request is accountable to.
type quotaBucket struct {
	key      string
	tpm      int
	burstPct int
}

// quotaBucketsFor resolves the token buckets a request's spend lands on, in
// ladder order: tenant aggregate, tenant|model, user aggregate, user|model,
// key, VIP-shared. Only buckets with a resolved non-zero limit exist. The
// read errors are tolerated here (reservation and settlement both run
// mid-request): admission has already refused fresh requests for an
// unknowable identity, so an error now is the outage beginning mid-flight —
// the affected bucket drops out exactly as an unlimited one would, and the
// admission gate owns the deny from the next request on.
//
// burstPct is the tenant's bucket-capacity override, shared by every bucket
// under the tenant (model, user, user|model): burstiness is a property of
// how bursty the TENANT may be, and a per-bucket capacity would let a
// tenant widen its aggregate burst by splitting spend.
func quotaBucketsFor(svc rateLimitService, tenantID, modelName, userID, keyID, svcIdent string) []quotaBucket {
	if svc == nil {
		return nil
	}
	var out []quotaBucket
	var defaults qosDefaults
	if d, err := resolveQoSDefaults(svc, svcIdent); err == nil {
		defaults = d
	}

	// The tenant-keyed dimensions exist only for attributed traffic; a
	// keyless caller (empty tenant) must not read the store for the empty
	// pair, and its spend lands only on the per-VIP shared bucket below.
	burstPct := 0
	if tenantID != "" {
		var tenantTPM int
		_, tenantTPM, burstPct, _ = svc.GetTenantRateLimit(tenantID)
		if tenantTPM <= 0 {
			tenantTPM = defaults.tenantTPM
		}
		if tenantTPM > 0 {
			out = append(out, quotaBucket{key: tenantID, tpm: tenantTPM, burstPct: burstPct})
		}
		if modelName != "" {
			if modelTPM, err := svc.GetTenantModelRateLimit(tenantID, modelName); err == nil && modelTPM > 0 {
				out = append(out, quotaBucket{key: modelQuotaKey(tenantID, modelName), tpm: modelTPM, burstPct: burstPct})
			}
		}
	}
	if userID != "" && tenantID != "" {
		userTPM := 0
		if _, _, t, err := svc.GetUserRateLimit(tenantID, userID); err == nil {
			userTPM = t
		}
		if userTPM <= 0 {
			userTPM = defaults.userTPM
		}
		if userTPM > 0 {
			out = append(out, quotaBucket{key: rl.UserQuotaKey(tenantID, userID), tpm: userTPM, burstPct: burstPct})
		}
		if modelName != "" {
			if umTPM, err := svc.GetUserModelRateLimit(tenantID, userID, modelName); err == nil && umTPM > 0 {
				out = append(out, quotaBucket{key: rl.UserModelQuotaKey(tenantID, userID, modelName), tpm: umTPM, burstPct: burstPct})
			}
		}
	}
	if keyID != "" {
		if key, err := svc.GetAPIKeyByID(keyID); err == nil && key.TokensPerMin > 0 {
			out = append(out, quotaBucket{key: rl.KeyQuotaKey(keyID), tpm: key.TokensPerMin, burstPct: burstPct})
		}
	}
	if svcIdent != "" && defaults.vipTPM > 0 {
		out = append(out, quotaBucket{key: rl.VipSharedQuotaKey(svcIdent), tpm: defaults.vipTPM, burstPct: 0})
	}
	return out
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
func tokenQuotaConsumeInternal(svc rateLimitService, store *rl.RateLimiterStore, tenantID, modelName, userID, keyID, svcIdent string, count, reservedAmt int, resEpoch int64) (allowed bool, retrySecs int) {
	// Keyless settles are keyed on the service alone; with neither a
	// tenant nor a service identity there is no bucket to touch.
	if tenantID == "" && svcIdent == "" {
		return true, 0
	}
	// Same tolerance as reservation: settlement must run even when the
	// limits are unknowable — an unreleased claim would deny the tenant's
	// admissions until the epoch expires it, turning the outage into a
	// second, self-inflicted quota failure.
	buckets := quotaBucketsFor(svc, tenantID, modelName, userID, keyID, svcIdent)
	if reservedAmt <= 0 && (count <= 0 || len(buckets) == 0) {
		return true, 0
	}
	// The request's PRIMARY bucket settles even when its own limit resolved
	// to zero (reservation release rides the settle call): the tenant
	// aggregate for attributed traffic — matching the old shape — and the
	// per-VIP shared bucket for keyless traffic, whose claim would
	// otherwise strand when the defaults row vanishes mid-request. Every
	// other bucket exists only with a live limit.
	primaryKey := tenantID
	if tenantID == "" {
		primaryKey = rl.VipSharedQuotaKey(svcIdent)
	}
	settledPrimary := false
	allowed = true
	for _, b := range buckets {
		bAllowed, bRetry := store.SettleTokens(b.key, count, reservedAmt, resEpoch, b.tpm, b.burstPct)
		if b.key == primaryKey {
			settledPrimary = true
		}
		if !bAllowed {
			allowed = false
			retrySecs = max(retrySecs, bRetry)
		}
	}
	if !settledPrimary {
		pAllowed, pRetry := store.SettleTokens(primaryKey, count, reservedAmt, resEpoch, 0, 0)
		if !pAllowed {
			allowed = false
			retrySecs = max(retrySecs, pRetry)
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
// The identity trio (userID/keyID/svcIdent) reserves against the user,
// user|model, key and per-VIP buckets next to the tenant aggregate;
// parameter order mirrors tokenQuotaReserveInternal.
//
//export llb_ai_token_quota_reserve
func llb_ai_token_quota_reserve(tenantID *C.char, modelName *C.char, userID *C.char, keyID *C.char, svcIdent *C.char, promptEst C.int, maxTokens C.int, resEpoch *C.longlong, result *C.ai_gw_decision_t) (ret C.int) {
	// See llb_ai_validate_key for why the denial is recorded in the deferred
	// function rather than at each deny arm.
	var metricTenant, metricModel string

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
		recordGateDenial(ret, result, metricTenant, metricModel)
	}()

	if resEpoch != nil {
		*resEpoch = 0
	}

	tenant := C.GoString(tenantID)
	metricTenant, metricModel = tenant, C.GoString(modelName)
	want := 0
	if promptEst > 0 {
		want += int(promptEst)
	}
	if maxTokens > 0 {
		want += int(maxTokens)
	}
	// A keyless caller (no tenant) may still reserve against the per-VIP
	// shared bucket when it names the service.
	if want <= 0 || (tenant == "" && C.GoString(svcIdent) == "") {
		return 0
	}

	var svc rateLimitService
	if us := mh.AIKeyService; us != nil {
		svc = us
	}

	store := getGlobalRL()
	allowed, retrySecs, epoch := tokenQuotaReserveInternal(svc, store, tenant, C.GoString(modelName), C.GoString(userID), C.GoString(keyID), C.GoString(svcIdent), want)
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
// The identity trio (userID/keyID/svcIdent) charges the user, user|model,
// key and per-VIP buckets the reservation claimed; parameter order mirrors
// tokenQuotaConsumeInternal.
//
//export llb_ai_token_quota_consume
func llb_ai_token_quota_consume(tenantID *C.char, modelName *C.char, userID *C.char, keyID *C.char, svcIdent *C.char, promptTokens C.int, completTokens C.int, estimated C.int, reservedToks C.int, resEpoch C.longlong, result *C.ai_gw_decision_t) (ret C.int) {
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
	// tenant's admissions stay blocked until the window rolls over. A
	// keyless caller (no tenant) settles the per-VIP shared bucket when it
	// names the service.
	if (tenant == "" && C.GoString(svcIdent) == "") || (count <= 0 && reservedToks <= 0) {
		return 0
	}

	// The per-tenant usage families stay attributed-only: a keyless settle
	// has no tenant to label, and an empty label value reads as a scrape
	// bug. Keyless volume is already visible per VIP in the unmetered
	// counter.
	if count > 0 && tenant != "" {
		prom.RecordTokenUsage(C.GoString(modelName), tenant, int(promptTokens),
			int(completTokens), estimated != 0)
	}

	var svc rateLimitService
	if us := mh.AIKeyService; us != nil {
		svc = us
	}

	store := getGlobalRL()
	allowed, retrySecs := tokenQuotaConsumeInternal(svc, store, tenant, C.GoString(modelName), C.GoString(userID), C.GoString(keyID), C.GoString(svcIdent), count,
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

// AiInFlightStreamsTotal sums the per-model in-flight SSE counters. This
// is the maintenance drain read-back's in-flight figure: it deliberately
// reuses the counters llb_ai_stream_start/end already maintain (the
// loxilb_ai_active_streams gauge's backing state) rather than inventing
// a second counting layer that could disagree with the metrics surface.
func AiInFlightStreamsTotal() int64 {
	var total int64
	activeSSECounters.Range(func(_, v any) bool {
		total += atomic.LoadInt64(v.(*int64))
		return true
	})
	return total
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
// is tracked by llb_ai_stream_start/_end, and denials never reach this export
// at all — the gate answers them itself, so they are counted under
// outcome="denied" by recordGateDenial and their reason by the
// point-of-denial counters.
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

// llb_ai_pd_tier_selected records the terminal P/D routing-tier decision.
//
// C sockproxy calls this exactly once per successful prefill selection, at
// the terminal return of the tier that produced the endpoint (0=Tier-0
// session, 1=Tier-1 trie, 15=Tier-1.5 KV-exact, 2=Tier-2 min-load).
//
//export llb_ai_pd_tier_selected
func llb_ai_pd_tier_selected(modelName *C.char, tier C.int) {
	defer cgoRecover("llb_ai_pd_tier_selected")
	modelNameStr := C.GoString(modelName)
	prom.RecordPDTierSelected(modelNameStr, int(tier))
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

// llb_ai_record_usage_missing records one completed response that carried no
// readable usage object, and charges nothing.
//
// C sockproxy calls this when a non-streamed AI Gateway response has finished
// and no dialect ever extracted a usage object from it. The streaming path
// reaches the same counter through the quota charge's estimated arm; the
// non-streamed path had no route to it at all, so responses that completed
// without usage were invisible rather than merely uncharged.
//
// Accounting-only by construction: it moves loxilb_ai_tokens_missing_total and
// nothing else. These responses stay free by decision, not by omission — see
// prom.RecordTokenUsageMissing for why charging an estimate was rejected and
// what would reopen it.
//
// reason names the reporting boundary the data plane fired at — one of the
// LLB_AI_UMISS_* literals in common/sockproxy_ai_gw.h — and becomes the
// family's reason label. It is passed through unread: RecordTokenUsageMissing
// owns the accepted set, so an unknown value lands on "unknown" there rather
// than opening a cardinality hole here.
//
//export llb_ai_record_usage_missing
func llb_ai_record_usage_missing(tenantID *C.char, modelName *C.char, reason *C.char) {
	defer cgoRecover("llb_ai_record_usage_missing")
	prom.RecordTokenUsageMissing(C.GoString(modelName), C.GoString(tenantID),
		C.GoString(reason))
}
