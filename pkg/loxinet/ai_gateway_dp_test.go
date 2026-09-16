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

import (
	"errors"
	"fmt"
	"testing"
	"time"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/aikey"
	rl "github.com/loxilb-io/loxilb/pkg/ratelimit"
)

// mockAPIKeyValidator implements apiKeyValidator for unit tests.
type mockAPIKeyValidator struct {
	entry *cmn.ApiKeyEntry
	err   error
}

func (m *mockAPIKeyValidator) ValidateAPIKey(_ string) (*cmn.ApiKeyEntry, error) {
	return m.entry, m.err
}

// mockRateLimitService implements rateLimitService for unit tests.
type mockRateLimitService struct {
	tenantRPS int
	tenantTPM int
	// tenantBurst is the per-tenant bucket-capacity override in percent;
	// 0 keeps the process-wide default, which is what every pre-existing
	// case in this file expects.
	tenantBurst int
	modelTPM    map[string]int // per-model tokens_per_min; nil = no model quotas
	keyByID     map[string]*cmn.ApiKeySummary
	limitsErr   error

	// Ladder rows. userRows is keyed "tenant|user"; userModelTPM
	// "tenant|user|model"; defaults nil = no defaults rows configured.
	userRows     map[string]cmn.UserRateLimitEntry
	userModelTPM map[string]int
	defaults     map[string]cmn.RateLimitDefaultsEntry // keyed "scope|rule_ident"
	// userErr / defaultsErr let outage cases target one ladder read
	// without failing the tenant reads the same request makes.
	userErr     error
	defaultsErr error
}

func (m *mockRateLimitService) GetTenantRateLimit(_ string) (int, int, int, error) {
	return m.tenantRPS, m.tenantTPM, m.tenantBurst, m.limitsErr
}

func (m *mockRateLimitService) GetTenantModelRateLimit(_, model string) (int, error) {
	return m.modelTPM[model], m.limitsErr
}

func (m *mockRateLimitService) GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error) {
	if m.keyByID != nil {
		if key, ok := m.keyByID[keyID]; ok {
			return key, nil
		}
	}
	return nil, errors.New("API key not found")
}

func (m *mockRateLimitService) GetUserRateLimit(tenantID, userID string) (int, int, int, error) {
	if m.userErr != nil {
		return 0, 0, 0, m.userErr
	}
	e := m.userRows[tenantID+"|"+userID]
	return e.RPS, e.BurstSize, e.TokensPerMin, nil
}

func (m *mockRateLimitService) GetUserModelRateLimit(tenantID, userID, model string) (int, error) {
	if m.userErr != nil {
		return 0, m.userErr
	}
	return m.userModelTPM[tenantID+"|"+userID+"|"+model], nil
}

func (m *mockRateLimitService) GetRateLimitDefaults(scope, ruleIdent string) (cmn.RateLimitDefaultsEntry, bool, error) {
	if m.defaultsErr != nil {
		return cmn.RateLimitDefaultsEntry{}, false, m.defaultsErr
	}
	e, ok := m.defaults[scope+"|"+ruleIdent]
	return e, ok, nil
}

// pastTime returns a time guaranteed to be in the past.
func pastTime() *time.Time {
	t := time.Now().Add(-24 * time.Hour)
	return &t
}

// futureTime returns a time guaranteed to be in the future.
func futureTime() *time.Time {
	t := time.Now().Add(24 * time.Hour)
	return &t
}

// TestRateLimitCheckInternalPerKeyThrottling verifies that a key with
// RateLimitRPS=2 is throttled after 2 requests (burst=rps=2 initial tokens).
func TestRateLimitCheckInternalPerKeyThrottling(t *testing.T) {
	store := rl.New()
	svc := &mockRateLimitService{
		tenantRPS: 0, // no tenant-level limit
		keyByID: map[string]*cmn.ApiKeySummary{
			"key-limited": {KeyID: "key-limited", RateLimitRPS: 2, BurstSize: 0},
		},
	}

	// First two requests must be allowed (burst=2 initial tokens).
	for i := 1; i <= 2; i++ {
		decision, _, errCode := rateLimitCheckInternal(svc, store, "key-limited", "tenant-1", "", "", "")
		if decision != 0 {
			t.Fatalf("request %d: expected allow (decision=0), got decision=%d errorCode=%q", i, decision, errCode)
		}
	}

	// Third request must be rate-limited.
	decision, retrySecs, errCode := rateLimitCheckInternal(svc, store, "key-limited", "tenant-1", "", "", "")
	if decision != 3 {
		t.Fatalf("request 3: expected deny_429 (decision=3), got decision=%d", decision)
	}
	if errCode != "rate_limit_exceeded" {
		t.Errorf("expected error_code %q, got %q", "rate_limit_exceeded", errCode)
	}
	if retrySecs <= 0 {
		t.Errorf("expected retrySecs > 0, got %d", retrySecs)
	}
}

// TestRateLimitCheckInternalUnlimitedKey verifies that a key with
// RateLimitRPS=0 (unlimited) is never throttled by CheckKey regardless of
// how many requests are made.
func TestRateLimitCheckInternalUnlimitedKey(t *testing.T) {
	store := rl.New()
	svc := &mockRateLimitService{
		tenantRPS: 0, // no tenant-level limit
		keyByID: map[string]*cmn.ApiKeySummary{
			"key-unlimited": {KeyID: "key-unlimited", RateLimitRPS: 0, BurstSize: 0},
		},
	}

	// Any number of requests must be allowed when RateLimitRPS=0.
	for i := 1; i <= 100; i++ {
		decision, _, errCode := rateLimitCheckInternal(svc, store, "key-unlimited", "tenant-2", "", "", "")
		if decision != 0 {
			t.Fatalf("request %d: expected allow (decision=0), got decision=%d errorCode=%q", i, decision, errCode)
		}
	}
}

// TestRateLimitCheckInternalTenantErrorCode verifies that per-tenant bucket
// denial uses error_code 'tenant_quota_exceeded', not 'rate_limit_exceeded'.
func TestRateLimitCheckInternalTenantErrorCode(t *testing.T) {
	store := rl.New()
	svc := &mockRateLimitService{
		tenantRPS: 1, // tenant limited to 1 RPS
		keyByID: map[string]*cmn.ApiKeySummary{
			// key has no per-key limit
			"key-norlimit": {KeyID: "key-norlimit", RateLimitRPS: 0, BurstSize: 0},
		},
	}

	// First request allowed (burst=1).
	decision, _, _ := rateLimitCheckInternal(svc, store, "key-norlimit", "tenant-3", "", "", "")
	if decision != 0 {
		t.Fatalf("request 1: expected allow, got decision=%d", decision)
	}

	// Second request must be tenant-rate-limited with tenant_quota_exceeded.
	decision, _, errCode := rateLimitCheckInternal(svc, store, "key-norlimit", "tenant-3", "", "", "")
	if decision != 3 {
		t.Fatalf("request 2: expected deny_429 (decision=3), got decision=%d", decision)
	}
	if errCode != "tenant_quota_exceeded" {
		t.Errorf("expected error_code %q, got %q", "tenant_quota_exceeded", errCode)
	}
}

// TestTokenQuotaConsumeInternal verifies the response-side token charge:
// within-quota charges pass, the charge that tips the tenant over latches the
// exceeded flag, and the NEXT request is denied 429 with
// token_quota_exceeded by the rate-limit gate's stage 3.
func TestTokenQuotaConsumeInternal(t *testing.T) {
	store := rl.New()
	svc := &mockRateLimitService{
		tenantRPS: 1000, // stage-1/2 must not interfere
		tenantTPM: 100,
		keyByID: map[string]*cmn.ApiKeySummary{
			"key-tpm": {KeyID: "key-tpm", RateLimitRPS: 0, BurstSize: 0},
		},
	}

	// Charge 60 of 100: allowed, gate stays open.
	allowed, _ := tokenQuotaConsumeInternal(svc, store, "tenant-tpm", "", "", "", "", 60, 0, 0)
	if !allowed {
		t.Fatalf("charge 60/100: expected allowed")
	}
	if decision, _, _ := rateLimitCheckInternal(svc, store, "key-tpm", "tenant-tpm", "", "", ""); decision != 0 {
		t.Fatalf("gate after 60/100: expected allow, got decision=%d", decision)
	}

	// Charge 50 more (110 > 100): denied, exceeded flag latches.
	allowed, retrySecs := tokenQuotaConsumeInternal(svc, store, "tenant-tpm", "", "", "", "", 50, 0, 0)
	if allowed {
		t.Fatalf("charge 110/100: expected denied")
	}
	if retrySecs <= 0 {
		t.Errorf("expected positive retrySecs, got %d", retrySecs)
	}

	// The NEXT request must be denied 429 with token_quota_exceeded.
	decision, _, errCode := rateLimitCheckInternal(svc, store, "key-tpm", "tenant-tpm", "", "", "")
	if decision != 3 {
		t.Fatalf("gate after quota trip: expected deny_429 (decision=3), got decision=%d", decision)
	}
	if errCode != "token_quota_exceeded" {
		t.Errorf("expected error_code %q, got %q", "token_quota_exceeded", errCode)
	}
}

// TestTokenQuotaConsumeInternalUnlimited verifies that tokens_per_min=0
// (unlimited), a nil service, and non-positive counts all pass without
// latching the quota.
func TestTokenQuotaConsumeInternalUnlimited(t *testing.T) {
	store := rl.New()

	// tokens_per_min=0 → unlimited: huge charges pass.
	svc := &mockRateLimitService{tenantTPM: 0}
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "tenant-unlim", "", "", "", "", 1<<30, 0, 0); !allowed {
		t.Fatalf("unlimited tenant: expected allowed")
	}
	if store.IsTokenQuotaExceeded("tenant-unlim") {
		t.Errorf("unlimited tenant: exceeded flag must not latch")
	}

	// nil service (userservice disabled) → allowed.
	if allowed, _ := tokenQuotaConsumeInternal(nil, store, "tenant-nosvc", "", "", "", "", 500, 0, 0); !allowed {
		t.Fatalf("nil service: expected allowed")
	}

	// Non-positive count / empty tenant → allowed no-ops.
	svc2 := &mockRateLimitService{tenantTPM: 10}
	if allowed, _ := tokenQuotaConsumeInternal(svc2, store, "tenant-x", "", "", "", "", 0, 0, 0); !allowed {
		t.Fatalf("count 0: expected allowed")
	}
	if allowed, _ := tokenQuotaConsumeInternal(svc2, store, "", "", "", "", "", 50, 0, 0); !allowed {
		t.Fatalf("empty tenant: expected allowed")
	}
}

func TestValidateAPIKeyInternal(t *testing.T) {
	validEntry := &cmn.ApiKeyEntry{
		KeyID:         "abc123",
		TenantID:      "tenant-1",
		AllowedModels: nil,
		ExpiresAt:     nil,
		Enabled:       true,
	}

	tests := []struct {
		name          string
		svc           apiKeyValidator
		rawKey        string
		modelName     string
		wantDecision  int
		wantTenantID  string
		wantKeyID     string
		wantModelOut  string
		wantErrorCode string
	}{
		{
			name:          "empty raw key returns deny_401",
			svc:           &mockAPIKeyValidator{entry: validEntry},
			rawKey:        "",
			modelName:     "gpt-4",
			wantDecision:  1,
			wantErrorCode: "invalid_api_key",
		},
		{
			// The sentinel, not a lookalike string: only ErrInvalidKey is a
			// verdict on the credential. This case used to wrap a same-text
			// errors.New, which is exactly how the taxonomy stayed
			// untested — any error at all produced the 401.
			name:          "invalid key (ErrInvalidKey) returns deny_401",
			svc:           &mockAPIKeyValidator{err: aikey.ErrInvalidKey},
			rawKey:        "lxb_bad_key",
			modelName:     "gpt-4",
			wantDecision:  1,
			wantErrorCode: "invalid_api_key",
		},
		{
			// A store that cannot answer is not a verdict on the
			// credential. 401 here tells a client with a good key to stop
			// retrying; 503 tells it the truth.
			name:          "store outage (ErrDBUnavailable) returns deny_503",
			svc:           &mockAPIKeyValidator{err: fmt.Errorf("aikey: key store unavailable: %w", aikey.ErrDBUnavailable)},
			rawKey:        "lxb_good_key_unreachable_store",
			modelName:     "gpt-4",
			wantDecision:  4,
			wantErrorCode: "policy_store_unavailable",
		},
		{
			// A raw driver error — the server died mid-query, so nothing
			// wrapped it — is still "the store could not answer", never
			// "your key is bad".
			name:          "unclassified store error returns deny_503",
			svc:           &mockAPIKeyValidator{err: errors.New("driver: bad connection")},
			rawKey:        "lxb_key_during_outage",
			modelName:     "gpt-4",
			wantDecision:  4,
			wantErrorCode: "policy_store_unavailable",
		},
		{
			name: "expired key returns deny_401",
			svc: &mockAPIKeyValidator{entry: &cmn.ApiKeyEntry{
				KeyID:     "exp-key",
				TenantID:  "tenant-2",
				Enabled:   true,
				ExpiresAt: pastTime(),
			}},
			rawKey:        "lxb_expired",
			modelName:     "gpt-4",
			wantDecision:  1,
			wantErrorCode: "invalid_api_key",
		},
		{
			name: "model not in allowed list returns deny_403",
			svc: &mockAPIKeyValidator{entry: &cmn.ApiKeyEntry{
				KeyID:         "key-restricted",
				TenantID:      "tenant-3",
				Enabled:       true,
				AllowedModels: []string{"gpt-3.5", "gpt-4"},
			}},
			rawKey:        "lxb_restricted_key",
			modelName:     "claude-3",
			wantDecision:  2,
			wantTenantID:  "tenant-3",
			wantErrorCode: "model_not_allowed",
		},
		{
			name: "empty model name not in non-empty allowed list returns deny_403",
			svc: &mockAPIKeyValidator{entry: &cmn.ApiKeyEntry{
				KeyID:         "key-restricted2",
				TenantID:      "tenant-4",
				Enabled:       true,
				AllowedModels: []string{"gpt-4"},
			}},
			rawKey:        "lxb_key2",
			modelName:     "",
			wantDecision:  2,
			wantTenantID:  "tenant-4",
			wantErrorCode: "model_not_allowed",
		},
		{
			name:         "valid key with no model restrictions returns allow",
			svc:          &mockAPIKeyValidator{entry: validEntry},
			rawKey:       "lxb_valid_key",
			modelName:    "gpt-4",
			wantDecision: 0,
			wantTenantID: "tenant-1",
			wantKeyID:    "abc123",
			wantModelOut: "gpt-4",
		},
		{
			name: "valid key with allowed model returns allow",
			svc: &mockAPIKeyValidator{entry: &cmn.ApiKeyEntry{
				KeyID:         "key-allowed",
				TenantID:      "tenant-5",
				Enabled:       true,
				AllowedModels: []string{"gpt-4", "gpt-3.5"},
				ExpiresAt:     futureTime(),
			}},
			rawKey:       "lxb_allowed_key",
			modelName:    "gpt-4",
			wantDecision: 0,
			wantTenantID: "tenant-5",
			wantKeyID:    "key-allowed",
			wantModelOut: "gpt-4",
		},
		{
			name: "valid key with future expiry returns allow",
			svc: &mockAPIKeyValidator{entry: &cmn.ApiKeyEntry{
				KeyID:     "key-future",
				TenantID:  "tenant-6",
				Enabled:   true,
				ExpiresAt: futureTime(),
			}},
			rawKey:       "lxb_future_key",
			modelName:    "any-model",
			wantDecision: 0,
			wantTenantID: "tenant-6",
			wantKeyID:    "key-future",
			wantModelOut: "any-model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDecision, gotTenantID, gotKeyID, gotModelOut, gotErrorCode :=
				validateAPIKeyInternal(tt.svc, tt.rawKey, tt.modelName)

			if gotDecision != tt.wantDecision {
				t.Errorf("decision = %d, want %d", gotDecision, tt.wantDecision)
			}
			if gotTenantID != tt.wantTenantID {
				t.Errorf("tenantID = %q, want %q", gotTenantID, tt.wantTenantID)
			}
			if gotKeyID != tt.wantKeyID {
				t.Errorf("keyID = %q, want %q", gotKeyID, tt.wantKeyID)
			}
			if gotModelOut != tt.wantModelOut {
				t.Errorf("modelOut = %q, want %q", gotModelOut, tt.wantModelOut)
			}
			if gotErrorCode != tt.wantErrorCode {
				t.Errorf("errorCode = %q, want %q", gotErrorCode, tt.wantErrorCode)
			}
		})
	}
}

// TestTokenQuotaReserveInternal verifies the pre-admission path end to end at
// the Go layer: an admissible reservation passes and its epoch settles
// correctly; a reservation that cannot fit is denied WITHOUT latching the
// exceeded flag (the gate's stage 3 must keep admitting smaller requests);
// settlement credits the unused ceiling back.
func TestTokenQuotaReserveInternal(t *testing.T) {
	store := rl.New()
	svc := &mockRateLimitService{
		tenantRPS: 1000,
		tenantTPM: 1000,
		keyByID: map[string]*cmn.ApiKeySummary{
			"key-resv": {KeyID: "key-resv", RateLimitRPS: 0, BurstSize: 0},
		},
	}

	// Reserve 700 of 1000 (prompt est 200 + max_tokens 500): admitted.
	allowed, _, ep := tokenQuotaReserveInternal(svc, store, "tenant-resv", "", "", "", "", 700)
	if !allowed || ep == 0 {
		t.Fatalf("reserve 700/1000: expected admitted with epoch, got allowed=%v ep=%d", allowed, ep)
	}

	// A second 700 cannot fit: pre-admission deny...
	allowed, retrySecs, _ := tokenQuotaReserveInternal(svc, store, "tenant-resv", "", "", "", "", 700)
	if allowed {
		t.Fatalf("reserve 1400/1000: expected pre-admission deny")
	}
	if retrySecs <= 0 {
		t.Errorf("pre-admission deny: expected positive retrySecs, got %d", retrySecs)
	}
	// ...that must NOT latch: the stage-3 gate stays open for the tenant.
	if decision, _, _ := rateLimitCheckInternal(svc, store, "key-resv", "tenant-resv", "", "", ""); decision != 0 {
		t.Fatalf("gate after reserve-deny: expected allow (no latch), got decision=%d", decision)
	}
	// A smaller request still fits alongside the standing reservation.
	if allowed, _, _ := tokenQuotaReserveInternal(svc, store, "tenant-resv", "", "", "", "", 300); !allowed {
		t.Fatalf("reserve 300 with 700 standing: expected admitted")
	}

	// Settle the first request: actual 100 of the 700 ceiling. The freed 600
	// plus the released 300-claim window must admit a 600 reservation
	// (consumed 100 + standing 300 + 600 = 1000).
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "tenant-resv", "", "", "", "", 100, 700, ep); !allowed {
		t.Fatalf("settlement 100/1000: expected allowed")
	}
	if allowed, _, _ := tokenQuotaReserveInternal(svc, store, "tenant-resv", "", "", "", "", 600); !allowed {
		t.Fatalf("reserve 600 after settlement: expected admitted (100 consumed + 300 + 600 = 1000)")
	}
}

// TestTokenQuotaReserveInternalSkips verifies the no-op contracts: unlimited
// tenants, nil service, zero want and empty tenant all admit with epoch 0
// (nothing to settle).
func TestTokenQuotaReserveInternalSkips(t *testing.T) {
	store := rl.New()

	svc := &mockRateLimitService{tenantTPM: 0}
	if allowed, _, ep := tokenQuotaReserveInternal(svc, store, "tenant-unlim", "", "", "", "", 1<<30); !allowed || ep != 0 {
		t.Fatalf("unlimited tenant: expected admit with epoch 0")
	}
	if allowed, _, ep := tokenQuotaReserveInternal(nil, store, "tenant-nosvc", "", "", "", "", 500); !allowed || ep != 0 {
		t.Fatalf("nil service: expected admit with epoch 0")
	}
	svc2 := &mockRateLimitService{tenantTPM: 100}
	if allowed, _, ep := tokenQuotaReserveInternal(svc2, store, "tenant-y", "", "", "", "", 0); !allowed || ep != 0 {
		t.Fatalf("want 0: expected admit with epoch 0")
	}
	if allowed, _, ep := tokenQuotaReserveInternal(svc2, store, "", "", "", "", "", 50); !allowed || ep != 0 {
		t.Fatalf("empty tenant: expected admit with epoch 0")
	}
}

// TestTokenQuotaConsumeReleasesOnZeroCount pins the uncounted-response rule:
// a request that reserved at admission but produced no countable tokens
// (aborted stream, non-JSON error response) must still release its claim at
// settlement, or the tenant's admissions stay blocked until window rollover.
func TestTokenQuotaConsumeReleasesOnZeroCount(t *testing.T) {
	store := rl.New()
	svc := &mockRateLimitService{tenantTPM: 1000}

	allowed, _, ep := tokenQuotaReserveInternal(svc, store, "tenant-rel", "", "", "", "", 900)
	if !allowed {
		t.Fatalf("reserve 900/1000: expected admitted")
	}
	// Settle with count 0 — the release must still run.
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "tenant-rel", "", "", "", "", 0, 900, ep); !allowed {
		t.Fatalf("zero-count settlement: expected allowed")
	}
	// Full headroom must be back.
	if allowed, _, _ := tokenQuotaReserveInternal(svc, store, "tenant-rel", "", "", "", "", 1000); !allowed {
		t.Fatalf("reserve 1000 after zero-count release: expected admitted")
	}
}

// TestRateLimitCheckInternalQuotaWarming pins the cold-start gate posture:
// while the store is warming (restart, peer state not yet re-learned) a
// tenant WITH a token quota is denied with the distinct token_quota_warming
// code and a short retry, a tenant WITHOUT one is untouched, and the first
// peer batch ends the hold.
func TestRateLimitCheckInternalQuotaWarming(t *testing.T) {
	store := rl.New()
	store.StartQuotaWarmup(time.Hour, func(bool) {})

	quotaSvc := &mockRateLimitService{tenantRPS: 0, tenantTPM: 100}
	decision, retrySecs, errCode := rateLimitCheckInternal(quotaSvc, store, "", "tenant-warm", "", "", "")
	if decision != 3 || errCode != "token_quota_warming" {
		t.Fatalf("warming store must deny a quota tenant with token_quota_warming, got decision=%d errCode=%q", decision, errCode)
	}
	if retrySecs <= 0 {
		t.Errorf("warming denial must advise a positive retry, got %d", retrySecs)
	}

	// No token quota configured: warming must not block the tenant.
	freeSvc := &mockRateLimitService{tenantRPS: 0, tenantTPM: 0}
	if decision, _, errCode := rateLimitCheckInternal(freeSvc, store, "", "tenant-free", "", "", ""); decision != 0 {
		t.Fatalf("warming must not deny a tenant without a token quota, got decision=%d errCode=%q", decision, errCode)
	}

	// First peer batch warms the store; the quota tenant serves again.
	store.ImportState([]rl.RateLimiterEntry{{KeyID: "t:tenant-warm", IsTenant: true}})
	if decision, _, errCode := rateLimitCheckInternal(quotaSvc, store, "", "tenant-warm", "", "", ""); decision != 0 {
		t.Fatalf("warmed store must admit the quota tenant, got decision=%d errCode=%q", decision, errCode)
	}
}

// TestTokenQuotaModelKeying pins the G6 contract: a model with its own
// tight quota trips independently — the same tenant's OTHER models and the
// aggregate stay admitted — and the model check only engages for requests
// that name the limited model.
func TestTokenQuotaModelKeying(t *testing.T) {
	store := rl.New()
	svc := &mockRateLimitService{
		tenantRPS: 0,
		tenantTPM: 100000, // generous aggregate
		modelTPM:  map[string]int{"expensive": 100},
	}

	// Overrun the expensive model's budget; the aggregate barely notices.
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "tenant-mk", "expensive", "", "", "", 150, 0, 0); allowed {
		t.Fatalf("charge 150/100 on the model bucket: expected denied")
	}

	// Requests for the expensive model are now denied at the gate...
	decision, _, errCode := rateLimitCheckInternal(svc, store, "", "tenant-mk", "", "", "expensive")
	if decision != 3 || errCode != "token_quota_exceeded" {
		t.Fatalf("gate for tripped model: expected deny token_quota_exceeded, got decision=%d errCode=%q", decision, errCode)
	}
	// ...while a cheap model under the same tenant serves on.
	if decision, _, errCode := rateLimitCheckInternal(svc, store, "", "tenant-mk", "", "", "cheap"); decision != 0 {
		t.Fatalf("gate for other model: expected allow, got decision=%d errCode=%q", decision, errCode)
	}
	// A request naming no model sees only the (healthy) aggregate.
	if decision, _, _ := rateLimitCheckInternal(svc, store, "", "tenant-mk", "", "", ""); decision != 0 {
		t.Fatalf("gate without model: expected allow")
	}
}

// TestTokenQuotaModelReserveRollback pins the dual-reservation atomicity:
// when the model bucket denies a reservation the aggregate claim taken a
// moment earlier must be released, or the tenant leaks admission headroom
// on every model-denied request.
func TestTokenQuotaModelReserveRollback(t *testing.T) {
	store := rl.New()
	svc := &mockRateLimitService{
		tenantTPM: 1000,
		modelTPM:  map[string]int{"tight": 100},
	}

	// Wants 500: fits the aggregate (1000), exceeds the model bucket (100).
	allowed, retrySecs, ep := tokenQuotaReserveInternal(svc, store, "tenant-rb", "tight", "", "", "", 500)
	if allowed || ep != 0 {
		t.Fatalf("model-bucket deny expected (allowed=%v ep=%d)", allowed, ep)
	}
	if retrySecs <= 0 {
		t.Errorf("model-bucket deny must advise a retry, got %d", retrySecs)
	}

	// The aggregate claim must have been rolled back: a 1000-token
	// reservation for a model with no quota of its own still fits.
	if allowed, _, _ := tokenQuotaReserveInternal(svc, store, "tenant-rb", "free", "", "", "", 1000); !allowed {
		t.Fatal("aggregate claim leaked: full-quota reservation no longer fits")
	}
}

// TestTokenQuotaModelWarming pins the cold-start interaction: a tenant with
// ONLY a model quota (no aggregate TPM) is still held during warmup for
// requests naming that model, and unaffected for models without quotas.
func TestTokenQuotaModelWarming(t *testing.T) {
	store := rl.New()
	store.StartQuotaWarmup(time.Hour, func(bool) {})
	svc := &mockRateLimitService{
		tenantTPM: 0,
		modelTPM:  map[string]int{"metered": 100},
	}

	if decision, _, errCode := rateLimitCheckInternal(svc, store, "", "tenant-mw", "", "", "metered"); decision != 3 || errCode != "token_quota_warming" {
		t.Fatalf("warming store must hold a model-quota tenant, got decision=%d errCode=%q", decision, errCode)
	}
	if decision, _, _ := rateLimitCheckInternal(svc, store, "", "tenant-mw", "", "", "unmetered"); decision != 0 {
		t.Fatal("warming must not hold a model without a quota")
	}
}

// TestTokenQuotaReserveInternalPerTenantBurst covers the wiring, not the
// bucket arithmetic: the tenant's configured capacity has to travel from the
// rate-limit service through the bridge into ReserveTokens. If it does not,
// both tenants below get the process-wide default and the narrow one is
// wrongly admitted — a config that reads back correctly over the API while
// enforcing nothing.
func TestTokenQuotaReserveInternalPerTenantBurst(t *testing.T) {
	// Default capacity: 900 of a 1000 TPM quota fits.
	wide := &mockRateLimitService{tenantRPS: 1000, tenantTPM: 1000}
	if allowed, _, _ := tokenQuotaReserveInternal(wide, rl.New(), "wide", "", "", "", "", 900); !allowed {
		t.Fatal("900/1000 must be admitted at the default burst")
	}

	// Same quota, capacity narrowed to 50%: the bucket holds 500, so a
	// 900-token claim can never be satisfied.
	narrow := &mockRateLimitService{tenantRPS: 1000, tenantTPM: 1000, tenantBurst: 50}
	allowed, retry, ep := tokenQuotaReserveInternal(narrow, rl.New(), "narrow", "", "", "", "", 900)
	if allowed {
		t.Fatal("900/1000 must be denied when the tenant's burst holds only 500")
	}
	if retry <= 0 {
		t.Fatal("a pre-admission deny must carry a retry-after hint")
	}
	if ep != 0 {
		t.Fatal("a claim larger than the bucket must not be recorded")
	}

	// The narrow tenant still works inside its own capacity.
	if allowed, _, _ := tokenQuotaReserveInternal(narrow, rl.New(), "narrow", "", "", "", "", 400); !allowed {
		t.Fatal("400 tokens must be admitted at a 50% burst of 1000 TPM")
	}
}

// TestTokenQuotaConsumeReleasesAVanishedBucket: a bucket whose limit stops
// resolving between admission and settlement still gets its claim back.
//
// Settlement re-resolves the ladder from the store, so the buckets it charges
// are the ones configured NOW. That is right for the charge and wrong for the
// release: an operator removing a per-model quota — or a single store read
// erroring mid-flight, which quotaBucketsFor tolerates by dropping the bucket
// — leaves the claim on a live bucket with nothing to hand it back. It then
// sits there until the epoch expires it, and every request the bucket
// measures in the meantime is measured against headroom that is not spent.
//
// The oracle is the NEXT reservation, because the leak has no other surface:
// the leaked claim is invisible in the charge, in the response and in the
// config. Observed as a live 429 token_quota_would_exceed against a bucket
// holding nothing (cicd/ai-jwtauth QOS-RES-003).
func TestTokenQuotaConsumeReleasesAVanishedBucket(t *testing.T) {
	store := rl.New()
	const tenant, model = "tenant-vanish", "gpt-4"

	// Admission: both the tenant aggregate and the tenant|model bucket take
	// a 900-token claim.
	armed := &mockRateLimitService{tenantTPM: 1000, modelTPM: map[string]int{model: 1000}}
	allowed, _, ep := tokenQuotaReserveInternal(armed, store, tenant, model, "", "", "", 900)
	if !allowed {
		t.Fatalf("reserve 900 against two 1000-token buckets: expected admitted")
	}

	// The model limit is removed while the request is in flight, so
	// settlement no longer resolves that bucket at all.
	vanished := &mockRateLimitService{tenantTPM: 1000}
	if allowed, _ := tokenQuotaConsumeInternal(vanished, store, tenant, model, "", "", "", 0, 900, ep); !allowed {
		t.Fatalf("settlement of a vanished bucket: expected allowed")
	}

	// The limit comes back. A fresh full-size request must fit: nothing was
	// charged, so the only thing that could refuse it is a claim nobody
	// released.
	allowed, _, _ = tokenQuotaReserveInternal(armed, store, tenant, model, "", "", "", 900)
	if !allowed {
		t.Fatalf("reserve 900 after the vanished bucket settled: refused against a claim " +
			"nobody released — the bucket is holding phantom spend for the rest of the epoch")
	}

	// Non-vacuity: the release must not be a blanket wipe either. A claim
	// that is still outstanding has to keep denying an over-large request,
	// or this test would pass against a settlement that simply zeroed
	// every bucket it touched.
	if allowed, _, _ := tokenQuotaReserveInternal(armed, store, tenant, model, "", "", "", 900); allowed {
		t.Fatalf("a second 900-token claim fitted alongside the first in a 1000-token " +
			"bucket — the release is wiping claims rather than returning one")
	}
}

// TestTokenQuotaReserveRollbackReleasesEveryEarlierBucket is the rollback
// half of the same property, pinned on the USER rungs rather than the tenant
// ones so a fix that only covered the tenant aggregate cannot satisfy both.
func TestTokenQuotaReserveRollbackReleasesEveryEarlierBucket(t *testing.T) {
	store := rl.New()
	const tenant, user, model = "tenant-rb", "u1", "gpt-4"

	// Ladder: tenant 10000, tenant|model 10000, user 10000, user|model 100.
	// A 900-token request clears the first three and cannot fit the last.
	svc := &mockRateLimitService{
		tenantTPM:    10000,
		modelTPM:     map[string]int{model: 10000},
		userRows:     map[string]cmn.UserRateLimitEntry{tenant + "|" + user: {TokensPerMin: 10000}},
		userModelTPM: map[string]int{tenant + "|" + user + "|" + model: 100},
	}
	if allowed, _, _ := tokenQuotaReserveInternal(svc, store, tenant, model, user, "", "", 900); allowed {
		t.Fatalf("reserve 900 against a 100-token user|model bucket: expected refused")
	}

	// Every claim the earlier rungs granted must be gone: a request on a
	// model with no tight bucket exercises exactly those rungs.
	plain := &mockRateLimitService{
		tenantTPM: 10000,
		userRows:  map[string]cmn.UserRateLimitEntry{tenant + "|" + user: {TokensPerMin: 10000}},
	}
	if allowed, _, _ := tokenQuotaReserveInternal(plain, store, tenant, "other", user, "", "", 10000); !allowed {
		t.Fatalf("the refused request left claims behind on the rungs that had admitted it")
	}
}

// TestTokenQuotaStatesFromRoutesEveryScopeToItsOwnSeries — each quota scope
// must reach the series named for what it keys on, and the tenant labels must
// still carry tenants and only tenants.
//
// The rate limiter's quota map is keyed by scope: the tenant aggregate and
// "<tenant>|<model>" keep bare keys, while the ladder buckets keep their wire
// prefix ("uq:", "um:", "kq:", "v:"). Splitting every key on the first "|"
// published an API key and a keyless service as tenants, and a user as a
// model. That defect was first fixed by DROPPING the ladder rows, which left
// per-user, per-key and per-VIP saturation exported nowhere; they are now
// routed onto their own series instead.
//
// This test must keep doing BOTH jobs. Asserting only the new routing would
// let the original defect back in through a row whose Scope is set AND whose
// Tenant carries a prefix, so the no-prefix sweep below stays, and it now
// covers User, KeyID and Service too — the labels a mis-parse would land on
// today.
func TestTokenQuotaStatesFromRoutesEveryScopeToItsOwnSeries(t *testing.T) {
	got := tokenQuotaStatesFrom([]rl.TokenQuotaUsage{
		{TenantID: "acme", Consumed: 10, Limit: 100},
		{TenantID: modelQuotaKey("acme", "gpt-4"), Consumed: 20, Limit: 200},
		{TenantID: rl.UserQuotaKey("acme", "bob"), Consumed: 30, Limit: 300},
		{TenantID: rl.UserModelQuotaKey("acme", "bob", "gpt-4"), Consumed: 40, Limit: 400},
		{TenantID: rl.KeyQuotaKey("ak-123"), Consumed: 50, Limit: 500},
		{TenantID: rl.VipSharedQuotaKey("10.0.0.1:8080"), Consumed: 60, Limit: 600},
	})

	want := []prom.TokenQuotaState{
		{Tenant: "acme", Model: "", Consumed: 10, Limit: 100},
		{Tenant: "acme", Model: "gpt-4", Consumed: 20, Limit: 200},
		{Scope: "user", Tenant: "acme", User: "bob", Consumed: 30, Limit: 300},
		{Scope: "user_model", Tenant: "acme", User: "bob", Model: "gpt-4", Consumed: 40, Limit: 400},
		{Scope: "key", KeyID: "ak-123", Consumed: 50, Limit: 500},
		{Scope: "vip", Service: "10.0.0.1:8080", Consumed: 60, Limit: 600},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d rows, got %d: %+v", len(want), len(got), got)
	}
	// Order-independent: the converter's output order follows its input, but
	// nothing downstream depends on it and pinning it would fail for a
	// reordering that broke nothing.
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing row %+v; got %+v", w, got)
		}
	}

	// Named, so a regression says which identity leaked and onto which label.
	// Every identity-bearing label, not just the tenant: a "uq:" that
	// survived into User would be the same defect one column across.
	for _, st := range got {
		for label, v := range map[string]string{
			"tenant": st.Tenant, "model": st.Model,
			"user": st.User, "key_id": st.KeyID, "service": st.Service,
		} {
			if v != "" && rl.HasReservedScopePrefix(v) {
				t.Errorf("a wire-prefixed identity reached label %s=%q (scope=%q, row %+v)", label, v, st.Scope, st)
			}
		}
	}
}

// TestScopedTokenQuotaStateDropsKeysItCannotParse — a key shape this build
// does not understand must produce NO series, never a guessed one.
//
// The delimiter cannot legally appear inside a tenant, user or model: the
// config surface refuses it, which is what makes the prefix inference
// unambiguous in the first place. So a field count that does not match means
// the key came from somewhere this build cannot reason about, and the only
// safe label for it is no label at all. Each case below would, under a
// "split and publish whatever falls out" parser, have produced a plausible
// looking series carrying the wrong identity.
func TestScopedTokenQuotaStateDropsKeysItCannotParse(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"user scope with no user", "uq:acme"},
		{"user scope with a model appended", "uq:acme|bob|gpt-4"},
		{"user-model scope missing the model", "um:acme|bob"},
		{"user-model scope with a fourth field", "um:acme|bob|gpt-4|extra"},
		{"key scope with an empty id", "kq:"},
		{"key scope carrying a delimiter", "kq:ak-123|bob"},
		{"vip scope with an empty service", "v:"},
		{"a scope this build does not know", "zz:something"},
		{"the wire spelling of a tenant, which must never be in the map", "t:acme"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if st, ok := scopedTokenQuotaState(rl.TokenQuotaUsage{
				TenantID: tc.key, Consumed: 1, Limit: 10,
			}); ok {
				t.Fatalf("key %q was parsed into %+v; an unparseable key must export nothing", tc.key, st)
			}
			// And it must not sneak out through the converter either.
			for _, g := range tokenQuotaStatesFrom([]rl.TokenQuotaUsage{{TenantID: tc.key, Consumed: 1, Limit: 10}}) {
				if g.Scope != "" {
					t.Fatalf("key %q reached the collector as %+v", tc.key, g)
				}
			}
		})
	}
}

// TestReserveSeesImportedDebtOnEveryLadderRung — the pre-admission
// reservation must refuse against a bucket whose debt arrived from a peer,
// on every rung, not just the tenant aggregate.
//
// This is the question a failover actually asks. The receiving node has
// never charged the bucket, so nothing has published a limit on it and
// IsTokenQuotaExceeded — the post-hoc gate — reads false whatever arrived.
// The reservation is the only stage that can refuse the FIRST request,
// because it takes the limit as an argument, from configuration, exactly
// as the request path supplies it.
//
// The tenant aggregate is the control: it is the rung that is known to
// work, so a ladder rung failing beside it is failing on its own account.
func TestReserveSeesImportedDebtOnEveryLadderRung(t *testing.T) {
	const tpm = 10
	const tenant = "imp-tenant"
	const user = "imp-user"
	const model = "imp-model"
	const keyID = "imp-key-id"
	const svcIdent = "10.0.0.1:2020"

	for _, tc := range []struct {
		name    string
		bucket  string
		svc     *mockRateLimitService
		tenant  string
		user    string
		keyID   string
		svcName string
	}{
		{
			name:   "tenant aggregate (control)",
			bucket: tenant,
			svc:    &mockRateLimitService{tenantTPM: tpm},
			tenant: tenant,
		},
		{
			name:   "tenant|model",
			bucket: modelQuotaKey(tenant, model),
			svc:    &mockRateLimitService{modelTPM: map[string]int{model: tpm}},
			tenant: tenant,
		},
		{
			name:   "per-user",
			bucket: rl.UserQuotaKey(tenant, user),
			svc: &mockRateLimitService{
				userRows: map[string]cmn.UserRateLimitEntry{tenant + "|" + user: {TokensPerMin: tpm}},
			},
			tenant: tenant,
			user:   user,
		},
		{
			name:   "per-user-per-model",
			bucket: rl.UserModelQuotaKey(tenant, user, model),
			svc: &mockRateLimitService{
				userModelTPM: map[string]int{tenant + "|" + user + "|" + model: tpm},
			},
			tenant: tenant,
			user:   user,
		},
		{
			name:   "per-key TPM",
			bucket: rl.KeyQuotaKey(keyID),
			svc: &mockRateLimitService{
				keyByID: map[string]*cmn.ApiKeySummary{keyID: {TokensPerMin: tpm}},
			},
			tenant: tenant,
			keyID:  keyID,
		},
		{
			name:   "per-VIP shared",
			bucket: rl.VipSharedQuotaKey(svcIdent),
			svc: &mockRateLimitService{
				defaults: map[string]cmn.RateLimitDefaultsEntry{
					"rule|" + svcIdent: {VipSharedTPM: tpm},
				},
			},
			svcName: svcIdent,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A peer's absolute snapshot, arriving at a node that has never
			// served this identity: one quota row, in debt, nothing else.
			src := rl.New()
			src.AllowTokens(tc.bucket, tpm, tpm, 0)
			src.AllowTokens(tc.bucket, tpm/5+1, tpm, 0)
			if !src.IsTokenQuotaExceeded(tc.bucket) {
				t.Fatalf("setup: %q is not in debt on the sending node", tc.bucket)
			}
			store := rl.New()
			store.ImportState(src.ExportState())

			mdl := model
			if tc.user == "" && tc.keyID == "" && tc.tenant == "" {
				mdl = "" // the keyless rung names no model
			}
			allowed, _, _ := tokenQuotaReserveInternal(tc.svc, store,
				tc.tenant, mdl, tc.user, tc.keyID, tc.svcName, 1)
			if allowed {
				t.Errorf("the imported debt on %q did not refuse the first request: "+
					"this rung admits one full request per node after a failover", tc.bucket)
			}
		})
	}
}
