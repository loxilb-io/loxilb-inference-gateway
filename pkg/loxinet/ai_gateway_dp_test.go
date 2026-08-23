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
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
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
	keyByID   map[string]*cmn.ApiKeySummary
}

func (m *mockRateLimitService) GetTenantRateLimit(_ string) (int, int) {
	return m.tenantRPS, m.tenantTPM
}

func (m *mockRateLimitService) GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error) {
	if m.keyByID != nil {
		if key, ok := m.keyByID[keyID]; ok {
			return key, nil
		}
	}
	return nil, errors.New("API key not found")
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
		decision, _, errCode := rateLimitCheckInternal(svc, store, "key-limited", "tenant-1")
		if decision != 0 {
			t.Fatalf("request %d: expected allow (decision=0), got decision=%d errorCode=%q", i, decision, errCode)
		}
	}

	// Third request must be rate-limited.
	decision, retrySecs, errCode := rateLimitCheckInternal(svc, store, "key-limited", "tenant-1")
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
		decision, _, errCode := rateLimitCheckInternal(svc, store, "key-unlimited", "tenant-2")
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
	decision, _, _ := rateLimitCheckInternal(svc, store, "key-norlimit", "tenant-3")
	if decision != 0 {
		t.Fatalf("request 1: expected allow, got decision=%d", decision)
	}

	// Second request must be tenant-rate-limited with tenant_quota_exceeded.
	decision, _, errCode := rateLimitCheckInternal(svc, store, "key-norlimit", "tenant-3")
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
	allowed, _ := tokenQuotaConsumeInternal(svc, store, "tenant-tpm", 60)
	if !allowed {
		t.Fatalf("charge 60/100: expected allowed")
	}
	if decision, _, _ := rateLimitCheckInternal(svc, store, "key-tpm", "tenant-tpm"); decision != 0 {
		t.Fatalf("gate after 60/100: expected allow, got decision=%d", decision)
	}

	// Charge 50 more (110 > 100): denied, exceeded flag latches.
	allowed, retrySecs := tokenQuotaConsumeInternal(svc, store, "tenant-tpm", 50)
	if allowed {
		t.Fatalf("charge 110/100: expected denied")
	}
	if retrySecs <= 0 {
		t.Errorf("expected positive retrySecs, got %d", retrySecs)
	}

	// The NEXT request must be denied 429 with token_quota_exceeded.
	decision, _, errCode := rateLimitCheckInternal(svc, store, "key-tpm", "tenant-tpm")
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
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "tenant-unlim", 1<<30); !allowed {
		t.Fatalf("unlimited tenant: expected allowed")
	}
	if store.IsTokenQuotaExceeded("tenant-unlim") {
		t.Errorf("unlimited tenant: exceeded flag must not latch")
	}

	// nil service (userservice disabled) → allowed.
	if allowed, _ := tokenQuotaConsumeInternal(nil, store, "tenant-nosvc", 500); !allowed {
		t.Fatalf("nil service: expected allowed")
	}

	// Non-positive count / empty tenant → allowed no-ops.
	svc2 := &mockRateLimitService{tenantTPM: 10}
	if allowed, _ := tokenQuotaConsumeInternal(svc2, store, "tenant-x", 0); !allowed {
		t.Fatalf("count 0: expected allowed")
	}
	if allowed, _ := tokenQuotaConsumeInternal(svc2, store, "", 50); !allowed {
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
			name:          "invalid key (service returns error) returns deny_401",
			svc:           &mockAPIKeyValidator{err: errors.New("invalid or disabled API key")},
			rawKey:        "lxb_bad_key",
			modelName:     "gpt-4",
			wantDecision:  1,
			wantErrorCode: "invalid_api_key",
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
