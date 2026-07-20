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
package common

import (
	"encoding/json"
	"testing"
	"time"
)

func TestApiKeyEntryJSONMarshal(t *testing.T) {
	now := time.Date(2026, 2, 24, 0, 0, 0, 0, time.UTC)
	expires := now.Add(24 * time.Hour)

	entry := ApiKeyEntry{
		KeyID:         "key-001",
		KeyHash:       "secret-hash-value",
		TenantID:      "tenant-001",
		Name:          "test key",
		AllowedModels: []string{"gpt-4", "claude-3"},
		RateLimitRPS:  100,
		BurstSize:     200,
		TokensPerMin:  1000,
		CreatedAt:     now,
		ExpiresAt:     &expires,
		Enabled:       true,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify KeyHash is absent from JSON output
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}
	if _, exists := raw["keyHash"]; exists {
		t.Error("keyHash should not be present in JSON output (json:\"-\" tag)")
	}
	if _, exists := raw["KeyHash"]; exists {
		t.Error("KeyHash should not be present in JSON output (json:\"-\" tag)")
	}

	// Unmarshal round-trip preserves all other fields
	var decoded ApiKeyEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal round-trip failed: %v", err)
	}
	if decoded.KeyID != entry.KeyID {
		t.Errorf("KeyID mismatch: got %q, want %q", decoded.KeyID, entry.KeyID)
	}
	if decoded.KeyHash != "" {
		t.Errorf("KeyHash should be empty after JSON round-trip, got %q", decoded.KeyHash)
	}
	if decoded.TenantID != entry.TenantID {
		t.Errorf("TenantID mismatch: got %q, want %q", decoded.TenantID, entry.TenantID)
	}
	if decoded.Name != entry.Name {
		t.Errorf("Name mismatch: got %q, want %q", decoded.Name, entry.Name)
	}
	if len(decoded.AllowedModels) != len(entry.AllowedModels) {
		t.Errorf("AllowedModels length mismatch: got %d, want %d", len(decoded.AllowedModels), len(entry.AllowedModels))
	} else {
		for i := range entry.AllowedModels {
			if decoded.AllowedModels[i] != entry.AllowedModels[i] {
				t.Errorf("AllowedModels[%d] mismatch: got %q, want %q", i, decoded.AllowedModels[i], entry.AllowedModels[i])
			}
		}
	}
	if decoded.RateLimitRPS != entry.RateLimitRPS {
		t.Errorf("RateLimitRPS mismatch: got %d, want %d", decoded.RateLimitRPS, entry.RateLimitRPS)
	}
	if decoded.BurstSize != entry.BurstSize {
		t.Errorf("BurstSize mismatch: got %d, want %d", decoded.BurstSize, entry.BurstSize)
	}
	if decoded.TokensPerMin != entry.TokensPerMin {
		t.Errorf("TokensPerMin mismatch: got %d, want %d", decoded.TokensPerMin, entry.TokensPerMin)
	}
	if !decoded.CreatedAt.Equal(entry.CreatedAt) {
		t.Errorf("CreatedAt mismatch: got %v, want %v", decoded.CreatedAt, entry.CreatedAt)
	}
	if decoded.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil after round-trip")
	} else if !decoded.ExpiresAt.Equal(*entry.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch: got %v, want %v", *decoded.ExpiresAt, *entry.ExpiresAt)
	}
	if decoded.Enabled != entry.Enabled {
		t.Errorf("Enabled mismatch: got %v, want %v", decoded.Enabled, entry.Enabled)
	}
}

func TestApiKeyEntryNilExpiresAt(t *testing.T) {
	entry := ApiKeyEntry{
		KeyID:     "key-002",
		KeyHash:   "another-secret",
		TenantID:  "tenant-002",
		Name:      "no-expiry key",
		CreatedAt: time.Now(),
		Enabled:   false,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// expiresAt should be absent when nil (omitempty)
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}
	if _, exists := raw["expiresAt"]; exists {
		t.Error("expiresAt should be absent when nil (omitempty)")
	}

	var decoded ApiKeyEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal round-trip failed: %v", err)
	}
	if decoded.ExpiresAt != nil {
		t.Errorf("ExpiresAt should remain nil after round-trip, got %v", decoded.ExpiresAt)
	}
	if decoded.Enabled != false {
		t.Error("Enabled should be false after round-trip")
	}
}
