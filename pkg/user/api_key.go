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
package user

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	tk "github.com/loxilb-io/loxilib"

	cmn "github.com/loxilb-io/loxilb/common"
)

const (
	apiKeyPrefix = "lxb_"

	sqlInsertAPIKey = "INSERT INTO api_keys" +
		" (key_id, key_hash, tenant_id, name, allowed_models," +
		" rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled)" +
		" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

	sqlSelectAPIKeyByHash = "SELECT key_id, key_hash, tenant_id, name, allowed_models," +
		" rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled" +
		" FROM api_keys WHERE key_hash = ? AND enabled = 1"

	sqlSelectAPIKeysByTenant = "SELECT key_id, tenant_id, name, allowed_models," +
		" rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled" +
		" FROM api_keys WHERE tenant_id = ? AND enabled = 1"

	sqlSelectKeyHashByID = "SELECT key_hash FROM api_keys WHERE key_id = ?"

	sqlSelectAPIKeyByID = "SELECT key_id, tenant_id, name, allowed_models," +
		" rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled" +
		" FROM api_keys WHERE key_id = ? AND enabled = 1"

	sqlSelectAllAPIKeys = "SELECT key_id, tenant_id, name, allowed_models," +
		" rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled" +
		" FROM api_keys WHERE enabled = 1"

	sqlUpdateAPIKeyEnabled = "UPDATE api_keys SET enabled = ? WHERE key_id = ?"

	sqlReplaceIntoTenantRateLimit = "REPLACE INTO tenant_rate_limits" +
		" (tenant_id, rps, tokens_per_min, updated_at) VALUES (?, ?, ?, ?)"
	sqlUpdateAPIKeyAllowedModels = "UPDATE api_keys SET allowed_models = ? WHERE key_id = ?"
	sqlSelectTenantRateLimit     = "SELECT rps, tokens_per_min FROM tenant_rate_limits WHERE tenant_id = ?"
	sqlSelectTenantRateLimitFull = "SELECT rps, tokens_per_min, updated_at FROM tenant_rate_limits WHERE tenant_id = ?"
)

// rateLimitCacheEntry holds tenant rate limit values cached in memory.
type rateLimitCacheEntry struct {
	rps          int
	tokensPerMin int
}

// CreateAPIKey generates a new API key, stores only its SHA-256 hash in the database,
// and returns the raw key once to the caller. The entry provides metadata (TenantID,
// Name, AllowedModels, etc.); KeyID and raw key are generated internally.
func (s *UserService) CreateAPIKey(entry cmn.ApiKeyEntry) (string, string, error) {
	// Generate 32 cryptographically random bytes.
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		tk.LogIt(tk.LogError, "[AIGateway] Failed to generate random bytes: %v\n", err)
		return "", "", err
	}

	// KeyID is derived from the first 16 random bytes (32 hex chars, fits VARCHAR(64)).
	keyID := hex.EncodeToString(rawBytes[:16])
	// Raw key exposed to the caller exactly once.
	rawKey := apiKeyPrefix + hex.EncodeToString(rawBytes)

	// Store only the SHA-256 hash of the raw key.
	h := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(h[:])

	allowedModels := strings.Join(entry.AllowedModels, ",")
	now := time.Now().UTC()

	_, err := s.DB.Exec(sqlInsertAPIKey,
		keyID, keyHash, entry.TenantID, entry.Name,
		allowedModels, entry.RateLimitRPS, entry.BurstSize, entry.TokensPerMin,
		now, entry.ExpiresAt, entry.Enabled)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIGateway] Failed to create API key for tenant %s: %v\n", entry.TenantID, err)
		return "", "", err
	}

	tk.LogIt(tk.LogInfo, "[AIGateway] Created API key %s for tenant %s\n", keyID, entry.TenantID)
	return rawKey, keyID, nil
}

// ValidateAPIKey checks whether rawKey is a valid, enabled API key.
// Cache is checked first (go-cache, ~5 min TTL); the DB is used only on a miss.
// Cache hits complete without any syscalls, well under the 5 µs target.
func (s *UserService) ValidateAPIKey(rawKey string) (*cmn.ApiKeyEntry, error) {
	// Compute the hash used as both the cache key and the DB lookup value.
	h := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(h[:])

	// Layer 1: in-memory cache (no syscalls on hit).
	if cached, found := s.Cache.Get(keyHash); found {
		entry, ok := cached.(*cmn.ApiKeyEntry)
		if ok {
			return entry, nil
		}
	}

	// Layer 2: database fallback.
	var entry cmn.ApiKeyEntry
	var allowedModels string
	var expiresAt sql.NullTime

	err := s.DB.QueryRow(sqlSelectAPIKeyByHash, keyHash).Scan(
		&entry.KeyID, &entry.KeyHash, &entry.TenantID, &entry.Name,
		&allowedModels, &entry.RateLimitRPS, &entry.BurstSize, &entry.TokensPerMin,
		&entry.CreatedAt, &expiresAt, &entry.Enabled)
	if err != nil {
		if err == sql.ErrNoRows {
			tk.LogIt(tk.LogWarning, "[AIGateway] API key not found or disabled\n")
			return nil, errors.New("invalid or disabled API key")
		}
		tk.LogIt(tk.LogError, "[AIGateway] Failed to validate API key: %v\n", err)
		return nil, err
	}

	if allowedModels != "" {
		entry.AllowedModels = strings.Split(allowedModels, ",")
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		entry.ExpiresAt = &t
	}

	// Populate cache for subsequent lookups.
	s.Cache.Set(keyHash, &entry, CacheExpirationTime*time.Minute)

	return &entry, nil
}

// RevokeAPIKey disables the API key identified by keyID in the database and
// synchronously evicts it from the cache before returning.
func (s *UserService) RevokeAPIKey(keyID string) error {
	// Fetch the hash so we can evict the correct cache entry.
	var keyHash string
	err := s.DB.QueryRow(sqlSelectKeyHashByID, keyID).Scan(&keyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			tk.LogIt(tk.LogWarning, "[AIGateway] API key not found for revocation: %s\n", keyID)
			return errors.New("API key not found")
		}
		tk.LogIt(tk.LogError, "[AIGateway] Failed to fetch key hash for revocation: %v\n", err)
		return err
	}

	// Persist the revocation.
	if _, err = s.DB.Exec(sqlUpdateAPIKeyEnabled, false, keyID); err != nil {
		tk.LogIt(tk.LogError, "[AIGateway] Failed to revoke API key %s: %v\n", keyID, err)
		return err
	}

	// Synchronous cache eviction — must complete before returning.
	s.Cache.Delete(keyHash)
	s.Cache.Delete("keyid:" + keyID)

	tk.LogIt(tk.LogInfo, "[AIGateway] Revoked API key %s\n", keyID)
	return nil
}

// PatchAPIKey updates allowed_models and/or enabled for an existing API key.
// Only non-nil fields are updated. Cache is evicted after a successful DB update.
func (s *UserService) PatchAPIKey(keyID string, allowedModels []string, enabled *bool) error {
	// Fetch hash for cache eviction.
	var keyHash string
	err := s.DB.QueryRow(sqlSelectKeyHashByID, keyID).Scan(&keyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("API key not found")
		}
		return err
	}

	if allowedModels != nil {
		models := strings.Join(allowedModels, ",")
		if _, err = s.DB.Exec(sqlUpdateAPIKeyAllowedModels, models, keyID); err != nil {
			tk.LogIt(tk.LogError, "[AIGateway] Failed to patch allowed_models for key %s: %v\n", keyID, err)
			return err
		}
	}

	if enabled != nil {
		if _, err = s.DB.Exec(sqlUpdateAPIKeyEnabled, *enabled, keyID); err != nil {
			tk.LogIt(tk.LogError, "[AIGateway] Failed to patch enabled for key %s: %v\n", keyID, err)
			return err
		}
	}

	// Evict cache so next request re-reads updated state from DB.
	s.Cache.Delete(keyHash)
	s.Cache.Delete("keyid:" + keyID)

	tk.LogIt(tk.LogInfo, "[AIGateway] Patched API key %s\n", keyID)
	return nil
}

// SetTenantRateLimit upserts the per-tenant rate limit into the tenant_rate_limits
// table and refreshes the in-memory cache so that subsequent GetTenantRateLimit
// calls return the new values without a round-trip to the database.
func (s *UserService) SetTenantRateLimit(tenantID string, rps, tokensPerMin int) error {
	now := time.Now().UTC()
	if _, err := s.DB.Exec(sqlReplaceIntoTenantRateLimit, tenantID, rps, tokensPerMin, now); err != nil {
		tk.LogIt(tk.LogError, "[AIGateway] Failed to set rate limit for tenant %s: %v\n", tenantID, err)
		return err
	}
	cacheKey := "rl:" + tenantID
	s.Cache.Set(cacheKey, &rateLimitCacheEntry{rps: rps, tokensPerMin: tokensPerMin}, CacheExpirationTime*time.Minute)
	tk.LogIt(tk.LogInfo, "[AIGateway] Set rate limit for tenant %s: rps=%d tokensPerMin=%d\n", tenantID, rps, tokensPerMin)
	return nil
}

// GetTenantRateLimit returns the per-tenant rate limit values.
// The in-memory cache is checked first; on a miss the database is queried and
// the result is cached. If the tenant has no configured limits, (0, 0) is returned.
func (s *UserService) GetTenantRateLimit(tenantID string) (rps, tokensPerMin int) {
	cacheKey := "rl:" + tenantID
	if cached, found := s.Cache.Get(cacheKey); found {
		if entry, ok := cached.(*rateLimitCacheEntry); ok {
			return entry.rps, entry.tokensPerMin
		}
	}

	var r, t int
	err := s.DB.QueryRow(sqlSelectTenantRateLimit, tenantID).Scan(&r, &t)
	if err != nil {
		if err != sql.ErrNoRows {
			tk.LogIt(tk.LogError, "[AIGateway] Failed to get rate limit for tenant %s: %v\n", tenantID, err)
		}
		return 0, 0
	}

	s.Cache.Set(cacheKey, &rateLimitCacheEntry{rps: r, tokensPerMin: t}, CacheExpirationTime*time.Minute)
	return r, t
}

// GetAPIKeyByID retrieves API key metadata by key ID (without the hash).
// The in-memory cache is checked first (cache key "keyid:<keyID>"); the DB
// is queried only on a miss, and the result is cached before returning.
// Returns nil, error if not found.
func (s *UserService) GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error) {
	cacheKey := "keyid:" + keyID
	if cached, found := s.Cache.Get(cacheKey); found {
		if summary, ok := cached.(*cmn.ApiKeySummary); ok {
			return summary, nil
		}
	}

	var key cmn.ApiKeySummary
	var allowedModels string
	var expiresAt sql.NullTime

	err := s.DB.QueryRow(sqlSelectAPIKeyByID, keyID).Scan(
		&key.KeyID, &key.TenantID, &key.Name,
		&allowedModels, &key.RateLimitRPS, &key.BurstSize, &key.TokensPerMin,
		&key.CreatedAt, &expiresAt, &key.Enabled)
	if err != nil {
		if err == sql.ErrNoRows {
			tk.LogIt(tk.LogWarning, "[AIGateway] API key not found: %s\n", keyID)
			return nil, errors.New("API key not found")
		}
		tk.LogIt(tk.LogError, "[AIGateway] Failed to get API key %s: %v\n", keyID, err)
		return nil, err
	}

	if allowedModels != "" {
		key.AllowedModels = strings.Split(allowedModels, ",")
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		key.ExpiresAt = &t
	}

	s.Cache.Set(cacheKey, &key, CacheExpirationTime*time.Minute)

	return &key, nil
}

// ListAPIKeys returns a summary of API keys. If tenantID is non-empty, filters
// by tenant; if empty, returns all keys across all tenants.
func (s *UserService) ListAPIKeys(tenantID string) ([]cmn.ApiKeySummary, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID == "" {
		rows, err = s.DB.Query(sqlSelectAllAPIKeys)
	} else {
		rows, err = s.DB.Query(sqlSelectAPIKeysByTenant, tenantID)
	}
	if err != nil {
		tk.LogIt(tk.LogError, "[AIGateway] Failed to list API keys (tenant=%q): %v\n", tenantID, err)
		return nil, err
	}
	defer rows.Close()

	var keys []cmn.ApiKeySummary
	for rows.Next() {
		var key cmn.ApiKeySummary
		var allowedModels string
		var expiresAt sql.NullTime

		if err := rows.Scan(
			&key.KeyID, &key.TenantID, &key.Name,
			&allowedModels, &key.RateLimitRPS, &key.BurstSize, &key.TokensPerMin,
			&key.CreatedAt, &expiresAt, &key.Enabled); err != nil {
			tk.LogIt(tk.LogError, "[AIGateway] Failed to scan API key row: %v\n", err)
			return nil, err
		}

		if allowedModels != "" {
			key.AllowedModels = strings.Split(allowedModels, ",")
		}
		if expiresAt.Valid {
			t := expiresAt.Time
			key.ExpiresAt = &t
		}

		keys = append(keys, key)
	}

	if err = rows.Err(); err != nil {
		tk.LogIt(tk.LogError, "[AIGateway] Row iteration error listing API keys (tenant=%q): %v\n", tenantID, err)
		return nil, err
	}

	tk.LogIt(tk.LogInfo, "[AIGateway] Listed %d API keys (tenant=%q)\n", len(keys), tenantID)
	return keys, nil
}

// GetTenantRateLimitEntry returns the full rate limit entry (including updated_at) for a tenant.
// Returns nil, error if not found.
func (s *UserService) GetTenantRateLimitEntry(tenantID string) (*cmn.TenantRateLimitEntry, error) {
	var entry cmn.TenantRateLimitEntry
	entry.TenantID = tenantID

	err := s.DB.QueryRow(sqlSelectTenantRateLimitFull, tenantID).Scan(
		&entry.RPS, &entry.TokensPerMin, &entry.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			tk.LogIt(tk.LogWarning, "[AIGateway] Rate limit not found for tenant: %s\n", tenantID)
			return nil, errors.New("tenant rate limit not found")
		}
		tk.LogIt(tk.LogError, "[AIGateway] Failed to get rate limit entry for tenant %s: %v\n", tenantID, err)
		return nil, err
	}

	return &entry, nil
}
