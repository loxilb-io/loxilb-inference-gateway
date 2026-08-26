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
	"fmt"
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

	// Auth path: only enabled keys may authenticate. This filter is a security
	// invariant and must stay.
	sqlSelectAPIKeyByHash = "SELECT key_id, key_hash, tenant_id, name, allowed_models," +
		" rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled" +
		" FROM api_keys WHERE key_hash = ? AND enabled = 1"

	// Management list/get paths: return keys regardless of enabled state so an
	// operator can see, audit and re-enable a disabled key. The response carries
	// the `enabled` field to distinguish them; filtering on enabled=1 here made a
	// disabled key vanish entirely (list []/get 404) even though it still exists.
	sqlSelectAPIKeysByTenant = "SELECT key_id, tenant_id, name, allowed_models," +
		" rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled" +
		" FROM api_keys WHERE tenant_id = ?"

	sqlSelectKeyHashByID = "SELECT key_hash FROM api_keys WHERE key_id = ?"

	sqlSelectAPIKeyByID = "SELECT key_id, tenant_id, name, allowed_models," +
		" rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled" +
		" FROM api_keys WHERE key_id = ?"

	sqlSelectAllAPIKeys = "SELECT key_id, tenant_id, name, allowed_models," +
		" rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled" +
		" FROM api_keys"

	sqlUpdateAPIKeyEnabled = "UPDATE api_keys SET enabled = ? WHERE key_id = ?"

	sqlDeleteAPIKeyByID = "DELETE FROM api_keys WHERE key_id = ?"

	sqlReplaceIntoTenantRateLimit = "REPLACE INTO tenant_rate_limits" +
		" (tenant_id, rps, tokens_per_min, updated_at) VALUES (?, ?, ?, ?)"
	sqlUpdateAPIKeyAllowedModels = "UPDATE api_keys SET allowed_models = ? WHERE key_id = ?"
	sqlSelectTenantRateLimit     = "SELECT rps, tokens_per_min FROM tenant_rate_limits WHERE tenant_id = ?"
	sqlSelectTenantRateLimitFull = "SELECT rps, tokens_per_min, updated_at FROM tenant_rate_limits WHERE tenant_id = ?"

	sqlReplaceIntoTenantModelRateLimit = "REPLACE INTO tenant_model_rate_limits" +
		" (tenant_id, model, tokens_per_min, updated_at) VALUES (?, ?, ?, ?)"
	sqlDeleteTenantModelRateLimit  = "DELETE FROM tenant_model_rate_limits WHERE tenant_id = ? AND model = ?"
	sqlSelectTenantModelRateLimit  = "SELECT tokens_per_min FROM tenant_model_rate_limits WHERE tenant_id = ? AND model = ?"
	sqlSelectTenantModelRateLimits = "SELECT model, tokens_per_min FROM tenant_model_rate_limits WHERE tenant_id = ?"
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
	if err := s.dbReady(); err != nil {
		return "", "", err
	}
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

	// Layer 2: database fallback. Fails closed (401 upstream) when the DB is
	// unavailable — a cache hit above still validates during a short outage.
	if err := s.dbReady(); err != nil {
		return nil, err
	}
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
	if err := s.dbReady(); err != nil {
		return err
	}
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

// DeleteAPIKey permanently removes the API key identified by keyID from the
// database and synchronously evicts it from the cache. Unlike RevokeAPIKey,
// which only flips enabled=false (a reversible soft-disable that stays visible
// to the management endpoints), this is a hard delete: a subsequent lookup
// returns "not found". This backs DELETE /config/ai/apikey/{key_id}.
func (s *UserService) DeleteAPIKey(keyID string) error {
	if err := s.dbReady(); err != nil {
		return err
	}
	// Fetch the hash so we can evict the correct cache entry.
	var keyHash string
	err := s.DB.QueryRow(sqlSelectKeyHashByID, keyID).Scan(&keyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			tk.LogIt(tk.LogWarning, "[AIGateway] API key not found for deletion: %s\n", keyID)
			return errors.New("API key not found")
		}
		tk.LogIt(tk.LogError, "[AIGateway] Failed to fetch key hash for deletion: %v\n", err)
		return err
	}

	if _, err = s.DB.Exec(sqlDeleteAPIKeyByID, keyID); err != nil {
		tk.LogIt(tk.LogError, "[AIGateway] Failed to delete API key %s: %v\n", keyID, err)
		return err
	}

	// Synchronous cache eviction — must complete before returning.
	s.Cache.Delete(keyHash)
	s.Cache.Delete("keyid:" + keyID)

	tk.LogIt(tk.LogInfo, "[AIGateway] Deleted API key %s\n", keyID)
	return nil
}

// PatchAPIKey updates allowed_models and/or enabled for an existing API key.
// Only non-nil fields are updated. Cache is evicted after a successful DB update.
func (s *UserService) PatchAPIKey(keyID string, allowedModels []string, enabled *bool) error {
	if err := s.dbReady(); err != nil {
		return err
	}
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
	if err := s.dbReady(); err != nil {
		return err
	}
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

	// No configured-limit signal is distinguishable from DB-unavailable here;
	// (0, 0) means "no limit", matching the no-row case. The datapath key check
	// has already failed closed by this point if the DB is down and uncached.
	if s.dbReady() != nil {
		return 0, 0
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

// SetTenantModelRateLimit upserts one per-model token quota for a tenant
// into the tenant_model_rate_limits table. tokensPerMin <= 0 removes the
// row: the model falls back to the tenant-level quota alone. The cache is
// refreshed so subsequent GetTenantModelRateLimit calls see the new value
// without a database round-trip.
func (s *UserService) SetTenantModelRateLimit(tenantID, model string, tokensPerMin int) error {
	if err := s.dbReady(); err != nil {
		return err
	}
	if model == "" || strings.ContainsAny(tenantID+model, "|") {
		// "|" is the composite quota-key delimiter (tenant|model): a name
		// containing it would alias another tenant/model pair's bucket.
		return fmt.Errorf("invalid tenant/model name for model rate limit (%q/%q)", tenantID, model)
	}
	cacheKey := "rlm:" + tenantID + "|" + model
	if tokensPerMin <= 0 {
		if _, err := s.DB.Exec(sqlDeleteTenantModelRateLimit, tenantID, model); err != nil {
			tk.LogIt(tk.LogError, "[AIGateway] Failed to clear model rate limit for %s/%s: %v\n", tenantID, model, err)
			return err
		}
		s.Cache.Delete(cacheKey)
		tk.LogIt(tk.LogInfo, "[AIGateway] Cleared model rate limit for tenant %s model %s\n", tenantID, model)
		return nil
	}
	now := time.Now().UTC()
	if _, err := s.DB.Exec(sqlReplaceIntoTenantModelRateLimit, tenantID, model, tokensPerMin, now); err != nil {
		tk.LogIt(tk.LogError, "[AIGateway] Failed to set model rate limit for %s/%s: %v\n", tenantID, model, err)
		return err
	}
	s.Cache.Set(cacheKey, &rateLimitCacheEntry{tokensPerMin: tokensPerMin}, CacheExpirationTime*time.Minute)
	tk.LogIt(tk.LogInfo, "[AIGateway] Set model rate limit for tenant %s model %s: tokensPerMin=%d\n", tenantID, model, tokensPerMin)
	return nil
}

// GetTenantModelRateLimit returns the per-model token quota for a tenant,
// or 0 when the pair has no model-specific limit configured (the tenant
// aggregate quota, if any, still applies). Cache-first, same posture as
// GetTenantRateLimit: no-row and DB-unavailable both read as "no limit".
func (s *UserService) GetTenantModelRateLimit(tenantID, model string) (tokensPerMin int) {
	if model == "" {
		return 0
	}
	cacheKey := "rlm:" + tenantID + "|" + model
	if cached, found := s.Cache.Get(cacheKey); found {
		if entry, ok := cached.(*rateLimitCacheEntry); ok {
			return entry.tokensPerMin
		}
	}
	if s.dbReady() != nil {
		return 0
	}
	var t int
	err := s.DB.QueryRow(sqlSelectTenantModelRateLimit, tenantID, model).Scan(&t)
	if err != nil {
		if err != sql.ErrNoRows {
			tk.LogIt(tk.LogError, "[AIGateway] Failed to get model rate limit for %s/%s: %v\n", tenantID, model, err)
			return 0
		}
		// Cache the miss too: an unlimited model on a busy tenant would
		// otherwise pay one DB round-trip per request.
		t = 0
	}
	s.Cache.Set(cacheKey, &rateLimitCacheEntry{tokensPerMin: t}, CacheExpirationTime*time.Minute)
	return t
}

// GetTenantModelRateLimits returns every configured per-model quota for a
// tenant, for the config GET surface. Reads the database directly (config
// reads are not on the datapath).
func (s *UserService) GetTenantModelRateLimits(tenantID string) ([]cmn.TenantModelRateLimit, error) {
	if err := s.dbReady(); err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(sqlSelectTenantModelRateLimits, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cmn.TenantModelRateLimit
	for rows.Next() {
		var m cmn.TenantModelRateLimit
		if err := rows.Scan(&m.Model, &m.TokensPerMin); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
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

	if err := s.dbReady(); err != nil {
		return nil, err
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
	if err := s.dbReady(); err != nil {
		return nil, err
	}
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
	if err := s.dbReady(); err != nil {
		return nil, err
	}
	var entry cmn.TenantRateLimitEntry
	entry.TenantID = tenantID

	err := s.DB.QueryRow(sqlSelectTenantRateLimitFull, tenantID).Scan(
		&entry.RPS, &entry.TokensPerMin, &entry.UpdatedAt)
	noTenantRow := err == sql.ErrNoRows
	if err != nil && !noTenantRow {
		tk.LogIt(tk.LogError, "[AIGateway] Failed to get rate limit entry for tenant %s: %v\n", tenantID, err)
		return nil, err
	}

	entry.ModelLimits, err = s.GetTenantModelRateLimits(tenantID)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIGateway] Failed to get model rate limits for tenant %s: %v\n", tenantID, err)
		return nil, err
	}
	// A tenant configured only with per-model quotas has no aggregate row —
	// still a real configuration worth returning.
	if noTenantRow && len(entry.ModelLimits) == 0 {
		tk.LogIt(tk.LogWarning, "[AIGateway] Rate limit not found for tenant: %s\n", tenantID)
		return nil, errors.New("tenant rate limit not found")
	}

	return &entry, nil
}
