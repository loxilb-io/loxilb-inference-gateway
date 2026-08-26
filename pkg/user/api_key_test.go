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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/patrickmn/go-cache"

	cmn "github.com/loxilb-io/loxilb/common"
)

// setupTestDB opens an in-memory SQLite database and creates the tables
// required by the API key service. SQLite is used as a MySQL stand-in so
// no real database is needed for unit tests.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite3: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS api_keys (
		key_id TEXT PRIMARY KEY,
		key_hash TEXT,
		tenant_id TEXT,
		name TEXT DEFAULT '',
		allowed_models TEXT DEFAULT '',
		rate_limit_rps INTEGER DEFAULT 0,
		burst_size INTEGER DEFAULT 0,
		tokens_per_min INTEGER DEFAULT 0,
		created_at DATETIME,
		expires_at DATETIME,
		enabled INTEGER DEFAULT 1
	)`)
	if err != nil {
		t.Fatalf("create api_keys table: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS tenant_rate_limits (
		tenant_id TEXT PRIMARY KEY,
		rps INTEGER DEFAULT 0,
		tokens_per_min INTEGER DEFAULT 0,
		burst_pct INTEGER DEFAULT 0,
		updated_at DATETIME
	)`)
	if err != nil {
		t.Fatalf("create tenant_rate_limits table: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS tenant_model_rate_limits (
		tenant_id TEXT,
		model TEXT,
		tokens_per_min INTEGER DEFAULT 0,
		updated_at DATETIME,
		PRIMARY KEY (tenant_id, model)
	)`)
	if err != nil {
		t.Fatalf("create tenant_model_rate_limits table: %v", err)
	}
	return db
}

// newTestService returns a UserService backed by an in-memory SQLite database.
func newTestService(t *testing.T) *UserService {
	t.Helper()
	return &UserService{
		DB:    setupTestDB(t),
		Cache: cache.New(5*time.Minute, 10*time.Minute),
	}
}

// TestCreateAPIKey verifies that a new API key is generated and stored.
func TestCreateAPIKey(t *testing.T) {
	svc := newTestService(t)
	entry := cmn.ApiKeyEntry{
		TenantID:      "tenant1",
		Name:          "test key",
		AllowedModels: []string{"gpt-4", "gpt-3.5"},
		RateLimitRPS:  100,
		BurstSize:     10,
		TokensPerMin:  1000,
		Enabled:       true,
	}
	rawKey, _, err := svc.CreateAPIKey(entry)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if rawKey == "" {
		t.Fatal("expected non-empty raw key")
	}
	if !strings.HasPrefix(rawKey, apiKeyPrefix) {
		t.Fatalf("raw key must start with %q, got %q", apiKeyPrefix, rawKey[:len(apiKeyPrefix)])
	}
}

// TestValidateAPIKey_CacheMiss_DBHit confirms a cache-miss path queries the DB
// and returns the stored key entry.
func TestValidateAPIKey_CacheMiss_DBHit(t *testing.T) {
	svc := newTestService(t)
	entry := cmn.ApiKeyEntry{
		TenantID:      "tenant1",
		AllowedModels: []string{"gpt-4"},
		RateLimitRPS:  50,
		Enabled:       true,
	}
	rawKey, _, err := svc.CreateAPIKey(entry)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	// Flush cache to force a DB lookup on the next call.
	svc.Cache.Flush()

	result, err := svc.ValidateAPIKey(rawKey)
	if err != nil {
		t.Fatalf("ValidateAPIKey (DB hit): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil ApiKeyEntry")
	}
	if result.TenantID != "tenant1" {
		t.Fatalf("TenantID: want tenant1, got %s", result.TenantID)
	}
	if len(result.AllowedModels) != 1 || result.AllowedModels[0] != "gpt-4" {
		t.Fatalf("AllowedModels: want [gpt-4], got %v", result.AllowedModels)
	}
}

// TestValidateAPIKey_CacheHit confirms the second call is served from cache.
func TestValidateAPIKey_CacheHit(t *testing.T) {
	svc := newTestService(t)
	entry := cmn.ApiKeyEntry{TenantID: "tenant2", Enabled: true}
	rawKey, _, err := svc.CreateAPIKey(entry)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	// First call populates the cache.
	if _, err = svc.ValidateAPIKey(rawKey); err != nil {
		t.Fatalf("first ValidateAPIKey: %v", err)
	}
	// Second call must use cache (no DB needed).
	result, err := svc.ValidateAPIKey(rawKey)
	if err != nil {
		t.Fatalf("second ValidateAPIKey (cache hit): %v", err)
	}
	if result.TenantID != "tenant2" {
		t.Fatalf("TenantID: want tenant2, got %s", result.TenantID)
	}
}

// TestValidateAPIKey_NotFound verifies that an unknown key returns an error.
func TestValidateAPIKey_NotFound(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.ValidateAPIKey("lxb_" + strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}
}

// TestListAPIKeys confirms that all keys for a tenant are returned.
func TestListAPIKeys(t *testing.T) {
	svc := newTestService(t)
	for _, name := range []string{"key-a", "key-b"} {
		if _, _, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "tenantList", Name: name, Enabled: true}); err != nil {
			t.Fatalf("CreateAPIKey %s: %v", name, err)
		}
	}
	keys, err := svc.ListAPIKeys("tenantList")
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
}

// TestListAPIKeys_Empty confirms that a tenant with no keys returns an empty slice.
func TestListAPIKeys_Empty(t *testing.T) {
	svc := newTestService(t)
	keys, err := svc.ListAPIKeys("nonexistent-tenant")
	if err != nil {
		t.Fatalf("ListAPIKeys on empty tenant: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("want 0 keys, got %d", len(keys))
	}
}

// TestRevokeAPIKey verifies that a revoked key can no longer be validated.
func TestRevokeAPIKey(t *testing.T) {
	svc := newTestService(t)
	rawKey, _, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "tenant4", Enabled: true})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	// Derive key_id via the stored hash.
	h := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(h[:])
	var keyID string
	if err := svc.DB.QueryRow("SELECT key_id FROM api_keys WHERE key_hash = ?", keyHash).Scan(&keyID); err != nil {
		t.Fatalf("fetch key_id: %v", err)
	}

	if err := svc.RevokeAPIKey(keyID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}

	// Key should no longer be valid.
	if _, err := svc.ValidateAPIKey(rawKey); err == nil {
		t.Fatal("ValidateAPIKey should fail after revocation")
	}
}

// TestRevokeAPIKey_NotFound verifies that revoking an absent key returns an error.
func TestRevokeAPIKey_NotFound(t *testing.T) {
	svc := newTestService(t)
	if err := svc.RevokeAPIKey("nonexistent-key-id"); err == nil {
		t.Fatal("expected error for non-existent key, got nil")
	}
}

// TestDisabledKeyVisibleToManagement verifies that disabling a key (via revoke or
// PATCH enabled=false) removes it from the auth path but keeps it visible to the
// management list/get endpoints, flagged enabled=false. Regression guard for the
// bug where a disabled key vanished entirely (list []/get 404) despite still
// existing in the store.
func TestDisabledKeyVisibleToManagement(t *testing.T) {
	svc := newTestService(t)
	rawKey, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "tenantDisabled", Name: "k1", Enabled: true})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	// Disable the key via the PATCH soft-disable path (enabled=false).
	disabled := false
	if err := svc.PatchAPIKey(keyID, nil, &disabled); err != nil {
		t.Fatalf("PatchAPIKey disable: %v", err)
	}

	// Auth path must reject it.
	if _, err := svc.ValidateAPIKey(rawKey); err == nil {
		t.Fatal("ValidateAPIKey should fail for a disabled key")
	}

	// Management get must still return it, flagged disabled.
	got, err := svc.GetAPIKeyByID(keyID)
	if err != nil {
		t.Fatalf("GetAPIKeyByID should still find a disabled key: %v", err)
	}
	if got.Enabled {
		t.Fatal("GetAPIKeyByID should report enabled=false for a disabled key")
	}

	// Management list (both all-keys and by-tenant) must still include it.
	keys, err := svc.ListAPIKeys("tenantDisabled")
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Enabled {
		t.Fatalf("ListAPIKeys should return the disabled key with enabled=false, got %+v", keys)
	}

	// Re-enable and confirm it authenticates again.
	enabled := true
	if err := svc.PatchAPIKey(keyID, nil, &enabled); err != nil {
		t.Fatalf("PatchAPIKey re-enable: %v", err)
	}
	if _, err := svc.ValidateAPIKey(rawKey); err != nil {
		t.Fatalf("ValidateAPIKey should succeed after re-enable: %v", err)
	}
}

// TestDeleteAPIKeyHardRemoves verifies that DeleteAPIKey (backing DELETE
// /apikey/{id}) is a hard delete: the key is gone from every view, unlike a
// soft-disable which stays visible. Distinguishes delete from revoke/disable.
func TestDeleteAPIKeyHardRemoves(t *testing.T) {
	svc := newTestService(t)
	rawKey, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "tenantDelete", Name: "k1", Enabled: true})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	if err := svc.DeleteAPIKey(keyID); err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}

	// Gone from get-by-id (404 upstream), list, and auth.
	if _, err := svc.GetAPIKeyByID(keyID); err == nil {
		t.Fatal("GetAPIKeyByID should fail after hard delete")
	}
	keys, err := svc.ListAPIKeys("tenantDelete")
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListAPIKeys should be empty after hard delete, got %+v", keys)
	}
	if _, err := svc.ValidateAPIKey(rawKey); err == nil {
		t.Fatal("ValidateAPIKey should fail after hard delete")
	}

	// Deleting an already-gone key is an error (drives the 404 path).
	if err := svc.DeleteAPIKey(keyID); err == nil {
		t.Fatal("DeleteAPIKey on a missing key should return an error")
	}
}

// TestSetTenantRateLimit verifies that the rate limit is persisted in the DB.
func TestSetTenantRateLimit(t *testing.T) {
	svc := newTestService(t)
	if err := svc.SetTenantRateLimit("tenant5", 100, 2000, 0); err != nil {
		t.Fatalf("SetTenantRateLimit: %v", err)
	}

	var rps, tpm int
	if err := svc.DB.QueryRow("SELECT rps, tokens_per_min FROM tenant_rate_limits WHERE tenant_id = ?", "tenant5").Scan(&rps, &tpm); err != nil {
		t.Fatalf("SELECT after set: %v", err)
	}
	if rps != 100 || tpm != 2000 {
		t.Fatalf("want rps=100 tpm=2000, got rps=%d tpm=%d", rps, tpm)
	}
}

// TestSetTenantRateLimit_Upsert verifies that a second call updates the existing row.
func TestSetTenantRateLimit_Upsert(t *testing.T) {
	svc := newTestService(t)
	if err := svc.SetTenantRateLimit("tenant6", 10, 100, 0); err != nil {
		t.Fatalf("first SetTenantRateLimit: %v", err)
	}
	if err := svc.SetTenantRateLimit("tenant6", 20, 200, 0); err != nil {
		t.Fatalf("upsert SetTenantRateLimit: %v", err)
	}

	var rps, tpm int
	if err := svc.DB.QueryRow("SELECT rps, tokens_per_min FROM tenant_rate_limits WHERE tenant_id = ?", "tenant6").Scan(&rps, &tpm); err != nil {
		t.Fatalf("SELECT after upsert: %v", err)
	}
	if rps != 20 || tpm != 200 {
		t.Fatalf("want rps=20 tpm=200 after upsert, got rps=%d tpm=%d", rps, tpm)
	}
}

// TestGetTenantRateLimit_CacheHit verifies that SetTenantRateLimit populates
// the cache so that GetTenantRateLimit returns without a DB round-trip.
func TestGetTenantRateLimit_CacheHit(t *testing.T) {
	svc := newTestService(t)
	if err := svc.SetTenantRateLimit("tenant7", 50, 500, 0); err != nil {
		t.Fatalf("SetTenantRateLimit: %v", err)
	}
	// Cache is populated by Set; this call must return from cache.
	rps, tpm, _ := svc.GetTenantRateLimit("tenant7")
	if rps != 50 || tpm != 500 {
		t.Fatalf("want rps=50 tpm=500, got rps=%d tpm=%d", rps, tpm)
	}
}

// TestGetTenantRateLimit_CacheMiss_DBHit confirms a cold-cache read from the DB.
func TestGetTenantRateLimit_CacheMiss_DBHit(t *testing.T) {
	svc := newTestService(t)
	if err := svc.SetTenantRateLimit("tenant8", 75, 750, 0); err != nil {
		t.Fatalf("SetTenantRateLimit: %v", err)
	}
	// Flush cache to force DB read.
	svc.Cache.Flush()

	rps, tpm, _ := svc.GetTenantRateLimit("tenant8")
	if rps != 75 || tpm != 750 {
		t.Fatalf("want rps=75 tpm=750, got rps=%d tpm=%d", rps, tpm)
	}
}

// TestGetTenantRateLimit_NotFound confirms (0,0) is returned for unknown tenants.
func TestGetTenantRateLimit_NotFound(t *testing.T) {
	svc := newTestService(t)
	rps, tpm, _ := svc.GetTenantRateLimit("nonexistent-tenant")
	if rps != 0 || tpm != 0 {
		t.Fatalf("want rps=0 tpm=0 for unknown tenant, got rps=%d tpm=%d", rps, tpm)
	}
}

// countingDB wraps a DBTX and counts the number of QueryRow calls made.
// It is used to verify that the cache prevents redundant DB round-trips.
type countingDB struct {
	DBTX
	queryRowCalls int
}

func (c *countingDB) QueryRow(query string, args ...any) *sql.Row {
	c.queryRowCalls++
	return c.DBTX.QueryRow(query, args...)
}

// TestGetAPIKeyByID_CacheHit verifies that a second call to GetAPIKeyByID for
// the same key is served from cache without issuing an additional DB query.
func TestGetAPIKeyByID_CacheHit(t *testing.T) {
	rawSvc := newTestService(t)
	rawKey, _, err := rawSvc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "tenantCacheHit", RateLimitRPS: 42, Enabled: true})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	// Derive keyID from DB.
	h := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(h[:])
	var keyID string
	if err := rawSvc.DB.QueryRow("SELECT key_id FROM api_keys WHERE key_hash = ?", keyHash).Scan(&keyID); err != nil {
		t.Fatalf("fetch key_id: %v", err)
	}

	// Wrap the real DB with a query counter.
	counter := &countingDB{DBTX: rawSvc.DB}
	svc := &UserService{DB: counter, Cache: rawSvc.Cache}
	svc.Cache.Flush() // start cold

	// First call: must hit DB.
	result1, err := svc.GetAPIKeyByID(keyID)
	if err != nil {
		t.Fatalf("first GetAPIKeyByID: %v", err)
	}
	if result1.RateLimitRPS != 42 {
		t.Fatalf("RateLimitRPS: want 42, got %d", result1.RateLimitRPS)
	}
	if counter.queryRowCalls != 1 {
		t.Fatalf("expected 1 DB query after first call, got %d", counter.queryRowCalls)
	}

	// Second call: must be served from cache — query count must not increase.
	result2, err := svc.GetAPIKeyByID(keyID)
	if err != nil {
		t.Fatalf("second GetAPIKeyByID (cache hit): %v", err)
	}
	if result2.RateLimitRPS != 42 {
		t.Fatalf("RateLimitRPS on cache hit: want 42, got %d", result2.RateLimitRPS)
	}
	if counter.queryRowCalls != 1 {
		t.Fatalf("expected DB query count to remain 1 after cache hit, got %d", counter.queryRowCalls)
	}
}

// TestRevokeAPIKey_CacheEviction verifies that RevokeAPIKey evicts both the
// hash-keyed and the keyid-keyed cache entries before returning.
func TestRevokeAPIKey_CacheEviction(t *testing.T) {
	svc := newTestService(t)
	rawKey, _, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "tenantEvict", Enabled: true})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	// Derive key_id and key_hash.
	h := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(h[:])
	var keyID string
	if err := svc.DB.QueryRow("SELECT key_id FROM api_keys WHERE key_hash = ?", keyHash).Scan(&keyID); err != nil {
		t.Fatalf("fetch key_id: %v", err)
	}

	// Warm both cache entries.
	if _, err := svc.ValidateAPIKey(rawKey); err != nil {
		t.Fatalf("ValidateAPIKey (warm hash cache): %v", err)
	}
	if _, err := svc.GetAPIKeyByID(keyID); err != nil {
		t.Fatalf("GetAPIKeyByID (warm keyid cache): %v", err)
	}

	// Confirm both entries are present.
	if _, found := svc.Cache.Get(keyHash); !found {
		t.Fatal("expected hash cache entry before revocation")
	}
	if _, found := svc.Cache.Get("keyid:" + keyID); !found {
		t.Fatal("expected keyid cache entry before revocation")
	}

	// Revoke the key.
	if err := svc.RevokeAPIKey(keyID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}

	// Both cache entries must be absent after revocation.
	if _, found := svc.Cache.Get(keyHash); found {
		t.Fatal("hash cache entry must be evicted after RevokeAPIKey")
	}
	if _, found := svc.Cache.Get("keyid:" + keyID); found {
		t.Fatal("keyid cache entry must be evicted after RevokeAPIKey")
	}
}

// BenchmarkValidateAPIKey measures the cache-hit path latency.
// A pre-seeded cache entry ensures the DB is never touched during the benchmark.
// Target: < 5 µs/op.
func BenchmarkValidateAPIKey(b *testing.B) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		b.Fatalf("open sqlite3: %v", err)
	}
	svc := &UserService{
		DB:    db,
		Cache: cache.New(5*time.Minute, 10*time.Minute),
	}

	rawKey := "lxb_" + strings.Repeat("a", 64)
	h := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(h[:])
	svc.Cache.Set(keyHash, &cmn.ApiKeyEntry{
		KeyID:    "bench-key",
		TenantID: "bench-tenant",
		Enabled:  true,
	}, 5*time.Minute)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		svc.ValidateAPIKey(rawKey) //nolint:errcheck
	}
}

// TestTenantModelRateLimit_SetGet covers the per-model quota CRUD: upsert,
// cache-backed read, update, zero-TPM removal, and the no-limit default.
func TestTenantModelRateLimit_SetGet(t *testing.T) {
	svc := newTestService(t)

	if got := svc.GetTenantModelRateLimit("t1", "m1"); got != 0 {
		t.Fatalf("unset model limit must read 0, got %d", got)
	}

	if err := svc.SetTenantModelRateLimit("t1", "m1", 500); err != nil {
		t.Fatalf("set model limit: %v", err)
	}
	if got := svc.GetTenantModelRateLimit("t1", "m1"); got != 500 {
		t.Fatalf("expected 500, got %d", got)
	}

	// Upsert overwrites.
	if err := svc.SetTenantModelRateLimit("t1", "m1", 900); err != nil {
		t.Fatalf("upsert model limit: %v", err)
	}
	if got := svc.GetTenantModelRateLimit("t1", "m1"); got != 900 {
		t.Fatalf("expected 900 after upsert, got %d", got)
	}

	// Another model on the same tenant is independent.
	if err := svc.SetTenantModelRateLimit("t1", "m2", 100); err != nil {
		t.Fatalf("set second model limit: %v", err)
	}
	if got := svc.GetTenantModelRateLimit("t1", "m1"); got != 900 {
		t.Fatalf("m1 must be unaffected by m2, got %d", got)
	}

	// tokens_per_min<=0 removes the row and the cache entry.
	if err := svc.SetTenantModelRateLimit("t1", "m1", 0); err != nil {
		t.Fatalf("clear model limit: %v", err)
	}
	if got := svc.GetTenantModelRateLimit("t1", "m1"); got != 0 {
		t.Fatalf("cleared model limit must read 0, got %d", got)
	}
}

// TestTenantModelRateLimit_RejectsDelimiter pins the composite-key guard:
// names containing '|' would alias another tenant|model bucket and must be
// rejected at config time.
func TestTenantModelRateLimit_RejectsDelimiter(t *testing.T) {
	svc := newTestService(t)
	if err := svc.SetTenantModelRateLimit("t1", "bad|model", 100); err == nil {
		t.Fatal("model name containing '|' must be rejected")
	}
	if err := svc.SetTenantModelRateLimit("bad|tenant", "m", 100); err == nil {
		t.Fatal("tenant name containing '|' must be rejected")
	}
	if err := svc.SetTenantModelRateLimit("t1", "", 100); err == nil {
		t.Fatal("empty model name must be rejected")
	}
}

// TestGetTenantRateLimitEntry_ModelLimits verifies the GET surface carries
// the per-model quotas, including for a tenant that has ONLY model quotas.
func TestGetTenantRateLimitEntry_ModelLimits(t *testing.T) {
	svc := newTestService(t)

	if err := svc.SetTenantModelRateLimit("t-models-only", "m1", 250); err != nil {
		t.Fatalf("set model limit: %v", err)
	}
	entry, err := svc.GetTenantRateLimitEntry("t-models-only")
	if err != nil {
		t.Fatalf("entry for model-only tenant must exist: %v", err)
	}
	if len(entry.ModelLimits) != 1 || entry.ModelLimits[0].Model != "m1" || entry.ModelLimits[0].TokensPerMin != 250 {
		t.Fatalf("unexpected model limits: %+v", entry.ModelLimits)
	}

	// A tenant with neither aggregate nor model limits stays not-found.
	if _, err := svc.GetTenantRateLimitEntry("t-none"); err == nil {
		t.Fatal("tenant with no limits at all must read not-found")
	}
}
