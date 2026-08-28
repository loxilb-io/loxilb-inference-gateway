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
package aikey

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilib"
	"github.com/patrickmn/go-cache"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/options"
)

const (
	// CacheExpirationTime is the TTL, in minutes, of a cached key or quota.
	CacheExpirationTime = 5
	// CacheCleanupInterval is how often, in minutes, expired cache entries are
	// swept.
	CacheCleanupInterval = 10

	apiKeyPrefix = "lxb_"

	// Bounds on a caller-supplied key. The lower bound is a floor on guessing
	// cost; the upper bound keeps a key from becoming an unbounded request
	// header. Generated keys are 68 characters and sit comfortably inside it.
	minSuppliedKeyLen = 16
	maxSuppliedKeyLen = 512
)

// Cache-key prefixes. Every entry this package caches carries one.
//
// The prefix is not decoration: the management plane's token cache and this
// package's key cache were previously one map, in which an API key was stored
// under a bare sha256 hex string and a session token under its own raw value.
// A hash presented as a token therefore hit the wrong domain's entry. The two
// caches are now separate objects; the prefixes make a future re-merge fail
// loudly rather than silently authenticate across planes.
const (
	cachePfxKeyHash = "ak:"
	cachePfxKeyID   = "keyid:"
	cachePfxTenant  = "rl:"
	cachePfxModel   = "rlm:"
)

// ErrDBUnavailable is defined in common so callers can recognise it without
// depending on this package. It maps to HTTP 503.
var ErrDBUnavailable = cmn.ErrDBUnavailable

// errStoreUnavailable is what this package actually returns. It wraps
// ErrDBUnavailable, so errors.Is still recognises the condition, while naming
// the store that is missing: the shared sentinel's own wording is the
// management plane's, and a log line telling an operator the user database is
// down when it is the key store that is down sends them to the wrong server.
var errStoreUnavailable = fmt.Errorf("aikey: key store unavailable: %w", ErrDBUnavailable)

// ErrKeyNotFound is returned when no key matches the identifier given.
var ErrKeyNotFound = errors.New("API key not found")

// ErrInvalidKey is returned when a presented key is unknown, disabled, or
// malformed. It is deliberately one error for all three: distinguishing them
// to the caller would confirm which key values exist.
var ErrInvalidKey = errors.New("invalid or disabled API key")

// SQL for the data-plane tables. PostgreSQL, not a mechanical translation of
// the MySQL originals — see the notes on the upsert statements.
var (
	sqlInsertAPIKey = fmt.Sprintf(`INSERT INTO %s.api_keys`+
		` (key_id, key_hash, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled)`+
		` VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, Schema)

	// Auth path: only enabled keys may authenticate. This filter is a security
	// invariant and must stay.
	sqlSelectAPIKeyByHash = fmt.Sprintf(`SELECT key_id, key_hash, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled`+
		` FROM %s.api_keys WHERE key_hash = $1 AND enabled = TRUE`, Schema)

	// Management list/get paths: return keys regardless of enabled state so an
	// operator can see, audit and re-enable a disabled key. The response
	// carries the `enabled` field to distinguish them.
	sqlSelectAPIKeysByTenant = fmt.Sprintf(`SELECT key_id, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled`+
		` FROM %s.api_keys WHERE tenant_id = $1`, Schema)

	sqlSelectKeyHashByID = fmt.Sprintf(`SELECT key_hash FROM %s.api_keys WHERE key_id = $1`, Schema)

	sqlSelectAPIKeyByID = fmt.Sprintf(`SELECT key_id, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled`+
		` FROM %s.api_keys WHERE key_id = $1`, Schema)

	sqlSelectAllAPIKeys = fmt.Sprintf(`SELECT key_id, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled`+
		` FROM %s.api_keys`, Schema)

	sqlUpdateAPIKeyEnabled = fmt.Sprintf(`UPDATE %s.api_keys SET enabled = $1 WHERE key_id = $2`, Schema)

	sqlUpdateAPIKeyAllowedModels = fmt.Sprintf(`UPDATE %s.api_keys SET allowed_models = $1 WHERE key_id = $2`, Schema)

	sqlDeleteAPIKeyByID = fmt.Sprintf(`DELETE FROM %s.api_keys WHERE key_id = $1`, Schema)

	// The MySQL original was REPLACE INTO, which PostgreSQL has no equivalent
	// for — and which is not the semantics wanted anyway. REPLACE is
	// delete-then-insert, so it resets every column the statement does not
	// name back to its default; a column added to this table later, or by a
	// newer peer, would be silently cleared on each write. ON CONFLICT DO
	// UPDATE sets exactly the four columns this call owns and leaves the rest
	// of the row alone.
	sqlUpsertTenantRateLimit = fmt.Sprintf(`INSERT INTO %s.tenant_rate_limits`+
		` (tenant_id, rps, tokens_per_min, burst_pct, updated_at) VALUES ($1, $2, $3, $4, $5)`+
		` ON CONFLICT (tenant_id) DO UPDATE SET`+
		` rps = EXCLUDED.rps, tokens_per_min = EXCLUDED.tokens_per_min,`+
		` burst_pct = EXCLUDED.burst_pct, updated_at = EXCLUDED.updated_at`, Schema)

	sqlSelectTenantRateLimit = fmt.Sprintf(
		`SELECT rps, tokens_per_min, burst_pct FROM %s.tenant_rate_limits WHERE tenant_id = $1`, Schema)

	sqlSelectTenantRateLimitFull = fmt.Sprintf(
		`SELECT rps, tokens_per_min, burst_pct, updated_at FROM %s.tenant_rate_limits WHERE tenant_id = $1`, Schema)

	// Same reasoning as the tenant upsert above.
	sqlUpsertTenantModelRateLimit = fmt.Sprintf(`INSERT INTO %s.tenant_model_rate_limits`+
		` (tenant_id, model, tokens_per_min, updated_at) VALUES ($1, $2, $3, $4)`+
		` ON CONFLICT (tenant_id, model) DO UPDATE SET`+
		` tokens_per_min = EXCLUDED.tokens_per_min, updated_at = EXCLUDED.updated_at`, Schema)

	sqlDeleteTenantModelRateLimit = fmt.Sprintf(
		`DELETE FROM %s.tenant_model_rate_limits WHERE tenant_id = $1 AND model = $2`, Schema)

	sqlSelectTenantModelRateLimit = fmt.Sprintf(
		`SELECT tokens_per_min FROM %s.tenant_model_rate_limits WHERE tenant_id = $1 AND model = $2`, Schema)

	sqlSelectTenantModelRateLimits = fmt.Sprintf(
		`SELECT model, tokens_per_min FROM %s.tenant_model_rate_limits WHERE tenant_id = $1`, Schema)
)

// DBTX is the minimal database surface this package uses, satisfied by
// *sql.DB. It exists so a test can substitute a double without an external
// mock library.
type DBTX interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Ping() error
}

// rateLimitCacheEntry holds tenant rate limit values cached in memory.
type rateLimitCacheEntry struct {
	rps          int
	tokensPerMin int
	// burstPct is the tenant's token-bucket capacity override in percent of
	// tokensPerMin; 0 means no override. Cached alongside the other two so a
	// charge resolves the whole quota configuration in one lookup.
	burstPct int
}

// Service owns the data-plane API-key store: its connection pool, its cache,
// and the fan-out that keeps peer gateways from honouring a key this one has
// just revoked.
//
// It shares nothing with the management-plane user service. That is the point
// of the type existing.
type Service struct {
	// mu guards db and invalidate. Both are installed after the struct
	// exists — db by the boot connect or by the reconnect tick, invalidate by
	// the cluster wiring — while data-plane goroutines are already reading
	// them. An interface value is two words, so an unguarded swap is not just
	// a stale read but a torn one.
	mu         sync.RWMutex
	db         DBTX
	invalidate func(KeyInvalidation)

	Cache *cache.Cache

	// rlLastKnown holds, per rate-limit cache key, the last value the store
	// actually answered with (a configured limit or an explicit "no row"),
	// and never expires. It exists for the store-outage window: the TTL cache
	// above forgets, and a forgotten limit read as (0,0,0) is "unlimited" —
	// which turned a store outage into every quota silently off for any
	// tenant whose limits were not in the TTL cache. During an outage the
	// last-known value is enforced instead; only a tenant the store has NEVER
	// answered for is refused. Bounded by the number of distinct tenants and
	// tenant|model pairs this process has served.
	rlLastKnown sync.Map
}

// rememberRateLimit records a store-confirmed rate-limit value in both the
// TTL cache (freshness) and the last-known map (outage fallback). Every
// write MUST go through here: a value that reaches only the TTL cache
// silently ages out of outage coverage.
func (s *Service) rememberRateLimit(cacheKey string, e *rateLimitCacheEntry) {
	s.Cache.Set(cacheKey, e, CacheExpirationTime*time.Minute)
	s.rlLastKnown.Store(cacheKey, e)
}

// lastKnownRateLimit retrieves the outage-fallback value for a cache key.
func (s *Service) lastKnownRateLimit(cacheKey string) (*rateLimitCacheEntry, bool) {
	if v, ok := s.rlLastKnown.Load(cacheKey); ok {
		if e, ok2 := v.(*rateLimitCacheEntry); ok2 {
			return e, true
		}
	}
	return nil, false
}

// New returns a service with no store attached. Every store-backed method on
// it reports ErrDBUnavailable until Connect succeeds.
//
// It is separate from Connect so that a caller can publish the service before
// dialling. Connect retries with a doubling backoff and can take tens of
// seconds against a store that is down, and for the whole of that time the
// gateway is configured with a store it has not reached yet. A caller that
// only publishes the pointer afterwards leaves every reader — the key
// lifecycle API and the data plane alike — seeing nil, which means something
// entirely different: that no store was configured at all.
func New() *Service {
	return &Service{
		Cache: cache.New(CacheExpirationTime*time.Minute, CacheCleanupInterval*time.Minute),
	}
}

// Connect dials the configured store, verifies its provisioning and creates
// the data-plane tables.
//
// On persistent failure the service stays usable but degraded: the pool stays
// nil, every store-backed method returns ErrDBUnavailable, and cached keys
// keep validating until their TTL expires. The data plane decides for itself
// what to do with that; this package does not choose to admit traffic on its
// behalf.
func (s *Service) Connect() error {
	return s.connect()
}

// NewService is New followed by Connect, for callers with no reason to publish
// the service before the dial completes.
func NewService() (*Service, error) {
	svc := New()
	return svc, svc.Connect()
}

// connect dials the configured store, provisions it and adopts the pool.
//
// The boot path and the reconnect tick share it so that a service which heals
// is provisioned exactly the way a fresh boot provisions one — a store that
// came back empty gets its tables, rather than a pool that answers ready and
// then fails every statement.
func (s *Service) connect() error {
	password, err := ResolvePassword(options.Opts.AIKeyDBPasswordPath)
	if err != nil {
		tk.LogIt(tk.LogCritical, "[AIKey] %v\n", err)
		return err
	}
	dsn := PostgresDSN(options.Opts.AIKeyDBUser, password, options.Opts.AIKeyDBHost,
		options.Opts.AIKeyDBPort, options.Opts.AIKeyDBName, SSLModeFor(options.Opts.AIKeySSLOption))

	var db *sql.DB
	if options.Opts.AIKeySSLOption {
		db, err = ConnectWithSecureTLS(dsn, connectMaxRetries, connectBackoff,
			options.Opts.AIKeySSLCACert, options.Opts.AIKeySSLClientCert, options.Opts.AIKeySSLClientKey)
	} else {
		db, err = ConnectWithRetry(dsn, connectMaxRetries, connectBackoff)
	}
	if err != nil {
		tk.LogIt(tk.LogCritical, "[AIKey] Key store unavailable at %s: %v\n", RedactDSN(dsn), err)
		return err
	}

	if err = s.Attach(db); err != nil {
		db.Close()
		tk.LogIt(tk.LogCritical, "[AIKey] %v\n", err)
		return err
	}

	tk.LogIt(tk.LogInfo, "[AIKey] Key store ready at %s\n", RedactDSN(dsn))
	return nil
}

// Ticker heals a service that started without a store. It runs on the loxinet
// housekeeping tick.
//
// A pool that already exists is left alone: *sql.DB re-dials its own
// connections, so a store that restarts is recovered without anything being
// swapped, and swapping it anyway would strand the queries in flight on the
// old pool. The case the pool cannot fix by itself is having no pool at all,
// which is what a store that was down at boot leaves behind.
func (s *Service) Ticker() {
	if s == nil {
		return
	}
	db, err := s.store()
	if err != nil {
		if cErr := s.connect(); cErr == nil {
			tk.LogIt(tk.LogInfo, "[AIKey] Key store reconnected\n")
		}
		return
	}
	if err = db.Ping(); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Key store unreachable: %v\n", err)
	}
}

// Attach runs the preflight and the table DDL against db and, on success,
// adopts it as the service's pool. Exported so a caller that opened its own
// connection — a test, or a reconnect path — provisions the store the same
// way a fresh boot does.
//
// db is not adopted when provisioning fails: a half-provisioned pool that
// answers ready would let queries run against tables that do not exist.
func (s *Service) Attach(db *sql.DB) error {
	if err := preflight(db); err != nil {
		return err
	}
	if err := ensureSchema(db); err != nil {
		return err
	}
	s.mu.Lock()
	s.db = db
	s.mu.Unlock()
	return nil
}

// SetInvalidationSink installs the fan-out used when a key stops being valid.
// Passing nil disables it, which is the correct state for a standalone
// gateway with no peers.
func (s *Service) SetInvalidationSink(fn func(KeyInvalidation)) {
	s.mu.Lock()
	s.invalidate = fn
	s.mu.Unlock()
}

// sink returns the installed fan-out, or nil when there is none.
func (s *Service) sink() func(KeyInvalidation) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.invalidate
}

// store returns the pool to run a statement against, or ErrDBUnavailable when
// there is none.
//
// It hands back the handle rather than reporting readiness, because a caller
// that asked "is it ready?" and then read the field again could be answered
// about one pool and use another: the reconnect tick installs the pool while
// the data plane is running. Only a non-nil *sql.DB is ever stored — a
// typed-nil pointer inside the interface would pass this check and panic at
// the first query.
func (s *Service) store() (DBTX, error) {
	if s == nil {
		return nil, errStoreUnavailable
	}
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		return nil, errStoreUnavailable
	}
	return db, nil
}

func cacheKeyForHash(keyHash string) string { return cachePfxKeyHash + keyHash }
func cacheKeyForID(keyID string) string     { return cachePfxKeyID + keyID }
func cacheKeyForTenant(t string) string     { return cachePfxTenant + t }
func cacheKeyForModel(t, m string) string   { return cachePfxModel + t + "|" + m }

// hashKey returns the stored form of a raw key. Only this ever reaches the
// database. A plain SHA-256 is the right construction here, not a slow
// password hash: raw keys are machine-generated 256-bit random values (and
// supplied keys are length-gated), so there is no low-entropy secret for a
// computationally expensive hash to protect, and this runs on the
// per-request validation path where a deliberate slowdown would price every
// request. Human-chosen management-plane passwords are bcrypt-hashed in
// pkg/user, where that cost belongs.
func hashKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// validateSuppliedKey checks caller-supplied key material. A supplied key is
// an import path — migrating a tenant from another gateway — so it is not
// required to look like a generated one, only to be a usable credential:
// long enough to resist guessing, and safe to carry in an HTTP header.
func validateSuppliedKey(raw string) error {
	if len(raw) < minSuppliedKeyLen || len(raw) > maxSuppliedKeyLen {
		return fmt.Errorf("supplied API key must be between %d and %d characters", minSuppliedKeyLen, maxSuppliedKeyLen)
	}
	for i := 0; i < len(raw); i++ {
		// Printable US-ASCII excluding space: anything else cannot survive a
		// header round-trip intact, and a key that changes in transit is an
		// authentication failure nobody can diagnose.
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return errors.New("supplied API key must contain only printable non-space ASCII characters")
		}
	}
	return nil
}

// CreateAPIKey registers an API key for a tenant and returns the raw key to
// the caller exactly once.
//
// Two paths. With entry.ApiKey empty — the primary path — the gateway mints
// the credential and returns it. With entry.ApiKey set, the caller's own key
// material is registered and the returned raw key is empty: the caller
// already holds it, and echoing it would put it in response logs and API
// traces for no benefit.
//
// key_id is generated independently of the key in both paths. Deriving it
// from the first half of the secret, as the MySQL implementation did, made a
// public identifier a function of the credential it identifies.
func (s *Service) CreateAPIKey(entry cmn.ApiKeyEntry) (string, string, error) {
	db, err := s.store()
	if err != nil {
		return "", "", err
	}

	// 16 bytes for the identifier, 32 for a generated secret, drawn
	// separately so the identifier reveals nothing about the key.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to generate key id: %v\n", err)
		return "", "", err
	}
	keyID := hex.EncodeToString(idBytes)

	var rawKey, returnedKey string
	if entry.ApiKey != "" {
		if err := validateSuppliedKey(entry.ApiKey); err != nil {
			return "", "", err
		}
		rawKey = entry.ApiKey
	} else {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to generate key material: %v\n", err)
			return "", "", err
		}
		rawKey = apiKeyPrefix + hex.EncodeToString(secret)
		returnedKey = rawKey
	}

	keyHash := hashKey(rawKey)
	allowedModels := strings.Join(entry.AllowedModels, ",")
	now := time.Now().UTC()

	if _, err := db.Exec(sqlInsertAPIKey,
		keyID, keyHash, entry.TenantID, entry.Name,
		allowedModels, entry.RateLimitRPS, entry.BurstSize, entry.TokensPerMin,
		now, entry.ExpiresAt, entry.Enabled); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to create API key for tenant %s: %v\n", entry.TenantID, err)
		return "", "", err
	}

	tk.LogIt(tk.LogInfo, "[AIKey] Created API key %s for tenant %s (supplied=%t)\n",
		keyID, entry.TenantID, entry.ApiKey != "")
	return returnedKey, keyID, nil
}

// ValidateAPIKey checks whether rawKey is a valid, enabled API key.
// The cache is checked first; the store is used only on a miss, so a hit
// completes without any syscalls.
func (s *Service) ValidateAPIKey(rawKey string) (*cmn.ApiKeyEntry, error) {
	keyHash := hashKey(rawKey)

	// Layer 1: in-memory cache (no syscalls on hit).
	if cached, found := s.Cache.Get(cacheKeyForHash(keyHash)); found {
		if entry, ok := cached.(*cmn.ApiKeyEntry); ok {
			return entry, nil
		}
	}

	// Layer 2: store. Fails closed when unavailable — a cache hit above still
	// validates during a short outage.
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	var entry cmn.ApiKeyEntry
	var allowedModels string
	var expiresAt sql.NullTime

	err = db.QueryRow(sqlSelectAPIKeyByHash, keyHash).Scan(
		&entry.KeyID, &entry.KeyHash, &entry.TenantID, &entry.Name,
		&allowedModels, &entry.RateLimitRPS, &entry.BurstSize, &entry.TokensPerMin,
		&entry.CreatedAt, &expiresAt, &entry.Enabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tk.LogIt(tk.LogWarning, "[AIKey] API key not found or disabled\n")
			return nil, ErrInvalidKey
		}
		tk.LogIt(tk.LogError, "[AIKey] Failed to validate API key: %v\n", err)
		return nil, err
	}

	if allowedModels != "" {
		entry.AllowedModels = strings.Split(allowedModels, ",")
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		entry.ExpiresAt = &t
	}

	s.Cache.Set(cacheKeyForHash(keyHash), &entry, CacheExpirationTime*time.Minute)

	return &entry, nil
}

// RevokeAPIKey disables the key identified by keyID and evicts it — here and
// on every peer — before returning.
func (s *Service) RevokeAPIKey(keyID string) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	keyHash, err := s.keyHashByID(db, keyID)
	if err != nil {
		return err
	}

	if _, err = db.Exec(sqlUpdateAPIKeyEnabled, false, keyID); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to revoke API key %s: %v\n", keyID, err)
		return err
	}

	s.evictAndFanOut(KeyInvalidation{KeyHash: keyHash, KeyID: keyID})

	tk.LogIt(tk.LogInfo, "[AIKey] Revoked API key %s\n", keyID)
	return nil
}

// DeleteAPIKey permanently removes the key identified by keyID and evicts it
// here and on every peer. Unlike RevokeAPIKey, which flips enabled=false (a
// reversible soft-disable that stays visible to the management endpoints),
// this is a hard delete: a subsequent lookup returns "not found".
func (s *Service) DeleteAPIKey(keyID string) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	keyHash, err := s.keyHashByID(db, keyID)
	if err != nil {
		return err
	}

	if _, err = db.Exec(sqlDeleteAPIKeyByID, keyID); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to delete API key %s: %v\n", keyID, err)
		return err
	}

	s.evictAndFanOut(KeyInvalidation{KeyHash: keyHash, KeyID: keyID})

	tk.LogIt(tk.LogInfo, "[AIKey] Deleted API key %s\n", keyID)
	return nil
}

// PatchAPIKey updates allowed_models and/or enabled for an existing key.
// Only non-nil fields are updated. The cache is evicted afterwards — locally
// and on peers, because a patch that disables a key is a revocation by
// another name.
func (s *Service) PatchAPIKey(keyID string, allowedModels []string, enabled *bool) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	keyHash, err := s.keyHashByID(db, keyID)
	if err != nil {
		return err
	}

	if allowedModels != nil {
		models := strings.Join(allowedModels, ",")
		if _, err = db.Exec(sqlUpdateAPIKeyAllowedModels, models, keyID); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to patch allowed_models for key %s: %v\n", keyID, err)
			return err
		}
	}

	if enabled != nil {
		if _, err = db.Exec(sqlUpdateAPIKeyEnabled, *enabled, keyID); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to patch enabled for key %s: %v\n", keyID, err)
			return err
		}
	}

	s.evictAndFanOut(KeyInvalidation{KeyHash: keyHash, KeyID: keyID})

	tk.LogIt(tk.LogInfo, "[AIKey] Patched API key %s\n", keyID)
	return nil
}

// keyHashByID resolves a key id to its stored hash, which is what the cache
// is keyed by. Every mutation needs it to evict the right entry.
//
// It takes the pool rather than fetching one, so that the lookup and the
// mutation that follows it run against the same store even if the reconnect
// tick replaces the pool in between.
func (s *Service) keyHashByID(db DBTX, keyID string) (string, error) {
	var keyHash string
	err := db.QueryRow(sqlSelectKeyHashByID, keyID).Scan(&keyHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tk.LogIt(tk.LogWarning, "[AIKey] API key not found: %s\n", keyID)
			return "", ErrKeyNotFound
		}
		tk.LogIt(tk.LogError, "[AIKey] Failed to fetch key hash for %s: %v\n", keyID, err)
		return "", err
	}
	return keyHash, nil
}

// SetTenantRateLimit upserts the per-tenant rate limit and refreshes the
// cache so subsequent reads do not need a round-trip.
func (s *Service) SetTenantRateLimit(tenantID string, rps, tokensPerMin, burstPct int) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := db.Exec(sqlUpsertTenantRateLimit, tenantID, rps, tokensPerMin, burstPct, now); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to set rate limit for tenant %s: %v\n", tenantID, err)
		return err
	}
	s.rememberRateLimit(cacheKeyForTenant(tenantID),
		&rateLimitCacheEntry{rps: rps, tokensPerMin: tokensPerMin, burstPct: burstPct})
	tk.LogIt(tk.LogInfo, "[AIKey] Set rate limit for tenant %s: rps=%d tokensPerMin=%d burstPct=%d\n",
		tenantID, rps, tokensPerMin, burstPct)
	return nil
}

// GetTenantRateLimit returns the per-tenant rate limit values, cache first.
// If the tenant has no configured limits, zeroes are returned with a nil
// error. A non-nil error means the store is unreachable AND it has never
// answered for this tenant, so no truthful value exists — the caller must
// fail closed rather than read the zeroes as "unlimited".
func (s *Service) GetTenantRateLimit(tenantID string) (rps, tokensPerMin, burstPct int, err error) {
	cacheKey := cacheKeyForTenant(tenantID)
	if cached, found := s.Cache.Get(cacheKey); found {
		if entry, ok := cached.(*rateLimitCacheEntry); ok {
			return entry.rps, entry.tokensPerMin, entry.burstPct, nil
		}
	}

	// With the store unreachable, "no limit configured" and "could not ask"
	// used to collapse into the same zeroes — so an outage switched quotas
	// off for exactly the traffic they were configured to bound, for any
	// tenant whose limits had aged out of the TTL cache while its key had
	// not. The decision taken for that window: enforce the LAST value the
	// store confirmed (a real limit or an explicit no-row), and refuse only
	// a tenant the store has never answered for — the same shape the key
	// cache itself gives a cached key during an outage.
	db, dbErr := s.store()
	if dbErr != nil {
		if e, ok := s.lastKnownRateLimit(cacheKey); ok {
			return e.rps, e.tokensPerMin, e.burstPct, nil
		}
		return 0, 0, 0, errStoreUnavailable
	}
	var r, t, b int
	err = db.QueryRow(sqlSelectTenantRateLimit, tenantID).Scan(&r, &t, &b)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// An explicit "no limits configured" is an answer worth keeping:
			// it is what makes an unlimited tenant distinguishable from an
			// unanswered one when the store goes away.
			s.rememberRateLimit(cacheKey, &rateLimitCacheEntry{})
			return 0, 0, 0, nil
		}
		tk.LogIt(tk.LogError, "[AIKey] Failed to get rate limit for tenant %s: %v\n", tenantID, err)
		if e, ok := s.lastKnownRateLimit(cacheKey); ok {
			return e.rps, e.tokensPerMin, e.burstPct, nil
		}
		return 0, 0, 0, errStoreUnavailable
	}

	s.rememberRateLimit(cacheKey, &rateLimitCacheEntry{rps: r, tokensPerMin: t, burstPct: b})
	return r, t, b, nil
}

// SetTenantModelRateLimit upserts one per-model token quota for a tenant.
// tokensPerMin <= 0 removes the row: the model falls back to the tenant-level
// quota alone.
func (s *Service) SetTenantModelRateLimit(tenantID, model string, tokensPerMin int) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	if model == "" || strings.ContainsAny(tenantID+model, "|") {
		// "|" is the composite quota-key delimiter (tenant|model): a name
		// containing it would alias another tenant/model pair's bucket.
		return fmt.Errorf("invalid tenant/model name for model rate limit (%q/%q)", tenantID, model)
	}
	cacheKey := cacheKeyForModel(tenantID, model)
	if tokensPerMin <= 0 {
		if _, err := db.Exec(sqlDeleteTenantModelRateLimit, tenantID, model); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to clear model rate limit for %s/%s: %v\n", tenantID, model, err)
			return err
		}
		// The clear is itself a store-confirmed answer ("no limit"), so it is
		// remembered rather than merely dropped from the TTL cache — a bare
		// delete would leave the last-known map still enforcing the removed
		// limit through the next outage.
		s.rememberRateLimit(cacheKey, &rateLimitCacheEntry{})
		s.Cache.Delete(cacheKey)
		tk.LogIt(tk.LogInfo, "[AIKey] Cleared model rate limit for tenant %s model %s\n", tenantID, model)
		return nil
	}
	now := time.Now().UTC()
	if _, err := db.Exec(sqlUpsertTenantModelRateLimit, tenantID, model, tokensPerMin, now); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to set model rate limit for %s/%s: %v\n", tenantID, model, err)
		return err
	}
	s.rememberRateLimit(cacheKey, &rateLimitCacheEntry{tokensPerMin: tokensPerMin})
	tk.LogIt(tk.LogInfo, "[AIKey] Set model rate limit for tenant %s model %s: tokensPerMin=%d\n",
		tenantID, model, tokensPerMin)
	return nil
}

// GetTenantModelRateLimit returns the per-model token quota for a tenant, or
// 0 when the pair has no model-specific limit configured (the tenant
// aggregate quota, if any, still applies). A non-nil error carries the same
// meaning as GetTenantRateLimit's: the store is unreachable and has never
// answered for this pair, so the zero must not be read as "unlimited".
func (s *Service) GetTenantModelRateLimit(tenantID, model string) (tokensPerMin int, err error) {
	if model == "" {
		return 0, nil
	}
	cacheKey := cacheKeyForModel(tenantID, model)
	if cached, found := s.Cache.Get(cacheKey); found {
		if entry, ok := cached.(*rateLimitCacheEntry); ok {
			return entry.tokensPerMin, nil
		}
	}
	db, dbErr := s.store()
	if dbErr != nil {
		if e, ok := s.lastKnownRateLimit(cacheKey); ok {
			return e.tokensPerMin, nil
		}
		return 0, errStoreUnavailable
	}
	var t int
	err = db.QueryRow(sqlSelectTenantModelRateLimit, tenantID, model).Scan(&t)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			tk.LogIt(tk.LogError, "[AIKey] Failed to get model rate limit for %s/%s: %v\n", tenantID, model, err)
			if e, ok := s.lastKnownRateLimit(cacheKey); ok {
				return e.tokensPerMin, nil
			}
			return 0, errStoreUnavailable
		}
		// Cache the miss too: an unlimited model on a busy tenant would
		// otherwise pay one round-trip per request — and the remembered miss
		// is what keeps that model servable through a later outage.
		t = 0
	}
	s.rememberRateLimit(cacheKey, &rateLimitCacheEntry{tokensPerMin: t})
	return t, nil
}

// GetTenantModelRateLimits returns every configured per-model quota for a
// tenant, for the config GET surface. Reads the store directly (config reads
// are not on the datapath).
func (s *Service) GetTenantModelRateLimits(tenantID string) ([]cmn.TenantModelRateLimit, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(sqlSelectTenantModelRateLimits, tenantID)
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

// GetAPIKeyByID retrieves API key metadata by key id, without the hash.
// Returns nil and an error if not found.
func (s *Service) GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error) {
	cacheKey := cacheKeyForID(keyID)
	if cached, found := s.Cache.Get(cacheKey); found {
		if summary, ok := cached.(*cmn.ApiKeySummary); ok {
			return summary, nil
		}
	}

	db, err := s.store()
	if err != nil {
		return nil, err
	}
	var key cmn.ApiKeySummary
	var allowedModels string
	var expiresAt sql.NullTime

	err = db.QueryRow(sqlSelectAPIKeyByID, keyID).Scan(
		&key.KeyID, &key.TenantID, &key.Name,
		&allowedModels, &key.RateLimitRPS, &key.BurstSize, &key.TokensPerMin,
		&key.CreatedAt, &expiresAt, &key.Enabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tk.LogIt(tk.LogWarning, "[AIKey] API key not found: %s\n", keyID)
			return nil, ErrKeyNotFound
		}
		tk.LogIt(tk.LogError, "[AIKey] Failed to get API key %s: %v\n", keyID, err)
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

// ListAPIKeys returns a summary of API keys. If tenantID is non-empty it
// filters by tenant; if empty it returns all keys across all tenants.
func (s *Service) ListAPIKeys(tenantID string) ([]cmn.ApiKeySummary, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	var rows *sql.Rows
	if tenantID == "" {
		rows, err = db.Query(sqlSelectAllAPIKeys)
	} else {
		rows, err = db.Query(sqlSelectAPIKeysByTenant, tenantID)
	}
	if err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to list API keys (tenant=%q): %v\n", tenantID, err)
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
			tk.LogIt(tk.LogError, "[AIKey] Failed to scan API key row: %v\n", err)
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
		tk.LogIt(tk.LogError, "[AIKey] Row iteration error listing API keys (tenant=%q): %v\n", tenantID, err)
		return nil, err
	}

	tk.LogIt(tk.LogInfo, "[AIKey] Listed %d API keys (tenant=%q)\n", len(keys), tenantID)
	return keys, nil
}

// GetTenantRateLimitEntry returns the full rate limit entry, including
// updated_at and any per-model quotas. Returns nil and an error if the tenant
// has no configuration at all.
func (s *Service) GetTenantRateLimitEntry(tenantID string) (*cmn.TenantRateLimitEntry, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	var entry cmn.TenantRateLimitEntry
	entry.TenantID = tenantID

	err = db.QueryRow(sqlSelectTenantRateLimitFull, tenantID).Scan(
		&entry.RPS, &entry.TokensPerMin, &entry.BurstPct, &entry.UpdatedAt)
	noTenantRow := errors.Is(err, sql.ErrNoRows)
	if err != nil && !noTenantRow {
		tk.LogIt(tk.LogError, "[AIKey] Failed to get rate limit entry for tenant %s: %v\n", tenantID, err)
		return nil, err
	}

	entry.ModelLimits, err = s.GetTenantModelRateLimits(tenantID)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to get model rate limits for tenant %s: %v\n", tenantID, err)
		return nil, err
	}
	// A tenant configured only with per-model quotas has no aggregate row —
	// still a real configuration worth returning.
	if noTenantRow && len(entry.ModelLimits) == 0 {
		tk.LogIt(tk.LogWarning, "[AIKey] Rate limit not found for tenant: %s\n", tenantID)
		return nil, errors.New("tenant rate limit not found")
	}

	return &entry, nil
}
