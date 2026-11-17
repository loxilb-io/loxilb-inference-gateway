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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	tk "github.com/loxilb-io/loxilb/internal/tk"
	"github.com/patrickmn/go-cache"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/pgstore"
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

// ErrNotFound is the shared "no such row" sentinel for everything this
// package stores. Callers classify on it with errors.Is rather than on the
// wording: the REST layer used to decide 404-vs-500 by looking for the
// substring "not found" in the message, which made an HTTP status code
// depend on phrasing — and would have answered "this row does not exist" to
// any store or driver error that happened to contain those two words.
var ErrNotFound = errors.New("not found")

// ErrKeyNotFound is returned when no key matches the identifier given. It
// wraps ErrNotFound, so errors.Is recognises the condition while the message
// still names the resource — the same reason errStoreUnavailable above names
// the store it could not reach. A row of some other kind must NOT borrow this
// one: a client told "API key not found" after asking for a rate-limit row
// has been handed the wrong resource's name.
var ErrKeyNotFound = fmt.Errorf("API key %w", ErrNotFound)

// ErrInvalidKey is returned when a presented key is unknown, disabled, or
// malformed. It is deliberately one error for all three: distinguishing them
// to the caller would confirm which key values exist.
var ErrInvalidKey = errors.New("invalid or disabled API key")

// SQL for the data-plane tables. PostgreSQL, not a mechanical translation of
// the MySQL originals — see the notes on the upsert statements.
var (
	sqlInsertAPIKey = fmt.Sprintf(`INSERT INTO %s.api_keys`+
		` (key_id, key_hash, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled, client_op_id)`+
		` VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, Schema)

	// The idempotent create's row lookup, locked for the rest of the
	// transaction so two retries carrying the same operation id serialise
	// on the row instead of both rotating it.
	sqlSelectAPIKeyByClientOp = fmt.Sprintf(`SELECT key_id, key_hash, first_used_at`+
		` FROM %s.api_keys WHERE tenant_id = $1 AND client_op_id = $2 FOR UPDATE`, Schema)

	// A retried create rotates the secret of a row no request has ever
	// authenticated with; the earlier secret was delivered to nobody.
	sqlRotateAPIKeyHash = fmt.Sprintf(`UPDATE %s.api_keys SET key_hash = $1, created_at = $2`+
		` WHERE key_id = $3`, Schema)

	// Written once, by the data path, the first time a key created with an
	// operation id authenticates: from then on a retry of its create is
	// refused rather than rotating a secret somebody holds.
	sqlMarkAPIKeyFirstUse = fmt.Sprintf(`UPDATE %s.api_keys SET first_used_at = $1`+
		` WHERE key_id = $2 AND first_used_at IS NULL`, Schema)

	// Auth path: only enabled keys may authenticate. This filter is a security
	// invariant and must stay.
	sqlSelectAPIKeyByHash = fmt.Sprintf(`SELECT key_id, key_hash, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled,`+
		` client_op_id, first_used_at`+
		` FROM %s.api_keys WHERE key_hash = $1 AND enabled = TRUE`, Schema)

	// Management list/get paths: return keys regardless of enabled state so an
	// operator can see, audit and re-enable a disabled key. The response
	// carries the `enabled` field to distinguish them.
	sqlSelectAPIKeysByTenant = fmt.Sprintf(`SELECT key_id, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled, client_op_id`+
		` FROM %s.api_keys WHERE tenant_id = $1`, Schema)

	sqlSelectKeyHashByID = fmt.Sprintf(`SELECT key_hash FROM %s.api_keys WHERE key_id = $1`, Schema)

	sqlSelectAPIKeyByID = fmt.Sprintf(`SELECT key_id, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled, client_op_id`+
		` FROM %s.api_keys WHERE key_id = $1`, Schema)

	sqlSelectAllAPIKeys = fmt.Sprintf(`SELECT key_id, tenant_id, name, allowed_models,`+
		` rate_limit_rps, burst_size, tokens_per_min, created_at, expires_at, enabled, client_op_id`+
		` FROM %s.api_keys`, Schema)

	sqlCountKnownTenants = fmt.Sprintf(`SELECT COUNT(*) FROM (`+
		`SELECT tenant_id FROM %s.api_keys UNION SELECT tenant_id FROM %s.tenant_rate_limits) t`,
		Schema, Schema)

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
//
// Only the context-taking methods are on it, on purpose. Every statement
// this package runs carries a deadline (pkg/pgstore budgets), because a
// store that stalls while keeping TCP open answers a statement without one
// never -- and a cache-miss key lookup runs on a proxy worker thread, so
// "never" there is a parked worker and every connection it owns. With the
// plain methods absent from the interface a new call site cannot run without
// a deadline and compile.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	PingContext(ctx context.Context) error
}

// opContext bounds one management operation by the operation budget, and by
// the caller's context: a request whose client has gone away is cancelled
// with it. parent may be nil for a caller with no request to inherit from.
func (s *Service) opContext(parent context.Context) (context.Context, context.CancelFunc) {
	return pgstore.WithBudget(parent, pgstore.OpTimeout())
}

// lookupContext bounds one data-path store round trip. There is no request
// context to inherit on that path -- the caller is a proxy worker thread
// inside a cgo callback -- so the budget is the whole deadline.
func lookupContext() (context.Context, context.CancelFunc) {
	return pgstore.WithBudget(context.Background(), pgstore.LookupTimeout())
}

// writeErr and readErr classify a statement's error for the caller: a write
// says whether the server may still apply it (pkg/pgstore outcome.go), a
// read only whether the store could be asked. Every error a store-backed
// method returns from a statement goes through one of them, so the REST
// layer's errors.Is checks see the shared sentinels rather than the
// driver's types.
func writeErr(err error) error { return pgstore.ClassifyWriteErrFor(pgstore.PlaneAIKey, err) }
func readErr(err error) error  { return pgstore.ClassifyReadErr(err) }

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

	// guard fronts every data-path store round trip (lookup_guard.go): the
	// in-flight bound, the store-health circuit and the lookup statistics.
	// negative remembers key hashes the store said do not exist.
	guard    lookupGuard
	negative negativeKeyCache

	// class is the objective and class snapshot (class_snapshot.go).
	class classState
}

// rememberRateLimit records a store-confirmed rate-limit value in both the
// TTL cache (freshness) and the last-known map (outage fallback). Every
// write MUST go through here: a value that reaches only the TTL cache
// silently ages out of outage coverage.
func (s *Service) rememberRateLimit(cacheKey string, e *rateLimitCacheEntry) {
	s.Cache.Set(cacheKey, e, CacheExpirationTime*time.Minute)
	s.rlLastKnown.Store(cacheKey, e)
}

// lastKnownRateLimit retrieves the outage-fallback value for a cache key:
// what the store confirmed to this process, else, while the process serves
// the last-known-good file because the store has not answered since it
// started, the file's row (class_lkg_limits.go).
func (s *Service) lastKnownRateLimit(cacheKey string) (*rateLimitCacheEntry, bool) {
	if v, ok := s.rlLastKnown.Load(cacheKey); ok {
		if e, ok2 := v.(*rateLimitCacheEntry); ok2 {
			return e, true
		}
	}
	return s.lkgRateLimit(cacheKey)
}

// rememberKeySummary records a store-confirmed view of one key by ID in the
// TTL cache and in the last-known map. Both data-path reads that learn a
// key's limits write through here -- the by-hash validation and the by-ID
// read -- so a key this process has validated always has a by-ID entry to
// fall back on while the store is away. The entry is removed with the key's
// other cached views (invalidate.go) and when the store says the row is gone.
func (s *Service) rememberKeySummary(keyID string, k *cmn.ApiKeySummary) {
	cacheKey := cacheKeyForID(keyID)
	s.Cache.Set(cacheKey, k, CacheExpirationTime*time.Minute)
	s.rlLastKnown.Store(cacheKey, k)
}

func (s *Service) lastKnownKeySummary(keyID string) (*cmn.ApiKeySummary, bool) {
	if v, ok := s.rlLastKnown.Load(cacheKeyForID(keyID)); ok {
		if k, ok2 := v.(*cmn.ApiKeySummary); ok2 {
			return k, true
		}
	}
	return nil, false
}

func (s *Service) forgetKeySummary(keyID string) {
	s.rlLastKnown.Delete(cacheKeyForID(keyID))
}

// summaryOfEntry is the by-ID view of a validated key: the same columns the
// by-ID read scans, so the two writers of rememberKeySummary agree.
func summaryOfEntry(e *cmn.ApiKeyEntry) *cmn.ApiKeySummary {
	return &cmn.ApiKeySummary{
		KeyID: e.KeyID, TenantID: e.TenantID, Name: e.Name, AllowedModels: e.AllowedModels,
		RateLimitRPS: e.RateLimitRPS, BurstSize: e.BurstSize, TokensPerMin: e.TokensPerMin,
		CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt, Enabled: e.Enabled,
	}
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

// Ready reports whether the key store currently answers: the pool exists
// (the background dial has succeeded at least once) and a liveness ping
// succeeds right now. This is the readiness-surface question -- distinct
// from the restore engine's configured-check, which deliberately never
// asks it (a store outage must not hold a boot replay hostage).
//
// The ping runs under the ping budget, and under the caller's context: a
// readiness probe whose client has gone is not worth finishing. A store that
// stalls while keeping its connections open is reported not ready within the
// budget, instead of the probe hanging for as long as the stall lasts.
func (s *Service) Ready(ctx context.Context) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := pgstore.WithBudget(ctx, pgstore.PingTimeout())
	defer cancel()
	return readErr(db.PingContext(ctx))
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
	ctx, cancel := pgstore.WithBudget(context.Background(), pgstore.PingTimeout())
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
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
	// The preflight and the DDL are a management operation of this process
	// against a store it has only just reached: budgeted like any other, so
	// a store that accepted the dial and then stalled does not hold the boot
	// or the reconnect tick.
	ctx, cancel := s.opContext(context.Background())
	defer cancel()
	if err := preflight(ctx, db); err != nil {
		return err
	}
	if err := ensureSchema(ctx, db); err != nil {
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
//
// Both rejections are typed. They are two branches of one validator reached
// from one call site, so they must classify alike; leaving them as plain
// errors left that to whether their wording happened to match a phrase in the
// API layer's fallback classifier, and it did for one branch and not the
// other.
func validateSuppliedKey(raw string) error {
	if len(raw) < minSuppliedKeyLen || len(raw) > maxSuppliedKeyLen {
		return cmn.NewValidationError("api_key",
			"supplied API key must be between %d and %d characters", minSuppliedKeyLen, maxSuppliedKeyLen)
	}
	for i := 0; i < len(raw); i++ {
		// Printable US-ASCII excluding space: anything else cannot survive a
		// header round-trip intact, and a key that changes in transit is an
		// authentication failure nobody can diagnose.
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return cmn.NewValidationError("api_key",
				"supplied API key must contain only printable non-space ASCII characters")
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
func (s *Service) CreateAPIKey(ctx context.Context, entry cmn.ApiKeyEntry) (string, string, error) {
	created, err := s.CreateKey(ctx, entry)
	return created.RawKey, created.KeyID, err
}

// ErrKeyAlreadyDelivered is the verdict of a retried create whose key has
// already authenticated: the secret the first answer carried is in use, and
// a second secret cannot be delivered for the same operation. The caller
// holds the key_id in the error and reads the key back.
var ErrKeyAlreadyDelivered = errors.New("API key has already authenticated: its secret cannot be delivered again")

// KeyAlreadyDeliveredError carries the key the retry converged on.
type KeyAlreadyDeliveredError struct{ KeyID string }

func (e *KeyAlreadyDeliveredError) Error() string {
	return fmt.Sprintf("%v (key_id %s)", ErrKeyAlreadyDelivered, e.KeyID)
}
func (e *KeyAlreadyDeliveredError) Unwrap() error { return ErrKeyAlreadyDelivered }

// Bounds of a client operation id: long enough for a UUID with a prefix,
// short enough to index, and the same character set a supplied key is held
// to, for the same reason (it rides in a header too).
const maxClientOpIDLen = 128

func validateClientOpID(id string) error {
	if len(id) > maxClientOpIDLen {
		return cmn.NewValidationError("client_op_id", "client_op_id must be at most %d characters", maxClientOpIDLen)
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return cmn.NewValidationError("client_op_id", "client_op_id must contain only printable non-space ASCII characters")
		}
	}
	return nil
}

// CreateKey creates an API key for a tenant and answers with the one
// delivery of its secret.
//
// A create is not idempotent by nature: the server mints the secret, and a
// create whose answer was lost (a 504: the statement was sent and the store
// did not answer within the budget) may have left an enabled key whose
// secret nobody holds. A caller that wants a safe retry sends a
// client_op_id. The create then converges on one row per (tenant_id,
// client_op_id):
//
//   - no such row: the key is created with the id recorded;
//   - a row no request has ever authenticated with: this is the retry of a
//     create whose answer was lost. The secret is minted again and the row's
//     hash rotated to it, so the earlier secret, delivered to nobody, stops
//     authenticating; the answer carries the SAME key_id, Reused=true. The
//     row's other fields are the first request's and are not rewritten;
//   - a row that has authenticated: KeyAlreadyDeliveredError (409). The
//     secret in use is not rotated out from under its holder, and a second
//     secret is not minted for the same operation.
//
// The lookup and the write run in one transaction with the row locked, so
// two retries carrying the same id serialise on it. A create without an id
// behaves as before.
func (s *Service) CreateKey(ctx context.Context, entry cmn.ApiKeyEntry) (cmn.ApiKeyCreated, error) {
	var none cmn.ApiKeyCreated
	// A key's tenant_id reaches the QoS ladder as a bucket key exactly as an
	// operator-set tenant row does, so it is held to the same rule. Without
	// this, the key surface was a way to introduce an aliasing tenant that
	// the rate-limit surfaces refuse.
	if err := ValidateQoSIdentity("tenant_id", entry.TenantID); err != nil {
		return none, err
	}
	class, err := ValidateClassPolicy(entry.AIClassPolicy)
	if err != nil {
		return none, err
	}
	if entry.ClientOpID != "" {
		if err := validateClientOpID(entry.ClientOpID); err != nil {
			return none, err
		}
	}
	if entry.ApiKey != "" {
		if err := validateSuppliedKey(entry.ApiKey); err != nil {
			return none, err
		}
	}
	db, err := s.store()
	if err != nil {
		return none, err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()

	// 16 bytes for the identifier, 32 for a generated secret, drawn
	// separately so the identifier reveals nothing about the key.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to generate key id: %v\n", err)
		return none, err
	}
	keyID := hex.EncodeToString(idBytes)

	var rawKey, returnedKey string
	if entry.ApiKey != "" {
		rawKey = entry.ApiKey
	} else {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to generate key material: %v\n", err)
			return none, err
		}
		rawKey = apiKeyPrefix + hex.EncodeToString(secret)
		returnedKey = rawKey
	}

	keyHash := hashKey(rawKey)
	// A probe for this secret before it existed may have left a negative
	// entry; the key is about to exist.
	s.forgetNegative(keyHash)
	allowedModels := strings.Join(entry.AllowedModels, ",")
	now := time.Now().UTC()
	clientOpID := sql.NullString{String: entry.ClientOpID, Valid: entry.ClientOpID != ""}

	var out cmn.ApiKeyCreated
	var rotatedFrom string // the hash a retry replaced, to evict
	inserted := false
	err = inTx(ctx, db, func(tx stmtRunner) error {
		if clientOpID.Valid {
			var existingID, existingHash string
			var firstUsed sql.NullTime
			err := tx.QueryRowContext(ctx, sqlSelectAPIKeyByClientOp, entry.TenantID, entry.ClientOpID).
				Scan(&existingID, &existingHash, &firstUsed)
			switch {
			case err == nil:
				if firstUsed.Valid {
					return &KeyAlreadyDeliveredError{KeyID: existingID}
				}
				if _, err := tx.ExecContext(ctx, sqlRotateAPIKeyHash, keyHash, now, existingID); err != nil {
					tk.LogIt(tk.LogError, "[AIKey] Failed to rotate the secret of key %s on a retried create: %v\n", existingID, err)
					return writeErr(err)
				}
				out = cmn.ApiKeyCreated{RawKey: returnedKey, KeyID: existingID, Reused: true}
				rotatedFrom = existingHash
				return nil
			case errors.Is(err, sql.ErrNoRows):
				// First time this operation is seen: create.
			default:
				// Nothing has been written at this point, so a failure here
				// is a read's: the store could not be asked.
				tk.LogIt(tk.LogError, "[AIKey] Failed to look up client_op_id for tenant %s: %v\n", entry.TenantID, err)
				return readErr(err)
			}
		}

		if _, err := tx.ExecContext(ctx, sqlInsertAPIKey,
			keyID, keyHash, entry.TenantID, entry.Name,
			allowedModels, entry.RateLimitRPS, entry.BurstSize, entry.TokensPerMin,
			now, entry.ExpiresAt, entry.Enabled, clientOpID); err != nil {
			// Only an imported credential colliding with the credential-hash
			// index is a caller conflict, as is a second create racing this
			// one on the same operation id (the lock above serialises the
			// retries that find a row; two that find none both insert, and
			// the index refuses the second). ID/generated-key collisions
			// remain server errors. Do not expose the driver Detail: it may
			// contain the credential hash.
			var unique *pgconn.PgError
			if errors.As(err, &unique) && unique.Code == "23505" {
				switch {
				case entry.ApiKey != "" && unique.ConstraintName == "uq_api_keys_key_hash":
					return cmn.NewConflictError("imported API key is already registered")
				case unique.ConstraintName == "uq_api_keys_client_op":
					return cmn.NewConflictError("a create with this client_op_id is being applied: read the key back")
				}
			}
			tk.LogIt(tk.LogError, "[AIKey] Failed to create API key for tenant %s: %v\n", entry.TenantID, err)
			return writeErr(err)
		}

		// The class fields have their own statement, in the same
		// transaction: a key asked for with a class never exists without it.
		if !class.IsZero() {
			if _, err := tx.ExecContext(ctx, sqlUpdateKeyClass, keyID, class.PriorityClass, class.DefaultObjective,
				joinList(class.AllowedObjectives)); err != nil {
				tk.LogIt(tk.LogError, "[AIKey] Failed to set class of new key %s: %v\n", keyID, err)
				return writeErr(err)
			}
		}
		inserted = true
		out = cmn.ApiKeyCreated{RawKey: returnedKey, KeyID: keyID}
		return nil
	})
	if err != nil {
		return none, err
	}

	if rotatedFrom != "" && rotatedFrom != keyHash {
		// The earlier secret may have been cached by a validation on this
		// node or a peer; it has stopped being valid.
		s.evictAndFanOut(KeyInvalidation{KeyHash: rotatedFrom, KeyID: out.KeyID})
	}
	if inserted && !class.IsZero() {
		s.refreshClassesAfterWrite()
	}

	tk.LogIt(tk.LogInfo, "[AIKey] Created API key %s for tenant %s (supplied=%t, reused=%t)\n",
		out.KeyID, entry.TenantID, entry.ApiKey != "", out.Reused)
	return out, nil
}

// markFirstUse records, off the proxy worker, that a key created with an
// operation id has authenticated once. The statement is a no-op after the
// first time, and its failure costs nothing but the next retry of that
// create being allowed to rotate a secret that is in use; it is logged.
func (s *Service) markFirstUse(keyID string) {
	go func() {
		db, err := s.store()
		if err != nil {
			return
		}
		ctx, cancel := s.opContext(context.Background())
		defer cancel()
		if _, err := db.ExecContext(ctx, sqlMarkAPIKeyFirstUse, time.Now().UTC(), keyID); err != nil {
			tk.LogIt(tk.LogWarning, "[AIKey] First use of key %s not recorded: %v\n", keyID, err)
		}
	}()
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

	// Layer 1b: a hash the store recently said does not exist is refused
	// without asking again (bounded, short TTL; lookup_guard.go).
	if s.negativeHit(keyHash) {
		return nil, ErrInvalidKey
	}

	// Layer 2: store. Fails closed when unavailable — a cache hit above still
	// validates during a short outage.
	//
	// The lookup budget is the longest the calling proxy worker is parked.
	// A store that stalls while keeping its connections open is answered
	// "could not ask" inside it; the data plane then refuses the request
	// the way it refuses one during a cold outage. The guard in front of the
	// round trip refuses at once, inside the same budget, once the store has
	// failed a few in a row or the in-flight slots are taken. A cache hit
	// above never gets here, so cached keys keep validating through a stall.
	var entry cmn.ApiKeyEntry
	var allowedModels string
	var expiresAt, firstUsed sql.NullTime
	var clientOpID sql.NullString
	err := s.dataPathRead(func(ctx context.Context, db DBTX) error {
		return db.QueryRowContext(ctx, sqlSelectAPIKeyByHash, keyHash).Scan(
			&entry.KeyID, &entry.KeyHash, &entry.TenantID, &entry.Name,
			&allowedModels, &entry.RateLimitRPS, &entry.BurstSize, &entry.TokensPerMin,
			&entry.CreatedAt, &expiresAt, &entry.Enabled, &clientOpID, &firstUsed)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tk.LogIt(tk.LogWarning, "[AIKey] API key not found or disabled\n")
			s.rememberNegative(keyHash)
			return nil, ErrInvalidKey
		}
		if errors.Is(err, ErrDBUnavailable) {
			return nil, err
		}
		tk.LogIt(tk.LogError, "[AIKey] Failed to validate API key: %v\n", err)
		return nil, readErr(err)
	}

	if allowedModels != "" {
		entry.AllowedModels = strings.Split(allowedModels, ",")
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		entry.ExpiresAt = &t
	}

	entry.ClientOpID = clientOpID.String

	s.Cache.Set(cacheKeyForHash(keyHash), &entry, CacheExpirationTime*time.Minute)
	// The row carries the key's limits, so the by-ID view the quota stages
	// read is written now: a key validated here always has one to fall back
	// on while the store is away.
	s.rememberKeySummary(entry.KeyID, summaryOfEntry(&entry))
	// A key created with an operation id has now authenticated: its create
	// may no longer be retried into a new secret.
	if clientOpID.Valid && !firstUsed.Valid {
		s.markFirstUse(entry.KeyID)
	}

	return &entry, nil
}

// RevokeAPIKey disables the key identified by keyID and evicts it — here and
// on every peer — before returning.
func (s *Service) RevokeAPIKey(ctx context.Context, keyID string) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	keyHash, err := s.keyHashByID(ctx, db, keyID)
	if err != nil {
		return err
	}

	if _, err = db.ExecContext(ctx, sqlUpdateAPIKeyEnabled, false, keyID); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to revoke API key %s: %v\n", keyID, err)
		return writeErr(err)
	}

	s.evictAndFanOut(KeyInvalidation{KeyHash: keyHash, KeyID: keyID})

	tk.LogIt(tk.LogInfo, "[AIKey] Revoked API key %s\n", keyID)
	return nil
}

// DeleteAPIKey permanently removes the key identified by keyID and evicts it
// here and on every peer. Unlike RevokeAPIKey, which flips enabled=false (a
// reversible soft-disable that stays visible to the management endpoints),
// this is a hard delete: a subsequent lookup returns "not found".
func (s *Service) DeleteAPIKey(ctx context.Context, keyID string) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	keyHash, err := s.keyHashByID(ctx, db, keyID)
	if err != nil {
		return err
	}

	if _, err = db.ExecContext(ctx, sqlDeleteAPIKeyByID, keyID); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to delete API key %s: %v\n", keyID, err)
		return writeErr(err)
	}

	s.evictAndFanOut(KeyInvalidation{KeyHash: keyHash, KeyID: keyID})

	tk.LogIt(tk.LogInfo, "[AIKey] Deleted API key %s\n", keyID)
	return nil
}

// PatchAPIKey updates allowed_models and/or enabled for an existing key.
// Only non-nil fields are updated. The cache is evicted afterwards — locally
// and on peers, because a patch that disables a key is a revocation by
// another name.
func (s *Service) PatchAPIKey(ctx context.Context, keyID string, allowedModels []string, enabled *bool) error {
	return s.PatchAPIKeyAll(ctx, keyID, cmn.ApiKeyPatch{AllowedModels: allowedModels, Enabled: enabled})
}

// keyHashByID resolves a key id to its stored hash, which is what the cache
// is keyed by. Every mutation needs it to evict the right entry.
//
// It takes the pool rather than fetching one, so that the lookup and the
// mutation that follows it run against the same store even if the reconnect
// tick replaces the pool in between.
func (s *Service) keyHashByID(ctx context.Context, db stmtRunner, keyID string) (string, error) {
	var keyHash string
	err := db.QueryRowContext(ctx, sqlSelectKeyHashByID, keyID).Scan(&keyHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			tk.LogIt(tk.LogWarning, "[AIKey] API key not found: %s\n", keyID)
			return "", ErrKeyNotFound
		}
		tk.LogIt(tk.LogError, "[AIKey] Failed to fetch key hash for %s: %v\n", keyID, err)
		return "", readErr(err)
	}
	return keyHash, nil
}

// SetTenantRateLimit upserts the per-tenant rate limit and refreshes the
// cache so subsequent reads do not need a round-trip.
func (s *Service) SetTenantRateLimit(ctx context.Context, tenantID string, rps, tokensPerMin, burstPct int) error {
	// The tenant id becomes a bucket key verbatim: the tenant aggregate quota
	// is keyed on the BARE id, so a tenant named "t1|gpt-4" is the same
	// quotaMap entry as tenant t1's gpt-4 model bucket, and one named "uq:t|u"
	// round-trips through the quota sync wire as a USER-scope key. The user
	// surface has always refused both; this one accepted them, so the guard
	// the reserved-prefix list exists to provide had a way around it.
	if err := ValidateQoSIdentity("tenant_id", tenantID); err != nil {
		return err
	}
	if tenantID == "" {
		return cmn.NewValidationError("tenant_id", "tenant_id is required")
	}
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, sqlUpsertTenantRateLimit, tenantID, rps, tokensPerMin, burstPct, now); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to set rate limit for tenant %s: %v\n", tenantID, err)
		return writeErr(err)
	}
	s.rememberRateLimit(cacheKeyForTenant(tenantID),
		&rateLimitCacheEntry{rps: rps, tokensPerMin: tokensPerMin, burstPct: burstPct})
	tk.LogIt(tk.LogInfo, "[AIKey] Set rate limit for tenant %s: rps=%d tokensPerMin=%d burstPct=%d\n",
		tenantID, rps, tokensPerMin, burstPct)
	// The last-known-good file carries the limit rows: it follows the write
	// at once, not one refresh interval later.
	s.refreshClassesAfterWrite()
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
	var r, t, b int
	err = s.dataPathRead(func(ctx context.Context, db DBTX) error {
		return db.QueryRowContext(ctx, sqlSelectTenantRateLimit, tenantID).Scan(&r, &t, &b)
	})
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
func (s *Service) SetTenantModelRateLimit(ctx context.Context, tenantID, model string, tokensPerMin int) error {
	// "|" is the composite quota-key delimiter (tenant|model): a name
	// containing it would alias another tenant/model pair's bucket. The
	// reserved scope prefixes are the second half of the same property and
	// the ad-hoc check here never covered them, so the shared validator is
	// used instead of a local spelling that can drift from it.
	//
	// Ahead of the store handle, like every other QoS write surface: a
	// refusal that only fires once a pool exists is not a refusal on a
	// gateway whose store is down, and it reports the outage's error
	// instead of the caller's mistake.
	if err := ValidateQoSIdentity("tenant_id", tenantID); err != nil {
		return err
	}
	if err := ValidateQoSIdentity("model", model); err != nil {
		return err
	}
	if model == "" {
		return cmn.NewValidationError("model", "model is required for a model rate limit")
	}
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	cacheKey := cacheKeyForModel(tenantID, model)
	if tokensPerMin <= 0 {
		if _, err := db.ExecContext(ctx, sqlDeleteTenantModelRateLimit, tenantID, model); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to clear model rate limit for %s/%s: %v\n", tenantID, model, err)
			return writeErr(err)
		}
		// The clear is itself a store-confirmed answer ("no limit"), so it is
		// remembered rather than merely dropped from the TTL cache — a bare
		// delete would leave the last-known map still enforcing the removed
		// limit through the next outage.
		s.rememberRateLimit(cacheKey, &rateLimitCacheEntry{})
		s.Cache.Delete(cacheKey)
		tk.LogIt(tk.LogInfo, "[AIKey] Cleared model rate limit for tenant %s model %s\n", tenantID, model)
		// The last-known-good file carries the limit rows: it follows the
		// write at once, not one refresh interval later.
		s.refreshClassesAfterWrite()
		return nil
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, sqlUpsertTenantModelRateLimit, tenantID, model, tokensPerMin, now); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to set model rate limit for %s/%s: %v\n", tenantID, model, err)
		return writeErr(err)
	}
	s.rememberRateLimit(cacheKey, &rateLimitCacheEntry{tokensPerMin: tokensPerMin})
	tk.LogIt(tk.LogInfo, "[AIKey] Set model rate limit for tenant %s model %s: tokensPerMin=%d\n",
		tenantID, model, tokensPerMin)
	// The last-known-good file carries the limit rows: it follows the write
	// at once, not one refresh interval later.
	s.refreshClassesAfterWrite()
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
	var t int
	err = s.dataPathRead(func(ctx context.Context, db DBTX) error {
		return db.QueryRowContext(ctx, sqlSelectTenantModelRateLimit, tenantID, model).Scan(&t)
	})
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
func (s *Service) GetTenantModelRateLimits(ctx context.Context, tenantID string) ([]cmn.TenantModelRateLimit, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	rows, err := db.QueryContext(ctx, sqlSelectTenantModelRateLimits, tenantID)
	if err != nil {
		return nil, readErr(err)
	}
	defer rows.Close()
	var out []cmn.TenantModelRateLimit
	for rows.Next() {
		var m cmn.TenantModelRateLimit
		if err := rows.Scan(&m.Model, &m.TokensPerMin); err != nil {
			return nil, readErr(err)
		}
		out = append(out, m)
	}
	return out, readErr(rows.Err())
}

// GetAPIKeyByID retrieves API key metadata by key id, without the hash.
// Returns nil and an error if not found.
//
// It is a data-path read (the quota check and the settle path consult it on
// a cache miss) as well as a management one, so it carries the lookup
// budget rather than a caller's context: the longest a proxy worker is ever
// parked by it is that budget.
func (s *Service) GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error) {
	cacheKey := cacheKeyForID(keyID)
	if cached, found := s.Cache.Get(cacheKey); found {
		if summary, ok := cached.(*cmn.ApiKeySummary); ok {
			return summary, nil
		}
	}

	// Store, under the lookup budget and the guard; then the last view the
	// store confirmed, so that a key's limits that aged out of the TTL cache
	// during an outage are enforced rather than read as "unlimited". Only a
	// key the store has never described to this process is reported as
	// unavailable, and the admission path fails closed on that.
	var key cmn.ApiKeySummary
	var allowedModels string
	var expiresAt sql.NullTime
	var clientOpID sql.NullString
	err := s.dataPathRead(func(ctx context.Context, db DBTX) error {
		return db.QueryRowContext(ctx, sqlSelectAPIKeyByID, keyID).Scan(
			&key.KeyID, &key.TenantID, &key.Name,
			&allowedModels, &key.RateLimitRPS, &key.BurstSize, &key.TokensPerMin,
			&key.CreatedAt, &expiresAt, &key.Enabled, &clientOpID)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// A real answer: the row is gone. Nothing last-known may outlive it.
			tk.LogIt(tk.LogWarning, "[AIKey] API key not found: %s\n", keyID)
			s.forgetKeySummary(keyID)
			return nil, ErrKeyNotFound
		}
		if k, ok := s.lastKnownKeySummary(keyID); ok {
			return k, nil
		}
		if errors.Is(err, ErrDBUnavailable) {
			return nil, err
		}
		tk.LogIt(tk.LogError, "[AIKey] Failed to get API key %s: %v\n", keyID, err)
		return nil, readErr(err)
	}

	if allowedModels != "" {
		key.AllowedModels = strings.Split(allowedModels, ",")
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		key.ExpiresAt = &t
	}
	key.ClientOpID = clientOpID.String

	s.rememberKeySummary(keyID, &key)

	return &key, nil
}

// KnownTenantCount returns how many distinct tenants the store knows: the
// tenants that own an API key and the tenants that have a rate-limit row.
func (s *Service) KnownTenantCount(ctx context.Context) (int, error) {
	db, err := s.store()
	if err != nil {
		return 0, err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	var n int
	if err := db.QueryRowContext(ctx, sqlCountKnownTenants).Scan(&n); err != nil {
		return 0, readErr(err)
	}
	return n, nil
}

// ListAPIKeys returns a summary of API keys. If tenantID is non-empty it
// filters by tenant; if empty it returns all keys across all tenants.
func (s *Service) ListAPIKeys(ctx context.Context, tenantID string) ([]cmn.ApiKeySummary, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	var rows *sql.Rows
	if tenantID == "" {
		rows, err = db.QueryContext(ctx, sqlSelectAllAPIKeys)
	} else {
		rows, err = db.QueryContext(ctx, sqlSelectAPIKeysByTenant, tenantID)
	}
	if err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to list API keys (tenant=%q): %v\n", tenantID, err)
		return nil, readErr(err)
	}
	defer rows.Close()

	var keys []cmn.ApiKeySummary
	for rows.Next() {
		var key cmn.ApiKeySummary
		var allowedModels string
		var expiresAt sql.NullTime
		var clientOpID sql.NullString

		if err := rows.Scan(
			&key.KeyID, &key.TenantID, &key.Name,
			&allowedModels, &key.RateLimitRPS, &key.BurstSize, &key.TokensPerMin,
			&key.CreatedAt, &expiresAt, &key.Enabled, &clientOpID); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to scan API key row: %v\n", err)
			return nil, readErr(err)
		}

		if allowedModels != "" {
			key.AllowedModels = strings.Split(allowedModels, ",")
		}
		if expiresAt.Valid {
			t := expiresAt.Time
			key.ExpiresAt = &t
		}
		key.ClientOpID = clientOpID.String

		keys = append(keys, key)
	}

	if err = rows.Err(); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Row iteration error listing API keys (tenant=%q): %v\n", tenantID, err)
		return nil, readErr(err)
	}

	tk.LogIt(tk.LogInfo, "[AIKey] Listed %d API keys (tenant=%q)\n", len(keys), tenantID)
	return keys, nil
}

// GetTenantRateLimitEntry returns the full rate limit entry, including
// updated_at and any per-model quotas. Returns nil and an error if the tenant
// has no configuration at all.
func (s *Service) GetTenantRateLimitEntry(ctx context.Context, tenantID string) (*cmn.TenantRateLimitEntry, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	var entry cmn.TenantRateLimitEntry
	entry.TenantID = tenantID

	err = db.QueryRowContext(ctx, sqlSelectTenantRateLimitFull, tenantID).Scan(
		&entry.RPS, &entry.TokensPerMin, &entry.BurstPct, &entry.UpdatedAt)
	noTenantRow := errors.Is(err, sql.ErrNoRows)
	if err != nil && !noTenantRow {
		tk.LogIt(tk.LogError, "[AIKey] Failed to get rate limit entry for tenant %s: %v\n", tenantID, err)
		return nil, readErr(err)
	}

	entry.ModelLimits, err = s.GetTenantModelRateLimits(ctx, tenantID)
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
