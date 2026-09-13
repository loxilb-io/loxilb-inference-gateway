/*
 * Copyright (c) 2026 LoxiLB Authors
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

// QoS ladder storage: explicit per-user limits (ladder level 1) and the
// configurable defaults (level 3). The read paths follow the exact posture
// GetTenantRateLimit established — TTL cache first, then the store, then the
// last store-confirmed value during an outage; a non-nil error means none of
// those exist and the caller must fail closed rather than read zeroes as
// "unlimited". Any deviation from that shape here would give the user
// dimension a different outage behaviour from the tenant dimension, which is
// exactly the kind of asymmetry an operator cannot see until a failover.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	tk "github.com/loxilb-io/loxilib"

	cmn "github.com/loxilb-io/loxilb/common"
	rl "github.com/loxilb-io/loxilb/pkg/ratelimit"
)

// Cache-key prefixes for the ladder tables, same discipline as the existing
// rl:/rlm: prefixes in service.go.
const (
	cachePfxUser      = "rlu:"
	cachePfxUserModel = "rlum:"
	cachePfxDefaults  = "rld:"
)

func cacheKeyForUser(tenantID, userID string) string {
	return cachePfxUser + tenantID + "|" + userID
}
func cacheKeyForUserModel(tenantID, userID, model string) string {
	return cachePfxUserModel + tenantID + "|" + userID + "|" + model
}
func cacheKeyForDefaults(scope, ruleIdent string) string {
	return cachePfxDefaults + scope + "|" + ruleIdent
}

var (
	sqlUpsertUserRateLimit = fmt.Sprintf(`INSERT INTO %s.user_rate_limits`+
		` (tenant_id, user_id, rps, burst_size, tokens_per_min, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`+
		` ON CONFLICT (tenant_id, user_id) DO UPDATE SET`+
		` rps = EXCLUDED.rps, burst_size = EXCLUDED.burst_size,`+
		` tokens_per_min = EXCLUDED.tokens_per_min, updated_at = EXCLUDED.updated_at`, Schema)

	sqlSelectUserRateLimit = fmt.Sprintf(
		`SELECT rps, burst_size, tokens_per_min FROM %s.user_rate_limits WHERE tenant_id = $1 AND user_id = $2`, Schema)

	sqlSelectUserRateLimitFull = fmt.Sprintf(
		`SELECT rps, burst_size, tokens_per_min, updated_at FROM %s.user_rate_limits WHERE tenant_id = $1 AND user_id = $2`, Schema)

	sqlSelectUserRateLimitsByTenant = fmt.Sprintf(
		`SELECT user_id, rps, burst_size, tokens_per_min, updated_at FROM %s.user_rate_limits WHERE tenant_id = $1 ORDER BY user_id`, Schema)

	sqlDeleteUserRateLimit = fmt.Sprintf(
		`DELETE FROM %s.user_rate_limits WHERE tenant_id = $1 AND user_id = $2`, Schema)

	sqlUpsertUserModelRateLimit = fmt.Sprintf(`INSERT INTO %s.user_model_rate_limits`+
		` (tenant_id, user_id, model, tokens_per_min, updated_at) VALUES ($1, $2, $3, $4, $5)`+
		` ON CONFLICT (tenant_id, user_id, model) DO UPDATE SET`+
		` tokens_per_min = EXCLUDED.tokens_per_min, updated_at = EXCLUDED.updated_at`, Schema)

	sqlDeleteUserModelRateLimits = fmt.Sprintf(
		`DELETE FROM %s.user_model_rate_limits WHERE tenant_id = $1 AND user_id = $2`, Schema)

	sqlSelectUserModelRateLimit = fmt.Sprintf(
		`SELECT tokens_per_min FROM %s.user_model_rate_limits WHERE tenant_id = $1 AND user_id = $2 AND model = $3`, Schema)

	sqlSelectUserModelRateLimits = fmt.Sprintf(
		`SELECT model, tokens_per_min FROM %s.user_model_rate_limits WHERE tenant_id = $1 AND user_id = $2 ORDER BY model`, Schema)

	sqlUpsertRateLimitDefaults = fmt.Sprintf(`INSERT INTO %s.rate_limit_defaults`+
		` (scope, rule_ident, default_user_rps, default_user_tpm, default_tenant_rps, default_tenant_tpm,`+
		` vip_shared_rps, vip_shared_tpm, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`+
		` ON CONFLICT (scope, rule_ident) DO UPDATE SET`+
		` default_user_rps = EXCLUDED.default_user_rps, default_user_tpm = EXCLUDED.default_user_tpm,`+
		` default_tenant_rps = EXCLUDED.default_tenant_rps, default_tenant_tpm = EXCLUDED.default_tenant_tpm,`+
		` vip_shared_rps = EXCLUDED.vip_shared_rps, vip_shared_tpm = EXCLUDED.vip_shared_tpm,`+
		` updated_at = EXCLUDED.updated_at`, Schema)

	sqlSelectRateLimitDefaults = fmt.Sprintf(
		`SELECT default_user_rps, default_user_tpm, default_tenant_rps, default_tenant_tpm,`+
			` vip_shared_rps, vip_shared_tpm FROM %s.rate_limit_defaults WHERE scope = $1 AND rule_ident = $2`, Schema)

	sqlSelectRateLimitDefaultsFull = fmt.Sprintf(
		`SELECT default_user_rps, default_user_tpm, default_tenant_rps, default_tenant_tpm,`+
			` vip_shared_rps, vip_shared_tpm, updated_at FROM %s.rate_limit_defaults WHERE scope = $1 AND rule_ident = $2`, Schema)

	sqlDeleteRateLimitDefaults = fmt.Sprintf(
		`DELETE FROM %s.rate_limit_defaults WHERE scope = $1 AND rule_ident = $2`, Schema)
)

// userRateLimitCacheEntry carries a user row's three limit values through
// the TTL cache and the last-known outage map. The all-zero entry is the
// remembered "no row" answer, exactly as rateLimitCacheEntry's is.
type userRateLimitCacheEntry struct {
	rps          int
	burstSize    int
	tokensPerMin int
}

// defaultsCacheEntry carries one defaults row through the caches.
type defaultsCacheEntry struct {
	userRPS, userTPM     int
	tenantRPS, tenantTPM int
	vipRPS, vipTPM       int
	exists               bool // false = store confirmed there is no such row
}

// ValidateQoSIdentity rejects identity values (tenant, user, model, key or
// service idents) that cannot be composed into bucket keys without aliasing:
// "|" is the composite-key delimiter, and the sync-wire scope prefixes would
// let one identity's bucket round-trip into another scope's. Enforced at
// every config write and at the claims mapper — never on the hot path.
func ValidateQoSIdentity(kind, id string) error {
	if strings.Contains(id, "|") {
		return cmn.NewValidationError(kind, "invalid %s %q: '|' is the composite bucket-key delimiter", kind, id)
	}
	if rl.HasReservedScopePrefix(id) {
		return cmn.NewValidationError(kind, "invalid %s %q: begins with a reserved rate-limit scope prefix", kind, id)
	}
	return nil
}

// SetUserRateLimit upserts one user's explicit limits (and optional
// per-model quotas) and refreshes the caches. An entry whose limit fields
// are all zero is refused: a row that constrains nothing is
// indistinguishable from clutter, and "remove the limits" is what
// DeleteUserRateLimit says explicitly.
func (s *Service) SetUserRateLimit(entry cmn.UserRateLimitEntry) error {
	if err := ValidateQoSIdentity("tenant_id", entry.TenantID); err != nil {
		return err
	}
	if err := ValidateQoSIdentity("user_id", entry.UserID); err != nil {
		return err
	}
	if entry.TenantID == "" || entry.UserID == "" {
		return cmn.NewValidationError("", "tenant_id and user_id are required")
	}
	if entry.RPS < 0 || entry.BurstSize < 0 || entry.TokensPerMin < 0 {
		return cmn.NewValidationError("", "rate limit values must not be negative")
	}
	decides := entry.RPS > 0 || entry.TokensPerMin > 0
	for _, ml := range entry.ModelLimits {
		if err := ValidateQoSIdentity("model", ml.Model); err != nil {
			return err
		}
		if ml.Model == "" {
			return cmn.NewValidationError("model_limits", "model_limits entries require a model name")
		}
		if ml.TokensPerMin < 0 {
			return cmn.NewValidationError("model_limits", "rate limit values must not be negative")
		}
		if ml.TokensPerMin > 0 {
			decides = true
		}
	}
	if !decides {
		return cmn.NewValidationError("", "a user rate-limit entry must set at least one non-zero limit (zero falls through the ladder; use DELETE to remove limits)")
	}

	db, err := s.store()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := db.Exec(sqlUpsertUserRateLimit,
		entry.TenantID, entry.UserID, entry.RPS, entry.BurstSize, entry.TokensPerMin, now); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to set user rate limit for %s/%s: %v\n", entry.TenantID, entry.UserID, err)
		return err
	}
	s.rememberUserRateLimit(cacheKeyForUser(entry.TenantID, entry.UserID),
		&userRateLimitCacheEntry{rps: entry.RPS, burstSize: entry.BurstSize, tokensPerMin: entry.TokensPerMin})

	// Model limits are REPLACED as a set, mirroring the tenant surface's
	// posture (NetTenantRateLimitSet): the entry the caller sends is the
	// entry that exists afterwards.
	if _, err := db.Exec(sqlDeleteUserModelRateLimits, entry.TenantID, entry.UserID); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to clear user model rate limits for %s/%s: %v\n", entry.TenantID, entry.UserID, err)
		return err
	}
	for _, ml := range entry.ModelLimits {
		if ml.TokensPerMin <= 0 {
			s.rememberUserRateLimit(cacheKeyForUserModel(entry.TenantID, entry.UserID, ml.Model),
				&userRateLimitCacheEntry{})
			continue
		}
		if _, err := db.Exec(sqlUpsertUserModelRateLimit,
			entry.TenantID, entry.UserID, ml.Model, ml.TokensPerMin, now); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to set user model rate limit for %s/%s/%s: %v\n",
				entry.TenantID, entry.UserID, ml.Model, err)
			return err
		}
		s.rememberUserRateLimit(cacheKeyForUserModel(entry.TenantID, entry.UserID, ml.Model),
			&userRateLimitCacheEntry{tokensPerMin: ml.TokensPerMin})
	}

	tk.LogIt(tk.LogInfo, "[AIKey] Set user rate limit for %s/%s: rps=%d burst=%d tokensPerMin=%d models=%d\n",
		entry.TenantID, entry.UserID, entry.RPS, entry.BurstSize, entry.TokensPerMin, len(entry.ModelLimits))
	return nil
}

// rememberUserRateLimit is rememberRateLimit's twin for the user tables:
// TTL cache for freshness, last-known map for the outage window. One writer
// path, so a value can never reach one and not the other.
func (s *Service) rememberUserRateLimit(cacheKey string, e *userRateLimitCacheEntry) {
	s.Cache.Set(cacheKey, e, CacheExpirationTime*time.Minute)
	s.rlLastKnown.Store(cacheKey, e)
}

func (s *Service) lastKnownUserRateLimit(cacheKey string) (*userRateLimitCacheEntry, bool) {
	if v, ok := s.rlLastKnown.Load(cacheKey); ok {
		if e, ok2 := v.(*userRateLimitCacheEntry); ok2 {
			return e, true
		}
	}
	return nil, false
}

// GetUserRateLimit is the hot-path read: cache first, then the store, then
// the last store-confirmed value. A non-nil error means the store has never
// answered for this pair — fail closed, the zeroes are not "unlimited".
func (s *Service) GetUserRateLimit(tenantID, userID string) (rps, burstSize, tokensPerMin int, err error) {
	cacheKey := cacheKeyForUser(tenantID, userID)
	if cached, found := s.Cache.Get(cacheKey); found {
		if e, ok := cached.(*userRateLimitCacheEntry); ok {
			return e.rps, e.burstSize, e.tokensPerMin, nil
		}
	}
	db, dbErr := s.store()
	if dbErr != nil {
		if e, ok := s.lastKnownUserRateLimit(cacheKey); ok {
			return e.rps, e.burstSize, e.tokensPerMin, nil
		}
		return 0, 0, 0, errStoreUnavailable
	}
	var r, b, t int
	err = db.QueryRow(sqlSelectUserRateLimit, tenantID, userID).Scan(&r, &b, &t)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// The remembered miss is what keeps an unlimited user servable
			// through a later outage — same reasoning as the tenant path.
			s.rememberUserRateLimit(cacheKey, &userRateLimitCacheEntry{})
			return 0, 0, 0, nil
		}
		tk.LogIt(tk.LogError, "[AIKey] Failed to get user rate limit for %s/%s: %v\n", tenantID, userID, err)
		if e, ok := s.lastKnownUserRateLimit(cacheKey); ok {
			return e.rps, e.burstSize, e.tokensPerMin, nil
		}
		return 0, 0, 0, errStoreUnavailable
	}
	s.rememberUserRateLimit(cacheKey, &userRateLimitCacheEntry{rps: r, burstSize: b, tokensPerMin: t})
	return r, b, t, nil
}

// GetUserModelRateLimit returns the per-model token quota for a user, or 0
// when the triple has no row (the user aggregate, if any, still applies).
// Error semantics identical to GetUserRateLimit.
func (s *Service) GetUserModelRateLimit(tenantID, userID, model string) (tokensPerMin int, err error) {
	if model == "" {
		return 0, nil
	}
	cacheKey := cacheKeyForUserModel(tenantID, userID, model)
	if cached, found := s.Cache.Get(cacheKey); found {
		if e, ok := cached.(*userRateLimitCacheEntry); ok {
			return e.tokensPerMin, nil
		}
	}
	db, dbErr := s.store()
	if dbErr != nil {
		if e, ok := s.lastKnownUserRateLimit(cacheKey); ok {
			return e.tokensPerMin, nil
		}
		return 0, errStoreUnavailable
	}
	var t int
	err = db.QueryRow(sqlSelectUserModelRateLimit, tenantID, userID, model).Scan(&t)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			tk.LogIt(tk.LogError, "[AIKey] Failed to get user model rate limit for %s/%s/%s: %v\n", tenantID, userID, model, err)
			if e, ok := s.lastKnownUserRateLimit(cacheKey); ok {
				return e.tokensPerMin, nil
			}
			return 0, errStoreUnavailable
		}
		t = 0
	}
	s.rememberUserRateLimit(cacheKey, &userRateLimitCacheEntry{tokensPerMin: t})
	return t, nil
}

// GetUserRateLimitEntry is the config GET surface: the full row with
// metadata and model limits, read from the store directly (config reads are
// not on the datapath). ErrKeyNotFound when no row exists.
func (s *Service) GetUserRateLimitEntry(tenantID, userID string) (*cmn.UserRateLimitEntry, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	e := &cmn.UserRateLimitEntry{TenantID: tenantID, UserID: userID}
	err = db.QueryRow(sqlSelectUserRateLimitFull, tenantID, userID).
		Scan(&e.RPS, &e.BurstSize, &e.TokensPerMin, &e.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	rows, err := db.Query(sqlSelectUserModelRateLimits, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ml cmn.UserModelRateLimit
		if err := rows.Scan(&ml.Model, &ml.TokensPerMin); err != nil {
			return nil, err
		}
		e.ModelLimits = append(e.ModelLimits, ml)
	}
	return e, rows.Err()
}

// ListUserRateLimits returns every explicit user row for a tenant, without
// model limits (the per-user GET carries those).
func (s *Service) ListUserRateLimits(tenantID string) ([]cmn.UserRateLimitEntry, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(sqlSelectUserRateLimitsByTenant, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []cmn.UserRateLimitEntry{}
	for rows.Next() {
		e := cmn.UserRateLimitEntry{TenantID: tenantID}
		if err := rows.Scan(&e.UserID, &e.RPS, &e.BurstSize, &e.TokensPerMin, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteUserRateLimit removes a user's explicit row and its model rows. The
// clear is a store-confirmed answer ("no limits"), so it is remembered —
// a bare eviction would leave the last-known map still enforcing the
// removed limit through the next outage.
func (s *Service) DeleteUserRateLimit(tenantID, userID string) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	res, err := db.Exec(sqlDeleteUserRateLimit, tenantID, userID)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to delete user rate limit for %s/%s: %v\n", tenantID, userID, err)
		return err
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
		return ErrKeyNotFound
	}
	if _, err := db.Exec(sqlDeleteUserModelRateLimits, tenantID, userID); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to delete user model rate limits for %s/%s: %v\n", tenantID, userID, err)
		return err
	}
	s.rememberUserRateLimit(cacheKeyForUser(tenantID, userID), &userRateLimitCacheEntry{})
	s.Cache.Delete(cacheKeyForUser(tenantID, userID))
	tk.LogIt(tk.LogInfo, "[AIKey] Deleted user rate limit for %s/%s\n", tenantID, userID)
	return nil
}

// SetRateLimitDefaults upserts one defaults row. Scope 'global' must carry
// no rule_ident; scope 'rule' must carry one. All-zero rows are refused for
// the same reason all-zero user rows are.
func (s *Service) SetRateLimitDefaults(entry cmn.RateLimitDefaultsEntry) error {
	switch entry.Scope {
	case cmn.RateLimitScopeGlobal:
		if entry.RuleIdent != "" {
			return cmn.NewValidationError("rule_ident", "scope 'global' does not take a rule_ident")
		}
	case cmn.RateLimitScopeRule:
		if entry.RuleIdent == "" {
			return cmn.NewValidationError("rule_ident", "scope 'rule' requires a rule_ident")
		}
		if err := ValidateQoSIdentity("rule_ident", entry.RuleIdent); err != nil {
			return err
		}
	default:
		return cmn.NewValidationError("scope", "invalid scope %q: must be 'global' or 'rule'", entry.Scope)
	}
	vals := []int{entry.DefaultUserRPS, entry.DefaultUserTPM, entry.DefaultTenantRPS,
		entry.DefaultTenantTPM, entry.VipSharedRPS, entry.VipSharedTPM}
	decides := false
	for _, v := range vals {
		if v < 0 {
			return cmn.NewValidationError("", "rate limit values must not be negative")
		}
		if v > 0 {
			decides = true
		}
	}
	if !decides {
		return cmn.NewValidationError("", "a defaults entry must set at least one non-zero limit (zero falls through; use DELETE to remove the row)")
	}

	db, err := s.store()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := db.Exec(sqlUpsertRateLimitDefaults,
		entry.Scope, entry.RuleIdent, entry.DefaultUserRPS, entry.DefaultUserTPM,
		entry.DefaultTenantRPS, entry.DefaultTenantTPM, entry.VipSharedRPS, entry.VipSharedTPM, now); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to set rate limit defaults (%s/%s): %v\n", entry.Scope, entry.RuleIdent, err)
		return err
	}
	s.rememberDefaults(cacheKeyForDefaults(entry.Scope, entry.RuleIdent), &defaultsCacheEntry{
		userRPS: entry.DefaultUserRPS, userTPM: entry.DefaultUserTPM,
		tenantRPS: entry.DefaultTenantRPS, tenantTPM: entry.DefaultTenantTPM,
		vipRPS: entry.VipSharedRPS, vipTPM: entry.VipSharedTPM, exists: true,
	})
	if entry.VipSharedTPM > 0 {
		// Same contract as the user-limit warning: the write is accepted,
		// but it must not look like protection nothing provides. The token
		// side of the shared bucket is charged by metered (credentialed)
		// traffic; keyless responses are not token-metered yet, so on a
		// service with only keyless traffic this bound cannot trip.
		tk.LogIt(tk.LogWarning,
			"[AIKey] rate limit defaults (%s/%s): vip_shared_tpm is charged by metered traffic only — keyless responses are not token-metered; vip_shared_rps is the always-live keyless bound\n",
			entry.Scope, entry.RuleIdent)
	}
	tk.LogIt(tk.LogInfo, "[AIKey] Set rate limit defaults (%s/%s): user rps=%d tpm=%d, tenant rps=%d tpm=%d, vip rps=%d tpm=%d\n",
		entry.Scope, entry.RuleIdent, entry.DefaultUserRPS, entry.DefaultUserTPM,
		entry.DefaultTenantRPS, entry.DefaultTenantTPM, entry.VipSharedRPS, entry.VipSharedTPM)
	return nil
}

func (s *Service) rememberDefaults(cacheKey string, e *defaultsCacheEntry) {
	s.Cache.Set(cacheKey, e, CacheExpirationTime*time.Minute)
	s.rlLastKnown.Store(cacheKey, e)
}

func (s *Service) lastKnownDefaults(cacheKey string) (*defaultsCacheEntry, bool) {
	if v, ok := s.rlLastKnown.Load(cacheKey); ok {
		if e, ok2 := v.(*defaultsCacheEntry); ok2 {
			return e, true
		}
	}
	return nil, false
}

// GetRateLimitDefaults is the hot-path defaults read for one scope row.
// exists=false with a nil error is the store-confirmed "no such row" —
// the ladder falls through. Error semantics as GetUserRateLimit.
func (s *Service) GetRateLimitDefaults(scope, ruleIdent string) (entry cmn.RateLimitDefaultsEntry, exists bool, err error) {
	entry = cmn.RateLimitDefaultsEntry{Scope: scope, RuleIdent: ruleIdent}
	cacheKey := cacheKeyForDefaults(scope, ruleIdent)
	fill := func(e *defaultsCacheEntry) (cmn.RateLimitDefaultsEntry, bool, error) {
		entry.DefaultUserRPS, entry.DefaultUserTPM = e.userRPS, e.userTPM
		entry.DefaultTenantRPS, entry.DefaultTenantTPM = e.tenantRPS, e.tenantTPM
		entry.VipSharedRPS, entry.VipSharedTPM = e.vipRPS, e.vipTPM
		return entry, e.exists, nil
	}
	if cached, found := s.Cache.Get(cacheKey); found {
		if e, ok := cached.(*defaultsCacheEntry); ok {
			return fill(e)
		}
	}
	db, dbErr := s.store()
	if dbErr != nil {
		if e, ok := s.lastKnownDefaults(cacheKey); ok {
			return fill(e)
		}
		return entry, false, errStoreUnavailable
	}
	e := &defaultsCacheEntry{}
	err = db.QueryRow(sqlSelectRateLimitDefaults, scope, ruleIdent).
		Scan(&e.userRPS, &e.userTPM, &e.tenantRPS, &e.tenantTPM, &e.vipRPS, &e.vipTPM)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.rememberDefaults(cacheKey, &defaultsCacheEntry{})
			return entry, false, nil
		}
		tk.LogIt(tk.LogError, "[AIKey] Failed to get rate limit defaults (%s/%s): %v\n", scope, ruleIdent, err)
		if le, ok := s.lastKnownDefaults(cacheKey); ok {
			return fill(le)
		}
		return entry, false, errStoreUnavailable
	}
	e.exists = true
	s.rememberDefaults(cacheKey, e)
	return fill(e)
}

// GetRateLimitDefaultsEntry is the config GET surface (store-direct, with
// metadata). ErrKeyNotFound when the row does not exist.
func (s *Service) GetRateLimitDefaultsEntry(scope, ruleIdent string) (*cmn.RateLimitDefaultsEntry, error) {
	db, err := s.store()
	if err != nil {
		return nil, err
	}
	e := &cmn.RateLimitDefaultsEntry{Scope: scope, RuleIdent: ruleIdent}
	err = db.QueryRow(sqlSelectRateLimitDefaultsFull, scope, ruleIdent).
		Scan(&e.DefaultUserRPS, &e.DefaultUserTPM, &e.DefaultTenantRPS, &e.DefaultTenantTPM,
			&e.VipSharedRPS, &e.VipSharedTPM, &e.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return e, nil
}

// DeleteRateLimitDefaults removes one defaults row; the clear is remembered
// as the store-confirmed "no row" for the outage window.
func (s *Service) DeleteRateLimitDefaults(scope, ruleIdent string) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	res, err := db.Exec(sqlDeleteRateLimitDefaults, scope, ruleIdent)
	if err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Failed to delete rate limit defaults (%s/%s): %v\n", scope, ruleIdent, err)
		return err
	}
	if n, aerr := res.RowsAffected(); aerr == nil && n == 0 {
		return ErrKeyNotFound
	}
	s.rememberDefaults(cacheKeyForDefaults(scope, ruleIdent), &defaultsCacheEntry{})
	s.Cache.Delete(cacheKeyForDefaults(scope, ruleIdent))
	tk.LogIt(tk.LogInfo, "[AIKey] Deleted rate limit defaults (%s/%s)\n", scope, ruleIdent)
	return nil
}

// PatchAPIKeyRateLimits updates the three rate-limit columns of an existing
// key — the PATCH gap fix: these were settable at creation and then frozen,
// so operators recycled keys to change a limit, invalidating credentials
// their clients were still holding. Only non-nil fields change. The cache
// is evicted (locally and on peers) because the validation path caches the
// whole entry, limits included.
func (s *Service) PatchAPIKeyRateLimits(keyID string, rps, burstSize, tokensPerMin *int) error {
	if rps == nil && burstSize == nil && tokensPerMin == nil {
		return nil
	}
	for _, v := range []*int{rps, burstSize, tokensPerMin} {
		if v != nil && *v < 0 {
			return cmn.NewValidationError("", "rate limit values must not be negative")
		}
	}
	db, err := s.store()
	if err != nil {
		return err
	}
	keyHash, err := s.keyHashByID(db, keyID)
	if err != nil {
		return err
	}
	if rps != nil {
		if _, err = db.Exec(sqlUpdateAPIKeyRPS, *rps, keyID); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to patch rate_limit_rps for key %s: %v\n", keyID, err)
			return err
		}
	}
	if burstSize != nil {
		if _, err = db.Exec(sqlUpdateAPIKeyBurst, *burstSize, keyID); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to patch burst_size for key %s: %v\n", keyID, err)
			return err
		}
	}
	if tokensPerMin != nil {
		if _, err = db.Exec(sqlUpdateAPIKeyTPM, *tokensPerMin, keyID); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to patch tokens_per_min for key %s: %v\n", keyID, err)
			return err
		}
	}
	s.evictAndFanOut(KeyInvalidation{KeyHash: keyHash, KeyID: keyID})
	tk.LogIt(tk.LogInfo, "[AIKey] Patched rate limits for API key %s\n", keyID)
	return nil
}

var (
	sqlUpdateAPIKeyRPS = fmt.Sprintf(
		`UPDATE %s.api_keys SET rate_limit_rps = $1 WHERE key_id = $2`, Schema)
	sqlUpdateAPIKeyBurst = fmt.Sprintf(
		`UPDATE %s.api_keys SET burst_size = $1 WHERE key_id = $2`, Schema)
	sqlUpdateAPIKeyTPM = fmt.Sprintf(
		`UPDATE %s.api_keys SET tokens_per_min = $1 WHERE key_id = $2`, Schema)
)
