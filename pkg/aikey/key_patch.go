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
	"strings"
	"time"

	tk "github.com/loxilb-io/loxilb/internal/tk"

	cmn "github.com/loxilb-io/loxilb/common"
)

// PatchAPIKeyAll applies every field a PATCH names to one key in one
// transaction. A field left nil is not touched. The key's cache entry is
// evicted afterwards, here and on the peers, because a patch that disables
// a key or lowers its limit is a revocation by another name.
//
// One transaction, because one PATCH is one request and gets one outcome:
// before this, the allowed_models, rate-limit and class statements of a
// single PATCH ran one after another through three hooks, and a store that
// stalled between two of them left the key half-changed with the caller
// told about the statement that failed and nothing about the ones that had
// already been applied.
func (s *Service) PatchAPIKeyAll(ctx context.Context, keyID string, patch cmn.ApiKeyPatch) error {
	if patch.IsZero() {
		return nil
	}
	for _, v := range []*int{patch.RateLimitRPS, patch.BurstSize, patch.TokensPerMin} {
		if v != nil && *v < 0 {
			return cmn.NewValidationError("", "rate limit values must not be negative")
		}
	}
	pc, def, allowed, err := classPatchArgs(patch.Class)
	if err != nil {
		return err
	}
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()

	var keyHash string
	err = inTx(ctx, db, func(tx stmtRunner) error {
		var err error
		// The hash is what the cache is keyed by; resolving it first also
		// makes a patch of a key that does not exist a 404 before anything
		// is written.
		if keyHash, err = s.keyHashByID(ctx, tx, keyID); err != nil {
			return err
		}
		if patch.AllowedModels != nil {
			models := strings.Join(patch.AllowedModels, ",")
			if _, err = tx.ExecContext(ctx, sqlUpdateAPIKeyAllowedModels, models, keyID); err != nil {
				tk.LogIt(tk.LogError, "[AIKey] Failed to patch allowed_models for key %s: %v\n", keyID, err)
				return writeErr(err)
			}
		}
		if patch.Enabled != nil {
			if _, err = tx.ExecContext(ctx, sqlUpdateAPIKeyEnabled, *patch.Enabled, keyID); err != nil {
				tk.LogIt(tk.LogError, "[AIKey] Failed to patch enabled for key %s: %v\n", keyID, err)
				return writeErr(err)
			}
		}
		if patch.RateLimitRPS != nil {
			if _, err = tx.ExecContext(ctx, sqlUpdateAPIKeyRPS, *patch.RateLimitRPS, keyID); err != nil {
				tk.LogIt(tk.LogError, "[AIKey] Failed to patch rate_limit_rps for key %s: %v\n", keyID, err)
				return writeErr(err)
			}
		}
		if patch.BurstSize != nil {
			if _, err = tx.ExecContext(ctx, sqlUpdateAPIKeyBurst, *patch.BurstSize, keyID); err != nil {
				tk.LogIt(tk.LogError, "[AIKey] Failed to patch burst_size for key %s: %v\n", keyID, err)
				return writeErr(err)
			}
		}
		if patch.TokensPerMin != nil {
			if _, err = tx.ExecContext(ctx, sqlUpdateAPIKeyTPM, *patch.TokensPerMin, keyID); err != nil {
				tk.LogIt(tk.LogError, "[AIKey] Failed to patch tokens_per_min for key %s: %v\n", keyID, err)
				return writeErr(err)
			}
		}
		if !patch.Class.IsZero() {
			if _, err = tx.ExecContext(ctx, sqlPatchKeyClass, keyID, pc, def, allowed); err != nil {
				tk.LogIt(tk.LogError, "[AIKey] Failed to patch class of key %s: %v\n", keyID, err)
				return writeErr(err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.evictAndFanOut(KeyInvalidation{KeyHash: keyHash, KeyID: keyID})
	if !patch.Class.IsZero() {
		s.refreshClassesAfterWrite()
	}
	tk.LogIt(tk.LogInfo, "[AIKey] Patched API key %s\n", keyID)
	return nil
}

// SetTenantLimits writes a tenant's aggregate limit and the per-model
// quotas carried with it in one transaction: the entry the caller sent is
// the entry that exists afterwards, or nothing changed. A model with a
// non-positive quota is removed, as SetTenantModelRateLimit removes it.
//
// The caches are updated only after the commit, from the values written,
// so a transaction that failed leaves the last store-confirmed values in
// force and nothing the store never accepted.
func (s *Service) SetTenantLimits(ctx context.Context, tenantID string, rps, tokensPerMin, burstPct int, modelLimits []cmn.TenantModelRateLimit) error {
	if err := ValidateQoSIdentity("tenant_id", tenantID); err != nil {
		return err
	}
	if tenantID == "" {
		return cmn.NewValidationError("tenant_id", "tenant_id is required")
	}
	for _, ml := range modelLimits {
		if err := ValidateQoSIdentity("model", ml.Model); err != nil {
			return err
		}
		if ml.Model == "" {
			return cmn.NewValidationError("model", "model is required for a model rate limit")
		}
	}
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := s.opContext(ctx)
	defer cancel()
	now := time.Now().UTC()

	err = inTx(ctx, db, func(tx stmtRunner) error {
		if _, err := tx.ExecContext(ctx, sqlUpsertTenantRateLimit, tenantID, rps, tokensPerMin, burstPct, now); err != nil {
			tk.LogIt(tk.LogError, "[AIKey] Failed to set rate limit for tenant %s: %v\n", tenantID, err)
			return writeErr(err)
		}
		for _, ml := range modelLimits {
			if ml.TokensPerMin <= 0 {
				if _, err := tx.ExecContext(ctx, sqlDeleteTenantModelRateLimit, tenantID, ml.Model); err != nil {
					tk.LogIt(tk.LogError, "[AIKey] Failed to clear model rate limit for %s/%s: %v\n", tenantID, ml.Model, err)
					return writeErr(err)
				}
				continue
			}
			if _, err := tx.ExecContext(ctx, sqlUpsertTenantModelRateLimit, tenantID, ml.Model, ml.TokensPerMin, now); err != nil {
				tk.LogIt(tk.LogError, "[AIKey] Failed to set model rate limit for %s/%s: %v\n", tenantID, ml.Model, err)
				return writeErr(err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.rememberRateLimit(cacheKeyForTenant(tenantID),
		&rateLimitCacheEntry{rps: rps, tokensPerMin: tokensPerMin, burstPct: burstPct})
	for _, ml := range modelLimits {
		cacheKey := cacheKeyForModel(tenantID, ml.Model)
		if ml.TokensPerMin <= 0 {
			// The clear is a store-confirmed "no limit", remembered rather
			// than merely dropped so the last-known map does not go on
			// enforcing the removed quota through the next outage.
			s.rememberRateLimit(cacheKey, &rateLimitCacheEntry{})
			s.Cache.Delete(cacheKey)
			continue
		}
		s.rememberRateLimit(cacheKey, &rateLimitCacheEntry{tokensPerMin: ml.TokensPerMin})
	}
	tk.LogIt(tk.LogInfo, "[AIKey] Set rate limit for tenant %s: rps=%d tokensPerMin=%d burstPct=%d models=%d\n",
		tenantID, rps, tokensPerMin, burstPct, len(modelLimits))
	// The last-known-good file carries the limit rows: it follows the write
	// at once, not one refresh interval later.
	s.refreshClassesAfterWrite()
	return nil
}
