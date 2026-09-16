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

import (
	"errors"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// The store legs run against a live PostgreSQL (storeFixture / testDSNEnv),
// like every other leg in this package. Validation legs run anywhere: the
// refusals fire before the pool is touched.

// TestUserRateLimitValidationRefusals: the refusals that keep the bucket
// keyspace unambiguous fire BEFORE any store round-trip, so they hold even
// on a gateway whose store is down.
func TestUserRateLimitValidationRefusals(t *testing.T) {
	svc := &Service{} // no store attached: a refusal reaching the pool would error differently
	cases := []struct {
		name  string
		entry cmn.UserRateLimitEntry
	}{
		{"pipe in tenant", cmn.UserRateLimitEntry{TenantID: "t|1", UserID: "u", RPS: 1}},
		{"pipe in user", cmn.UserRateLimitEntry{TenantID: "t1", UserID: "a|b", RPS: 1}},
		{"reserved prefix tenant", cmn.UserRateLimitEntry{TenantID: "uq:t1", UserID: "u", RPS: 1}},
		{"reserved prefix user", cmn.UserRateLimitEntry{TenantID: "t1", UserID: "v:x", RPS: 1}},
		{"pipe in model", cmn.UserRateLimitEntry{TenantID: "t1", UserID: "u", RPS: 1,
			ModelLimits: []cmn.UserModelRateLimit{{Model: "a|b", TokensPerMin: 5}}}},
		{"negative rps", cmn.UserRateLimitEntry{TenantID: "t1", UserID: "u", RPS: -1}},
		{"all-zero entry decides nothing", cmn.UserRateLimitEntry{TenantID: "t1", UserID: "u"}},
		{"missing user", cmn.UserRateLimitEntry{TenantID: "t1", RPS: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.SetUserRateLimit(tc.entry)
			if err == nil {
				t.Fatalf("entry must be refused at validation")
			}
			if errors.Is(err, ErrDBUnavailable) {
				t.Fatalf("refusal reached the store; validation must fire first (got %v)", err)
			}
			// The refusal must be TYPED: the API layer classifies by
			// structure, and an untyped refusal falls to the phrase
			// classifier, whose default is a 500 that tells the caller
			// nothing. This exact class shipped once and was caught by the
			// live smoke, not the compiler — hence the pin.
			var ve *cmn.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("refusal is not a *cmn.ValidationError (got %T) — the API would answer 500", err)
			}
		})
	}
}

// TestRateLimitDefaultsValidationRefusals: same property for the defaults
// surface, including the scope/rule_ident pairing rules.
func TestRateLimitDefaultsValidationRefusals(t *testing.T) {
	svc := &Service{}
	cases := []struct {
		name  string
		entry cmn.RateLimitDefaultsEntry
	}{
		{"unknown scope", cmn.RateLimitDefaultsEntry{Scope: "vip", DefaultUserRPS: 1}},
		{"global with rule_ident", cmn.RateLimitDefaultsEntry{Scope: "global", RuleIdent: "x", DefaultUserRPS: 1}},
		{"rule without rule_ident", cmn.RateLimitDefaultsEntry{Scope: "rule", DefaultUserRPS: 1}},
		{"rule_ident with pipe", cmn.RateLimitDefaultsEntry{Scope: "rule", RuleIdent: "a|b", DefaultUserRPS: 1}},
		{"negative value", cmn.RateLimitDefaultsEntry{Scope: "global", DefaultUserTPM: -5}},
		{"all-zero row decides nothing", cmn.RateLimitDefaultsEntry{Scope: "global"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.SetRateLimitDefaults(tc.entry)
			if err == nil {
				t.Fatalf("entry must be refused at validation")
			}
			if errors.Is(err, ErrDBUnavailable) {
				t.Fatalf("refusal reached the store; validation must fire first (got %v)", err)
			}
			var ve *cmn.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("refusal is not a *cmn.ValidationError (got %T) — the API would answer 500", err)
			}
		})
	}
}

// TestUserRateLimitRoundTrip: upsert → hot read → config read → replace
// model set → delete, with the cache answering between store reads.
func TestUserRateLimitRoundTrip(t *testing.T) {
	svc := storeFixture(t)

	entry := cmn.UserRateLimitEntry{
		TenantID: "t1", UserID: "alice", RPS: 5, BurstSize: 10, TokensPerMin: 1000,
		ModelLimits: []cmn.UserModelRateLimit{
			{Model: "llama-70b", TokensPerMin: 400},
			{Model: "mistral-7b", TokensPerMin: 300},
		},
	}
	if err := svc.SetUserRateLimit(entry); err != nil {
		t.Fatalf("set: %v", err)
	}

	rps, burst, tpm, err := svc.GetUserRateLimit("t1", "alice")
	if err != nil || rps != 5 || burst != 10 || tpm != 1000 {
		t.Fatalf("hot read: got (%d,%d,%d,%v) want (5,10,1000,nil)", rps, burst, tpm, err)
	}
	mtpm, err := svc.GetUserModelRateLimit("t1", "alice", "llama-70b")
	if err != nil || mtpm != 400 {
		t.Fatalf("model read: got (%d,%v) want (400,nil)", mtpm, err)
	}

	full, err := svc.GetUserRateLimitEntry("t1", "alice")
	if err != nil {
		t.Fatalf("config read: %v", err)
	}
	if len(full.ModelLimits) != 2 {
		t.Fatalf("config read: %d model limits, want 2", len(full.ModelLimits))
	}

	// Model limits REPLACE as a set: re-post with one model, the other must
	// be gone — a merge here would resurrect removed limits forever.
	entry.ModelLimits = []cmn.UserModelRateLimit{{Model: "llama-70b", TokensPerMin: 200}}
	if err := svc.SetUserRateLimit(entry); err != nil {
		t.Fatalf("replace: %v", err)
	}
	full, err = svc.GetUserRateLimitEntry("t1", "alice")
	if err != nil || len(full.ModelLimits) != 1 || full.ModelLimits[0].TokensPerMin != 200 {
		t.Fatalf("after replace: %+v, %v", full, err)
	}

	list, err := svc.ListUserRateLimits("t1")
	if err != nil || len(list) != 1 || list[0].UserID != "alice" {
		t.Fatalf("list: %+v, %v", list, err)
	}

	if err := svc.DeleteUserRateLimit("t1", "alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// A missing user rate-limit row reports itself as a user rate-limit row,
	// not as an API key. It still satisfies errors.Is(err, ErrNotFound), which
	// is what the REST layer classifies 404 on.
	_, err = svc.GetUserRateLimitEntry("t1", "alice")
	if !errors.Is(err, ErrUserRateLimitNotFound) {
		t.Fatalf("after delete: want ErrUserRateLimitNotFound, got %v", err)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: want it to satisfy ErrNotFound, got %v", err)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("after delete: a user rate-limit row must not report as a missing API key: %v", err)
	}
	if err := svc.DeleteUserRateLimit("t1", "alice"); !errors.Is(err, ErrUserRateLimitNotFound) {
		t.Fatalf("double delete: want ErrUserRateLimitNotFound, got %v", err)
	}
	// The hot path reads the confirmed "no row" — zeroes with nil error.
	rps, _, tpm, err = svc.GetUserRateLimit("t1", "alice")
	if err != nil || rps != 0 || tpm != 0 {
		t.Fatalf("hot read after delete: got (%d,%d,%v) want zeroes,nil", rps, tpm, err)
	}
}

// TestUserRateLimitOutageServesLastKnown: with the pool gone, the hot read
// answers the last store-confirmed value; a pair the store never answered
// for refuses instead of reading as unlimited.
func TestUserRateLimitOutageServesLastKnown(t *testing.T) {
	svc := storeFixture(t)
	if err := svc.SetUserRateLimit(cmn.UserRateLimitEntry{TenantID: "t1", UserID: "alice", RPS: 7}); err != nil {
		t.Fatalf("set: %v", err)
	}
	// Prime the miss for bob too: the store CONFIRMS he has no row.
	if _, _, _, err := svc.GetUserRateLimit("t1", "bob"); err != nil {
		t.Fatalf("prime bob: %v", err)
	}

	// Outage: detach the pool and expire the TTL cache so only the
	// last-known map can answer.
	detachStore(svc)
	svc.Cache.Flush()

	rps, _, _, err := svc.GetUserRateLimit("t1", "alice")
	if err != nil || rps != 7 {
		t.Fatalf("outage read of a confirmed row: got (%d,%v) want (7,nil)", rps, err)
	}
	if rps, _, _, err := svc.GetUserRateLimit("t1", "bob"); err != nil || rps != 0 {
		t.Fatalf("outage read of a confirmed miss: got (%d,%v) want (0,nil)", rps, err)
	}
	// carol was never asked about before the outage: no truthful answer
	// exists, and zeroes here would read as "unlimited".
	if _, _, _, err := svc.GetUserRateLimit("t1", "carol"); err == nil {
		t.Fatalf("outage read of a never-answered pair must fail closed")
	}
}

// TestRateLimitDefaultsRoundTrip: both scopes, the confirmed-miss answer,
// and delete.
func TestRateLimitDefaultsRoundTrip(t *testing.T) {
	svc := storeFixture(t)

	if err := svc.SetRateLimitDefaults(cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeGlobal, DefaultUserRPS: 3, DefaultTenantTPM: 9000,
	}); err != nil {
		t.Fatalf("set global: %v", err)
	}
	if err := svc.SetRateLimitDefaults(cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeRule, RuleIdent: "10.0.0.1:2040", VipSharedRPS: 2,
	}); err != nil {
		t.Fatalf("set rule: %v", err)
	}

	g, ok, err := svc.GetRateLimitDefaults(cmn.RateLimitScopeGlobal, "")
	if err != nil || !ok || g.DefaultUserRPS != 3 || g.DefaultTenantTPM != 9000 {
		t.Fatalf("global hot read: %+v ok=%v err=%v", g, ok, err)
	}
	r, ok, err := svc.GetRateLimitDefaults(cmn.RateLimitScopeRule, "10.0.0.1:2040")
	if err != nil || !ok || r.VipSharedRPS != 2 {
		t.Fatalf("rule hot read: %+v ok=%v err=%v", r, ok, err)
	}
	// A rule the table does not name: confirmed miss, not an error.
	if _, ok, err := svc.GetRateLimitDefaults(cmn.RateLimitScopeRule, "10.0.0.1:9999"); err != nil || ok {
		t.Fatalf("unnamed rule: ok=%v err=%v, want (false, nil)", ok, err)
	}

	if err := svc.DeleteRateLimitDefaults(cmn.RateLimitScopeGlobal, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = svc.GetRateLimitDefaultsEntry(cmn.RateLimitScopeGlobal, "")
	if !errors.Is(err, ErrRateLimitDefaultsNotFound) {
		t.Fatalf("after delete: want ErrRateLimitDefaultsNotFound, got %v", err)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: want it to satisfy ErrNotFound, got %v", err)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("after delete: a defaults row must not report as a missing API key: %v", err)
	}
}

// TestPatchAPIKeyRateLimits: the PATCH gap fix — the three columns change
// on a live key, nil fields stay, and the cache eviction makes the next
// validation see the new values.
func TestPatchAPIKeyRateLimits(t *testing.T) {
	svc := storeFixture(t)
	_, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{
		TenantID: "t1", Name: "patch-me", AllowedModels: []string{"m1"},
		RateLimitRPS: 10, BurstSize: 20, TokensPerMin: 3000,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	newRPS := 4
	if err := svc.PatchAPIKeyRateLimits(keyID, &newRPS, nil, nil); err != nil {
		t.Fatalf("patch rps: %v", err)
	}
	key, err := svc.GetAPIKeyByID(keyID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if key.RateLimitRPS != 4 {
		t.Errorf("rps: got %d want 4", key.RateLimitRPS)
	}
	if key.BurstSize != 20 || key.TokensPerMin != 3000 {
		t.Errorf("nil fields must stay: burst=%d tpm=%d want 20/3000", key.BurstSize, key.TokensPerMin)
	}

	neg := -1
	if err := svc.PatchAPIKeyRateLimits(keyID, nil, nil, &neg); err == nil {
		t.Fatalf("negative tpm must be refused")
	}
	if err := svc.PatchAPIKeyRateLimits("no-such-key", &newRPS, nil, nil); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown key: want ErrKeyNotFound, got %v", err)
	}
	// All-nil is a no-op, not an error: PATCH bodies naming only
	// allowed_models/enabled route the rate fields here as nils.
	if err := svc.PatchAPIKeyRateLimits(keyID, nil, nil, nil); err != nil {
		t.Fatalf("all-nil patch: %v", err)
	}
}

// TestUserModelRateLimitRemovalLeavesNoCachedQuota: a per-model quota that
// was removed must stop being enforced.
//
// Both user-side writers clear model rows WHOLESALE — SetUserRateLimit
// replaces the set, DeleteUserRateLimit removes all of them — so the models
// being dropped are never named to the writer. The hot path
// (GetUserModelRateLimit) is cache-first, so a removal that does not evict
// leaves the old quota enforcing for the rest of the TTL and, through the
// last-known map, for every later store outage.
//
// TestUserRateLimitRoundTrip already covers the removal, but only through
// GetUserRateLimitEntry — the CONFIG read, which goes straight to the store.
// That read is green whether or not the cache was evicted, which is exactly
// why the hole survived: the API reported the row gone while the gateway
// went on refusing requests against it. Every assertion here reads the HOT
// path instead.
func TestUserModelRateLimitRemovalLeavesNoCachedQuota(t *testing.T) {
	svc := storeFixture(t)

	entry := cmn.UserRateLimitEntry{
		TenantID: "t1", UserID: "alice", RPS: 5,
		ModelLimits: []cmn.UserModelRateLimit{
			{Model: "llama-70b", TokensPerMin: 400},
			{Model: "mistral-7b", TokensPerMin: 300},
		},
	}
	if err := svc.SetUserRateLimit(entry); err != nil {
		t.Fatalf("set: %v", err)
	}
	// Prime the hot path for BOTH models: a cache that was never populated
	// could not demonstrate a stale read, and this test would pass on the
	// unfixed code for the wrong reason.
	if tpm, err := svc.GetUserModelRateLimit("t1", "alice", "mistral-7b"); err != nil || tpm != 300 {
		t.Fatalf("prime mistral: got (%d,%v) want (300,nil)", tpm, err)
	}
	if tpm, err := svc.GetUserModelRateLimit("t1", "alice", "llama-70b"); err != nil || tpm != 400 {
		t.Fatalf("prime llama: got (%d,%v) want (400,nil)", tpm, err)
	}

	// Replace the set with llama only. mistral's row is deleted.
	entry.ModelLimits = []cmn.UserModelRateLimit{{Model: "llama-70b", TokensPerMin: 200}}
	if err := svc.SetUserRateLimit(entry); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if tpm, err := svc.GetUserModelRateLimit("t1", "alice", "mistral-7b"); err != nil || tpm != 0 {
		t.Fatalf("removed model still quoted on the hot path: got (%d,%v) want (0,nil)", tpm, err)
	}
	// The model that SURVIVED the replace must carry its NEW value, not be
	// collaterally forgotten by the eviction that cleared its neighbour.
	if tpm, err := svc.GetUserModelRateLimit("t1", "alice", "llama-70b"); err != nil || tpm != 200 {
		t.Fatalf("surviving model after replace: got (%d,%v) want (200,nil)", tpm, err)
	}

	// The outage window is the other half: evicting the TTL cache alone
	// would leave the last-known map answering 300 the moment the store
	// goes away.
	detachStore(svc)
	svc.Cache.Flush()
	if tpm, err := svc.GetUserModelRateLimit("t1", "alice", "mistral-7b"); err != nil || tpm != 0 {
		t.Fatalf("removed model resurrected by the outage path: got (%d,%v) want (0,nil)", tpm, err)
	}

	// The DELETE path clears model rows the same wholesale way.
	svc = storeFixture(t)
	if err := svc.SetUserRateLimit(cmn.UserRateLimitEntry{
		TenantID: "t1", UserID: "bob", RPS: 5,
		ModelLimits: []cmn.UserModelRateLimit{{Model: "llama-70b", TokensPerMin: 400}},
	}); err != nil {
		t.Fatalf("set bob: %v", err)
	}
	if tpm, err := svc.GetUserModelRateLimit("t1", "bob", "llama-70b"); err != nil || tpm != 400 {
		t.Fatalf("prime bob: got (%d,%v) want (400,nil)", tpm, err)
	}
	if err := svc.DeleteUserRateLimit("t1", "bob"); err != nil {
		t.Fatalf("delete bob: %v", err)
	}
	if tpm, err := svc.GetUserModelRateLimit("t1", "bob", "llama-70b"); err != nil || tpm != 0 {
		t.Fatalf("deleted user's model quota still enforced: got (%d,%v) want (0,nil)", tpm, err)
	}
	detachStore(svc)
	svc.Cache.Flush()
	if tpm, err := svc.GetUserModelRateLimit("t1", "bob", "llama-70b"); err != nil || tpm != 0 {
		t.Fatalf("deleted user's model quota resurrected by the outage path: got (%d,%v) want (0,nil)", tpm, err)
	}
}

// TestTenantAndKeySurfacesRefuseAliasingIdentities: the three QoS write
// surfaces that reach a bucket key through a TENANT id, held to the rule the
// user surface above has always enforced.
//
// The keyspace property is one property, and it was enforced in one place.
// The tenant aggregate quota is keyed on the BARE tenant id
// (pkg/loxinet/ai_gateway_dp.go quotaBucketsFor), and tenant|model composes
// with the same delimiter, so a tenant literally named "t1|gpt-4" IS tenant
// t1's gpt-4 bucket — two identities spending one quota. A tenant carrying a
// reserved scope prefix is the cross-scope twin: "uq:t1|alice" as a tenant
// aggregate key is a USER-scope key on the quota sync wire, so the bucket
// round-trips into a scope nobody addressed it to.
//
// Each of these three surfaces could mint such a tenant. The refusal must
// also fire ahead of the store handle: a guard that only runs once a pool
// exists answers a caller's mistake with the outage's error code, and does
// not run at all on a gateway whose store is down.
func TestTenantAndKeySurfacesRefuseAliasingIdentities(t *testing.T) {
	svc := &Service{} // no store attached, exactly as the user-surface leg above
	bad := []struct{ name, tenant string }{
		{"pipe in tenant", "t1|gpt-4"},
		{"reserved user-quota prefix", "uq:t1|alice"},
		{"reserved vip prefix", "v:llb-svc"},
		{"reserved tenant-wire prefix", "t:t1"},
	}
	for _, tc := range bad {
		t.Run("tenant_ratelimit/"+tc.name, func(t *testing.T) {
			assertValidationRefusal(t, svc.SetTenantRateLimit(tc.tenant, 1, 0, 0))
		})
		t.Run("tenant_model_ratelimit/"+tc.name, func(t *testing.T) {
			assertValidationRefusal(t, svc.SetTenantModelRateLimit(tc.tenant, "gpt-4", 10))
		})
		t.Run("apikey_create/"+tc.name, func(t *testing.T) {
			_, _, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: tc.tenant, Name: "k"})
			assertValidationRefusal(t, err)
		})
	}

	// The model half of the composite key is the same property from the other
	// side, and the ad-hoc check this surface used to carry saw only the pipe.
	for _, model := range []string{"gpt|4", "um:t1|alice|gpt-4", "kq:abc"} {
		t.Run("tenant_model_ratelimit/model "+model, func(t *testing.T) {
			assertValidationRefusal(t, svc.SetTenantModelRateLimit("t1", model, 10))
		})
	}

	// Non-vacuity: an ordinary identity must still reach the store, or a
	// validator that refused everything would pass every case above and take
	// the whole config surface down.
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"tenant_ratelimit", svc.SetTenantRateLimit("t1", 1, 0, 0)},
		{"tenant_model_ratelimit", svc.SetTenantModelRateLimit("t1", "gpt-4", 10)},
	} {
		if !errors.Is(tc.err, ErrDBUnavailable) {
			t.Errorf("%s: a valid identity was refused before the store (got %v) — "+
				"the guard is rejecting ordinary names", tc.name, tc.err)
		}
	}
	if _, _, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "t1", Name: "k"}); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("apikey_create: a valid tenant was refused before the store (got %v)", err)
	}
}

// assertValidationRefusal is the shared oracle of the leg above: refused,
// refused BEFORE the store, and refused with the type the API layer
// classifies on.
func assertValidationRefusal(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("identity must be refused at validation")
	}
	if errors.Is(err, ErrDBUnavailable) {
		t.Fatalf("refusal reached the store; validation must fire first (got %v)", err)
	}
	var ve *cmn.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("refusal is not a *cmn.ValidationError (got %T) — the API would answer 500", err)
	}
}
