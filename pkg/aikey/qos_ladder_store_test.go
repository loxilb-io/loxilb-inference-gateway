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
	if _, err := svc.GetUserRateLimitEntry("t1", "alice"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("after delete: want ErrKeyNotFound, got %v", err)
	}
	if err := svc.DeleteUserRateLimit("t1", "alice"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("double delete: want ErrKeyNotFound, got %v", err)
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
	if _, err := svc.GetRateLimitDefaultsEntry(cmn.RateLimitScopeGlobal, ""); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("after delete: want ErrKeyNotFound, got %v", err)
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
