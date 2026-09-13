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

package loxinet

// The QoS ladder corpus (D-2/D-6). The dimension under test in each case is
// the ONLY limited one, so a denial can come from exactly one bucket — and
// the adversarial cases then stack dimensions to prove the buckets do not
// bleed into each other: one user's throttling must not touch its
// neighbour, and no user's personal headroom may pierce the tenant's
// ceiling.

import (
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	rl "github.com/loxilb-io/loxilb/pkg/ratelimit"
)

// ladderSvc builds a mock with one tenant, two explicit users and a
// defaults table, mirroring the shape an IdP-backed deployment holds.
func ladderSvc() *mockRateLimitService {
	return &mockRateLimitService{
		tenantRPS: 0, // per-case
		userRows:  map[string]cmn.UserRateLimitEntry{},
		defaults:  map[string]cmn.RateLimitDefaultsEntry{},
	}
}

// TestLadderExplicitUserRPS: an explicit user row's rps binds that user.
func TestLadderExplicitUserRPS(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.userRows["t1|alice"] = cmn.UserRateLimitEntry{TenantID: "t1", UserID: "alice", RPS: 2}

	for i := 1; i <= 2; i++ {
		if d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", ""); d != 0 {
			t.Fatalf("request %d: expected allow, got decision=%d code=%q", i, d, code)
		}
	}
	d, retry, code := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", "")
	if d != 3 {
		t.Fatalf("request 3: expected deny_429, got decision=%d", d)
	}
	if code != "user_rate_limit_exceeded" {
		t.Errorf("expected user_rate_limit_exceeded, got %q", code)
	}
	if retry <= 0 {
		t.Errorf("expected retry > 0, got %d", retry)
	}
}

// TestLadderDefaultUserRPSIsolation is the two-users adversarial leg: with
// NO explicit rows and a default-user limit, one user exhausting its bucket
// must not consume the other's. A shared bucket would pass a single-user
// test identically — only the neighbour probe can tell them apart.
func TestLadderDefaultUserRPSIsolation(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.defaults["global|"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeGlobal, DefaultUserRPS: 2,
	}

	// alice spends her default allowance to the deny.
	for i := 1; i <= 2; i++ {
		if d, _, _ := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", ""); d != 0 {
			t.Fatalf("alice request %d: expected allow, got decision=%d", i, d)
		}
	}
	if d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", ""); d != 3 || code != "user_rate_limit_exceeded" {
		t.Fatalf("alice request 3: expected user_rate_limit_exceeded deny, got decision=%d code=%q", d, code)
	}

	// bob is untouched: the default names a PER-user allowance, not a pool.
	if d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "bob", "", ""); d != 0 {
		t.Fatalf("bob after alice's deny: expected allow, got decision=%d code=%q", d, code)
	}
}

// TestLadderExplicitUserOverridesDefault: an explicit row beats the default
// in BOTH directions — a tighter row denies sooner, a looser row admits
// past the default. The loose direction is the one a fall-through bug
// cannot pass: if the default were consulted first, carol would be denied
// at 1 rps despite her explicit 5.
func TestLadderExplicitUserOverridesDefault(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.defaults["global|"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeGlobal, DefaultUserRPS: 1,
	}
	svc.userRows["t1|carol"] = cmn.UserRateLimitEntry{TenantID: "t1", UserID: "carol", RPS: 5}

	for i := 1; i <= 5; i++ {
		if d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "carol", "", ""); d != 0 {
			t.Fatalf("carol request %d: explicit rps=5 should beat default rps=1; got decision=%d code=%q", i, d, code)
		}
	}
	if d, _, _ := rateLimitCheckInternal(svc, store, "", "t1", "carol", "", ""); d != 3 {
		t.Fatalf("carol request 6: expected deny at her explicit limit, got decision=%d", d)
	}
}

// TestLadderTenantCapsSumOfUsers: users inside their own budgets are still
// stopped by the tenant ceiling — the tenant bucket bounds the SUM.
func TestLadderTenantCapsSumOfUsers(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.tenantRPS = 3
	svc.defaults["global|"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeGlobal, DefaultUserRPS: 10, // generous per-user
	}

	users := []string{"u1", "u2", "u3", "u4"}
	denied := ""
	for i, u := range users {
		d, _, code := rateLimitCheckInternal(svc, store, "", "t1", u, "", "")
		if i < 3 && d != 0 {
			t.Fatalf("request %d (%s): inside tenant budget, expected allow, got decision=%d code=%q", i+1, u, d, code)
		}
		if i == 3 {
			if d != 3 {
				t.Fatalf("request 4 (%s): tenant rps=3 must cap the sum, got decision=%d", u, d)
			}
			denied = code
		}
	}
	if denied != "tenant_quota_exceeded" {
		t.Errorf("the sum-cap denial must be the TENANT's code, got %q", denied)
	}
}

// TestLadderRuleDefaultsOverrideGlobalFieldwise: a rule-scope row overrides
// the global row per FIELD — its zero fields keep falling through.
func TestLadderRuleDefaultsOverrideGlobalFieldwise(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.defaults["global|"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeGlobal, DefaultUserRPS: 5, DefaultUserTPM: 1000,
	}
	svc.defaults["rule|10.10.10.254:2040"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeRule, RuleIdent: "10.10.10.254:2040", DefaultUserRPS: 1,
		// DefaultUserTPM deliberately zero: must fall through to global 1000.
	}

	d, err := resolveQoSDefaults(svc, "10.10.10.254:2040")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if d.userRPS != 1 {
		t.Errorf("rule row must override userRPS: got %d want 1", d.userRPS)
	}
	if d.userTPM != 1000 {
		t.Errorf("rule row's zero userTPM must fall through to global: got %d want 1000", d.userTPM)
	}

	// And on the wire: one request on the rule passes, the second denies —
	// the rule override, not the global 5.
	if d1, _, _ := rateLimitCheckInternal(svc, store, "", "t1", "dave", "10.10.10.254:2040", ""); d1 != 0 {
		t.Fatalf("first request: expected allow, got %d", d1)
	}
	if d2, _, code := rateLimitCheckInternal(svc, store, "", "t1", "dave", "10.10.10.254:2040", ""); d2 != 3 || code != "user_rate_limit_exceeded" {
		t.Fatalf("second request: rule default rps=1 must deny, got decision=%d code=%q", d2, code)
	}
}

// TestLadderUserTPMDebtLatch: a user token-quota charge that lands the
// bucket in debt denies THAT USER's next request and nobody else's.
func TestLadderUserTPMDebtLatch(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.tenantRPS = 1000
	svc.userRows["t1|alice"] = cmn.UserRateLimitEntry{TenantID: "t1", UserID: "alice", TokensPerMin: 100}

	// Charge alice 150/100 through the settle path — her bucket latches.
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "t1", "", "alice", "", "", 150, 0, 0); allowed {
		t.Fatalf("charging 150 against tpm=100 must report debt")
	}
	d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", "")
	if d != 3 || code != "token_quota_exceeded" {
		t.Fatalf("alice after debt: expected token_quota_exceeded deny, got decision=%d code=%q", d, code)
	}
	// bob (no TPM row, no default) sails through.
	if d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "bob", "", ""); d != 0 {
		t.Fatalf("bob after alice's debt: expected allow, got decision=%d code=%q", d, code)
	}
}

// TestLadderUserModelTPM: the user|model bucket denies only that pair.
func TestLadderUserModelTPM(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.tenantRPS = 1000
	svc.userModelTPM = map[string]int{"t1|alice|llama-70b": 100}

	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "t1", "llama-70b", "alice", "", "", 150, 0, 0); allowed {
		t.Fatalf("um charge 150/100 must report debt")
	}
	if d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", "llama-70b"); d != 3 || code != "token_quota_exceeded" {
		t.Fatalf("alice+llama after debt: expected deny, got decision=%d code=%q", d, code)
	}
	// Same user, other model: the um bucket must not bleed across models.
	if d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", "mistral-7b"); d != 0 {
		t.Fatalf("alice+mistral: expected allow, got decision=%d code=%q", d, code)
	}
}

// TestLadderKeyTPMDebtLatch: the key's own tokens_per_min — stored since
// the field existed and never enforced — now latches like every other
// bucket (ladder level 1.5).
func TestLadderKeyTPMDebtLatch(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.tenantRPS = 1000
	svc.keyByID = map[string]*cmn.ApiKeySummary{
		"key-1": {KeyID: "key-1", TokensPerMin: 100},
	}

	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "t1", "", "", "key-1", "", 150, 0, 0); allowed {
		t.Fatalf("key charge 150/100 must report debt")
	}
	d, _, code := rateLimitCheckInternal(svc, store, "key-1", "t1", "", "", "")
	if d != 3 || code != "token_quota_exceeded" {
		t.Fatalf("key after debt: expected token_quota_exceeded, got decision=%d code=%q", d, code)
	}
}

// TestLadderReserveRollbackAcrossBuckets: when a later bucket denies a
// reservation, every earlier claim is released — otherwise the denied
// request leaks headroom out of the tenant until the epoch expires it.
func TestLadderReserveRollbackAcrossBuckets(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.tenantTPM = 10000 // roomy aggregate
	svc.userRows["t1|alice"] = cmn.UserRateLimitEntry{TenantID: "t1", UserID: "alice", TokensPerMin: 100}

	// alice's user bucket denies a 500-token claim; the tenant claim taken
	// before it must be given back.
	allowed, _, epoch := tokenQuotaReserveInternal(svc, store, "t1", "", "alice", "", "", 500)
	if allowed {
		t.Fatalf("reserve 500 against user tpm=100 must deny")
	}
	if epoch != 0 {
		t.Fatalf("denied reservation must not return an epoch")
	}
	// The tenant's headroom is intact: a full-size reservation for a user
	// without a tight bucket succeeds.
	allowed, _, epoch = tokenQuotaReserveInternal(svc, store, "t1", "", "bob", "", "", 9000)
	if !allowed || epoch == 0 {
		t.Fatalf("tenant headroom leaked by the rolled-back claim: reserve 9000/10000 denied")
	}
}

// TestLadderSSEAbortSettlesUserBuckets is the abort leg: a reservation
// settled with zero actuals (client vanished mid-stream) must release the
// user bucket's claim, not only the tenant's.
func TestLadderSSEAbortSettlesUserBuckets(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.tenantTPM = 10000
	svc.userRows["t1|alice"] = cmn.UserRateLimitEntry{TenantID: "t1", UserID: "alice", TokensPerMin: 200}

	allowed, _, epoch := tokenQuotaReserveInternal(svc, store, "t1", "", "alice", "", "", 150)
	if !allowed || epoch == 0 {
		t.Fatalf("reserve 150/200 must admit with an epoch")
	}
	// While the claim is held, a second 150 must NOT fit (150+150 > 200).
	if a2, _, _ := tokenQuotaReserveInternal(svc, store, "t1", "", "alice", "", "", 150); a2 {
		t.Fatalf("second 150 with 150 reserved must deny — the user claim is not being held")
	}
	// Abort: settle with zero actual tokens, releasing the claim.
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "t1", "", "alice", "", "", 0, 150, epoch); !allowed {
		t.Fatalf("abort settlement must not latch debt")
	}
	// The full allowance is back.
	if a3, _, _ := tokenQuotaReserveInternal(svc, store, "t1", "", "alice", "", "", 150); !a3 {
		t.Fatalf("after abort release the user's allowance must be whole again")
	}
}

// TestLadderWarmupCoversUserQuota: the cold-start warming gate must fire
// for a user whose ONLY quota is user-level — a warming check that reads
// just the tenant TPM would silently admit against a zeroed user bucket.
func TestLadderWarmupCoversUserQuota(t *testing.T) {
	store := rl.New()
	store.StartQuotaWarmup(time.Hour, nil) // deadline far beyond the test
	svc := ladderSvc()
	svc.tenantRPS = 1000
	svc.userRows["t1|alice"] = cmn.UserRateLimitEntry{TenantID: "t1", UserID: "alice", TokensPerMin: 100}

	d, retry, code := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", "")
	if d != 3 || code != "token_quota_warming" {
		t.Fatalf("user-TPM-only identity during warmup: expected token_quota_warming, got decision=%d code=%q", d, code)
	}
	if retry != 1 {
		t.Errorf("warming retry advice: got %d want 1", retry)
	}
	// A user with NO quota anywhere is not gated by warmup.
	if d, _, _ := rateLimitCheckInternal(svc, store, "", "t1", "bob", "", ""); d != 0 {
		t.Fatalf("quota-less user during warmup: expected allow, got decision=%d", d)
	}
}

// TestLadderUserOutageFailsClosed: an unknowable user row (store
// unreachable, never cached) refuses the request as the store's outage —
// the same posture the tenant read has, proven by the paired arms.
func TestLadderUserOutageFailsClosed(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.tenantRPS = 1000
	svc.userErr = cmn.ErrDBUnavailable

	d, retry, code := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", "")
	if d != 4 || code != "policy_store_unavailable" {
		t.Fatalf("unknowable user limits: expected deny_503 policy_store_unavailable, got decision=%d code=%q", d, code)
	}
	if retry != 5 {
		t.Errorf("outage retry advice: got %d want 5", retry)
	}
	// Identity WITHOUT a user is untouched by the user-read outage.
	if d, _, _ := rateLimitCheckInternal(svc, store, "", "t1", "", "", ""); d != 0 {
		t.Fatalf("tenant-only identity must not consult the failing user read; got decision=%d", d)
	}
}

// TestLadderDefaultsOutagePostures: unknowable defaults fail CLOSED for an
// identity-bearing request and OPEN for a keyless one (the shared bucket
// is opt-in; an outage must not invent enforcement none-mode traffic never
// had).
func TestLadderDefaultsOutagePostures(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.tenantRPS = 1000
	svc.defaultsErr = cmn.ErrDBUnavailable

	if d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "alice", "", ""); d != 4 || code != "policy_store_unavailable" {
		t.Fatalf("identity-bearing with unknowable defaults: expected deny_503, got decision=%d code=%q", d, code)
	}
	if d, _, _ := rateLimitCheckInternal(svc, store, "", "", "", "10.10.10.254:2050", ""); d != 0 {
		t.Fatalf("keyless with unknowable defaults: expected fail-open allow, got decision=%d", d)
	}
}

// TestLadderKeylessVipBucket: keyless traffic on a service with an opt-in
// shared bucket is bounded by it; a service without one stays unmetered.
func TestLadderKeylessVipBucket(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.defaults["rule|10.10.10.254:2050"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeRule, RuleIdent: "10.10.10.254:2050", VipSharedRPS: 2,
	}

	for i := 1; i <= 2; i++ {
		if d, _, _ := rateLimitCheckInternal(svc, store, "", "", "", "10.10.10.254:2050", ""); d != 0 {
			t.Fatalf("keyless request %d: expected allow, got decision=%d", i, d)
		}
	}
	if d, _, code := rateLimitCheckInternal(svc, store, "", "", "", "10.10.10.254:2050", ""); d != 3 || code != "rate_limit_exceeded" {
		t.Fatalf("keyless request 3: expected shared-bucket deny, got decision=%d code=%q", d, code)
	}
	// A different service with no bucket configured: unmetered as before.
	if d, _, _ := rateLimitCheckInternal(svc, store, "", "", "", "10.10.10.254:2051", ""); d != 0 {
		t.Fatalf("keyless on unconfigured service: expected allow, got decision=%d", d)
	}
	// And with no service identity at all (today's ABI): unmetered.
	if d, _, _ := rateLimitCheckInternal(svc, store, "", "", "", "", ""); d != 0 {
		t.Fatalf("keyless with no svcIdent: expected allow, got decision=%d", d)
	}
}

// TestLadderDormantWithoutIdentity pins the stage-A activation contract:
// with the user/svc parameters empty (what the CGO exports pass until the
// identity-forwarding ABI lands), behaviour is EXACTLY the pre-ladder
// behaviour even with ladder rows configured — no bucket keyed on an empty
// identity may exist.
func TestLadderDormantWithoutIdentity(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.tenantRPS = 1000
	svc.defaults["global|"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeGlobal, DefaultUserRPS: 1, DefaultUserTPM: 1,
	}
	svc.userRows["t1|alice"] = cmn.UserRateLimitEntry{TenantID: "t1", UserID: "alice", RPS: 1}

	for i := 1; i <= 20; i++ {
		if d, _, code := rateLimitCheckInternal(svc, store, "", "t1", "", "", ""); d != 0 {
			t.Fatalf("request %d without user identity: ladder rows must stay dormant, got decision=%d code=%q", i, d, code)
		}
	}
}

// TestLadderKeylessVipTokenCharge: a keyless settle (no tenant, service
// named) charges the per-VIP shared bucket, and the keyless admission
// latch then denies. This is the Go half of keyless token metering; the
// data plane does not make this call yet, so until it does the pair
// below is what keeps the path honest.
func TestLadderKeylessVipTokenCharge(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.defaults["rule|10.10.10.254:2050"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeRule, RuleIdent: "10.10.10.254:2050", VipSharedTPM: 100,
	}

	// Charge 150/100 through the settle path — the shared bucket latches.
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "", "", "", "", "10.10.10.254:2050", 150, 0, 0); allowed {
		t.Fatalf("keyless charge 150 against vip tpm=100 must report debt")
	}
	if d, _, code := rateLimitCheckInternal(svc, store, "", "", "", "10.10.10.254:2050", ""); d != 3 || code != "token_quota_exceeded" {
		t.Fatalf("keyless after debt: expected token_quota_exceeded, got decision=%d code=%q", d, code)
	}
	// Another service's keyless traffic is untouched: the bucket is
	// per-VIP, not global.
	if d, _, _ := rateLimitCheckInternal(svc, store, "", "", "", "10.10.10.254:2051", ""); d != 0 {
		t.Fatalf("neighbour service caught the debt: expected allow, got decision=%d", d)
	}
	// With neither tenant nor service there is nothing to settle: no
	// bucket may be minted for the empty identity.
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "", "", "", "", "", 150, 0, 0); !allowed {
		t.Fatalf("settle with no identity at all must be a no-op allow")
	}
}

// TestLadderKeylessVipReserveAndRelease: the keyless reserve claims the
// shared bucket and an abort settle hands the claim back — the same
// claim/release contract every attributed bucket has.
func TestLadderKeylessVipReserveAndRelease(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.defaults["rule|10.10.10.254:2050"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeRule, RuleIdent: "10.10.10.254:2050", VipSharedTPM: 200,
	}

	allowed, _, epoch := tokenQuotaReserveInternal(svc, store, "", "", "", "", "10.10.10.254:2050", 150)
	if !allowed || epoch == 0 {
		t.Fatalf("keyless reserve 150/200 must admit with an epoch")
	}
	// While the claim is held, a second 150 must NOT fit.
	if a2, _, _ := tokenQuotaReserveInternal(svc, store, "", "", "", "", "10.10.10.254:2050", 150); a2 {
		t.Fatalf("second 150 with 150 reserved must deny — the shared-bucket claim is not being held")
	}
	// Abort: settle with zero actuals, releasing the claim.
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "", "", "", "", "10.10.10.254:2050", 0, 150, epoch); !allowed {
		t.Fatalf("keyless abort settlement must not latch debt")
	}
	if a3, _, _ := tokenQuotaReserveInternal(svc, store, "", "", "", "", "10.10.10.254:2050", 150); !a3 {
		t.Fatalf("after abort release the shared bucket's allowance must be whole again")
	}
	// A service with no shared bucket reserves nothing and admits.
	if a, _, e := tokenQuotaReserveInternal(svc, store, "", "", "", "", "10.10.10.254:2051", 150); !a || e != 0 {
		t.Fatalf("keyless reserve on an unconfigured service must be a no-op allow, got allowed=%v epoch=%d", a, e)
	}
}

// TestLadderKeylessVipReleaseSurvivesDefaultsRemoval: the defaults row
// vanishing between reserve and settle must not strand the claim — the
// shared bucket is the keyless request's PRIMARY bucket and settles even
// when its limit no longer resolves, exactly as the tenant aggregate does
// for attributed traffic.
func TestLadderKeylessVipReleaseSurvivesDefaultsRemoval(t *testing.T) {
	store := rl.New()
	svc := ladderSvc()
	svc.defaults["rule|10.10.10.254:2050"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeRule, RuleIdent: "10.10.10.254:2050", VipSharedTPM: 200,
	}

	allowed, _, epoch := tokenQuotaReserveInternal(svc, store, "", "", "", "", "10.10.10.254:2050", 150)
	if !allowed || epoch == 0 {
		t.Fatalf("keyless reserve 150/200 must admit with an epoch")
	}
	// The operator deletes the row mid-request.
	delete(svc.defaults, "rule|10.10.10.254:2050")
	if allowed, _ := tokenQuotaConsumeInternal(svc, store, "", "", "", "", "10.10.10.254:2050", 0, 150, epoch); !allowed {
		t.Fatalf("settle after defaults removal must not latch debt")
	}
	// The row comes back: the full allowance is available, so the claim
	// was released rather than stranded until the epoch expires it.
	svc.defaults["rule|10.10.10.254:2050"] = cmn.RateLimitDefaultsEntry{
		Scope: cmn.RateLimitScopeRule, RuleIdent: "10.10.10.254:2050", VipSharedTPM: 200,
	}
	if a, _, _ := tokenQuotaReserveInternal(svc, store, "", "", "", "", "10.10.10.254:2050", 200); !a {
		t.Fatalf("claim stranded: full-allowance reserve denied after release")
	}
}
