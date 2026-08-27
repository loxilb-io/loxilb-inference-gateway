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
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"

	cmn "github.com/loxilb-io/loxilb/common"
)

// These legs need a real PostgreSQL: they are about what the server does with
// the statements, and a mock would only replay what the test already assumed.
//
//	AIKEY_TEST_DSN  — the store to run against
//	AIKEY_TEST_PG=required — fail instead of skipping when it is absent
//
// The evidence run sets both. A gate that can quietly skip is not a gate, so
// the harness makes the skip itself a failure.
const (
	testDSNEnv      = "AIKEY_TEST_DSN"
	testRequiredEnv = "AIKEY_TEST_PG"
)

// storeFixture opens a store, provisions it, and hands back a Service with a
// clean set of tables.
func storeFixture(t *testing.T) *Service {
	t.Helper()

	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		if os.Getenv(testRequiredEnv) == "required" {
			t.Fatalf("%s is unset but %s=required: the store legs would have skipped silently", testDSNEnv, testRequiredEnv)
		}
		t.Skipf("%s unset — set it to a PostgreSQL DSN to run the store legs", testDSNEnv)
	}

	db, err := ConnectWithRetry(dsn, 3, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("connect to %s: %v", RedactDSN(dsn), err)
	}
	t.Cleanup(func() { db.Close() })

	svc := &Service{Cache: cache.New(CacheExpirationTime*time.Minute, CacheCleanupInterval*time.Minute)}
	if err := svc.Attach(db); err != nil {
		t.Fatalf("provision the store: %v", err)
	}

	truncate(t, db)
	t.Cleanup(func() { truncate(t, db) })
	return svc
}

func truncate(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, table := range []string{"api_keys", "tenant_rate_limits", "tenant_model_rate_limits"} {
		if _, err := db.Exec(fmt.Sprintf("DELETE FROM %s.%s", Schema, table)); err != nil {
			t.Fatalf("clear %s: %v", table, err)
		}
	}
}

// poolOf returns a service's live pool, failing the test if it has none.
func poolOf(t *testing.T, svc *Service) *sql.DB {
	t.Helper()
	db, err := svc.store()
	if err != nil {
		t.Fatalf("service has no store: %v", err)
	}
	pool, ok := db.(*sql.DB)
	if !ok {
		t.Fatalf("service store is %T, want *sql.DB", db)
	}
	return pool
}

// peerOf returns a second Service sharing the store — the shape of an HA pair
// — with its own cache, as two processes would have.
func peerOf(t *testing.T, primary *Service) *Service {
	t.Helper()
	peer := &Service{Cache: cache.New(CacheExpirationTime*time.Minute, CacheCleanupInterval*time.Minute)}
	if err := peer.Attach(poolOf(t, primary)); err != nil {
		t.Fatalf("attach peer to the shared store: %v", err)
	}
	return peer
}

// The provisioning path must be safe to run twice: it runs on every boot, and
// on every reconnect after the store heals.
func TestEnsureSchemaIsIdempotent(t *testing.T) {
	svc := storeFixture(t)
	db := poolOf(t, svc)
	for i := 0; i < 3; i++ {
		if err := ensureSchema(db); err != nil {
			t.Fatalf("ensureSchema pass %d: %v", i+1, err)
		}
	}
}

// U-12 — the upsert sets the columns it names and leaves the rest of the row
// alone.
//
// This is the semantic difference between ON CONFLICT DO UPDATE and the
// REPLACE INTO it replaces. MySQL implements REPLACE as delete-then-insert,
// so a column the statement does not name is silently reset to its default —
// which is what would happen to any column added to this table by a newer
// peer, or by a migration this build does not know about. The probe column
// stands in for that column.
func TestUpsertLeavesUnnamedColumnsIntact(t *testing.T) {
	svc := storeFixture(t)
	db := poolOf(t, svc)

	if _, err := db.Exec(fmt.Sprintf(
		"ALTER TABLE %s.tenant_rate_limits ADD COLUMN IF NOT EXISTS probe_col TEXT", Schema)); err != nil {
		t.Fatalf("add probe column: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(fmt.Sprintf("ALTER TABLE %s.tenant_rate_limits DROP COLUMN IF EXISTS probe_col", Schema))
	})

	const tenant = "team-a"
	if err := svc.SetTenantRateLimit(tenant, 10, 1000, 50); err != nil {
		t.Fatalf("initial set: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf(
		"UPDATE %s.tenant_rate_limits SET probe_col = 'keepme' WHERE tenant_id = $1", Schema), tenant); err != nil {
		t.Fatalf("seed probe column: %v", err)
	}

	// The upsert path: same tenant, new values.
	if err := svc.SetTenantRateLimit(tenant, 20, 1000, 50); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	var rps, tpm, burst int
	var probe sql.NullString
	if err := db.QueryRow(fmt.Sprintf(
		"SELECT rps, tokens_per_min, burst_pct, probe_col FROM %s.tenant_rate_limits WHERE tenant_id = $1", Schema),
		tenant).Scan(&rps, &tpm, &burst, &probe); err != nil {
		t.Fatalf("read back: %v", err)
	}

	if rps != 20 {
		t.Errorf("rps = %d, want 20 — the upsert did not update the column it owns", rps)
	}
	if tpm != 1000 || burst != 50 {
		t.Errorf("tokens_per_min/burst_pct = %d/%d, want 1000/50", tpm, burst)
	}
	if !probe.Valid || probe.String != "keepme" {
		t.Errorf("probe_col = %v, want \"keepme\" — the upsert reset a column it does not own, "+
			"which is REPLACE INTO's delete-then-insert behaviour", probe)
	}

	// Exactly one row: an upsert that inserted a second row would also pass
	// the checks above if the read happened to find the new one.
	var rows int
	if err := db.QueryRow(fmt.Sprintf(
		"SELECT COUNT(*) FROM %s.tenant_rate_limits WHERE tenant_id = $1", Schema), tenant).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("tenant rows = %d, want 1", rows)
	}
}

// The per-model upsert has the same contract, on a composite key.
func TestModelUpsertLeavesUnnamedColumnsIntact(t *testing.T) {
	svc := storeFixture(t)
	db := poolOf(t, svc)

	if _, err := db.Exec(fmt.Sprintf(
		"ALTER TABLE %s.tenant_model_rate_limits ADD COLUMN IF NOT EXISTS probe_col TEXT", Schema)); err != nil {
		t.Fatalf("add probe column: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(fmt.Sprintf("ALTER TABLE %s.tenant_model_rate_limits DROP COLUMN IF EXISTS probe_col", Schema))
	})

	const tenant, model = "team-a", "llama-3-70b"
	if err := svc.SetTenantModelRateLimit(tenant, model, 5000); err != nil {
		t.Fatalf("initial set: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf(
		"UPDATE %s.tenant_model_rate_limits SET probe_col = 'keepme' WHERE tenant_id = $1 AND model = $2", Schema),
		tenant, model); err != nil {
		t.Fatalf("seed probe column: %v", err)
	}
	if err := svc.SetTenantModelRateLimit(tenant, model, 9000); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	var tpm int
	var probe sql.NullString
	if err := db.QueryRow(fmt.Sprintf(
		"SELECT tokens_per_min, probe_col FROM %s.tenant_model_rate_limits WHERE tenant_id = $1 AND model = $2", Schema),
		tenant, model).Scan(&tpm, &probe); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if tpm != 9000 {
		t.Errorf("tokens_per_min = %d, want 9000", tpm)
	}
	if !probe.Valid || probe.String != "keepme" {
		t.Errorf("probe_col = %v, want \"keepme\"", probe)
	}
}

// U-23 — a caller-supplied key is stored as its hash, authenticates as
// itself, and is never echoed back.
func TestCreateAPIKeyWithSuppliedKey(t *testing.T) {
	svc := storeFixture(t)
	db := poolOf(t, svc)

	const supplied = "sk-imported-from-another-gateway-0001"
	returned, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{
		ApiKey: supplied, TenantID: "team-a", Name: "imported", Enabled: true,
		AllowedModels: []string{"llama-3-70b"}, RateLimitRPS: 20, TokensPerMin: 100000,
	})
	if err != nil {
		t.Fatalf("create with a supplied key: %v", err)
	}

	// Never echoed: the caller already holds it, and returning it would put
	// it in response logs and API traces for no benefit.
	if returned != "" {
		t.Errorf("create returned key material for a supplied key: %q", returned)
	}
	if keyID == "" {
		t.Fatal("create returned no key id")
	}
	// The identifier must not be derived from the credential.
	if strings.Contains(supplied, keyID) {
		t.Errorf("key id %q is a substring of the key it identifies", keyID)
	}

	// Only the hash is at rest.
	var storedHash string
	if err := db.QueryRow(fmt.Sprintf(
		"SELECT key_hash FROM %s.api_keys WHERE key_id = $1", Schema), keyID).Scan(&storedHash); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if storedHash != hashKey(supplied) {
		t.Errorf("stored hash = %q, want sha256(supplied) = %q", storedHash, hashKey(supplied))
	}
	if storedHash == supplied {
		t.Error("the raw key is stored verbatim")
	}

	// A request bearing that exact key validates.
	entry, err := svc.ValidateAPIKey(supplied)
	if err != nil {
		t.Fatalf("the supplied key does not authenticate: %v", err)
	}
	if entry.KeyID != keyID || entry.TenantID != "team-a" {
		t.Errorf("validated the wrong key: %+v", entry)
	}

	// No read path can return it.
	summary, err := svc.GetAPIKeyByID(keyID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	assertNoKeyMaterial(t, "GetAPIKeyByID", summary, supplied)
	list, err := svc.ListAPIKeys("team-a")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assertNoKeyMaterial(t, "ListAPIKeys", list, supplied)
	assertNoKeyMaterial(t, "ValidateAPIKey", entry, supplied)
}

// The primary path is unchanged: the gateway mints the key, returns it once,
// and stores only its hash.
func TestCreateAPIKeyGeneratesWhenNoneSupplied(t *testing.T) {
	svc := storeFixture(t)
	db := poolOf(t, svc)

	raw, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "team-b", Name: "minted", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(raw, apiKeyPrefix) {
		t.Errorf("generated key %q does not carry the %q prefix", raw, apiKeyPrefix)
	}
	// The identifier used to be the first half of the secret. Drawing them
	// separately is the fix; this asserts it stayed fixed.
	if strings.Contains(raw, keyID) {
		t.Errorf("key id %q is a substring of the key it identifies", keyID)
	}

	var storedHash string
	if err := db.QueryRow(fmt.Sprintf(
		"SELECT key_hash FROM %s.api_keys WHERE key_id = $1", Schema), keyID).Scan(&storedHash); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if storedHash != hashKey(raw) {
		t.Errorf("stored hash does not match the returned key")
	}
	if _, err := svc.ValidateAPIKey(raw); err != nil {
		t.Fatalf("the generated key does not authenticate: %v", err)
	}
}

// Two keys cannot share one hash. Once a caller may supply key material, a
// duplicate would give the authentication lookup two rows to choose from and
// resolve a request to an arbitrary one of two tenants.
func TestSuppliedKeyCannotDuplicateAnExistingHash(t *testing.T) {
	svc := storeFixture(t)

	const supplied = "sk-imported-from-another-gateway-0001"
	if _, _, err := svc.CreateAPIKey(cmn.ApiKeyEntry{ApiKey: supplied, TenantID: "team-a", Enabled: true}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, _, err := svc.CreateAPIKey(cmn.ApiKeyEntry{ApiKey: supplied, TenantID: "team-b", Enabled: true}); err == nil {
		t.Error("a second tenant registered the same key material — the authentication lookup now has two rows to choose from")
	}
}

// Key material that could not survive a header round-trip, or that is short
// enough to guess, is rejected before it reaches the store.
func TestSuppliedKeyValidation(t *testing.T) {
	for name, key := range map[string]string{
		"too short":         "sk-short",
		"embedded space":    "sk-imported key with spaces here",
		"embedded newline":  "sk-imported\nkey-0000000000000",
		"non-ascii":         "sk-imported-kéy-0000000000000000",
		"control character": "sk-imported\x00key-0000000000000",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateSuppliedKey(key); err == nil {
				t.Errorf("validateSuppliedKey(%q) accepted it", key)
			}
		})
	}
	if err := validateSuppliedKey("sk-imported-from-another-gateway-0001"); err != nil {
		t.Errorf("a well-formed supplied key was rejected: %v", err)
	}
}

// U-22 — a key revoked on one gateway stops authenticating on its peer.
//
// The peer has its own cache and has already validated the key, so without
// the fan-out it keeps honouring it for the rest of the TTL. The negative
// control runs first and asserts exactly that, because a test that cannot
// observe the defect it guards against proves nothing about the fix.
func TestRevocationReachesPeerCache(t *testing.T) {
	svc := storeFixture(t)
	peer := peerOf(t, svc)

	raw, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "team-a", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Negative control: no fan-out installed. Both sides cache the key, the
	// primary revokes it, and the peer still admits it.
	if _, err = svc.ValidateAPIKey(raw); err != nil {
		t.Fatalf("primary validate: %v", err)
	}
	if _, err = peer.ValidateAPIKey(raw); err != nil {
		t.Fatalf("peer validate: %v", err)
	}
	if err = svc.RevokeAPIKey(keyID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err = svc.ValidateAPIKey(raw); err == nil {
		t.Error("the gateway that performed the revocation still admits the key")
	}
	if _, err = peer.ValidateAPIKey(raw); err != nil {
		t.Skipf("the peer already rejects the key without a fan-out (%v) — "+
			"the negative control does not hold, so the positive leg below would prove nothing", err)
	}

	// Positive leg: same scene, fan-out wired.
	raw2, keyID2, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "team-a", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var delivered int
	svc.SetInvalidationSink(func(inv KeyInvalidation) {
		delivered++
		peer.ApplyInvalidation(inv)
	})

	if _, err = svc.ValidateAPIKey(raw2); err != nil {
		t.Fatalf("primary validate: %v", err)
	}
	if _, err = peer.ValidateAPIKey(raw2); err != nil {
		t.Fatalf("peer validate: %v", err)
	}
	if err = svc.RevokeAPIKey(keyID2); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if delivered != 1 {
		t.Errorf("fan-out delivered %d times, want 1", delivered)
	}
	if _, err = peer.ValidateAPIKey(raw2); err == nil {
		t.Error("the peer still admits a key revoked on the primary — a stale positive from its own cache")
	}

	// The peer must not re-broadcast what it was told. Peers are a mesh, so a
	// re-broadcast would circulate for as long as the entries exist.
	var peerFanOut int
	peer.SetInvalidationSink(func(KeyInvalidation) { peerFanOut++ })
	peer.ApplyInvalidation(KeyInvalidation{KeyHash: hashKey(raw2), KeyID: keyID2})
	if peerFanOut != 0 {
		t.Errorf("the receiving side re-broadcast the invalidation %d times", peerFanOut)
	}
}

// A hard delete must reach peers too — it is a revocation by another name.
func TestDeleteReachesPeerCache(t *testing.T) {
	svc := storeFixture(t)
	peer := peerOf(t, svc)
	svc.SetInvalidationSink(peer.ApplyInvalidation)

	raw, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "team-a", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err = peer.ValidateAPIKey(raw); err != nil {
		t.Fatalf("peer validate: %v", err)
	}
	if err = svc.DeleteAPIKey(keyID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err = peer.ValidateAPIKey(raw); err == nil {
		t.Error("the peer still admits a deleted key")
	}
}

// So must a patch that disables a key.
func TestPatchDisableReachesPeerCache(t *testing.T) {
	svc := storeFixture(t)
	peer := peerOf(t, svc)
	svc.SetInvalidationSink(peer.ApplyInvalidation)

	raw, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "team-a", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err = peer.ValidateAPIKey(raw); err != nil {
		t.Fatalf("peer validate: %v", err)
	}
	disabled := false
	if err = svc.PatchAPIKey(keyID, nil, &disabled); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if _, err = peer.ValidateAPIKey(raw); err == nil {
		t.Error("the peer still admits a key disabled on the primary")
	}
}

// Quotas survive the round trip through PostgreSQL with the values that went
// in — the dialect port's other half, where MySQL's TINYINT/DATETIME
// conversions used to live.
func TestRateLimitRoundTrip(t *testing.T) {
	svc := storeFixture(t)

	const tenant = "team-a"
	if err := svc.SetTenantRateLimit(tenant, 25, 120000, 40); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := svc.SetTenantModelRateLimit(tenant, "llama-3-70b", 9000); err != nil {
		t.Fatalf("set model: %v", err)
	}

	// Read through a peer so the values come from the store, not this
	// service's own cache.
	peer := peerOf(t, svc)
	rps, tpm, burst := peer.GetTenantRateLimit(tenant)
	if rps != 25 || tpm != 120000 || burst != 40 {
		t.Errorf("rate limit = %d/%d/%d, want 25/120000/40", rps, tpm, burst)
	}
	if got := peer.GetTenantModelRateLimit(tenant, "llama-3-70b"); got != 9000 {
		t.Errorf("model quota = %d, want 9000", got)
	}

	entry, err := peerOf(t, svc).GetTenantRateLimitEntry(tenant)
	if err != nil {
		t.Fatalf("get entry: %v", err)
	}
	if entry.RPS != 25 || entry.TokensPerMin != 120000 || entry.BurstPct != 40 {
		t.Errorf("entry = %+v, want rps=25 tpm=120000 burst=40", entry)
	}
	if entry.UpdatedAt.IsZero() {
		t.Error("updated_at came back zero — the timestamp did not round-trip")
	}
	if len(entry.ModelLimits) != 1 || entry.ModelLimits[0].TokensPerMin != 9000 {
		t.Errorf("model limits = %+v, want one entry at 9000", entry.ModelLimits)
	}

	// A non-positive quota removes the row rather than storing a zero that
	// would read as an explicit "no tokens".
	if err := svc.SetTenantModelRateLimit(tenant, "llama-3-70b", 0); err != nil {
		t.Fatalf("clear model quota: %v", err)
	}
	if got := peerOf(t, svc).GetTenantModelRateLimit(tenant, "llama-3-70b"); got != 0 {
		t.Errorf("cleared model quota reads %d, want 0", got)
	}
}

// created_at and expires_at must come back as the instants that went in.
// The management plane's equivalent shortcut — a naive column parsed with a
// fixed layout — is what broke GET /auth/users.
func TestTimestampsRoundTrip(t *testing.T) {
	svc := storeFixture(t)

	expiry := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Millisecond)
	before := time.Now().UTC().Add(-time.Second)
	raw, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{
		TenantID: "team-a", Enabled: true, ExpiresAt: &expiry,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	after := time.Now().UTC().Add(time.Second)

	entry, err := peerOf(t, svc).ValidateAPIKey(raw)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if entry.CreatedAt.Before(before) || entry.CreatedAt.After(after) {
		t.Errorf("created_at = %v, expected between %v and %v", entry.CreatedAt, before, after)
	}
	if entry.ExpiresAt == nil {
		t.Fatal("expires_at came back nil")
	}
	if diff := entry.ExpiresAt.Sub(expiry); diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("expires_at = %v, want %v (drift %v)", entry.ExpiresAt.UTC(), expiry, diff)
	}

	// A key with no expiry stays nil rather than becoming the zero time,
	// which the datapath would read as "expired in year 1".
	raw2, _, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "team-a", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	entry2, err := peerOf(t, svc).ValidateAPIKey(raw2)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if entry2.ExpiresAt != nil {
		t.Errorf("a key with no expiry came back with expires_at = %v", entry2.ExpiresAt)
	}
	_ = keyID
}

// A disabled key must not authenticate, but must stay visible to the
// management read paths so an operator can find it and re-enable it.
func TestDisabledKeyIsUnusableButVisible(t *testing.T) {
	svc := storeFixture(t)

	raw, keyID, err := svc.CreateAPIKey(cmn.ApiKeyEntry{TenantID: "team-a", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err = svc.RevokeAPIKey(keyID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	fresh := peerOf(t, svc)
	if _, err = fresh.ValidateAPIKey(raw); err == nil {
		t.Error("a revoked key still authenticates")
	}
	summary, err := fresh.GetAPIKeyByID(keyID)
	if err != nil {
		t.Fatalf("a revoked key vanished from the management read path: %v", err)
	}
	if summary.Enabled {
		t.Error("the revoked key still reads as enabled")
	}
	keys, err := fresh.ListAPIKeys("team-a")
	if err != nil || len(keys) != 1 {
		t.Errorf("list returned %d keys, err=%v; want the revoked key still listed", len(keys), err)
	}
}

// The preflight must name the problem rather than let a missing schema
// surface as an opaque driver error on the first live request.
func TestPreflightRejectsMissingSchema(t *testing.T) {
	svc := storeFixture(t)
	db := poolOf(t, svc)

	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'aigw_absent')`).Scan(&exists); err != nil {
		t.Fatalf("catalogue query: %v", err)
	}
	if exists {
		t.Skip("a schema named aigw_absent exists on this server")
	}
	// Exercised through the same catalogue query the preflight runs, with a
	// schema that is not there.
	var usage bool
	err := db.QueryRow(
		`SELECT has_schema_privilege(current_user, 'aigw_absent', 'USAGE')`).Scan(&usage)
	if err == nil {
		t.Error("has_schema_privilege on a missing schema did not error — the preflight's existence check is what catches it")
	}
}

// assertNoKeyMaterial fails if the serialised form of v contains the secret.
// Serialised rather than field-by-field: what matters is that no response
// body, log line or API trace can carry it, whatever the struct grows next.
func assertNoKeyMaterial(t *testing.T, what string, v any, secret string) {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", what, err)
	}
	if strings.Contains(string(blob), secret) {
		t.Errorf("%s serialises the key material: %s", what, blob)
	}
	if strings.Contains(fmt.Sprintf("%+v", v), secret) {
		t.Errorf("%s prints the key material under %%+v, which is how it would reach a log line", what)
	}
}
