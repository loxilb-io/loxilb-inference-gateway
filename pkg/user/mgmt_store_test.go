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
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"golang.org/x/crypto/bcrypt"
)

// --- U-25: every query selects exactly what its caller scans --------------

func TestU25_PreviousPasswordQuerySelectsWhatItScans(t *testing.T) {
	svc := storeFixture(t)
	pool, err := svc.store()
	if err != nil {
		t.Fatalf("no store: %v", err)
	}

	// The property, stated against the server rather than by reading the SQL:
	// the previous-password query returns one column, so one destination is
	// the right number. The two-column query it used to share is still there
	// for ValidateUser, which scans two.
	var one string
	insertUserRow(t, svc, "arity", mustHash(t, "Admin123!"), "admin")
	if err := pool.QueryRow(SelectUserPasswordOnlyQuery, "arity").Scan(&one); err != nil {
		t.Fatalf("previous-password query does not scan into one destination: %v", err)
	}
	var hash, role string
	if err := pool.QueryRow(SelectUserPasswordQuery, "arity").Scan(&hash, &role); err != nil {
		t.Fatalf("ValidateUser's query does not scan into two destinations: %v", err)
	}
	if one != hash {
		t.Errorf("the two queries disagree about the stored hash")
	}

	// And end to end, which is what the arity mismatch actually broke: a password
	// change on an existing user succeeds, takes effect, and does not spend
	// the retry budget failing.
	id := userID(t, svc, "arity")
	start := time.Now()
	if err := svc.UpdateUser(cmn.User{ID: id, Username: "arity", Password: "Rotated9!x"}); err != nil {
		t.Fatalf("password change failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("password change took %v — the retry ladder is still being walked", elapsed)
	}
	if _, ok, err := svc.ValidateUser("arity", "Rotated9!x"); err != nil || !ok {
		t.Fatalf("the new password does not authenticate: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := svc.ValidateUser("arity", "Admin123!"); ok {
		t.Error("the old password still authenticates")
	}
}

// --- U-26: the list works, and created_at is a time all the way through ---

func TestU26_GetUsersWithRowsPresent(t *testing.T) {
	svc := storeFixture(t)

	if users, err := svc.GetUsers(); err != nil || len(users) != 0 {
		t.Fatalf("empty store: users=%d err=%v", len(users), err)
	}

	before := time.Now().Add(-time.Second)
	if _, err := svc.AddUser(cmn.User{Username: "listed", Password: "Admin123!", Role: "admin", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if _, err := svc.AddUser(cmn.User{Username: "listed2", Password: "Viewer99!", Role: "viewer", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	users, err := svc.GetUsers()
	if err != nil {
		t.Fatalf("GetUsers failed with rows present — the defect this gate exists for: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("users=%d, want 2", len(users))
	}
	after := time.Now().Add(time.Second)
	for _, u := range users {
		// created_at arrives as a time.Time the driver parsed, not a string
		// this code re-parsed with a layout picked by hand.
		if u.CreatedAt.Before(before) || u.CreatedAt.After(after) {
			t.Errorf("user %q created_at=%v is outside [%v, %v] — it did not round-trip", u.Username, u.CreatedAt, before, after)
		}
		if u.CreatedAt.IsZero() {
			t.Errorf("user %q created_at is the zero time", u.Username)
		}
		// The list must not carry password material at all.
		if u.Password != "" {
			t.Errorf("user %q carries password material in the list: %q", u.Username, u.Password)
		}
	}

	// And the statement itself does not ask for the column, so a later edit
	// to the mapping cannot forward what was never fetched.
	if strings.Contains(SelectAllUsersQuery, "password") {
		t.Errorf("the list query selects the password column: %s", SelectAllUsersQuery)
	}
}

// --- U-27: tokens at rest are hashes, in the database and in the cache ----

func TestU27_TokensAreHashedAtRest(t *testing.T) {
	svc := storeFixture(t)
	insertUserRow(t, svc, "tokuser", mustHash(t, "Admin123!"), "admin")
	pool, err := svc.store()
	if err != nil {
		t.Fatalf("no store: %v", err)
	}

	token, ok, err := svc.Login("tokuser", "Admin123!")
	if err != nil || !ok || token == "" {
		t.Fatalf("login: token=%q ok=%v err=%v", token, ok, err)
	}

	// The raw token still validates — the scheme has to work, not merely be
	// unreadable.
	if _, err := svc.ValidateToken(token); err != nil {
		t.Fatalf("the issued token does not validate: %v", err)
	}

	// A dump of the table contains no usable credential.
	rows, err := pool.Query(fmt.Sprintf("SELECT token_hash, username, role FROM %s.token", Schema))
	if err != nil {
		t.Fatalf("dump token table: %v", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var stored, username, role string
		if err := rows.Scan(&stored, &username, &role); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen++
		if stored == token {
			t.Error("the raw token is stored in the database")
		}
		if stored != hashToken(token) {
			t.Errorf("stored value is neither the token nor its hash: %q", stored)
		}
		if len(stored) != 64 {
			t.Errorf("stored value is %d characters, want a 64-character sha256 hex", len(stored))
		}
		// The decisive check: what is in the table must not authenticate.
		if _, err := svc.ValidateToken(stored); err == nil {
			t.Error("the value stored in the table authenticates — a database dump yields live credentials")
		}
	}
	if seen != 1 {
		t.Fatalf("token rows=%d, want 1", seen)
	}

	// The cache is keyed the same way, so a memory dump is no better than a
	// table dump.
	if _, found := svc.Cache.Get(token); found {
		t.Error("the raw token is a cache key")
	}
	if _, found := svc.Cache.Get(hashToken(token)); !found {
		t.Error("the cache is not keyed by the token hash")
	}

	// The hash column is unique, so one stored credential cannot be made to
	// stand for two sessions, and a replayed insert is refused by the store
	// rather than silently accepted.
	if _, err := pool.Exec(InsertTokenQuery, hashToken(token), "tokuser", time.Now().Add(time.Hour), "admin"); err == nil {
		t.Error("a second row with the same token hash was accepted — the hash is not unique")
	}

	// And the token itself carries no claims to forge.
	if strings.Count(token, ".") >= 2 {
		t.Errorf("the token still looks like a JWT: %q", token)
	}
	if len(token) != TokenBytes*2 {
		t.Errorf("token is %d characters, want %d hex characters of entropy", len(token), TokenBytes*2)
	}
}

// A hard-coded signing key in the source is what the opaque-token scheme
// removes; assert it
// is gone rather than trusting that nobody re-adds one.
func TestU27b_NoSigningKeyInSource(t *testing.T) {
	for _, f := range []string{"user.go", "user_util.go", "connect.go", "revoke.go", "queries.go", "schema.go"} {
		src := readSource(t, f)
		for _, banned := range []string{"netlox_secret_key", "jwtKey", "SigningMethod"} {
			if strings.Contains(src, banned) {
				t.Errorf("%s still references %q", f, banned)
			}
		}
	}
}

// --- U-28 (write half): a role the system does not implement is refused ---

func TestU28w_InvalidRolesAreRefusedAtWriteTime(t *testing.T) {
	svc := storeFixture(t)

	for _, role := range []string{"operator", "Admin", "ADMIN", "viewers", "", "admin ", "reviewer"} {
		_, err := svc.AddUser(cmn.User{Username: "role-" + role, Password: "Admin123!", Role: role, CreatedAt: time.Now()})
		if !errors.Is(err, cmn.ErrInvalidRole) {
			t.Errorf("AddUser with role %q: err=%v, want ErrInvalidRole", role, err)
		}
	}
	for _, role := range []string{"admin", "viewer"} {
		if _, err := svc.AddUser(cmn.User{Username: "ok-" + role, Password: "Admin123!", Role: role, CreatedAt: time.Now()}); err != nil {
			t.Errorf("AddUser with role %q was refused: %v", role, err)
		}
	}

	// The column refuses it too, so the closed set is stated in the store as
	// well as in the code and cannot be bypassed by writing a row by hand.
	pool, err := svc.store()
	if err != nil {
		t.Fatalf("no store: %v", err)
	}
	if _, err := pool.Exec(fmt.Sprintf(
		`INSERT INTO %s.users (username, password, created_at, role) VALUES ($1, $2, $3, $4)`, Schema),
		"handwritten", "x", time.Now(), "operator"); err == nil {
		t.Error("a row with an unimplemented role was accepted by the database")
	}
}

// --- U-29: reconnect under -race with concurrent validators --------------

func TestU29_ReconnectWithConcurrentValidators(t *testing.T) {
	svc := storeFixture(t)
	insertUserRow(t, svc, "racer", mustHash(t, "Admin123!"), "admin")
	token, ok, err := svc.Login("racer", "Admin123!")
	if err != nil || !ok {
		t.Fatalf("login: %v", err)
	}
	// closeGrace is left at its default here on purpose. Shortening it would
	// have the fixture's own pool retired mid-test, and the cleanup that
	// truncates through it would then fail on a closed pool — a fixture
	// interaction, not a property. Retirement itself is U-19a's subject; this
	// leg is about what the readers see while the swap happens.
	replacement := &closeCountingDB{DB: openMgmtStore(t)}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Validating from cache and from the store, while the pool is
				// replaced underneath. The cache hit is the common path and
				// the store read is the one that holds a handle.
				if _, err := svc.ValidateToken(token); err != nil && !errors.Is(err, cmn.ErrTokenNotFound) {
					// A closed pool would surface here. ErrDBUnavailable is
					// acceptable only if the service is genuinely degraded,
					// which it never is in this test.
					t.Errorf("validation failed during a reconnect: %v", err)
					return
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	svc.Attach(replacement)
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && replacement.closeCount() != 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if replacement.closeCount() != 0 {
		t.Error("the live pool was closed")
	}
}

// --- U-30: the cache never outlives the token ----------------------------

func TestU30_CacheTTLIsBoundedByExpiry(t *testing.T) {
	svc := storeFixture(t)
	insertUserRow(t, svc, "ttluser", mustHash(t, "Admin123!"), "admin")
	pool, err := svc.store()
	if err != nil {
		t.Fatalf("no store: %v", err)
	}

	// A token ten seconds from expiry. The flat five-minute cache this
	// replaces would have honoured it for 290 seconds past its own expiry.
	raw, err := generateToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	expiry := time.Now().Add(10 * time.Second)
	if _, err := pool.Exec(InsertTokenQuery, hashToken(raw), "ttluser", expiry, "admin"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	if _, err := svc.ValidateToken(raw); err != nil {
		t.Fatalf("a live token was rejected: %v", err)
	}
	_, expiresAt, found := svc.Cache.GetWithExpiration(hashToken(raw))
	if !found {
		t.Fatal("the validated token was not cached")
	}
	ttl := time.Until(expiresAt)
	if ttl > 11*time.Second {
		t.Errorf("cache TTL is %v, longer than the token's remaining %v — the cache outlives the credential", ttl, time.Until(expiry))
	}
	if ttl <= 0 {
		t.Errorf("cache TTL is %v — the entry is already dead", ttl)
	}

	// And the ceiling still applies to a long-lived token.
	long, _ := generateToken()
	if _, err := pool.Exec(InsertTokenQuery, hashToken(long), "ttluser", time.Now().Add(24*time.Hour), "admin"); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if _, err := svc.ValidateToken(long); err != nil {
		t.Fatalf("validate: %v", err)
	}
	_, longExpiry, found := svc.Cache.GetWithExpiration(hashToken(long))
	if !found {
		t.Fatal("not cached")
	}
	if ttl := time.Until(longExpiry); ttl > time.Duration(CacheExpirationTime)*time.Minute+time.Second {
		t.Errorf("cache TTL is %v, above the %d-minute ceiling", ttl, CacheExpirationTime)
	}
}

// --- U-31: an unknown user and a wrong password are indistinguishable ----

func TestU31_LoginDoesNotEnumerateUsers(t *testing.T) {
	svc := storeFixture(t)
	insertUserRow(t, svc, "known", mustHash(t, "Admin123!"), "admin")

	tokMissing, okMissing, errMissing := svc.Login("no-such-user", "Admin123!")
	tokWrong, okWrong, errWrong := svc.Login("known", "WrongPass1!")

	if okMissing || okWrong || tokMissing != "" || tokWrong != "" {
		t.Fatalf("a login succeeded that should not have: missing=%v/%q wrong=%v/%q", okMissing, tokMissing, okWrong, tokWrong)
	}
	// Identical error value, so the two cases cannot be told apart by shape.
	if !errors.Is(errMissing, errWrong) && !(errMissing == nil && errWrong == nil) {
		t.Errorf("unknown user gives %v, wrong password gives %v — the two are distinguishable", errMissing, errWrong)
	}

	// And comparable cost, so they cannot be told apart with a stopwatch.
	// bcrypt at the default cost dominates both paths; the tolerance is wide
	// because this runs on a shared machine, and the defect it guards against
	// was a whole bcrypt verification of difference, not a few percent.
	const rounds = 5
	var missingTotal, wrongTotal time.Duration
	for i := 0; i < rounds; i++ {
		start := time.Now()
		_, _, _ = svc.Login("no-such-user", "Admin123!")
		missingTotal += time.Since(start)

		start = time.Now()
		_, _, _ = svc.Login("known", "WrongPass1!")
		wrongTotal += time.Since(start)
	}
	missing := missingTotal / rounds
	wrong := wrongTotal / rounds
	ratio := float64(missing) / float64(wrong)
	if ratio < 0.4 || ratio > 2.5 {
		t.Errorf("unknown-user login averages %v and wrong-password %v (ratio %.2f) — the miss path is measurably different",
			missing, wrong, ratio)
	}
	// A guard against the test passing because both paths became trivial: the
	// wrong-password path must still be doing bcrypt work.
	if wrong < 5*time.Millisecond {
		t.Errorf("wrong-password login took %v — too fast to be doing bcrypt work, so the comparison above is vacuous", wrong)
	}
}

// --- revocation: deleting or demoting a user ends their sessions ---------

func TestU23_RevocationIsCompleteAndPlaneScoped(t *testing.T) {
	svc := storeFixture(t)
	pool, err := svc.store()
	if err != nil {
		t.Fatalf("no store: %v", err)
	}
	insertUserRow(t, svc, "doomed", mustHash(t, "Admin123!"), "admin")

	var published [][]string
	svc.SetTokenSink(func(h []string) { published = append(published, h) })

	token, ok, err := svc.Login("doomed", "Admin123!")
	if err != nil || !ok {
		t.Fatalf("login: %v", err)
	}
	if _, err := svc.ValidateToken(token); err != nil {
		t.Fatalf("fresh token rejected: %v", err)
	}

	id := userID(t, svc, "doomed")
	if err := svc.DeleteUser(id); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// The row is gone, the token row is gone, the cache entry is gone, and the
	// peers were told. Before this, the account vanished and its sessions kept
	// working for up to their full lifetime.
	var tokenRows int
	if err := pool.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s.token", Schema)).Scan(&tokenRows); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if tokenRows != 0 {
		t.Errorf("token rows=%d after deleting the user, want 0", tokenRows)
	}
	if _, found := svc.Cache.Get(hashToken(token)); found {
		t.Error("the deleted user's token is still in the local cache")
	}
	if _, err := svc.ValidateToken(token); err == nil {
		t.Error("the deleted user's token still authenticates")
	}
	if len(published) != 1 || len(published[0]) != 1 || published[0][0] != hashToken(token) {
		t.Errorf("peers were not told exactly the revoked hash: %v", published)
	}
	// What travels is the hash, never the token.
	for _, batch := range published {
		for _, h := range batch {
			if h == token {
				t.Error("a raw token was published on the invalidation channel")
			}
		}
	}
}

func TestU23b_RoleChangeRevokesSessions(t *testing.T) {
	svc := storeFixture(t)
	insertUserRow(t, svc, "demoted", mustHash(t, "Admin123!"), "admin")
	token, ok, err := svc.Login("demoted", "Admin123!")
	if err != nil || !ok {
		t.Fatalf("login: %v", err)
	}

	id := userID(t, svc, "demoted")
	if err := svc.UpdateUser(cmn.User{ID: id, Username: "demoted", Password: "Viewer99!", Role: "viewer"}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if _, err := svc.ValidateToken(token); err == nil {
		t.Error("a token issued as admin still authenticates after the account was demoted to viewer")
	}
}

// The decoy path must be a real bcrypt verification, or U-31's timing leg is
// measuring nothing.
func TestEnumerationDecoyIsAWorkingHash(t *testing.T) {
	if len(enumerationDecoyHash) == 0 {
		t.Fatal("the decoy hash is empty — the unknown-user path does no work")
	}
	err := bcrypt.CompareHashAndPassword(enumerationDecoyHash, []byte("anything"))
	if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("the decoy hash is not a parseable bcrypt hash: %v", err)
	}
	cost, err := bcrypt.Cost(enumerationDecoyHash)
	if err != nil || cost != bcrypt.DefaultCost {
		t.Errorf("decoy cost=%d err=%v, want %d — the miss path must cost what the hit path costs", cost, err, bcrypt.DefaultCost)
	}
}

var _ = sql.ErrNoRows
