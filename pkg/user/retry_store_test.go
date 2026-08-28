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
	"encoding/base64"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/pgstore"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
)

// --- U-6 / U-7: RetryOperation's attempt and sleep accounting -------------
//
// The two properties are counted, not timed loosely: the defect was that a
// terminal error was retried and that a sleep followed the final attempt, and
// both are statements about counts.

func TestU6_RetryOperationTerminalErrorIsNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"sql.ErrNoRows", sql.ErrNoRows},
		{"ErrUserNotFound", ErrUserNotFound},
		{"ErrTokenNotFound", cmn.ErrTokenNotFound},
		{"ErrInvalidToken", ErrInvalidToken},
		{"ErrTokenExpired", ErrTokenExpired},
		{"ErrBootstrapClosed", ErrBootstrapClosed},
		{"wrapped ErrNoRows", errWrap{sql.ErrNoRows}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			start := time.Now()
			err := RetryOperation(func() error {
				attempts++
				return tc.err
			}, AuthMaxRetries, AuthRetryDelay, retryableDBError)
			elapsed := time.Since(start)

			if attempts != 1 {
				t.Errorf("terminal error retried: attempts=%d, want 1", attempts)
			}
			if elapsed >= 50*time.Millisecond {
				t.Errorf("terminal error slept: elapsed=%v, want < 50ms", elapsed)
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("error not returned unchanged: got %v", err)
			}
		})
	}
}

func TestU7_RetryOperationTransientErrorUsesFullBudgetWithoutTrailingSleep(t *testing.T) {
	transient := errors.New("connection refused")
	attempts := 0
	start := time.Now()
	err := RetryOperation(func() error {
		attempts++
		return transient
	}, AuthMaxRetries, AuthRetryDelay, retryableDBError)
	elapsed := time.Since(start)

	if attempts != AuthMaxRetries {
		t.Errorf("attempts=%d, want %d", attempts, AuthMaxRetries)
	}
	if !errors.Is(err, transient) {
		t.Errorf("error not returned: got %v", err)
	}

	// maxRetries-1 sleeps, doubling: 300ms + 600ms = 900ms for 3 attempts.
	// A trailing sleep after the final attempt would add another 1200ms, so
	// the upper bound below is what actually distinguishes the two shapes.
	var wantSleep time.Duration
	d := AuthRetryDelay
	for i := 0; i < AuthMaxRetries-1; i++ {
		wantSleep += d
		d *= AuthRetryBackoff
	}
	if elapsed < wantSleep {
		t.Errorf("slept %v, want at least %v (backoff not applied?)", elapsed, wantSleep)
	}
	if elapsed >= wantSleep+d {
		t.Errorf("slept %v, want less than %v — a sleep followed the final attempt", elapsed, wantSleep+d)
	}
}

// The predicate must not be a wildcard in either direction: a transient error
// has to stay retryable, or U-7 would pass for the wrong reason.
func TestU7b_RetryableClassification(t *testing.T) {
	if retryableDBError(nil) {
		t.Error("nil classified as retryable")
	}
	if !retryableDBError(errors.New("dial tcp: connection refused")) {
		t.Error("a transport failure must stay retryable")
	}
	if retryableDBError(sql.ErrNoRows) {
		t.Error("ErrNoRows must be terminal")
	}
}

type errWrap struct{ inner error }

func (e errWrap) Error() string { return "wrapped: " + e.inner.Error() }
func (e errWrap) Unwrap() error { return e.inner }

// --- U-8: an unknown token answers immediately ---------------------------

func TestU8_ValidateTokenUnknownTokenAnswersImmediately(t *testing.T) {
	svc := storeFixture(t)

	start := time.Now()
	_, err := svc.ValidateToken("a-token-that-was-never-issued")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("unknown token accepted")
	}
	if !errors.Is(err, cmn.ErrTokenNotFound) {
		t.Errorf("want ErrTokenNotFound (which the REST layer maps to 401), got %v", err)
	}
	// ErrTokenNotFound must NOT be ErrDBUnavailable, or the caller would
	// answer 503 and report an unknown credential as an outage.
	if errors.Is(err, cmn.ErrDBUnavailable) {
		t.Error("an unknown token must not be reported as the store being unavailable")
	}
	if elapsed >= 50*time.Millisecond {
		t.Errorf("elapsed=%v, want < 50ms — the retry budget was spent on a terminal answer", elapsed)
	}
}

// --- U-17: one password scheme, and no verifier for the old one ----------

func TestU17_BcryptOnlyVerification(t *testing.T) {
	svc := storeFixture(t)

	t.Run("hashUserPassword emits bcrypt", func(t *testing.T) {
		h, err := hashUserPassword("Admin123!")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		if !strings.HasPrefix(h, "$2") {
			t.Fatalf("stored form is not bcrypt: %q", h)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(h), []byte("Admin123!")); err != nil {
			t.Fatalf("bcrypt cannot verify what the writer produced: %v", err)
		}
	})

	t.Run("a bcrypt row verifies", func(t *testing.T) {
		insertUserRow(t, svc, "bcryptuser", mustHash(t, "Admin123!"), "admin")
		role, ok, err := svc.ValidateUser("bcryptuser", "Admin123!")
		if err != nil || !ok {
			t.Fatalf("valid credential rejected: ok=%v err=%v", ok, err)
		}
		if role != "admin" {
			t.Errorf("role=%q, want admin", role)
		}
		if _, ok, _ := svc.ValidateUser("bcryptuser", "WrongPass1!"); ok {
			t.Error("wrong password accepted")
		}
	})

	// The end-to-end shape the two defects hid between: creating a user, then
	// changing the password, then logging in with the new one. This could not
	// complete before — validatePassword scanned one destination from a
	// two-column query, so the change always failed; and had it succeeded, it
	// wrote a format ValidateUser could not read.
	t.Run("add then change then login", func(t *testing.T) {
		if _, err := svc.AddUser(cmn.User{Username: "rotator", Password: "Admin123!", Role: "admin", CreatedAt: time.Now()}); err != nil {
			t.Fatalf("AddUser: %v", err)
		}
		if _, ok, err := svc.ValidateUser("rotator", "Admin123!"); err != nil || !ok {
			t.Fatalf("login before change: ok=%v err=%v", ok, err)
		}
		id := userID(t, svc, "rotator")
		if err := svc.UpdateUser(cmn.User{ID: id, Username: "rotator", Password: "NewPass456!"}); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		if _, ok, err := svc.ValidateUser("rotator", "NewPass456!"); err != nil || !ok {
			t.Fatalf("the new password does not authenticate: ok=%v err=%v", ok, err)
		}
		if _, ok, _ := svc.ValidateUser("rotator", "Admin123!"); ok {
			t.Error("the old password still authenticates after a change")
		}
	})

	t.Run("a legacy pbkdf2 row is refused, not accepted and not a panic", func(t *testing.T) {
		// Exactly what the deleted writer produced: base64 of salt||hash.
		legacy := base64.StdEncoding.EncodeToString(make([]byte, 48))
		insertUserRow(t, svc, "legacyuser", legacy, "admin")
		role, ok, err := svc.ValidateUser("legacyuser", "Admin123!")
		if ok {
			t.Fatal("a pbkdf2 row was accepted — a dual-format verifier exists")
		}
		if role != "" {
			t.Errorf("role leaked on a refusal: %q", role)
		}
		if err != nil {
			t.Errorf("an unreadable row must refuse like any bad credential, not surface an error to the caller: %v", err)
		}
	})

	t.Run("no dual-format verifier exists in the source", func(t *testing.T) {
		for _, f := range []string{"user.go", "user_util.go"} {
			src := readSource(t, f)
			if strings.Contains(src, "pbkdf2.Key(") {
				t.Errorf("%s still computes pbkdf2", f)
			}
		}
	})
}

// --- U-18: a short stored value refuses instead of panicking -------------

func TestU18_ShortStoredValueDoesNotPanic(t *testing.T) {
	svc := storeFixture(t)

	// Under pbkdf2 these decoded to fewer than 16 bytes and were sliced [:16].
	for i, stored := range []string{
		"",
		"x",
		base64.StdEncoding.EncodeToString([]byte("short")),
		"$2a$10$truncated",
		"not base64 at all !!",
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d (%q) panicked: %v", i, stored, r)
				}
			}()
			name := "shortuser" + string(rune('a'+i))
			insertUserRow(t, svc, name, stored, "admin")
			if _, ok, _ := svc.ValidateUser(name, "Admin123!"); ok {
				t.Errorf("case %d (%q) authenticated", i, stored)
			}
		}()
	}
}

// --- U-19: no pool is discarded without Close ----------------------------

type closeCountingDB struct {
	*sql.DB
	mu     sync.Mutex
	closed int
}

func (c *closeCountingDB) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	return nil
}
func (c *closeCountingDB) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func TestU19a_AttachRetiresTheSupersededPool(t *testing.T) {
	first := &closeCountingDB{DB: openMgmtStore(t)}
	second := &closeCountingDB{DB: openMgmtStore(t)}

	svc := &UserService{Cache: cache.New(time.Minute, time.Minute), closeGrace: 20 * time.Millisecond}
	svc.Attach(first)
	if first.closeCount() != 0 {
		t.Fatal("the first handle was closed on attach")
	}

	svc.Attach(second)
	// Still open during the grace window: an operation holding the handle it
	// was given must not have it closed underneath it.
	if first.closeCount() != 0 {
		t.Error("the superseded pool was closed immediately, aborting in-flight statements")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && first.closeCount() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if first.closeCount() != 1 {
		t.Errorf("superseded pool closed %d times, want 1 — a reconnect leaks a pool per tick", first.closeCount())
	}
	if second.closeCount() != 0 {
		t.Error("the live pool was closed")
	}

	// Re-attaching the same handle must not retire it.
	svc.Attach(second)
	time.Sleep(60 * time.Millisecond)
	if second.closeCount() != 0 {
		t.Error("attaching the live handle again closed it")
	}
}

// A -race run only says something about the pool swap if something actually
// races it. Without this leg the race detector passes because nothing ever
// read the field while it was being written, which is not the same as the
// field being safe to write.
func TestU19c_ConcurrentReadsDuringReconnect(t *testing.T) {
	svc := &UserService{Cache: cache.New(time.Minute, time.Minute), closeGrace: time.Millisecond}
	handles := make([]*closeCountingDB, 8)
	for i := range handles {
		handles[i] = &closeCountingDB{DB: openMgmtStore(t)}
	}
	svc.Attach(handles[0])

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
				if h, err := svc.store(); err == nil && h == nil {
					t.Error("store returned a nil handle with no error")
				}
			}
		}()
	}
	for round := 0; round < 200; round++ {
		svc.Attach(handles[round%len(handles)])
	}
	close(stop)
	wg.Wait()
}

// The connect half is asserted on the source: connectStore owns the pool from
// the moment the dial returns, so every failure path after it has to release
// it. Structural rather than dynamic because reaching those paths needs a
// server that answers, then fails preflight, then fails DDL.
func TestU19b_ConnectStoreClosesThePoolOnEveryFailurePath(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "connect.go", nil, 0)
	if err != nil {
		t.Fatalf("parse connect.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == "connectStore" && f.Recv == nil {
			fn = f
		}
	}
	if fn == nil {
		t.Fatal("connectStore not found — if it was renamed, this gate must move with it")
	}

	// The pool exists only once the dial has RETURNED it, so the branch that
	// handles the dial's own error owns nothing. Start after it.
	dialIdx := -1
	for i, stmt := range fn.Body.List {
		found := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
					(sel.Sel.Name == "ConnectWithRetry" || sel.Sel.Name == "ConnectWithSecureTLS") {
					found = true
				}
			}
			return true
		})
		if found {
			dialIdx = i
		}
	}
	if dialIdx < 0 {
		t.Fatal("no store dial found in connectStore")
	}

	checked := 0
	for _, stmt := range fn.Body.List[dialIdx+2:] {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		returnsErr := false
		ast.Inspect(ifStmt.Body, func(n ast.Node) bool {
			if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) == 2 {
				if id, ok := ret.Results[0].(*ast.Ident); ok && id.Name == "nil" {
					returnsErr = true
				}
			}
			return true
		})
		if !returnsErr {
			continue
		}
		checked++
		closes := false
		ast.Inspect(ifStmt.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "db" {
						closes = true
					}
				}
			}
			return true
		})
		if !closes {
			t.Errorf("connectStore line %d: returns an error after the dial without db.Close() — the pool and its goroutine leak",
				fset.Position(ifStmt.Pos()).Line)
		}
	}
	if checked < 2 {
		t.Errorf("only %d failure paths inspected; connectStore has a preflight and a schema step, so the gate is not seeing them", checked)
	}
}

// --- U-20: a login that could not be persisted leaves no usable token ----

type saveFailingDB struct{ *sql.DB }

func (f saveFailingDB) Exec(query string, args ...any) (sql.Result, error) {
	if strings.Contains(strings.ToUpper(query), ".TOKEN (") {
		return nil, errors.New("store rejected the token row")
	}
	return f.DB.Exec(query, args...)
}

func TestU20_LoginDoesNotCacheATokenItCouldNotPersist(t *testing.T) {
	svc := storeFixture(t)
	insertUserRow(t, svc, "loginuser", mustHash(t, "Admin123!"), "admin")
	// Swap in a handle that refuses the token insert, once the user exists.
	pool, err := svc.store()
	if err != nil {
		t.Fatalf("no store: %v", err)
	}
	svc.Attach(saveFailingDB{pool.(*sql.DB)})

	token, ok, err := svc.Login("loginuser", "Admin123!")
	if err == nil || ok || token != "" {
		t.Fatalf("login reported success although the token could not be saved: token=%q ok=%v err=%v", token, ok, err)
	}
	if svc.Cache.ItemCount() != 0 {
		t.Fatalf("a failed login left %d entry(ies) in the validation cache — the token authenticates for the full TTL against a row that was never written",
			svc.Cache.ItemCount())
	}
}

// --- fixtures ------------------------------------------------------------

// These legs need a real PostgreSQL: they are about what the server does with
// the statements — schema-qualified names, numbered placeholders, RETURNING,
// a CHECK-constrained role column, ON DELETE CASCADE — and a mock would only
// replay what the test already assumed. The same call pkg/aikey made.
//
//	MGMT_TEST_DSN  — the store to run against
//	MGMT_TEST_PG=required — fail instead of skipping when it is absent
//
// The evidence run sets both. A gate that can quietly skip is not a gate, so
// the harness makes the skip itself a failure.
const (
	testDSNEnv      = "MGMT_TEST_DSN"
	testRequiredEnv = "MGMT_TEST_PG"
)

// storeFixture opens the management store, provisions it, and hands back a
// UserService with clean tables.
func storeFixture(t *testing.T) *UserService {
	t.Helper()
	svc := &UserService{Cache: cache.New(CacheExpirationTime*time.Minute, CacheCleanupInterval*time.Minute)}
	svc.Attach(openMgmtStore(t))
	return svc
}

func openMgmtStore(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		if os.Getenv(testRequiredEnv) == "required" {
			t.Fatalf("%s is unset but %s=required: the store legs would have skipped silently", testDSNEnv, testRequiredEnv)
		}
		t.Skipf("%s unset — set it to a PostgreSQL DSN to run the store legs", testDSNEnv)
	}
	db, err := store.ConnectWithRetry(dsn, 3, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("connect to %s: %v", pgstore.RedactDSN(dsn), err)
	}
	t.Cleanup(func() { db.Close() })

	// Drop before provisioning, so the tables under test are the ones the
	// current DDL describes.
	//
	// ensureSchema is CREATE TABLE IF NOT EXISTS — correct in production,
	// where it must be a no-op on every boot after the first, and quietly
	// fatal in a test: against a store some earlier run already populated,
	// the DDL constants are never executed at all. Two gates passed that way,
	// asserting constraints on a table built from a different version of the
	// schema than the one in the source. A fixture that does not build what
	// it is testing is not a fixture.
	//
	// This makes the suite destructive to whatever is in aigw_mgmt, in the
	// same way pkg/aikey's is to aigw: run it against a scratch store, never
	// against one a live topology is using.
	dropSchemaTables(t, db)
	if err := ensureSchema(db); err != nil {
		t.Fatalf("provision the store: %v", err)
	}
	t.Cleanup(func() { truncate(t, db) })
	return db
}

func dropSchemaTables(t *testing.T, db *sql.DB) {
	t.Helper()
	// token first: it references users.
	for _, table := range []string{"token", "users"} {
		if _, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s.%s CASCADE", Schema, table)); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}
}

func truncate(t *testing.T, db *sql.DB) {
	t.Helper()
	// token first: it references users.
	for _, table := range []string{"token", "users"} {
		if _, err := db.Exec(fmt.Sprintf("DELETE FROM %s.%s", Schema, table)); err != nil {
			t.Fatalf("clear %s: %v", table, err)
		}
	}
}

func insertUserRow(t *testing.T, svc *UserService, username, password, role string) {
	t.Helper()
	h, err := svc.store()
	if err != nil {
		t.Fatalf("no store: %v", err)
	}
	if _, err := h.Exec(fmt.Sprintf(
		`INSERT INTO %s.users (username, password, created_at, role) VALUES ($1, $2, $3, $4)`, Schema),
		username, password, time.Now(), role); err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
}

func userID(t *testing.T, svc *UserService, username string) int {
	t.Helper()
	h, err := svc.store()
	if err != nil {
		t.Fatalf("no store: %v", err)
	}
	var id int
	if err := h.QueryRow(fmt.Sprintf(`SELECT id FROM %s.users WHERE username = $1`, Schema), username).Scan(&id); err != nil {
		t.Fatalf("read id for %s: %v", username, err)
	}
	return id
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := hashUserPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
