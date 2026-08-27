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
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	tk "github.com/loxilb-io/loxilib"
	"github.com/patrickmn/go-cache"
)

// setupLogCapture redirects all tk.LogIt output to a temporary file
// and returns the path and a cleanup function.
// NOTE: Do NOT call t.Parallel in tests using this — LogItInit
// writes package-level state (DefaultLogger).
func setupLogCapture(t *testing.T) (logPath string, cleanup func()) {
	t.Helper()
	f, err := os.CreateTemp("", "loxilb-cred-test-*.log")
	if err != nil {
		t.Fatalf("create temp log file: %v", err)
	}
	logPath = f.Name()
	f.Close()

	tk.LogItInit(logPath, tk.LogDebug, false)

	cleanup = func() {
		os.Remove(logPath)
	}
	return logPath, cleanup
}

// assertNoCredentialPatterns reads the captured log output and fails the
// test if any JWT token or API key rawKey patterns are found.
func assertNoCredentialPatterns(t *testing.T, logPath string) {
	t.Helper()
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	logStr := string(content)

	// JWT header pattern: base64-encoded JSON starting with {"alg":...}
	jwtRe := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}`)
	if match := jwtRe.FindString(logStr); match != "" {
		t.Errorf("JWT token pattern leaked in log output: %s", match)
	}

	// API key rawKey pattern: lxb_ prefix followed by 64 hex chars
	apiKeyRe := regexp.MustCompile(`lxb_[0-9a-f]{64}`)
	if match := apiKeyRe.FindString(logStr); match != "" {
		t.Errorf("API key rawKey pattern leaked in log output: %s", match)
	}
}

// setupCredLeakTestDB opens the management store the rest of this package's
// store legs use. It was an in-memory SQLite; the statements it exercises are
// now schema-qualified PostgreSQL with numbered placeholders, so a SQLite
// stand-in would only prove that a different dialect does not leak.
func setupCredLeakTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return openMgmtStore(t)
}

// TestNoCredentialLeakInLogs exercises the Logout and ValidateToken code
// paths with JWT-like tokens and verifies that no credential values appear
// in the captured log output.
//
// This test is the runtime layer of the SEC-03 CI regression gate.
func TestNoCredentialLeakInLogs(t *testing.T) {
	// Do NOT use t.Parallel — tk.LogItInit writes package-level vars.

	logPath, cleanup := setupLogCapture(t)
	defer cleanup()

	db := setupCredLeakTestDB(t)

	svc := &UserService{
		Cache: cache.New(5*time.Minute, 10*time.Minute),
	}
	svc.Attach(db)

	// A token of the shape the old JWT scheme produced, so the eyJ pattern in
	// assertNoCredentialPatterns still has something to match on, plus one of
	// the opaque hex tokens the scheme now issues.
	fakeJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZmFrZSJ9.fakesig"
	realToken, err := generateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// The token table references users, so the owner has to exist.
	insertUserRow(t, svc, "testuser", mustHash(t, "Admin123!"), "admin")

	for _, tok := range []string{fakeJWT, realToken} {
		// --- Exercise Logout path ---
		// Populate cache so Logout can recover the username. Keyed by hash,
		// which is what the code does.
		svc.Cache.Set(hashToken(tok), "testuser|admin", 5*time.Minute)

		// Insert a token row so DeleteTokenQuery succeeds (exercises the log line)
		if _, err := db.Exec(InsertTokenQuery,
			hashToken(tok), "testuser", time.Now().Add(1*time.Hour), "admin"); err != nil {
			t.Fatalf("insert token: %v", err)
		}

		if err := svc.Logout(tok); err != nil {
			t.Logf("Logout returned error (may be expected): %v", err)
		}

		// --- Exercise ValidateToken path (token not in cache or DB) ---
		if _, err := svc.ValidateToken(tok); err != nil {
			t.Logf("ValidateToken returned error (expected — token deleted): %v", err)
		}
	}

	// --- Assert no credential patterns in log output ---
	assertNoCredentialPatterns(t, logPath)

	// The opaque token is 64 hex characters and matches no pattern above, so
	// assert it directly: a scheme change must not quietly retire the check.
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if strings.Contains(string(content), realToken) {
		t.Error("an opaque session token appeared verbatim in the log output")
	}
	if !strings.Contains(string(content), "testuser") {
		t.Error("the log lines under test never ran — nothing named the user they log")
	}
}
