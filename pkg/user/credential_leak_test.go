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
	"testing"
	"time"

	tk "github.com/loxilb-io/loxilib"
	_ "github.com/mattn/go-sqlite3"
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

// setupCredLeakTestDB creates an in-memory SQLite database with the token
// table required by Logout and ValidateToken code paths.
func setupCredLeakTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite3: %v", err)
	}

	// Create the token table matching the schema used by DeleteTokenQuery
	// and ValidateTokenQuery. SQLite does not have NOW, but the queries
	// that only delete by token_value work fine.
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS token (
		token_value TEXT PRIMARY KEY,
		username TEXT,
		expires_at DATETIME,
		role TEXT
	)`)
	if err != nil {
		t.Fatalf("create token table: %v", err)
	}
	return db
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
	defer db.Close()

	svc := &UserService{
		DB:    db,
		Cache: cache.New(5*time.Minute, 10*time.Minute),
	}

	// Use a realistic JWT-like token that would match the eyJ pattern
	fakeJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZmFrZSJ9.fakesig"

	// --- Exercise Logout path ---
	// Populate cache so Logout can recover the username
	svc.Cache.Set(fakeJWT, "testuser|admin", 5*time.Minute)

	// Insert a token row so DeleteTokenQuery succeeds (exercises the log line)
	_, err := db.Exec("INSERT INTO token (token_value, username, expires_at, role) VALUES (?, ?, ?, ?)",
		fakeJWT, "testuser", time.Now().Add(1*time.Hour).Format("2006-01-02 15:04:05"), "admin")
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}

	err = svc.Logout(fakeJWT)
	if err != nil {
		t.Logf("Logout returned error (may be expected): %v", err)
	}

	// --- Exercise ValidateToken path (token not in cache or DB) ---
	_, err = svc.ValidateToken(fakeJWT)
	if err != nil {
		t.Logf("ValidateToken returned error (expected — token deleted): %v", err)
	}

	// --- Assert no credential patterns in log output ---
	assertNoCredentialPatterns(t, logPath)
}
