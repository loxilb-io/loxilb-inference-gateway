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
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// awkwardPasswords are the characters that break fmt.Sprintf DSN
// construction: each is structural in a URL, so an unescaped one moves the
// parse boundary and the password silently becomes part of the host, the
// path, or the query.
var awkwardPasswords = []string{
	"p@ssword",
	"p/assword",
	"p:assword",
	"p?assword",
	"p#assword",
	"p@s/s:w?ord#1",
	"@/:?",
	"pass word",
	"pÄssword",
	"%40already-encoded",
}

// U-13 — a password containing '@', '/', ':' or '?' survives DSN
// construction and comes back out of pgx.ParseConfig byte-for-byte.
func TestPostgresDSNRoundTripsAwkwardPasswords(t *testing.T) {
	for _, pw := range awkwardPasswords {
		t.Run(pw, func(t *testing.T) {
			dsn := PostgresDSN("aigwuser", pw, "db.example.internal", "5432", "loxilb", SSLModeVerifyFull)

			cfg, err := pgx.ParseConfig(dsn)
			if err != nil {
				t.Fatalf("ParseConfig(%q) failed: %v", RedactDSN(dsn), err)
			}
			if cfg.Password != pw {
				t.Errorf("password round-trip: got %q, want %q", cfg.Password, pw)
			}
			if cfg.User != "aigwuser" {
				t.Errorf("user round-trip: got %q, want %q", cfg.User, "aigwuser")
			}
			if cfg.Host != "db.example.internal" {
				t.Errorf("host round-trip: got %q, want %q", cfg.Host, "db.example.internal")
			}
			if cfg.Port != 5432 {
				t.Errorf("port round-trip: got %d, want 5432", cfg.Port)
			}
			if cfg.Database != "loxilb" {
				t.Errorf("database round-trip: got %q, want %q", cfg.Database, "loxilb")
			}
		})
	}
}

// The DSN must ask for a verified connection when TLS is selected, and there
// is no third posture: anything other than verify-full would accept a
// certificate that does not match the host.
func TestSSLModeFor(t *testing.T) {
	if got := SSLModeFor(true); got != SSLModeVerifyFull {
		t.Errorf("SSLModeFor(true) = %q, want %q", got, SSLModeVerifyFull)
	}
	if got := SSLModeFor(false); got != SSLModeDisable {
		t.Errorf("SSLModeFor(false) = %q, want %q", got, SSLModeDisable)
	}
	dsn := PostgresDSN("u", "p", "h", "5432", "d", SSLModeFor(true))
	if !strings.Contains(dsn, "sslmode=verify-full") {
		t.Errorf("DSN %q does not carry sslmode=verify-full", RedactDSN(dsn))
	}
}

// U-14 — RedactDSN never emits the password, for a well-formed DSN or for one
// that cannot be parsed at all. The unparseable case is the one that matters:
// it is exactly when a password is malformed, and returning the input on a
// parse failure would leak it into the log line reporting the failure.
func TestRedactDSNNeverLeaksPassword(t *testing.T) {
	const secret = "s3cr3t-P@ss/w:rd?x"

	valid := PostgresDSN("aigwuser", secret, "db.example.internal", "5432", "loxilb", SSLModeVerifyFull)
	redacted := RedactDSN(valid)
	if strings.Contains(redacted, secret) {
		t.Errorf("redacted DSN contains the raw password: %q", redacted)
	}
	// The escaped form must not survive either — a reader with a URL decoder
	// is not a meaningful obstacle.
	for _, enc := range []string{"s3cr3t", "P%40ss", "%2Fw", "%3Ar"} {
		if strings.Contains(redacted, enc) {
			t.Errorf("redacted DSN contains password fragment %q: %q", enc, redacted)
		}
	}
	if !strings.Contains(redacted, "aigwuser") || !strings.Contains(redacted, "db.example.internal") {
		t.Errorf("redacted DSN lost the parts that make it useful in a log: %q", redacted)
	}

	// A control character cannot appear in a URL, so this cannot be parsed.
	unparseable := "postgres://aigwuser:" + secret + "\x7f@db.example.internal:5432/loxilb"
	redacted = RedactDSN(unparseable)
	if strings.Contains(redacted, secret) {
		t.Errorf("redacted unparseable DSN contains the raw password: %q", redacted)
	}
	if redacted == unparseable {
		t.Errorf("RedactDSN returned an unparseable DSN unchanged: %q", redacted)
	}
}

// A DSN with no password at all must not grow a fake one, and must not panic.
func TestRedactDSNWithoutPassword(t *testing.T) {
	redacted := RedactDSN("postgres://aigwuser@db.example.internal:5432/loxilb")
	if strings.Contains(redacted, "xxxxx") {
		t.Errorf("RedactDSN invented a password: %q", redacted)
	}
	if !strings.Contains(redacted, "aigwuser") {
		t.Errorf("RedactDSN dropped the user: %q", redacted)
	}
}
