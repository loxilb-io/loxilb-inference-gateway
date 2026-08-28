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
	"fmt"
	"time"
)

// Store tuning and policy constants. These lived in pkg/db while that package
// held a MySQL connection shared with nothing; with the driver gone, the only
// caller is this package and the values belong beside the statements they
// bound.
const (
	// MinPasswordLength is the floor the documented policy states.
	MinPasswordLength = 9
	// TokenExpirationMinutes is the lifetime of a management session token.
	TokenExpirationMinutes = 1440 // 24 hours

	// AuthMaxRetries / AuthRetryDelay is the REQUEST profile, and it is a
	// budget rather than a preference. Every RetryOperation call here runs
	// underneath an HTTP handler, so the retries are paid for by a client
	// holding a connection open, and by whatever is upstream of it. Three
	// attempts at 300 ms with doubling backoff bound the worst case at 900 ms
	// of sleep, which stays under the OAM proxy's own budget.
	AuthMaxRetries   = 3
	AuthRetryDelay   = 300 * time.Millisecond
	AuthRetryBackoff = 2

	// The BACKGROUND profile: a boot dial or a reconnect that has nobody
	// waiting on it can afford to be patient.
	DbMaxRetries = 5
	DbRetryDelay = 5 * time.Second
)

// Management-plane statements.
//
// PostgreSQL numbered placeholders, and every table qualified by Schema —
// nothing here relies on the role's search_path.
//
// Each statement selects exactly what its caller scans. That is not a style
// note: sharing one two-column query between a caller that scanned two
// destinations and a caller that scanned one is what made every password
// change fail with "sql: expected 2 destination arguments in Scan, not 1",
// and the mismatch was invisible at the call site because the query was named
// there rather than written there.
var (
	SelectAllUsersQuery = fmt.Sprintf(
		`SELECT id, username, created_at, role FROM %s.users ORDER BY id`, Schema)

	SelectUserQuery = fmt.Sprintf(
		`SELECT id, username, password, role FROM %s.users WHERE id = $1`, Schema)

	InsertUserQuery = fmt.Sprintf(
		`INSERT INTO %s.users (username, password, created_at, role) VALUES ($1, $2, $3, $4) RETURNING id`, Schema)

	// CountUsersQuery answers "has anyone been created yet", which is the
	// bootstrap's precondition.
	CountUsersQuery = fmt.Sprintf(`SELECT COUNT(*) FROM %s.users`, Schema)

	// BootstrapUserQuery creates the first user only while the table is
	// empty. Check and insert are one statement, because checking and then
	// inserting lets two simultaneous requests both create an administrator.
	BootstrapUserQuery = fmt.Sprintf(
		`INSERT INTO %s.users (username, password, created_at, role)
		 SELECT $1, $2, $3, $4
		 WHERE NOT EXISTS (SELECT 1 FROM %s.users)
		 RETURNING id`, Schema, Schema)

	UpdateUserQuery = fmt.Sprintf(
		`UPDATE %s.users SET username = $1, password = $2, role = $3 WHERE id = $4`, Schema)

	DeleteUserQuery = fmt.Sprintf(`DELETE FROM %s.users WHERE id = $1`, Schema)

	SelectUsernameByIDQuery = fmt.Sprintf(
		`SELECT username FROM %s.users WHERE id = $1`, Schema)

	// ValidateUser needs the hash and the role.
	SelectUserPasswordQuery = fmt.Sprintf(
		`SELECT password, role FROM %s.users WHERE username = $1`, Schema)

	// validatePassword needs only the hash.
	SelectUserPasswordOnlyQuery = fmt.Sprintf(
		`SELECT password FROM %s.users WHERE username = $1`, Schema)

	// Tokens are stored by hash. The raw token is returned to its owner once
	// and never written down.
	InsertTokenQuery = fmt.Sprintf(
		`INSERT INTO %s.token (token_hash, username, expires_at, role) VALUES ($1, $2, $3, $4)`, Schema)

	// ValidateTokenQuery also returns expires_at, so the cache entry can be
	// bounded by the token's real remaining life instead of a flat five
	// minutes that outlives it.
	ValidateTokenQuery = fmt.Sprintf(
		`SELECT username, role, expires_at FROM %s.token WHERE token_hash = $1 AND expires_at > now()`, Schema)

	DeleteTokenQuery = fmt.Sprintf(`DELETE FROM %s.token WHERE token_hash = $1`, Schema)

	DeleteExpiredTokenQuery = fmt.Sprintf(`DELETE FROM %s.token WHERE expires_at <= now()`, Schema)

	// Revocation: every token belonging to one user, returned so the caller
	// can evict the same hashes from its own cache and from its peers'.
	SelectTokenHashesForUserQuery = fmt.Sprintf(
		`SELECT token_hash FROM %s.token WHERE username = $1`, Schema)

	DeleteTokensForUserQuery = fmt.Sprintf(`DELETE FROM %s.token WHERE username = $1`, Schema)
)
