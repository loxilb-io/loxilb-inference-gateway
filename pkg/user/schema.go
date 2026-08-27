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
	"fmt"

	tk "github.com/loxilb-io/loxilib"
)

// Schema is the PostgreSQL schema the management-plane tables live in, owned
// by a role that has no access to the data plane's tables in the same
// database. The storage-layer counterpart of the two planes holding separate
// caches.
//
// Every statement names it explicitly rather than relying on the role's
// search_path: search_path is a role attribute this process cannot verify it
// still has, and a table silently created in the wrong schema is a fault that
// surfaces much later as missing users.
const Schema = "aigw_mgmt"

// Management-plane DDL.
//
// Four constraints here are repairs that were impossible to make cheaply on
// the MySQL tables and are free at creation time:
//
//   - username is UNIQUE. Without it duplicate accounts were creatable, the
//     duplicate check in AddUser was dead code, and login authenticated
//     against whichever row the planner returned first.
//   - role is a CHECK-constrained enum. The authorizer already refuses
//     anything outside it; the column now refuses to hold it, so a row hand
//     written into the database cannot express an authority the code does
//     not implement.
//   - the token table holds token_hash, never the token. Read access to this
//     table used to yield live 24-hour bearer credentials.
//   - token.username REFERENCES users(username) ON DELETE CASCADE. Deleting a
//     user used to leave that user's tokens valid until they expired; the
//     revocation path deletes them explicitly, and this is the backstop for
//     every path that forgets to.
var (
	createUsersTable = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.users (
	id          SERIAL PRIMARY KEY,
	username    TEXT NOT NULL UNIQUE,
	password    TEXT NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	role        TEXT NOT NULL CHECK (role IN ('admin','viewer'))
)`, Schema)

	createTokenTable = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.token (
	id          SERIAL PRIMARY KEY,
	token_hash  CHAR(64) NOT NULL UNIQUE,
	username    TEXT NOT NULL REFERENCES %s.users(username) ON UPDATE CASCADE ON DELETE CASCADE,
	expires_at  TIMESTAMPTZ NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	role        TEXT NOT NULL
)`, Schema, Schema)

	createTokenUsernameIndex = fmt.Sprintf(
		`CREATE INDEX IF NOT EXISTS token_username_idx ON %s.token (username)`, Schema)

	createTokenExpiryIndex = fmt.Sprintf(
		`CREATE INDEX IF NOT EXISTS token_expires_at_idx ON %s.token (expires_at)`, Schema)
)

// preflight verifies the store is provisioned the way this package needs
// before any DDL runs, so a provisioning mistake reports itself by name
// instead of arriving later as an opaque driver error on a login.
func preflight(db *sql.DB) error {
	var schemaExists bool
	if err := db.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`, Schema).Scan(&schemaExists); err != nil {
		return fmt.Errorf("mgmt: management store preflight failed: cannot read the schema catalogue: %w", err)
	}
	if !schemaExists {
		return fmt.Errorf("mgmt: management store preflight failed: schema %q does not exist. "+
			"Run scripts/aigw-db-bootstrap.sql against this database as its owner", Schema)
	}

	var usage, create bool
	if err := db.QueryRow(
		`SELECT has_schema_privilege(current_user, $1, 'USAGE'),
		        has_schema_privilege(current_user, $1, 'CREATE')`, Schema).Scan(&usage, &create); err != nil {
		return fmt.Errorf("mgmt: management store preflight failed: cannot read schema privileges on %q: %w", Schema, err)
	}
	if !usage || !create {
		var role string
		_ = db.QueryRow(`SELECT current_user`).Scan(&role)
		return fmt.Errorf("mgmt: management store preflight failed: schema %q is not accessible to role %q "+
			"(usage=%t create=%t). Run scripts/aigw-db-bootstrap.sql against this database as its owner",
			Schema, role, usage, create)
	}

	var searchPath string
	if err := db.QueryRow(`SHOW search_path`).Scan(&searchPath); err == nil {
		tk.LogIt(tk.LogInfo, "[Mgmt] Store preflight passed: schema %q writable, search_path=%s\n", Schema, searchPath)
	}
	return nil
}

// ensureSchema provisions the management-plane tables. Idempotent: safe on
// every boot, and the path by which a gateway that started against a cold
// database becomes functional when the store heals.
func ensureSchema(db *sql.DB) error {
	stmts := []struct {
		what string
		sql  string
	}{
		{"users table", createUsersTable},
		{"token table", createTokenTable},
		{"token username index", createTokenUsernameIndex},
		{"token expires_at index", createTokenExpiryIndex},
	}
	for _, s := range stmts {
		if _, err := db.Exec(s.sql); err != nil {
			return fmt.Errorf("mgmt: failed to create %s: %w", s.what, err)
		}
	}
	return nil
}
