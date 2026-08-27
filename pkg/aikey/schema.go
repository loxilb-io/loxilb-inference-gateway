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
	"fmt"

	tk "github.com/loxilb-io/loxilib"
)

// Schema is the PostgreSQL schema the data-plane tables live in. It is owned
// by the gateway's own role, which has no access to the management plane's
// tables in the same database — the storage-layer counterpart of giving this
// package its own cache.
//
// Every statement names it explicitly rather than relying on the role's
// search_path. search_path is a role attribute the gateway cannot verify it
// still has, and a table silently created in the wrong schema is a fault that
// only shows up as missing keys much later.
const Schema = "aigw"

// Data-plane DDL. Provisioned by the gateway at boot inside the schema its
// role owns; the schema, role and grants themselves belong to the deployment
// (scripts/aigw-db-bootstrap.sql), because they need privileges this role
// does not have.
//
// Differences from the MySQL originals that are deliberate, not mechanical:
//
//   - The integer columns are NOT NULL. MySQL's `INT DEFAULT 0` left them
//     nullable, and every read scans them into a plain int — a NULL row, once
//     written by anything but this code, fails the scan and takes out the
//     whole listing.
//   - Timestamps are TIMESTAMPTZ. MySQL's DATETIME(3) stores a naive wall
//     clock that is only correct while every writer remembers to convert to
//     UTC first; the management plane's equivalent shortcut is what broke
//     GET /auth/users.
//   - key_hash is UNIQUE. It is the authentication lookup key, and once a
//     caller may supply key material, two rows could otherwise carry the same
//     hash and the lookup would resolve a request to an arbitrary one of two
//     tenants.
//   - No ON UPDATE trigger. Every writer sets updated_at explicitly, so the
//     MySQL clause never fired; reusing OAM's set_updated_at() instead would
//     put a public-schema dependency in a role that is deliberately denied
//     the public schema.
var (
	createAPIKeysTable = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.api_keys (
	key_id         VARCHAR(64) PRIMARY KEY,
	key_hash       VARCHAR(64) NOT NULL,
	tenant_id      VARCHAR(128) NOT NULL,
	name           VARCHAR(255) NOT NULL DEFAULT '',
	allowed_models TEXT NOT NULL,
	rate_limit_rps INTEGER NOT NULL DEFAULT 0,
	burst_size     INTEGER NOT NULL DEFAULT 0,
	tokens_per_min INTEGER NOT NULL DEFAULT 0,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at     TIMESTAMPTZ,
	enabled        BOOLEAN NOT NULL DEFAULT TRUE
)`, Schema)

	createAPIKeysTenantIndex = fmt.Sprintf(
		`CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON %s.api_keys (tenant_id)`, Schema)

	createAPIKeysHashIndex = fmt.Sprintf(
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_key_hash ON %s.api_keys (key_hash)`, Schema)

	createTenantRateLimitsTable = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.tenant_rate_limits (
	tenant_id      VARCHAR(128) PRIMARY KEY,
	rps            INTEGER NOT NULL DEFAULT 0,
	tokens_per_min INTEGER NOT NULL DEFAULT 0,
	burst_pct      INTEGER NOT NULL DEFAULT 0,
	updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
)`, Schema)

	// Back-fills burst_pct on a table created before the column existed.
	// PostgreSQL has ADD COLUMN IF NOT EXISTS, so unlike the MySQL path there
	// is no duplicate-column error to tolerate.
	alterTenantRateLimitsAddBurst = fmt.Sprintf(
		`ALTER TABLE %s.tenant_rate_limits ADD COLUMN IF NOT EXISTS burst_pct INTEGER NOT NULL DEFAULT 0`, Schema)

	createTenantModelRateLimitsTable = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.tenant_model_rate_limits (
	tenant_id      VARCHAR(128) NOT NULL,
	model          VARCHAR(255) NOT NULL,
	tokens_per_min INTEGER NOT NULL DEFAULT 0,
	updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (tenant_id, model)
)`, Schema)
)

// preflight verifies the store is provisioned the way this package needs
// before any DDL runs, so a provisioning mistake reports itself by name
// instead of arriving later as an opaque driver error on a live request.
//
// It checks that the schema exists and that this role holds USAGE and CREATE
// on it. search_path is reported but not required: every statement here
// qualifies its table, so a role without the schema on its path still works,
// and failing on it would be asserting something the code does not depend on.
func preflight(db *sql.DB) error {
	var schemaExists bool
	if err := db.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`, Schema).Scan(&schemaExists); err != nil {
		return fmt.Errorf("aikey: key store preflight failed: cannot read the schema catalogue: %w", err)
	}
	if !schemaExists {
		return fmt.Errorf("aikey: key store preflight failed: schema %q does not exist. "+
			"Run scripts/aigw-db-bootstrap.sql against this database as its owner. See docs/AI-KEY-STORE.md", Schema)
	}

	var usage, create bool
	if err := db.QueryRow(
		`SELECT has_schema_privilege(current_user, $1, 'USAGE'),
		        has_schema_privilege(current_user, $1, 'CREATE')`, Schema).Scan(&usage, &create); err != nil {
		return fmt.Errorf("aikey: key store preflight failed: cannot read schema privileges on %q: %w", Schema, err)
	}
	if !usage || !create {
		var role string
		_ = db.QueryRow(`SELECT current_user`).Scan(&role)
		return fmt.Errorf("aikey: key store preflight failed: schema %q is not accessible to role %q "+
			"(usage=%t create=%t). Run scripts/aigw-db-bootstrap.sql against this database as its owner. "+
			"See docs/AI-KEY-STORE.md", Schema, role, usage, create)
	}

	var searchPath string
	if err := db.QueryRow(`SHOW search_path`).Scan(&searchPath); err == nil {
		tk.LogIt(tk.LogInfo, "[AIKey] Store preflight passed: schema %q writable, search_path=%s\n", Schema, searchPath)
	}
	return nil
}

// ensureSchema provisions the data-plane tables. Idempotent: safe on every
// boot, and the path by which a gateway that started against a cold database
// becomes functional when the store heals.
func ensureSchema(db *sql.DB) error {
	stmts := []struct {
		what string
		sql  string
	}{
		{"api_keys table", createAPIKeysTable},
		{"api_keys tenant index", createAPIKeysTenantIndex},
		{"api_keys key_hash unique index", createAPIKeysHashIndex},
		{"tenant_rate_limits table", createTenantRateLimitsTable},
		{"tenant_rate_limits.burst_pct column", alterTenantRateLimitsAddBurst},
		{"tenant_model_rate_limits table", createTenantModelRateLimitsTable},
	}
	for _, s := range stmts {
		if _, err := db.Exec(s.sql); err != nil {
			return fmt.Errorf("aikey: failed to create %s: %w", s.what, err)
		}
	}
	return nil
}
