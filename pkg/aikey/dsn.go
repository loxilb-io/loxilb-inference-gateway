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

// Package aikey owns the data-plane API-key store: the credentials the AI
// Gateway checks on the VIP, and the per-tenant quotas that ride with them.
//
// It is deliberately a package of its own rather than a corner of pkg/user.
// The two hold credentials for different planes, and sharing a cache between
// them is what let a data-plane key hash be presented as a management token.
// Nothing here may import the management-plane packages, and the store this
// package talks to is reached with its own role, its own schema and its own
// connection pool.
package aikey

import "github.com/loxilb-io/loxilb/pkg/pgstore"

// SSL modes used when building a PostgreSQL DSN. Re-exported from pkg/pgconn,
// which owns the connection plumbing both planes share.
const (
	SSLModeDisable    = pgstore.SSLModeDisable
	SSLModeVerifyFull = pgstore.SSLModeVerifyFull
)

// PostgresDSN builds a PostgreSQL connection URL from discrete settings.
func PostgresDSN(user, password, host, port, dbname, sslMode string) string {
	return pgstore.PostgresDSN(user, password, host, port, dbname, sslMode)
}

// SSLModeFor maps --aikey-db-ssl onto a DSN sslmode.
func SSLModeFor(sslEnabled bool) string { return pgstore.SSLModeFor(sslEnabled) }

// RedactDSN returns dsn with any password replaced, for logging.
func RedactDSN(dsn string) string { return pgstore.RedactDSN(dsn) }
