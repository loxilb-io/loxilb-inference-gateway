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
	"crypto/tls"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/loxilb-io/loxilb/pkg/pgstore"
)

// Connection pool sizing and connect budget, from the shared plumbing.
const (
	poolMaxOpenConns    = pgstore.PoolMaxOpenConns
	poolMaxIdleConns    = pgstore.PoolMaxIdleConns
	poolConnMaxLifetime = pgstore.PoolConnMaxLifetime

	connectMaxRetries = pgstore.DefaultMaxRetries
	connectBackoff    = pgstore.DefaultBackoff
)

// PasswordEnv is the environment variable the store password may arrive in,
// as an alternative to --aikey-db-password-file. It is the same name the
// bootstrap script takes, so an operator sets one value in one vocabulary.
const PasswordEnv = "AIGW_DB_PASSWORD"

// ErrNoPassword is returned when the store is configured but no password can
// be resolved. Boot fails on it rather than attempting a passwordless
// connection: a silent fallback here would be a silent downgrade of the only
// credential protecting the key store.
var ErrNoPassword = pgstore.ErrNoPassword

// store binds the shared plumbing to the data plane, so an error names this
// store rather than "the database".
var store = pgstore.Store{
	Plane:        "aikey",
	LogTag:       "[AIKey]",
	PasswordEnv:  PasswordEnv,
	PasswordFlag: "--aikey-db-password-file",
}

// ResolvePassword returns the store password from the password file if one is
// named, otherwise from the environment.
func ResolvePassword(passwordPath string) (string, error) {
	return store.ResolvePassword(passwordPath)
}

// secureTLSConfig builds the TLS configuration used for a verified store
// connection.
func secureTLSConfig(serverName, caCertFile, clientCertFile, clientKeyFile string) (*tls.Config, error) {
	return store.SecureTLSConfig(serverName, caCertFile, clientCertFile, clientKeyFile)
}

// secureConnConfig parses dsn and applies the store's TLS posture to it.
func secureConnConfig(dsn, caCertFile, clientCertFile, clientKeyFile string) (*pgx.ConnConfig, error) {
	return store.SecureConnConfig(dsn, caCertFile, clientCertFile, clientKeyFile)
}

// ConnectWithSecureTLS opens a verified-TLS connection to the key store.
func ConnectWithSecureTLS(dsn string, maxRetries int, backoff time.Duration, caCertFile, clientCertFile, clientKeyFile string) (*sql.DB, error) {
	return store.ConnectWithSecureTLS(dsn, maxRetries, backoff, caCertFile, clientCertFile, clientKeyFile)
}

// ConnectWithRetry opens a plaintext connection to the key store.
func ConnectWithRetry(dsn string, maxRetries int, backoff time.Duration) (*sql.DB, error) {
	return store.ConnectWithRetry(dsn, maxRetries, backoff)
}
