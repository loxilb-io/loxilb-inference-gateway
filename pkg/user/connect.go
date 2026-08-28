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
	"time"

	"github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/pgstore"
	tk "github.com/loxilb-io/loxilib"
)

// PasswordEnv is the environment variable the management store password may
// arrive in, as an alternative to --mgmt-db-password-file. It is the name the
// bootstrap script takes, so an operator sets one value in one vocabulary.
const PasswordEnv = "AIGW_MGMT_DB_PASSWORD"

// store binds the shared PostgreSQL plumbing to the management plane.
//
// It is a distinct pgstore.Store from the data plane's: a different role, a
// different schema, a different password and a different pool. The two planes
// share a server, not a connection.
var store = pgstore.Store{
	Plane:        "mgmt",
	LogTag:       "[Mgmt]",
	PasswordEnv:  PasswordEnv,
	PasswordFlag: "--mgmt-db-password-file",
}

// mgmtDSN builds the management store's connection string from the
// --mgmt-db-* options and the resolved password.
func mgmtDSN() (string, error) {
	password, err := store.ResolvePassword(options.Opts.MgmtDBPasswordPath)
	if err != nil {
		return "", err
	}
	return pgstore.PostgresDSN(
		options.Opts.MgmtDBUser,
		password,
		options.Opts.MgmtDBHost,
		options.Opts.MgmtDBPort,
		options.Opts.MgmtDBName,
		pgstore.SSLModeFor(options.Opts.MgmtSSLOption),
	), nil
}

// mgmtDialParams is everything the dial derives from the process options,
// resolved once on the caller's goroutine. The background dial retries for
// seconds and must not re-read mutable package globals from its own
// goroutine: nothing rewrites the options mid-run in the product, but the
// dial outlives its caller by design, and a reader that re-derives its
// configuration per attempt is one config-reload feature away from a real
// race. Snapshotting also pins the dial to the configuration it was started
// under, which is the only configuration its caller ever asked it to try.
type mgmtDialParams struct {
	dsn        string
	useTLS     bool
	caCert     string
	clientCert string
	clientKey  string
}

func resolveMgmtDialParams() (mgmtDialParams, error) {
	dsn, err := mgmtDSN()
	if err != nil {
		return mgmtDialParams{}, err
	}
	return mgmtDialParams{
		dsn:        dsn,
		useTLS:     options.Opts.MgmtSSLOption,
		caCert:     options.Opts.MgmtSSLCACert,
		clientCert: options.Opts.MgmtSSLClientCert,
		clientKey:  options.Opts.MgmtSSLClientKey,
	}, nil
}

// connectStore dials the management store, verifies it is provisioned, and
// creates this plane's tables.
//
// Replaces the MySQL InitDB. The differences that matter are not the dialect:
// the pool is closed on every failure path rather than leaked, the TLS posture
// has no plaintext fallback, and a provisioning mistake is reported by name in
// preflight instead of arriving later as an opaque error on a login.
func connectStore(p mgmtDialParams) (*sql.DB, error) {
	tk.LogIt(tk.LogInfo, "%s Connecting to the management store at %s\n", store.LogTag, pgstore.RedactDSN(p.dsn))

	var db *sql.DB
	var err error
	if p.useTLS {
		db, err = store.ConnectWithSecureTLS(p.dsn, pgstore.DefaultMaxRetries, pgstore.DefaultBackoff,
			p.caCert, p.clientCert, p.clientKey)
	} else {
		db, err = store.ConnectWithRetry(p.dsn, pgstore.DefaultMaxRetries, pgstore.DefaultBackoff)
	}
	if err != nil {
		return nil, err
	}

	// From here on the pool is ours and every failure has to release it.
	if err := preflight(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := ensureSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// connectBackoff is the boot dial's patience. Exposed as a variable so a test
// can shorten it; the process only ever uses the default.
var connectBackoff = DbRetryDelay

// dialWithRetry rides out a database that is still starting: a cold server
// accepts authenticated TCP connections only several seconds after it first
// answers pings.
func dialWithRetry(p mgmtDialParams) (*sql.DB, error) {
	var lastErr error
	for i := 0; i < DbMaxRetries; i++ {
		if i > 0 {
			time.Sleep(connectBackoff)
		}
		db, err := connectStore(p)
		if err == nil {
			return db, nil
		}
		lastErr = err
		tk.LogIt(tk.LogError, "%s Store connection attempt %d/%d failed: %v\n",
			store.LogTag, i+1, DbMaxRetries, err)
	}
	return nil, lastErr
}
