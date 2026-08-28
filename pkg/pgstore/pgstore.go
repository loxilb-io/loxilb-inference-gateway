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

// Package pgstore holds the PostgreSQL connection plumbing both planes use:
// DSN construction and redaction, password resolution, pool sizing, retrying
// connects, and the verified-TLS posture.
//
// It exists because the two planes must not reach each other. The management
// store cannot obtain this code by importing pkg/aikey — that import is the
// thing the plane-separation gate forbids — and copying it would let the two
// connection paths drift, which is exactly how one of them would end up with
// a plaintext fallback the other had removed.
//
// Nothing here knows what is stored. It carries no schema, no query and no
// credential type; a Store value only names the plane so that an error says
// which store failed rather than "the database".
package pgstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	pgxconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	tk "github.com/loxilb-io/loxilib"

	// registers the "pgx" driver with database/sql
	_ "github.com/jackc/pgx/v5/stdlib"
)

// ConnectTimeoutSeconds bounds a single dial attempt to the store.
const ConnectTimeoutSeconds = 2

// SSL modes used when building a PostgreSQL DSN.
const (
	// SSLModeDisable connects in plaintext — appropriate only where the
	// database is reachable solely on an internal compose/cluster network.
	SSLModeDisable = "disable"
	// SSLModeVerifyFull requires TLS and verifies both the certificate chain
	// and the server hostname. Selected by the plane's --*-db-ssl flag, which
	// also supplies the CA and the client keypair.
	SSLModeVerifyFull = "verify-full"
)

// Connection pool sizing, matching loxilb-oam's so that processes sharing one
// PostgreSQL server present a predictable combined connection count.
const (
	PoolMaxOpenConns    = 10
	PoolMaxIdleConns    = 5
	PoolConnMaxLifetime = 5 * time.Minute

	DefaultMaxRetries = 5
	DefaultBackoff    = 2 * time.Second
)

// ErrNoPassword is returned when a store is configured but no password can be
// resolved. Boot fails on it rather than attempting a passwordless
// connection: a silent fallback would be a silent downgrade of the only
// credential protecting the store.
var ErrNoPassword = errors.New("no store password configured")

// PostgresDSN builds a PostgreSQL connection URL from discrete settings.
//
// Credentials are escaped rather than concatenated: a password containing
// '@', '/', ':' or '?' produces an unparseable DSN under fmt.Sprintf
// construction, which surfaces as a confusing authentication failure rather
// than a configuration error.
func PostgresDSN(user, password, host, port, dbname, sslMode string) string {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(host, port),
		Path:   "/" + dbname,
	}
	q := url.Values{}
	q.Set("sslmode", sslMode)
	// Bound the dial. Without it a stopped server is not reported until the
	// kernel gives up on the SYN — about 15 s — and the request profile
	// spends that three times over, so an unreachable store cost ~45 s per
	// request while the retry sleeps it was budgeted against total 900 ms.
	// The failure this bounds is "nothing is listening", which one attempt
	// establishes; the retries are there for a server that is up and
	// briefly busy, and those answer well inside this.
	q.Set("connect_timeout", strconv.Itoa(ConnectTimeoutSeconds))
	u.RawQuery = q.Encode()
	return u.String()
}

// SSLModeFor maps the plane's boolean --*-db-ssl flag onto a DSN sslmode.
func SSLModeFor(sslEnabled bool) string {
	if sslEnabled {
		return SSLModeVerifyFull
	}
	return SSLModeDisable
}

// RedactDSN returns dsn with any password replaced, for logging.
//
// A DSN that cannot be parsed is not returned unchanged — an unparseable DSN
// is exactly the case where the password is most likely to be the reason, so
// returning it would log the credential at the moment it is most visible.
func RedactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "postgres://<unparseable DSN redacted>"
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
		}
	}
	return u.String()
}

// Store binds the shared plumbing to one plane so that failures name the
// store that failed. It holds no connection state of its own.
type Store struct {
	// Plane prefixes returned errors, e.g. "aikey" or "mgmt".
	Plane string
	// LogTag prefixes log lines, e.g. "[AIKey]" or "[Mgmt]".
	LogTag string
	// PasswordEnv is the environment variable the password may arrive in.
	PasswordEnv string
	// PasswordFlag is the command-line flag named in the "no password" error,
	// so the operator is told the two ways to supply it.
	PasswordFlag string
}

func (s Store) errf(format string, a ...any) error {
	return fmt.Errorf(s.Plane+": "+format, a...)
}

// ResolvePassword returns the store password from the password file if one is
// named, otherwise from the environment.
//
// The file wins over the environment because it is the deployment-managed
// path (compose/Kubernetes secret mounts), and a stale exported variable
// should not silently override a mounted secret. A named-but-unreadable file
// is an error, never a fall-through to the environment — that would turn a
// broken secret mount into a confusing authentication failure against a stale
// password.
func (s Store) ResolvePassword(passwordPath string) (string, error) {
	if passwordPath != "" {
		b, err := os.ReadFile(passwordPath)
		if err != nil {
			return "", s.errf("cannot read store password file %q: %w", passwordPath, err)
		}
		// Trailing newlines are what every `echo secret > file` produces;
		// interior whitespace is part of the password and is preserved.
		pw := strings.Trim(string(b), "\r\n")
		if pw == "" {
			return "", s.errf("store password file %q is empty: %w", passwordPath, ErrNoPassword)
		}
		return pw, nil
	}
	if pw := os.Getenv(s.PasswordEnv); pw != "" {
		return pw, nil
	}
	return "", s.errf("no store password (set %s or %s): %w", s.PasswordEnv, s.PasswordFlag, ErrNoPassword)
}

// SecureTLSConfig builds the TLS configuration used for a verified store
// connection. Split out from ConnectWithSecureTLS so the properties that make
// it secure are assertable without a live server.
func (s Store) SecureTLSConfig(serverName, caCertFile, clientCertFile, clientKeyFile string) (*tls.Config, error) {
	rootCertPool := x509.NewCertPool()
	pem, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, s.errf("cannot read store CA certificate %q: %w", caCertFile, err)
	}
	if !rootCertPool.AppendCertsFromPEM(pem) {
		// AppendCertsFromPEM reports failure only by returning false. Ignoring
		// it leaves an empty pool, and an empty pool with RootCAs set fails
		// every verification at connect time with an opaque error instead of
		// naming the file that is wrong.
		return nil, s.errf("store CA certificate %q contains no usable certificate", caCertFile)
	}

	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, s.errf("cannot load store client keypair: %w", err)
	}

	return &tls.Config{
		RootCAs:      rootCertPool,
		Certificates: []tls.Certificate{clientCert},
		// pgx derives ServerName itself only when it builds the TLS config
		// from sslmode; supplying our own means we have to set it, or
		// verification would fail against every certificate.
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// SecureConnConfig parses dsn and applies the store's TLS posture to it.
//
// Separate from ConnectWithSecureTLS so that the three properties that make a
// store connection secure — a verified chain, a floor on the protocol
// version, and the absence of any plaintext fallback — are assertable without
// a live PostgreSQL to connect to.
func (s Store) SecureConnConfig(dsn, caCertFile, clientCertFile, clientKeyFile string) (*pgx.ConnConfig, error) {
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, s.errf("invalid store DSN: %w", err)
	}

	tlsCfg, err := s.SecureTLSConfig(connConfig.Host, caCertFile, clientCertFile, clientKeyFile)
	if err != nil {
		return nil, err
	}
	connConfig.TLSConfig = tlsCfg
	// sslmode=prefer/allow leave a non-TLS fallback in place. Drop them.
	connConfig.Fallbacks = nil
	return connConfig, nil
}

// ConnectWithSecureTLS opens a verified-TLS connection to the store.
//
// The TLS settings are applied to the parsed connection config rather than
// through DSN parameters, because pgx only reads certificate paths from a DSN
// in some sslmode combinations. Any plaintext fallbacks pgx derived from the
// DSN's sslmode are dropped: a connection asked for over TLS must never
// silently downgrade.
//
// This is a library call in a long-running process, so an unreadable
// certificate returns an error rather than terminating it — the gateway
// starts degraded rather than not at all.
func (s Store) ConnectWithSecureTLS(dsn string, maxRetries int, backoff time.Duration, caCertFile, clientCertFile, clientKeyFile string) (*sql.DB, error) {
	connConfig, err := s.SecureConnConfig(dsn, caCertFile, clientCertFile, clientKeyFile)
	if err != nil {
		return nil, err
	}

	// Registered once: each call returns a new DSN string keyed to the config,
	// so registering inside the retry loop would leak an entry per attempt.
	secureDSN := stdlib.RegisterConnConfig(connConfig)
	return s.openWithRetry(secureDSN, maxRetries, backoff)
}

// ConnectWithRetry opens a plaintext connection to the store.
func (s Store) ConnectWithRetry(dsn string, maxRetries int, backoff time.Duration) (*sql.DB, error) {
	return s.openWithRetry(dsn, maxRetries, backoff)
}

// openWithRetry opens and pings the store, doubling the backoff after each
// failed attempt. A pool that opened but failed its ping is closed before the
// next attempt: sql.Open allocates whether or not the connection works, so
// discarding one per retry leaks a pool and its goroutines.
func (s Store) openWithRetry(dsn string, maxRetries int, backoff time.Duration) (*sql.DB, error) {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			lastErr = err
			continue
		}
		if err = db.Ping(); err == nil {
			db.SetMaxOpenConns(PoolMaxOpenConns)
			db.SetMaxIdleConns(PoolMaxIdleConns)
			db.SetConnMaxLifetime(PoolConnMaxLifetime)
			return db, nil
		}
		lastErr = err
		db.Close()
		tk.LogIt(tk.LogError, "%s Store connection attempt %d/%d failed: %v\n", s.LogTag, i+1, maxRetries, err)
	}
	return nil, s.errf("could not connect to the store after %d attempts: %w", maxRetries, lastErr)
}

// IsUniqueViolation reports whether err is PostgreSQL's unique_violation
// (SQLSTATE 23505).
//
// It replaces the MySQL error-number check the management store used to make.
// That one keyed on a driver-specific integer; this keys on the SQLSTATE the
// standard defines, so it holds for any table's unique constraint rather than
// for the one the author happened to be looking at.
func IsUniqueViolation(err error) bool {
	var pgErr *pgxconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsUnavailable reports whether err means the store could not be reached or
// the connection to it broke, as distinct from the store reaching a verdict
// the caller will not like.
//
// The distinction decides a status code. A credential the store examined and
// rejected is a 401; a credential the store never saw because there was
// nothing to ask is a 503, and answering 401 there tells a caller their token
// is wrong when nothing checked it. The retry classifier cannot make this
// call: it treats every error that is not on a short terminal list as worth
// retrying, which includes application outcomes like a duplicate username, so
// using it here would report a rejected create as a database outage.
//
// A server that answered with an SQLSTATE examined the request, so a pgconn
// PgError is deliberately NOT unavailable — including class 08, which arrives
// only once a connection existed.
func IsUnavailable(err error) bool {
	if err == nil {
		return false
	}
	// The pool gave up, or handed back a connection that had already died.
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, sql.ErrTxDone) {
		return true
	}
	// The server replied. Whatever it said, it was reachable.
	var pgErr *pgxconn.PgError
	if errors.As(err, &pgErr) {
		return false
	}
	// pgx could not establish a session at all: refused, timed out, TLS
	// refused, no route.
	var connErr *pgxconn.ConnectError
	if errors.As(err, &connErr) {
		return true
	}
	// Anything at the socket layer, including a deadline exceeded while
	// dialling.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}
