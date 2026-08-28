/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * SPDX (GPL-2.0 OR BSD-3-Clause)
 */

package pgstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	pgxconn "github.com/jackc/pgx/v5/pgconn"
)

// IsUnavailable decides a status code, so its contract is worth pinning
// directly: "the store never answered" must be separable from "the store
// answered and the answer was no". The wire probes exercise the first half
// only — they stop the container — so the half that matters most for not
// regressing, a server that replied with an SQLSTATE, has no coverage there.
func TestIsUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},

		// Reached the server; it reached a verdict.
		{"unique violation", &pgxconn.PgError{Code: "23505"}, false},
		{"undefined table", &pgxconn.PgError{Code: "42P01"}, false},
		// Class 08 only arrives once a connection existed, so it is still an
		// answer from the server rather than a failure to reach one.
		{"connection exception SQLSTATE", &pgxconn.PgError{Code: "08006"}, false},
		{"wrapped PgError", fmt.Errorf("insert: %w", &pgxconn.PgError{Code: "23505"}), false},

		// Application outcomes must never be mistaken for an outage: these are
		// the ones RetryOperation's `retryable` test would have swept up.
		{"no rows", sql.ErrNoRows, false},
		{"plain error", errors.New("username already exists"), false},

		// Never reached the server.
		{"bad conn", driver.ErrBadConn, true},
		{"conn done", sql.ErrConnDone, true},
		{"dial refused", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"wrapped dial failure", fmt.Errorf("connect: %w",
			&net.OpError{Op: "dial", Err: errors.New("connection refused")}), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsUnavailable(tc.err); got != tc.want {
				t.Errorf("IsUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
