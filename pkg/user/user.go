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
	"context"
	"database/sql"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
	"github.com/loxilb-io/loxilb/pkg/authz"
	"github.com/loxilb-io/loxilb/pkg/pgstore"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
)

const (
	CacheExpirationTime  = 5  // 5 minutes
	CacheCleanupInterval = 10 // 10 minutes
)

// DBTX is a minimal database operations interface satisfied by *sql.DB.
// It allows UserService.DB to be replaced by a test double without
// importing an external mock library.
//
// Only the context-taking methods are on it, on purpose: every statement
// this package runs carries a deadline (pkg/pgstore budgets), and with the
// plain methods absent a new call site cannot run without one and compile.
// A store that stalls while keeping TCP open used to hold a management
// request for as long as the stall lasted, and then commit the write after
// the client had given up.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	PingContext(ctx context.Context) error
}

// opContext bounds one management operation by the operation budget and by
// the caller's context. nil is the background context.
func opContext(parent context.Context) (context.Context, context.CancelFunc) {
	return pgstore.WithBudget(parent, pgstore.OpTimeout())
}

// dbCloseGracePeriod is how long a superseded pool is left open after a
// reconnect. Closing it immediately would abort statements that are still
// running on the handle their caller was handed, turning a leak into
// "sql: database is closed" on in-flight requests; leaving it open forever is
// the leak. The window is far longer than the request budget above.
const dbCloseGracePeriod = 30 * time.Second

type UserService struct {
	// mu guards db. The handle is replaced by the reconnect tick while
	// request goroutines are reading it, so the swap needs a lock and the
	// field must not be reachable from outside the package: an exported field
	// is an unguarded reader by construction.
	mu sync.RWMutex
	db DBTX
	// closeGrace overrides dbCloseGracePeriod for this service. Zero means the
	// default; it is a field rather than a package variable so that a test
	// shortening it cannot affect anything else running alongside it.
	closeGrace time.Duration
	// tokenSink publishes management-token evictions to HA peers. Guarded by
	// mu because it is installed after construction, from a different
	// goroutine than the ones that read it.
	tokenSink TokenSink
	Cache     *cache.Cache
}

// Attach installs a database handle and retires the one it replaces.
//
// The superseded pool is closed after a grace period rather than immediately,
// because operations already in flight hold it directly (see store).
func (s *UserService) Attach(h DBTX) {
	s.mu.Lock()
	old := s.db
	s.db = h
	s.mu.Unlock()
	if old == nil || old == h {
		return
	}
	if c, ok := old.(io.Closer); ok {
		grace := s.closeGrace
		if grace <= 0 {
			grace = dbCloseGracePeriod
		}
		time.AfterFunc(grace, func() {
			if err := c.Close(); err != nil {
				tk.LogIt(tk.LogError, "Failed to close superseded database pool: %v\n", err.Error())
			}
		})
	}
}

// store returns the handle to run an operation on, or ErrDBUnavailable when
// the service is degraded.
//
// Callers must run every statement of one operation on the handle they were
// given, and must not re-read the field partway through: re-reading can
// observe a reconnect mid-operation, and — since a degraded service holds nil
// — can observe nil after a check that had already passed.
func (s *UserService) store() (DBTX, error) {
	if s == nil {
		return nil, ErrDBUnavailable
	}
	s.mu.RLock()
	h := s.db
	s.mu.RUnlock()
	if h == nil {
		return nil, ErrDBUnavailable
	}
	return h, nil
}

// Ready reports whether the management auth store currently answers: the
// pool exists (a dial has succeeded) and a liveness ping succeeds right
// now. Readiness-surface question only -- the auth chain itself keeps its
// degraded-503-and-heal behavior.
//
// The ping runs under the ping budget: a store that stalls while keeping its
// connections open is reported not ready within it.
func (s *UserService) Ready(ctx context.Context) error {
	h, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := pgstore.WithBudget(ctx, pgstore.PingTimeout())
	defer cancel()
	return pgstore.ClassifyReadErr(h.PingContext(ctx))
}

// ErrDBUnavailable is defined in common so the authentication chain can
// recognise it without depending on this package. It maps to HTTP 503.
var ErrDBUnavailable = cmn.ErrDBUnavailable

// ErrBootstrapClosed is defined in common so the REST layer can recognise it
// without depending on this package.
var ErrBootstrapClosed = cmn.ErrBootstrapClosed

// ErrUsernameExists is the answer to a create that collides with an existing
// account. The REST layer renders it as 409; the wording is matched by the
// error-classification table, so it is a sentinel here rather than a literal
// built at each call site.
var ErrUsernameExists = errors.New("username already exists")

// dbReady reports whether the backing database is usable, for callers that
// need the answer without needing the handle. Attach must only ever be given a
// non-nil handle — storing a typed-nil pointer in the interface would make
// this check pass and every query panic instead.
func (s *UserService) dbReady() error {
	_, err := s.store()
	return err
}

// NewUserService creates a new UserService instance and completes its first
// store dial in the background. The dial is retried to ride out a database
// that is still starting — a cold server accepts authenticated TCP
// connections only several seconds after it first answers pings — and against
// a store that is DOWN those retries block for over a minute. Returning only
// after they finish held the caller's whole init sequence hostage to the
// management store's availability: everything ordered after this call (other
// subsystems, and the boot snapshot restore waiting on them) inherited the
// outage, and the data plane's persisted config could be rolled back and
// quarantined because an unrelated store was unreachable.
//
// The caller therefore gets the service immediately, degraded: the handle is
// nil until the background dial lands, store-backed methods return
// ErrDBUnavailable (HTTP 503) in the meantime, and on persistent dial failure
// UserServiceTicker keeps reconnecting — the same recovery path an outage
// after a healthy start already uses. Attach publishes the handle under the
// service's lock, so the background hand-off is safe against readers.
func NewUserService() *UserService {
	svc := &UserService{
		Cache: cache.New(time.Duration(CacheExpirationTime)*time.Minute, time.Duration(CacheCleanupInterval)*time.Minute),
	}
	// Resolved here, synchronously, so the background dial never reads the
	// option globals from its own goroutine — and so an unresolvable
	// configuration (an unreadable password file) is reported at boot, not
	// from a goroutine seconds later.
	params, err := resolveMgmtDialParams()
	if err != nil {
		tk.LogIt(tk.LogCritical, "%s Store configuration unresolvable, user service degraded: %v\n",
			store.LogTag, err)
		return svc
	}
	go func() {
		userDB, err := dialWithRetry(params)
		if err != nil || userDB == nil {
			tk.LogIt(tk.LogCritical, "%s Store unavailable after %d attempts, user service degraded: %v\n",
				store.LogTag, DbMaxRetries, err)
			return
		}
		svc.Attach(userDB)
	}()
	return svc
}

// ValidateUser validates the user credentials.
// It returns the user's role if the credentials are valid, or an error if the credentials are invalid.
func (s *UserService) AddUser(ctx context.Context, user cmn.User) (int, error) {
	handle, err := s.store()
	if err != nil {
		return 0, err
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	// Refuse an unimplementable role before doing any work. The authorizer
	// denies anything outside the set at decision time, but accepting it here
	// stored an account that then had no authority at all — which reads as a
	// broken authorizer rather than a rejected role.
	if !authz.IsValidRole(user.Role) {
		return 0, cmn.ErrInvalidRole
	}
	var userID int
	err = retryWrite(ctx, func() error {
		// Policy only. The previous-password rule compares against a stored
		// row, and the only row it could find here belongs to a username that
		// already exists — which is a conflict the insert below reports
		// properly, as 409 "username already exists". Running the comparison
		// first answered 400 "password must not be the same as the previous
		// password" instead, which told the caller the wrong thing and turned
		// this endpoint into a confirmation oracle for other accounts'
		// passwords.
		if err := s.validatePasswordPolicy(user.Username, user.Password); err != nil {
			tk.LogIt(tk.LogError, "Password validation failed: %v\n", err.Error())
			return err
		}

		hashedPassword, err := hashUserPassword(user.Password)
		if err != nil {
			return err
		}

		// RETURNING rather than LastInsertId: PostgreSQL drivers do not
		// implement LastInsertId at all, and it silently returned an error
		// that this path would have reported as a failed create.
		if err := handle.QueryRowContext(ctx, InsertUserQuery,
			user.Username, hashedPassword, user.CreatedAt, user.Role).Scan(&userID); err != nil {
			if pgstore.IsUniqueViolation(err) {
				tk.LogIt(tk.LogWarning, "Duplicate username: %v\n", user.Username)
				return ErrUsernameExists
			}
			tk.LogIt(tk.LogError, "Failed to insert user: %v\n", err.Error())
			return pgstore.ClassifyWriteErr(err)
		}

		tk.LogIt(tk.LogInfo, "User created: %v\n", user.Username)
		return nil
	})
	return userID, err
}

// hashUserPassword encodes a password in the at-rest format ValidateUser
// verifies. It is shared by every write path so that a change of scheme cannot
// land in one path and leave the others producing rows nothing can verify.
func hashUserPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		tk.LogIt(tk.LogError, "Failed to hash password: %v\n", err.Error())
		return "", err
	}
	return string(hashed), nil
}

// BootstrapUser creates the very first user, and only while none exists.
//
// It exists so the management API can be brought up without a pre-shared
// credential while still refusing unauthenticated creation once an account is
// present. The caller is responsible for the loopback-peer half of the
// condition; this half — that the table is empty — is enforced here, in the
// same statement as the insert, because checking and then inserting lets two
// simultaneous requests both create an administrator.
//
// Unlike AddUser this does not retry: a closed bootstrap is a terminal answer,
// and retrying it would only delay the rejection.
func (s *UserService) BootstrapUser(ctx context.Context, user cmn.User) (int, error) {
	handle, err := s.store()
	if err != nil {
		return 0, err
	}
	ctx, cancel := opContext(ctx)
	defer cancel()

	// Refuse a closed bootstrap before doing anything else. The caller is
	// unauthenticated, so it must learn nothing beyond "no" — and the password
	// checks below query the user table by name, which on a populated table is
	// a path that reports its own failures instead of this one.
	var existing int
	if err := handle.QueryRowContext(ctx, CountUsersQuery).Scan(&existing); err != nil {
		tk.LogIt(tk.LogError, "Failed to count users: %v\n", err.Error())
		return 0, pgstore.ClassifyReadErr(err)
	}
	if existing > 0 {
		return 0, ErrBootstrapClosed
	}
	if !authz.IsValidRole(user.Role) {
		return 0, cmn.ErrInvalidRole
	}

	// Policy only: this path runs only with the table empty, so there is no
	// previous password to compare against and the query would be a wasted
	// round trip against a table the check above has already counted.
	if err := s.validatePasswordPolicy(user.Username, user.Password); err != nil {
		tk.LogIt(tk.LogError, "Password validation failed: %v\n", err.Error())
		return 0, err
	}
	hashedPassword, err := hashUserPassword(user.Password)
	if err != nil {
		return 0, err
	}

	// The count above is only a fast rejection; this insert is what makes the
	// decision, because it re-tests emptiness in the same statement.
	//
	// RETURNING makes "did it insert" and "what id" one answer: the INSERT ...
	// SELECT ... WHERE NOT EXISTS produces no row when the table is not empty,
	// so sql.ErrNoRows *is* the closed-bootstrap verdict. The MySQL version
	// had to ask RowsAffected and then LastInsertId separately, and the second
	// of those does not exist on PostgreSQL at all.
	var userID int
	err = handle.QueryRowContext(ctx, BootstrapUserQuery,
		user.Username, hashedPassword, user.CreatedAt, user.Role).Scan(&userID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// The table was not empty: either an account already existed or a
		// concurrent bootstrap won the race.
		return 0, ErrBootstrapClosed
	case pgstore.IsUniqueViolation(err):
		return 0, ErrBootstrapClosed
	case err != nil:
		tk.LogIt(tk.LogError, "Failed to bootstrap user: %v\n", err.Error())
		return 0, pgstore.ClassifyWriteErr(err)
	}

	// Logged loudly: this is the one credential in the system that was created
	// without presenting a credential, and it must be visible when auditing how
	// an account came to exist.
	tk.LogIt(tk.LogCritical, "Bootstrap: first user %q created with role %q from a loopback peer\n",
		user.Username, user.Role)
	return userID, nil
}

// GetUsers returns all users from the database.
func (s *UserService) GetUsers(ctx context.Context) ([]cmn.User, error) {
	handle, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	var users []cmn.User
	err = RetryOperation(ctx, func() error {
		// The password column is not selected at all. Not selected, rather
		// than selected-and-dropped: a value that is never read cannot be
		// forwarded by a later edit to whatever renders this list.
		rows, err := handle.QueryContext(ctx, SelectAllUsersQuery)
		if err != nil {
			tk.LogIt(tk.LogError, "Failed to fetch users: %v\n", err.Error())
			return pgstore.ClassifyReadErr(err)
		}
		defer rows.Close()
		users = users[:0]
		for rows.Next() {
			var user cmn.User
			// created_at is scanned as time.Time, which is what the column
			// is. Scanning it as a string and re-parsing it with a layout
			// picked by hand is what made this endpoint fail for every
			// database that returned a different one — the driver had already
			// done the parsing correctly.
			var delegation bool
			if err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt, &user.Role, &delegation); err != nil {
				tk.LogIt(tk.LogError, "Failed to scan user: %v\n", err.Error())
				return pgstore.ClassifyReadErr(err)
			}
			user.DelegationAllowed = &delegation
			users = append(users, user)
		}

		if err = rows.Err(); err != nil {
			tk.LogIt(tk.LogError, "Rows error: %v\n", err.Error())
			return pgstore.ClassifyReadErr(err)
		}

		return nil
	}, AuthMaxRetries, AuthRetryDelay, retryableDBError)
	return users, err
}

// DelegationAllowed reports whether the account may delegate. An account
// that does not exist may not; a store that cannot answer returns the
// error so the caller can count it, and treats the answer as no. There is
// no retry: the question is asked on the request path, once, and a slow
// answer would hold a management call for a flag that only ever narrows
// what the record claims.
func (s *UserService) DelegationAllowed(ctx context.Context, username string) (bool, error) {
	handle, err := s.store()
	if err != nil {
		return false, err
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	var allowed bool
	if err := handle.QueryRowContext(ctx, SelectUserDelegationQuery, username).Scan(&allowed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, pgstore.ClassifyReadErr(err)
	}
	return allowed, nil
}

// DeleteUser deletes a user and every session they hold.
//
// The two are one operation. Deleting the row alone left the user's tokens
// valid until they expired, so a removed administrator kept administering for
// up to twenty-four hours.
func (s *UserService) DeleteUser(ctx context.Context, id int) error {
	handle, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	return retryWrite(ctx, func() error {
		var username string
		if err := handle.QueryRowContext(ctx, SelectUsernameByIDQuery, id).Scan(&username); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// Nothing to delete and nothing to revoke. Reported as the
				// same "no such user" the REST layer maps to 404.
				return ErrUserNotFound
			}
			tk.LogIt(tk.LogError, "Failed to read the user being deleted: %v\n", err.Error())
			return pgstore.ClassifyReadErr(err)
		}
		return s.revokeSessions(ctx, handle, username, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, DeleteUserQuery, id); err != nil {
				tk.LogIt(tk.LogError, "Failed to delete user: %v\n", err.Error())
				return pgstore.ClassifyWriteErr(err)
			}
			return nil
		})
	})
}

// UpdateUser updates a user in the database.
func (s *UserService) UpdateUser(ctx context.Context, user cmn.User) error {
	handle, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	return retryWrite(ctx, func() error {
		// Check if the user exists
		var existingUser cmn.User
		query := SelectUserQuery
		err := handle.QueryRowContext(ctx, query, user.ID).Scan(&existingUser.ID, &existingUser.Username, &existingUser.Password, &existingUser.Role)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				tk.LogIt(tk.LogError, "User not found: %s\n", err.Error())
				return ErrUserNotFound
			}
			tk.LogIt(tk.LogError, "Failed to query user: %s\n", err.Error())
			return pgstore.ClassifyReadErr(err)
		}

		// Validate the new password
		if err := s.validatePassword(ctx, user.Username, user.Password); err != nil {
			tk.LogIt(tk.LogError, "Password validation failed: %v\n", err.Error())
			return err
		}

		// Hash through the same helper every other writer uses. Calling
		// bcrypt directly here is how this path came to store a format
		// ValidateUser could not read.
		hashedPassword, err := hashUserPassword(user.Password)
		if err != nil {
			return err
		}

		// Role is optional on an update; an empty one keeps what is stored.
		// A non-empty one has to be a role that exists.
		if user.Role == "" {
			user.Role = existingUser.Role
		} else if !authz.IsValidRole(user.Role) {
			return cmn.ErrInvalidRole
		}

		// A password change or a role change both invalidate every session
		// the account holds: the old password must stop working, and a token
		// row carries the role it was issued with, so a demoted user whose
		// sessions survived would keep the authority they were demoted out
		// of — in this process's cache and in every peer's.
		if err := s.revokeSessions(ctx, handle, existingUser.Username, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, UpdateUserQuery, user.Username, hashedPassword, user.Role, user.ID, user.DelegationAllowed); err != nil {
				tk.LogIt(tk.LogError, "Failed to update user: %v\n", err.Error())
				return pgstore.ClassifyWriteErr(err)
			}
			return nil
		}); err != nil {
			return err
		}

		tk.LogIt(tk.LogInfo, "User updated successfully: %v\n", user.Username)
		return nil
	})
}

func (s *UserService) Login(ctx context.Context, username, password string) (string, bool, error) {
	if err := s.dbReady(); err != nil {
		return "", false, err
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	// User check
	role, vaild, err := s.ValidateUser(ctx, username, password)
	if err != nil {
		return "", false, err
	}
	// Gen Token
	if vaild {
		token, err := GenerateToken(username, role, TokenExpirationMinutes)
		if err != nil {
			return "", false, err
		}
		// Persist first, publish second. Caching before the insert meant a
		// login that failed — and was reported to the caller as failed —
		// still left a token in the validation cache, where it authenticated
		// for the full TTL against a row that was never written. The cache is
		// a read-through of the store, so it must not hold what the store
		// refused.
		if err := s.saveToken(ctx, username, token, role); err != nil {
			tk.LogIt(tk.LogWarning, "Save fail : %v \n", err.Error())
			return "", false, err
		}
		combined := username + "|" + role
		s.Cache.Set(hashToken(token), combined, time.Duration(CacheExpirationTime)*time.Minute)
		// return result
		return token, true, nil // Valid login

	}
	return "", false, nil // Invalid Login
}

// Logout deletes the token from the cache and the database.
func (s *UserService) Logout(ctx context.Context, tokenString string) error {
	// The API server starts before the user service finishes initialising, so
	// this can be called on a nil receiver during startup.
	if s == nil {
		return ErrDBUnavailable
	}
	// Cache and database are both keyed by the hash, never by the token.
	hashed := hashToken(tokenString)

	// Recover username from cache before deletion (for safe logging)
	var username string
	if val, found := s.Cache.Get(hashed); found {
		if combined, ok := val.(string); ok {
			if parts := strings.SplitN(combined, "|", 2); len(parts) == 2 {
				username = parts[0]
			}
		}
	}

	// Evict before the delete, and evict even if the store is unreachable:
	// the cache is what this process will answer from, so dropping it first
	// is the fail-closed order.
	s.Cache.Delete(hashed)

	handle, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := opContext(ctx)
	defer cancel()
	return retryWrite(ctx, func() error {
		_, err := handle.ExecContext(ctx, DeleteTokenQuery, hashed)
		if err != nil {
			tk.LogIt(tk.LogError, "Failed to delete token: %v\n", err.Error())
			return pgstore.ClassifyWriteErr(err)
		}

		tk.LogIt(tk.LogInfo, "User logged out: %v\n", username)
		return nil
	})
}

// UserServiceTicker is a periodic function that runs every 10 seconds.
func (s *UserService) UserServiceTicker() {
	handle, err := s.store()
	if err != nil {
		tk.LogIt(tk.LogCritical, "Database connection is nil\n")
		if err := s.reconnectDB(); err != nil {
			return
		}
		if handle, err = s.store(); err != nil {
			return
		}
	}
	pingCtx, cancel := pgstore.WithBudget(context.Background(), pgstore.PingTimeout())
	err = handle.PingContext(pingCtx)
	cancel()
	if err != nil {
		tk.LogIt(tk.LogError, "Failed to ping database: %v\n", err.Error())
		if err := s.reconnectDB(); err != nil {
			return
		}
	}

	// Expired Token Cleanup
	s.cleanupExpiredTokens()
}

// reconnectDB re-establishes the database connection. InitDB is used rather
// than a bare reconnect so that a service that started degraded (database down
// at boot, tables never created) becomes fully functional on heal — the
// CREATE TABLE IF NOT EXISTS statements are no-ops on an intact schema.
func (s *UserService) reconnectDB() error {
	params, err := resolveMgmtDialParams()
	if err != nil {
		tk.LogIt(tk.LogCritical, "Failed to reconnect to the database: %v\n", err)
		return err
	}
	tempDB, err := connectStore(params)
	if err != nil || tempDB == nil {
		tk.LogIt(tk.LogCritical, "Failed to reconnect to the database: %v\n", err)
		if err == nil {
			err = ErrDBUnavailable
		}
		return err
	}
	// Attach retires the superseded pool. Before this, every failed ping
	// replaced the handle and dropped the previous one on the floor, so a
	// database that was down leaked a pool and its goroutine on every tick.
	s.Attach(tempDB)
	tk.LogIt(tk.LogInfo, "Reconnected to the database\n")
	return nil
}

// cleanupExpiredTokens removes tokens with expired 'expires_at' values
func (s *UserService) cleanupExpiredTokens() {
	handle, err := s.store()
	if err != nil {
		return
	}
	query := DeleteExpiredTokenQuery

	ctx, cancel := opContext(context.Background())
	defer cancel()
	result, err := handle.ExecContext(ctx, query)
	if err != nil {
		tk.LogIt(tk.LogInfo, "Failed to delete expired tokens: %v\n", err)
		return
	}

	// Log the number of deleted rows
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		tk.LogIt(tk.LogInfo, "Failed to retrieve rows affected: %v\n", err)
		return
	}

	tk.LogIt(tk.LogInfo, "Deleted %d expired tokens\n", rowsAffected)
}
