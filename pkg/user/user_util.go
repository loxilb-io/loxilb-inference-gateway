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
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrTokenExpired = errors.New("token is expired")
	ErrInvalidToken = errors.New("invalid token")
)

// enumerationDecoyHash is a well-formed bcrypt hash at the same cost as a
// real one, used to make the "no such user" path pay what the "wrong
// password" path pays. Computed once at start-up rather than written down, so
// there is no fixed string in the binary that a stored value could ever equal.
var enumerationDecoyHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("decoy-for-constant-cost-verification"), bcrypt.DefaultCost)
	if err != nil {
		// Cannot happen for a fixed input at a valid cost; if it somehow
		// does, an empty hash still makes CompareHashAndPassword do its
		// parsing work and simply returns an error the caller discards.
		return nil
	}
	return h
}()

// TokenBytes is the entropy in a management session token. 256 bits, so the
// token is unguessable on its own terms rather than because something signs
// it.
const TokenBytes = 32

// The JWT this replaces was a costume. It was signed with a key hard-coded in
// the source, and no code path ever verified the signature — every check went
// to the database anyway, so the token was a database handle wearing claims
// that anyone could rewrite. An opaque random string says what it is: a
// bearer credential whose only meaning is the row it matches.
//
// generateToken returns the raw token, which is shown to its owner once and
// never written down. What is stored, in the database and in the cache, is
// hashToken(raw).
func generateToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mgmt: cannot generate a session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hashToken maps a raw token to what is stored for it.
//
// SHA-256 without a salt, deliberately: this is a 256-bit random value, not a
// password, so there is no dictionary to defend against and the lookup has to
// be a single indexed equality. Read access to the token table now yields
// hashes, not the 24-hour bearer credentials it used to hand out.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ErrUserNotFound is the terminal answer to "is there a row for this name".
// It is a sentinel rather than a fresh errors.New so that RetryOperation can
// recognise it: a closure that translated sql.ErrNoRows into a new error value
// destroyed the only evidence that the failure was terminal, and the retry
// wrapper then spent the full budget re-asking a question whose answer cannot
// change.
var ErrUserNotFound = errors.New("User not found")

// retryable reports whether an operation is worth repeating.
//
// The default policy for the store: repeat transport and availability
// failures, never repeat an answer. "No such row" and "this credential is
// wrong" are answers — they are as true on the fifth attempt as on the first,
// and retrying them turns a cheap negative into an expensive one. A login with
// an unknown username used to cost five attempts and five sleeps.
func retryableDBError(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, sql.ErrNoRows),
		errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrInvalidToken),
		errors.Is(err, ErrTokenExpired),
		errors.Is(err, cmn.ErrTokenNotFound),
		errors.Is(err, ErrBootstrapClosed):
		return false
	}
	return true
}

// RetryOperation retries operation until it succeeds, until retryable says the
// error is terminal, or until the attempt budget is spent.
//
// retryDelay doubles between attempts, and no sleep follows the final one:
// sleeping after the last attempt bought nothing and was pure added latency on
// every failure — with the old 5 x 2 s profile it was five sleeps for five
// attempts, which is exactly the ten seconds a failing password change spent
// before answering.
func RetryOperation(operation func() error, maxRetries int, retryDelay time.Duration, retryable func(error) bool) error {
	if retryable == nil {
		retryable = retryableDBError
	}
	var err error
	delay := retryDelay
	for i := 0; i < maxRetries; i++ {
		err = operation()
		if err == nil {
			return nil
		}
		if !retryable(err) {
			return err
		}
		if i == maxRetries-1 {
			break
		}
		time.Sleep(delay)
		delay *= AuthRetryBackoff
	}
	return err
}

// UserService provides user-related operations such as user validation and token generation.
func (s *UserService) ValidateUser(username, password string) (string, bool, error) {
	handle, err := s.store()
	if err != nil {
		return "", false, err
	}
	var storedHash string
	var role string
	// Query the database for the stored password hash.
	err = RetryOperation(func() error {
		err := handle.QueryRow(SelectUserPasswordQuery, username).Scan(&storedHash, &role)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				tk.LogIt(tk.LogWarning, "User not found: %v\n", username)
				return ErrUserNotFound
			}
			tk.LogIt(tk.LogError, "Failed to query user: %v\n", err.Error())
			return err
		}
		return nil
	}, AuthMaxRetries, AuthRetryDelay, retryableDBError)

	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Do the verification anyway, against a fixed hash of the same
			// cost. Returning here made "no such user" measurably cheaper
			// than "wrong password", so an unauthenticated caller could
			// enumerate accounts with a stopwatch — and bcrypt at the
			// default cost makes that difference tens of milliseconds, not
			// microseconds. The result is discarded; only the time it took
			// matters.
			_ = bcrypt.CompareHashAndPassword(enumerationDecoyHash, []byte(password))
			return "", false, nil
		}
		return "", false, err
	}

	// One scheme, everywhere. bcrypt carries its own salt and cost inside the
	// encoded string, so a stored value is self-describing and there is no
	// second format for another writer to disagree about. The pbkdf2 path this
	// replaces read the column as base64 of salt||hash and sliced [:16] — a
	// panic on any shorter value, and unable to read what UpdateUser had
	// already been writing, which made a successful password change into a
	// permanent lockout with no route back through the API.
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			tk.LogIt(tk.LogWarning, "Invalid password for user: %v\n", username)
			return "", false, nil
		}
		// A stored value bcrypt cannot parse is a broken row, not a wrong
		// password. Say so in the log, where an operator can act on it, and
		// give the caller the same refusal as any other bad credential — the
		// alternative disclosed the decoder's own words to an unauthenticated
		// caller on /auth/login.
		tk.LogIt(tk.LogError, "Stored password for %v is unreadable: %v\n", username, err.Error())
		return "", false, nil
	}

	tk.LogIt(tk.LogInfo, "User validated successfully: %v\n", username)
	return role, true, nil
}

// Validate the password against the following rules:
//   - Must be at least MinPasswordLength characters long
//   - Must contain at least one uppercase letter
//   - Must contain at least one lowercase letter
//   - Must contain at least one number
//   - Must contain at least one special character
//   - Must not contain the same character more than twice in a row
//   - Must not be the same as the username
//   - Must not be the same as the previous password
//
// This list previously carried a ninth rule, "must not contain consecutive
// characters", that nothing implemented. A documented policy the code does
// not enforce is a false claim to whoever reads it, so the two are reconciled
// here — by deleting the claim rather than by inventing an implementation of
// it. "Consecutive characters" was never specified: read literally it rejects
// any password containing "ab", which is unusable, and every workable reading
// (runs of three? four? wrap-around? keyboard-adjacent?) is a different
// policy. Choosing one here would be writing new policy under the heading of
// fixing a mismatch, and it would silently reject credentials that are valid
// today. If the product wants a sequence rule it needs a specified one, and
// then this function and this list change together.
func (s *UserService) validatePassword(username, password string) error {
	if len(password) < MinPasswordLength {
		err := errors.New("password must be at least 9 characters long")
		tk.LogIt(tk.LogError, "%v\n", err.Error())
		return err
	}

	if password == username {
		err := errors.New("password must not be the same as the username")
		tk.LogIt(tk.LogError, "%v\n", err.Error())
		return err
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	var prevChar rune
	var repeatCount int

	for i, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}

		if i > 0 {
			if char == prevChar {
				repeatCount++
				if repeatCount >= 2 {
					err := errors.New("password must not contain the same character more than twice in a row")
					tk.LogIt(tk.LogError, "%v\n", err.Error())
					return err
				}
			} else {
				repeatCount = 0
			}
		}

		prevChar = char
	}

	if !hasUpper {
		err := errors.New("password must contain at least one uppercase letter")
		tk.LogIt(tk.LogError, "%v\n", err.Error())
		return err
	}
	if !hasLower {
		err := errors.New("password must contain at least one lowercase letter")
		tk.LogIt(tk.LogError, "%v\n", err.Error())
		return err
	}
	if !hasNumber {
		err := errors.New("password must contain at least one number")
		tk.LogIt(tk.LogError, "%v\n", err.Error())
		return err
	}
	if !hasSpecial {
		err := errors.New("password must contain at least one special character")
		tk.LogIt(tk.LogError, "%v\n", err.Error())
		return err
	}

	// Reject reuse of the previous password.
	handle, err := s.store()
	if err != nil {
		return err
	}
	var previousPassword string
	query := SelectUserPasswordOnlyQuery
	err = handle.QueryRow(query, username).Scan(&previousPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No previous password found, continue with validation
			tk.LogIt(tk.LogInfo, "No previous password found for username: %v\n", username)
		} else {
			tk.LogIt(tk.LogError, "Failed to query previous password: %v\n", err.Error())
			return err
		}
	} else {
		err = bcrypt.CompareHashAndPassword([]byte(previousPassword), []byte(password))
		if err == nil {
			err := errors.New("password must not be the same as the previous password")
			tk.LogIt(tk.LogError, "%v\n", err.Error())
			return err
		}
	}

	tk.LogIt(tk.LogInfo, "Password validated successfully")

	return nil
}

// Public wrapper function
func (s *UserService) ValidatePassword(username, password string) error {
	return s.validatePassword(username, password)
}

// ValidateToken validates a token using the in-memory cache and the database as a fallback.
func (s *UserService) ValidateToken(token string) (interface{}, error) {
	// The API server starts before the user service finishes initialising, so
	// this can be called on a nil receiver during startup.
	if s == nil {
		return nil, ErrDBUnavailable
	}
	// The cache is keyed by the same hash the database is, so a memory dump
	// of this process yields no more usable credentials than a dump of the
	// table does.
	hashed := hashToken(token)
	if caches, found := s.Cache.Get(hashed); found {
		return caches, nil
	}

	// If not found in cache, check the database
	handle, err := s.store()
	if err != nil {
		return nil, err
	}
	var username string
	var role string
	var expiresAt time.Time
	err = RetryOperation(func() error {
		err := handle.QueryRow(ValidateTokenQuery, hashed).Scan(&username, &role, &expiresAt)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				tk.LogIt(tk.LogError, "Token not found\n")
				return cmn.ErrTokenNotFound
			}
			tk.LogIt(tk.LogError, "Failed to query token: %v\n", err.Error())
			return err // Other errors
		}
		return nil
	}, AuthMaxRetries, AuthRetryDelay, retryableDBError)

	if err != nil {
		return nil, err
	}

	combined := username + "|" + role
	s.Cache.Set(hashed, combined, cacheTTLFor(expiresAt))
	return combined, nil
}

// cacheTTLFor bounds a cache entry by the token's real remaining life.
//
// The flat five minutes this replaces ignored expires_at entirely, so a token
// read one second before it expired stayed honoured for five minutes after —
// the cache outliving the credential it was caching. Never longer than the
// token has left, and never longer than the cache's own ceiling.
func cacheTTLFor(expiresAt time.Time) time.Duration {
	remaining := time.Until(expiresAt)
	ceiling := time.Duration(CacheExpirationTime) * time.Minute
	if remaining < ceiling {
		return remaining
	}
	return ceiling
}

// GenerateToken returns a new opaque management session token.
//
// The username, role and expiry are no longer carried inside the token: they
// live in the row the token's hash matches, which is the only place that was
// ever consulted. A token that carries no claims cannot carry a forged one.
func GenerateToken(username, role string, expirationMinutes int) (string, error) {
	return generateToken()
}

func (s *UserService) saveToken(username, token, role string) error {
	handle, err := s.store()
	if err != nil {
		return err
	}
	expirationTime := time.Now().Add(time.Duration(TokenExpirationMinutes) * time.Minute)
	_, err = handle.Exec(InsertTokenQuery, hashToken(token), username, expirationTime, role)
	return err
}
