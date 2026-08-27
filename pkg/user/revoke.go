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
	"errors"
	"fmt"

	tk "github.com/loxilb-io/loxilib"
)

// TokenSink receives management-token evictions so they can be published to
// HA peers.
//
// The management plane cannot import the XSync machinery — that lives in
// pkg/loxinet, which imports this package — so the fan-out arrives as a
// function the constructor installs. The same shape the key store uses for
// its own invalidations, and the reason the XSync message carries a plane
// discriminator: one channel, two kinds of credential, and neither side may
// evict the other's cache entries.
type TokenSink func(tokenHashes []string)

// SetTokenSink installs the peer-eviction fan-out. Nil disables it, which is
// the correct state for a single gateway.
func (s *UserService) SetTokenSink(sink TokenSink) {
	s.mu.Lock()
	s.tokenSink = sink
	s.mu.Unlock()
}

func (s *UserService) publishEviction(hashes []string) {
	if len(hashes) == 0 {
		return
	}
	s.mu.RLock()
	sink := s.tokenSink
	s.mu.RUnlock()
	if sink != nil {
		sink(hashes)
	}
}

// tokenHashesFor reads every token hash belonging to username, inside tx.
//
// Read inside the transaction that will delete them, so a token issued
// concurrently is either already visible here or blocked behind this
// transaction — never deleted without also being evicted from the peers'
// caches, where it would keep working for the rest of its cached life.
func tokenHashesFor(tx *sql.Tx, username string) ([]string, error) {
	rows, err := tx.Query(SelectTokenHashesForUserQuery, username)
	if err != nil {
		return nil, fmt.Errorf("mgmt: cannot read tokens for %q: %w", username, err)
	}
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return nil, fmt.Errorf("mgmt: cannot read a token row for %q: %w", username, err)
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	return hashes, nil
}

// evictLocal drops the given token hashes from this process's cache.
func (s *UserService) evictLocal(hashes []string) {
	for _, h := range hashes {
		s.Cache.Delete(h)
	}
}

// revokeSessions removes every session belonging to username — from the
// store, from this process's cache, and from its peers'.
//
// It exists because deleting a user, or reducing their authority, used to
// leave their tokens working. The row went away and the sessions did not: the
// token table held no reference to the user, nothing deleted it, and the
// caches held the decision for up to their TTL. So a deleted administrator
// kept administering for up to twenty-four hours, and a demoted one kept the
// authority they had been demoted out of.
//
// Store, local cache and peers are updated in that order, and the peers are
// told only after the transaction commits: publishing an eviction for a
// deletion that then rolled back would have peers drop live sessions.
func (s *UserService) revokeSessions(handle DBTX, username string, within func(*sql.Tx) error) error {
	beginner, ok := handle.(txBeginner)
	if !ok {
		return errors.New("mgmt: store handle does not support transactions")
	}
	tx, err := beginner.Begin()
	if err != nil {
		return fmt.Errorf("mgmt: cannot begin a revocation transaction: %w", err)
	}
	defer tx.Rollback()

	// Read the hashes BEFORE running the caller's statement.
	//
	// token.username REFERENCES users(username) ON DELETE CASCADE, so deleting
	// the user takes the token rows with it. Reading afterwards found an empty
	// set and published nothing — the store was correct and the peers were
	// never told, which is the half of the defect that matters, because their
	// caches are what keeps a revoked session alive. The FK is the backstop
	// for paths that forget to revoke; it must not be allowed to erase the
	// evidence the revocation path needs.
	hashes, err := tokenHashesFor(tx, username)
	if err != nil {
		return err
	}
	if within != nil {
		if err := within(tx); err != nil {
			return err
		}
	}
	// Explicit delete as well as the cascade: a role change updates the user
	// rather than deleting it, so nothing cascades, and the sessions carrying
	// the old role have to go. Harmless when the cascade already ran.
	if _, err := tx.Exec(DeleteTokensForUserQuery, username); err != nil {
		return fmt.Errorf("mgmt: cannot revoke tokens for %q: %w", username, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("mgmt: cannot commit the revocation: %w", err)
	}

	s.evictLocal(hashes)
	s.publishEviction(hashes)
	if len(hashes) > 0 {
		tk.LogIt(tk.LogInfo, "%s Revoked %d session(s) for %q\n", store.LogTag, len(hashes), username)
	}
	return nil
}

// txBeginner is the part of *sql.DB the revocation path needs. Kept separate
// from DBTX so a test double that has no use for transactions is not forced
// to implement one.
type txBeginner interface {
	Begin() (*sql.Tx, error)
}

// ApplyTokenInvalidation evicts one management token from this process's
// cache, on notice from a peer.
//
// The receiving side evicts and does not fan out again: peers form a mesh, not
// a tree, so re-broadcasting what a peer just told us would circulate for as
// long as the entries live.
//
// tokenHash is sha256(token), the same value the cache is keyed by — so this
// needs no access to the token and none is available.
func (s *UserService) ApplyTokenInvalidation(tokenHash string) {
	if s == nil || s.Cache == nil || tokenHash == "" {
		return
	}
	s.Cache.Delete(tokenHash)
}
