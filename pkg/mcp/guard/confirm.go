/*
 * Copyright (c) 2026 NetLOX Inc
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

package guard

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultConfirmTTL is how long an issued confirm token stays redeemable
// (docs/MCP-DESIGN.md §2.2 "Confirm-token flow").
const DefaultConfirmTTL = 120 * time.Second

// Confirm-flow errors. Redeem never reveals which pending token (if any)
// almost matched — only whether this exact (token, binding) pair is valid.
var (
	ErrConfirmUnknown  = errors.New("confirm token unknown, already used, or expired")
	ErrConfirmMismatch = errors.New("confirm token was issued for different arguments, tool, or target")
)

// Binding is the SHA-256 digest a confirm token is bound to: tool name,
// target, and the canonicalized arguments of the destructive call. Redeeming
// with any of the three changed fails (TOCTOU defense, threat T4).
type Binding [sha256.Size]byte

// BindArgs computes the binding for a destructive call. args must be the
// tool's input struct with its confirm_token field cleared; encoding/json
// marshals struct fields in declaration order, which makes the encoding
// canonical for a fixed input type.
func BindArgs(tool, target string, args any) (Binding, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return Binding{}, fmt.Errorf("canonicalize args: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(tool))
	h.Write([]byte{0})
	h.Write([]byte(target))
	h.Write([]byte{0})
	h.Write(raw)
	var b Binding
	copy(b[:], h.Sum(nil))
	return b, nil
}

// Confirmer issues and redeems single-use, TTL-bound confirm tokens.
// A nil *Confirmer disables the flow (--no-confirm): destructive tools
// execute directly.
type Confirmer struct {
	mu      sync.Mutex
	pending map[string]pendingConfirm
	ttl     time.Duration
	now     func() time.Time
}

type pendingConfirm struct {
	binding Binding
	expires time.Time
}

// NewConfirmer builds a Confirmer; ttl <= 0 uses DefaultConfirmTTL.
func NewConfirmer(ttl time.Duration) *Confirmer {
	if ttl <= 0 {
		ttl = DefaultConfirmTTL
	}
	return &Confirmer{pending: map[string]pendingConfirm{}, ttl: ttl, now: time.Now}
}

// SetClock overrides the time source (tests only).
func (c *Confirmer) SetClock(now func() time.Time) { c.now = now }

// Issue mints a new single-use token bound to the given binding.
func (c *Confirmer) Issue(b Binding) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	c.pending[token] = pendingConfirm{binding: b, expires: c.now().Add(c.ttl)}
	return token, nil
}

// Redeem consumes a token. It succeeds at most once per token, only before
// expiry, and only when the presented binding matches the one at issue time.
// The token is consumed on a binding mismatch as well: a mismatch is a
// misuse signal, and burning the token forces a fresh preview.
func (c *Confirmer) Redeem(token string, b Binding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	p, ok := c.pending[token]
	if !ok {
		return ErrConfirmUnknown
	}
	delete(c.pending, token)
	if subtle.ConstantTimeCompare(p.binding[:], b[:]) != 1 {
		return ErrConfirmMismatch
	}
	return nil
}

// Pending reports the number of unexpired outstanding tokens (metrics/tests).
func (c *Confirmer) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	return len(c.pending)
}

func (c *Confirmer) sweepLocked() {
	now := c.now()
	for tok, p := range c.pending {
		if now.After(p.expires) {
			delete(c.pending, tok)
		}
	}
}
