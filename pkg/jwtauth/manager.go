/*
 * Copyright (c) 2026 LoxiLB Authors
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

package jwtauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

// Lifecycle defaults. Tests override them through Options; production keeps
// them.
const (
	defaultMaxStaleness  = 24 * time.Hour
	defaultMinRefetchGap = 10 * time.Second
	defaultBackoffBase   = 1 * time.Second
	defaultBackoffCap    = 60 * time.Second
	defaultFetchTimeout  = 10 * time.Second

	// maxJWKSBytes bounds a JWKS (or discovery) response body. A realm's
	// keyset is a few KB; a megabyte already means something is wrong on
	// the other end, and an unbounded read is a memory hole.
	maxJWKSBytes = 1 << 20
)

// Manager owns the active profiles and their background JWKS lifecycles,
// and answers Verify calls from the request path off in-memory snapshots.
type Manager struct {
	mu       sync.Mutex
	profiles map[string]*profileState
	closed   bool

	httpClient    *http.Client
	now           func() time.Time
	maxStaleness  time.Duration
	minRefetchGap time.Duration
	backoffBase   time.Duration
	backoffCap    time.Duration
	fetchTimeout  time.Duration
}

// Option configures a Manager.
type Option func(*Manager)

// WithHTTPClient overrides the JWKS-fetching client (tests, custom TLS).
func WithHTTPClient(c *http.Client) Option { return func(m *Manager) { m.httpClient = c } }

// WithClock overrides the time source used for staleness and refetch
// rate-limit decisions (never for goroutine sleeps).
func WithClock(now func() time.Time) Option { return func(m *Manager) { m.now = now } }

// WithMaxStaleness overrides how long a last-known-good keyset stays
// trusted after refreshes start failing.
func WithMaxStaleness(d time.Duration) Option { return func(m *Manager) { m.maxStaleness = d } }

// WithMinRefetchGap overrides the minimum spacing between kid-miss
// triggered refetches of one profile.
func WithMinRefetchGap(d time.Duration) Option { return func(m *Manager) { m.minRefetchGap = d } }

// WithRetryBackoff overrides the initial-fetch retry backoff (base, cap).
func WithRetryBackoff(base, ceiling time.Duration) Option {
	return func(m *Manager) { m.backoffBase, m.backoffCap = base, ceiling }
}

// New builds a Manager. It starts no goroutines until a profile is set.
func New(opts ...Option) *Manager {
	m := &Manager{
		profiles:      make(map[string]*profileState),
		httpClient:    &http.Client{Timeout: defaultFetchTimeout},
		now:           time.Now,
		maxStaleness:  defaultMaxStaleness,
		minRefetchGap: defaultMinRefetchGap,
		backoffBase:   defaultBackoffBase,
		backoffCap:    defaultBackoffCap,
		fetchTimeout:  defaultFetchTimeout,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// profileState is one active profile plus its keyset lifecycle.
type profileState struct {
	prof Profile // normalized, immutable

	// snap is the request path's only read. nil until the first successful
	// fetch — the profile answers 503-class until then (fail closed).
	snap atomic.Pointer[keySnapshot]

	// jwksURL caches the resolved (possibly OIDC-discovered) endpoint.
	jwksURL atomic.Pointer[string]

	// refetchCh carries kid-miss refetch requests to the lifecycle
	// goroutine. Capacity 1: at most one request queues while a fetch is
	// in flight; extras are dropped, which is exactly the thundering-herd
	// behavior wanted on key rotation.
	refetchCh chan struct{}
	stopCh    chan struct{}

	mu          sync.Mutex
	lastRefetch time.Time // last kid-miss refetch accepted (rate-limit anchor)
}

// keySnapshot is an immutable keyset with its fetch time; staleness is
// judged against fetchedAt at verify time.
type keySnapshot struct {
	set       *keySet
	fetchedAt time.Time
}

// KeysetStatus reports one profile's lifecycle state for observability.
type KeysetStatus struct {
	// Keys is the number of usable verification keys in the snapshot.
	Keys int
	// LastSuccess is the time of the last successful JWKS fetch; zero when
	// none has succeeded yet.
	LastSuccess time.Time
	// Usable is true when the request path would accept the snapshot
	// (fetched at least once and inside the staleness cutoff).
	Usable bool
}

// SetProfile validates, normalizes, and activates a profile. An unchanged
// re-set is a no-op (the running keyset survives); any change restarts the
// lifecycle from scratch — the profile answers 503-class until the first
// fetch against the new configuration succeeds, which is the correct
// posture when the issuer or key source just changed.
func (m *Manager) SetProfile(p Profile) error {
	p = p.normalize()
	if err := p.validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("jwtauth: manager is closed")
	}
	if old, ok := m.profiles[p.Name]; ok {
		if reflect.DeepEqual(old.prof, p) {
			return nil
		}
		close(old.stopCh)
	}
	if len(p.Audiences) == 0 {
		tk.LogIt(tk.LogWarning, "[JWTAuth] profile %s: no audiences configured — audience check disabled\n", p.Name)
	}
	ps := &profileState{
		prof:      p,
		refetchCh: make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
	}
	m.profiles[p.Name] = ps
	go m.runProfile(ps)
	tk.LogIt(tk.LogInfo, "[JWTAuth] profile %s activated (issuer %s)\n", p.Name, p.Issuer)
	return nil
}

// RemoveProfile deactivates a profile. Verifies against it answer
// 503-class afterwards. Rule-reference validation belongs to the config
// layer, not here.
func (m *Manager) RemoveProfile(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ps, ok := m.profiles[name]; ok {
		close(ps.stopCh)
		delete(m.profiles, name)
		tk.LogIt(tk.LogInfo, "[JWTAuth] profile %s removed\n", name)
	}
}

// Profiles returns the names of the active profiles.
func (m *Manager) Profiles() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.profiles))
	for name := range m.profiles {
		out = append(out, name)
	}
	return out
}

// Status reports a profile's keyset lifecycle state; ok is false when the
// profile does not exist.
func (m *Manager) Status(name string) (st KeysetStatus, ok bool) {
	ps := m.profile(name)
	if ps == nil {
		return KeysetStatus{}, false
	}
	snap := ps.snap.Load()
	if snap == nil {
		return KeysetStatus{}, true
	}
	return KeysetStatus{
		Keys:        len(snap.set.keys),
		LastSuccess: snap.fetchedAt,
		Usable:      m.now().Sub(snap.fetchedAt) <= m.maxStaleness,
	}, true
}

// Close stops every profile lifecycle. The Manager cannot be reused.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	for _, ps := range m.profiles {
		close(ps.stopCh)
	}
	m.profiles = make(map[string]*profileState)
}

func (m *Manager) profile(name string) *profileState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.profiles[name]
}

// runProfile is one profile's lifecycle goroutine: initial fetch with
// backoff (the profile is unusable until it succeeds), then periodic
// refresh plus rate-limited kid-miss refetches. Refresh failures keep the
// last-known-good snapshot; the staleness cutoff is enforced on the read
// side so a wedged refresh loop cannot keep stale keys trusted forever.
func (m *Manager) runProfile(ps *profileState) {
	backoff := m.backoffBase
	for {
		err := m.fetchOnce(ps)
		if err == nil {
			break
		}
		tk.LogIt(tk.LogError, "[JWTAuth] profile %s: JWKS fetch failed (retry in %v): %v\n",
			ps.prof.Name, backoff, err)
		select {
		case <-ps.stopCh:
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > m.backoffCap {
			backoff = m.backoffCap
		}
	}

	interval := time.Duration(ps.prof.RefreshSec) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ps.stopCh:
			return
		case <-ticker.C:
		case <-ps.refetchCh:
		}
		if err := m.fetchOnce(ps); err != nil {
			tk.LogIt(tk.LogError, "[JWTAuth] profile %s: JWKS refresh failed, keeping last-known-good keyset: %v\n",
				ps.prof.Name, err)
		}
	}
}

// requestRefetch asks the lifecycle goroutine for an out-of-cycle JWKS
// fetch after a kid miss. It never blocks the request path: outside the
// rate limit, or with a request already queued, it is a no-op.
func (m *Manager) requestRefetch(ps *profileState) {
	now := m.now()
	ps.mu.Lock()
	if now.Sub(ps.lastRefetch) < m.minRefetchGap {
		ps.mu.Unlock()
		return
	}
	ps.lastRefetch = now
	ps.mu.Unlock()
	select {
	case ps.refetchCh <- struct{}{}:
	default:
	}
}

// fetchOnce resolves the JWKS URL (through OIDC discovery when the profile
// does not pin one) and swaps in a fresh snapshot on success.
func (m *Manager) fetchOnce(ps *profileState) error {
	jwksURL, err := m.resolveJWKSURL(ps)
	if err != nil {
		return err
	}
	body, err := m.httpGet(jwksURL)
	if err != nil {
		return err
	}
	set, err := parseKeySet(body)
	if err != nil {
		return err
	}
	// An empty keyset would turn every token into unknown_kid. That is a
	// broken or mid-rotation publication, not a keyset to trust; keep the
	// last-known-good one and let the staleness cutoff arbitrate.
	if len(set.keys) == 0 {
		return fmt.Errorf("JWKS at %s contains no usable signature keys", jwksURL)
	}
	ps.snap.Store(&keySnapshot{set: set, fetchedAt: m.now()})
	tk.LogIt(tk.LogDebug, "[JWTAuth] profile %s: keyset refreshed (%d keys)\n", ps.prof.Name, len(set.keys))
	return nil
}

// resolveJWKSURL returns the profile's JWKS endpoint, running OIDC
// discovery once and caching the answer. Discovery failure is retried on
// the next fetch attempt.
func (m *Manager) resolveJWKSURL(ps *profileState) (string, error) {
	if cached := ps.jwksURL.Load(); cached != nil {
		return *cached, nil
	}
	u := ps.prof.JWKSURL
	if u == "" {
		disco := strings.TrimSuffix(ps.prof.Issuer, "/") + "/.well-known/openid-configuration"
		body, err := m.httpGet(disco)
		if err != nil {
			return "", fmt.Errorf("OIDC discovery: %w", err)
		}
		var doc struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("OIDC discovery document: %w", err)
		}
		if doc.JWKSURI == "" {
			return "", fmt.Errorf("OIDC discovery document at %s has no jwks_uri", disco)
		}
		if err := checkHTTPURL("jwks_uri", doc.JWKSURI); err != nil {
			return "", err
		}
		u = doc.JWKSURI
	}
	ps.jwksURL.Store(&u)
	return u, nil
}

func (m *Manager) httpGet(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", url, maxJWKSBytes)
	}
	return body, nil
}
