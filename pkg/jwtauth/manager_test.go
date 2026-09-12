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
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestLifecycleFailClosedUntilFirstFetch: a profile answers 503-class from
// activation until its first successful JWKS fetch, then recovers by
// backoff retry without intervention.
func TestLifecycleFailClosedUntilFirstFetch(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	doc := jwksDoc(t, jwkRSA("kid-rsa", &rsaKey.PublicKey))
	js := newJWKSServer(t, doc)
	js.set(doc, http.StatusInternalServerError)

	m, _ := newTestManager(t, js, nil)
	tok := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(nil))

	// The fetch is failing: no keyset, deny 503 — never allow.
	_, err := m.Verify(tok, "test")
	verdict(t, err, DecisionDeny503, CodeStoreUnavailable, ReasonNoKeyset)
	if st, ok := m.Status("test"); !ok || st.Usable {
		t.Fatalf("status = %+v ok=%v, want present and unusable", st, ok)
	}

	// Server recovers; the backoff loop must find it without any nudge.
	js.set(doc, http.StatusOK)
	waitVerified(t, m, tok, "test")
	if st, _ := m.Status("test"); !st.Usable || st.Keys != 1 {
		t.Fatalf("status after recovery = %+v", st)
	}
}

// TestLifecycleRotation: a token signed by a newly rotated key is denied
// with unknown_kid, which schedules a background refetch; once that lands
// the new token verifies and the retired key's tokens stop verifying.
func TestLifecycleRotation(t *testing.T) {
	oldKey := testRSAKey(t, "kid-old")
	newKey := testRSAKey(t, "kid-new")
	js := newJWKSServer(t, jwksDoc(t, jwkRSA("kid-old", &oldKey.PublicKey)))
	m, _ := newTestManager(t, js, nil)

	oldTok := signToken(t, "RS256", "kid-old", oldKey, baseClaims(nil))
	newTok := signToken(t, "RS256", "kid-new", newKey, baseClaims(nil))
	waitVerified(t, m, oldTok, "test")

	// Rotate: the IdP now publishes only the new key.
	js.set(jwksDoc(t, jwkRSA("kid-new", &newKey.PublicKey)), http.StatusOK)

	// First request with the new key loses (the hot path never blocks on
	// the network) and triggers the refetch that makes its retry win.
	_, err := m.Verify(newTok, "test")
	verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonUnknownKid)
	waitVerified(t, m, newTok, "test")

	// The retired key is gone from the snapshot.
	_, err = m.Verify(oldTok, "test")
	verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonUnknownKid)
}

// TestLifecycleRefetchRateLimit: kid-miss refetches are spaced by the
// configured minimum gap — a burst of unknown-kid tokens must not turn
// into a fetch herd against the IdP.
func TestLifecycleRefetchRateLimit(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	strangerKey := testRSAKey(t, "kid-stranger")
	js := newJWKSServer(t, jwksDoc(t, jwkRSA("kid-rsa", &rsaKey.PublicKey)))

	clk := &testClock{}
	m := New(
		WithClock(clk.now),
		WithRetryBackoff(10*time.Millisecond, 50*time.Millisecond),
		WithMinRefetchGap(time.Hour),
	)
	t.Cleanup(m.Close)
	if err := m.SetProfile(Profile{
		Name: "test", Issuer: "https://idp.example/realms/ai",
		JWKSURL: js.srv.URL + "/jwks",
	}); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	good := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(nil))
	waitVerified(t, m, good, "test")
	base := js.hitCount() // initial fetch (1, or more if backoff raced)

	// First unknown-kid miss: one refetch allowed.
	bad := signToken(t, "RS256", "kid-nobody", strangerKey, baseClaims(nil))
	_, err := m.Verify(bad, "test")
	verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonUnknownKid)
	deadline := time.Now().Add(2 * time.Second)
	for js.hitCount() == base && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	afterFirst := js.hitCount()
	if afterFirst != base+1 {
		t.Fatalf("first kid miss: hits went %d -> %d, want exactly one refetch", base, afterFirst)
	}

	// A burst of further misses inside the gap: all dropped.
	for i := 0; i < 20; i++ {
		_, _ = m.Verify(bad, "test")
	}
	time.Sleep(100 * time.Millisecond)
	if got := js.hitCount(); got != afterFirst {
		t.Fatalf("refetch rate limit leaked: hits %d -> %d", afterFirst, got)
	}

	// Advancing the clock past the gap re-arms the refetch.
	clk.advance(2 * time.Hour)
	_, _ = m.Verify(bad, "test")
	deadline = time.Now().Add(2 * time.Second)
	for js.hitCount() == afterFirst && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := js.hitCount(); got != afterFirst+1 {
		t.Fatalf("re-armed refetch: hits %d -> %d, want exactly one more", afterFirst, got)
	}
}

// TestLifecycleLastKnownGood: a failing refresh keeps the previous keyset
// serving (inside the staleness window) instead of dropping to 503.
func TestLifecycleLastKnownGood(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	strangerKey := testRSAKey(t, "kid-stranger")
	doc := jwksDoc(t, jwkRSA("kid-rsa", &rsaKey.PublicKey))
	js := newJWKSServer(t, doc)
	m, _ := newTestManager(t, js, nil)
	good := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(nil))
	waitVerified(t, m, good, "test")

	// The IdP goes down. A kid miss triggers a refetch, which fails.
	js.set(nil, http.StatusInternalServerError)
	bad := signToken(t, "RS256", "kid-nobody", strangerKey, baseClaims(nil))
	_, _ = m.Verify(bad, "test")
	base := js.hitCount()
	deadline := time.Now().Add(2 * time.Second)
	for js.hitCount() == base && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let the failed fetch settle

	// The last-known-good keyset still verifies traffic.
	if _, err := m.Verify(good, "test"); err != nil {
		t.Fatalf("good token denied during IdP outage: %v", err)
	}
}

// TestLifecycleRecoversAfterOutage: the other half of last-known-good. An
// IdP that comes back must be picked up again — a manager that survived the
// outage by serving cached keys and then never refetched would look healthy
// while silently refusing every rotated key until the staleness cutoff
// turned the profile off entirely.
func TestLifecycleRecoversAfterOutage(t *testing.T) {
	oldKey := testRSAKey(t, "kid-old")
	newKey := testRSAKey(t, "kid-new")
	js := newJWKSServer(t, jwksDoc(t, jwkRSA("kid-old", &oldKey.PublicKey)))
	m, _ := newTestManager(t, js, nil)

	oldTok := signToken(t, "RS256", "kid-old", oldKey, baseClaims(nil))
	waitVerified(t, m, oldTok, "test")

	// The IdP goes down, and stays down across a kid miss whose refetch
	// fails. Waiting for the fetch to be ATTEMPTED is what makes the rest of
	// this test mean anything: without it the server can be restored before
	// the lifecycle goroutine ever tried, and a manager that wedges on a
	// failed refresh would still pass on the fetch that never failed.
	js.set(nil, http.StatusInternalServerError)
	base := js.hitCount()
	newTok := signToken(t, "RS256", "kid-new", newKey, baseClaims(nil))
	_, err := m.Verify(newTok, "test")
	verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonUnknownKid)
	deadline := time.Now().Add(2 * time.Second)
	for js.hitCount() == base && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if js.hitCount() == base {
		t.Fatal("no refetch was attempted during the outage — the recovery this " +
			"test claims to prove would be proven against a fetch that never failed")
	}
	time.Sleep(20 * time.Millisecond) // let the failed fetch settle
	if _, err := m.Verify(oldTok, "test"); err != nil {
		t.Fatalf("good token denied during the outage: %v", err)
	}

	// The IdP comes back, having rotated while it was away. The recovery
	// that matters is that the new key is picked up at all: a token no
	// cached keyset could ever verify is admitted only by a fetch that
	// happened after the outage ended.
	js.set(jwksDoc(t, jwkRSA("kid-new", &newKey.PublicKey)), http.StatusOK)
	waitVerified(t, m, newTok, "test")

	if st, _ := m.Status("test"); !st.Usable {
		t.Fatalf("profile still unusable after the IdP recovered: %+v", st)
	}
}

// TestLifecycleStalenessCutoff: once the last successful fetch ages past
// the cutoff, the profile degrades to 503-class — stale keys are not
// trusted forever just because refreshes keep failing.
func TestLifecycleStalenessCutoff(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	js := newJWKSServer(t, jwksDoc(t, jwkRSA("kid-rsa", &rsaKey.PublicKey)))
	m, clk := newTestManager(t, js, nil)
	good := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(func(c map[string]any) {
		c["exp"] = time.Now().Add(48 * time.Hour).Unix() // outlive the cutoff jump
	}))
	waitVerified(t, m, good, "test")

	clk.advance(25 * time.Hour) // default cutoff is 24h
	_, err := m.Verify(good, "test")
	verdict(t, err, DecisionDeny503, CodeStoreUnavailable, ReasonNoKeyset)
	if st, _ := m.Status("test"); st.Usable {
		t.Fatalf("status still usable after staleness cutoff: %+v", st)
	}
}

// TestLifecycleEmptyKeysetRejected: a JWKS publishing zero usable keys is
// treated as a failed fetch (keep last-known-good), not as an instruction
// to deny everything with unknown_kid.
func TestLifecycleEmptyKeysetRejected(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	js := newJWKSServer(t, jwksDoc(t, jwkRSA("kid-rsa", &rsaKey.PublicKey)))
	m, _ := newTestManager(t, js, nil)
	good := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(nil))
	waitVerified(t, m, good, "test")

	js.set(jwksDoc(t), http.StatusOK) // empty "keys" array, HTTP 200
	strangerKey := testRSAKey(t, "kid-stranger")
	bad := signToken(t, "RS256", "kid-nobody", strangerKey, baseClaims(nil))
	_, _ = m.Verify(bad, "test") // trigger refetch
	time.Sleep(100 * time.Millisecond)
	if _, err := m.Verify(good, "test"); err != nil {
		t.Fatalf("good token denied after empty-keyset publication: %v", err)
	}
}

// TestLifecycleOIDCDiscovery: with no jwks_url configured, the endpoint is
// discovered from <issuer>/.well-known/openid-configuration.
func TestLifecycleOIDCDiscovery(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	js := newJWKSServer(t, jwksDoc(t, jwkRSA("kid-rsa", &rsaKey.PublicKey)))
	m := New(WithRetryBackoff(10*time.Millisecond, 50*time.Millisecond))
	t.Cleanup(m.Close)
	if err := m.SetProfile(Profile{
		Name:   "disco",
		Issuer: js.srv.URL, // discovery + issuer share the test server
	}); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	tok := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(func(c map[string]any) {
		c["iss"] = js.srv.URL
	}))
	waitVerified(t, m, tok, "disco")
}

// TestSetProfileSemantics: re-setting an unchanged profile keeps the
// running keyset; changing it restarts the lifecycle fail-closed.
func TestSetProfileSemantics(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	js := newJWKSServer(t, jwksDoc(t, jwkRSA("kid-rsa", &rsaKey.PublicKey)))
	m, _ := newTestManager(t, js, nil)
	tok := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(nil))
	waitVerified(t, m, tok, "test")

	// Unchanged re-set: the keyset survives, no new fetch is forced.
	if err := m.SetProfile(Profile{
		Name: "test", Issuer: "https://idp.example/realms/ai",
		JWKSURL: js.srv.URL + "/jwks",
	}); err != nil {
		t.Fatalf("unchanged SetProfile: %v", err)
	}
	if _, err := m.Verify(tok, "test"); err != nil {
		t.Fatalf("keyset lost on unchanged re-set: %v", err)
	}

	// Changed profile (issuer): lifecycle restarts; old-issuer tokens die
	// even after the new fetch lands.
	if err := m.SetProfile(Profile{
		Name: "test", Issuer: "https://other.example/realms/ai",
		JWKSURL: js.srv.URL + "/jwks",
	}); err != nil {
		t.Fatalf("changed SetProfile: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := m.Status("test"); st.Usable {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, err := m.Verify(tok, "test")
	verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonBadIssuer)
}

// TestProfileValidation: configuration-time rejection of unusable
// profiles.
func TestProfileValidation(t *testing.T) {
	m := New()
	t.Cleanup(m.Close)
	cases := []struct {
		name string
		p    Profile
	}{
		{"empty name", Profile{Issuer: "https://idp.example"}},
		{"no issuer", Profile{Name: "p"}},
		{"bad issuer scheme", Profile{Name: "p", Issuer: "ftp://idp.example"}},
		{"issuer without host", Profile{Name: "p", Issuer: "https://"}},
		{"bad jwks scheme", Profile{Name: "p", Issuer: "https://idp.example", JWKSURL: "file:///etc/passwd"}},
		{"alg none", Profile{Name: "p", Issuer: "https://idp.example", Algs: []string{"none"}}},
		{"alg HS256", Profile{Name: "p", Issuer: "https://idp.example", Algs: []string{"HS256"}}},
		{"alg unknown", Profile{Name: "p", Issuer: "https://idp.example", Algs: []string{"XX999"}}},
		{"negative leeway", Profile{Name: "p", Issuer: "https://idp.example", LeewaySec: -1}},
		{"negative refresh", Profile{Name: "p", Issuer: "https://idp.example", RefreshSec: -1}},
		{"bad model authz", Profile{Name: "p", Issuer: "https://idp.example", ModelAuthz: "maybe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := m.SetProfile(tc.p); err == nil {
				t.Fatalf("profile %+v accepted, want rejection", tc.p)
			}
		})
	}
	if got := len(m.Profiles()); got != 0 {
		t.Fatalf("%d profiles active after rejected sets", got)
	}
}

// TestRefreshObserverCountsEveryAttempt: the observer fires exactly once per
// fetch attempt, with the outcome that attempt reached.
//
// This is what makes a JWKS outage visible. A failing refresh changes no
// request outcome until the staleness cutoff expires — the gateway keeps
// serving on the last-known-good keyset — so if the failure is not observed
// here, the first symptom an operator sees is traffic being refused that was
// fine a moment earlier.
func TestRefreshObserverCountsEveryAttempt(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	js := newJWKSServer(t, jwksDoc(t, jwkRSA("kid-rsa", &rsaKey.PublicKey)))

	var mu sync.Mutex
	seen := map[string]int{}
	observe := func(profile, outcome string) {
		mu.Lock()
		defer mu.Unlock()
		seen[profile+"/"+outcome]++
	}
	count := func(key string) int {
		mu.Lock()
		defer mu.Unlock()
		return seen[key]
	}

	m := New(
		WithRefreshObserver(observe),
		WithRetryBackoff(10*time.Millisecond, 50*time.Millisecond),
	)
	t.Cleanup(m.Close)
	if err := m.SetProfile(Profile{
		Name: "obs", Issuer: "https://idp.example/realms/ai",
		JWKSURL: js.srv.URL + "/jwks",
	}); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}

	good := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(nil))
	waitVerified(t, m, good, "obs")

	if n := count("obs/" + RefreshSuccess); n < 1 {
		t.Fatalf("a verified token implies a successful fetch, but success count is %d", n)
	}
	// The control for the assertion below: nothing has failed yet, so a
	// failure count that is already non-zero would make the next check
	// pass for the wrong reason.
	if n := count("obs/" + RefreshFailure); n != 0 {
		t.Fatalf("no fetch has failed yet, but failure count is %d", n)
	}

	// Take the endpoint away and force an out-of-cycle fetch with an
	// unknown-kid token. The keyset stays usable, so the ONLY signal that
	// anything went wrong is the observer.
	js.srv.Close()
	strangerKey := testRSAKey(t, "kid-stranger")
	bad := signToken(t, "RS256", "kid-nobody", strangerKey, baseClaims(nil))
	if _, err := m.Verify(bad, "obs"); err == nil {
		t.Fatal("an unknown kid must not verify")
	}

	deadline := time.Now().Add(3 * time.Second)
	for count("obs/"+RefreshFailure) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := count("obs/" + RefreshFailure); n == 0 {
		t.Error("a fetch against a dead JWKS endpoint must be observed as a failure")
	}

	// The keyset is still good, which is precisely why the failure had to be
	// counted: nothing in the request path reports it.
	if _, err := m.Verify(good, "obs"); err != nil {
		t.Errorf("last-known-good keyset must still verify: %v", err)
	}
}
