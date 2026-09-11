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

// Test-side JOSE implementation. Tokens and JWKS documents are built with
// the standard library only, so the tests cross-check the production
// verifier against an independently written signer instead of round-
// tripping one library against itself.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// testRSAKey / testECKey are generated once; key generation dominates test
// time otherwise.
var (
	rsaOnce    sync.Once
	rsaKeys    map[string]*rsa.PrivateKey
	ecOnce     sync.Once
	ecKeys     map[string]*ecdsa.PrivateKey
	keyGenLock sync.Mutex
)

func testRSAKey(t *testing.T, kid string) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() { rsaKeys = make(map[string]*rsa.PrivateKey) })
	keyGenLock.Lock()
	defer keyGenLock.Unlock()
	if k, ok := rsaKeys[kid]; ok {
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	rsaKeys[kid] = k
	return k
}

func testECKey(t *testing.T, kid string) *ecdsa.PrivateKey {
	t.Helper()
	ecOnce.Do(func() { ecKeys = make(map[string]*ecdsa.PrivateKey) })
	keyGenLock.Lock()
	defer keyGenLock.Unlock()
	if k, ok := ecKeys[kid]; ok {
		return k
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec keygen: %v", err)
	}
	ecKeys[kid] = k
	return k
}

// jwkRSA renders one RSA public key as a JWK object.
func jwkRSA(kid string, pub *rsa.PublicKey) map[string]any {
	e := make([]byte, 0, 4)
	for v := pub.E; v > 0; v >>= 8 {
		e = append([]byte{byte(v)}, e...)
	}
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64u(pub.N.Bytes()), "e": b64u(e),
	}
}

// jwkEC renders one P-256 public key as a JWK object.
func jwkEC(kid string, pub *ecdsa.PublicKey) map[string]any {
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	return map[string]any{
		"kty": "EC", "kid": kid, "use": "sig", "crv": "P-256",
		"x": b64u(x), "y": b64u(y),
	}
}

func jwksDoc(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("jwks marshal: %v", err)
	}
	return doc
}

// signParts assembles and signs a compact JWS over exact header/payload
// bytes, so tests can feed the verifier payloads (duplicate keys, deep
// nesting) that json.Marshal could never produce.
func signParts(t *testing.T, alg string, key any, hdrJSON, payloadJSON []byte) []byte {
	t.Helper()
	si := b64u(hdrJSON) + "." + b64u(payloadJSON)
	digest := sha256.Sum256([]byte(si))
	var sig []byte
	switch alg {
	case "RS256":
		s, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rs256 sign: %v", err)
		}
		sig = s
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, key.(*ecdsa.PrivateKey), digest[:])
		if err != nil {
			t.Fatalf("es256 sign: %v", err)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "HS256":
		mac := hmac.New(sha256.New, key.([]byte))
		mac.Write([]byte(si))
		sig = mac.Sum(nil)
	default:
		t.Fatalf("signParts: unsupported alg %s", alg)
	}
	return []byte(si + "." + b64u(sig))
}

// signToken builds a token from claim maps with a standard header.
func signToken(t *testing.T, alg, kid string, key any, claims map[string]any) []byte {
	t.Helper()
	hdr := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("header marshal: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("payload marshal: %v", err)
	}
	return signParts(t, alg, key, hdrJSON, payloadJSON)
}

// jwksServer serves a swappable JWKS document (plus OIDC discovery) and
// counts fetches.
type jwksServer struct {
	srv *httptest.Server

	mu     sync.Mutex
	body   []byte
	status int
	hits   int
}

func newJWKSServer(t *testing.T, body []byte) *jwksServer {
	t.Helper()
	js := &jwksServer{body: body, status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		js.mu.Lock()
		defer js.mu.Unlock()
		js.hits++
		w.WriteHeader(js.status)
		_, _ = w.Write(js.body)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": js.srv.URL + "/jwks"})
	})
	js.srv = httptest.NewServer(mux)
	t.Cleanup(js.srv.Close)
	return js
}

func (js *jwksServer) set(body []byte, status int) {
	js.mu.Lock()
	defer js.mu.Unlock()
	js.body, js.status = body, status
}

func (js *jwksServer) hitCount() int {
	js.mu.Lock()
	defer js.mu.Unlock()
	return js.hits
}

// testClock is an adjustable clock for staleness/rate-limit decisions.
type testClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}

// newTestManager wires a Manager with fast lifecycle knobs and one active
// profile pointing at the server's /jwks endpoint.
func newTestManager(t *testing.T, js *jwksServer, mutate func(*Profile)) (*Manager, *testClock) {
	t.Helper()
	clk := &testClock{}
	m := New(
		WithClock(clk.now),
		WithRetryBackoff(10*time.Millisecond, 50*time.Millisecond),
		WithMinRefetchGap(10*time.Millisecond),
	)
	t.Cleanup(m.Close)
	p := Profile{
		Name:    "test",
		Issuer:  "https://idp.example/realms/ai",
		JWKSURL: js.srv.URL + "/jwks",
	}
	if mutate != nil {
		mutate(&p)
	}
	if err := m.SetProfile(p); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	return m, clk
}

// waitVerified polls until the token verifies, for lifecycle transitions
// (initial fetch, rotation refetch) that complete in the background.
func waitVerified(t *testing.T, m *Manager, token []byte, profile string) *Claims {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := m.Verify(token, profile)
		if err == nil {
			return c
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, err := m.Verify(token, profile)
	t.Fatalf("token never became verifiable: %v", err)
	return nil
}

// verdict asserts the error is a *VerdictError with the wanted arm.
func verdict(t *testing.T, err error, decision int, code, reason string) *VerdictError {
	t.Helper()
	if err == nil {
		t.Fatalf("want verdict %d/%s/%s, got nil error", decision, code, reason)
	}
	ve, ok := err.(*VerdictError)
	if !ok {
		t.Fatalf("error is %T, not *VerdictError: %v", err, err)
	}
	if ve.Decision != decision || ve.Code != code || ve.Reason != reason {
		t.Fatalf("verdict = %d/%s/%s, want %d/%s/%s (%v)",
			ve.Decision, ve.Code, ve.Reason, decision, code, reason, ve)
	}
	return ve
}

// baseClaims returns a valid claim set for the test profile.
func baseClaims(mutate func(map[string]any)) map[string]any {
	c := map[string]any{
		"iss":       "https://idp.example/realms/ai",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Add(-time.Minute).Unix(),
		"sub":       "user-1",
		"tenant_id": "acme",
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}
