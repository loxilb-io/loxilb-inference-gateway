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
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestVerifyTokenCorpus drives the verifier through the malformed-and-
// hostile token corpus against a healthy keyset. Every case asserts the
// exact decision arm, client code, and metric reason.
func TestVerifyTokenCorpus(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	ecKey := testECKey(t, "kid-ec")
	otherRSA := testRSAKey(t, "kid-other")
	js := newJWKSServer(t, jwksDoc(t,
		jwkRSA("kid-rsa", &rsaKey.PublicKey),
		jwkEC("kid-ec", &ecKey.PublicKey),
	))
	m, _ := newTestManager(t, js, func(p *Profile) {
		p.Audiences = []string{"ai-gateway"}
		p.ModelAuthz = ModelAuthzAllowAll
	})
	audClaims := func(mutate func(map[string]any)) map[string]any {
		return baseClaims(func(c map[string]any) {
			c["aud"] = "ai-gateway"
			if mutate != nil {
				mutate(c)
			}
		})
	}
	valid := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(nil))
	waitVerified(t, m, valid, "test")

	t.Run("valid RS256", func(t *testing.T) {
		c, err := m.Verify(valid, "test")
		if err != nil {
			t.Fatalf("valid token denied: %v", err)
		}
		if c.Tenant != "acme" || c.User != "user-1" {
			t.Fatalf("claims = %+v", c)
		}
	})
	t.Run("valid ES256", func(t *testing.T) {
		tok := signToken(t, "ES256", "kid-ec", ecKey, audClaims(nil))
		if _, err := m.Verify(tok, "test"); err != nil {
			t.Fatalf("valid ES256 denied: %v", err)
		}
	})
	t.Run("missing token", func(t *testing.T) {
		_, err := m.Verify(nil, "test")
		verdict(t, err, DecisionDeny401, CodeMissingToken, ReasonMissing)
	})
	t.Run("oversize token", func(t *testing.T) {
		_, err := m.Verify(bytes.Repeat([]byte("a"), MaxTokenBytes+1), "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonOversize)
	})
	t.Run("garbage token", func(t *testing.T) {
		_, err := m.Verify([]byte("not-a-jwt"), "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("two segments", func(t *testing.T) {
		parts := bytes.Split(valid, []byte("."))
		_, err := m.Verify(bytes.Join(parts[:2], []byte(".")), "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("empty signature segment", func(t *testing.T) {
		parts := bytes.Split(valid, []byte("."))
		tok := append(append(append([]byte{}, parts[0]...), '.'), parts[1]...)
		tok = append(tok, '.')
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("padded header segment", func(t *testing.T) {
		parts := bytes.Split(valid, []byte("."))
		tok := append(append([]byte{}, parts[0]...), '=', '=')
		tok = append(append(tok, '.'), parts[1]...)
		tok = append(append(tok, '.'), parts[2]...)
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("alg none", func(t *testing.T) {
		hdr := []byte(`{"alg":"none","typ":"JWT"}`)
		payload, _ := json.Marshal(audClaims(nil))
		tok := []byte(b64u(hdr) + "." + b64u(payload) + "." + b64u([]byte("sig")))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("HMAC token", func(t *testing.T) {
		tok := signParts(t, "HS256", []byte("secret"),
			[]byte(`{"alg":"HS256","typ":"JWT"}`), mustJSON(t, audClaims(nil)))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("alg outside profile accept-list", func(t *testing.T) {
		// The profile accepts RS256+ES256 by default; RS384 is supported
		// by the package but not configured here.
		tok := signParts(t, "RS256", rsaKey,
			[]byte(`{"alg":"RS384","typ":"JWT","kid":"kid-rsa"}`), mustJSON(t, audClaims(nil)))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("crit header", func(t *testing.T) {
		tok := signParts(t, "RS256", rsaKey,
			[]byte(`{"alg":"RS256","typ":"JWT","kid":"kid-rsa","crit":["exp"]}`), mustJSON(t, audClaims(nil)))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("bad signature", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", otherRSA, audClaims(nil))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonBadSignature)
	})
	t.Run("tampered payload", func(t *testing.T) {
		parts := bytes.Split(valid, []byte("."))
		forged := mustJSON(t, audClaims(func(c map[string]any) { c["tenant_id"] = "evil" }))
		tok := append(append([]byte{}, parts[0]...), '.')
		tok = append(tok, []byte(b64u(forged))...)
		tok = append(append(tok, '.'), parts[2]...)
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonBadSignature)
	})
	t.Run("unknown kid", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-unknown", otherRSA, audClaims(nil))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonUnknownKid)
	})
	t.Run("expired", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			c["exp"] = time.Now().Add(-time.Hour).Unix()
		}))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeTokenExpired, ReasonExpired)
	})
	t.Run("expired within leeway is valid", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			c["exp"] = time.Now().Add(-10 * time.Second).Unix() // default leeway 30s
		}))
		if _, err := m.Verify(tok, "test"); err != nil {
			t.Fatalf("token inside leeway denied: %v", err)
		}
	})
	t.Run("nbf in future", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			c["nbf"] = time.Now().Add(time.Hour).Unix()
		}))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeTokenExpired, ReasonExpired)
	})
	t.Run("iat in far future", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			c["iat"] = time.Now().Add(time.Hour).Unix()
		}))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeTokenExpired, ReasonExpired)
	})
	t.Run("missing exp", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			delete(c, "exp")
		}))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("non-numeric exp", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			c["exp"] = "tomorrow"
		}))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("wrong issuer", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			c["iss"] = "https://rogue.example/realms/ai"
		}))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonBadIssuer)
	})
	t.Run("wrong audience", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			c["aud"] = "someone-else"
			delete(c, "azp")
		}))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonBadAudience)
	})
	t.Run("audience via aud array", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(func(c map[string]any) {
			c["aud"] = []string{"other", "ai-gateway"}
		}))
		if _, err := m.Verify(tok, "test"); err != nil {
			t.Fatalf("aud-array token denied: %v", err)
		}
	})
	t.Run("audience via azp", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(func(c map[string]any) {
			c["aud"] = "account" // Keycloak's default aud
			c["azp"] = "ai-gateway"
		}))
		if _, err := m.Verify(tok, "test"); err != nil {
			t.Fatalf("azp token denied: %v", err)
		}
	})
	t.Run("missing tenant", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			delete(c, "tenant_id")
		}))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonNoTenant)
	})
	t.Run("non-string tenant", func(t *testing.T) {
		tok := signToken(t, "RS256", "kid-rsa", rsaKey, audClaims(func(c map[string]any) {
			c["tenant_id"] = 42
		}))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonNoTenant)
	})
	t.Run("duplicate claim keys", func(t *testing.T) {
		payload := []byte(`{"iss":"https://idp.example/realms/ai","aud":"ai-gateway",` +
			`"exp":` + expIn(time.Hour) + `,"tenant_id":"acme","tenant_id":"evil","sub":"u"}`)
		tok := signParts(t, "RS256", rsaKey,
			[]byte(`{"alg":"RS256","typ":"JWT","kid":"kid-rsa"}`), payload)
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("duplicate nested claim keys", func(t *testing.T) {
		payload := []byte(`{"iss":"https://idp.example/realms/ai","aud":"ai-gateway",` +
			`"exp":` + expIn(time.Hour) + `,"tenant_id":"acme","sub":"u",` +
			`"realm_access":{"roles":["a"],"roles":["b"]}}`)
		tok := signParts(t, "RS256", rsaKey,
			[]byte(`{"alg":"RS256","typ":"JWT","kid":"kid-rsa"}`), payload)
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("deeply nested payload", func(t *testing.T) {
		depth := maxClaimDepth + 4
		payload := `{"iss":"https://idp.example/realms/ai","aud":"ai-gateway",` +
			`"exp":` + expIn(time.Hour) + `,"tenant_id":"acme","deep":` +
			strings.Repeat(`{"d":`, depth) + `1` + strings.Repeat(`}`, depth) + `}`
		tok := signParts(t, "RS256", rsaKey,
			[]byte(`{"alg":"RS256","typ":"JWT","kid":"kid-rsa"}`), []byte(payload))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("non-object payload", func(t *testing.T) {
		tok := signParts(t, "RS256", rsaKey,
			[]byte(`{"alg":"RS256","typ":"JWT","kid":"kid-rsa"}`), []byte(`["not","an","object"]`))
		_, err := m.Verify(tok, "test")
		verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
	})
	t.Run("unknown profile", func(t *testing.T) {
		_, err := m.Verify(valid, "no-such-profile")
		verdict(t, err, DecisionDeny503, CodeStoreUnavailable, ReasonNoKeyset)
	})
	t.Run("removed profile", func(t *testing.T) {
		if err := m.SetProfile(Profile{
			Name: "gone", Issuer: "https://idp.example/realms/ai",
			JWKSURL: js.srv.URL + "/jwks",
		}); err != nil {
			t.Fatalf("SetProfile: %v", err)
		}
		m.RemoveProfile("gone")
		_, err := m.Verify(valid, "gone")
		verdict(t, err, DecisionDeny503, CodeStoreUnavailable, ReasonNoKeyset)
	})
}

// TestVerifyKidlessToken covers a token with no kid header: with a single
// type-compatible key in the set, verification should still succeed.
func TestVerifyKidlessToken(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	js := newJWKSServer(t, jwksDoc(t, jwkRSA("kid-rsa", &rsaKey.PublicKey)))
	m, _ := newTestManager(t, js, nil)
	tok := signToken(t, "RS256", "", rsaKey, baseClaims(nil))
	waitVerified(t, m, tok, "test")
}

// TestVerifyProfileAlgRestriction proves the accept-list is per profile: a
// token that is valid under the default list is refused by a profile
// configured for ES256 only.
func TestVerifyProfileAlgRestriction(t *testing.T) {
	rsaKey := testRSAKey(t, "kid-rsa")
	ecKey := testECKey(t, "kid-ec")
	js := newJWKSServer(t, jwksDoc(t,
		jwkRSA("kid-rsa", &rsaKey.PublicKey),
		jwkEC("kid-ec", &ecKey.PublicKey),
	))
	m, _ := newTestManager(t, js, func(p *Profile) { p.Algs = []string{"ES256"} })
	esTok := signToken(t, "ES256", "kid-ec", ecKey, baseClaims(nil))
	waitVerified(t, m, esTok, "test")
	rsTok := signToken(t, "RS256", "kid-rsa", rsaKey, baseClaims(nil))
	_, err := m.Verify(rsTok, "test")
	verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonMalformed)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func expIn(d time.Duration) string {
	return mustItoa(time.Now().Add(d).Unix())
}

func mustItoa(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
