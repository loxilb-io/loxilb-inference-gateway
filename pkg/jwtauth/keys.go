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

// This file is the only place the JWT/JWK library is touched. The verifier
// needs exactly two things from a library — "parse a JWKS document into
// verification keys" and "check this compact JWS against this key" — so the
// dependency is confined here behind sigKey/keySet, and swapping libraries
// (should a review or CVE force it) never reaches verify.go or the
// lifecycle code.

import (
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// sigKey is one usable verification key from a JWKS document.
type sigKey struct {
	kid string
	alg string // declared alg, "" when the key does not pin one
	kty string // "RSA" or "EC"
	key jwk.Key
}

// keySet is an immutable parsed keyset; snapshots of it are what the
// request path reads.
type keySet struct {
	keys []sigKey
}

// parseKeySet parses a JWKS document, keeping only keys usable for
// signature verification with the algorithms this package supports.
// Unusable entries (enc-use keys, symmetric keys, unknown types) are
// skipped, not fatal: an IdP is free to publish encryption keys in the
// same document.
func parseKeySet(data []byte) (*keySet, error) {
	set, err := jwk.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("jwks parse: %w", err)
	}
	ks := &keySet{}
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		kty := key.KeyType().String()
		if kty != "RSA" && kty != "EC" {
			continue
		}
		if use, ok := key.KeyUsage(); ok && use != "" && use != "sig" {
			continue
		}
		sk := sigKey{kty: kty, key: key}
		if kid, ok := key.KeyID(); ok {
			sk.kid = kid
		}
		if alg, ok := key.Algorithm(); ok {
			sk.alg = alg.String()
			// A key that pins an algorithm outside the supported set can
			// never verify anything here; drop it now.
			if !supportedAlgs[sk.alg] {
				continue
			}
		}
		ks.keys = append(ks.keys, sk)
	}
	return ks, nil
}

// algKty returns the key type an algorithm name requires.
func algKty(alg string) string {
	if strings.HasPrefix(alg, "ES") {
		return "EC"
	}
	return "RSA" // RS* and PS*
}

// candidates returns the keys that could verify a token carrying the given
// kid and alg. With a kid, only exact kid matches qualify (the normal
// Keycloak case). Without one, every type-compatible signing key qualifies;
// keysets are small, so trying each is bounded work.
func (ks *keySet) candidates(kid, alg string) []sigKey {
	want := algKty(alg)
	var out []sigKey
	for _, k := range ks.keys {
		if kid != "" && k.kid != kid {
			continue
		}
		if k.kty != want {
			continue
		}
		if k.alg != "" && k.alg != alg {
			continue
		}
		out = append(out, k)
	}
	return out
}

// verifyToken checks the compact-serialized token's signature with one key
// and returns the payload on success.
func verifyToken(token []byte, alg string, k sigKey) ([]byte, error) {
	sa, ok := jwa.LookupSignatureAlgorithm(alg)
	if !ok {
		return nil, fmt.Errorf("unknown signature algorithm %q", alg)
	}
	return jws.Verify(token, jws.WithKey(sa, k.key))
}
