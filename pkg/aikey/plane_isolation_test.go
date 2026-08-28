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

// This is an external test package on purpose. Asserting that the two planes
// cannot reach each other's credentials requires naming both of their types,
// and pkg/aikey itself must not import the management plane — so the one
// place that names both is a test binary, not the shipped package.
package aikey_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/aikey"
	"github.com/loxilb-io/loxilb/pkg/user"
)

// U-4 — a data-plane API key is invisible to the management plane's token
// cache, and a management token is invisible to the key cache.
//
// The defect this replaces: one cache held both domains, an API key was
// stored under a bare sha256 hex string, and a session token under its own
// raw value. Presenting a key's hash as a management Bearer token therefore
// found the API-key entry and asserted it to a string, which panicked the
// connection's goroutine — and, had the stored type happened to be a string,
// would have authenticated instead.
func TestPlanesDoNotShareCredentialCaches(t *testing.T) {
	const rawKey = "lxb_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	akSvc := &aikey.Service{Cache: cache.New(aikey.CacheExpirationTime*time.Minute, aikey.CacheCleanupInterval*time.Minute)}
	usrSvc := &user.UserService{Cache: cache.New(aikey.CacheExpirationTime*time.Minute, aikey.CacheCleanupInterval*time.Minute)}

	if akSvc.Cache == usrSvc.Cache {
		t.Fatal("the two planes share one cache object — the cross-plane defect is back")
	}

	// Populate the data-plane cache the way ValidateAPIKey does. The cache
	// key is opaque here by design; what matters is that nothing the key
	// lookup writes is reachable from the token lookup.
	keyHash := sha256Hex(rawKey)
	akSvc.Cache.Set("ak:"+keyHash, &cmn.ApiKeyEntry{KeyID: "k1", KeyHash: keyHash, TenantID: "team-a", Enabled: true},
		aikey.CacheExpirationTime*time.Minute)

	// Direction 1 — the key hash presented as a management Bearer token.
	// This is the exact shape that panicked at auth.go:100.
	if _, found := usrSvc.Cache.Get(keyHash); found {
		t.Error("the key hash resolves in the management token cache")
	}
	principal, err := usrSvc.ValidateToken(keyHash)
	if err == nil {
		t.Errorf("ValidateToken accepted a data-plane key hash and returned %v", principal)
	}
	if principal != nil {
		t.Errorf("ValidateToken returned a principal for a data-plane key hash: %v", principal)
	}

	// Direction 2 — a management session token presented on the VIP as an
	// API key. It must not satisfy the key lookup from the token cache, and
	// with no store attached the lookup fails closed rather than reaching for
	// another domain's entry.
	const token = "mgmt-session-token-value"
	usrSvc.Cache.Set(token, "admin|admin", cache.DefaultExpiration)
	if entry, err := akSvc.ValidateAPIKey(token); err == nil {
		t.Errorf("ValidateAPIKey accepted a management session token and returned %+v", entry)
	}
}

// sha256Hex is the stored form of a raw key. Recomputed here rather than
// reached for inside the package, so this test observes the key store the way
// an attacker presenting a stolen hash would: from the outside.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
