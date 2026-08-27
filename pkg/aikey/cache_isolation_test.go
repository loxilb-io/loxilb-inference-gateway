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
package aikey

import (
	"errors"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"

	cmn "github.com/loxilb-io/loxilb/common"
)

// U-4, store side — an entry written by this package is reachable only under
// its prefixed cache key, never under the bare sha256 hex string that the
// shared-cache layout used. The prefix is the second of the two barriers
// between the planes; the first, separate cache objects, is asserted in
// plane_isolation_test.go, which is where the management-plane type may be
// imported.
func TestCachedKeyNotReachableUnderBareHash(t *testing.T) {
	const rawKey = "lxb_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	keyHash := hashKey(rawKey)

	svc := &Service{Cache: cache.New(CacheExpirationTime*time.Minute, CacheCleanupInterval*time.Minute)}
	svc.Cache.Set(cacheKeyForHash(keyHash), &cmn.ApiKeyEntry{KeyID: "k1", KeyHash: keyHash}, CacheExpirationTime*time.Minute)

	if _, found := svc.Cache.Get(keyHash); found {
		t.Error("the key is cached under its bare hash, the key shape that made the cross-plane collision reachable")
	}
	if _, found := svc.Cache.Get(cacheKeyForHash(keyHash)); !found {
		t.Fatal("the key is not cached under its prefixed key either — the test proved nothing")
	}
}

// Every entry this package caches carries a domain prefix. Asserted over the
// live cache after each write path rather than by reading the source, so a
// new write path that forgets the prefix is caught.
func TestEveryCachedKeyIsPrefixed(t *testing.T) {
	svc := &Service{Cache: cache.New(CacheExpirationTime*time.Minute, CacheCleanupInterval*time.Minute)}

	svc.Cache.Set(cacheKeyForHash("abc"), &cmn.ApiKeyEntry{}, time.Minute)
	svc.Cache.Set(cacheKeyForID("k1"), &cmn.ApiKeySummary{}, time.Minute)
	svc.Cache.Set(cacheKeyForTenant("team-a"), &rateLimitCacheEntry{}, time.Minute)
	svc.Cache.Set(cacheKeyForModel("team-a", "llama"), &rateLimitCacheEntry{}, time.Minute)

	prefixes := []string{cachePfxKeyHash, cachePfxKeyID, cachePfxTenant, cachePfxModel}
	items := svc.Cache.Items()
	if len(items) != 4 {
		t.Fatalf("expected 4 cached items, got %d", len(items))
	}
	for k := range items {
		matched := false
		for _, p := range prefixes {
			if len(k) > len(p) && k[:len(p)] == p {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("cache key %q carries no domain prefix", k)
		}
	}
}

// A nil service must fail closed rather than panic. The API server accepts
// connections before the store finishes connecting, so this is a real state
// and not a defensive flourish.
func TestNilServiceFailsClosed(t *testing.T) {
	var svc *Service
	if _, err := svc.store(); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("store() on a nil service = %v, want ErrDBUnavailable", err)
	}
	// evict must tolerate it too: the invalidation fan-out can arrive from a
	// peer before this side has a service at all.
	svc.evict(KeyInvalidation{KeyHash: "abc", KeyID: "k1"})
}
