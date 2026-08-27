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
	tk "github.com/loxilb-io/loxilib"
)

// KeyInvalidation names a key that has stopped being valid.
//
// Both identifiers travel because the two caches are keyed differently: the
// authentication path caches by hash, the management read path by key id.
// Evicting one and not the other leaves a revoked key readable as enabled
// until its TTL runs out.
//
// The hash is not a credential — it is what the store holds, and a peer that
// can receive this message can already read the store.
type KeyInvalidation struct {
	KeyHash string
	KeyID   string
}

// evictAndFanOut drops a key from this instance's cache and asks the peers to
// do the same.
//
// The local eviction is synchronous and happens first: the instance that just
// performed the revocation must never be the one still honouring the key. The
// fan-out is best-effort — a peer that is unreachable now converges when the
// entry's TTL expires — but it is what closes the window in which a key
// revoked here keeps authenticating over there, which is the whole reason
// cache ownership moved into this package.
func (s *Service) evictAndFanOut(inv KeyInvalidation) {
	s.evict(inv)
	// Read the sink, then call it with no lock held: the fan-out talks to
	// peers over the network, and holding the service lock across that would
	// stall every key lookup behind an unreachable peer's timeout.
	if fn := s.sink(); fn != nil {
		fn(inv)
	}
}

// ApplyInvalidation evicts a key on the receiving side of the fan-out.
//
// It deliberately does not fan out again. Peers are a mesh, not a tree, so
// re-broadcasting what a peer told us would loop for as long as the entries
// exist.
func (s *Service) ApplyInvalidation(inv KeyInvalidation) {
	s.evict(inv)
	tk.LogIt(tk.LogDebug, "[AIKey] Applied peer key invalidation for %s\n", inv.KeyID)
}

// evict removes every cached view of one key.
func (s *Service) evict(inv KeyInvalidation) {
	if s == nil || s.Cache == nil {
		return
	}
	if inv.KeyHash != "" {
		s.Cache.Delete(cacheKeyForHash(inv.KeyHash))
	}
	if inv.KeyID != "" {
		s.Cache.Delete(cacheKeyForID(inv.KeyID))
	}
}
