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
)

// detachStore simulates the store going away from under a healthy service —
// the outage window these tests are about, as opposed to the born-degraded
// service the reconnect tests cover.
func detachStore(svc *Service) {
	svc.mu.Lock()
	svc.db = nil
	svc.mu.Unlock()
}

// During a store outage the quota reads must answer with the LAST value the
// store confirmed — a configured limit, or an explicit "no limits" — and
// refuse only a tenant the store has never answered for. The alternative
// this pins against: the TTL cache expires, the store is down, and the read
// returns zeroes that the caller takes as "unlimited" — quotas silently off
// for exactly the cached-key traffic that still authenticates through the
// outage.
//
// The warming reads go through a PEER service (fresh cache, shared store) so
// what is proven is the READ path's remembering, not just the write path's;
// the TTL cache is then flushed before the store is detached, so the
// assertions cannot be satisfied by the ordinary cache either.
func TestQuotaOutageEnforcesLastKnown(t *testing.T) {
	svc := storeFixture(t)
	if err := svc.SetTenantRateLimit("t-lim", 25, 120000, 40); err != nil {
		t.Fatalf("set tenant limit: %v", err)
	}
	if err := svc.SetTenantModelRateLimit("t-lim", "llama-3-70b", 9000); err != nil {
		t.Fatalf("set model limit: %v", err)
	}

	peer := peerOf(t, svc)
	if rps, tpm, burst, err := peer.GetTenantRateLimit("t-lim"); err != nil || rps != 25 || tpm != 120000 || burst != 40 {
		t.Fatalf("warm read = (%d,%d,%d,%v), want (25,120000,40,nil)", rps, tpm, burst, err)
	}
	if tpm, err := peer.GetTenantModelRateLimit("t-lim", "llama-3-70b"); err != nil || tpm != 9000 {
		t.Fatalf("warm model read = (%d,%v), want (9000,nil)", tpm, err)
	}
	// The store's explicit "no limits configured" answer is itself worth
	// remembering: it is what keeps an unlimited tenant servable below.
	if rps, tpm, burst, err := peer.GetTenantRateLimit("t-none"); err != nil || rps != 0 || tpm != 0 || burst != 0 {
		t.Fatalf("warm no-limits read = (%d,%d,%d,%v), want zeroes,nil", rps, tpm, burst, err)
	}

	peer.Cache.Flush()
	detachStore(peer)

	if rps, tpm, burst, err := peer.GetTenantRateLimit("t-lim"); err != nil || rps != 25 || tpm != 120000 || burst != 40 {
		t.Errorf("outage read = (%d,%d,%d,%v), want the last-known (25,120000,40,nil)", rps, tpm, burst, err)
	}
	if tpm, err := peer.GetTenantModelRateLimit("t-lim", "llama-3-70b"); err != nil || tpm != 9000 {
		t.Errorf("outage model read = (%d,%v), want the last-known (9000,nil)", tpm, err)
	}
	if rps, tpm, burst, err := peer.GetTenantRateLimit("t-none"); err != nil || rps != 0 || tpm != 0 || burst != 0 {
		t.Errorf("outage no-limits read = (%d,%d,%d,%v), want zeroes,nil — the remembered answer, not a refusal", rps, tpm, burst, err)
	}
	// Never answered for: the zero must not be readable as "unlimited".
	if _, _, _, err := peer.GetTenantRateLimit("t-cold"); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("outage read of a never-answered tenant = %v, want ErrDBUnavailable", err)
	}
	if _, err := peer.GetTenantModelRateLimit("t-lim", "never-read-model"); !errors.Is(err, ErrDBUnavailable) {
		t.Errorf("outage read of a never-answered model pair = %v, want ErrDBUnavailable", err)
	}
}

// Clearing a limit is a store-confirmed answer too: a tenant whose model
// quota was removed must read 0 ("no limit") through a later outage — not
// the stale limit, and not a refusal.
func TestQuotaOutageClearedLimitStaysCleared(t *testing.T) {
	svc := storeFixture(t)
	if err := svc.SetTenantModelRateLimit("t-clr", "llama-3-70b", 9000); err != nil {
		t.Fatalf("set model limit: %v", err)
	}
	if tpm, err := svc.GetTenantModelRateLimit("t-clr", "llama-3-70b"); err != nil || tpm != 9000 {
		t.Fatalf("read before clear = (%d,%v), want (9000,nil)", tpm, err)
	}
	if err := svc.SetTenantModelRateLimit("t-clr", "llama-3-70b", 0); err != nil {
		t.Fatalf("clear model limit: %v", err)
	}

	svc.Cache.Flush()
	detachStore(svc)

	if tpm, err := svc.GetTenantModelRateLimit("t-clr", "llama-3-70b"); err != nil || tpm != 0 {
		t.Errorf("outage read of a cleared limit = (%d,%v), want (0,nil)", tpm, err)
	}
}
