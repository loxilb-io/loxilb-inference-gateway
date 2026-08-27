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
package loxinet

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	rl "github.com/loxilb-io/loxilb/pkg/ratelimit"
)

// U-21, inverted — with no key store, a keyed identity FAILS CLOSED.
//
// This began as a characterization gate pinning the opposite: the three
// getters were guarded by `if svc != nil`, so with a nil service every limit
// stayed at zero, zero meant *unlimited*, and per-key RPS, per-tenant RPS,
// tenant TPM, per-model TPM and burst were all inert at once with nothing
// logged and no denial metric moving. The characterization named its own
// ending: when the store became required, the test inverts, and the
// inversion is the evidence the no-op is gone. The store-required change
// landed; this is the inverted form.
//
// What legitimately remains of the old behaviour is the empty identity:
// traffic that no key or tenant attributes cannot have a limit looked up
// for it, so it passes — that half is pinned below so the fail-closed guard
// cannot quietly grow into denying non-attributing service traffic.
func TestU21_QoSFailsClosedWithNoKeyStore(t *testing.T) {
	store := rl.New()

	// A service that would impose tight limits: the control that the
	// admission path can deny at all, so the assertions below compare
	// against a working denial path rather than a broken one.
	limited := &stubRateLimitService{
		keyRPS:       1,
		keyBurst:     1,
		tenantRPS:    1,
		tenantTPM:    1,
		modelTPM:     1,
		burstPercent: 100,
	}

	const key, tenant, model = "k-u21", "t-u21", "m-u21"

	// With a service, the tight limits bite within a handful of requests.
	deniedWithService := false
	for i := 0; i < 20; i++ {
		decision, _, _ := rateLimitCheckInternal(limited, store, key, tenant, model)
		if decision != 0 {
			deniedWithService = true
			break
		}
	}
	if !deniedWithService {
		t.Fatal("a service imposing rps=1 never denied in 20 requests — the control is broken, so the assertions below would mean nothing")
	}

	// A keyed identity with no service behind it is refused as the store's
	// outage, from the very first request — never admitted against limits
	// nobody can read, and never blamed on the credential.
	storeNil := rl.New()
	decision, _, code := rateLimitCheckInternal(nil, storeNil, key, tenant, model)
	if decision != 4 || code != "policy_store_unavailable" {
		t.Fatalf("keyed identity with no key store: got decision=%d code=%q, want the fail-closed store verdict — the inert no-op this test used to pin has come back", decision, code)
	}

	// The empty identity still passes: nothing attributes it, so there is
	// no limit to fail closed on.
	for i := 0; i < 200; i++ {
		decision, _, code := rateLimitCheckInternal(nil, storeNil, "", "", "")
		if decision != 0 {
			t.Fatalf("request %d: non-attributing traffic was denied (code=%q) — the fail-closed guard has grown past keyed identities", i, code)
		}
	}
}

// stubRateLimitService imposes fixed limits, standing in for a configured key
// store.
type stubRateLimitService struct {
	keyRPS, keyBurst       int
	tenantRPS, tenantTPM   int
	modelTPM, burstPercent int
	limitsErr              error
}

func (s *stubRateLimitService) GetTenantRateLimit(tenantID string) (rps, tokensPerMin, burstPct int, err error) {
	return s.tenantRPS, s.tenantTPM, s.burstPercent, s.limitsErr
}

func (s *stubRateLimitService) GetTenantModelRateLimit(tenantID, model string) (tokensPerMin int, err error) {
	return s.modelTPM, s.limitsErr
}

func (s *stubRateLimitService) GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error) {
	return &cmn.ApiKeySummary{RateLimitRPS: s.keyRPS, BurstSize: s.keyBurst}, nil
}
