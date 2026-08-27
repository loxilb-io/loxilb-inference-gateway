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

// U-21 — with no key store, every QoS limit is a no-op.
//
// This is a characterization gate, not a repair. It pins what the code does
// today so that the change is visible when PR 3 (step I-11) makes the store
// required: at that point this test inverts, and inverting it is the evidence
// that the no-op is gone.
//
// The behaviour it pins is not "limits are skipped". It is worse than that,
// and the difference is why it is worth pinning: the three getters are guarded
// by `if svc != nil`, so with a nil service the limits stay at their zero
// values — and zero means *unlimited* in CheckKey/CheckTenant, not denied. So
// per-key RPS, per-tenant RPS, tenant TPM, per-model TPM and burst are all
// inert at once, the gateway logs nothing, and no denial metric moves, because
// there is nothing to deny against. A QoS dashboard shows a quiet, healthy
// system.
func TestU21_QoSIsInertWithNoKeyStore(t *testing.T) {
	store := rl.New()

	// A service that would impose tight limits, so the comparison below is
	// between "limits applied" and "limits skipped" rather than between two
	// unlimited runs.
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
		t.Fatal("a service imposing rps=1 never denied in 20 requests — the control is broken, so the comparison below would mean nothing")
	}

	// With no service, nothing denies, however many requests arrive.
	storeNil := rl.New()
	for i := 0; i < 200; i++ {
		decision, _, code := rateLimitCheckInternal(nil, storeNil, key, tenant, model)
		if decision != 0 {
			t.Fatalf("request %d was denied (code=%q) with no key store — the no-op documented here has changed. "+
				"If that is PR 3 landing, invert this test; it is the evidence that the inert path is gone.", i, code)
		}
	}
}

// stubRateLimitService imposes fixed limits, standing in for a configured key
// store.
type stubRateLimitService struct {
	keyRPS, keyBurst       int
	tenantRPS, tenantTPM   int
	modelTPM, burstPercent int
}

func (s *stubRateLimitService) GetTenantRateLimit(tenantID string) (rps, tokensPerMin, burstPct int) {
	return s.tenantRPS, s.tenantTPM, s.burstPercent
}

func (s *stubRateLimitService) GetTenantModelRateLimit(tenantID, model string) (tokensPerMin int) {
	return s.modelTPM
}

func (s *stubRateLimitService) GetAPIKeyByID(keyID string) (*cmn.ApiKeySummary, error) {
	return &cmn.ApiKeySummary{RateLimitRPS: s.keyRPS, BurstSize: s.keyBurst}, nil
}
