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

package loxinet

import (
	"errors"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func testJWTProfileMod(name string) cmn.JWTAuthProfileMod {
	return cmn.JWTAuthProfileMod{
		Name:    name,
		Issuer:  "https://idp.example/realms/ai",
		JWKSURL: "https://idp.example/realms/ai/protocol/openid-connect/certs",
	}
}

// TestJWTAuthProfileCRUD covers the holder's add/get/delete round-trip,
// upsert semantics, and validation rejection.
func TestJWTAuthProfileCRUD(t *testing.T) {
	h := JWTAuthProfileInit()
	defer h.Manager().Close()

	pm := testJWTProfileMod("kc-a")
	if _, err := h.ProfileAdd(&pm); err != nil {
		t.Fatalf("ProfileAdd: %v", err)
	}
	pm2 := testJWTProfileMod("kc-b")
	pm2.Audiences = []string{"ai-gateway"}
	if _, err := h.ProfileAdd(&pm2); err != nil {
		t.Fatalf("ProfileAdd second: %v", err)
	}

	got, err := h.ProfileGet()
	if err != nil {
		t.Fatalf("ProfileGet: %v", err)
	}
	if len(got) != 2 || got[0].Name != "kc-a" || got[1].Name != "kc-b" {
		t.Fatalf("ProfileGet = %+v, want kc-a,kc-b in name order", got)
	}
	// Get reports EXACTLY what was configured -- no defaults leak in.
	if got[0].LeewaySec != 0 || got[0].TenantClaim != "" {
		t.Fatalf("stored profile grew defaults: %+v", got[0])
	}

	// Upsert: replacing kc-a changes its stored config, count stays 2.
	pm.DefaultTenant = "shared"
	if _, err := h.ProfileAdd(&pm); err != nil {
		t.Fatalf("ProfileAdd replace: %v", err)
	}
	got, _ = h.ProfileGet()
	if len(got) != 2 || got[0].DefaultTenant != "shared" {
		t.Fatalf("upsert did not replace: %+v", got)
	}

	// Validation failures reject the profile and store nothing.
	bad := testJWTProfileMod("kc-bad")
	bad.Algs = []string{"HS256"}
	if _, err := h.ProfileAdd(&bad); err == nil {
		t.Fatalf("HS256 profile accepted")
	}
	bad = testJWTProfileMod("kc-bad")
	bad.Issuer = "not-a-url"
	if _, err := h.ProfileAdd(&bad); err == nil {
		t.Fatalf("bad issuer accepted")
	}
	if got, _ = h.ProfileGet(); len(got) != 2 {
		t.Fatalf("rejected profile was stored: %+v", got)
	}

	// Delete: unknown name errors; known name removes.
	if _, err := h.ProfileDel("nope"); err == nil {
		t.Fatalf("deleting unknown profile succeeded")
	}
	if _, err := h.ProfileDel("kc-a"); err != nil {
		t.Fatalf("ProfileDel: %v", err)
	}
	if got, _ = h.ProfileGet(); len(got) != 1 || got[0].Name != "kc-b" {
		t.Fatalf("after delete: %+v", got)
	}
}

// TestJWTAuthProfileDeleteRefusedWhileReferenced proves the reference
// guard: a profile named by any LB rule is not deletable, and the error
// names the referencing rules.
func TestJWTAuthProfileDeleteRefusedWhileReferenced(t *testing.T) {
	h := JWTAuthProfileInit()
	defer h.Manager().Close()
	pm := testJWTProfileMod("kc-ref")
	if _, err := h.ProfileAdd(&pm); err != nil {
		t.Fatalf("ProfileAdd: %v", err)
	}

	refs := []string{"10.0.0.1:8080/tcp"}
	h.ruleRefs = func(name string) []string {
		if name == "kc-ref" {
			return refs
		}
		return nil
	}

	if _, err := h.ProfileDel("kc-ref"); err == nil {
		t.Fatalf("referenced profile deleted")
	} else if !strings.Contains(err.Error(), "10.0.0.1:8080/tcp") {
		t.Fatalf("refusal does not name the referencing rule: %v", err)
	} else {
		// The type is what carries the status: the spec answers this route's
		// reference refusal with 409, and the wording matches no phrase the
		// message classifier reads as a conflict. Untyped, it degrades to a
		// 400 and the caller is told to fix a request that was never wrong.
		var conflict *cmn.ConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("refusal is %T, want *cmn.ConflictError so the API answers 409", err)
		}
	}
	if got, _ := h.ProfileGet(); len(got) != 1 {
		t.Fatalf("refused delete still removed the profile: %+v", got)
	}

	// Reference gone -> delete proceeds.
	refs = nil
	if _, err := h.ProfileDel("kc-ref"); err != nil {
		t.Fatalf("ProfileDel after detach: %v", err)
	}
}

// TestJWKSStatesReportsEveryProfile covers the snapshot behind the
// loxilb_ai_jwks_* families: one entry per configured profile, read from the
// manager rather than from state the holder keeps of its own.
//
// The JWKS URL here is unreachable, which is the point. A profile whose
// keyset has never loaded must still be REPORTED -- with zero keys and
// usable=false -- because that is exactly the state an operator needs to see.
// A snapshot that listed only healthy profiles would go quiet at the moment
// it matters.
func TestJWKSStatesReportsEveryProfile(t *testing.T) {
	h := JWTAuthProfileInit()
	defer h.Manager().Close()

	pm := testJWTProfileMod("kc-metrics")
	if _, err := h.ProfileAdd(&pm); err != nil {
		t.Fatalf("ProfileAdd: %v", err)
	}

	states := h.jwksStates()
	if len(states) != 1 {
		t.Fatalf("jwksStates returned %d entries, want 1: %+v", len(states), states)
	}
	st := states[0]
	if st.Profile != "kc-metrics" {
		t.Errorf("profile = %q, want kc-metrics", st.Profile)
	}
	if st.Usable {
		t.Error("a profile whose JWKS has never loaded must report usable=false")
	}
	if st.Keys != 0 {
		t.Errorf("keys = %d, want 0 before any successful fetch", st.Keys)
	}
	if !st.LastSuccess.IsZero() {
		t.Errorf("last success = %v, want the zero time before any fetch", st.LastSuccess)
	}

	// Removing the profile removes its series: a stale series would report a
	// keyset for a profile that no longer exists.
	if _, err := h.ProfileDel("kc-metrics"); err != nil {
		t.Fatalf("ProfileDel: %v", err)
	}
	if states := h.jwksStates(); len(states) != 0 {
		t.Errorf("a deleted profile must report no state, got %+v", states)
	}
}
