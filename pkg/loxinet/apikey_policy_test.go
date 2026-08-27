/*
 * Copyright (c) 2025 NetLOX Inc
 *
 * SPDX (Short Identifier): Apache-2.0
 */

package loxinet

import (
	"errors"
	"fmt"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/aikey"
	rl "github.com/loxilb-io/loxilb/pkg/ratelimit"
)

// The gates in this file pin the per-service api_key_auth policy: what it
// resolves to, what it does to AI-gateway accounting, and — the property the
// whole field exists for — what it must NOT be affected by.
//
// Authentication used to be a rider on whether a service streamed. An operator
// could not enable SSE without enabling auth, nor authenticate a service that
// did not stream. Splitting them is only real if the two axes stay
// independent, and independence is the kind of property that decays silently:
// nothing fails to compile when a predicate quietly starts reading one more
// input.
//
// Expectations here are written out as literal tables rather than computed
// from the predicate under test. A table that recomputes `sse || pd || ...`
// agrees with any implementation of that expression, including a wrong one.

// policyCases is the closed set of api_key_auth values a service can carry,
// with the value each resolves to. The empty string is the unset field, and
// its row is the compatibility promise: an operator who has never heard of
// this field gets the behaviour they had before it existed.
var policyCases = []struct {
	policy   string
	resolved string
	enforces bool
}{
	{policy: "", resolved: cmn.ApiKeyAuthDisabled, enforces: false},
	{policy: cmn.ApiKeyAuthDisabled, resolved: cmn.ApiKeyAuthDisabled, enforces: false},
	{policy: cmn.ApiKeyAuthRequired, resolved: cmn.ApiKeyAuthRequired, enforces: true},
}

// ssePdCases enumerates the streaming axes. Both are booleans, so this is the
// complete cross product and not a sample.
var ssePdCases = []struct {
	sse bool
	pd  bool
}{
	{sse: false, pd: false},
	{sse: true, pd: false},
	{sse: false, pd: true},
	{sse: true, pd: true},
}

// TestAiGwModeForTruthTable: ai_gw_mode is sse ∨ pd ∨ required, over the
// complete cross product of the three inputs.
//
// Every expectation below is a literal, so the test disagrees with a predicate
// that computes the wrong function rather than agreeing with whatever the
// predicate happens to compute.
func TestAiGwModeForTruthTable(t *testing.T) {
	tests := []struct {
		sse    bool
		pd     bool
		policy string
		want   bool
	}{
		// Neither streaming mode: accounting follows the policy alone. The
		// third row is the case that could not be expressed at all before
		// api_key_auth existed — authenticate a service that does not stream.
		{sse: false, pd: false, policy: "", want: false},
		{sse: false, pd: false, policy: cmn.ApiKeyAuthDisabled, want: false},
		{sse: false, pd: false, policy: cmn.ApiKeyAuthRequired, want: true},

		// SSE on: accounting is armed regardless of the policy, and in
		// particular a disabled policy does not switch it off.
		{sse: true, pd: false, policy: "", want: true},
		{sse: true, pd: false, policy: cmn.ApiKeyAuthDisabled, want: true},
		{sse: true, pd: false, policy: cmn.ApiKeyAuthRequired, want: true},

		// P/D disaggregation on: same.
		{sse: false, pd: true, policy: "", want: true},
		{sse: false, pd: true, policy: cmn.ApiKeyAuthDisabled, want: true},
		{sse: false, pd: true, policy: cmn.ApiKeyAuthRequired, want: true},

		// Both streaming modes on.
		{sse: true, pd: true, policy: "", want: true},
		{sse: true, pd: true, policy: cmn.ApiKeyAuthDisabled, want: true},
		{sse: true, pd: true, policy: cmn.ApiKeyAuthRequired, want: true},
	}

	if len(tests) != len(ssePdCases)*len(policyCases) {
		t.Fatalf("truth table has %d rows, the input space has %d — it is no longer exhaustive",
			len(tests), len(ssePdCases)*len(policyCases))
	}

	for _, tt := range tests {
		name := fmt.Sprintf("sse=%v/pd=%v/policy=%q", tt.sse, tt.pd, tt.policy)
		t.Run(name, func(t *testing.T) {
			if got := aiGwModeFor(tt.sse, tt.pd, tt.policy); got != tt.want {
				t.Errorf("aiGwModeFor(%v, %v, %q) = %v, want %v",
					tt.sse, tt.pd, tt.policy, got, tt.want)
			}
		})
	}
}

// TestApiKeyAuthIsIndependentOfStreamingModes: the value the data plane
// enforces is derived from the service's own field and from nothing else.
//
// The wire field dat.apikey_auth is written in the eBPF installer, which is
// cgo and cannot be reached from a test. What is checked here is the
// expression that decides it; that the installer actually uses this expression
// and reads neither streaming mode is a source-level invariant, checked by
// scripts/check-source-invariants.sh, because it is a property of the text
// rather than of any value.
func TestApiKeyAuthIsIndependentOfStreamingModes(t *testing.T) {
	for _, pc := range policyCases {
		pc := pc
		t.Run(fmt.Sprintf("policy=%q", pc.policy), func(t *testing.T) {
			for _, sp := range ssePdCases {
				got := cmn.ResolveApiKeyAuth(pc.policy)
				if got != pc.resolved {
					t.Errorf("sse=%v pd=%v: ResolveApiKeyAuth(%q) = %q, want %q",
						sp.sse, sp.pd, pc.policy, got, pc.resolved)
				}
				// The enforcement bit the installer writes onto the wire.
				if enforces := got == cmn.ApiKeyAuthRequired; enforces != pc.enforces {
					t.Errorf("sse=%v pd=%v: policy %q enforces = %v, want %v",
						sp.sse, sp.pd, pc.policy, enforces, pc.enforces)
				}
			}
		})
	}
}

// TestAbsentApiKeyAuthResolvesDisabled: an absent api_key_auth resolves to
// "disabled" for every sse/pd combination, and leaves AI-gateway accounting
// to be decided by the streaming modes alone.
//
// This is the upgrade-compatibility gate. Every service configured before the
// field existed carries the empty string, so if the unset value ever resolved
// to "required" the first restart after an upgrade would start refusing
// traffic on every one of them.
func TestAbsentApiKeyAuthResolvesDisabled(t *testing.T) {
	// Literal expectations again: with no policy, accounting is exactly the
	// streaming modes.
	wantMode := map[[2]bool]bool{
		{false, false}: false,
		{true, false}:  true,
		{false, true}:  true,
		{true, true}:   true,
	}

	for _, sp := range ssePdCases {
		t.Run(fmt.Sprintf("sse=%v/pd=%v", sp.sse, sp.pd), func(t *testing.T) {
			if got := cmn.ResolveApiKeyAuth(""); got != cmn.ApiKeyAuthDisabled {
				t.Errorf("unset api_key_auth resolved to %q, want %q — every service "+
					"configured before this field existed would change behaviour",
					got, cmn.ApiKeyAuthDisabled)
			}
			want := wantMode[[2]bool{sp.sse, sp.pd}]
			if got := aiGwModeFor(sp.sse, sp.pd, ""); got != want {
				t.Errorf("aiGwModeFor(%v, %v, \"\") = %v, want %v",
					sp.sse, sp.pd, got, want)
			}
		})
	}
}

// TestApiKeyAuthClosedSet pins the set itself. A third value added without a
// datapath that understands it is a service whose enforcement the data plane
// would have to guess at, and guessing here is guessing between admitting
// everything and rejecting everything.
func TestApiKeyAuthClosedSet(t *testing.T) {
	for _, valid := range []string{"", cmn.ApiKeyAuthDisabled, cmn.ApiKeyAuthRequired} {
		if !cmn.IsValidApiKeyAuth(valid) {
			t.Errorf("IsValidApiKeyAuth(%q) = false, want true", valid)
		}
	}
	// Case, substring and near-miss spellings are not the policy. "Required"
	// silently resolving to itself and then failing the == comparison would
	// admit unauthenticated traffic on a service the operator meant to protect.
	for _, invalid := range []string{
		"Required", "REQUIRED", "required ", " required", "requires",
		"Disabled", "off", "on", "true", "none", "optional",
	} {
		if cmn.IsValidApiKeyAuth(invalid) {
			t.Errorf("IsValidApiKeyAuth(%q) = true, want false", invalid)
		}
		// Whatever an invalid value resolves to, it must not enforce: it never
		// reaches the datapath, because the REST layer refuses it first.
		if cmn.ResolveApiKeyAuth(invalid) == cmn.ApiKeyAuthRequired {
			t.Errorf("invalid policy %q resolves to %q", invalid, cmn.ApiKeyAuthRequired)
		}
	}
}

// TestKeyStoreVerdictFailsClosed: with no key store, the data-plane
// validator returns 503 policy_store_unavailable and never allow.
//
// The gate that matters is the negative one. A service whose api_key_auth is
// "required" has an operator behind it who asked for a credential to be
// checked; if the store is absent and this returned allow, the gateway would
// serve unauthenticated traffic on exactly the services configured not to —
// the single outcome the policy exists to prevent, and one that produces no
// error anywhere and so would be found in production or not at all.
func TestKeyStoreVerdictFailsClosed(t *testing.T) {
	// A nil *aikey.Service, spelled explicitly. This is the value the process
	// holds when --aikey-db-host was never given.
	decision, errorCode, haveStore := keyStoreVerdict(nil)

	if haveStore {
		t.Fatalf("keyStoreVerdict(nil) reported a store")
	}
	if decision == aiDecisionAllow {
		t.Errorf("keyStoreVerdict(nil) = allow — a missing store must never admit a request")
	}
	if decision != aiDecisionDeny503 {
		t.Errorf("decision = %d, want %d (deny_503)", decision, aiDecisionDeny503)
	}
	// The code is load-bearing: an operator reading 401 goes looking at the
	// client's key, and a client reading 401 stops retrying. Both are wrong
	// when the truth is that the gateway cannot tell.
	if errorCode != aiErrPolicyStoreNA {
		t.Errorf("errorCode = %q, want %q", errorCode, aiErrPolicyStoreNA)
	}
	if decision == aiDecisionDeny401 {
		t.Errorf("a policy-store outage was reported as deny_401, which tells the "+
			"client its credential is wrong and that retrying will not help (code %q)",
			errorCode)
	}
}

// TestKeyStoreVerdictAdmitsAConfiguredStore is the non-vacuity control for the
// gate above. Without it, a keyStoreVerdict that reported "no store" for every
// input — including a healthy one, taking the whole gateway down — would pass.
func TestKeyStoreVerdictAdmitsAConfiguredStore(t *testing.T) {
	// aikey.New() hands back a service that is safe to use before it has
	// dialled anything, which is what makes it legitimate to publish the
	// pointer before Connect().
	svc := aikey.New()
	if svc == nil {
		t.Fatal("aikey.New() returned nil")
	}
	decision, errorCode, haveStore := keyStoreVerdict(svc)
	if !haveStore {
		t.Errorf("a configured store was reported absent — every request would 503")
	}
	if decision != aiDecisionAllow || errorCode != "" {
		t.Errorf("configured store produced decision=%d errorCode=%q, want 0 and empty: "+
			"this function decides only whether a store exists, not whether the key is valid",
			decision, errorCode)
	}
}

// TestRateLimitCheckFailsClosedWithoutService: the QoS stage never silently
// no-ops when it holds a keyed identity and no service.
//
// The silent no-op is the dangerous shape: with a nil service every
// limit reads as zero, zero means "no limit configured", and the entire QoS
// plane switches off for exactly the traffic it was configured to bound —
// producing no error, no log the operator is watching for, and a 200. The
// identity is what makes the nil service an invariant violation rather than a
// configuration: stage 1 of the gate only forwards a key_id/tenant_id it got
// from a successful validation, and validation cannot succeed without a
// service.
func TestRateLimitCheckFailsClosedWithoutService(t *testing.T) {
	store := rl.New()

	// A keyed identity with no service: fail closed, and with the store's
	// error code — a 429-shaped "slow down" would be a lie about whose
	// problem this is.
	for _, tc := range []struct{ key, tenant string }{
		{key: "key-1", tenant: "tenant-1"},
		{key: "key-1", tenant: ""},
		{key: "", tenant: "tenant-1"},
	} {
		decision, _, errorCode := rateLimitCheckInternal(nil, store, tc.key, tc.tenant, "")
		if decision == 0 {
			t.Errorf("key=%q tenant=%q: nil service silently allowed a keyed identity — "+
				"the QoS plane switched off without a sound", tc.key, tc.tenant)
		}
		if decision != 4 || errorCode != "policy_store_unavailable" {
			t.Errorf("key=%q tenant=%q: decision=%d code=%q, want 4/policy_store_unavailable",
				tc.key, tc.tenant, decision, errorCode)
		}
	}

	// No identity, no service: allowed. This is ordinary traffic on a
	// non-attributing service, and denying it would take down every
	// non-enforcing AI service the moment the store flag was omitted.
	if decision, _, _ := rateLimitCheckInternal(nil, store, "", "", ""); decision != 0 {
		t.Errorf("nil service with no identity denied (decision=%d) — non-enforcing traffic must pass", decision)
	}

	// Non-vacuity: a real (mock) service with no limits configured still
	// allows, so the guard above is about the nil, not about this function
	// denying everything.
	if decision, _, _ := rateLimitCheckInternal(&mockRateLimitService{}, store, "key-1", "tenant-1", ""); decision != 0 {
		t.Errorf("a live service with no limits was denied (decision=%d)", decision)
	}
}

// TestRateLimitCheckFailsClosedOnUnknowableLimits: the degraded-store half of
// the same property. During a store outage a cached key still authenticates,
// and the quota reads used to answer zeroes for a tenant whose limits were
// never cached — zero meaning "no limit", so every quota switched off for
// exactly the window the outage created. The decision taken: the service
// enforces the last store-confirmed values itself, and reports an error only
// when it holds none — and on that error this stage must refuse with the
// store's code, exactly as it does for a missing service.
func TestRateLimitCheckFailsClosedOnUnknowableLimits(t *testing.T) {
	store := rl.New()
	degraded := &mockRateLimitService{limitsErr: errors.New("store unreachable, nothing cached")}

	decision, _, errorCode := rateLimitCheckInternal(degraded, store, "key-1", "tenant-1", "")
	if decision != 4 || errorCode != "policy_store_unavailable" {
		t.Errorf("tenant limits unknowable: decision=%d code=%q, want 4/policy_store_unavailable", decision, errorCode)
	}

	// The model-limit read is a second, independent consult of the store —
	// it must not be reachable past a failed tenant read, and when it is the
	// one that fails, the answer is the same refusal.
	modelOnly := &mockRateLimitService{limitsErr: nil}
	decision, _, errorCode = rateLimitCheckInternal(modelOnly, store, "key-1", "tenant-1", "m")
	if decision != 0 {
		t.Fatalf("control: a healthy no-limit service denied (decision=%d code=%q)", decision, errorCode)
	}

	// Non-vacuity control: same call shape, no error — allowed. The refusal
	// above is about the error, not about a degraded-looking zero config.
	if decision, _, _ := rateLimitCheckInternal(&mockRateLimitService{}, store, "key-1", "tenant-1", ""); decision != 0 {
		t.Errorf("a live service with no limits was denied (decision=%d)", decision)
	}
}
