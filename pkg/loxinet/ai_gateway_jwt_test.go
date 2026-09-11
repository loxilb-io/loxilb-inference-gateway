/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX (Short Identifier): Apache-2.0
 */

package loxinet

import (
	"errors"
	"testing"

	"github.com/loxilb-io/loxilb/pkg/jwtauth"
)

// The gates in this file pin the pure-Go half of the bearer admission arm
// (validateBearerInternal): which ladder arm each failure takes, that the
// 503s stay 503s (fail-closed, retryable) and the 401s stay 401s
// (credential verdicts, not worth retrying), and what the upstream flags come
// out as for each profile posture.

// fakeVerifier returns a canned verdict; it records the token and profile
// it was asked about so dispatch mistakes surface as wrong-argument
// failures, not silently-green tests.
type fakeVerifier struct {
	claims  *jwtauth.Claims
	err     error
	gotTok  string
	gotProf string
	calls   int
}

func (f *fakeVerifier) Verify(token []byte, profileName string) (*jwtauth.Claims, error) {
	f.calls++
	f.gotTok = string(token)
	f.gotProf = profileName
	return f.claims, f.err
}

func staticPolicy(fwd, passthrough, ok bool) bearerUpstreamPolicy {
	return func(string) (bool, bool, bool) { return fwd, passthrough, ok }
}

// TestValidateBearerEmptyProfileFailsClosed: a JWT-enforcing rule whose
// profile reference is empty is an invariant violation (rule validation
// refuses the pairing), and the answer is the gateway's outage arm — 503,
// never allow and never a 401 that blames the client's credential.
func TestValidateBearerEmptyProfileFailsClosed(t *testing.T) {
	v := &fakeVerifier{claims: &jwtauth.Claims{Tenant: "t1", AllowAllModels: true}}
	dec, _, _, code, _ := validateBearerInternal(v, staticPolicy(false, false, true),
		"sometoken", "m", "", 0)
	if dec != jwtauth.DecisionDeny503 || code != jwtauth.CodeStoreUnavailable {
		t.Fatalf("empty profile: got decision=%d code=%q, want 503/%s",
			dec, code, jwtauth.CodeStoreUnavailable)
	}
	if v.calls != 0 {
		t.Fatalf("verifier consulted despite missing profile (%d calls)", v.calls)
	}
}

// TestValidateBearerOversizeDenies401: an oversize capture dropped the
// token, and the verdict must be 401 invalid_token WITHOUT consulting the
// verifier — there is no token to verify, and handing it "" would misfile
// the denial as missing_token.
func TestValidateBearerOversizeDenies401(t *testing.T) {
	v := &fakeVerifier{claims: &jwtauth.Claims{Tenant: "t1", AllowAllModels: true}}
	dec, _, _, code, _ := validateBearerInternal(v, staticPolicy(false, false, true),
		"", "m", "prof", aiBearerFlagOversize)
	if dec != jwtauth.DecisionDeny401 || code != jwtauth.CodeInvalidToken {
		t.Fatalf("oversize: got decision=%d code=%q, want 401/%s",
			dec, code, jwtauth.CodeInvalidToken)
	}
	if v.calls != 0 {
		t.Fatalf("verifier consulted for an oversize-dropped token (%d calls)", v.calls)
	}
}

// TestValidateBearerMissingToken: no bearer at all is the coarse 401
// missing_token — the arm that also answers mode 4's neither-credential
// case.
func TestValidateBearerMissingToken(t *testing.T) {
	v := &fakeVerifier{}
	dec, _, _, code, _ := validateBearerInternal(v, staticPolicy(false, false, true),
		"", "m", "prof", 0)
	if dec != jwtauth.DecisionDeny401 || code != jwtauth.CodeMissingToken {
		t.Fatalf("missing: got decision=%d code=%q, want 401/%s",
			dec, code, jwtauth.CodeMissingToken)
	}
}

// TestValidateBearerVerdictPassthrough: a VerdictError from the verifier
// keeps ITS decision and code — the export must not re-classify what the
// verify layer already decided (an expired token stays token_expired, a
// cold keyset stays a 503).
func TestValidateBearerVerdictPassthrough(t *testing.T) {
	cases := []struct {
		name string
		err  *jwtauth.VerdictError
	}{
		{"expired", &jwtauth.VerdictError{Decision: jwtauth.DecisionDeny401, Code: jwtauth.CodeTokenExpired, Reason: jwtauth.ReasonExpired}},
		{"bad-sig", &jwtauth.VerdictError{Decision: jwtauth.DecisionDeny401, Code: jwtauth.CodeInvalidToken, Reason: jwtauth.ReasonBadSignature}},
		{"no-keyset", &jwtauth.VerdictError{Decision: jwtauth.DecisionDeny503, Code: jwtauth.CodeStoreUnavailable, Reason: jwtauth.ReasonNoKeyset}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := &fakeVerifier{err: c.err}
			dec, _, _, code, _ := validateBearerInternal(v, staticPolicy(false, false, true),
				"tok", "m", "prof", 0)
			if dec != c.err.Decision || code != c.err.Code {
				t.Fatalf("got decision=%d code=%q, want %d/%s", dec, code, c.err.Decision, c.err.Code)
			}
		})
	}
}

// TestValidateBearerUnclassifiedErrorIs401: an error that is not a
// VerdictError must still deny — 401 invalid_token, never allow. A verify
// layer bug must fail closed.
func TestValidateBearerUnclassifiedErrorIs401(t *testing.T) {
	v := &fakeVerifier{err: errors.New("plumbing exploded")}
	dec, _, _, code, _ := validateBearerInternal(v, staticPolicy(false, false, true),
		"tok", "m", "prof", 0)
	if dec != jwtauth.DecisionDeny401 || code != jwtauth.CodeInvalidToken {
		t.Fatalf("got decision=%d code=%q, want 401/%s", dec, code, jwtauth.CodeInvalidToken)
	}
}

// TestValidateBearerModelDenied403CarriesTenant: the model gate is the one
// deny that happens AFTER the token verified, so the tenant is real and
// must ride out with the 403 for metric attribution — mirroring the
// API-key arm's 403 contract.
func TestValidateBearerModelDenied403CarriesTenant(t *testing.T) {
	v := &fakeVerifier{claims: &jwtauth.Claims{
		Tenant: "acme", User: "u1", AllowedModels: []string{"allowed-model"}}}
	dec, tenant, _, code, _ := validateBearerInternal(v, staticPolicy(false, false, true),
		"tok", "other-model", "prof", 0)
	if dec != jwtauth.DecisionDeny403 || code != jwtauth.CodeModelNotAllowed {
		t.Fatalf("got decision=%d code=%q, want 403/%s", dec, code, jwtauth.CodeModelNotAllowed)
	}
	if tenant != "acme" {
		t.Fatalf("403 lost its tenant: got %q, want acme", tenant)
	}
}

// TestValidateBearerNoModelSkipsAuthorize: a request naming no model
// anywhere skips model authorization, same as the API-key arm — the
// accept-list binds to a named model, not to the request's existence.
func TestValidateBearerNoModelSkipsAuthorize(t *testing.T) {
	v := &fakeVerifier{claims: &jwtauth.Claims{
		Tenant: "acme", User: "u1", AllowedModels: []string{"only-this"}}}
	dec, tenant, user, _, _ := validateBearerInternal(v, staticPolicy(false, false, true),
		"tok", "", "prof", 0)
	if dec != 0 || tenant != "acme" || user != "u1" {
		t.Fatalf("model-less allow broken: dec=%d tenant=%q user=%q", dec, tenant, user)
	}
}

// TestValidateBearerUpstreamFlagMatrix pins the upstream-switch encoding for
// every profile posture, including the fail-safe row: a profile that
// vanished between verify and flag resolution strips Authorization and
// forwards nothing.
func TestValidateBearerUpstreamFlagMatrix(t *testing.T) {
	cases := []struct {
		name        string
		fwd         bool
		passthrough bool
		ok          bool
		wantFlags   int
	}{
		{"default: strip, no forward", false, false, true, aiAuthFlagStripAuthz},
		{"forward identity", true, false, true, aiAuthFlagStripAuthz | aiAuthFlagFwdIdentity},
		{"passthrough only", false, true, true, 0},
		{"passthrough + forward", true, true, true, aiAuthFlagFwdIdentity},
		{"profile vanished: fail-safe strip", true, true, false, aiAuthFlagStripAuthz},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := &fakeVerifier{claims: &jwtauth.Claims{Tenant: "t", User: "u", AllowAllModels: true}}
			dec, _, _, _, flags := validateBearerInternal(v,
				staticPolicy(c.fwd, c.passthrough, c.ok), "tok", "m", "prof", 0)
			if dec != 0 {
				t.Fatalf("unexpected deny: %d", dec)
			}
			if flags != c.wantFlags {
				t.Fatalf("flags = %#x, want %#x", flags, c.wantFlags)
			}
		})
	}
}

// TestValidateBearerDispatchArguments: the token and profile handed to the
// verifier are the ones the C gate captured — no trimming, no defaulting.
func TestValidateBearerDispatchArguments(t *testing.T) {
	v := &fakeVerifier{claims: &jwtauth.Claims{Tenant: "t", AllowAllModels: true}}
	_, _, _, _, _ = validateBearerInternal(v, staticPolicy(false, false, true),
		"eyJ.token.sig", "m", "realm-a", 0)
	if v.gotTok != "eyJ.token.sig" || v.gotProf != "realm-a" {
		t.Fatalf("verifier saw (%q, %q), want the captured token and profile", v.gotTok, v.gotProf)
	}
}
