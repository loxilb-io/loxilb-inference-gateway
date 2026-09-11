/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX (Short Identifier): Apache-2.0
 */

package loxinet

import (
	"errors"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// The gates in this file pin the api_key_auth / jwt_auth_profile pairing a
// rule may carry (resolveJwtAuthProfileWith): JWT-capable modes REQUIRE a
// configured profile, other modes must not carry one, and on replace an
// omitted profile preserves the existing reference in lockstep with
// apiKeyAuthOnReplace.

func existsSet(names ...string) func(string) bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return func(n string) bool { return set[n] }
}

func TestJwtProfilePairingMatrix(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		existing string
		incoming string
		exists   func(string) bool
		want     string
		wantErr  error
	}{
		// JWT-capable modes: profile required, must exist.
		{"jwt with configured profile", cmn.ApiKeyAuthJWT, "", "realm-a", existsSet("realm-a"), "realm-a", nil},
		{"or-jwt with configured profile", cmn.ApiKeyAuthApiKeyOrJWT, "", "realm-a", existsSet("realm-a"), "realm-a", nil},
		{"jwt without profile refused", cmn.ApiKeyAuthJWT, "", "", existsSet("realm-a"), "", cmn.ErrJwtProfileRequired},
		{"jwt with unknown profile refused", cmn.ApiKeyAuthJWT, "", "ghost", existsSet("realm-a"), "", cmn.ErrJwtProfileRequired},

		// Replace: omitted profile preserves the existing reference; a rule
		// whose preserved reference no longer exists is refused rather than
		// silently re-installed pointing at nothing.
		{"replace preserves profile on omit", cmn.ApiKeyAuthJWT, "realm-a", "", existsSet("realm-a"), "realm-a", nil},
		{"replace can change profile", cmn.ApiKeyAuthJWT, "realm-a", "realm-b", existsSet("realm-a", "realm-b"), "realm-b", nil},
		{"replace with vanished preserved profile refused", cmn.ApiKeyAuthJWT, "ghost", "", existsSet("realm-a"), "", cmn.ErrJwtProfileRequired},

		// Non-JWT modes: a profile is a dangling reference and refused; the
		// resolved rule carries none (a mode change away from jwt drops the
		// old reference so it stops blocking profile deletion).
		{"required with profile refused", cmn.ApiKeyAuthRequired, "", "realm-a", existsSet("realm-a"), "", cmn.ErrJwtProfileNotApplicable},
		{"disabled with profile refused", cmn.ApiKeyAuthDisabled, "", "realm-a", existsSet("realm-a"), "", cmn.ErrJwtProfileNotApplicable},
		{"unset with profile refused", "", "", "realm-a", existsSet("realm-a"), "", cmn.ErrJwtProfileNotApplicable},
		{"mode change away from jwt drops reference", cmn.ApiKeyAuthRequired, "realm-a", "", existsSet("realm-a"), "", nil},
		{"plain rule carries nothing", "", "", "", existsSet(), "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveJwtAuthProfileWith(c.mode, c.existing, c.incoming, c.exists)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
			if got != c.want {
				t.Fatalf("profile = %q, want %q", got, c.want)
			}
		})
	}
}

// TestJwtProfileRefsBlockDeletion wires a holder's ruleRefs the way
// loxinet.go does and proves the delete guard reads the live rule scan:
// referenced → refused, dereferenced → allowed.
func TestJwtProfileRefsBlockDeletion(t *testing.T) {
	h := JWTAuthProfileInit()
	defer h.Manager().Close()

	refs := []string{"20.20.20.1:9000"}
	h.ruleRefs = func(name string) []string {
		if name == "realm-a" {
			return refs
		}
		return nil
	}

	if _, err := h.ProfileAdd(&cmn.JWTAuthProfileMod{
		Name:    "realm-a",
		Issuer:  "https://kc.example/realms/a",
		JWKSURL: "https://kc.example/realms/a/protocol/openid-connect/certs",
	}); err != nil {
		t.Fatalf("ProfileAdd: %v", err)
	}

	if _, err := h.ProfileDel("realm-a"); err == nil {
		t.Fatalf("delete succeeded while a rule references the profile")
	}

	refs = nil
	if _, err := h.ProfileDel("realm-a"); err != nil {
		t.Fatalf("delete refused after the last reference went away: %v", err)
	}
}
