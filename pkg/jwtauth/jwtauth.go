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

// Package jwtauth verifies data-plane bearer tokens (JWTs) against a
// configured identity provider and maps their claims onto the gateway's
// admission identity (tenant, user, allowed models).
//
// It is deliberately free of cgo and of any REST dependency, for the same
// reason pkg/authz is: the packages that link the eBPF datapath library
// cannot host unit-testable logic, so everything decidable lives here and
// the CGO export is reduced to wiring.
//
// Design posture (mirrors the API-key gate it sits beside):
//
//   - Fail closed. A profile whose keyset was never fetched, or whose last
//     successful fetch is older than the staleness cutoff, answers
//     "store unavailable" (503-class) — never allow.
//   - No network I/O on the request path. Verification reads an in-memory
//     keyset snapshot; JWKS fetching is background goroutine work.
//   - The client-facing 401 surface is deliberately coarse (invalid_token
//     vs token_expired only); fine-grained reasons are for metrics and logs.
//   - The identity provider owns the claim schema. Every claim extraction
//     is a configured dot-path; nothing about claim names is hardcoded
//     beyond Keycloak-shaped defaults.
package jwtauth

import (
	"fmt"
	"net/url"
	"strings"
)

// MaxTokenBytes bounds the serialized JWT the verifier accepts. It mirrors
// the C-side capture cap for the Authorization header (loxilb-ebpf
// common/sockproxy_http.c); anything longer is denied before parsing.
const MaxTokenBytes = 4096

// Model-authorization modes for a profile whose token yields no model list.
const (
	// ModelAuthzClaimsRequired denies every model when neither the models
	// claim nor role-derived models are present. Fail-closed default.
	ModelAuthzClaimsRequired = "claims-required"
	// ModelAuthzAllowAll admits any model when the token carries no model
	// authorization claims; the token itself still had to verify.
	ModelAuthzAllowAll = "allow-all"
)

// supportedAlgs is the closed set of signature algorithms this package will
// ever accept. Symmetric algorithms (HS*) are excluded categorically: the
// gateway holds only the IdP's public keys, so a symmetric configuration
// could only be satisfied by sharing a secret with every verifier, which
// defeats the point of asymmetric issuance. "none" is likewise rejected
// unconditionally in the verifier, independent of configuration.
var supportedAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
}

// Defaults applied by normalize() when the corresponding field is zero.
const (
	defaultLeewaySec  = 30
	defaultRefreshSec = 3600

	defaultTenantClaim     = "tenant_id"
	defaultUserClaim       = "sub"
	defaultRolesClaim      = "realm_access.roles"
	defaultModelRolePrefix = "model:"
	defaultUsernameClaim   = "preferred_username"
)

// Profile is one issuer configuration. LB rules reference a profile by name;
// several rules (VIPs) may share one profile, and several profiles may be
// active at once (multiple realms/issuers).
//
// Zero values select documented defaults where a default exists; there is no
// field where zero is a meaningful non-default configuration.
type Profile struct {
	// Name is the profile's identity. Referenced by LB rules.
	Name string

	// Issuer is the exact string the token's iss claim must equal. It must
	// be an http(s) URL; when JWKSURL is empty it is also the base for OIDC
	// discovery (<issuer>/.well-known/openid-configuration).
	Issuer string

	// JWKSURL overrides OIDC discovery when set.
	JWKSURL string

	// Audiences is the accept-list matched against the token's aud values
	// and azp. At least one must match. Empty skips the audience check
	// (logged once at activation — this is a deliberate loosening).
	Audiences []string

	// Algs is the signature-algorithm accept-list. Default: RS256, ES256.
	Algs []string

	// LeewaySec is the clock-skew allowance for exp/nbf/iat. Default 30.
	LeewaySec int

	// RefreshSec is the periodic JWKS refresh interval. Default 3600.
	RefreshSec int

	// Claim mapping (dot-paths into the token payload). A path segment is
	// split on "."; claim names containing a literal dot are unsupported.
	TenantClaim     string // default "tenant_id"
	UserClaim       string // default "sub"
	ModelsClaim     string // no default: unset means role-derived models
	RolesClaim      string // default "realm_access.roles"
	ModelRolePrefix string // default "model:"
	UsernameClaim   string // default "preferred_username"

	// ModelAuthz decides what happens when no model list can be derived
	// from the token. Default ModelAuthzClaimsRequired (deny).
	ModelAuthz string

	// DefaultTenant is used when the tenant claim is absent. Empty means
	// an unattributable token is denied (401): a request that cannot be
	// attributed cannot be metered.
	DefaultTenant string

	// ForwardIdentity injects verified X-Auth-* identity headers upstream.
	// Consumed by the gate wiring, not by this package's verifier.
	ForwardIdentity bool

	// AuthorizationPassthrough leaves the client's Authorization header on
	// the upstream request instead of stripping it. Consumed by the gate
	// wiring, not by this package's verifier.
	AuthorizationPassthrough bool
}

// normalize returns a copy of p with defaults applied. Validation runs on
// the normalized copy so error messages describe effective configuration.
func (p Profile) normalize() Profile {
	if p.LeewaySec == 0 {
		p.LeewaySec = defaultLeewaySec
	}
	if p.RefreshSec == 0 {
		p.RefreshSec = defaultRefreshSec
	}
	if len(p.Algs) == 0 {
		p.Algs = []string{"RS256", "ES256"}
	}
	if p.TenantClaim == "" {
		p.TenantClaim = defaultTenantClaim
	}
	if p.UserClaim == "" {
		p.UserClaim = defaultUserClaim
	}
	if p.RolesClaim == "" {
		p.RolesClaim = defaultRolesClaim
	}
	if p.ModelRolePrefix == "" {
		p.ModelRolePrefix = defaultModelRolePrefix
	}
	if p.UsernameClaim == "" {
		p.UsernameClaim = defaultUsernameClaim
	}
	if p.ModelAuthz == "" {
		p.ModelAuthz = ModelAuthzClaimsRequired
	}
	return p
}

// validate checks a normalized profile. It returns a plain error (not a
// VerdictError): profile problems are configuration-time, not request-time.
func (p Profile) validate() error {
	if p.Name == "" {
		return fmt.Errorf("jwtauth: profile name is required")
	}
	if err := checkHTTPURL("issuer", p.Issuer); err != nil {
		return err
	}
	if p.JWKSURL != "" {
		if err := checkHTTPURL("jwks_url", p.JWKSURL); err != nil {
			return err
		}
	}
	for _, a := range p.Algs {
		if a == "none" || strings.HasPrefix(a, "HS") {
			return fmt.Errorf("jwtauth: profile %s: algorithm %q is not permitted", p.Name, a)
		}
		if !supportedAlgs[a] {
			return fmt.Errorf("jwtauth: profile %s: unsupported algorithm %q", p.Name, a)
		}
	}
	if p.LeewaySec < 0 {
		return fmt.Errorf("jwtauth: profile %s: negative leeway", p.Name)
	}
	if p.RefreshSec < 0 {
		return fmt.Errorf("jwtauth: profile %s: negative refresh interval", p.Name)
	}
	switch p.ModelAuthz {
	case ModelAuthzClaimsRequired, ModelAuthzAllowAll:
	default:
		return fmt.Errorf("jwtauth: profile %s: unknown model_authz %q", p.Name, p.ModelAuthz)
	}
	return nil
}

func checkHTTPURL(field, raw string) error {
	if raw == "" {
		return fmt.Errorf("jwtauth: %s is required", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("jwtauth: %s: %v", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("jwtauth: %s: scheme %q is not http(s)", field, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("jwtauth: %s: missing host", field)
	}
	return nil
}
