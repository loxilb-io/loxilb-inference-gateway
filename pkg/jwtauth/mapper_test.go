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

package jwtauth

import (
	"reflect"
	"testing"
)

// mapperProfile returns a normalized profile for direct mapper tests.
func mapperProfile(mutate func(*Profile)) *Profile {
	p := Profile{Name: "map", Issuer: "https://idp.example"}
	if mutate != nil {
		mutate(&p)
	}
	n := p.normalize()
	return &n
}

func TestMapClaimsTable(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Profile)
		claims  map[string]any
		want    Claims
		wantErr struct {
			code   string
			reason string
		}
	}{
		{
			name: "keycloak-shaped defaults with model roles",
			claims: map[string]any{
				"tenant_id":          "acme",
				"sub":                "u-1",
				"preferred_username": "alice",
				"realm_access": map[string]any{
					"roles": []any{"model:llama3", "model:qwen", "offline_access"},
				},
			},
			want: Claims{
				Tenant: "acme", User: "u-1", Username: "alice",
				Roles:         []string{"model:llama3", "model:qwen", "offline_access"},
				AllowedModels: []string{"llama3", "qwen"},
			},
		},
		{
			name:   "models claim wins over roles",
			mutate: func(p *Profile) { p.ModelsClaim = "allowed_models" },
			claims: map[string]any{
				"tenant_id":      "acme",
				"sub":            "u-1",
				"allowed_models": []any{"phi4"},
				"realm_access":   map[string]any{"roles": []any{"model:llama3"}},
			},
			want: Claims{
				Tenant: "acme", User: "u-1",
				Roles:         []string{"model:llama3"},
				AllowedModels: []string{"phi4"},
			},
		},
		{
			name:   "explicit empty models claim grants nothing",
			mutate: func(p *Profile) { p.ModelsClaim = "allowed_models"; p.ModelAuthz = ModelAuthzAllowAll },
			claims: map[string]any{
				"tenant_id":      "acme",
				"allowed_models": []any{},
				"realm_access":   map[string]any{"roles": []any{"model:llama3"}},
			},
			// The claim is present, so it is authoritative: no models, and
			// no fallback to roles or to allow-all.
			want: Claims{
				Tenant: "acme", Roles: []string{"model:llama3"},
				AllowedModels: nil, AllowAllModels: false,
			},
		},
		{
			name:   "absent models claim falls back to roles",
			mutate: func(p *Profile) { p.ModelsClaim = "allowed_models" },
			claims: map[string]any{
				"tenant_id":    "acme",
				"realm_access": map[string]any{"roles": []any{"model:llama3"}},
			},
			want: Claims{
				Tenant: "acme",
				Roles:  []string{"model:llama3"}, AllowedModels: []string{"llama3"},
			},
		},
		{
			name:   "no model claims, claims-required denies",
			claims: map[string]any{"tenant_id": "acme"},
			want:   Claims{Tenant: "acme", AllowAllModels: false},
		},
		{
			name:   "no model claims, allow-all admits",
			mutate: func(p *Profile) { p.ModelAuthz = ModelAuthzAllowAll },
			claims: map[string]any{"tenant_id": "acme"},
			want:   Claims{Tenant: "acme", AllowAllModels: true},
		},
		{
			name:   "custom dot-path tenant",
			mutate: func(p *Profile) { p.TenantClaim = "org.unit.id" },
			claims: map[string]any{
				"org": map[string]any{"unit": map[string]any{"id": "acme"}},
			},
			want: Claims{Tenant: "acme"},
		},
		{
			name:   "missing tenant denied",
			claims: map[string]any{"sub": "u-1"},
			wantErr: struct{ code, reason string }{
				code: CodeInvalidToken, reason: ReasonNoTenant,
			},
		},
		{
			name:   "empty-string tenant denied",
			claims: map[string]any{"tenant_id": ""},
			wantErr: struct{ code, reason string }{
				code: CodeInvalidToken, reason: ReasonNoTenant,
			},
		},
		{
			name:   "non-string tenant denied",
			claims: map[string]any{"tenant_id": map[string]any{"id": "acme"}},
			wantErr: struct{ code, reason string }{
				code: CodeInvalidToken, reason: ReasonNoTenant,
			},
		},
		{
			name:   "missing tenant with default tenant",
			mutate: func(p *Profile) { p.DefaultTenant = "shared" },
			claims: map[string]any{"sub": "u-1"},
			want:   Claims{Tenant: "shared", User: "u-1"},
		},
		{
			name:   "custom role prefix",
			mutate: func(p *Profile) { p.ModelRolePrefix = "ai/" },
			claims: map[string]any{
				"tenant_id":    "acme",
				"realm_access": map[string]any{"roles": []any{"ai/llama3", "model:ignored"}},
			},
			want: Claims{
				Tenant: "acme",
				Roles:  []string{"ai/llama3", "model:ignored"}, AllowedModels: []string{"llama3"},
			},
		},
		{
			name: "prefix-only role names no model",
			claims: map[string]any{
				"tenant_id":    "acme",
				"realm_access": map[string]any{"roles": []any{"model:"}},
			},
			want: Claims{Tenant: "acme", Roles: []string{"model:"}},
		},
		{
			name: "non-string role elements dropped",
			claims: map[string]any{
				"tenant_id":    "acme",
				"realm_access": map[string]any{"roles": []any{"model:llama3", 42, nil}},
			},
			want: Claims{Tenant: "acme", Roles: []string{"model:llama3"}, AllowedModels: []string{"llama3"}},
		},
		{
			name:   "bare string models claim accepted as one-element list",
			mutate: func(p *Profile) { p.ModelsClaim = "allowed_models" },
			claims: map[string]any{"tenant_id": "acme", "allowed_models": "llama3"},
			want:   Claims{Tenant: "acme", AllowedModels: []string{"llama3"}},
		},
		{
			name:   "non-string user ignored",
			claims: map[string]any{"tenant_id": "acme", "sub": 42},
			want:   Claims{Tenant: "acme"},
		},
		{
			name:   "dot-path through non-object stops",
			mutate: func(p *Profile) { p.TenantClaim = "org.id"; p.DefaultTenant = "shared" },
			claims: map[string]any{"org": "flat-string"},
			want:   Claims{Tenant: "shared"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapClaims(mapperProfile(tc.mutate), tc.claims)
			if tc.wantErr.code != "" {
				verdict(t, err, DecisionDeny401, tc.wantErr.code, tc.wantErr.reason)
				return
			}
			if err != nil {
				t.Fatalf("mapClaims: %v", err)
			}
			if !reflect.DeepEqual(*got, tc.want) {
				t.Fatalf("claims = %+v, want %+v", *got, tc.want)
			}
		})
	}
}

func TestClaimsAuthorize(t *testing.T) {
	restricted := &Claims{Tenant: "acme", AllowedModels: []string{"llama3", "qwen"}}
	if err := restricted.Authorize("llama3"); err != nil {
		t.Fatalf("allowed model denied: %v", err)
	}
	err := restricted.Authorize("gpt-oss")
	verdict(t, err, DecisionDeny403, CodeModelNotAllowed, ReasonModelDenied)
	// Matching is exact-string, same as the API-key arm: no prefixes, no
	// case folding.
	verdict(t, restricted.Authorize("LLAMA3"), DecisionDeny403, CodeModelNotAllowed, ReasonModelDenied)
	verdict(t, restricted.Authorize("llama3 "), DecisionDeny403, CodeModelNotAllowed, ReasonModelDenied)

	open := &Claims{Tenant: "acme", AllowAllModels: true}
	if err := open.Authorize("anything"); err != nil {
		t.Fatalf("allow-all denied: %v", err)
	}

	empty := &Claims{Tenant: "acme"}
	verdict(t, empty.Authorize("llama3"), DecisionDeny403, CodeModelNotAllowed, ReasonModelDenied)
	// The empty model name is not special: an empty accept-list denies it
	// too, and it never matches a named entry.
	verdict(t, empty.Authorize(""), DecisionDeny403, CodeModelNotAllowed, ReasonModelDenied)
}

func TestLookupPath(t *testing.T) {
	claims := map[string]any{
		"a":    map[string]any{"b": map[string]any{"c": "deep"}},
		"flat": "top",
	}
	if v, ok := lookupPath(claims, "a.b.c"); !ok || v != "deep" {
		t.Fatalf("a.b.c = %v, %v", v, ok)
	}
	if v, ok := lookupPath(claims, "flat"); !ok || v != "top" {
		t.Fatalf("flat = %v, %v", v, ok)
	}
	for _, path := range []string{"", "a.b.c.d", "a.x", "x", "flat.deeper"} {
		if _, ok := lookupPath(claims, path); ok {
			t.Fatalf("path %q unexpectedly resolved", path)
		}
	}
}

// TestMapClaimsRejectsUnsafeIdentity covers the header-injection path. The
// gateway splices the mapped tenant and user into upstream request headers
// (X-Auth-Tenant / X-Auth-User) with a plain "name: value\r\n" write and no
// escaping, so a claim carrying CR or LF does not travel as a value — it
// ends the header and starts another one, inside a request the backend
// trusts precisely because the gateway built it.
//
// A signature does not make a claim safe. It proves the IdP minted it, and
// IdPs mint what their user directories hold: tenant attributes filled by
// self-service registration or directory sync, and user claims often mapped
// to an address the account owner chooses. The identity must therefore be
// rejected here, before it can reach a header, a log line, or a metric
// label.
func TestMapClaimsRejectsUnsafeIdentity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Profile)
		claims map[string]any
	}{
		{
			name:   "CRLF in tenant splices a second header",
			claims: map[string]any{"tenant_id": "acme\r\nX-Auth-User: admin", "sub": "u1"},
		},
		{
			name:   "bare LF in tenant",
			claims: map[string]any{"tenant_id": "acme\nX-Api-Key: stolen", "sub": "u1"},
		},
		{
			name:   "bare CR in tenant",
			claims: map[string]any{"tenant_id": "acme\rX-Api-Key: stolen", "sub": "u1"},
		},
		{
			name:   "NUL truncates the value in the C copy",
			claims: map[string]any{"tenant_id": "acme\x00evil", "sub": "u1"},
		},
		{
			name:   "CRLF in the user claim",
			claims: map[string]any{"tenant_id": "acme", "sub": "u1\r\nX-Auth-Tenant: other"},
		},
		{
			name:   "CRLF in the display username reaches log lines",
			claims: map[string]any{"tenant_id": "acme", "sub": "u1", "preferred_username": "bob\r\nfake log entry"},
		},
		{
			name:   "DEL and other C0 controls",
			claims: map[string]any{"tenant_id": "acme\x7f\x01", "sub": "u1"},
		},
		{
			// The tenant arrives from the profile rather than the token,
			// but it lands in the same header, so it cannot be exempt.
			name:   "unsafe default tenant",
			mutate: func(p *Profile) { p.DefaultTenant = "acme\r\nX-Auth-User: admin" },
			claims: map[string]any{"sub": "u1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mapClaims(mapperProfile(tc.mutate), tc.claims)
			if err == nil {
				t.Fatal("unsafe identity accepted — it would be spliced into an upstream header verbatim")
			}
			verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonUnsafeIdentity)
		})
	}
}

// TestMapClaimsRejectsOversizeIdentity covers silent truncation. The data
// plane copies identity into fixed 128-byte buffers with strncpy, keeping
// 127 bytes and dropping the rest without a word. Two tenants sharing a
// long prefix therefore become ONE identity downstream: the same quota
// bucket, the same X-Auth-Tenant at the backend, the same metric label.
// An identity that cannot be carried whole must be refused, not shortened
// into somebody else's.
func TestMapClaimsRejectsOversizeIdentity(t *testing.T) {
	long := make([]byte, identityMaxBytes+1)
	for i := range long {
		long[i] = 'a'
	}
	atLimit := string(long[:identityMaxBytes])
	overLimit := string(long)

	if _, err := mapClaims(mapperProfile(nil), map[string]any{
		"tenant_id": atLimit, "sub": "u1",
	}); err != nil {
		t.Fatalf("identity at the limit rejected: %v", err)
	}

	for _, tc := range []struct {
		name   string
		claims map[string]any
	}{
		{"tenant over the limit", map[string]any{"tenant_id": overLimit, "sub": "u1"}},
		{"user over the limit", map[string]any{"tenant_id": "acme", "sub": overLimit}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mapClaims(mapperProfile(nil), tc.claims)
			if err == nil {
				t.Fatal("oversize identity accepted — the data plane would truncate it to 127 bytes " +
					"and alias it onto every identity sharing that prefix")
			}
			verdict(t, err, DecisionDeny401, CodeInvalidToken, ReasonUnsafeIdentity)
		})
	}
}
