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
	"fmt"
	"strings"
)

// Claims is the gateway-facing identity mapped out of a verified token.
// Everything here already passed signature and registered-claim checks.
type Claims struct {
	// Tenant is the metering identity; never empty (an unattributable
	// token is denied during mapping).
	Tenant string
	// User is the per-user QoS identity (usually sub). May be empty when
	// the configured user claim is absent — the QoS ladder then falls
	// through to tenant scope.
	User string
	// Username is display-only.
	Username string
	// Roles is the raw configured roles array, for logging/debugging.
	Roles []string

	// AllowedModels is the model accept-list derived from the token, in
	// force when AllowAllModels is false. Empty with AllowAllModels false
	// means every model is denied.
	AllowedModels []string
	// AllowAllModels is true only when the token yields no model claims
	// and the profile opted into allow-all.
	AllowAllModels bool
}

// Authorize checks a model name against the token-derived accept-list,
// with the same exact-string matching the API-key arm applies to its
// AllowedModels (pkg/loxinet/ai_gateway_dp.go). A non-nil error is a
// *VerdictError (403-class).
func (c *Claims) Authorize(model string) error {
	if c.AllowAllModels {
		return nil
	}
	for _, m := range c.AllowedModels {
		if m == model {
			return nil
		}
	}
	return deny403Model(fmt.Sprintf("model %q not in token's allowed set", model))
}

// mapClaims applies a profile's claim mapping to a verified payload.
func mapClaims(p *Profile, claims map[string]any) (*Claims, error) {
	out := &Claims{}

	// Tenant: the one mapping that can fail the request. A token that
	// cannot be attributed to a tenant cannot be metered, so it is denied
	// unless the profile names a fallback tenant. A present-but-non-string
	// (or empty) value is treated the same as absent: silently coercing
	// a number or object into a metering identity would let two different
	// tokens alias one bucket.
	if v, ok := lookupPath(claims, p.TenantClaim); ok {
		if s, isStr := v.(string); isStr && s != "" {
			out.Tenant = s
		}
	}
	if out.Tenant == "" {
		if p.DefaultTenant == "" {
			return nil, deny401(ReasonNoTenant,
				fmt.Sprintf("claim %q missing or not a usable string, and no default tenant", p.TenantClaim))
		}
		out.Tenant = p.DefaultTenant
	}

	if v, ok := lookupPath(claims, p.UserClaim); ok {
		if s, isStr := v.(string); isStr {
			out.User = s
		}
	}
	if v, ok := lookupPath(claims, p.UsernameClaim); ok {
		if s, isStr := v.(string); isStr {
			out.Username = s
		}
	}
	if v, ok := lookupPath(claims, p.RolesClaim); ok {
		out.Roles = stringSlice(v)
	}

	// Model authorization, in order of authority:
	//  1. the models claim, when configured AND present — authoritative
	//     even when empty (an explicit empty list is a grant of nothing,
	//     not an absence);
	//  2. roles carrying the model prefix;
	//  3. neither yields a list → the profile's model_authz mode decides
	//     (claims-required denies everything, allow-all admits anything).
	if p.ModelsClaim != "" {
		if v, ok := lookupPath(claims, p.ModelsClaim); ok {
			out.AllowedModels = stringSlice(v)
			return out, nil
		}
	}
	for _, r := range out.Roles {
		if strings.HasPrefix(r, p.ModelRolePrefix) {
			if m := r[len(p.ModelRolePrefix):]; m != "" {
				out.AllowedModels = append(out.AllowedModels, m)
			}
		}
	}
	if len(out.AllowedModels) == 0 && p.ModelAuthz == ModelAuthzAllowAll {
		out.AllowAllModels = true
	}
	return out, nil
}

// lookupPath walks a dot-path through nested JSON objects. Claim names
// containing a literal dot are unsupported (documented on Profile).
func lookupPath(claims map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	cur := any(claims)
	for _, seg := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// stringSlice extracts the string elements of a claim value that should be
// an array of strings. A bare string is accepted as a one-element list;
// non-string elements are dropped (they cannot name a model or role, and
// failing the whole token for one stray element would let a single bad
// mapper entry at the IdP lock every client out).
func stringSlice(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
