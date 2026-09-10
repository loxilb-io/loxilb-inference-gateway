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

	tk "github.com/loxilb-io/loxilib"

	"github.com/loxilb-io/loxilb/pkg/jwtauth"
)

// Upstream-hygiene flags returned to the C gate on an allowed bearer
// verdict. Values are lockstep with the AI_GW_AUTHF_* defines in
// loxilb-ebpf common/sockproxy_ai_gw.h.
const (
	aiAuthFlagStripAuthz  = 0x1
	aiAuthFlagFwdIdentity = 0x2
)

// Bearer-capture flags handed IN by the C gate; lockstep with the
// AI_GW_BEARERF_* defines in sockproxy_ai_gw.h.
const (
	aiBearerFlagOversize = 0x1
)

// bearerVerifier is the subset of the jwtauth manager the bearer arm uses.
// It is satisfied by *jwtauth.Manager and by test fakes.
type bearerVerifier interface {
	Verify(token []byte, profileName string) (*jwtauth.Claims, error)
}

// bearerUpstreamPolicy resolves a profile's upstream switches; satisfied by
// JWTAuthProfileH.ProfileUpstreamPolicy and by test fakes.
type bearerUpstreamPolicy func(profile string) (forwardIdentity, authzPassthrough, ok bool)

// validateBearerInternal is the pure-Go bearer verdict, separated from the
// CGO export so unit tests can exercise every arm without C types. It
// mirrors validateAPIKeyInternal's contract: decision selects the ladder
// arm (0 allow / 1=401 / 2=403 / 4=503), errorCode is the client-facing
// code, and the identities are meaningful only on allow.
//
// The 503 arms are the fail-closed ones and deliberately distinct from 401:
// an empty profile on a JWT-enforcing rule is an invariant violation (rule
// validation refuses that pairing, so seeing it means state corruption),
// and a keyset the manager has never fetched is the gateway's outage, not
// the client's credential — only the 503 is worth the client retrying.
func validateBearerInternal(mgr bearerVerifier, upstream bearerUpstreamPolicy,
	bearer, model, profile string, bearerFlags int) (decision int, tenant, user, errorCode string, authFlags int) {
	if profile == "" {
		tk.LogIt(tk.LogCritical,
			"[AIGateway] validate_bearer: JWT-enforcing rule with NO jwt_auth_profile — failing closed\n")
		return jwtauth.DecisionDeny503, "", "", jwtauth.CodeStoreUnavailable, 0
	}
	if bearerFlags&aiBearerFlagOversize != 0 {
		// The capture dropped the token rather than storing a truncated one:
		// a truncated JWT would fail verification anyway, but as an
		// indistinguishable bad_signature. Named here so the denial carries
		// its real reason.
		tk.LogIt(tk.LogWarning, "[AIGateway] validate_bearer: bearer token over capture cap (profile %s)\n", profile)
		return jwtauth.DecisionDeny401, "", "", jwtauth.CodeInvalidToken, 0
	}
	if bearer == "" {
		return jwtauth.DecisionDeny401, "", "", jwtauth.CodeMissingToken, 0
	}

	claims, err := mgr.Verify([]byte(bearer), profile)
	if err != nil {
		var ve *jwtauth.VerdictError
		if errors.As(err, &ve) {
			tk.LogIt(tk.LogInfo, "[AIGateway] validate_bearer: denied (%s): %v\n", ve.Reason, err)
			return ve.Decision, "", "", ve.Code, 0
		}
		tk.LogIt(tk.LogError, "[AIGateway] validate_bearer: unclassified verify error: %v\n", err)
		return jwtauth.DecisionDeny401, "", "", jwtauth.CodeInvalidToken, 0
	}

	// Model authorization binds to the gate's single body-first resolution;
	// a request naming no model anywhere skips the check, same as the
	// API-key arm.
	if model != "" {
		if err := claims.Authorize(model); err != nil {
			tk.LogIt(tk.LogWarning, "[AIGateway] validate_bearer: model %q not allowed for tenant %s\n",
				model, claims.Tenant)
			// The tenant is real (the token verified) — return it so the
			// denial is counted against the right tenant, mirroring the
			// API-key arm's 403.
			return jwtauth.DecisionDeny403, claims.Tenant, "", jwtauth.CodeModelNotAllowed, 0
		}
	}

	// Upstream switches from the profile. A profile that vanished between verify
	// and here (delete race) yields the fail-safe posture: strip the
	// Authorization header, forward nothing.
	flags := aiAuthFlagStripAuthz
	if fwd, passthrough, ok := upstream(profile); ok {
		flags = 0
		if !passthrough {
			flags |= aiAuthFlagStripAuthz
		}
		if fwd {
			flags |= aiAuthFlagFwdIdentity
		}
	}

	tk.LogIt(tk.LogInfo, "[AIGateway] validate_bearer: token verified for tenant %s user %s (profile %s)\n",
		claims.Tenant, claims.User, profile)
	return 0, claims.Tenant, claims.User, "", flags
}
