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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// maxClaimDepth bounds JSON nesting in token header and payload. Real
// tokens nest two or three levels (realm_access.roles); anything deeper is
// hostile or broken input, and unbounded recursion on attacker-controlled
// input is a stack to blow.
const maxClaimDepth = 32

// Verify checks one bearer token against a named profile and returns the
// mapped identity. A non-nil error is always a *VerdictError carrying the
// decision-ladder arm the gate should take. No network I/O happens here:
// key material is read from the profile's in-memory snapshot.
func (m *Manager) Verify(token []byte, profileName string) (*Claims, error) {
	ps := m.profile(profileName)
	if ps == nil {
		// A rule referencing a profile the manager does not hold is a
		// configuration wound, not a client fault. Fail closed as a store
		// problem; answering 401 would blame the client's credential.
		return nil, deny503(fmt.Sprintf("profile %q not active", profileName))
	}

	if len(token) == 0 {
		return nil, deny401(ReasonMissing, "no token presented")
	}
	if len(token) > MaxTokenBytes {
		return nil, deny401(ReasonOversize, fmt.Sprintf("token is %d bytes (max %d)", len(token), MaxTokenBytes))
	}

	hdr, err := parseCompactHeader(token)
	if err != nil {
		return nil, deny401(ReasonMalformed, err.Error())
	}

	// Algorithm gate. "none" and HS* are rejected before consulting the
	// profile: no configuration may enable them. Everything else must be
	// on the profile's accept-list.
	if hdr.Alg == "" || hdr.Alg == "none" || strings.HasPrefix(hdr.Alg, "HS") {
		return nil, deny401(ReasonMalformed, fmt.Sprintf("algorithm %q rejected", hdr.Alg))
	}
	algOK := false
	for _, a := range ps.prof.Algs {
		if a == hdr.Alg {
			algOK = true
			break
		}
	}
	if !algOK {
		return nil, deny401(ReasonMalformed, fmt.Sprintf("algorithm %q not in profile accept-list", hdr.Alg))
	}

	now := m.now()
	snap := ps.snap.Load()
	if snap == nil {
		return nil, deny503(fmt.Sprintf("profile %q has no keyset yet", profileName))
	}
	if now.Sub(snap.fetchedAt) > m.maxStaleness {
		return nil, deny503(fmt.Sprintf("profile %q keyset is stale (last success %s)",
			profileName, snap.fetchedAt.Format(time.RFC3339)))
	}

	cands := snap.set.candidates(hdr.Kid, hdr.Alg)
	if len(cands) == 0 {
		// Unknown kid: likely key rotation. Schedule a background refetch
		// (rate-limited) and deny this request now — the hot path never
		// blocks on the network, so the first request after a rotation
		// loses and its retry wins.
		m.requestRefetch(ps)
		return nil, deny401(ReasonUnknownKid, fmt.Sprintf("kid %q not in keyset", hdr.Kid))
	}

	var payload []byte
	verified := false
	for _, k := range cands {
		if p, err := verifyToken(token, hdr.Alg, k); err == nil {
			payload, verified = p, true
			break
		}
	}
	if !verified {
		return nil, deny401(ReasonBadSignature, "signature verification failed")
	}

	claims, derr := decodeStrictObject(payload)
	if derr != nil {
		return nil, deny401(ReasonMalformed, fmt.Sprintf("payload: %v", derr))
	}

	if verr := validateRegisteredClaims(&ps.prof, claims, now); verr != nil {
		return nil, verr
	}
	return mapClaims(&ps.prof, claims)
}

// compactHeader is the protected header subset the verifier acts on.
type compactHeader struct {
	Alg string
	Kid string
}

// parseCompactHeader splits a compact JWS and strictly decodes its
// protected header. Base64url is unpadded per RFC 7515; padded or otherwise
// irregular encodings are rejected rather than tolerated — a verifier that
// accepts encodings the signer never produces widens the attack surface
// for free.
func parseCompactHeader(token []byte) (*compactHeader, error) {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("token has %d segments, want 3", len(parts))
	}
	for i, p := range parts {
		if len(p) == 0 {
			return nil, fmt.Errorf("token segment %d is empty", i)
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(string(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("header segment: %v", err)
	}
	obj, err := decodeStrictObject(raw)
	if err != nil {
		return nil, fmt.Errorf("header: %v", err)
	}
	// RFC 7515: an unrecognized crit extension MUST cause rejection. This
	// package recognizes none, so any crit at all is a rejection.
	if _, ok := obj["crit"]; ok {
		return nil, fmt.Errorf("header carries crit extensions")
	}
	h := &compactHeader{}
	if v, ok := obj["alg"].(string); ok {
		h.Alg = v
	}
	if v, ok := obj["kid"].(string); ok {
		h.Kid = v
	}
	return h, nil
}

// validateRegisteredClaims enforces the time-window, issuer, and audience
// claims against the profile.
func validateRegisteredClaims(p *Profile, claims map[string]any, now time.Time) *VerdictError {
	leeway := time.Duration(p.LeewaySec) * time.Second

	// exp is mandatory. A token without an expiry never leaves the
	// revocation horizon (bearer-token revocation IS expiry here), so
	// treating it as valid would make the token immortal.
	exp, ok, err := numClaim(claims, "exp")
	if err != nil {
		return deny401(ReasonMalformed, "exp is not numeric")
	}
	if !ok {
		return deny401(ReasonMalformed, "exp claim missing")
	}
	if !now.Before(exp.Add(leeway)) {
		return deny401(ReasonExpired, fmt.Sprintf("token expired at %s", exp.Format(time.RFC3339)))
	}
	if nbf, ok, err := numClaim(claims, "nbf"); err != nil {
		return deny401(ReasonMalformed, "nbf is not numeric")
	} else if ok && now.Before(nbf.Add(-leeway)) {
		return deny401(ReasonExpired, fmt.Sprintf("token not valid before %s", nbf.Format(time.RFC3339)))
	}
	if iat, ok, err := numClaim(claims, "iat"); err != nil {
		return deny401(ReasonMalformed, "iat is not numeric")
	} else if ok && now.Before(iat.Add(-leeway)) {
		return deny401(ReasonExpired, fmt.Sprintf("token issued in the future (%s)", iat.Format(time.RFC3339)))
	}

	iss, _ := claims["iss"].(string)
	if iss != p.Issuer {
		return deny401(ReasonBadIssuer, fmt.Sprintf("iss %q does not match profile issuer", iss))
	}

	if len(p.Audiences) > 0 && !audienceMatches(p.Audiences, claims) {
		return deny401(ReasonBadAudience, "no configured audience in aud/azp")
	}
	return nil
}

// audienceMatches reports whether any configured audience appears in the
// token's aud (string or array) or azp (Keycloak puts the requesting
// client's id there).
func audienceMatches(want []string, claims map[string]any) bool {
	accept := func(v string) bool {
		for _, w := range want {
			if v == w {
				return true
			}
		}
		return false
	}
	switch aud := claims["aud"].(type) {
	case string:
		if accept(aud) {
			return true
		}
	case []any:
		for _, e := range aud {
			if s, ok := e.(string); ok && accept(s) {
				return true
			}
		}
	}
	if azp, ok := claims["azp"].(string); ok && accept(azp) {
		return true
	}
	return false
}

// numClaim reads a numeric-date claim. ok is false when absent; err is
// non-nil when present but not numeric.
func numClaim(claims map[string]any, name string) (t time.Time, ok bool, err error) {
	v, present := claims[name]
	if !present {
		return time.Time{}, false, nil
	}
	n, isNum := v.(json.Number)
	if !isNum {
		return time.Time{}, false, fmt.Errorf("claim %s is not numeric", name)
	}
	f, ferr := n.Float64()
	if ferr != nil {
		return time.Time{}, false, ferr
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)), true, nil
}

// decodeStrictObject decodes a JSON object, rejecting what encoding/json
// silently tolerates and JWT abuse leans on: duplicate keys at any level
// (last-writer-wins lets two parsers see two different tokens), trailing
// data, non-object top level, and pathological nesting. Numbers come back
// as json.Number.
func decodeStrictObject(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeStrictValue(dec, 0)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("top-level JSON value is not an object")
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("trailing data after JSON object")
	}
	return obj, nil
}

func decodeStrictValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxClaimDepth {
		return nil, fmt.Errorf("JSON nesting exceeds %d levels", maxClaimDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch delim {
	case '{':
		obj := make(map[string]any)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, fmt.Errorf("non-string object key")
			}
			if _, dup := obj[key]; dup {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			val, err := decodeStrictValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = val
		}
		if _, err := dec.Token(); err != nil { // consume '}'
			return nil, err
		}
		return obj, nil
	case '[':
		var arr []any
		for dec.More() {
			val, err := decodeStrictValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil { // consume ']'
			return nil, err
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unexpected delimiter %q", delim)
	}
}
