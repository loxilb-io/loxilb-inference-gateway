/*
 * Copyright (c) 2026 NetLOX Inc
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

// l7policy.go — server-side validation for the dedicated L7_POLICY resource
// (L7PolicyArg and children, defined in common.go).
//
// The validation lives here, next to the types, because TWO independent
// intake paths must enforce the exact same rules: the REST handler
// (api/restapi/handler/l7policy.go, which maps a violation to a 400) and
// the config-restore apply path (pkg/loxinet NetL7PolicyAdd, which a
// snapshot document reaches without ever passing through the REST layer).
// A restored document is operator-editable on disk, so the apply path
// validating for itself is what keeps a hand-crafted unknown enum value a
// loud error instead of a silently unmatched no-op condition.
//
// The rules are the Octavia per-type constraints:
//
//   - FILE_TYPE accepts ONLY EQUAL_TO or REGEX.
//   - key is REQUIRED for HEADER / COOKIE / QUERY.
//   - a REGEX value is TRY-COMPILED at config time (malformed => error; the
//     authoritative single regcomp happens at attach in the C side).
//   - a REDIRECT statusCode must be one of {301,302,303,307,308} (0/absent
//     => 302); a REJECT statusCode defaults to 403 and must be a 4xx.
//   - insertHeaders are bounded and CRLF/control-char guarded.
//   - sessionPersistence HTTP_COOKIE is mutually exclusive with
//     APP_COOKIE/SOURCE_IP per pool.
package common

import (
	"fmt"
	"regexp"
	"strings"
)

// Canonical L7 enum values (mirror the swagger enums + the C IR).
const (
	L7FieldHost     = "HOST"
	L7FieldPath     = "PATH"
	L7FieldHeader   = "HEADER"
	L7FieldCookie   = "COOKIE"
	L7FieldFileType = "FILE_TYPE"
	L7FieldMethod   = "METHOD"
	L7FieldQuery    = "QUERY"

	L7OpEqual         = "EQUAL_TO"
	L7OpStartsWith    = "STARTS_WITH"
	L7OpSegmentPrefix = "SEGMENT_PREFIX"
	L7OpEndsWith      = "ENDS_WITH"
	L7OpContains      = "CONTAINS"
	L7OpRegex         = "REGEX"

	L7ActForward  = "FORWARD"
	L7ActRedirect = "REDIRECT"
	L7ActReject   = "REJECT"

	// insertHeaders ops + bounds. L7HdrMaxFilters MUST match the C
	// L7_MAX_HDR_FILTERS (sockproxy_l7policy.h) — the data-plane copy
	// truncates above it, so validation rejects over-count with an error
	// rather than silently dropping ops.
	L7HdrOpSet      = "SET"
	L7HdrOpAdd      = "ADD"
	L7HdrOpRemove   = "REMOVE"
	L7HdrMaxFilters = 8
	L7HdrNameMax    = 63  // L7_HDR_NAME_MAX-1 (NUL)
	L7HdrValueMax   = 255 // L7_HDR_VALUE_MAX-1 (NUL)
)

// l7ValidHdrOps gates the insertHeaders op enum (anything else => error,
// never a silent SET).
var l7ValidHdrOps = map[string]bool{L7HdrOpSet: true, L7HdrOpAdd: true, L7HdrOpRemove: true}

// l7ValidFields / l7ValidOps gate unknown enum values (a future SSL_* field
// is rejected here — it must not silently fall through as an unmatched
// no-op).
var l7ValidFields = map[string]bool{
	L7FieldHost: true, L7FieldPath: true, L7FieldHeader: true, L7FieldCookie: true,
	L7FieldFileType: true, L7FieldMethod: true, L7FieldQuery: true,
}

var l7ValidOps = map[string]bool{
	L7OpEqual: true, L7OpStartsWith: true, L7OpSegmentPrefix: true,
	L7OpEndsWith: true, L7OpContains: true, L7OpRegex: true,
}

// l7ValidRedirectStatus is the redirect status-code allow-list
// (Octavia/Gateway constraint).
var l7ValidRedirectStatus = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

// ValidateL7Policy enforces the Octavia per-type rules server-side. It
// returns a non-nil error describing the FIRST violation (the REST handler
// maps that to a 400; the restore apply path fails the domain). It is a
// pure function so unit tests can drive every per-type rule without the
// generated swagger types.
func ValidateL7Policy(p *L7PolicyArg) error {
	if p == nil {
		return fmt.Errorf("l7policy: nil body")
	}
	if strings.TrimSpace(p.LbId) == "" {
		return fmt.Errorf("l7policy: lbId is required (the stable id of the L4 load-balancer to attach to)")
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("l7policy: at least one rule is required")
	}
	for ri := range p.Rules {
		rule := &p.Rules[ri]
		for si := range rule.MatchSets {
			set := &rule.MatchSets[si]
			for ci := range set.Conditions {
				if err := validateL7Condition(&set.Conditions[ci]); err != nil {
					return fmt.Errorf("l7policy: rule[%d] set[%d] cond[%d]: %w", ri, si, ci, err)
				}
			}
		}
		if err := validateL7Action(&rule.Action); err != nil {
			return fmt.Errorf("l7policy: rule[%d] action: %w", ri, err)
		}
		if err := validateInsertHeaders(rule.InsertHeaders); err != nil {
			return fmt.Errorf("l7policy: rule[%d] insertHeaders: %w", ri, err)
		}
	}
	return validateSessionPersistence(p)
}

// validateSessionPersistence enforces HTTP_COOKIE session-persistence
// rules: each rule's SessionPersistence must be one of the known modes, and
// HTTP_COOKIE (LB-generated stateless cookie) is MUTUALLY EXCLUSIVE per
// pool with APP_COOKIE / SOURCE_IP — mixing them within one policy is
// ambiguous (the data plane can apply only one affinity mode). Empty ("")
// = off.
func validateSessionPersistence(p *L7PolicyArg) error {
	sawHTTPCookie := false
	sawOtherAffinity := false
	for ri := range p.Rules {
		mode := strings.ToUpper(strings.TrimSpace(p.Rules[ri].SessionPersistence))
		switch mode {
		case "": // off — no persistence on this rule
		case "HTTP_COOKIE":
			sawHTTPCookie = true
		case "APP_COOKIE", "SOURCE_IP":
			sawOtherAffinity = true
		default:
			return fmt.Errorf("l7policy: rule[%d] sessionPersistence: unsupported mode %q "+
				"(want one of HTTP_COOKIE, APP_COOKIE, SOURCE_IP, or empty)", ri, p.Rules[ri].SessionPersistence)
		}
	}
	if sawHTTPCookie && sawOtherAffinity {
		return fmt.Errorf("l7policy: sessionPersistence HTTP_COOKIE is mutually exclusive with " +
			"APP_COOKIE/SOURCE_IP per pool — do not mix them within one policy")
	}
	return nil
}

// l7HasCtrlChars reports whether s contains a CR, LF, NUL, or any other
// ASCII control char (or DEL). Such bytes in an insertHeaders name/value
// enable CRLF/header injection at the data plane, so they are rejected at
// config time — the first line of defence ahead of the data-plane
// l7_hdr_name_valid/l7_hdr_value_valid guards.
func l7HasCtrlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' { // HT is permitted inside a header value
			continue
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// validateInsertHeaders enforces request-header insertion rules:
//   - op ∈ {SET, ADD, REMOVE} (case-insensitive); anything else => error.
//   - bounded count ≤ L7HdrMaxFilters (C L7_MAX_HDR_FILTERS) so the
//     data-plane copy never silently truncates (DoS bound).
//   - non-empty name with no control chars / ':' (CRLF injection guard);
//     name length ≤ L7HdrNameMax; value length ≤ L7HdrValueMax and no
//     control chars (value is ignored for REMOVE but still
//     length/CRLF-checked when present).
func validateInsertHeaders(hdrs []L7HeaderFilterArg) error {
	if len(hdrs) > L7HdrMaxFilters {
		return fmt.Errorf("too many insertHeaders entries (%d > max %d)", len(hdrs), L7HdrMaxFilters)
	}
	for i := range hdrs {
		h := &hdrs[i]
		op := strings.ToUpper(strings.TrimSpace(h.Op))
		if !l7ValidHdrOps[op] {
			return fmt.Errorf("entry[%d]: unknown op %q (want SET/ADD/REMOVE)", i, h.Op)
		}
		name := strings.TrimSpace(h.Name)
		if name == "" {
			return fmt.Errorf("entry[%d]: header name is required", i)
		}
		if len(name) > L7HdrNameMax {
			return fmt.Errorf("entry[%d]: header name too long (%d > %d)", i, len(name), L7HdrNameMax)
		}
		if l7HasCtrlChars(name) || strings.ContainsRune(name, ':') {
			return fmt.Errorf("entry[%d]: header name %q contains illegal characters (CRLF/control/':')", i, h.Name)
		}
		if len(h.Value) > L7HdrValueMax {
			return fmt.Errorf("entry[%d]: header value too long (%d > %d)", i, len(h.Value), L7HdrValueMax)
		}
		if l7HasCtrlChars(h.Value) {
			return fmt.Errorf("entry[%d]: header value contains illegal control characters (CRLF injection)", i)
		}
	}
	return nil
}

func validateL7Condition(c *L7ConditionArg) error {
	field := strings.ToUpper(strings.TrimSpace(c.Field))
	op := strings.ToUpper(strings.TrimSpace(c.Op))

	if !l7ValidFields[field] {
		// An unknown/unsupported field (e.g. a SSL_* type) is rejected,
		// never silently accepted as a no-op condition.
		return fmt.Errorf("unknown or unsupported field %q", c.Field)
	}
	if !l7ValidOps[op] {
		return fmt.Errorf("unknown or unsupported op %q", c.Op)
	}

	// Octavia FILE_TYPE constraint: ONLY EQUAL_TO or REGEX are valid ops
	// for FILE_TYPE.
	if field == L7FieldFileType && op != L7OpEqual && op != L7OpRegex {
		return fmt.Errorf("FILE_TYPE accepts only EQUAL_TO or REGEX (got %q)", c.Op)
	}

	// key is REQUIRED for HEADER / COOKIE / QUERY (the fields that need a
	// name).
	if (field == L7FieldHeader || field == L7FieldCookie || field == L7FieldQuery) &&
		strings.TrimSpace(c.Key) == "" {
		return fmt.Errorf("key is required for %s", field)
	}

	// A REGEX value is try-compiled at config time so a malformed pattern
	// is an early loud error rather than a regcomp failure surfaced later
	// (the authoritative compile is the single attach-time regcomp on the
	// C side).
	if op == L7OpRegex {
		if strings.TrimSpace(c.Value) == "" {
			return fmt.Errorf("REGEX op requires a non-empty value")
		}
		if _, err := regexp.Compile(c.Value); err != nil {
			return fmt.Errorf("malformed REGEX pattern %q: %v", c.Value, err)
		}
	}
	return nil
}

func validateL7Action(a *L7ActionArg) error {
	kind := strings.ToUpper(strings.TrimSpace(a.Kind))
	switch kind {
	case L7ActForward:
		if a.Forward == nil {
			return fmt.Errorf("FORWARD action requires a forward target")
		}
	case L7ActRedirect:
		if a.Redirect == nil {
			return fmt.Errorf("REDIRECT action requires a redirect target")
		}
		code := a.Redirect.StatusCode
		// 0/absent defaults to 302; any explicit value must be in the
		// allow-list.
		if code != 0 && !l7ValidRedirectStatus[code] {
			return fmt.Errorf("REDIRECT statusCode %d not in {301,302,303,307,308}", code)
		}
	case L7ActReject:
		// REJECT statusCode defaults to 403; an explicit value must be a
		// 4xx.
		if a.Reject != nil && a.Reject.StatusCode != 0 &&
			(a.Reject.StatusCode < 400 || a.Reject.StatusCode > 499) {
			return fmt.Errorf("REJECT statusCode %d must be a 4xx", a.Reject.StatusCode)
		}
	default:
		return fmt.Errorf("unknown action kind %q (want FORWARD/REDIRECT/REJECT)", a.Kind)
	}
	return nil
}
