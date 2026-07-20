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

// l7policy_test.go — unit tests for the L7_POLICY control-plane surface.
//
// These tests exercise the PURE security logic (validateL7Policy / exportToGateway) directly,
// independent of the go-swagger-generated operation types, so the two load-bearing invariants
// are provable on darwin WITHOUT the regen toolchain:
//
//   * Octavia per-type validation: FILE_TYPE only EQUAL_TO/REGEX; key required for
//     HEADER/COOKIE/QUERY; malformed REGEX rejected; redirect statusCode allow-list.
// * hard-error superset export (Cilium GHSA-qcm3-7879-xcww class): every
//     Gateway-unrepresentable feature (invert / REJECT / COOKIE / FILE_TYPE) returns an
//     EXPLICIT ERROR — NEVER a silent drop.
//
// `go test ./api/restapi/handler/... -run L7Policy` runs them on the AWS gate after regen; the
// pure-logic subset compiles and passes on darwin too.

package handler

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// okPolicy returns a minimal valid policy (one rule, one FORWARD action) the tests mutate.
func okPolicy() *cmn.L7PolicyArg {
	return &cmn.L7PolicyArg{
		LbId: "lb-abc",
		Rules: []cmn.L7RuleArg{{
			Position: 1,
			MatchSets: []cmn.L7MatchSetArg{{
				Conditions: []cmn.L7ConditionArg{{Field: "PATH", Op: "STARTS_WITH", Value: "/api"}},
			}},
			Action: cmn.L7ActionArg{Kind: "FORWARD", Forward: &cmn.L7ForwardArg{PoolId: 1}},
		}},
	}
}

// withCond replaces the single rule's single condition with the given one (FORWARD action).
func withCond(c cmn.L7ConditionArg) *cmn.L7PolicyArg {
	p := okPolicy()
	p.Rules[0].MatchSets[0].Conditions = []cmn.L7ConditionArg{c}
	return p
}

// --- Octavia per-type validation ----------------------------------

func TestL7PolicyValidateBaselineOK(t *testing.T) {
	if err := validateL7Policy(okPolicy()); err != nil {
		t.Fatalf("baseline valid policy rejected: %v", err)
	}
}

func TestL7PolicyValidateFileType(t *testing.T) {
	cases := []struct {
		name    string
		op      string
		wantErr bool
	}{
		{"FILE_TYPE+EQUAL_TO ok", "EQUAL_TO", false},
		{"FILE_TYPE+REGEX ok", "REGEX", false},
		{"FILE_TYPE+STARTS_WITH rejected", "STARTS_WITH", true},
		{"FILE_TYPE+CONTAINS rejected", "CONTAINS", true},
		{"FILE_TYPE+ENDS_WITH rejected", "ENDS_WITH", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val := "png"
			if tc.op == "REGEX" {
				val = "png|jpg"
			}
			err := validateL7Policy(withCond(cmn.L7ConditionArg{Field: "FILE_TYPE", Op: tc.op, Value: val}))
			if tc.wantErr && err == nil {
				t.Fatalf("expected FILE_TYPE op %q to be rejected, got nil", tc.op)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected FILE_TYPE op %q to be accepted, got %v", tc.op, err)
			}
		})
	}
}

func TestL7PolicyValidateKeyRequired(t *testing.T) {
	for _, field := range []string{"HEADER", "COOKIE", "QUERY"} {
		t.Run(field+" without key rejected", func(t *testing.T) {
			err := validateL7Policy(withCond(cmn.L7ConditionArg{Field: field, Op: "EQUAL_TO", Value: "v"}))
			if err == nil {
				t.Fatalf("expected %s without key to be rejected, got nil", field)
			}
		})
		t.Run(field+" with key accepted", func(t *testing.T) {
			err := validateL7Policy(withCond(cmn.L7ConditionArg{Field: field, Op: "EQUAL_TO", Key: "X-Thing", Value: "v"}))
			if err != nil {
				t.Fatalf("expected %s with key to be accepted, got %v", field, err)
			}
		})
	}
}

func TestL7PolicyValidateBadRegex(t *testing.T) {
	err := validateL7Policy(withCond(cmn.L7ConditionArg{Field: "PATH", Op: "REGEX", Value: "([unclosed"}))
	if err == nil {
		t.Fatalf("expected a malformed REGEX pattern to be rejected (400), got nil")
	}
	if ok := validateL7Policy(withCond(cmn.L7ConditionArg{Field: "PATH", Op: "REGEX", Value: "^/v1/.*$"})); ok != nil {
		t.Fatalf("expected a well-formed REGEX pattern to be accepted, got %v", ok)
	}
}

func TestL7PolicyValidateRedirectStatusAllowList(t *testing.T) {
	mk := func(code int) *cmn.L7PolicyArg {
		p := okPolicy()
		p.Rules[0].Action = cmn.L7ActionArg{Kind: "REDIRECT", Redirect: &cmn.L7RedirectArg{Host: "h", StatusCode: code}}
		return p
	}
	// 0 (default 302) and each allowed code accepted; a disallowed code rejected.
	for _, code := range []int{0, 301, 302, 303, 307, 308} {
		if err := validateL7Policy(mk(code)); err != nil {
			t.Fatalf("expected redirect statusCode %d to be accepted, got %v", code, err)
		}
	}
	for _, code := range []int{200, 304, 399, 500} {
		if err := validateL7Policy(mk(code)); err == nil {
			t.Fatalf("expected redirect statusCode %d to be rejected, got nil", code)
		}
	}
}

func TestL7PolicyValidateRejectDefault403(t *testing.T) {
	// REJECT with no statusCode (0) is valid — the C side defaults to 403.
	p := okPolicy()
	p.Rules[0].Action = cmn.L7ActionArg{Kind: "REJECT", Reject: &cmn.L7RejectArg{}}
	if err := validateL7Policy(p); err != nil {
		t.Fatalf("expected REJECT with default status to be accepted, got %v", err)
	}
	// A non-4xx REJECT status is rejected.
	p.Rules[0].Action.Reject.StatusCode = 200
	if err := validateL7Policy(p); err == nil {
		t.Fatalf("expected REJECT statusCode 200 to be rejected, got nil")
	}
}

func TestL7PolicyValidateMissingLbId(t *testing.T) {
	p := okPolicy()
	p.LbId = ""
	if err := validateL7Policy(p); err == nil {
		t.Fatalf("expected a policy with no lbId to be rejected, got nil")
	}
}

// --- hard-error superset export ------------------------------
//
// Each Gateway-unrepresentable feature MUST return an explicit error — NEVER a silent drop.

func TestL7PolicyExportRepresentableOK(t *testing.T) {
	if err := exportToGateway(okPolicy()); err != nil {
		t.Fatalf("a Gateway-representable policy must export cleanly, got error: %v", err)
	}
}

func TestL7PolicyExportInvertIsHardError(t *testing.T) {
	p := withCond(cmn.L7ConditionArg{Field: "HEADER", Op: "EQUAL_TO", Key: "X-A", Value: "v", Invert: true})
	err := exportToGateway(p)
	if err == nil {
		t.Fatalf("invert is unrepresentable on Gateway — export MUST return an error, not silently drop")
	}
}

func TestL7PolicyExportRejectIsHardError(t *testing.T) {
	p := okPolicy()
	p.Rules[0].Action = cmn.L7ActionArg{Kind: "REJECT", Reject: &cmn.L7RejectArg{StatusCode: 403}}
	err := exportToGateway(p)
	if err == nil {
		t.Fatalf("REJECT is unrepresentable on Gateway — export MUST return an error, not silently drop")
	}
}

func TestL7PolicyExportCookieIsHardError(t *testing.T) {
	p := withCond(cmn.L7ConditionArg{Field: "COOKIE", Op: "EQUAL_TO", Key: "sess", Value: "v"})
	err := exportToGateway(p)
	if err == nil {
		t.Fatalf("COOKIE is unrepresentable on Gateway — export MUST return an error, not silently drop")
	}
}

func TestL7PolicyExportFileTypeIsHardError(t *testing.T) {
	p := withCond(cmn.L7ConditionArg{Field: "FILE_TYPE", Op: "EQUAL_TO", Value: "png"})
	err := exportToGateway(p)
	if err == nil {
		t.Fatalf("FILE_TYPE is unrepresentable on Gateway — export MUST return an error, not silently drop")
	}
}

// --- insertHeaders validation (03) ---------

// withInsertHeaders attaches the given insertHeaders list to the baseline rule.
func withInsertHeaders(h []cmn.L7HeaderFilterArg) *cmn.L7PolicyArg {
	p := okPolicy()
	p.Rules[0].InsertHeaders = h
	return p
}

func TestL7PolicyInsertHeadersValid(t *testing.T) {
	p := withInsertHeaders([]cmn.L7HeaderFilterArg{
		{Op: "SET", Name: "X-Inj", Value: "yes"},
		{Op: "add", Name: "X-Extra", Value: "1"}, // case-insensitive op
		{Op: "REMOVE", Name: "X-Drop"},           // value omitted is fine
	})
	if err := validateL7Policy(p); err != nil {
		t.Fatalf("valid insertHeaders rejected: %v", err)
	}
}

func TestL7PolicyInsertHeadersBadOp(t *testing.T) {
	p := withInsertHeaders([]cmn.L7HeaderFilterArg{{Op: "APPEND", Name: "X-Inj", Value: "y"}})
	if err := validateL7Policy(p); err == nil {
		t.Fatalf("unknown insertHeaders op must be a 400, got nil")
	}
}

func TestL7PolicyInsertHeadersCRLFInjection(t *testing.T) {
	// A CR/LF in either name or value is the header-injection class — reject.
	for _, tc := range []struct {
		name string
		h    cmn.L7HeaderFilterArg
	}{
		{"CRLF in value", cmn.L7HeaderFilterArg{Op: "SET", Name: "X-Inj", Value: "a\r\nEvil: 1"}},
		{"LF in name", cmn.L7HeaderFilterArg{Op: "SET", Name: "X-In\nj", Value: "y"}},
		{"colon in name", cmn.L7HeaderFilterArg{Op: "SET", Name: "X:Inj", Value: "y"}},
		{"empty name", cmn.L7HeaderFilterArg{Op: "ADD", Name: "", Value: "y"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateL7Policy(withInsertHeaders([]cmn.L7HeaderFilterArg{tc.h})); err == nil {
				t.Fatalf("%s must be rejected (CRLF/header injection guard), got nil", tc.name)
			}
		})
	}
}

func TestL7PolicyInsertHeadersOverCount(t *testing.T) {
	var h []cmn.L7HeaderFilterArg
	for i := 0; i < l7HdrMaxFilters+1; i++ {
		h = append(h, cmn.L7HeaderFilterArg{Op: "ADD", Name: "X-H", Value: "v"})
	}
	if err := validateL7Policy(withInsertHeaders(h)); err == nil {
		t.Fatalf("over-count insertHeaders (> %d) must be a 400 (DoS bound), got nil", l7HdrMaxFilters)
	}
}

// --- HTTP_COOKIE session-persistence validation -----------------

// withSessionPersistence sets the single rule's SessionPersistence mode.
func withSessionPersistence(mode string) *cmn.L7PolicyArg {
	p := okPolicy()
	p.Rules[0].SessionPersistence = mode
	return p
}

func TestL7PolicySessionPersistenceValidModes(t *testing.T) {
	for _, mode := range []string{"", "HTTP_COOKIE", "http_cookie", "APP_COOKIE", "SOURCE_IP"} {
		if err := validateL7Policy(withSessionPersistence(mode)); err != nil {
			t.Fatalf("sessionPersistence %q must be accepted, got %v", mode, err)
		}
	}
}

func TestL7PolicySessionPersistenceUnknownMode(t *testing.T) {
	if err := validateL7Policy(withSessionPersistence("MAGIC_COOKIE")); err == nil {
		t.Fatalf("unknown sessionPersistence mode must be a 400, got nil")
	}
}

func TestL7PolicySessionPersistenceMutualExclusion(t *testing.T) {
	// HTTP_COOKIE mixed with APP_COOKIE/SOURCE_IP within one policy must 400.
	for _, other := range []string{"APP_COOKIE", "SOURCE_IP"} {
		p := okPolicy()
		p.Rules = append(p.Rules, p.Rules[0]) // a second rule
		p.Rules[0].SessionPersistence = "HTTP_COOKIE"
		p.Rules[1].SessionPersistence = other
		if err := validateL7Policy(p); err == nil {
			t.Fatalf("HTTP_COOKIE mixed with %s must be mutually-exclusive 400, got nil", other)
		}
	}
	// HTTP_COOKIE on every rule (no conflicting mode) is fine.
	p := okPolicy()
	p.Rules = append(p.Rules, p.Rules[0])
	p.Rules[0].SessionPersistence = "HTTP_COOKIE"
	p.Rules[1].SessionPersistence = "HTTP_COOKIE"
	if err := validateL7Policy(p); err != nil {
		t.Fatalf("all-HTTP_COOKIE policy must be accepted, got %v", err)
	}
}
