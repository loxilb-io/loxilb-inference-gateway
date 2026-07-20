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

// l7policy.go — : the control-plane surface for the dedicated
// L7_POLICY resource (policy + ordered child rules).
//
// A policy references an existing L4 load-balancer by its STABLE opaque id
// — resolved here via findLBRuleByOpaqueID (404 if absent). The policy body is validated
// SERVER-SIDE with Octavia per-type rules (ASVS V5 —):
//
//   - FILE_TYPE accepts ONLY EQUAL_TO or REGEX (Octavia constraint).
//   - key is REQUIRED for HEADER / COOKIE / QUERY.
//   - a REGEX value is TRY-COMPILED at config time (a malformed pattern => 400; the
//
// authoritative single regcomp happens at attach in the C side —).
//   - a REDIRECT statusCode must be one of {301,302,303,307,308} (0/absent => 302).
//   - a REJECT statusCode defaults to 403.
//
// The hard-error superset-export invariant (the Cilium GHSA-qcm3-7879-xcww silent-drop
// bug class —): exportToGateway returns an EXPLICIT ERROR (never silently drops)
// for any feature a Gateway API target cannot represent — per-condition `invert`, the REJECT
// action kind, a COOKIE field, or a FILE_TYPE field. A divergence in security semantics on
// cross-target export must FAIL CLOSED, not be silently swallowed.
//
// NOTE (repo deferred-regen convention, Phases 72-74): the handler functions reference
// go-swagger-generated operation/param/responder types (operations.PostConfigL7PolicyParams,
// operations.NewPostConfigL7PolicyNoContent, ...) that are regenerated from swagger.yml on the
// build/AWS gate (`make build`), NOT locally on darwin. The PURE validation + export logic
// (validateL7Policy / exportToGateway) lives in plain functions that the unit tests exercise
// WITHOUT the generated types, so the security invariants are provable independently of regen.
package handler

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// --- canonical L7 enum values (mirror the swagger enums + the C IR) -----------

const (
	l7FieldHost     = "HOST"
	l7FieldPath     = "PATH"
	l7FieldHeader   = "HEADER"
	l7FieldCookie   = "COOKIE"
	l7FieldFileType = "FILE_TYPE"
	l7FieldMethod   = "METHOD"
	l7FieldQuery    = "QUERY"

	l7OpEqual         = "EQUAL_TO"
	l7OpStartsWith    = "STARTS_WITH"
	l7OpSegmentPrefix = "SEGMENT_PREFIX"
	l7OpEndsWith      = "ENDS_WITH"
	l7OpContains      = "CONTAINS"
	l7OpRegex         = "REGEX"

	l7ActForward  = "FORWARD"
	l7ActRedirect = "REDIRECT"
	l7ActReject   = "REJECT"

	// insertHeaders ops + bounds. l7HdrMaxFilters MUST match the C
	// L7_MAX_HDR_FILTERS (sockproxy_l7policy.h) — the data-plane copy truncates above it, so
	// the handler rejects over-count with a 400 rather than silently dropping ops.
	l7HdrOpSet      = "SET"
	l7HdrOpAdd      = "ADD"
	l7HdrOpRemove   = "REMOVE"
	l7HdrMaxFilters = 8
	l7HdrNameMax    = 63  // L7_HDR_NAME_MAX-1 (NUL)
	l7HdrValueMax   = 255 // L7_HDR_VALUE_MAX-1 (NUL)
)

// l7ValidHdrOps gates the insertHeaders op enum (anything else => 400, never a silent SET).
var l7ValidHdrOps = map[string]bool{l7HdrOpSet: true, l7HdrOpAdd: true, l7HdrOpRemove: true}

// l7ValidFields / l7ValidOps gate unknown enum values (a future SSL_* field is rejected here —
// it must not silently fall through as an unmatched no-op).
var l7ValidFields = map[string]bool{
	l7FieldHost: true, l7FieldPath: true, l7FieldHeader: true, l7FieldCookie: true,
	l7FieldFileType: true, l7FieldMethod: true, l7FieldQuery: true,
}

var l7ValidOps = map[string]bool{
	l7OpEqual: true, l7OpStartsWith: true, l7OpSegmentPrefix: true,
	l7OpEndsWith: true, l7OpContains: true, l7OpRegex: true,
}

// l7ValidRedirectStatus is the redirect status-code allow-list (Octavia/Gateway constraint).
var l7ValidRedirectStatus = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

// validateL7Policy enforces the Octavia per-type rules SERVER-SIDE. It returns a
// non-nil error describing the FIRST violation (the handler maps that to a 400). It is a pure
// function so the unit tests can drive every per-type rule without the generated swagger types.
func validateL7Policy(p *cmn.L7PolicyArg) error {
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
	if err := validateSessionPersistence(p); err != nil {
		return err
	}
	return nil
}

// validateSessionPersistence enforces HTTP_COOKIE session-persistence rules
// SERVER-SIDE: each rule's SessionPersistence must be one of the known modes, and HTTP_COOKIE
// (LB-generated stateless cookie) is MUTUALLY EXCLUSIVE per pool with APP_COOKIE / SOURCE_IP —
// mixing them within one policy is ambiguous (the data plane can apply only one affinity mode),
// so it is rejected with a 400 (the handler maps a non-nil error to 400). Empty ("") = off.
func validateSessionPersistence(p *cmn.L7PolicyArg) error {
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

// hasCtrlChars reports whether s contains a CR, LF, NUL, or any other ASCII control char
// (or DEL). Such bytes in an insertHeaders name/value enable CRLF/header injection at the
// data plane, so they are rejected with a 400 at config time — the first line
// of defence ahead of the data-plane l7_hdr_name_valid/l7_hdr_value_valid guards.
func hasCtrlChars(s string) bool {
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

// validateInsertHeaders enforces request-header insertion rules SERVER-SIDE:
//   - op ∈ {SET, ADD, REMOVE} (case-insensitive); anything else => 400.
//
// - bounded count ≤ l7HdrMaxFilters (C L7_MAX_HDR_FILTERS) so the data-plane copy never
// silently truncates (DoS bound).
//   - non-empty name with no control chars / ':' (CRLF injection guard); name
//     length ≤ l7HdrNameMax; value length ≤ l7HdrValueMax and no control chars (value is
//     ignored for REMOVE but still length/CRLF-checked when present).
func validateInsertHeaders(hdrs []cmn.L7HeaderFilterArg) error {
	if len(hdrs) > l7HdrMaxFilters {
		return fmt.Errorf("too many insertHeaders entries (%d > max %d)", len(hdrs), l7HdrMaxFilters)
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
		if len(name) > l7HdrNameMax {
			return fmt.Errorf("entry[%d]: header name too long (%d > %d)", i, len(name), l7HdrNameMax)
		}
		if hasCtrlChars(name) || strings.ContainsRune(name, ':') {
			return fmt.Errorf("entry[%d]: header name %q contains illegal characters (CRLF/control/':')", i, h.Name)
		}
		if len(h.Value) > l7HdrValueMax {
			return fmt.Errorf("entry[%d]: header value too long (%d > %d)", i, len(h.Value), l7HdrValueMax)
		}
		if hasCtrlChars(h.Value) {
			return fmt.Errorf("entry[%d]: header value contains illegal control characters (CRLF injection)", i)
		}
	}
	return nil
}

func validateL7Condition(c *cmn.L7ConditionArg) error {
	field := strings.ToUpper(strings.TrimSpace(c.Field))
	op := strings.ToUpper(strings.TrimSpace(c.Op))

	if !l7ValidFields[field] {
		// An unknown/unsupported field (e.g. a SSL_* type) is rejected, never
		// silently accepted as a no-op condition.
		return fmt.Errorf("unknown or unsupported field %q", c.Field)
	}
	if !l7ValidOps[op] {
		return fmt.Errorf("unknown or unsupported op %q", c.Op)
	}

	// Octavia FILE_TYPE constraint: ONLY EQUAL_TO or REGEX are valid ops for FILE_TYPE.
	if field == l7FieldFileType && op != l7OpEqual && op != l7OpRegex {
		return fmt.Errorf("FILE_TYPE accepts only EQUAL_TO or REGEX (got %q)", c.Op)
	}

	// key is REQUIRED for HEADER / COOKIE / QUERY (the field that needs a name).
	if (field == l7FieldHeader || field == l7FieldCookie || field == l7FieldQuery) &&
		strings.TrimSpace(c.Key) == "" {
		return fmt.Errorf("key is required for %s", field)
	}

	// A REGEX value is try-compiled at config time so a malformed pattern is a 400 here
	// rather than a regcomp failure surfaced later (the authoritative compile is the single
	// attach-time regcomp on the C side).
	if op == l7OpRegex {
		if strings.TrimSpace(c.Value) == "" {
			return fmt.Errorf("REGEX op requires a non-empty value")
		}
		if _, err := regexp.Compile(c.Value); err != nil {
			return fmt.Errorf("malformed REGEX pattern %q: %v", c.Value, err)
		}
	}
	return nil
}

func validateL7Action(a *cmn.L7ActionArg) error {
	kind := strings.ToUpper(strings.TrimSpace(a.Kind))
	switch kind {
	case l7ActForward:
		if a.Forward == nil {
			return fmt.Errorf("FORWARD action requires a forward target")
		}
	case l7ActRedirect:
		if a.Redirect == nil {
			return fmt.Errorf("REDIRECT action requires a redirect target")
		}
		code := a.Redirect.StatusCode
		// 0/absent defaults to 302; any explicit value must be in the allow-list.
		if code != 0 && !l7ValidRedirectStatus[code] {
			return fmt.Errorf("REDIRECT statusCode %d not in {301,302,303,307,308}", code)
		}
	case l7ActReject:
		// REJECT statusCode defaults to 403; an explicit value must be a 4xx.
		if a.Reject != nil && a.Reject.StatusCode != 0 &&
			(a.Reject.StatusCode < 400 || a.Reject.StatusCode > 499) {
			return fmt.Errorf("REJECT statusCode %d must be a 4xx", a.Reject.StatusCode)
		}
	default:
		return fmt.Errorf("unknown action kind %q (want FORWARD/REDIRECT/REJECT)", a.Kind)
	}
	return nil
}

// exportToGateway is HARD-ERROR superset-divergence guard (the Cilium
// GHSA-qcm3-7879-xcww silent-drop bug class). When a policy is exported to a Kubernetes
// Gateway API target, any feature Gateway CANNOT represent MUST surface as an EXPLICIT ERROR
// — it is NEVER silently dropped, because a silent drop would change the security semantics
// of the exported policy (e.g. an `invert`-ed deny condition vanishing, or a REJECT becoming
// an allow). The Gateway-unrepresentable features are:
//
//   - per-condition `invert` (Gateway has no negated match),
//   - the REJECT action kind (Gateway has no synthetic-reject filter),
//   - a COOKIE field (Gateway HTTPRoute matches have no cookie matcher),
//   - a FILE_TYPE field (Gateway has no file-extension matcher).
//
// Returns a non-nil error naming the unrepresentable feature when one is present; nil only
// when the WHOLE policy is faithfully representable on Gateway API.
func exportToGateway(p *cmn.L7PolicyArg) error {
	if p == nil {
		return fmt.Errorf("l7policy: nil body cannot be exported")
	}
	for ri := range p.Rules {
		rule := &p.Rules[ri]
		// REJECT is not representable on Gateway API — hard error, never a silent drop.
		if strings.EqualFold(strings.TrimSpace(rule.Action.Kind), l7ActReject) {
			return fmt.Errorf("l7policy: rule[%d] uses REJECT, which is unrepresentable on Gateway API — refusing to silently drop", ri)
		}
		for si := range rule.MatchSets {
			set := &rule.MatchSets[si]
			for ci := range set.Conditions {
				c := &set.Conditions[ci]
				field := strings.ToUpper(strings.TrimSpace(c.Field))
				if c.Invert {
					return fmt.Errorf("l7policy: rule[%d] set[%d] cond[%d] uses invert, which is unrepresentable on Gateway API — refusing to silently drop", ri, si, ci)
				}
				if field == l7FieldCookie {
					return fmt.Errorf("l7policy: rule[%d] set[%d] cond[%d] matches COOKIE, which is unrepresentable on Gateway API — refusing to silently drop", ri, si, ci)
				}
				if field == l7FieldFileType {
					return fmt.Errorf("l7policy: rule[%d] set[%d] cond[%d] matches FILE_TYPE, which is unrepresentable on Gateway API — refusing to silently drop", ri, si, ci)
				}
			}
		}
	}
	return nil
}

// l7PolicyStore is the in-memory L7_POLICY registry, keyed by policy id. The L7 API is
// unreleased so this clean-state store carries no back-compat debt. The control-plane
// attach (DpProxyAttachL7Policy) is driven from here; this resource is CRUD'd independently of
// the L4 LB it references.
var l7PolicyStore = map[string]*cmn.L7PolicyArg{}

// --- CRUD handlers (deferred-regen: generated op types come from `make build`) -----------

// ConfigPostL7Policy creates an L7_POLICY: resolves the referenced LB by its stable
// id (404 if absent), validates server-side (Octavia per-type rules => 400), and stores it.
func ConfigPostL7Policy(params operations.PostConfigL7PolicyParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: L7Policy %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	if params.Attr == nil {
		return &ResultResponse{Result: "l7policy: empty body"}
	}
	policy := l7PolicyFromModel(params.Attr)

	// the policy references the L4 LB by its STABLE opaque id — resolve it (404 if absent).
	lb, err := findLBRuleByOpaqueID(policy.LbId)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	if lb == nil {
		return operations.NewPostConfigL7PolicyNotFound()
	}

	// Octavia server-side validation — any violation is a 400.
	if err := validateL7Policy(policy); err != nil {
		tk.LogIt(tk.LogDebug, "api: l7policy validation failed: %v\n", err)
		return operations.NewPostConfigL7PolicyBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

	if policy.Id == "" {
		policy.Id = fmt.Sprintf("l7policy-%s-%d", policy.LbId, len(l7PolicyStore)+1)
	}

	// Attach the validated route IR to the running sockproxy rule fronting the
	// resolved LB's VIP:port:proto. This is the control-plane attach: the
	// route array reaches the eBPF userspace proxy via a SEPARATE CGO call
	// (DpProxyAttachL7Policy), never inline on the 4096-byte proxy_arg. Without
	// this the policy would be stored but never enforced (has_l7_policy stays 0).
	if _, err := ApiHooks.NetL7PolicyApply(lb.Serv.ServIP, lb.Serv.ServPort, lb.Serv.Proto, policy.Rules); err != nil {
		tk.LogIt(tk.LogError, "api: l7policy attach to dataplane failed: %v\n", err)
		return operations.NewPostConfigL7PolicyBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

	l7PolicyStore[policy.Id] = policy

	tk.LogIt(tk.LogInfo, "api: L7Policy %s attached to LB id=%s VIP=%s:%d/%s (%d rules)\n",
		policy.Id, policy.LbId, lb.Serv.ServIP, lb.Serv.ServPort, lb.Serv.Proto, len(policy.Rules))
	return operations.NewPostConfigL7PolicyNoContent()
}

// ConfigGetL7PolicyAll returns all configured L7 policies.
func ConfigGetL7PolicyAll(params operations.GetConfigL7PolicyAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: L7Policy %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	return operations.NewGetConfigL7PolicyAllOK().WithPayload(serializeL7PolicyCollection())
}

// ConfigGetL7PolicyByID returns a single L7 policy by its opaque id (404 on miss).
func ConfigGetL7PolicyByID(params operations.GetConfigL7PolicyIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: L7Policy %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	policy, ok := l7PolicyStore[params.ID]
	if !ok || policy == nil {
		return operations.NewGetConfigL7PolicyIDNotFound()
	}
	return operations.NewGetConfigL7PolicyIDOK().WithPayload(serializeL7Policy(policy))
}

// ConfigDeleteL7Policy detaches and removes an L7 policy by id (404 on miss). The detach path
// (proxy_detach_l7_policy) regfrees every compiled REGEX program on the C side.
func ConfigDeleteL7Policy(params operations.DeleteConfigL7PolicyIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: L7Policy %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	policy, ok := l7PolicyStore[params.ID]
	if !ok || policy == nil {
		return operations.NewDeleteConfigL7PolicyIDNotFound()
	}

	// Detach from the dataplane (regfrees every compiled REGEX program on the C
	// side). Resolve the referenced LB to recover its VIP:port:proto; if the LB is
	// already gone the sockproxy rule (and its attached policy) was torn down with
	// it, so a missing LB is not a delete error — we still drop the store entry.
	if lb, err := findLBRuleByOpaqueID(policy.LbId); err == nil && lb != nil {
		if _, derr := ApiHooks.NetL7PolicyRemove(lb.Serv.ServIP, lb.Serv.ServPort, lb.Serv.Proto); derr != nil {
			tk.LogIt(tk.LogError, "api: l7policy detach from dataplane failed: %v\n", derr)
		}
	}

	delete(l7PolicyStore, params.ID)
	tk.LogIt(tk.LogInfo, "api: L7Policy %s detached from LB id=%s\n", policy.Id, policy.LbId)
	return operations.NewDeleteConfigL7PolicyIDNoContent()
}

// --- model <-> cmn conversion (deferred-regen: models.* come from `make build`) ----------
//
// go-swagger derives the models.L7Policy/L7Rule/... shapes from the swagger.yml definitions
// above. The field mapping is deterministic (snake/camel case property -> exported Go field):
// lbId -> LbID, matchSets -> MatchSets, statusCode -> StatusCode, etc. These converters are
// the only regen-dependent code in this file; the validation + export invariants are pure and
// unit-tested without them.

// l7Str dereferences a go-swagger required *string (nil-safe → "").
func l7Str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// l7Ptr returns the address of a copy of s for go-swagger required *string fields.
func l7Ptr(s string) *string { return &s }

// l7PolicyFromModel converts the inbound generated model into the cmn IR-friendly Arg shape.
func l7PolicyFromModel(m *models.L7Policy) *cmn.L7PolicyArg {
	if m == nil {
		return &cmn.L7PolicyArg{}
	}
	p := &cmn.L7PolicyArg{
		Id:   m.ID,
		Name: m.Name,
		LbId: l7Str(m.LbID),
	}
	for _, r := range m.Rules {
		if r == nil {
			continue
		}
		rule := cmn.L7RuleArg{Position: int(r.Position)}
		for _, ms := range r.MatchSets {
			if ms == nil {
				continue
			}
			set := cmn.L7MatchSetArg{}
			for _, c := range ms.Conditions {
				if c == nil {
					continue
				}
				set.Conditions = append(set.Conditions, cmn.L7ConditionArg{
					Field:  l7Str(c.Field),
					Op:     l7Str(c.Op),
					Key:    c.Key,
					Value:  c.Value,
					Invert: c.Invert,
				})
			}
			rule.MatchSets = append(rule.MatchSets, set)
		}
		if r.Action != nil {
			rule.Action.Kind = l7Str(r.Action.Kind)
			if r.Action.Forward != nil {
				fwd := &cmn.L7ForwardArg{PoolId: uint32(r.Action.Forward.PoolID)}
				for _, br := range r.Action.Forward.BackendRefs {
					if br == nil {
						continue
					}
					fwd.BackendRefs = append(fwd.BackendRefs, cmn.L7BackendRefArg{
						Ep:     uint32(br.Ep),
						Weight: int(br.Weight),
					})
				}
				rule.Action.Forward = fwd
			}
			if r.Action.Redirect != nil {
				rule.Action.Redirect = &cmn.L7RedirectArg{
					Scheme:     r.Action.Redirect.Scheme,
					Host:       r.Action.Redirect.Host,
					Port:       int(r.Action.Redirect.Port),
					PathOp:     r.Action.Redirect.PathOp,
					Value:      r.Action.Redirect.Value,
					StatusCode: int(r.Action.Redirect.StatusCode),
				}
			}
			if r.Action.Reject != nil {
				rule.Action.Reject = &cmn.L7RejectArg{StatusCode: int(r.Action.Reject.StatusCode)}
			}
		}
		// carry the insertHeaders SET/ADD/REMOVE list from the wire model into
		// the cmn IR so it reaches DpProxyAttachL7Policy. Without this copy the validated
		// header ops would silently never reach the data plane (the 76-04 missing-leg class).
		for _, ih := range r.InsertHeaders {
			if ih == nil {
				continue
			}
			rule.InsertHeaders = append(rule.InsertHeaders, cmn.L7HeaderFilterArg{
				Op:    ih.Op,
				Name:  ih.Name,
				Value: ih.Value,
			})
		}
		// carry the session-persistence marker (engine is).
		rule.SessionPersistence = r.SessionPersistence
		p.Rules = append(p.Rules, rule)
	}
	return p
}

// serializeL7Policy converts a cmn policy back to the generated model for GET responses.
func serializeL7Policy(p *cmn.L7PolicyArg) *models.L7Policy {
	if p == nil {
		return &models.L7Policy{}
	}
	m := &models.L7Policy{
		ID:   p.Id,
		Name: p.Name,
		LbID: l7Ptr(p.LbId),
	}
	for ri := range p.Rules {
		r := &p.Rules[ri]
		mr := &models.L7Rule{Position: int64(r.Position)}
		for si := range r.MatchSets {
			ms := &models.L7RuleMatchSetsItems0{}
			for ci := range r.MatchSets[si].Conditions {
				c := &r.MatchSets[si].Conditions[ci]
				ms.Conditions = append(ms.Conditions, &models.L7Condition{
					Field:  l7Ptr(c.Field),
					Op:     l7Ptr(c.Op),
					Key:    c.Key,
					Value:  c.Value,
					Invert: c.Invert,
				})
			}
			mr.MatchSets = append(mr.MatchSets, ms)
		}
		mr.Action = &models.L7Action{Kind: l7Ptr(r.Action.Kind)}
		if r.Action.Forward != nil {
			fwd := &models.L7ActionForward{PoolID: uint32(r.Action.Forward.PoolId)}
			for bi := range r.Action.Forward.BackendRefs {
				br := &r.Action.Forward.BackendRefs[bi]
				fwd.BackendRefs = append(fwd.BackendRefs, &models.L7ActionForwardBackendRefsItems0{
					Ep:     uint32(br.Ep),
					Weight: int64(br.Weight),
				})
			}
			mr.Action.Forward = fwd
		}
		if r.Action.Redirect != nil {
			mr.Action.Redirect = &models.L7ActionRedirect{
				Scheme:     r.Action.Redirect.Scheme,
				Host:       r.Action.Redirect.Host,
				Port:       int64(r.Action.Redirect.Port),
				PathOp:     r.Action.Redirect.PathOp,
				Value:      r.Action.Redirect.Value,
				StatusCode: int64(r.Action.Redirect.StatusCode),
			}
		}
		if r.Action.Reject != nil {
			mr.Action.Reject = &models.L7ActionReject{StatusCode: int64(r.Action.Reject.StatusCode)}
		}
		// round-trip the additive fields back out on GET.
		for hi := range r.InsertHeaders {
			f := &r.InsertHeaders[hi]
			mr.InsertHeaders = append(mr.InsertHeaders, &models.L7RuleInsertHeadersItems0{
				Op:    f.Op,
				Name:  f.Name,
				Value: f.Value,
			})
		}
		mr.SessionPersistence = r.SessionPersistence
		m.Rules = append(m.Rules, mr)
	}
	return m
}

// serializeL7PolicyCollection wraps every stored policy for the GET-all response.
func serializeL7PolicyCollection() *models.L7PolicyGetEntry {
	out := &models.L7PolicyGetEntry{}
	for _, p := range l7PolicyStore {
		out.L7policyAttr = append(out.L7policyAttr, serializeL7Policy(p))
	}
	return out
}
