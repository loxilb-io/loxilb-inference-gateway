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
// (404 if absent). The desired-state registry itself lives control-plane
// side (pkg/loxinet, reached via the NetL7PolicyGet/Add/Del hooks) so the
// config snapshot/restore engine shares one store with this handler; here
// remains only the REST semantics: model conversion, early validation for
// clean 400s, and error→status mapping. The policy body is validated
// SERVER-SIDE with Octavia per-type rules (ASVS V5, cmn.ValidateL7Policy —
// shared with the restore apply path):
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
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// The Octavia server-side validation (and the canonical enum/bound
// constants) moved to cmn.ValidateL7Policy (common/l7policy.go): the
// config-restore apply path (pkg/loxinet NetL7PolicyAdd) must enforce the
// exact same rules on documents that never pass through this handler.
// These aliases keep this package's call sites (and its validation unit
// tests, which drive the shared implementation) unchanged.
var validateL7Policy = cmn.ValidateL7Policy

const l7HdrMaxFilters = cmn.L7HdrMaxFilters

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
		if strings.EqualFold(strings.TrimSpace(rule.Action.Kind), cmn.L7ActReject) {
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
				if field == cmn.L7FieldCookie {
					return fmt.Errorf("l7policy: rule[%d] set[%d] cond[%d] matches COOKIE, which is unrepresentable on Gateway API — refusing to silently drop", ri, si, ci)
				}
				if field == cmn.L7FieldFileType {
					return fmt.Errorf("l7policy: rule[%d] set[%d] cond[%d] matches FILE_TYPE, which is unrepresentable on Gateway API — refusing to silently drop", ri, si, ci)
				}
			}
		}
	}
	return nil
}

// --- CRUD handlers (deferred-regen: generated op types come from `make build`) -----------
//
// The desired-state registry (and with it the attach to the sockproxy
// dataplane, ID minting per the stable-ID scheme, and the one-policy-per-LB
// invariant) lives behind ApiHooks.NetL7PolicyGet/Add/Del (pkg/loxinet) so
// snapshot capture/restore shares it. The handlers translate models and map
// registry errors onto REST statuses:
//
//	validation failure            => 400
//	referenced LB not found       => 404
//	duplicate id / LB has policy  => 409
//	anything else (attach, ...)   => 400 with the error payload

// ConfigPostL7Policy creates an L7_POLICY: validates server-side (Octavia
// per-type rules => 400) and hands it to the control-plane registry, which
// resolves the referenced LB by its stable id (404 if absent), mints the
// policy id when absent, attaches and stores.
func ConfigPostL7Policy(params operations.PostConfigL7PolicyParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: L7Policy %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	if params.Attr == nil {
		return &ResultResponse{Result: "l7policy: empty body"}
	}
	policy := l7PolicyFromModel(params.Attr)

	// Octavia server-side validation — any violation is a 400. The registry
	// re-validates (its restore intake needs to), but validating here keeps
	// the 400 mapping crisp and the error text free of registry context.
	if err := validateL7Policy(policy); err != nil {
		tk.LogIt(tk.LogDebug, "api: l7policy validation failed: %v\n", err)
		return operations.NewPostConfigL7PolicyBadRequest().WithPayload(ResultErrorResponseErrorMessage(err.Error()))
	}

	if _, err := ApiHooks.NetL7PolicyAdd(policy); err != nil {
		tk.LogIt(tk.LogDebug, "api: l7policy add failed: %v\n", err)
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			return operations.NewPostConfigL7PolicyNotFound()
		case strings.Contains(msg, "l7policy-exists error") || strings.Contains(msg, "l7policy-exist error"):
			// Duplicate id (identical or conflicting) or an LB that already
			// carries a policy: resource conflict.
			return operations.NewPostConfigL7PolicyConflict().WithPayload(ResultErrorResponseErrorMessage(msg))
		default:
			return operations.NewPostConfigL7PolicyBadRequest().WithPayload(ResultErrorResponseErrorMessage(msg))
		}
	}

	return operations.NewPostConfigL7PolicyNoContent()
}

// ConfigGetL7PolicyAll returns all configured L7 policies.
func ConfigGetL7PolicyAll(params operations.GetConfigL7PolicyAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: L7Policy %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	policies, err := ApiHooks.NetL7PolicyGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return operations.NewGetConfigL7PolicyAllOK().WithPayload(serializeL7PolicyCollection(policies))
}

// ConfigGetL7PolicyByID returns a single L7 policy by its opaque id (404 on miss).
func ConfigGetL7PolicyByID(params operations.GetConfigL7PolicyIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: L7Policy %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	policies, err := ApiHooks.NetL7PolicyGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	for i := range policies {
		if policies[i].Id == params.ID {
			return operations.NewGetConfigL7PolicyIDOK().WithPayload(serializeL7Policy(&policies[i]))
		}
	}
	return operations.NewGetConfigL7PolicyIDNotFound()
}

// ConfigDeleteL7Policy detaches and removes an L7 policy by id (404 on miss). The detach path
// (proxy_detach_l7_policy) regfrees every compiled REGEX program on the C side.
func ConfigDeleteL7Policy(params operations.DeleteConfigL7PolicyIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: L7Policy %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	if _, err := ApiHooks.NetL7PolicyDel(params.ID); err != nil {
		if strings.Contains(err.Error(), "not-exists") {
			return operations.NewDeleteConfigL7PolicyIDNotFound()
		}
		tk.LogIt(tk.LogError, "api: l7policy delete failed: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
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

// serializeL7PolicyCollection wraps every stored policy for the GET-all
// response (the registry hands them back already sorted by id).
func serializeL7PolicyCollection(policies []cmn.L7PolicyArg) *models.L7PolicyGetEntry {
	out := &models.L7PolicyGetEntry{}
	for i := range policies {
		out.L7policyAttr = append(out.L7policyAttr, serializeL7Policy(&policies[i]))
	}
	return out
}
