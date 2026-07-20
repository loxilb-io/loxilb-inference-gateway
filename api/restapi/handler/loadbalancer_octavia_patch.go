/*
 * Copyright (c) 2022 NetLOX Inc
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
package handler

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// ruleNotExistsErrCode mirrors pkg/loxinet.RuleNotExistsErr (an unexported control-plane
// sentinel the handler package cannot import without creating a cycle — control-plane access
// is intentionally funnelled through the ApiHooks interface). NetLbRuleAdd returns this code
// when must-exist flag is set and the target rule is absent. The value is the
// 5th entry of the rules.go error iota (RuleErrBase = -7000): -7000+4 = -6996. Guarded by a
// unit test (TestRuleNotExistsErrCodeMatchesControlPlane is N/A here since pkg/loxinet can't
// be imported; the control-plane side owns the canonical value, and the pre-apply lookup
// already returns 404 for the common absent case — this const only covers the apply-race).
const ruleNotExistsErrCode = -6996

// rawPatchBodyKey is the request-context key under which setupGlobalMiddleware stashes
// the raw PATCH merge-patch body bytes (go-swagger drains r.Body during body bind, so the
// handler cannot re-read it without this). Unexported type prevents context-key collisions.
type rawPatchBodyKey struct{}

// WithRawPatchBody returns a context carrying the raw merge-patch body bytes. Called by the
// REST middleware (configure_loxilb_rest_api.go) for PATCH on the LB composite-key path.
func WithRawPatchBody(ctx context.Context, raw []byte) context.Context {
	return context.WithValue(ctx, rawPatchBodyKey{}, raw)
}

// rawPatchBodyFromContext recovers the raw merge-patch body bytes, or nil if absent.
func rawPatchBodyFromContext(ctx context.Context) []byte {
	if v, ok := ctx.Value(rawPatchBodyKey{}).([]byte); ok {
		return v
	}
	return nil
}

// patchPresence captures which JSON keys actually appeared in the RFC 7386 merge-patch
// body. Go cannot otherwise distinguish "absent" (leave untouched) from a zero value
// : a presence map keeps the merge from silently resetting fields.
type patchPresence struct {
	// top holds the present top-level keys (e.g. "serviceArguments", "endpoints",
	// "allowedSources").
	top map[string]json.RawMessage
	// svc holds the present serviceArguments sub-keys (e.g. "name", "security", "mode").
	svc map[string]json.RawMessage
}

func parsePatchPresence(raw []byte) (*patchPresence, error) {
	p := &patchPresence{top: map[string]json.RawMessage{}, svc: map[string]json.RawMessage{}}
	if len(raw) == 0 {
		return p, nil
	}
	if err := json.Unmarshal(raw, &p.top); err != nil {
		return nil, err
	}
	if svcRaw, ok := p.top["serviceArguments"]; ok && len(svcRaw) > 0 {
		// A serviceArguments object whose value is null leaves svc empty (nothing to overlay).
		_ = json.Unmarshal(svcRaw, &p.svc)
	}
	return p, nil
}

// svcPresent reports whether a serviceArguments key appeared in the patch body.
func (p *patchPresence) svcPresent(key string) bool {
	_, ok := p.svc[key]
	return ok
}

// svcIsNull reports whether a present serviceArguments key carried an explicit JSON null
// (RFC 7386: explicit null clears a clearable field).
func (p *patchPresence) svcIsNull(key string) bool {
	v, ok := p.svc[key]
	return ok && string(v) == "null"
}

// topPresent reports whether a top-level key appeared in the patch body.
func (p *patchPresence) topPresent(key string) bool {
	_, ok := p.top[key]
	return ok
}

// ConfigPatchLoadbalancer applies an RFC 7386 JSON merge-patch to an existing L4 LB rule
// identified by its VIP/port/protocol composite key (Octavia). Present fields
// overwrite, absent fields are left untouched, explicit null clears. Immutable
// fields (security/egress/mode/protocol/VIP composite key) are rejected with 400.
// 200 on existing, 404 if the target rule is absent. POST behavior is UNCHANGED.
//
// The headline gate — an in-flight connection survives PATCH — is satisfied by building a
// fully-merged LbRuleMod and routing through NetLbRuleAdd, which lands on the existing-rule
// in-place DpCreate branch and NEVER tears down the dataplane entry for an L4 rule.
// FullProxy/L7 PATCH is rejected (out of scope) precisely to stay off the teardown path.
func ConfigPatchLoadbalancer(params operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	patchErr := func(msg string) middleware.Responder {
		tk.LogIt(tk.LogDebug, "api: PATCH lb error: %s\n", msg)
		return operations.NewPatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoBadRequest().
			WithPayload(ResultErrorResponseErrorMessage(msg))
	}

	// (1) Look up the current rule by composite key (PathMatchMode "disabled" matches the
	// creation default, exactly as ConfigDeleteLoadbalancerWithoutPath). Absent -> 404;
	// the rule is NOT created by PATCH.
	current, err := findLBRuleByKey(params.IPAddress, int64(params.Port), params.Proto)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	if current == nil {
		return operations.NewPatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoNotFound()
	}

	// (2) Presence detection (RFC 7386): learn which keys are actually
	// present so absent fields are left untouched (not zero-reset).
	raw := rawPatchBodyFromContext(params.HTTPRequest.Context())
	pres, perr := parsePatchPresence(raw)
	if perr != nil {
		return patchErr("malformed merge-patch body: " + perr.Error())
	}

	pb := params.Attr // the parsed patch body (may be nil for an empty body)

	// (3) Mode guard: only L4 modes (DNAT/FullNAT/OneArm/HostOneArm/DSR) ride the
	// in-place DpCreate path. FullProxy/L7 PATCH is out of scope and would risk the dataplane
	// teardown danger path, so reject it before any control-plane call.
	if cmn.LBMode(current.Serv.Mode) == cmn.LBModeFullProxy {
		return patchErr("cannot patch a fullproxy/L7 load balancer rule (out of scope)")
	}

	// (4) Immutable-field guard: reject any present immutable field whose
	// value differs from the current rule, BEFORE touching the control plane. Defense-in-depth:
	// the control plane (rules.go) also rejects security/egress changes.
	if pb != nil && pb.ServiceArguments != nil {
		sa := pb.ServiceArguments
		if pres.svcPresent("security") && int32(sa.Security) != int32(current.Serv.Security) {
			return patchErr("cannot modify immutable field: security")
		}
		if pres.svcPresent("egress") && sa.Egress != current.Serv.Egress {
			return patchErr("cannot modify immutable field: egress")
		}
		if pres.svcPresent("mode") && int32(sa.Mode) != int32(current.Serv.Mode) {
			return patchErr("cannot modify immutable field: mode")
		}
		// WR-03: the composite key (protocol/externalIP/port) is the PATH, which is the
		// source of truth for the targeted rule. current.Serv.* is tautologically the path
		// value (findLBRuleByKey looked the rule up BY the path), so compare the body
		// against params.* directly — this makes the intent ("body must not change the
		// path-identified composite key") explicit and is robust if the lookup key changes.
		if pres.svcPresent("protocol") && sa.Protocol != "" && sa.Protocol != params.Proto {
			return patchErr("cannot modify immutable field: protocol")
		}
		// VIP composite key (externalIP / port) is immutable — it identifies the rule.
		if pres.svcPresent("externalIP") && sa.ExternalIP != nil && *sa.ExternalIP != params.IPAddress {
			return patchErr("cannot modify immutable field: externalIP (VIP composite key)")
		}
		if pres.svcPresent("port") && sa.Port != nil && uint16(*sa.Port) != uint16(params.Port) {
			return patchErr("cannot modify immutable field: port (VIP composite key)")
		}
	}

	// (5) Build the fully-merged LbRuleMod: start from the CURRENT rule, overlay ONLY the
	// present patch keys. The composite key (VIP/port/proto) always comes from the path, never
	// the body, so the merged rule targets the same rule.
	merged := *current
	merged.Serv.ServIP = params.IPAddress
	merged.Serv.ServPort = uint16(params.Port)
	merged.Serv.Proto = params.Proto
	merged.Serv.PathMatchMode = "disabled"
	// must-exist semantics — refuse to create if the rule vanished
	// between lookup and apply (race). POST never sets this, so its upsert is unchanged.
	merged.Serv.MustExist = true

	if pb != nil && pb.ServiceArguments != nil {
		sa := pb.ServiceArguments

		// mutable scalars — overlay only when present in the body.
		if pres.svcPresent("name") {
			merged.Serv.Name = sa.Name // explicit null/"" clears the name
		}
		if pres.svcPresent("sel") {
			merged.Serv.Sel = cmn.EpSelect(sa.Sel)
		}
		if pres.svcPresent("inactiveTimeOut") {
			merged.Serv.InactiveTimeout = uint32(sa.InactiveTimeOut)
		}
		if pres.svcPresent("monitor") {
			merged.Serv.Monitor = sa.Monitor
		}
		if pres.svcPresent("probetype") {
			merged.Serv.ProbeType = sa.Probetype
		}
		if pres.svcPresent("probeport") {
			merged.Serv.ProbePort = sa.Probeport
		}
		if pres.svcPresent("probereq") {
			merged.Serv.ProbeReq = sa.Probereq
		}
		if pres.svcPresent("proberesp") {
			merged.Serv.ProbeResp = sa.Proberesp
		}
		if pres.svcPresent("probetimeout") {
			merged.Serv.ProbeTimeout = uint32(sa.ProbeTimeout)
		}
		if pres.svcPresent("proberetries") {
			merged.Serv.ProbeRetries = int(sa.ProbeRetries)
		}
		// admin_state_up. AdminStateUp is a *bool in the API model only when
		// the swagger property is a pointer; here the generated field is a value bool, so we
		// honor it solely when the key is present (absent => unchanged).
		if pres.svcPresent("adminStateUp") {
			v := sa.AdminStateUp
			merged.Serv.AdminStateUp = &v
		}
		// Explicit-null clears for clearable string fields.
		if pres.svcIsNull("name") {
			merged.Serv.Name = ""
		}
	}

	// (6) Declarative collections — replace only when the top-level key is present
	// declarative endpoint replace lands on getLBConsolidatedEPs, which preserves CT for
	// matched (IP,port) endpoints). Absent => keep the current set untouched.
	if pres.topPresent("endpoints") {
		// WR-01 / : a PATCH must NEVER tear down the rule. A present-but-empty
		// endpoints array would build merged.Eps==nil, which reaches AddLbRule's
		// `len(retEps)==0 => DeleteLbRule` branch and destroys the rule + orphans the
		// opaque id the client holds. Reject it with 400; clients remove the rule via
		// DELETE, not via an empty-array PATCH.
		if len(params.Attr.Endpoints) == 0 {
			return patchErr("clearing all members via PATCH is not allowed; use DELETE to remove the rule")
		}
		merged.Eps = nil
		for _, data := range params.Attr.Endpoints {
			var epIP string
			var epTargetPort uint16
			var epWeight uint8
			if data.EndpointIP != nil {
				epIP = *data.EndpointIP
			}
			if data.TargetPort != nil {
				epTargetPort = uint16(*data.TargetPort)
			}
			if data.Weight != nil {
				epWeight = uint8(*data.Weight)
			}
			// carry the additive member fields through the PATCH
			// path too — without this a member update silently drops backup-tier, monitorAddress,
			// and subnetId (they survive POST but not PATCH). Backup is a *bool in the model
			// (absent => primary). Mirrors the POST ingest in ConfigPostLoadbalancer.
			epBackup := false
			if data.Backup != nil {
				epBackup = *data.Backup
			}
			merged.Eps = append(merged.Eps, cmn.LbEndPointArg{
				EpIP:           epIP,
				EpPort:         epTargetPort,
				Weight:         epWeight,
				EpRole:         int(data.EpRole),
				NixlPort:       uint16(data.NixlPort),
				Backup:         epBackup,
				SubnetId:       data.SubnetID,
				MonitorAddress: data.MonitorAddress,
			})
		}
	}
	if pres.topPresent("allowedSources") {
		merged.SrcIPs = nil
		for _, data := range params.Attr.AllowedSources {
			merged.SrcIPs = append(merged.SrcIPs, cmn.LbAllowedSrcIPArg{Prefix: data.Prefix})
		}
	}

	// (7) Apply via the same hook POST uses; it dispatches to AddLbRule's existing-rule
	// in-place branch (ends in DpCreate, no dataplane teardown for L4). Map the must-exist sentinel
	// (RuleNotExistsErr) to 404; everything else to the standard error responder.
	tk.LogIt(tk.LogDebug, "api: PATCH merged lbRules : %v\n", merged)
	rc, err := ApiHooks.NetLbRuleAdd(&merged)
	if err != nil {
		if rc == ruleNotExistsErrCode {
			return operations.NewPatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoNotFound()
		}
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return patchErr(err.Error())
	}
	return operations.NewPatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoOK()
}
