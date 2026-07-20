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
	"fmt"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

func ConfigPostFW(params operations.PostConfigFirewallParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Firewall %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)
	Opts := cmn.FwOptArg{}
	Rules := cmn.FwRuleArg{}
	FW := cmn.FwRuleMod{}

	// Reject out-of-range numeric inputs instead of silently truncating them via
	// the uint16/uint8/uint32 casts below (e.g. port 70000 -> 4464, proto 262 -> 6).
	if params.Attr == nil || params.Attr.RuleArguments == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid firewall rule: ruleArguments is required")}
	}
	ra := params.Attr.RuleArguments
	if ra.MinSourcePort < 0 || ra.MaxSourcePort < 0 || ra.MinDestinationPort < 0 || ra.MaxDestinationPort < 0 ||
		ra.MinSourcePort > 65535 || ra.MaxSourcePort > 65535 || ra.MinDestinationPort > 65535 || ra.MaxDestinationPort > 65535 {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid firewall port: out of range 0-65535")}
	}
	if ra.Protocol < 0 || ra.Protocol > 255 {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid firewall protocol: out of range 0-255")}
	}
	if ra.Preference < 0 || ra.Preference > 65535 {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid firewall preference: out of range 0-65535")}
	}
	if params.Attr.Opts != nil && (params.Attr.Opts.ToPort < 0 || params.Attr.Opts.ToPort > 65535) {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid firewall toPort: out of range 0-65535")}
	}

	//Body Maker
	Rules.DstIP = params.Attr.RuleArguments.DestinationIP
	Rules.DstPortMax = uint16(params.Attr.RuleArguments.MaxDestinationPort)
	Rules.DstPortMin = uint16(params.Attr.RuleArguments.MinDestinationPort)
	Rules.InPort = params.Attr.RuleArguments.PortName
	Rules.Pref = uint32(params.Attr.RuleArguments.Preference)
	Rules.Proto = uint8(params.Attr.RuleArguments.Protocol)
	Rules.SrcIP = params.Attr.RuleArguments.SourceIP
	Rules.SrcPortMax = uint16(params.Attr.RuleArguments.MaxSourcePort)
	Rules.SrcPortMin = uint16(params.Attr.RuleArguments.MinSourcePort)
	// opt-IN per-rule HW offload flag. Without this mapping,
	// the swagger middleware drops the wire field at the model boundary and
	// AddFwRule's expressibility validator (validateHwOffloadExpressible)
	// never fires because its first check is `if !w.HwOffload { return nil }`.
	Rules.HwOffload = params.Attr.RuleArguments.HwOffload

	if Rules.DstIP == "" {
		if Rules.SrcIP == "" {
			Rules.DstIP = "0.0.0.0/0"
		} else {
			if tk.IsNetIPv4(Rules.SrcIP) {
				Rules.DstIP = "0.0.0.0/0"
			} else {
				Rules.DstIP = "::/0"
			}
		}
	}

	if Rules.SrcIP == "" {
		if Rules.DstIP == "" {
			Rules.SrcIP = "0.0.0.0/0"
		} else {
			if tk.IsNetIPv4(Rules.DstIP) {
				Rules.SrcIP = "0.0.0.0/0"
			} else {
				Rules.SrcIP = "::/0"
			}
		}
	}
	// opts
	Opts.Allow = params.Attr.Opts.Allow
	Opts.Drop = params.Attr.Opts.Drop
	Opts.Rdr = params.Attr.Opts.Redirect
	Opts.RdrPort = params.Attr.Opts.RedirectPortName
	Opts.Trap = params.Attr.Opts.Trap
	Opts.Record = params.Attr.Opts.Record
	Opts.Mark = uint32(params.Attr.Opts.FwMark)
	Opts.DoSnat = params.Attr.Opts.DoSnat
	Opts.ToIP = params.Attr.Opts.ToIP
	Opts.ToPort = uint16(params.Attr.Opts.ToPort)
	Opts.OnDefault = params.Attr.Opts.OnDefault

	FW.Rule = Rules
	FW.Opts = Opts

	if Opts.Allow {
		tk.LogIt(tk.LogInfo, "[FW] Allowed traffic: SrcIP: %s, DstIP: %s, Protocol: %d, SrcPortMin: %d, SrcPortMax: %d, DstPortMin: %d, DstPortMax: %d, Preference: %d, InPort: %s\n",
			Rules.SrcIP, Rules.DstIP, Rules.Proto, Rules.SrcPortMin, Rules.SrcPortMax, Rules.DstPortMin, Rules.DstPortMax, Rules.Pref, Rules.InPort)
	} else if Opts.Drop {
		tk.LogIt(tk.LogInfo, "[FW] Dropped traffic: SrcIP: %s, DstIP: %s, Protocol: %d, SrcPortMin: %d, SrcPortMax: %d, DstPortMin: %d, DstPortMax: %d, Preference: %d, InPort: %s\n",
			Rules.SrcIP, Rules.DstIP, Rules.Proto, Rules.SrcPortMin, Rules.SrcPortMax, Rules.DstPortMin, Rules.DstPortMax, Rules.Pref, Rules.InPort)
	}

	_, err := ApiHooks.NetFwRuleAdd(&FW)
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

func ConfigDeleteFW(params operations.DeleteConfigFirewallParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Firewall %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	Rules := cmn.FwRuleArg{}
	FW := cmn.FwRuleMod{}

	// Same range validation as POST: a truncated value here would silently
	// target a DIFFERENT rule for deletion (e.g. port 70000 -> 4464).
	for _, c := range []struct {
		name string
		val  *int64
		max  int64
	}{
		{"minSourcePort", params.MinSourcePort, 65535},
		{"maxSourcePort", params.MaxSourcePort, 65535},
		{"minDestinationPort", params.MinDestinationPort, 65535},
		{"maxDestinationPort", params.MaxDestinationPort, 65535},
		{"protocol", params.Protocol, 255},
		{"preference", params.Preference, 65535},
	} {
		if c.val != nil && (*c.val < 0 || *c.val > c.max) {
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(
				fmt.Sprintf("invalid firewall %s: out of range 0-%d", c.name, c.max))}
		}
	}

	// Body Make
	// Rule
	if params.DestinationIP != nil {
		Rules.DstIP = *params.DestinationIP
	}
	if params.MaxDestinationPort != nil {
		Rules.DstPortMax = uint16(*params.MaxDestinationPort)
	}

	if params.MinDestinationPort != nil {

		Rules.DstPortMin = uint16(*params.MinDestinationPort)
	}
	if params.PortName != nil {
		Rules.InPort = *params.PortName
	}
	if params.Preference != nil {
		Rules.Pref = uint32(*params.Preference)
	}
	if params.Protocol != nil {
		Rules.Proto = uint8(*params.Protocol)
	}
	if params.SourceIP != nil {
		Rules.SrcIP = *params.SourceIP
	}

	if Rules.DstIP == "" {
		if Rules.SrcIP == "" {
			Rules.DstIP = "0.0.0.0/0"
		} else {
			if tk.IsNetIPv4(Rules.SrcIP) {
				Rules.DstIP = "0.0.0.0/0"
			} else {
				Rules.DstIP = "::/0"
			}
		}
	}

	if Rules.SrcIP == "" {
		if Rules.DstIP == "" {
			Rules.SrcIP = "0.0.0.0/0"
		} else {
			if tk.IsNetIPv4(Rules.DstIP) {
				Rules.SrcIP = "0.0.0.0/0"
			} else {
				Rules.SrcIP = "::/0"
			}
		}
	}

	if params.MinSourcePort != nil {
		Rules.SrcPortMin = uint16(*params.MinSourcePort)
	}

	if params.MaxSourcePort != nil {
		Rules.SrcPortMax = uint16(*params.MaxSourcePort)
	}

	FW.Rule = Rules
	ret, err := ApiHooks.NetFwRuleDel(&FW)
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	if ret != 0 {
		return &ResultResponse{Result: "fail"}
	}

	tk.LogIt(tk.LogInfo, "[FW] Deleted traffic rule: SrcIP: %s, DstIP: %s, Protocol: %d, SrcPortMin: %d, SrcPortMax: %d, DstPortMin: %d, DstPortMax: %d, Preference: %d, InPort: %s\n",
		Rules.SrcIP, Rules.DstIP, Rules.Proto, Rules.SrcPortMin, Rules.SrcPortMax, Rules.DstPortMin, Rules.DstPortMax, Rules.Pref, Rules.InPort)

	return &ResultResponse{Result: "Success"}
}

func ConfigGetFW(params operations.GetConfigFirewallAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Firewall %s API called by IP: %s. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)
	res, _ := ApiHooks.NetFwRuleGet()
	var result []*models.FirewallEntry
	result = make([]*models.FirewallEntry, 0)
	for _, FW := range res {
		var tmpResult models.FirewallEntry
		var tmpRule models.FirewallRuleEntry
		var tmpOpts models.FirewallOptionEntry

		if FW.Opts.Mark&0x40000000 != 0 {
			continue
		}

		// Rule
		tmpRule.DestinationIP = FW.Rule.DstIP
		tmpRule.MaxDestinationPort = int64(FW.Rule.DstPortMax)
		tmpRule.MinDestinationPort = int64(FW.Rule.DstPortMin)
		tmpRule.PortName = FW.Rule.InPort
		tmpRule.Preference = int64(FW.Rule.Pref)
		tmpRule.Protocol = int64(FW.Rule.Proto)
		tmpRule.SourceIP = FW.Rule.SrcIP
		tmpRule.MaxSourcePort = int64(FW.Rule.SrcPortMax)
		tmpRule.MinSourcePort = int64(FW.Rule.SrcPortMin)

		// Opts
		tmpOpts.Allow = FW.Opts.Allow
		tmpOpts.Drop = FW.Opts.Drop
		tmpOpts.Redirect = FW.Opts.Rdr
		tmpOpts.RedirectPortName = FW.Opts.RdrPort
		tmpOpts.Trap = FW.Opts.Trap
		tmpOpts.Record = FW.Opts.Record
		tmpOpts.FwMark = int64(FW.Opts.Mark)
		tmpOpts.DoSnat = FW.Opts.DoSnat
		tmpOpts.ToIP = FW.Opts.ToIP
		tmpOpts.ToPort = int64(FW.Opts.ToPort)
		tmpOpts.OnDefault = FW.Opts.OnDefault
		tmpOpts.Counter = FW.Opts.Counter
		tmpResult.RuleArguments = &tmpRule
		tmpResult.Opts = &tmpOpts

		result = append(result, &tmpResult)
	}
	return operations.NewGetConfigFirewallAllOK().WithPayload(&operations.GetConfigFirewallAllOKBody{FwAttr: result})
}
