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

package loxinet

import (
	"errors"
	"net"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// lbSockMapCode validates a service's sockMapMode and returns its dataplane code
// (0=off,1=both,2=request,3=response). sockMapSupport is whether the daemon was
// started with --sockmapsupport; without it no sockmap BPF assets are loaded, so a
// fresh request for acceleration is refused rather than accepted and silently
// ignored. A snapshot restore replay is let through with a warning instead: failing
// it would drop the whole service on a daemon restarted without the flag, and the
// dataplane already ignores the mode when the assets are absent.
func lbSockMapCode(serv *cmn.LbServiceArg, sockMapSupport bool) (uint8, error) {
	code, ok := cmn.SockMapModeToCode(serv.SockMapMode)
	if !ok {
		return 0, errors.New("invalid sockMapMode (off|both|request|response)")
	}
	if code == 0 {
		return 0, nil
	}
	if serv.Mode != cmn.LBModeFullProxy || serv.Proto != "tcp" ||
		serv.Security != cmn.LBServPlain || !tk.IsNetIPv4(serv.ServIP) {
		return 0, errors.New("sockmap-accel requires plaintext tcp fullproxy ipv4 service")
	}
	if !sockMapSupport {
		if !serv.RestoreReplay {
			return 0, errors.New("sockmap-accel requires loxilb started with --sockmapsupport")
		}
		tk.LogIt(tk.LogWarning, "lb-rule %s:%d: sockMapMode %s restored without --sockmapsupport, not accelerated\n",
			serv.ServIP, serv.ServPort, serv.SockMapMode)
	}
	return code, nil
}

// errSockMapPerRequestL7 refuses sockmap acceleration on a service whose data
// plane rewrites or inspects bytes on every request or response.
var errSockMapPerRequestL7 = errors.New("sockmap-accel is not allowed on a service whose data plane touches every request (sse_mode, pd_disagg_mode, a declared api_key_auth, or an attached L7 policy)")

// errSockMapL7Policy is the same refusal seen from the L7 policy side.
var errSockMapL7Policy = errors.New("an L7 policy cannot be attached to a sockmap-accelerated service: acceleration is only allowed where the data plane rewrites nothing per request")

// sockMapPerRequestL7 reports whether this service's data plane does per-request
// or per-response work that acceleration would skip. Acceleration replaces the
// userspace relay with a kernel redirect, so from the moment a direction is
// accelerated userspace no longer sees those bytes and can neither inspect nor
// rewrite them. Four declarations put work on that path:
//
//   - sse_mode and pd_disagg_mode: the proxy records each request from its
//     response, and re-runs admission at every keep-alive request boundary.
//   - a declared api_key_auth, "disabled" INCLUDED: every non-empty declaration
//     gives the data plane a non-zero apikey_auth wire value, and it then strips
//     X-Api-Key before dispatch on EVERY request. An explicit "disabled" enforces
//     no credential but still claims the header's namespace for the gateway, so an
//     accelerated request direction would carry the tenant's key upstream from the
//     second keep-alive request on. This is why the test is the wire value and not
//     aiGwModeFor, which resolves "disabled" to "not an AI gateway" — a correct
//     answer to a different question (that one arms accounting, this one owns
//     header bytes).
//   - an attached L7 policy: the proxy overwrites X-Forwarded-For, adds
//     X-Forwarded-Port and -Proto, applies the insertHeaders SET/ADD/REMOVE
//     operations on every request, and can inject a Set-Cookie on every response.
//
// aiGwModeFor is deliberately left alone as a predicate: it decides ai_gw_mode
// in the data plane, which is accounting and streaming state, not byte
// ownership. Its streaming/disaggregation arm is REUSED here rather than
// re-spelled, because that expression has exactly one definition in the tree
// (scripts/check-source-invariants.sh enforces it: independent copies once
// disagreed and a DPU deployment reaped long-lived inference connections). It is
// called with an empty credential so only the sse/pd axis comes from it; the
// credential and the L7 policy are this function's own inputs, and they are
// precisely where the two predicates answer differently.
func sockMapPerRequestL7(serv *cmn.LbServiceArg, apiKeyAuth string, l7Attached bool) bool {
	return aiGwModeFor(serv.SSEMode, serv.PDDisaggMode, "") ||
		apiKeyAuthWireValue(apiKeyAuth) != 0 || l7Attached
}

// lbSockMapL7Code refuses a sockMapMode other than off on such a service and
// returns the code the rule keeps.
//
// apiKeyAuth must be the policy the rule will carry after a replace, not the
// incoming field: a replace that omits api_key_auth keeps enforcement on, so the
// incoming value alone would let acceleration through on a protected service.
// l7Attached likewise describes the listener as it is, since a policy can be
// attached long after the rule was created; NetL7PolicyAdd refuses the other
// order.
//
// A snapshot restore replay is not failed, since that would abort the whole
// loadbalancer domain. The rule is restored with acceleration off instead.
func lbSockMapL7Code(serv *cmn.LbServiceArg, code uint8, apiKeyAuth string, l7Attached bool) (uint8, error) {
	if code == 0 || !sockMapPerRequestL7(serv, apiKeyAuth, l7Attached) {
		return code, nil
	}
	if !serv.RestoreReplay {
		return 0, errSockMapPerRequestL7
	}
	tk.LogIt(tk.LogWarning, "lb-rule %s:%d: sockMapMode %s dropped on restore, not allowed where the data plane touches every request\n",
		serv.ServIP, serv.ServPort, serv.SockMapMode)
	return 0, nil
}

// sockMapDirs reports which directions a dataplane mode code accelerates
// (0=off, 1=both, 2=request, 3=response).
func sockMapDirs(code uint8) (req bool, resp bool) {
	return code == 1 || code == 2, code == 1 || code == 3
}

// sockMapModeReduces reports whether moving from one mode to another takes a
// direction AWAY. Adding one does not qualify: an existing connection is never
// accelerated retroactively, so there is nothing to act on.
func sockMapModeReduces(from, to uint8) bool {
	fromReq, fromResp := sockMapDirs(from)
	toReq, toResp := sockMapDirs(to)
	return (fromReq && !toReq) || (fromResp && !toResp)
}

// sockMapDropAccelForRule closes the connections a rule is having accelerated,
// logging rather than failing: the caller has already committed the
// configuration change, and a rule whose connections could not be dropped is
// still correctly configured — it is the live connections that lag. The reason
// it is done at all is that the verdict decides on its peer_map lookup alone, so
// without this an accelerated pair would keep redirecting under a mode that no
// longer asks for it, until it closed on its own.
func sockMapDropAccelForRule(vip string, port uint16, proto string, why string) {
	ip := net.ParseIP(vip)
	if ip == nil || mh.dpEbpf == nil {
		return
	}
	n, err := DpSockMapDropAccelConns(ip, port, l7ProtoToNum(proto))
	if err != nil {
		tk.LogIt(tk.LogDebug, "lb-rule %s:%d: %s, no accelerated connection dropped (%v)\n",
			vip, port, why, err)
		return
	}
	if n > 0 {
		tk.LogIt(tk.LogInfo, "lb-rule %s:%d: %s, dropped %d accelerated connection(s)\n",
			vip, port, why, n)
	}
}
