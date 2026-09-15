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

// errSockMapAiGateway refuses sockmap acceleration on an AI gateway service.
var errSockMapAiGateway = errors.New("sockmap-accel is not allowed on an AI gateway service (sse_mode, pd_disagg_mode or api_key_auth)")

// lbSockMapAiGwCode refuses a sockMapMode other than off on a service that does
// AI-gateway processing, and returns the code the rule keeps. Such a service needs
// userspace to see every request and every response on a connection: the proxy
// re-runs admission (the API key and the rate limit among its checks) at each
// keep-alive request boundary and records the request from its response. Once a
// direction is accelerated the kernel moves those bytes between the sockets, so on
// the same connection the second and later requests reach the backend unchecked,
// and responses are never recorded.
//
// apiKeyAuth must be the policy the rule will carry after a replace, not the
// incoming field: a replace that omits api_key_auth keeps enforcement on, so the
// incoming value alone would let acceleration through on a protected service.
//
// A snapshot restore replay is not failed, since that would abort the whole
// loadbalancer domain. The rule is restored with acceleration off instead.
func lbSockMapAiGwCode(serv *cmn.LbServiceArg, code uint8, apiKeyAuth string) (uint8, error) {
	if code == 0 || !aiGwModeFor(serv.SSEMode, serv.PDDisaggMode, apiKeyAuth) {
		return code, nil
	}
	if !serv.RestoreReplay {
		return 0, errSockMapAiGateway
	}
	tk.LogIt(tk.LogWarning, "lb-rule %s:%d: sockMapMode %s dropped on restore, not allowed on an AI gateway service\n",
		serv.ServIP, serv.ServPort, serv.SockMapMode)
	return 0, nil
}
