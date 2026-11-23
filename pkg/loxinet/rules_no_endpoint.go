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
	"fmt"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// A host|path fullproxy rule may stand with no endpoints. The data plane then
// answers the requests its pool takes by the rule's no-endpoint status
// (loxilb-ebpf common/sockproxy_no_ep.h), and such a request goes to no other
// rule: not to a shorter path prefix of the same host, which would serve it
// with another rule's backend. A controller keeps the rule, with no
// endpoints, while its backend has none ready or is invalid.
//
// A rule of any other shape keeps refusing an empty endpoint list. Each
// exclusion below is a shape whose answer would not be the rule's own, or
// whose configuration is built from its endpoints.

// lbZeroEndpointsRefusal - why the rule serv describes may not stand with no
// endpoints, or nil when it may.
func lbZeroEndpointsRefusal(serv *cmn.LbServiceArg) error {
	switch {
	case serv.Mode != cmn.LBModeFullProxy:
		// Only the proxy answers a request; an L4 rule has no one to.
		return errors.New("only a fullproxy rule may have no endpoints")
	case serv.HostUrl == "" && serv.PathPrefix == "":
		return errors.New("only a rule with a host or a path_prefix may have no endpoints")
	case serv.Proto != "tcp" || !tk.IsNetIPv4(serv.ServIP):
		// The IPv4 TCP fullproxy rules are the ones the proxy alone serves.
		return errors.New("only an IPv4 tcp rule may have no endpoints")
	case serv.ModelName != "":
		return errors.New("a rule with a model_name may not have no endpoints")
	case serv.PDDisaggMode:
		return errors.New("a pd_disagg_mode rule may not have no endpoints")
	case serv.KvExactMode != 0:
		return errors.New("a kvExactMode rule may not have no endpoints")
	case serv.EppEndpoint != "":
		return errors.New("a rule with an Endpoint Picker may not have no endpoints")
	case serv.MCPProtocolVersion != "":
		return errors.New("an MCP rule may not have no endpoints")
	case serv.Sel == cmn.LbSelN2:
		// An N2 listener does not route by host or path.
		return errors.New("an n2 rule may not have no endpoints")
	case serv.Sel == cmn.LbSelCHWBL || serv.Sel == cmn.LbSelWRRHash:
		// Their hash ring is built from the endpoints.
		return errors.New("a chwbl or wrr-hash rule may not have no endpoints")
	}
	return nil
}

// lbNoEndpointStatus - the no-endpoint status serv asks for, resolved: 503
// when it names none. 500 is taken only by a rule that may have no
// endpoints: on any other it would never be answered, and a controller that
// sends it means a rule this gateway does not keep.
func lbNoEndpointStatus(serv *cmn.LbServiceArg) (int, error) {
	switch serv.NoEndpointStatus {
	case 0, cmn.NoEndpointStatusUnavailable:
		return cmn.NoEndpointStatusUnavailable, nil
	case cmn.NoEndpointStatusInternal:
		if err := lbZeroEndpointsRefusal(serv); err != nil {
			return 0, fmt.Errorf("no_endpoint_status 500: %w", err)
		}
		return cmn.NoEndpointStatusInternal, nil
	}
	return 0, fmt.Errorf("no_endpoint_status: %d is neither 503 nor 500", serv.NoEndpointStatus)
}

// lbNoEndpointDpStatus - the data plane's code for a no-endpoint status:
// SP_NO_EP_STATUS_503 (0) or SP_NO_EP_STATUS_500 (1).
func lbNoEndpointDpStatus(status int) uint8 {
	if status == cmn.NoEndpointStatusInternal {
		return 1
	}
	return 0
}

// lbZeroEndpointEdge - an update that takes a rule from no endpoints to some,
// or from some to none. Such an update is applied to the data plane in place:
// removing the pool and adding it back would hand the requests that arrive
// in between to a shorter prefix's rule.
func lbZeroEndpointEdge(oldEps, newEps []ruleLBEp) bool {
	return (len(oldEps) == 0) != (len(newEps) == 0)
}
