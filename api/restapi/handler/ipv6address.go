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
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/loxinlp"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	tk "github.com/loxilb-io/loxilib"
)

// ConfigPostIPv6Address assigns an IPv6 address to an interface. It is a 1:1 additive mirror
// of ConfigPostIPv4Address: the netlink backing (loxinlp.AddAddrNoHook ->
// nlp.ParseAddr) is protocol-generic and already IPv6-capable, so there is no IPv4/IPv6
// branching and no data-plane change.
func ConfigPostIPv6Address(params operations.PostConfigIpv6addressParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPv6 address %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	ret := loxinlp.AddAddrNoHook(*params.Attr.IPAddress, *params.Attr.Dev)
	if ret != 0 {
		return &ResultResponse{Result: "fail"}
	}
	return &ResultResponse{Result: "Success"}
}

// ConfigDeleteIPv6Address removes an IPv6 address from an interface. 1:1 mirror of
// ConfigDeleteIPv4Address — DelAddrNoHook is protocol-generic (netlink), no DP change.
func ConfigDeleteIPv6Address(params operations.DeleteConfigIpv6addressIPAddressMaskDevIfNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPv6 address   %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	ipNet := fmt.Sprintf("%s/%s", params.IPAddress, params.Mask)
	ret := loxinlp.DelAddrNoHook(ipNet, params.IfName)
	if ret != 0 {
		return &ResultResponse{Result: "fail"}
	}
	return &ResultResponse{Result: "Success"}
}

// ConfigGetIPv6Address lists addresses on interfaces. 1:1 mirror of ConfigGetIPv4Address —
// NetAddrGet is protocol-generic; it returns the same address records (no v4/v6 branching),
// mapped here onto the generated IPv6 get-entry model.
func ConfigGetIPv6Address(params operations.GetConfigIpv6addressAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPv6 address   %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	res, _ := ApiHooks.NetAddrGet()
	var result []*models.IPV6AddressGetEntry
	result = make([]*models.IPV6AddressGetEntry, 0)
	for _, ipaddrs := range res {
		// NetAddrGet is family-agnostic - keep only IPv6 entries here
		v6 := make([]string, 0, len(ipaddrs.IP))
		for _, ip := range ipaddrs.IP {
			if strings.Contains(ip, ":") {
				v6 = append(v6, ip)
			}
		}
		if len(v6) == 0 {
			continue
		}
		var tmpResult models.IPV6AddressGetEntry
		tmpResult.Dev = ipaddrs.Dev
		helperSync := int64(ipaddrs.Sync)
		tmpResult.Sync = &helperSync
		tmpResult.IPAddress = v6
		result = append(result, &tmpResult)
	}
	return operations.NewGetConfigIpv6addressAllOK().WithPayload(&operations.GetConfigIpv6addressAllOKBody{IPAttr: result})
}
