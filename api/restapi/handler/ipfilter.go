/*
 * Copyright (c) 2022-2025 NetLOX Inc
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
 *
 * IP Filter (Whitelist/Blacklist) REST API Handlers
 * Conditional compilation: requires HAVE_DP_IP_FILTER build flag
 */
package handler

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// ConfigPostIPFilter - Add IP filter rule (whitelist or blacklist)
func ConfigPostIPFilter(params operations.PostConfigIpfilterParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPFilter %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	// Handle optional priority field with default value.
	// Range-check the raw int64 before the uint16 cast - a negative value
	// would otherwise wrap to top priority (e.g. -1 -> 65535).
	priority := uint16(100) // Default priority
	if params.Attr.Priority != nil {
		if *params.Attr.Priority < 0 || *params.Attr.Priority > 65535 {
			tk.LogIt(tk.LogError, "[IPFILTER] invalid priority: %d out of range [0, 65535]\n", *params.Attr.Priority)
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid priority: out of range [0, 65535]")}
		}
		priority = uint16(*params.Attr.Priority)
	}

	// The XDP ipfilter is zone-less by design (it runs before zone
	// classification). Reject non-zero zones instead of accepting and
	// silently ignoring them.
	if params.Attr.Zone != 0 {
		tk.LogIt(tk.LogError, "[IPFILTER] invalid zone: %d (XDP ipfilter is zone-less, must be 0)\n", params.Attr.Zone)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid zone: XDP ipfilter is zone-less, zone must be 0 or omitted")}
	}

	fm := cmn.IPFilterMod{
		FilterType: *params.Attr.FilterType,
		CIDR:       *params.Attr.Cidr,
		Zone:       0,
		Priority:   priority,
		Action:     *params.Attr.Action,
	}

	// Validate filter type
	if fm.FilterType != "whitelist" && fm.FilterType != "blacklist" {
		tk.LogIt(tk.LogError, "[IPFILTER] Invalid filter type: %s (must be 'whitelist' or 'blacklist')\n", fm.FilterType)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("Invalid filter type: must be 'whitelist' or 'blacklist'")}
	}

	// Validate action
	if fm.Action != "allow" && fm.Action != "drop" {
		tk.LogIt(tk.LogError, "[IPFILTER] Invalid action: %s (must be 'allow' or 'drop')\n", fm.Action)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("Invalid action: must be 'allow' or 'drop'")}
	}

	// The datapath only acts on whitelist+allow and blacklist+drop; the other
	// two combinations would be accepted and silently dead. Reject them.
	if fm.FilterType == "whitelist" && fm.Action != "allow" {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid action: whitelist rules must use action 'allow'")}
	}
	if fm.FilterType == "blacklist" && fm.Action != "drop" {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid action: blacklist rules must use action 'drop'")}
	}

	// Validate CIDR
	if fm.CIDR == "" {
		tk.LogIt(tk.LogError, "[IPFILTER] CIDR is required\n")
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("CIDR is required")}
	}

	tk.LogIt(tk.LogDebug, "[IPFILTER] Add %s rule: CIDR=%s, Zone=%d, Priority=%d, Action=%s\n",
		fm.FilterType, fm.CIDR, fm.Zone, fm.Priority, fm.Action)

	tk.LogIt(tk.LogDebug, "[IPFILTER] >>> Calling NetIPFilterAdd: filterType=%s cidr=%s action=%s zone=%d priority=%d\n",
		fm.FilterType, fm.CIDR, fm.Action, fm.Zone, fm.Priority)

	_, err := ApiHooks.NetIPFilterAdd(&fm)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPFILTER] Failed to add rule: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigDeleteIPFilter - Delete IP filter rule
func ConfigDeleteIPFilter(params operations.DeleteConfigIpfilterParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPFilter %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	fm := cmn.IPFilterMod{}

	// Extract query parameters - these are required fields, not pointers
	fm.FilterType = params.FilterType
	fm.CIDR = params.Cidr

	if params.Zone != nil {
		fm.Zone = uint8(*params.Zone)
	}

	// Validate filter type
	if fm.FilterType != "whitelist" && fm.FilterType != "blacklist" {
		tk.LogIt(tk.LogError, "[IPFILTER] Invalid filter type: %s\n", fm.FilterType)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("Invalid filter type")}
	}

	_, err := ApiHooks.NetIPFilterDel(&fm)
	if err != nil {
		tk.LogIt(tk.LogError, "[IPFILTER] Failed to delete rule: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigGetIPFilter - Get all IP filter rules with statistics
func ConfigGetIPFilter(params operations.GetConfigIpfilterParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPFilter %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	res, err := ApiHooks.NetIPFilterGet()
	if err != nil {
		tk.LogIt(tk.LogError, "[IPFILTER] Failed to get rules: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	var result []*models.IPFilterEntry
	for _, ipf := range res {
		filterType := ipf.FilterType
		cidr := ipf.CIDR
		priority := int64(ipf.Priority)
		action := ipf.Action

		entry := models.IPFilterEntry{
			FilterType: &filterType,
			Cidr:       &cidr,
			Zone:       int64(ipf.Zone),
			Priority:   &priority,
			Action:     &action,
			Packets:    int64(ipf.Packets),
			Bytes:      int64(ipf.Bytes),
		}

		result = append(result, &entry)
	}

	return operations.NewGetConfigIpfilterOK().WithPayload(&operations.GetConfigIpfilterOKBody{
		IPFilterAttr: result,
	})
}

// ConfigGetIPFilterAll - Get all IP filter rules with statistics (for /all endpoint)
func ConfigGetIPFilterAll(params operations.GetConfigIpfilterAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: IPFilter %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	res, err := ApiHooks.NetIPFilterGet()
	if err != nil {
		tk.LogIt(tk.LogError, "[IPFILTER] Failed to get rules: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	var result []*models.IPFilterEntry
	for _, ipf := range res {
		filterType := ipf.FilterType
		cidr := ipf.CIDR
		priority := int64(ipf.Priority)
		action := ipf.Action

		entry := models.IPFilterEntry{
			FilterType: &filterType,
			Cidr:       &cidr,
			Zone:       int64(ipf.Zone),
			Priority:   &priority,
			Action:     &action,
			Packets:    int64(ipf.Packets),
			Bytes:      int64(ipf.Bytes),
		}

		result = append(result, &entry)
	}

	return operations.NewGetConfigIpfilterAllOK().WithPayload(&operations.GetConfigIpfilterAllOKBody{
		IPFilterAttr: result,
	})
}
