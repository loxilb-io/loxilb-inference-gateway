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
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	tk "github.com/loxilb-io/loxilib"
)

func ConfigGetConntrack(params operations.GetConfigConntrackAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Conntrack %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)
	// Get Conntrack informations
	res, err := ApiHooks.NetCtInfoGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	var result []*models.ConntrackEntry
	result = make([]*models.ConntrackEntry, 0)
	for _, conntrack := range res {
		var tmpResult models.ConntrackEntry
		tmpResult.ConntrackAct = conntrack.CAct
		tmpResult.ConntrackState = conntrack.CState
		tmpResult.DestinationIP = conntrack.Dip.String()
		tmpResult.DestinationPort = int64(conntrack.Dport)
		tmpResult.Protocol = conntrack.Proto
		tmpResult.Ident = conntrack.Ident
		tmpResult.SourceIP = conntrack.Sip.String()
		tmpResult.SourcePort = int64(conntrack.Sport)
		tmpResult.ServName = conntrack.ServiceName

		// lazy-on-read reconciliation: query DOCA HW counters for this
		// CT entry via dpuDebugProvider.ReconcileCtFlowStats (OffloadState enum).
		// On !doca builds or when dpuDebugProvider is nil, returns ("none", 0, 0) so
		// the model fields are omitempty and absent from JSON (backward-compat).
		// corrected: total = eBPF (MONOTONIC) + DOCA HW; no reset on offload.
		if dpuDebugProvider != nil {
			ref := CtFlowRef{
				SipStr:    conntrack.Sip.String(),
				DipStr:    conntrack.Dip.String(),
				Sport:     conntrack.Sport,
				Dport:     conntrack.Dport,
				Proto:     conntrack.Proto,
				IdentStr:  conntrack.Ident,
				EbpfPkts:  conntrack.Pkts,
				EbpfBytes: conntrack.Bytes,
			}
			offloadState, hwPkts, hwBytes := dpuDebugProvider.ReconcileCtFlowStats(ref)
			// compute reconciled totals. eBPF counter is monotonic lifetime total;
			// DOCA HW adds the offloaded-path portion. Populate model from reconciled values.
			reconciledPkts := conntrack.Pkts + hwPkts
			reconciledBytes := conntrack.Bytes + hwBytes
			tmpResult.Packets = int64(reconciledPkts)
			tmpResult.Bytes = int64(reconciledBytes)
			// New fields: omitempty ensures they're absent when OffloadState == "none".
			if offloadState != "none" {
				tmpResult.OffloadState = offloadState
				tmpResult.HwPkts = hwPkts
				tmpResult.HwBytes = hwBytes
			}
		} else {
			// No DOCA provider: fall back to eBPF-only counters (pre-v6.0 behavior).
			tmpResult.Packets = int64(conntrack.Pkts)
			tmpResult.Bytes = int64(conntrack.Bytes)
		}

		result = append(result, &tmpResult)
	}
	return operations.NewGetConfigConntrackAllOK().WithPayload(&operations.GetConfigConntrackAllOKBody{CtAttr: result})
}
