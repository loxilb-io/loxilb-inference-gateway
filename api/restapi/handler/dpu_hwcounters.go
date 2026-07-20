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

package handler

import (
	"net/http"
	"strings"

	tk "github.com/loxilb-io/loxilib"
)

// HwCounterEntry is a per-flow hardware counter entry in the hwcounters response.
type HwCounterEntry struct {
	FlowID   string `json:"flow_id"`
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

// HwCountersResponse is the GET response for /netlox/v1/config/dpu/hwcounters.
type HwCountersResponse struct {
	Flows      []HwCounterEntry `json:"flows"`
	TotalFlows int              `json:"total_flows"`
}

// parseFlowKey splits a flow_key like "tcp|203.0.113.100:80->198.51.100.10:8080"
// into protocol, srcIP, dstIP components. Returns empty strings for unparseable keys.
func parseFlowKey(key string) (protocol, srcIP, dstIP string) {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) < 2 {
		return "unknown", "", ""
	}
	protocol = parts[0]

	// Parse "src_ip:port->dst_ip:port" format
	addrPart := parts[1]
	arrow := strings.Index(addrPart, "->")
	if arrow < 0 {
		return protocol, "", ""
	}

	srcPart := addrPart[:arrow]
	dstPart := addrPart[arrow+2:]

	// Extract IP by stripping :port suffix
	if idx := strings.LastIndex(srcPart, ":"); idx > 0 {
		srcIP = srcPart[:idx]
	} else {
		srcIP = srcPart
	}
	if idx := strings.LastIndex(dstPart, ":"); idx > 0 {
		dstIP = dstPart[:idx]
	} else {
		dstIP = dstPart
	}

	return protocol, srcIP, dstIP
}

// HandleDpuHwCounters handles GET /netlox/v1/config/dpu/hwcounters.
func HandleDpuHwCounters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tk.LogIt(tk.LogTrace, "api: DPU HW Counters GET called by IP: %s\n", r.RemoteAddr)

	if dpuDebugProvider == nil {
		writeJSON(w, http.StatusOK, HwCountersResponse{
			Flows:      []HwCounterEntry{},
			TotalFlows: 0,
		})
		return
	}

	rawStats := dpuDebugProvider.AllFlowHwStats()
	entries := make([]HwCounterEntry, 0, len(rawStats))
	for _, s := range rawStats {
		proto, srcIP, dstIP := parseFlowKey(s.FlowKey)
		entries = append(entries, HwCounterEntry{
			FlowID:   s.FlowKey,
			Protocol: proto,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Packets:  s.HwPkts,
			Bytes:    s.HwBytes,
		})
	}

	writeJSON(w, http.StatusOK, HwCountersResponse{
		Flows:      entries,
		TotalFlows: len(entries),
	})
}
