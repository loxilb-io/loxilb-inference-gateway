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
	"net"
	"strconv"
	"strings"

	"github.com/loxilb-io/loxilb/api/restapi/handler"
)

// dpuDebugProviderAdapter bridges *DpuManager (pkg/loxinet) to the extended
// handler.DpuDebugProvider interface (P49-R1). It exists because:
//
// - locked the pkg/loxinet-internal method names AllFdbHwStats /
// AllRouteHwStats / AllAclHwStats returning pkg/loxinet-internal slice
// types ([]FdbHwStats etc.). Renaming them would break
//
//		CollectHwOffloadStats and violate the 49-03↔49-04↔49-05 naming contract.
//
//	  - The handler-side DpuDebugProvider.AllFdbHwStats expects
//	    []handler.FdbHwStatsEntry. The package-boundary type conversion lives
//	    here so DpuManager stays clean and pkg/loxinet never imports handler
//	    types into its core shapes.
//
// Compile-time interface-satisfaction assertion lives in dpu_manager.go so
// grep-based acceptance criteria anchor to the registration site.
type dpuDebugProviderAdapter struct {
	*DpuManager
}

// newDpuDebugProviderAdapter wraps an existing *DpuManager so it satisfies the
// extended handler.DpuDebugProvider interface. Called from loxinet init right
// before handler.SetDpuDebugProvider.
func newDpuDebugProviderAdapter(mgr *DpuManager) *dpuDebugProviderAdapter {
	return &dpuDebugProviderAdapter{DpuManager: mgr}
}

// OffloadStatsByPipe forwards to the manager — signature already matches the
// handler interface exactly (plain string-keyed maps, no pkg-internal types).
func (a *dpuDebugProviderAdapter) OffloadStatsByPipe() (map[string]uint64, map[string]uint64, map[string]int64) {
	return a.DpuManager.OffloadStatsByPipe()
}

// AllFdbHwStats converts pkg/loxinet FdbHwStats rows to handler-package
// FdbHwStatsEntry rows. Field-by-field copy — no pointer leak (threat).
func (a *dpuDebugProviderAdapter) AllFdbHwStats() []handler.FdbHwStatsEntry {
	rows := a.DpuManager.AllFdbHwStats()
	out := make([]handler.FdbHwStatsEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, handler.FdbHwStatsEntry{
			Mac:     r.Mac,
			Port:    r.Port,
			HwBytes: r.HwBytes,
			HwPkts:  r.HwPkts,
		})
	}
	return out
}

// AllRouteHwStats converts pkg/loxinet RouteHwStats rows to handler
// RouteHwStatsEntry rows. Expected to be empty on v7.0 until
// (full FIB-seeded LPM pipe) ships.
func (a *dpuDebugProviderAdapter) AllRouteHwStats() []handler.RouteHwStatsEntry {
	rows := a.DpuManager.AllRouteHwStats()
	out := make([]handler.RouteHwStatsEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, handler.RouteHwStatsEntry{
			Dst:        r.Dst,
			NextHopMac: r.NextHopMac,
			Port:       r.Port,
			HwBytes:    r.HwBytes,
			HwPkts:     r.HwPkts,
		})
	}
	return out
}

// AllAclHwStats converts pkg/loxinet AclHwStats rows to handler
// AclHwStatsEntry rows.
func (a *dpuDebugProviderAdapter) AllAclHwStats() []handler.AclHwStatsEntry {
	rows := a.DpuManager.AllAclHwStats()
	out := make([]handler.AclHwStatsEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, handler.AclHwStatsEntry{
			RuleID:  r.RuleID,
			Action:  r.Action,
			HwBytes: r.HwBytes,
			HwPkts:  r.HwPkts,
		})
	}
	return out
}

// ReconcileCtFlowStats implements handler.DpuDebugProvider.ReconcileCtFlowStats.
// Converts the handler-side CtFlowRef to a DpCtInfo (pkg/loxinet-internal) so
// that DpDocaBf2.ReconcileCtStats can look up the DOCA entry handle and query
// the HW counter. contract: MUST NOT propagate errors — bridge failures
// return ("none", 0, 0) with the error counter bumped inside ReconcileCtStats.
//
// IdentStr parsing: cmn.CtInfo.Ident is formatted as "idtype:ident" by
// DpMapGetCt4 (dpbroker.go:991). We parse it back to uint32 fields to match
// DpCtInfo.Key format. Parsing failures default to (0, 0) which matches the
// majority of regular TCP/UDP flows.
func (a *dpuDebugProviderAdapter) ReconcileCtFlowStats(ref handler.CtFlowRef) (offloadState string, hwPkts, hwBytes uint64) {
	// Build a minimal DpCtInfo from the handler-side ref. Fields not in ref
	// (NatIP, NatPort, NatFlags, etc.) are zero-valued — safe because
	// DpCtInfo.Key only uses DIP, SIP, Dport, Sport, Proto, IdType, Ident.
	sip := net.ParseIP(ref.SipStr)
	dip := net.ParseIP(ref.DipStr)
	if sip == nil {
		sip = net.IPv4zero
	}
	if dip == nil {
		dip = net.IPv4zero
	}

	// Parse "idtype:ident" → uint32 IdType, uint32 Ident.
	var idType, ident uint32
	if ref.IdentStr != "" {
		parts := strings.SplitN(ref.IdentStr, ":", 2)
		if len(parts) == 2 {
			if v, err := strconv.ParseUint(parts[0], 10, 32); err == nil {
				idType = uint32(v)
			}
			if v, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
				ident = uint32(v)
			}
		}
	}

	ct := &DpCtInfo{
		DIP:     dip,
		SIP:     sip,
		Dport:   ref.Dport,
		Sport:   ref.Sport,
		Proto:   ref.Proto,
		IdType:  idType,
		Ident:   ident,
		Packets: ref.EbpfPkts,
		Bytes:   ref.EbpfBytes,
	}

	rs := a.DpuManager.ReconcileCtFlowStats(ct)
	return string(rs.OffloadState), rs.HwPkts, rs.HwBytes
}

// QueryDocaEntries implements handler.DpuDebugProvider.QueryDocaEntries.
// Converts pkg/loxinet-internal DocaEntryRow rows to handler.DocaEntryDetail
// to avoid a circular import between pkg/loxinet and api/restapi/handler.
func (a *dpuDebugProviderAdapter) QueryDocaEntries(filter handler.DocaQueryFilter) ([]handler.DocaEntryDetail, error) {
	rows := a.DpuManager.QueryDocaEntries(filter.Pipe, filter.Svc, filter.Ep, filter.Limit)
	if rows == nil {
		return nil, nil
	}
	out := make([]handler.DocaEntryDetail, 0, len(rows))
	for _, r := range rows {
		out = append(out, handler.DocaEntryDetail{
			EntryHandleHashed: r.EntryHandleHashed,
			FiveTuple:         r.FiveTuple,
			HwPkts:            r.HwPkts,
			HwBytes:           r.HwBytes,
			AgeMsEstimate:     0, // age-query not exercised
			PipeKey:           r.PipeKey,
		})
	}
	return out, nil
}
