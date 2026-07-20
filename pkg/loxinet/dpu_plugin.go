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

package loxinet

import "fmt"

// ErrNotSupported is returned by DpuPlugin methods that are not implemented
// by a particular vendor plugin.
var ErrNotSupported = fmt.Errorf("operation not supported by this DPU plugin")

// ErrFwRuleNotOffloaded is returned by FwRuleDel when the rule was never
// HW-offloaded — the upstream rule table thinks it deleted a HW rule but the
// DOCA bridge has no record of it in either of the lazy DENY/ALLOW pipe entry
// maps nor in the pending-add queue. : ShadowFwRuleDel treats this
// as a no-op so the offload_active_by_pipe.acl counter doesn't underflow when
// a silent add-failure (rare after queue-drain fix, possible
// when silicon entry_status_cb rejects the entry) is followed by a Del.
var ErrFwRuleNotOffloaded = fmt.Errorf("FwRuleDel: rule was never HW-offloaded")

// DocaMeterStats holds per-meter hardware counters from DOCA shared resource query.
// BF2 returns aggregate counts only (not per-color).
type DocaMeterStats struct {
	TotalPkts  uint64
	TotalBytes uint64
}

// FlowHwStats holds per-flow hardware counters from DOCA.
//
// Direction is "forward" / "reply" for paired LB-flow entries
// programmed by pairedLBFlowOffload (see dpu_doca_bf2.go), and "" for legacy
// LBFlowOffload, route, fdb, and acl entries that are not direction-paired.
// Empty-string Direction is a first-class label value (preserved by the
// per-pipe HW counter pre-instantiation in dpu_metrics.go init).
type FlowHwStats struct {
	FlowKey   string `json:"flow_key"`
	PipeKey   string `json:"pipe_key"`
	Direction string `json:"direction"`
	HwBytes   uint64 `json:"hw_bytes"`
	HwPkts    uint64 `json:"hw_pkts"`
}

// FdbHwStats is one row in the per-FDB-entry hardware counter report.
// Emitted via multiPipeStatsProvider.AllFdbStats; consumed by the REST /dpu/debug
// fdb_entries[] array and by the Prometheus doca_fdb_entries_active metric.
// NOTE (threat): no unsafe.Pointer fields — only operator-visible data.
type FdbHwStats struct {
	Mac     string `json:"mac"`      // e.g., "aa:bb:cc:dd:ee:ff"
	Port    uint16 `json:"port"`     // DPDK forward-port ID from docaFdbOffloadEntry.fwdPortID
	HwBytes uint64 `json:"hw_bytes"` // cumulative per-entry (DOCA semantics)
	HwPkts  uint64 `json:"hw_pkts"`  // cumulative per-entry
}

// RouteHwStats is one row in the per-route hardware counter report.
// Emitted via multiPipeStatsProvider.AllRouteStats; filters d.entries where pipeKey=="route".
// (full FIB LPM pipe) postponed to v7.1 -- this surface currently
// reports the CT-path routed flows landed by RouteFlowOffload.
type RouteHwStats struct {
	Dst        string `json:"dst"`          // destination CIDR, e.g., "10.0.0.0/24"
	NextHopMac string `json:"next_hop_mac"` // resolved next-hop MAC
	Port       uint16 `json:"port"`         // egress DPDK port ID
	HwBytes    uint64 `json:"hw_bytes"`
	HwPkts     uint64 `json:"hw_pkts"`
}

// AclHwStats is one row in the per-ACL-rule hardware counter report.
// Emitted via multiPipeStatsProvider.AllAclStats; action is "DROP" or "FWD".
type AclHwStats struct {
	RuleID  uint32 `json:"rule_id"` // FwDpWorkQ.Mark / aclEntryKey.Pref surrogate
	Action  string `json:"action"`  // "DROP" | "FWD"
	HwBytes uint64 `json:"hw_bytes"`
	HwPkts  uint64 `json:"hw_pkts"`
}

// DpuCapabilities describes the offload capabilities of a DPU plugin.
// Adding new boolean fields is backwards-compatible (Go zero-values to false).
type DpuCapabilities struct {
	LBOffload          bool
	CTRouteOffload     bool
	ACLOffload         bool
	MeterOffload       bool
	L2Switching        bool
	TunnelEncap        bool
	TunnelDecap        bool
	MaxEntriesPerPipe  uint32
	MaxConcurrentPipes uint32
}

// DpuConfig holds configuration for initializing a DPU plugin.
type DpuConfig struct {
	PciAddr  string            // BF2 PCI address (e.g., "0000:03:00.0")
	Mode     string            // Plugin type identifier (e.g., "doca-bf2")
	LogLevel string            // Log verbosity level
	Extras   map[string]string // Vendor-specific config (BF2: "num_repr")
}

// DpuPlugin is the vendor-agnostic interface for DPU offload plugins.
// BF2 is the first implementation; future vendors implement the same contract.
// Methods that are not supported by a particular vendor return ErrNotSupported.
type DpuPlugin interface {
	// Lifecycle
	Init(cfg DpuConfig) error
	Shutdown() error
	Name() string
	Capabilities() DpuCapabilities

	// LB offload
	LBFlowOffload(ct *DpCtInfo, lbMark int) error
	LBFlowRemove(ct *DpCtInfo) error

	// Route offload
	RouteAdd(w *RouteDpWorkQ) error
	RouteDel(w *RouteDpWorkQ) error
	RouteFlowOffload(ct *DpCtInfo, rid int) error

	// FDB L2 offload
	FdbFlowOffload(fdb *FdbEnt) error
	FdbFlowRemove(fdb *FdbEnt) error

	// Firewall/ACL offload
	FwRuleAdd(w *FwDpWorkQ) error
	FwRuleDel(w *FwDpWorkQ) error

	// NextHop offload
	NextHopAdd(w *NextHopDpWorkQ) error
	NextHopDel(w *NextHopDpWorkQ) error

	// Meter offload (: QoS shared meter on DOCA)
	MeterAdd(w *PolDpWorkQ) error
	MeterDel(w *PolDpWorkQ) error

	// Stats
	FlowStats(ct *DpCtInfo) (bytes uint64, pkts uint64, err error)
	PipeStats(name string) (entries uint32, err error)
}
