//go:build doca

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

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	opts "github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/singleflight"
)

// docaCircuitBreaker protects against cascading DOCA offload failures.
// After cbThreshold consecutive failures, all offloads return early for cbCooldown.
type docaCircuitBreaker struct {
	consecutiveFailures atomic.Int32
	state               atomic.Int32 // 0=closed (normal), 1=open (tripped)
	lastTripped         atomic.Int64 // unix timestamp when breaker tripped
	// forced is a test-only override: when 1, allow always returns false and
	// recordSuccess will not auto-close the breaker. Set exclusively by
	// ForceOpen/ForceClose (reachable only through the debug REST endpoint).
	forced atomic.Int32
}

const (
	cbClosed      int32 = 0
	cbOpen        int32 = 1
	cbThreshold   int32 = 5
	cbCooldownSec int64 = 30
)

// allow returns true if offload should proceed, false if breaker is open.
func (cb *docaCircuitBreaker) allow() bool {
	if cb.forced.Load() == 1 {
		return false
	}
	if cb.state.Load() == cbClosed {
		return true
	}
	trippedAt := cb.lastTripped.Load()
	if time.Now().Unix()-trippedAt >= cbCooldownSec {
		cb.state.Store(cbClosed)
		cb.consecutiveFailures.Store(0)
		docaCircuitBreakerStateGauge.Set(0)
		logrus.Info("doca-bf2: circuit breaker reset after cooldown")
		return true
	}
	return false
}

// recordSuccess resets the consecutive failure counter and closes breaker if open.
func (cb *docaCircuitBreaker) recordSuccess() {
	if cb.forced.Load() == 1 {
		// Test-only override pinned OPEN — do not auto-close on success so the
		// degraded-path benchmark remains on the eBPF fallback for its full run.
		return
	}
	cb.consecutiveFailures.Store(0)
	if cb.state.CompareAndSwap(cbOpen, cbClosed) {
		docaCircuitBreakerStateGauge.Set(0)
		logrus.Info("doca-bf2: circuit breaker reset on success")
	}
}

// IsOpen reports whether the circuit breaker is currently tripped.
// Safe to call from any goroutine.
func (cb *docaCircuitBreaker) IsOpen() bool {
	return cb.state.Load() == cbOpen
}

// ForceOpen pins the breaker OPEN and suppresses auto-reset/recordSuccess
// side-effects until ForceClose is called. Test-only hook exposed through
// the debug REST endpoint so CICD scripts can drive the eBPF fallback path
// deterministically without racing DOCA initialisation.
func (cb *docaCircuitBreaker) ForceOpen() {
	cb.forced.Store(1)
	cb.state.Store(cbOpen)
	cb.lastTripped.Store(time.Now().Unix())
	docaCircuitBreakerStateGauge.Set(1)
	logrus.Warn("doca-bf2: circuit breaker force-opened via debug hook")
}

// ForceClose clears the forced-open override and returns the breaker to
// normal operation (closed, failure counter reset).
func (cb *docaCircuitBreaker) ForceClose() {
	cb.forced.Store(0)
	cb.state.Store(cbClosed)
	cb.consecutiveFailures.Store(0)
	docaCircuitBreakerStateGauge.Set(0)
	logrus.Info("doca-bf2: circuit breaker force-closed via debug hook")
}

// recordFailure increments the failure counter and trips the breaker at threshold.
func (cb *docaCircuitBreaker) recordFailure() {
	n := cb.consecutiveFailures.Add(1)
	if n >= cbThreshold {
		if cb.state.CompareAndSwap(cbClosed, cbOpen) {
			cb.lastTripped.Store(time.Now().Unix())
			docaCircuitBreakerStateGauge.Set(1)
			logrus.Warn("doca-bf2: circuit breaker tripped after 5 consecutive failures")
		}
	}
}

// CircuitBreakerOpen returns the current breaker state. Implements the
// circuitBreakerProvider interface in dpu_manager.go, which surfaces CB state
// through the handler.DpuDebugProvider used by /netlox/v1/config/dpu/debug.
func (d *DpDocaBf2) CircuitBreakerOpen() bool {
	return d.circuitBreaker.IsOpen()
}

// CircuitBreakerForce applies a test-only debug override to the CB state.
// mode is "open" or "close". Called from the debug REST endpoint so CICD
// scenarios can deterministically exercise the degraded (eBPF fallback) path.
func (d *DpDocaBf2) CircuitBreakerForce(mode string) error {
	switch mode {
	case "open":
		d.circuitBreaker.ForceOpen()
		return nil
	case "close":
		d.circuitBreaker.ForceClose()
		return nil
	default:
		return fmt.Errorf("doca-bf2: CircuitBreakerForce: unknown mode %q (expected open|close)", mode)
	}
}

// DOCA forward action constants (must match llb_doca_fwd_type_t in loxilb_doca_flow.h)
const (
	docaFwdPort = 1 // LLB_DOCA_FWD_PORT
)

// Default pipe capacities (must match CGO init: 8192 * 2 = 16384 per pipe).
// docaDefaultTCPPipeCapacityAggregate is declared next to the
// gauge it feeds in dpu_metrics.go; this file retains the per-pipe sizing
// constants used by the C-side init code path.
const (
	docaDefaultTCPPipeCapacity = 16384
	docaDefaultUDPPipeCapacity = 16384
	docaHighWaterMark          = 0.8 // 80% utilization triggers warning
)

// countEntriesForPipe counts Go-tracked entries belonging to the given pipeKey ("ct" or "udp_ct").
func countEntriesForPipe(entries map[string]*docaOffloadEntry, pipeKey string) int {
	count := 0
	for _, oe := range entries {
		if oe.pipeKey == pipeKey {
			count++
		}
	}
	return count
}

// retryEntry holds a copy of offload parameters for retry after transient DOCA failure.
// CRITICAL: ctInfo is copied by VALUE -- the perf buffer source is ephemeral.
type retryEntry struct {
	flowKey  string
	ctInfo   DpCtInfo // copied by value, not a pointer
	attempts int
	isLB     bool // true for LBFlowOffload, false for RouteFlowOffload
}

const (
	retryMaxAttempts = 3    // abandon after this many failed retries
	retryQueueMaxCap = 8192 // bounded at pipe capacity to prevent unbounded memory growth
)

// docaFdbOffloadEntry tracks a single FDB MAC offload entry in the DOCA FDB pipe.
type docaFdbOffloadEntry struct {
	pipe      unsafe.Pointer
	entry     unsafe.Pointer
	evicting  atomic.Uint32 // CAS guard prevents double-eviction
	userCtx   uint64
	fwdPortID uint16 // P49-R2: DPDK forward-port ID for AllFdbStats label
}

// ACL pipe capacity constant (must match LLB_DOCA_ACL_PIPE_CAPACITY in loxilb_doca_flow.h)
const LLB_DOCA_ACL_PIPE_CAPACITY = 4096

// aclEntryKey uniquely identifies an ACL deny rule for the in-memory map.
// Proto is NOT in the key because only proto=0 (any protocol) rules are offloaded.
// TRANSPORT l4_type_ext matches ports regardless of protocol, so protocol-specific
// deny rules cannot be correctly enforced in HW and must stay on eBPF.
type aclEntryKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Pref    uint16
}

// docaACLEntry stores an ACL deny rule's match fields + CIDR masks for pipe rebuild.
type docaACLEntry struct {
	key     aclEntryKey
	srcMask uint32         // CIDR mask for src IP (from w.SrcIP.Mask)
	dstMask uint32         // CIDR mask for dst IP (from w.DstIP.Mask)
	pref    uint16         // rule priority (lower = higher priority)
	entry   unsafe.Pointer // P49-R2: DOCA entry handle for AllAclStats; nil during pipe rebuild.
}

// docaMeterEntry tracks an active DOCA shared meter for stats collection and cleanup.
type docaMeterEntry struct {
	mark      int            // original PolDpWorkQ.Mark (1-based)
	cir       uint64         // committed info rate (bps)
	name      string         // policer name for Prometheus labels
	active    bool           // true when meter is configured and bound
	pipeEntry unsafe.Pointer // meter pipe entry handle (for removal on MeterDel)
	pipe      unsafe.Pointer // meter pipe handle
}

// docaOffloadEntry tracks both the pipe and entry handles for a single offloaded flow.
type docaOffloadEntry struct {
	pipe             unsafe.Pointer
	entry            unsafe.Pointer
	pipeKey          string
	pkey             []byte         // eBPF CT map key for tombstone write on DOCA aging eviction
	evicting         atomic.Uint32  // CAS guard prevents double-eviction
	userCtx          uint64         // unique ID for aged-entry identification
	lbMark           int            // LB rule mark -- enables MeterAdd live update by LB mark
	Direction        string         // prep: "forward" / "reply" / "" — populated by paired offload; empty for legacy/route/FDB/ACL entries (P51-04 reads this for AllFlowStats label).
	fwdPortID        uint16         // trace: DPDK forward-port ID at offload time (populated by pairedLBFlowOffload; 0 for legacy/route/FDB/ACL entries)
	pairedSteerEntry unsafe.Pointer // B23-03 vestigial: was set by paired-add when g_egress_steer was active. Always nil post--06 (TX-1) — g_egress_steer_pipe deleted, paired-add replaced by g_egress_dispatch's static init-time entries. Field kept for stub-symmetry with dpu_doca_bf2_stub.go; safe to remove in a follow-up cleanup.
	siblingKey       string         // paired-entry flowKey for non-NAT route flows. One eBPF CT entry → two DOCA entries (forward on g_ct_fwd_pipe, reverse on g_ct_rev_pipe); teardown of either cascades to the other so g_ct_rev_pipe cannot leak. Empty for LB pairs (each direction is its own eBPF CT entry → its own removal call), FDB, ACL, and the forward-only route fallback.
}

// aclPending — : a queued FwRule add waiting for the next debounce
// flush. The em byte buffer is caller-allocated via C.calloc inside FwRuleAdd
// and freed by flushAclPending after the CGO call returns (success or failure).
// onDone is the per-entry result channel; FwRuleAdd blocks on it.
//
// Per-entry CIDR masks are NOT supported on DOCA 2.9.4 BASIC pipes — the
// pipe-level template mask set at create time is the only mask.
// "CIDR via per-entry mask" was infeasible; exact-IP rules only, enforced by
// validateHwOffloadExpressible rejecting non-/32 prefixes.
type aclPending struct {
	hash   string         // ruleEnt-style stable key (action+5-tuple)
	action byte           // 0=deny (FWD_DROP) / 1=allow (FWD_PIPE → CT_FWD)
	em     unsafe.Pointer // *C.struct_doca_flow_match (caller-allocated, exact-IP values)
	onDone chan error     // closed/sent-to by flushAclPending; bounded ≤ aclDebounceMs wait
}

// aclBatchCap — : synchronous flush trigger when pending Adds
// reach this many entries. Bounds memory under burst load.
const aclBatchCap = 128

// aclDebounceMs — : idle-debounce window; first enqueue arms a
// time.AfterFunc, re-arms on each subsequent enqueue, cap-cancels on aclBatchCap
// hit. 50ms is well under any meaningful traffic window (eBPF mirror
// authoritative during install latency).
const aclDebounceMs = 50 * time.Millisecond

// DpDocaBf2 implements DpuPlugin for NVIDIA BlueField-2 via the DOCA CGO bridge.
type DpDocaBf2 struct {
	entries        map[string]*docaOffloadEntry // flowKey -> DOCA CT offload entry (NAT + route)
	portMap        map[[6]byte]uint16           // MAC -> DPDK port_id
	reversePortMap map[uint16][6]byte           // DPDK port_id -> MAC (reverse of portMap)
	ifindexToPort  map[int]uint16               // Linux ifindex -> DPDK port_id (VF rep interface mapping)
	portCount      int                          // total ports (PF + VF reprs)

	// A1: split mtx into per-domain mutexes (deadlock prevention + Prometheus scrape parallelism).
	//
	// Lock-acquisition order (NEVER violate — deadlock prevention):
	//   ctMtx → fdbMtx → userCtxMu → statsRWMu (writer paths)
	//
	// read-path rule (API p99 < 100ms under monitoring):
	//   Stats functions (FlowStats, AllFlowStats, AllFdbStats, AllRouteStats,
	//   AllAclStats, ActiveMeters) MUST take statsRWMu.RLock as the OUTER guard
	//   (so Shutdown's statsRWMu.Lock still drains in-flight scrapes), then
	//   acquire the appropriate domain mutex INSIDE for snapshot-only:
	//     - ctMtx for d.entries / d.meterMap
	//     - fdbMtx for d.fdbEntries / d.aclEntries
	// The domain mutex MUST be released BEFORE any DocaEntryQuery / submit
	//   call. Holding statsRWMu only is INSUFFICIENT — it does not cross-
	//   serialize against ctMtx/fdbMtx writers, which causes Go runtime
	//   `fatal error: concurrent map iteration and map write` panics.
	//
	// pairMu is INDEPENDENT (D-W-03 invariant — -INV-02).
	//
	// NEVER hold any of these across DOCA submit / DocaEntryAddBasic /
	// DocaEntryRemove — lesson; see anti-pattern doc at line 1193.
	ctMtx          sync.Mutex   // CT domain: entries, lbMarkToMeter, lbMarkToFlowKeys, route entries, meter entries
	fdbMtx         sync.Mutex   // FDB+ACL domain: fdbEntries, aclEntries, aclDenyEntries, aclAllowEntries, hasFdbPipe (RESEARCH OPEN Q2 — ACL folded here)
	userCtxMu      sync.Mutex   // userCtxToKey writes from BOTH CT and FDB paths (RESEARCH OPEN Q1 — 4th mutex subordinate to ctMtx/fdbMtx)
	statsRWMu      sync.RWMutex // RLock for read paths (outer drain guard); Lock for Shutdown. Read paths must additionally take ctMtx/fdbMtx for snapshot.
	initialized    bool
	bridge         *DocaBridge
	circuitBreaker docaCircuitBreaker // CGO-08: circuit breaker for offload failures
	offloadActive  atomic.Int64       // CGO-07: accurate active offloaded flow count

	// aging configuration and reverse lookup
	tcpAgingSec  uint32            // per-service TCP idle timeout (default 120s)
	udpAgingSec  uint32            // per-service UDP idle timeout (default 30s)
	aiAgingSec   uint32            // per-service AI/SSE idle timeout (default 3600s)
	userCtxToKey map[uint64]string // reverse lookup: userCtx -> flowKey
	nextUserCtx  atomic.Uint64     // monotonic counter for unique userCtx IDs

	// -03: retry queue for transient DOCA offload failures
	retryQueue []retryEntry // bounded pending-retry queue, protected by retryMu
	retryMu    sync.Mutex   // protects retryQueue (goCtHwOffloadHandler adds, worker thread processes)

	// FDB L2 offload entries
	fdbEntries map[string]*docaFdbOffloadEntry // macKey ("fdb:xx:xx:xx:xx:xx:xx") -> FDB offload entry

	// ACL deny-rule offload entries (HwOffload=false path, kept for audit
	// visibility carry-forward — populated only by the legacy
	// rebuild path that is no longer wired post-). atomic-rebuild
	// state (aclRebuildTimer/aclRebuildMu/aclPipeHandle) retired in favor of the
	// lazy DENY+ALLOW pipe pair + per-entry debouncer.
	aclEntries map[aclEntryKey]*docaACLEntry
	hasFdbPipe bool // cached FDB pipe availability (set once at init, avoids submit in Capabilities)

	// === : lazy DENY+ALLOW pipe pair + debounce queue ===
	// Lock-graph: aclLifecycleMu is leaf subordinate to fdbMtx; aclBatchMu is
	// independent of fdbMtx but MUST NOT be held across DocaBridge.submit.
	aclDenyEntries  map[string]*docaOffloadEntry // ruleEnt-key → opaque DENY entry handle
	aclAllowEntries map[string]*docaOffloadEntry // ruleEnt-key → opaque ALLOW entry handle
	aclPipesUp      bool                         // false until first HwOffload=true rule lands
	aclLifecycleMu  sync.Mutex                   // serializes OPENING / CLOSING transitions
	aclPendingAdd   []aclPending                 // debounce queue: queued adds, drained by flush
	aclPendingDel   []string                     // debounce queue: queued dels (by hash)
	aclBatchMu      sync.Mutex                   // guards aclPendingAdd / aclPendingDel / aclBatchTimer
	aclBatchTimer   *time.Timer                  // re-armed time.AfterFunc; cap-cancelled on aclBatchCap hit

	// QoS meter offload tracking
	meterMap         map[uint32]*docaMeterEntry // DOCA meter ID (0-based) -> meter entry
	lbMarkToMeter    map[int]uint32             // LB rule mark -> DOCA meter ID (auto-attach lookup)
	lbMarkToFlowKeys map[int][]string           // LB mark -> list of flowKeys (reverse index for O(1) live update)
	meterOffload     bool                       // true when DOCA meter init succeeded

	// === (bidirectional pairing) ===
	bidirEnabled bool                    // kill-switch (read once at Init; default ON)
	pendingPair  map[string]*pendingPair // connKey -> half-or-full pair
	pairMu       sync.Mutex              // guards pendingPair only (NOT ctMtx, NOT fdbMtx, NOT userCtxMu, NOT statsRWMu — invariant preserved)

	// A3: per-IP singleflight collapse for resolveFlowMACs.
	// 10 concurrent iperf3 sessions targeting the same dest IP collapse
	// into ONE netlink.NeighList scan. INDEPENDENT of every other mutex
	// in this struct (including pairMu) — singleflight.Group's internal
	// lock is leaf-level by design and must not participate in the
	// loxilb lock graph.
	resolveSF singleflight.Group

	// === B23-02 (deferred-retry queue, capacity-gated) ===
	deferredOffload sync.Map                                   // key=string(fwd.Key) value=*deferredEntry; 3-attempt cap; capacity-gated sweep. -06 (TX-1): the rationale for the queue (g_egress_steer capacity exhaustion) is gone because deleted the steer pipe. Producers (markDeferred call sites in pairedLBFlowOffload rollback paths) and consumer (sweepDeferred via agingPollCycle) are preserved as a generic transient-DOCA-error retry queue. Removable with deferred_offload.go in a follow-up cleanup.
	pairedOffloadFn func(fwd, rev *DpCtInfo, lbMark int) error // test-only override; nil = use d.pairedLBFlowOffload
}

// NewDpDocaBf2 creates a new BF2 DPU plugin instance.
func NewDpDocaBf2() *DpDocaBf2 {
	return &DpDocaBf2{
		entries:          make(map[string]*docaOffloadEntry),
		portMap:          make(map[[6]byte]uint16),
		reversePortMap:   make(map[uint16][6]byte),
		userCtxToKey:     make(map[uint64]string),
		fdbEntries:       make(map[string]*docaFdbOffloadEntry),
		aclEntries:       make(map[aclEntryKey]*docaACLEntry),
		meterMap:         make(map[uint32]*docaMeterEntry),
		lbMarkToMeter:    make(map[int]uint32),
		lbMarkToFlowKeys: make(map[int][]string),
		pendingPair:      make(map[string]*pendingPair), //
		// lazy DENY+ALLOW maps start empty; pipes stay CLOSED
		// until the first FwRuleAdd with HwOffload=true triggers ensureAclPipesUp.
		aclDenyEntries:  make(map[string]*docaOffloadEntry),
		aclAllowEntries: make(map[string]*docaOffloadEntry),
		aclPipesUp:      false,
		aclPendingAdd:   nil,
		aclPendingDel:   nil,
	}
}

// Bridge returns the DocaBridge reference for heartbeat monitoring.
// A1: read-only path uses statsRWMu.RLock so concurrent Prometheus
// scrapes parallelize against hot-path writers.
func (d *DpDocaBf2) Bridge() *DocaBridge {
	d.statsRWMu.RLock()
	defer d.statsRWMu.RUnlock()
	return d.bridge
}

// detectSriovVFs determines the VF representor count for the given PCI address.
// Detection order:
//  1. /sys/bus/pci/devices/<addr>/sriov_numvfs (host-side SR-IOV count)
//  2. Count /sys/class/net/pf0vf* representors (DPU switchdev mode)
//  3. Fallback to 2
func detectSriovVFs(pciAddr string) uint32 {
	// Try direct PCI sysfs path (works on host, often 0 on DPU)
	path := fmt.Sprintf("/sys/bus/pci/devices/%s/sriov_numvfs", pciAddr)
	data, err := os.ReadFile(path)
	if err == nil {
		if n, e := strconv.Atoi(strings.TrimSpace(string(data))); e == nil && n > 0 {
			return uint32(n)
		}
	}
	// Try with 0000: domain prefix if not already present
	if !strings.HasPrefix(pciAddr, "0000:") && len(pciAddr) <= 7 {
		path = fmt.Sprintf("/sys/bus/pci/devices/0000:%s/sriov_numvfs", pciAddr)
		data, err = os.ReadFile(path)
		if err == nil {
			if n, e := strconv.Atoi(strings.TrimSpace(string(data))); e == nil && n > 0 {
				return uint32(n)
			}
		}
	}
	// On DPU in switchdev mode, sriov_numvfs is 0 because VFs are created
	// on the host side. Detect by counting VF representor netdevs instead.
	matches, err := filepath.Glob("/sys/class/net/pf0vf*")
	if err == nil && len(matches) > 0 {
		return uint32(len(matches))
	}
	return 2 // fallback default
}

// Init initializes the DOCA bridge. On failure, returns error (DpuManager will log+swallow).
// A1: Init takes ctMtx as the broadest lock; fdbMtx, userCtxMu, statsRWMu are
// inactive at this point (no goroutines spawned yet that touch the other domains).
func (d *DpDocaBf2) Init(cfg DpuConfig) error {
	d.ctMtx.Lock()
	defer d.ctMtx.Unlock()

	// RC#4: Auto-detect VF count from sysfs, with explicit config override
	numRepr := detectSriovVFs(cfg.PciAddr)
	if cfg.Extras != nil {
		if v, ok := cfg.Extras["num_repr"]; ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				numRepr = uint32(n)
			}
		}
	}

	if err := DocaInit(cfg.PciAddr, numRepr); err != nil {
		return fmt.Errorf("doca-bf2 init failed: %w", err)
	}
	d.bridge = docaBridgeInstance
	d.initialized = true

	// Enable meter offload -- shared meters are pre-allocated at C init (64 slots)
	// If DOCA init succeeded above, meter pool is available.
	d.meterOffload = true
	logrus.Info("DpDocaBf2: MeterOffload enabled (64 shared meters pre-allocated)")

	// Load aging configuration from CLI options
	d.tcpAgingSec = opts.Opts.DocaTcpAging
	d.udpAgingSec = opts.Opts.DocaUdpAging
	d.aiAgingSec = opts.Opts.DocaAiAging

	// Set bridge back-pointer for aging poll cycle
	if d.bridge != nil {
		d.bridge.mu.Lock()
		d.bridge.bf2 = d
		d.bridge.mu.Unlock()
	}

	// Build port map: MAC -> DPDK port_id (for DPDK representor MACs)
	d.portMap = make(map[[6]byte]uint16)
	d.portCount = DocaGetPortCount()
	for i := 0; i < d.portCount; i++ {
		mac, err := DocaGetPortMacByID(uint16(i))
		if err == nil {
			d.portMap[mac] = uint16(i)
			d.reversePortMap[uint16(i)] = mac // reverse mapping for source MAC lookup
			hwAddr := net.HardwareAddr(mac[:])
			logrus.WithFields(logrus.Fields{
				"portID": i,
				"mac":    hwAddr.String(),
			}).Debug("DpDocaBf2 port mapped")
		}
	}

	// Build ifindex -> DPDK port_id map using DPDK's rte_eth_dev_info.if_index.
	// Each DPDK port (representor) reports the Linux interface index it is bound to.
	// This is the authoritative mapping — no name-pattern heuristics needed.
	d.ifindexToPort = make(map[int]uint16)
	for i := 0; i < d.portCount; i++ {
		ifindex, err := DocaGetPortIfindex(uint16(i))
		if err == nil && ifindex > 0 {
			d.ifindexToPort[ifindex] = uint16(i)
			logrus.WithFields(logrus.Fields{
				"dpdkPort": i,
				"ifindex":  ifindex,
			}).Debug("DpDocaBf2 ifindex->port mapped")
		}
	}

	// Cache FDB pipe availability once at init to avoid submit deadlock in Capabilities.
	// DocaGetFdbPipe routes through submit which cannot be called while mh.mtx is held
	// (ZoneTicker holds mh.mtx → PolTicker → CollectMeterStats → Capabilities → deadlock).
	fdbPipe := DocaGetFdbPipe()
	d.hasFdbPipe = fdbPipe != nil

	// NO eager ACL pipe creation at init time. The
	// DENY+ALLOW pipe pair is lazily created on the first FwRuleAdd(HwOffload=true)
	// via ensureAclPipesUp. Until then, the operator's zero counter budget is
	// preserved (mitigation). aclPipeHandle / DocaGetAclPipe
	// were retired / 64-03 (the C-side g_acl_pipe global is gone).

	// kill-switch is init-time only — NO per-call os.Getenv.
	// Default ON (env unset → enabled). Operator may set the kill-switch env to "0" to disable.
	d.bidirEnabled = os.Getenv("BF2_BIDIR_OFFLOAD") != "0"
	// pending-pair map already initialized in NewDpDocaBf2; ensure non-nil here too.
	if d.pendingPair == nil {
		d.pendingPair = make(map[string]*pendingPair)
	}
	logrus.WithField("bidirEnabled", d.bidirEnabled).Info("DpDocaBf2: bidir offload mode")

	logrus.WithFields(logrus.Fields{
		"pci":           cfg.PciAddr,
		"numRepr":       numRepr,
		"numPorts":      d.portCount,
		"ifindexToPort": fmt.Sprintf("%v", d.ifindexToPort),
		"portMapSize":   len(d.portMap),
		"hasFdbPipe":    d.hasFdbPipe,
		"bidirEnabled":  d.bidirEnabled,
	}).Info("DpDocaBf2 initialized")

	// register the DOCA metrics collector callback post
	// pipe-init. initDocaMetricsCollector sets the EGRESS gauge from
	// d.EgressCountersAvailable and calls RegisterDocaCollector so the
	// chunked walker fires on every per-tick InvokeRegisteredDocaCollectors
	// call. wires the invocation site in dpu_metrics.go.
	// amendment guard: initDocaMetricsCollector MUST NOT spawn a goroutine.
	initDocaMetricsCollector(d)

	// trace: full port mapping dump so we can correlate fwd_port=N
	// with the underlying interface (p0, pf0vf1, etc.) when debugging.
	if traceBidirEnabled() {
		// Build reverse lookup: portID -> ifindex (and resolve to ifname).
		portToIfindex := make(map[uint16]int)
		for ifindex, portID := range d.ifindexToPort {
			portToIfindex[portID] = ifindex
		}
		for portID := uint16(0); int(portID) < d.portCount; portID++ {
			mac, hasMac := d.reversePortMap[portID]
			ifindex := portToIfindex[portID]
			ifname := ""
			if ifindex > 0 {
				if iface, err := netlink.LinkByIndex(ifindex); err == nil {
					ifname = iface.Attrs().Name
				}
			}
			fields := logrus.Fields{
				"portID":  portID,
				"ifindex": ifindex,
				"ifname":  ifname,
			}
			if hasMac {
				fields["mac"] = net.HardwareAddr(mac[:]).String()
			}
			logrus.WithFields(fields).Info("[bf2-trace] init portMap")
		}
	}
	return nil
}

// Shutdown tears down DOCA bridge. CT pipe is a C global destroyed by llb_doca_shutdown.
// A1: Shutdown drains all maps; acquire all four mutexes IN LOCK-GRAPH ORDER
// (ctMtx → fdbMtx → userCtxMu → statsRWMu) — Shutdown is the only writer of statsRWMu.
func (d *DpDocaBf2) Shutdown() error {
	// drain the debounce queue once with the bridge still alive so
	// no HwOffload=true rule is lost mid-batch. flushAclPending takes aclBatchMu
	// internally and calls CGO outside the lock; safe to run before acquiring the
	// 4-mutex teardown sequence. Stop the timer to prevent a late-fire after
	// Shutdown returns.
	d.flushAclPending()
	d.aclBatchMu.Lock()
	if d.aclBatchTimer != nil {
		d.aclBatchTimer.Stop()
		d.aclBatchTimer = nil
	}
	d.aclBatchMu.Unlock()

	d.ctMtx.Lock()
	d.fdbMtx.Lock()
	d.userCtxMu.Lock()
	d.statsRWMu.Lock() // exclusive Lock (not RLock) — Shutdown is the only writer to statsRWMu
	defer d.statsRWMu.Unlock()
	defer d.userCtxMu.Unlock()
	defer d.fdbMtx.Unlock()
	defer d.ctMtx.Unlock()

	d.entries = make(map[string]*docaOffloadEntry)
	d.fdbEntries = make(map[string]*docaFdbOffloadEntry)
	d.aclEntries = make(map[aclEntryKey]*docaACLEntry)
	// reset lazy ACL state. doca_flow_destroy (via DocaShutdown
	// below) tears down the C-side DENY+ALLOW pipes if they were ever created.
	d.aclDenyEntries = make(map[string]*docaOffloadEntry)
	d.aclAllowEntries = make(map[string]*docaOffloadEntry)
	d.aclPipesUp = false
	d.aclPendingAdd = nil
	d.aclPendingDel = nil
	d.userCtxToKey = make(map[uint64]string)
	d.meterMap = make(map[uint32]*docaMeterEntry)
	d.lbMarkToMeter = make(map[int]uint32)
	d.lbMarkToFlowKeys = make(map[int][]string)
	d.meterOffload = false
	d.initialized = false

	DocaShutdown()
	return nil
}

// ShutdownCtx is the ctx-bounded graceful shutdown that the layered
// shutdown sequencer calls via DpuManager.
// It satisfies the unexported `gracefulShutdowner` capability declared
// in dpu_manager.go.
//
// Implementation: delegate to the bridge's `Shutdown(ctx)` so the worker
// goroutine (LockOSThread) stops accepting new submit work, drains the
// in-flight queue, and closes its `workerDone` rendezvous channel. The
// non-ctx Shutdown above remains the cleanup-state path used by
// DpuManager.Unregister / ShutdownAll on non-shutdown paths.
func (d *DpDocaBf2) ShutdownCtx(ctx context.Context) error {
	if d == nil || d.bridge == nil {
		return nil
	}
	return d.bridge.Shutdown(ctx)
}

// RebuildRootAfterFdbChange atomically re-issues the root-pipe rebuild so its
// miss dispatch tracks the current FDB pipe handle. Per : MUST be
// called after any llb_doca_fdb_pipe_destroy -> _create pair so the root-miss
// override refreshes to the new pipe handle. In there is no production
// path that destroys the FDB pipe at runtime (init creates it once, Shutdown
// tears the whole bridge down), so this hook is "wired but inactive" -- it
// exists so + (dynamic FDB resize, multi-bridge split, etc.) can call
// it without having to introduce a new entry point mid-migration.
//
// Serialization: uses DocaRebuildRootPipe's own submit lane. Callers MUST
// NOT hold ctMtx or fdbMtx when invoking this method (would deadlock against
// any Capabilities-style reader). Callers MUST NOT hold mh.mtx (would deadlock
// against the submit lane -- same reason DocaGetFdbPipe is commented at :348).
func (d *DpDocaBf2) RebuildRootAfterFdbChange() error {
	if !d.initialized {
		return nil
	}
	if err := d.DocaRebuildRootPipe(); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Warn(": FDB-triggered root rebuild failed")
		return err
	}
	logrus.Info(": root rebuild after FDB change OK")
	return nil
}

// IsFdbMissWired reports whether the FDB pipe handle was cached as non-nil at
// init time. Used smoke tests to assert the root->FDB miss
// dispatch is live without re-entering the CGO submit lane. Returns the
// cached d.hasFdbPipe value; does not re-query the C-side accessor.
//
// NOTE: d.hasFdbPipe is set once at init (:350-351) and mirrors the handle
// state at that moment. In no production path mutates it, so the
// value is stable. Future phases that destroy/create the FDB pipe at runtime
// must update d.hasFdbPipe under d.fdbMtx alongside calling
// RebuildRootAfterFdbChange.
func (d *DpDocaBf2) IsFdbMissWired() bool {
	// A1: hasFdbPipe is FDB-domain state.
	d.fdbMtx.Lock()
	defer d.fdbMtx.Unlock()
	return d.hasFdbPipe
}

// DocaRebuildRootPipe is an instance-method shim over the package-level
// DocaRebuildRootPipe so RebuildRootAfterFdbChange can dispatch through the
// plugin receiver in the established pattern. The package-level function
// enforces docaBridgeInstance!=nil, so this method is a thin wrapper.
func (d *DpDocaBf2) DocaRebuildRootPipe() error {
	return DocaRebuildRootPipe()
}

// CtRevTestDropAll rebuilds CT_REV_5TUPLE_PIPE with miss=DROP and immediately
// re-wires the V3 root pipe (port_meta dispatch) to the new pipe handle — all
// done inside the C function to avoid the V2 overwrite that DocaRebuildRootPipe
// would introduce (V2 has no port_meta entries and erases the CT_REV dispatch).
// Any VF-rep TCP packet that reaches CT_REV but has no 5-tuple entry will be
// dropped (not sent to kernel), confirming that root dispatch is correct.
// TEST-ONLY: remove after diagnosis is complete.
func (d *DpDocaBf2) CtRevTestDropAll() error {
	// NOTE: DocaCtRevTestDropAll now handles the V3 root rebuild internally.
	// Do NOT call DocaRebuildRootPipe here — that function uses V2 config
	// (no match_port_meta, only TCP+UDP→ACL) which would overwrite the V3
	// port_meta dispatch entries and make CT_REV unreachable again.
	if err := DocaCtRevTestDropAll(); err != nil {
		return fmt.Errorf("CtRevTestDropAll: CT_REV rebuild + V3 root re-wire failed: %w", err)
	}
	tk.LogIt(tk.LogInfo, "[DPU] CtRevTestDropAll: CT_REV miss=DROP active, V3 root re-wired\n")
	return nil
}

// resolveAgingSec returns the per-service idle timeout based on protocol and AI/SSE mode.
func (d *DpDocaBf2) resolveAgingSec(protoNum uint8, aiGwMode bool) uint32 {
	if aiGwMode {
		return d.aiAgingSec
	}
	if protoNum == 17 { // UDP
		return d.udpAgingSec
	}
	return d.tcpAgingSec // TCP default
}

// allocUserCtx generates a unique userCtx ID and registers it in the reverse lookup map.
// A1: callers hold d.ctMtx OR d.fdbMtx; this helper takes d.userCtxMu
// internally per the lock-graph order (ctMtx/fdbMtx → userCtxMu).
func (d *DpDocaBf2) allocUserCtx(flowKey string) uint64 {
	// Start from 1 (0 is reserved as NULL sentinel in C callback)
	id := d.nextUserCtx.Add(1)
	d.userCtxMu.Lock()
	d.userCtxToKey[id] = flowKey
	d.userCtxMu.Unlock()
	return id
}

// handleAgedEntry processes a DOCA-aged entry: CAS guard, map cleanup, DOCA removal, CT tombstone.
// Called from agingPollCycle on the DOCA worker thread.
//
// Lock order (A1): d.ctMtx.Lock -> CAS(0,1) under lock -> map cleanup -> d.userCtxMu for userCtxToKey -> d.ctMtx.Unlock -> DOCA operations.
func (d *DpDocaBf2) handleAgedEntry(userCtx uint64) {
	d.ctMtx.Lock()
	d.userCtxMu.Lock()
	flowKey, found := d.userCtxToKey[userCtx]
	d.userCtxMu.Unlock()
	if !found {
		d.ctMtx.Unlock()
		return
	}
	// dispatch FDB vs CT aged entries by key prefix
	if strings.HasPrefix(flowKey, "fdb:") {
		d.ctMtx.Unlock()
		d.handleAgedFdbEntry(flowKey, userCtx)
		return
	}
	oe, exists := d.entries[flowKey]
	if !exists {
		// Entry removed by LBFlowRemove already; clean reverse map
		d.userCtxMu.Lock()
		delete(d.userCtxToKey, userCtx)
		d.userCtxMu.Unlock()
		d.ctMtx.Unlock()
		return
	}
	// CAS guard under lock -- both LBFlowRemove and handleAgedEntry hold d.ctMtx
	if !oe.evicting.CompareAndSwap(0, 1) {
		d.ctMtx.Unlock()
		return // LBFlowRemove is handling
	}
	// Won CAS -- we own eviction
	delete(d.entries, flowKey)
	d.userCtxMu.Lock()
	delete(d.userCtxToKey, userCtx)
	d.userCtxMu.Unlock()
	// clean up lbMarkToFlowKeys reverse index
	if oe.lbMark > 0 {
		if keys, ok := d.lbMarkToFlowKeys[oe.lbMark]; ok {
			for i, fk := range keys {
				if fk == flowKey {
					d.lbMarkToFlowKeys[oe.lbMark] = append(keys[:i], keys[i+1:]...)
					break
				}
			}
			if len(d.lbMarkToFlowKeys[oe.lbMark]) == 0 {
				delete(d.lbMarkToFlowKeys, oe.lbMark)
			}
		}
	}
	pipe := oe.pipe
	entry := oe.entry
	pkey := oe.pkey
	// capture the sibling under the lock so aging out one half of a
	// non-NAT route forward/reverse pair tears down both — g_ct_rev_pipe cannot
	// leak. The sibling shares the same eBPF CT key (pkey) so it needs no
	// separate tombstone. The sibling's evicting CAS guards a concurrent
	// LBFlowRemove on the same pair.
	var sibKey string
	var sibPipe, sibEntry unsafe.Pointer
	if oe.siblingKey != "" {
		if sib, ok := d.entries[oe.siblingKey]; ok && sib.evicting.CompareAndSwap(0, 1) {
			sibKey, sibPipe, sibEntry = oe.siblingKey, sib.pipe, sib.entry
			delete(d.entries, sibKey)
			d.userCtxMu.Lock()
			delete(d.userCtxToKey, sib.userCtx)
			d.userCtxMu.Unlock()
		}
	}
	d.ctMtx.Unlock()

	// DOCA removal outside lock -- use Direct variant because handleAgedEntry
	// runs on the DOCA worker thread (via agingPollCycle); submit would self-deadlock.
	if err := DocaEntryRemoveDirect(pipe, entry); err != nil {
		logrus.WithFields(logrus.Fields{
			"flow":  flowKey,
			"error": err,
		}).Warn("doca-bf2: aged entry DOCA removal failed (best-effort)")
	}

	// cascade DOCA removal to the sibling (non-NAT route fwd/rev
	// pair). Direct variant — same DOCA worker thread as the primary removal.
	if sibKey != "" {
		if err := DocaEntryRemoveDirect(sibPipe, sibEntry); err != nil {
			logrus.WithFields(logrus.Fields{
				"flow":  sibKey,
				"error": err,
			}).Warn("doca-bf2: aged sibling DOCA removal failed (best-effort)")
		}
		d.deferredOffload.Delete(sibKey)
		d.offloadActive.Add(-1)
		docaStaleEntriesEvicted.Inc()
	}

	d.deferredOffload.Delete(flowKey)

	d.offloadActive.Add(-1)
	docaOffloadActiveFlows.Set(float64(d.offloadActive.Load()))
	docaStaleEntriesEvicted.Inc()

	// CT tombstone: delete eBPF CT map entry to prevent ghost re-offload
	dpCtTombstone(flowKey, pkey)

	logrus.WithField("flow", flowKey).Info("doca-bf2: DOCA aging evicted entry")
}

// EnqueueRetry adds a failed offload to the retry queue for processing on the next aging poll cycle.
// Returns true if enqueued, false if queue is full or duplicate exists.
// Thread-safe: called from goCtHwOffloadHandler (perf buffer callback goroutine).
func (d *DpDocaBf2) EnqueueRetry(flowKey string, ct *DpCtInfo, isLB bool) bool {
	d.retryMu.Lock()
	defer d.retryMu.Unlock()

	// Bounded: reject when queue is full
	if len(d.retryQueue) >= retryQueueMaxCap {
		logrus.WithField("flow", flowKey).Warn("doca-bf2: retry queue full, dropping offload retry")
		return false
	}

	// Dedup: skip if flowKey already pending retry
	for i := range d.retryQueue {
		if d.retryQueue[i].flowKey == flowKey {
			return false
		}
	}

	// Copy ctInfo by value (source is ephemeral perf buffer data)
	d.retryQueue = append(d.retryQueue, retryEntry{
		flowKey:  flowKey,
		ctInfo:   *ct,
		attempts: 0,
		isLB:     isLB,
	})

	logrus.WithField("flow", flowKey).Debug("doca-bf2: enqueued failed offload for retry")
	return true
}

// processRetries drains the retry queue, re-attempts offloads, and abandons after retryMaxAttempts.
// Called from agingPollCycle on the DOCA worker thread (single-threaded, no DOCA concurrency issue).
func (d *DpDocaBf2) processRetries() {
	// Take a snapshot of the current retry queue under lock, then clear it
	d.retryMu.Lock()
	if len(d.retryQueue) == 0 {
		d.retryMu.Unlock()
		return
	}
	snapshot := make([]retryEntry, len(d.retryQueue))
	copy(snapshot, d.retryQueue)
	d.retryQueue = d.retryQueue[:0] // clear, keep underlying array
	d.retryMu.Unlock()

	for i := range snapshot {
		re := &snapshot[i]
		re.attempts++

		var err error
		if re.isLB {
			err = d.LBFlowOffload(&re.ctInfo, 0)
		} else {
			err = d.RouteFlowOffload(&re.ctInfo, 0)
		}

		if err == nil {
			logrus.WithFields(logrus.Fields{
				"flow":     re.flowKey,
				"attempts": re.attempts,
			}).Info("doca-bf2: retry succeeded for flow")
			continue
		}

		// Failed again
		if re.attempts >= retryMaxAttempts {
			// Abandon after max attempts
			logrus.WithFields(logrus.Fields{
				"flow":     re.flowKey,
				"attempts": re.attempts,
				"error":    err,
			}).Warn("doca-bf2: retry abandoned after 3 attempts")
			docaOffloadFailuresTotal.Inc()
			continue
		}

		// Re-enqueue for next cycle (under lock)
		d.retryMu.Lock()
		if len(d.retryQueue) < retryQueueMaxCap {
			d.retryQueue = append(d.retryQueue, *re)
		}
		d.retryMu.Unlock()
	}
}

// Name returns the plugin identifier.
func (d *DpDocaBf2) Name() string {
	return "doca-bf2"
}

// Capabilities returns BF2 offload capabilities.
func (d *DpDocaBf2) Capabilities() DpuCapabilities {
	return DpuCapabilities{
		LBOffload:      true,
		CTRouteOffload: true,
		L2Switching:    d.hasFdbPipe,
		// ACLOffload is unconditionally advertised on BF2 — the
		// DENY+ALLOW pipes are lazy-created on the first FwRuleAdd(HwOffload=true);
		// non-flagged rules stay on eBPF regardless. The gate on
		// `aclPipeHandle != nil` retired with the single-pipe surface.
		ACLOffload:         true,
		MeterOffload:       d.meterOffload,
		TunnelEncap:        false,
		TunnelDecap:        false,
		MaxEntriesPerPipe:  65536,
		MaxConcurrentPipes: 128,
	}
}

// neighListFn is the test seam for netlink.NeighList — production code calls
// netlink.NeighList directly via the default value; tests in dpu_doca_bf2.go's
// !doca counterpart and dpu_doca_bf2_resolve_test.go can override it to count
// invocations (A3 singleflight-collapse test).
var neighListFn = func() ([]netlink.Neigh, error) {
	return netlink.NeighList(0, netlink.FAMILY_V4)
}

// resolveFlowMACs resolves a target IP to DPDK port ID + destination MAC + source MAC.
// Flow: target IP -> ARP neighbor table -> (LinkIndex -> ifindexToPort -> portID) + (dstMAC from ARP, srcMAC from reversePortMap).
// In BF2 switchdev, ARP entries contain VF MACs (inside namespaces) which differ from DPDK representor MACs.
// We use the ARP entry's LinkIndex (which interface the neighbor is reachable through) to determine the DPDK port.
//
// A4 (-05): if SelfIPCache.Has(ip) reports the IP as
// loxilb-owned, return d.reversePortMap[0] (proxy port DPDK port_id 0 MAC)
// for both src and dst MAC and SUPPRESS the "failed - no ifindex match"
// log line. This eliminates the spam triggered by `iperf3 -P 10` against a
// loxilb VIP-style IP (e.g., 31.31.31.254). OPEN Q3 — operator validates
// §7 that the proxy port[0] MAC is the correct dst.
//
// A3: the slow-path netlink.NeighList scan is wrapped in a per-IP
// singleflight.Group so 10 concurrent callers resolving the same dest IP
// collapse into ONE netlink probe. The Group's internal lock is leaf-level —
// no participation in the ctMtx → fdbMtx → userCtxMu → statsRWMu graph.
func (d *DpDocaBf2) resolveFlowMACs(ip net.IP) (uint16, [6]byte, [6]byte, bool) {
	var zeroMAC [6]byte

	// A4: self-IP fast path — no ARP probe, no warn log.
	// Cache populated by SelfIPCache.Init at boot + NetAddrAdd/Del hooks.
	// reversePortMap[0] is the proxy port DPDK port_id 0 MAC (OPEN Q3).
	if ip4 := ip.To4(); ip4 != nil {
		if SelfIPCache.Has(tk.IPtonl(ip4)) {
			srcMAC := d.reversePortMap[0]
			logrus.WithFields(logrus.Fields{
				"ip":      ip,
				"src_mac": fmt.Sprintf("%x", srcMAC),
			}).Trace("doca-bf2: resolveFlowMACs self-ip fast-path (A4)")
			return 0, srcMAC, srcMAC, true
		}
	}

	if len(d.ifindexToPort) == 0 {
		return 0, zeroMAC, zeroMAC, false
	}

	// A3: per-IP singleflight collapse. 10 parallel iperf3 sessions
	// resolving the same dest IP → ONE netlink.NeighList scan; the slow path
	// runs once and every collapsed caller receives the same struct.
	type resolveResult struct {
		port uint16
		dst  [6]byte
		src  [6]byte
		ok   bool
	}
	key := ip.String()
	v, _, _ := d.resolveSF.Do(key, func() (interface{}, error) {
		neighs, err := neighListFn()
		if err != nil {
			return resolveResult{}, nil
		}
		for _, n := range neighs {
			if n.IP.Equal(ip) && (n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_DELAY|netlink.NUD_PERMANENT)) != 0 {
				if len(n.HardwareAddr) == 6 {
					var dstMAC [6]byte
					copy(dstMAC[:], n.HardwareAddr)
					// Interface-based mapping: ARP LinkIndex -> DPDK port.
					if portID, ok := d.ifindexToPort[n.LinkIndex]; ok {
						return resolveResult{
							port: portID,
							dst:  dstMAC,
							src:  d.reversePortMap[portID],
							ok:   true,
						}, nil
					}
				}
			}
		}
		return resolveResult{}, nil
	})
	r := v.(resolveResult)
	if !r.ok {
		// Self-IPs were already returned via the A4 fast path above; this
		// log fires only for truly unresolved external IPs now.
		logrus.WithField("ip", ip).Info("doca-bf2: resolveFlowMACs failed - no ifindex match")
	}
	return r.port, r.dst, r.src, r.ok
}

// LBFlowOffload creates a DOCA BASIC pipe entry for an established TCP/UDP flow with NAT.
// Dispatches by NatFlags: DNAT(1), SNAT(2), HDNAT(3), HSNAT(4). DSR gracefully degrades to eBPF.
func (d *DpDocaBf2) LBFlowOffload(ct *DpCtInfo, lbMark int) error {
	if ct.NatFlags == 0 || ct.NatIP == nil {
		return nil // not a NAT flow
	}

	// DSR graceful degradation: let eBPF handle DSR flows
	if ct.NatDsr {
		logrus.Debug("doca-bf2: DSR flow skipped, eBPF handles")
		return nil
	}

	// HDNAT hairpin skip: complex hairpin NAT handled by eBPF
	if ct.NatFlags == 3 && (ct.NatIP.Equal(net.IPv4zero) || ct.NatIP.IsUnspecified()) {
		logrus.Debug("doca-bf2: HDNAT hairpin flow skipped, eBPF handles")
		return nil
	}

	// CGO-05: fail-open when DOCA bridge unavailable
	if d.bridge == nil {
		return nil
	}

	// CGO-08: circuit breaker early exit
	if !d.circuitBreaker.allow() {
		return nil
	}

	// Determine protocol number for pipe key
	var protoNum uint8
	switch ct.Proto {
	case "tcp":
		protoNum = 6
	case "udp":
		protoNum = 17
	default:
		return nil // only TCP/UDP supported
	}

	flowKey := ct.Key()

	d.ctMtx.Lock()
	defer d.ctMtx.Unlock()

	// Check if flow already offloaded (idempotent)
	if _, exists := d.entries[flowKey]; exists {
		return nil
	}

	// Protocol-aware pipe selection. TCP flows go to TCP CT pipe,
	// UDP flows go to dedicated UDP CT pipe. protoNum is guaranteed to be
	// 6 or 17 at this point (lines above return nil for other protos).
	var pipe unsafe.Pointer
	var pipeKey string
	// Unified CT pipe handles both TCP and UDP (TRANSPORT l4_type_ext).
	// -04: unified CT pipe split into miss-chained pair
	// g_ct_fwd_pipe → g_ct_rev_pipe → to_kernel; forward entries install
	// on g_ct_fwd_pipe (this accessor), reply traffic falls through via
	// the miss-chain. -06 (TX-2): wrapper renamed to
	// DocaGetCTFwdPipe in lockstep with the C-side llb_doca_get_ct_pipe →
	// llb_doca_get_ct_fwd_pipe rename.
	pipe = DocaGetCTFwdPipe()
	pipeKey = "ct"
	if pipe == nil {
		return fmt.Errorf("doca-bf2 LBFlowOffload: %s pipe not available", pipeKey)
	}

	// Compute match and rewrite params based on NatFlags
	var matchDstIP, matchSrcIP uint32
	var matchDstPort, matchSrcPort uint16
	var newDstIP, newSrcIP uint32
	var newDstPort, newSrcPort uint16
	var newDstMAC, newSrcMAC [6]byte
	var fwdPortID uint16

	switch ct.NatFlags {
	case 1, 3: // DNAT, HDNAT -- origin direction
		matchSrcIP = tk.IPtonl(ct.SIP)
		matchSrcPort = tk.Htons(ct.Sport)
		matchDstIP = tk.IPtonl(ct.DIP)
		matchDstPort = tk.Htons(ct.Dport)
		newDstIP = tk.IPtonl(ct.NatIP)
		newDstPort = tk.Htons(ct.NatPort)
		// DOCA actions template marks ALL fields changeable (UINT32_MAX).
		// Fields not being NAT'd must pass through the original value,
		// otherwise DOCA rewrites them to 0.0.0.0 / port 0.
		newSrcIP = matchSrcIP     // preserve original src IP
		newSrcPort = matchSrcPort // preserve original src port
		if ct.NatRIP != nil && !ct.NatRIP.IsUnspecified() {
			newSrcIP = tk.IPtonl(ct.NatRIP) // One-Arm: override src to VIP
		}
		// MAC-01/MAC-02: resolve destination and source MAC for DNAT
		if portID, dstMAC, srcMAC, ok := d.resolveFlowMACs(ct.NatIP); ok {
			newDstMAC = dstMAC
			newSrcMAC = srcMAC
			fwdPortID = portID
		} else {
			logrus.WithField("ip", ct.NatIP).Debug("doca-bf2: ARP unresolved for DNAT endpoint, skipping offload")
			return nil // eBPF handles until next scan cycle
		}
	case 2, 4: // SNAT, HSNAT -- reply direction
		matchSrcIP = tk.IPtonl(ct.SIP)
		matchSrcPort = tk.Htons(ct.Sport)
		matchDstIP = tk.IPtonl(ct.DIP)
		matchDstPort = tk.Htons(ct.Dport)
		newSrcIP = tk.IPtonl(ct.NatIP)
		newSrcPort = tk.Htons(ct.NatPort)
		// Preserve original dst (not being NAT'd) — same DOCA template reason.
		newDstIP = matchDstIP     // preserve original dst IP
		newDstPort = matchDstPort // preserve original dst port
		if ct.NatRIP != nil && !ct.NatRIP.IsUnspecified() {
			newDstIP = tk.IPtonl(ct.NatRIP) // One-Arm reply: override dst
		}
		// MAC-01/MAC-02: resolve destination and source MAC for SNAT reply
		if portID, dstMAC, srcMAC, ok := d.resolveFlowMACs(ct.DIP); ok {
			newDstMAC = dstMAC
			newSrcMAC = srcMAC
			fwdPortID = portID
		} else {
			logrus.WithField("ip", ct.DIP).Debug("doca-bf2: ARP unresolved for SNAT target, skipping offload")
			return nil // eBPF handles until next scan cycle
		}
	}

	// -05: resolve aiGwMode from LB rule for AI/SSE aging timeout
	var aiGwMode bool
	if ct.RuleID > 0 {
		mh.mtx.Lock()
		r := mh.zr.Rules.GetLBRuleByID(ct.RuleID)
		mh.mtx.Unlock()
		if r != nil {
			aiGwMode = r.sseMode || r.pdDisaggMode
		}
	}

	// resolve per-service aging timeout and allocate unique userCtx
	agingSec := d.resolveAgingSec(protoNum, aiGwMode)
	userCtx := d.allocUserCtx(flowKey)

	// auto-attach meter if policer targets this LB rule
	meterIDParam := uint32(0xFFFFFFFF) // LLB_DOCA_METER_NONE
	if mid, hasMeter := d.lbMarkToMeter[lbMark]; hasMeter {
		meterIDParam = mid
	}

	// Create DOCA entry with extended parameters.
	// -06: DocaEntryAddBasic signature reduced to
	// (entry, err) — the paired g_egress_steer steerEntry return is gone
	// along with the dropped C-side out_es_entry out-param. g_egress_dispatch
	// handles per-port FWD via static init-time entries keyed
	// on meta.pkt_meta = target_port_id.
	docaOffloadAttemptsTotal.Inc()
	entry, err := DocaEntryAddBasic(
		pipe,
		matchDstIP, matchDstPort,
		matchSrcIP, matchSrcPort,
		newDstIP, newDstPort,
		newSrcIP, newSrcPort,
		newDstMAC, newSrcMAC,
		0,            // no DOCA-side timeout (eBPF-driven lifecycle)
		protoNum,     // match_proto for UDP/TCP port field dispatch
		fwdPortID,    // per-entry FWD_PORT to target VF repr
		agingSec,     // per-entry DOCA aging
		userCtx,      // aged-entry identification
		meterIDParam, // auto-attach meter or METER_NONE
	)
	if err != nil {
		// Clean up reverse lookup on failure
		d.userCtxMu.Lock()
		delete(d.userCtxToKey, userCtx)
		d.userCtxMu.Unlock()
		d.circuitBreaker.recordFailure()
		docaOffloadFailuresTotal.Inc()
		// A2: per-pipe-per-reason install error.
		docaOffloadInstallErrorsTotal.WithLabelValues("ct", docaErrorReason(err)).Inc()
		return fmt.Errorf("doca-bf2 LBFlowOffload entry add failed: %w", err)
	}

	d.circuitBreaker.recordSuccess()
	d.offloadActive.Add(1)
	docaOffloadActiveFlows.Set(float64(d.offloadActive.Load()))

	d.entries[flowKey] = &docaOffloadEntry{
		pipe:    pipe,
		entry:   entry,
		pipeKey: pipeKey,
		pkey:    append([]byte(nil), ct.PKey...), // defensive copy for tombstone
		userCtx: userCtx,
		lbMark:  lbMark, // track LB rule mark for meter lookup
	}

	// maintain reverse index for O(1) live meter update
	if lbMark > 0 {
		d.lbMarkToFlowKeys[lbMark] = append(d.lbMarkToFlowKeys[lbMark], flowKey)
	}

	logrus.WithFields(logrus.Fields{
		"flow":     flowKey,
		"pipe":     pipeKey,
		"natFlags": ct.NatFlags,
		"fwdPort":  fwdPortID,
		"agingSec": agingSec,
		"meterID":  meterIDParam,
	}).Debug("DpDocaBf2 flow offloaded")
	return nil
}

// pairedLBFlowOffload programs forward+reply DOCA entries atomically
//
// On second-add failure, removes the first entry via DocaEntryRemoveDirect per
// RESEARCH §"Anti-Patterns to Avoid (LANDMINES)" line 374. The submit-routed
// DocaEntryRemove would self-deadlock when called from the worker pthread
// (Pattern 3).
//
// Mutex discipline: pairMu MUST NOT be held by the caller (— DOCA
// submit under pairMu deadlocks). ctMtx is acquired only for bookkeeping
// after both DOCA add calls return.
//
// Reply MAC/port input: the reply branch passes
// fwd.SIP (client IP) into resolveFlowMACs — uniform across DNAT, OneArm, and
// FullNAT. FIB next-hop fallback is invoked ONLY on direct ARP miss;
// the c15fd32 anti-pattern (always FIB-wrap, even on direct hit) is forbidden.
// Both forward and reply MAC/port resolution complete inside this function
// (symmetric pair-time).
func (d *DpDocaBf2) pairedLBFlowOffload(fwd, rev *DpCtInfo, lbMark int) error {
	if d.bridge == nil {
		return nil
	}
	if !d.circuitBreaker.allow() {
		return nil
	}
	if fwd == nil || rev == nil {
		return fmt.Errorf("phase51 paired offload: nil ct (fwd=%v rev=%v)", fwd, rev)
	}

	pipe := docaGetCTFwdPipeFn()
	if pipe == nil {
		return fmt.Errorf("phase51 paired offload: ct fwd pipe not available")
	}
	// fix: reply entries install on g_ct_rev_pipe, NOT g_ct_fwd_pipe.
	// The root pipe does per-ingress-port dispatch (commit cea766a4):
	// port_meta=0 (uplink p0) → g_ct_fwd_pipe; port_meta=1..N (representors,
	// where reply traffic ingresses) → g_ct_rev_pipe. A reply entry placed in
	// g_ct_fwd_pipe is unreachable — reply packets hit g_ct_rev_pipe, find it
	// empty, and fall through miss → to_kernel (slow path forever), starving
	// the reply direction while forward runs at HW speed.
	revPipe := docaGetCTRevPipeFn()
	if revPipe == nil {
		return fmt.Errorf("phase51 paired offload: ct rev pipe not available")
	}

	// === Forward direction params (mirrors LBFlowOffload case 1,3) ===
	// direct resolveFlowMACs(fwd.NatIP) first; FIB fallback only on miss.
	fwdP, err := d.buildPairedFlowParams(fwd, fwd, true)
	if err != nil {
		if mh.dpuMgr != nil {
			mh.dpuMgr.RecordOffload(pipeCT, err)
		}
		return fmt.Errorf("phase51 paired offload: forward param build failed: %w", err)
	}

	// === Reply direction params ===
	// payload: resolveFlowMACs(fwd.SIP) — NOT rev.DIP. Uniform across
	// DNAT/OneArm/FullNAT because the client IS arpable on the local subnet
	// in all three modes (cross-subnet falls through to FIB fallback).
	revP, err := d.buildPairedFlowParams(rev, fwd, false)
	if err != nil {
		if mh.dpuMgr != nil {
			mh.dpuMgr.RecordOffload(pipeCT, err)
		}
		return fmt.Errorf("phase51 paired offload: reply param build failed: %w", err)
	}

	// === Aging + userCtx allocation ===
	// Each entry gets its own userCtx; both registered under d.ctMtx.
	// A1: lock-graph order — ctMtx is held; allocUserCtx takes userCtxMu internally.
	d.ctMtx.Lock()
	fwdKey := fwd.Key()
	revKey := rev.Key()
	if _, dup := d.entries[fwdKey]; dup {
		d.ctMtx.Unlock()
		return nil // already paired by a concurrent path; no-op
	}
	if _, dup := d.entries[revKey]; dup {
		d.ctMtx.Unlock()
		return nil
	}
	// Resolve aiGwMode once for the rule (same for forward and reply).
	var aiGwMode bool
	if fwd.RuleID > 0 {
		mh.mtx.Lock()
		r := mh.zr.Rules.GetLBRuleByID(fwd.RuleID)
		mh.mtx.Unlock()
		if r != nil {
			aiGwMode = r.sseMode || r.pdDisaggMode
		}
	}
	agingSec := d.resolveAgingSec(fwdP.protoNum, aiGwMode)
	fwdUserCtx := d.allocUserCtx(fwdKey)
	revUserCtx := d.allocUserCtx(revKey)
	meterIDParam := uint32(0xFFFFFFFF)
	if mid, hasMeter := d.lbMarkToMeter[lbMark]; hasMeter {
		meterIDParam = mid
	}
	d.ctMtx.Unlock()

	// === Forward DocaEntryAddBasic ===
	if traceBidirEnabled() {
		logrus.WithFields(pairedFlowParamsTraceFields(&fwdP)).WithFields(logrus.Fields{
			"dir":     "forward",
			"pipe":    fmt.Sprintf("%p", pipe),
			"aging":   agingSec,
			"userCtx": fwdUserCtx,
			"meterID": meterIDParam,
			"fwdKey":  fwdKey,
		}).Info("[bf2-trace] pairedOffload PRE forward DocaEntryAddBasic")
	}
	docaOffloadAttemptsTotal.Inc()
	// -06: consume the 2-return signature (entry, err).
	// The paired g_egress_steer steerEntry return is gone along with the
	// dropped C-side out_es_entry out-param.
	fwdEntry, err := DocaEntryAddBasic(
		pipe,
		fwdP.matchDstIP, fwdP.matchDstPort,
		fwdP.matchSrcIP, fwdP.matchSrcPort,
		fwdP.newDstIP, fwdP.newDstPort,
		fwdP.newSrcIP, fwdP.newSrcPort,
		fwdP.newDstMAC, fwdP.newSrcMAC,
		0,
		fwdP.protoNum,
		fwdP.fwdPortID,
		agingSec,
		fwdUserCtx,
		meterIDParam,
	)
	if traceBidirEnabled() {
		logrus.WithFields(logrus.Fields{
			"dir":    "forward",
			"err":    err,
			"entry":  fmt.Sprintf("%p", fwdEntry),
			"fwdKey": fwdKey,
		}).Info("[bf2-trace] pairedOffload POST forward DocaEntryAddBasic")
	}
	if err != nil {
		// A1: ctMtx → userCtxMu lock-graph order.
		d.ctMtx.Lock()
		d.userCtxMu.Lock()
		delete(d.userCtxToKey, fwdUserCtx)
		delete(d.userCtxToKey, revUserCtx)
		d.userCtxMu.Unlock()
		d.ctMtx.Unlock()
		d.circuitBreaker.recordFailure()
		docaOffloadFailuresTotal.Inc()
		// A2: P2 atomic-rollback path uses explicit reason="paired_steer_failed"
		// so operators can distinguish paired-egress-steer cascade failures from
		// per-pipe install errors at the original add site.
		docaOffloadInstallErrorsTotal.WithLabelValues("ct", "paired_steer_failed").Inc()
		// D-B23-02: queue for next-tick deferred retry. The C-side
		// has already atomically rolled back any half-installed CT entry on
		// paired-steer failure, so there is no orphan to clean up
		// here — the markDeferred call is purely about giving the flow another
		// chance once egress_steer capacity frees up.
		d.markDeferred(fwd, rev, lbMark)
		if mh.dpuMgr != nil {
			mh.dpuMgr.RecordOffload(pipeCT, err)
		}
		return fmt.Errorf("phase51 paired offload: forward add failed: %w", err)
	}

	// === Reply DocaEntryAddBasic ===
	// reply (fsnat) entries install on g_ct_rev_pipe — the dedicated
	// reverse pipe. The root pipe dispatches reply traffic (ingress on
	// a representor, port_meta=1..N) straight to g_ct_rev_pipe; the forward pipe
	// only ever sees uplink-ingress (port_meta=0) traffic. Forward and reply
	// 5-tuples are disjoint, but pipe placement still matters because the root
	// dispatch — not a shared bidirectional pipe — decides which pipe a packet
	// reaches. (The pre- "unified BIDIRECTIONAL pipe, CT_REV unreachable"
	// model is dead: set_dir_info(BIDIRECTIONAL) was removed
	// per-ingress-port root dispatch was restored in cea766a4.)
	if traceBidirEnabled() {
		logrus.WithFields(pairedFlowParamsTraceFields(&revP)).WithFields(logrus.Fields{
			"dir":     "reply",
			"pipe":    fmt.Sprintf("%p", revPipe),
			"aging":   agingSec,
			"userCtx": revUserCtx,
			"meterID": meterIDParam,
			"revKey":  revKey,
		}).Info("[bf2-trace] pairedOffload PRE reply DocaEntryAddBasic")
	}
	docaOffloadAttemptsTotal.Inc()
	// -06: consume the 2-return signature (entry, err).
	revEntry, err := DocaEntryAddBasic(
		revPipe,
		revP.matchDstIP, revP.matchDstPort,
		revP.matchSrcIP, revP.matchSrcPort,
		revP.newDstIP, revP.newDstPort,
		revP.newSrcIP, revP.newSrcPort,
		revP.newDstMAC, revP.newSrcMAC,
		0,
		revP.protoNum,
		revP.fwdPortID,
		agingSec,
		revUserCtx,
		meterIDParam,
	)
	if traceBidirEnabled() {
		logrus.WithFields(logrus.Fields{
			"dir":    "reply",
			"err":    err,
			"entry":  fmt.Sprintf("%p", revEntry),
			"revKey": revKey,
		}).Info("[bf2-trace] pairedOffload POST reply DocaEntryAddBasic")
	}
	if err != nil {
		// Forward succeeded, reply failed. -06 (TX-1): the
		// paired-steer rollback step is gone — g_egress_steer_pipe was
		// deleted (validated DOCA samples prove the
		// EGRESS-domain steer pipe is wrong on BF2 2.9.4), so there is
		// no paired entry to release. The CT entry rollback below remains:
		// remove the forward CT entry installed on g_ct_fwd_pipe via the
		// Direct primitive because we are on the DOCA worker context.
		if rmErr := DocaEntryRemoveDirect(pipe, fwdEntry); rmErr != nil {
			logrus.WithError(rmErr).
				Error("phase51: paired rollback DocaEntryRemoveDirect failed; half-offloaded state")
		}
		// A1: ctMtx → userCtxMu lock-graph order.
		d.ctMtx.Lock()
		d.userCtxMu.Lock()
		delete(d.userCtxToKey, fwdUserCtx)
		delete(d.userCtxToKey, revUserCtx)
		d.userCtxMu.Unlock()
		d.ctMtx.Unlock()
		d.circuitBreaker.recordFailure()
		docaOffloadFailuresTotal.Inc()
		// A2: reply-fail rollback path; the rollback covers BOTH the
		// forward CT entry and the forward paired-steer entry. Use explicit
		// reason="paired_steer_failed" with pipe="ct_rev" so operators can
		// distinguish reply-side rollback from forward-side rollback.
		docaOffloadInstallErrorsTotal.WithLabelValues("ct_rev", "paired_steer_failed").Inc()
		// D-B23-02: mark the flow for next-tick deferred retry. The
		// pair is fully rolled back (no orphan CT, no orphan steer); deferred
		// retry will re-issue the paired offload once g_egress_steer has
		// headroom (capacity-gated sweep — see deferred_offload.go).
		d.markDeferred(fwd, rev, lbMark)
		if mh.dpuMgr != nil {
			mh.dpuMgr.RecordOffload(pipeCT, err)
		}
		return fmt.Errorf("phase51 paired offload: reply add failed (rolled back): %w", err)
	}

	// Both succeeded — bookkeeping under d.ctMtx only (the pairing-map mutex is
	// intentionally NOT held here; covers a different invariant, and holding
	// it across DOCA submit would self-deadlock per RESEARCH §).
	d.circuitBreaker.recordSuccess()
	d.offloadActive.Add(2)
	docaOffloadActiveFlows.Set(float64(d.offloadActive.Load()))

	d.ctMtx.Lock()
	d.entries[fwdKey] = &docaOffloadEntry{
		// -06 (TX-1): pairedSteerEntry no longer assigned —
		// g_egress_steer is deleted; the field stays in docaOffloadEntry
		// (mirrored in dpu_doca_bf2_stub.go) but is always nil now,
		// removable in a follow-up phase along with deferred_offload.go.
		pipe:      pipe,
		entry:     fwdEntry,
		pipeKey:   "ct",
		pkey:      append([]byte(nil), fwd.PKey...),
		userCtx:   fwdUserCtx,
		lbMark:    lbMark,
		Direction: "forward",
		fwdPortID: fwdP.fwdPortID,
	}
	d.entries[revKey] = &docaOffloadEntry{
		// fix: the reply entry lives on g_ct_rev_pipe (see the
		// reply-install comment above) — store revPipe so LBFlowRemove
		// and DOCA aging eviction target the correct pipe. pipeKey stays
		// "ct" (closed enum); Direction="reply" is the per-direction
		// discriminator.
		pipe:      revPipe,
		entry:     revEntry,
		pipeKey:   "ct",
		pkey:      append([]byte(nil), rev.PKey...),
		userCtx:   revUserCtx,
		lbMark:    lbMark,
		Direction: "reply",
		fwdPortID: revP.fwdPortID,
	}
	// -06 (TX-1): per-direction steerActiveCount.Add and the
	// docaEgressSteerActiveEntries.Inc calls are gone — there is no steer
	// entry to count now that g_egress_steer is deleted.
	if lbMark > 0 {
		d.lbMarkToFlowKeys[lbMark] = append(d.lbMarkToFlowKeys[lbMark], fwdKey, revKey)
	}
	d.ctMtx.Unlock()

	// One RecordOffload(pipeCT, nil) per pair — gauges treat the pair as one logical offload.
	if mh.dpuMgr != nil {
		mh.dpuMgr.RecordOffload(pipeCT, nil)
	}

	logrus.WithFields(logrus.Fields{
		"fwdKey":   fwdKey,
		"revKey":   revKey,
		"natFlags": fwd.NatFlags,
		"agingSec": agingSec,
	}).Debug("DpDocaBf2 phase51 paired offload OK")
	return nil
}

// LBFlowRemove removes a DOCA entry for the given CT flow. Idempotent.
// CAS guard prevents double-eviction race with DOCA aging callback.
// A1: lock-graph order — d.ctMtx is the CT-domain mutex; userCtxMu is taken for userCtxToKey writes.
func (d *DpDocaBf2) LBFlowRemove(ct *DpCtInfo) error {
	if d.bridge == nil {
		return nil
	}
	flowKey := ct.Key()

	d.ctMtx.Lock()
	defer d.ctMtx.Unlock()

	oe, exists := d.entries[flowKey]
	if !exists {
		return nil // not offloaded or already removed (e.g., via pipe destroy)
	}

	// CAS guard -- if DOCA aging already evicting, just clean up maps
	if !oe.evicting.CompareAndSwap(0, 1) {
		// DOCA aging already handling this entry
		delete(d.entries, flowKey)
		d.userCtxMu.Lock()
		delete(d.userCtxToKey, oe.userCtx)
		d.userCtxMu.Unlock()
		d.offloadActive.Add(-1)
		docaOffloadActiveFlows.Set(float64(d.offloadActive.Load()))
		return nil
	}

	if err := DocaEntryRemove(oe.pipe, oe.entry); err != nil {
		logrus.WithFields(logrus.Fields{
			"plugin": "doca-bf2",
			"flow":   flowKey,
			"error":  err,
		}).Warn("DpDocaBf2 LBFlowRemove entry remove failed (best-effort)")
		// CGO-07: do NOT decrement -- entry may still be in hardware
	} else {
		// CGO-07: only decrement on successful removal
		d.offloadActive.Add(-1)
		docaOffloadActiveFlows.Set(float64(d.offloadActive.Load()))
	}

	// -06 (TX-1): symmetric paired-steer sibling release is gone —
	// g_egress_steer_pipe was deleted the per-flow paired
	// entry pattern is replaced by g_egress_dispatch's static init-time
	// entries. pairedSteerEntry is always nil now; deferred
	// offload state is still cleared on the off-chance an in-flight
	// pre-63-04 flow lingered through the rebuild boundary.
	d.deferredOffload.Delete(flowKey)

	delete(d.entries, flowKey)
	d.userCtxMu.Lock()
	delete(d.userCtxToKey, oe.userCtx)
	d.userCtxMu.Unlock()

	// clean up lbMarkToFlowKeys reverse index
	if oe.lbMark > 0 {
		if keys, ok := d.lbMarkToFlowKeys[oe.lbMark]; ok {
			for i, fk := range keys {
				if fk == flowKey {
					d.lbMarkToFlowKeys[oe.lbMark] = append(keys[:i], keys[i+1:]...)
					break
				}
			}
			if len(d.lbMarkToFlowKeys[oe.lbMark]) == 0 {
				delete(d.lbMarkToFlowKeys, oe.lbMark)
			}
		}
	}

	// cascade teardown to the sibling. Non-NAT route flows install
	// a forward+reverse DOCA-entry pair under two d.entries keys backed by ONE
	// eBPF CT entry, so a single LBFlowRemove must tear down both. LB pairs
	// leave siblingKey empty — each direction is its own eBPF CT entry and gets
	// its own LBFlowRemove call. The whole cascade runs under the already-held
	// d.ctMtx; the sibling's evicting CAS guards against a concurrent
	// handleAgedEntry. No recursion — the sibling teardown is inlined.
	if oe.siblingKey != "" {
		if sib, ok := d.entries[oe.siblingKey]; ok && sib.evicting.CompareAndSwap(0, 1) {
			if err := DocaEntryRemove(sib.pipe, sib.entry); err != nil {
				logrus.WithFields(logrus.Fields{
					"plugin": "doca-bf2",
					"flow":   oe.siblingKey,
					"error":  err,
				}).Warn("DpDocaBf2 LBFlowRemove sibling remove failed (best-effort)")
			} else {
				d.offloadActive.Add(-1)
				docaOffloadActiveFlows.Set(float64(d.offloadActive.Load()))
			}
			delete(d.entries, oe.siblingKey)
			d.userCtxMu.Lock()
			delete(d.userCtxToKey, sib.userCtx)
			d.userCtxMu.Unlock()
			d.deferredOffload.Delete(oe.siblingKey)
		}
	}

	logrus.WithField("flow", flowKey).Debug("DpDocaBf2 flow removed")
	return nil
}

// routeFlowKey constructs a unique key for a route entry log message.
func routeFlowKey(w *RouteDpWorkQ) string {
	mlen, _ := w.Dst.Mask.Size()
	return fmt.Sprintf("%s/%d-zone%d", w.Dst.IP.String(), mlen, w.ZoneNum)
}

// RouteAdd is a no-op. Route entries are offloaded via RouteFlowOffload when
// established flows are detected in the CT scan (goCtHwOffloadHandler).
func (d *DpDocaBf2) RouteAdd(w *RouteDpWorkQ) error {
	logrus.WithFields(logrus.Fields{
		"route": routeFlowKey(w),
	}).Debug("doca-bf2: RouteAdd no-op (route offloaded at CT establishment)")
	return nil
}

// RouteDel removes a route's CT entries from the entries map if they exist.
func (d *DpDocaBf2) RouteDel(w *RouteDpWorkQ) error {
	if d.bridge == nil {
		return nil
	}
	// Route entries are tracked in d.entries with pipeKey "ct", keyed by flow 5-tuple.
	// Individual flow entries are removed by LBFlowRemove when CT entries expire.
	// RouteDel is a best-effort signal; no per-prefix tracking needed.
	return nil
}

// RouteFlowOffload creates a DOCA CT entry for a non-NAT established flow.
// Uses identity IP rewrite (match IPs = action IPs) with MAC rewrite and FWD_PORT
// to steer L3 routing flows through the eSwitch hardware.
func (d *DpDocaBf2) RouteFlowOffload(ct *DpCtInfo, rid int) error {
	if d.bridge == nil {
		return nil
	}

	// CGO-08: circuit breaker early exit
	if !d.circuitBreaker.allow() {
		return nil
	}

	// Determine protocol number (P47-R6 expanded: TCP/UDP/ICMP/SCTP/GRE/ESP
	// via protoNumForRouteOffload helper — see dpu_doca_bf2_helpers.go).
	protoNum, protoOk := protoNumForRouteOffload(ct.Proto)
	if !protoOk {
		return nil
	}

	flowKey := ct.Key()

	// A1: ctMtx guards d.entries (route entries are CT-domain bookkeeping).
	d.ctMtx.Lock()
	defer d.ctMtx.Unlock()

	// Idempotent: skip if already offloaded
	if _, exists := d.entries[flowKey]; exists {
		return nil
	}

	logrus.WithFields(logrus.Fields{"flow": flowKey, "sip": ct.SIP.String(), "dip": ct.DIP.String()}).
		Info("doca-bf2: RouteFlowOffload attempt")

	// Protocol-aware pipe selection for route flows.
	var pipe unsafe.Pointer
	var pipeKey string
	// Unified CT pipe handles both TCP and UDP (TRANSPORT l4_type_ext).
	// -06 (TX-2): wrapper renamed to DocaGetCTFwdPipe in lockstep
	// with the C-side llb_doca_get_ct_pipe → llb_doca_get_ct_fwd_pipe
	// rename. Route flows install on g_ct_fwd_pipe (same as LB forward
	// entries); they are tagged with pipeKey="route" for AllRouteStats
	// filtering.
	pipe = DocaGetCTFwdPipe()
	// P49-R2: tag routed-flow entries with pipeKey="route" (distinct from LB "ct")
	// so AllRouteStats can filter them.
	pipeKey = "route"
	if pipe == nil {
		return fmt.Errorf("doca-bf2 RouteFlowOffload: %s pipe not available", pipeKey)
	}

	// Identity IP rewrite: match values are passed as action values (no NAT).
	// Forward direction: client (ct.SIP) → server (ct.DIP).
	matchDstIP := tk.IPtonl(ct.DIP)
	matchDstPort := tk.Htons(ct.Dport)
	matchSrcIP := tk.IPtonl(ct.SIP)
	matchSrcPort := tk.Htons(ct.Sport)

	// synthesise the reverse direction — server (ct.DIP) → client
	// (ct.SIP). The eBPF layer fires ONE non-NAT EST event per routed flow
	// (NAT would create two CT entries → two events), so RouteFlowOffload
	// builds the reverse 5-tuple itself. Without a reverse entry the reply half
	// ingresses a representor port, hits g_ct_rev_pipe (empty), misses →
	// to_kernel → eBPF slow path. revFlowKey is the swapped-tuple
	// DpCtInfo.Key so it stays in lockstep with Key's format.
	revCt := *ct
	revCt.DIP, revCt.SIP = ct.SIP, ct.DIP
	revCt.Dport, revCt.Sport = ct.Sport, ct.Dport
	revFlowKey := revCt.Key()
	if revFlowKey == flowKey {
		revFlowKey = "" // degenerate self-flow — install forward only, no sibling
	} else if _, exists := d.entries[revFlowKey]; exists {
		return nil // sibling already installed by a concurrent path
	}

	// P47-R6: for cross-subnet flows the ARP target is the FIB next-hop gateway,
	// NOT the final destination (there is no ARP entry for a host on a remote
	// subnet). For direct-attached routes nextHopForFlow returns the address
	// unchanged. Forward steers toward ct.DIP; reverse steers toward ct.SIP.
	arpTarget := d.nextHopForFlow(ct.DIP)
	portID, dstMAC, srcMAC, ok := d.resolveFlowMACs(arpTarget)
	revArpTarget := d.nextHopForFlow(ct.SIP)
	revPortID, revDstMAC, revSrcMAC, revOk := d.resolveFlowMACs(revArpTarget)

	// Atomic: BOTH directions must resolve before EITHER entry installs. A
	// half-installed route pair would HW-offload one direction while the other
	// runs the eBPF slow path. If either ARP is unresolved, defer the whole
	// flow — the CT scan retries on the next cycle.
	if !ok || (revFlowKey != "" && !revOk) {
		logrus.WithFields(logrus.Fields{
			"flow":           flowKey,
			"fwd_resolved":   ok,
			"rev_resolved":   revOk,
			"arp_target":     arpTarget.String(),
			"rev_arp_target": revArpTarget.String(),
		}).Info("doca-bf2: route ARP unresolved (fwd or rev) — deferring flow to eBPF until CT scan retry")
		return nil
	}

	revPipe := DocaGetCTRevPipe()
	if revFlowKey != "" && revPipe == nil {
		return fmt.Errorf("doca-bf2 RouteFlowOffload: ct rev pipe not available")
	}

	// resolve aging timeout, allocate a unique userCtx per direction.
	agingSec := d.resolveAgingSec(protoNum, false)
	userCtx := d.allocUserCtx(flowKey)
	var revUserCtx uint64
	if revFlowKey != "" {
		revUserCtx = d.allocUserCtx(revFlowKey)
	}

	// === Forward entry → g_ct_fwd_pipe ===
	docaOffloadAttemptsTotal.Inc()
	entry, err := DocaEntryAddBasic(
		pipe,
		matchDstIP, matchDstPort,
		matchSrcIP, matchSrcPort,
		matchDstIP, matchDstPort, // identity: no IP/port rewrite
		matchSrcIP, matchSrcPort,
		dstMAC, srcMAC,
		0, // no DOCA-side timeout (eBPF-driven lifecycle)
		protoNum,
		portID,
		agingSec,   // per-entry DOCA aging
		userCtx,    // aged-entry identification
		0xFFFFFFFF, // LLB_DOCA_METER_NONE -- route flows have no meter
	)
	if err != nil {
		// A1: ctMtx → userCtxMu lock-graph order. ctMtx is held via defer.
		d.userCtxMu.Lock()
		delete(d.userCtxToKey, userCtx) // clean up on failure
		if revFlowKey != "" {
			delete(d.userCtxToKey, revUserCtx)
		}
		d.userCtxMu.Unlock()
		d.circuitBreaker.recordFailure()
		docaOffloadFailuresTotal.Inc()
		// A2: per-pipe-per-reason install error.
		docaOffloadInstallErrorsTotal.WithLabelValues("route", docaErrorReason(err)).Inc()
		return fmt.Errorf("doca-bf2 RouteFlowOffload entry add failed: %w", err)
	}

	// === Reverse entry → g_ct_rev_pipe ===
	// Reverse match/rewrite is the forward's swapped 5-tuple with identity
	// rewrite; MAC/port steer toward the client (revPortID/revDstMAC/revSrcMAC).
	var revEntry unsafe.Pointer
	if revFlowKey != "" {
		docaOffloadAttemptsTotal.Inc()
		revEntry, err = DocaEntryAddBasic(
			revPipe,
			matchSrcIP, matchSrcPort, // reverse dst = forward src (client)
			matchDstIP, matchDstPort, // reverse src = forward dst (server)
			matchSrcIP, matchSrcPort, // identity: no IP/port rewrite
			matchDstIP, matchDstPort,
			revDstMAC, revSrcMAC,
			0,
			protoNum,
			revPortID,
			agingSec,
			revUserCtx,
			0xFFFFFFFF,
		)
		if err != nil {
			// Reverse failed after the forward succeeded — roll back the
			// forward entry so the route flow is not left half-offloaded.
			// Direct primitive, mirroring pairedLBFlowOffload's reply-fail
			// rollback (same call context).
			if rmErr := DocaEntryRemoveDirect(pipe, entry); rmErr != nil {
				logrus.WithError(rmErr).
					Error("doca-bf2: RouteFlowOffload reverse-fail forward rollback failed; half-offloaded state")
			}
			d.userCtxMu.Lock()
			delete(d.userCtxToKey, userCtx)
			delete(d.userCtxToKey, revUserCtx)
			d.userCtxMu.Unlock()
			d.circuitBreaker.recordFailure()
			docaOffloadFailuresTotal.Inc()
			docaOffloadInstallErrorsTotal.WithLabelValues("route", docaErrorReason(err)).Inc()
			return fmt.Errorf("doca-bf2 RouteFlowOffload reverse entry add failed (rolled back): %w", err)
		}
	}

	d.circuitBreaker.recordSuccess()

	// Bookkeeping: forward + reverse cross-linked by siblingKey so LBFlowRemove
	// and DOCA aging tear down both halves of the routed flow together.
	d.entries[flowKey] = &docaOffloadEntry{
		pipe:      pipe,
		entry:     entry,
		pipeKey:   pipeKey,
		pkey:      append([]byte(nil), ct.PKey...), // defensive copy for tombstone
		userCtx:   userCtx,
		Direction: "forward",
		fwdPortID: portID,
	}
	if revFlowKey != "" {
		d.entries[flowKey].siblingKey = revFlowKey
		d.entries[revFlowKey] = &docaOffloadEntry{
			pipe:       revPipe,
			entry:      revEntry,
			pipeKey:    pipeKey, // "route" — shared closed-enum key for AllRouteStats
			pkey:       append([]byte(nil), ct.PKey...),
			userCtx:    revUserCtx,
			Direction:  "reply",
			fwdPortID:  revPortID,
			siblingKey: flowKey,
		}
		d.offloadActive.Add(2)
	} else {
		d.offloadActive.Add(1)
	}
	docaOffloadActiveFlows.Set(float64(d.offloadActive.Load()))

	logrus.WithFields(logrus.Fields{
		"flow":     flowKey,
		"revFlow":  revFlowKey,
		"pipe":     pipeKey,
		"fwdPort":  portID,
		"revPort":  revPortID,
		"agingSec": agingSec,
	}).Debug("DpDocaBf2 route flow offloaded (bidir)")
	return nil
}

// isPortOffloadable returns true if port is exact (min==max) or wildcard.
// Port ranges (min != max) cannot be offloaded to DOCA BASIC pipe.
func isPortOffloadable(min, max uint16) bool {
	if min == 0 && (max == 0 || max == 65535) {
		return true // wildcard (any port)
	}
	if min == max {
		return true // exact port match
	}
	return false // port range -- not offloadable
}

// ipMaskToUint32 converts net.IPMask to a uint32 whose MEMORY LAYOUT (on a
// little-endian host) is the network-byte-order mask. Same bug class as
// buildAclMatch's IP conversion (fixed 2026-05-18 commit 118c6af5):
// binary.BigEndian.Uint32 returns a host-order integer, NOT NBO bytes — when
// that integer is stored in memory on LE, the bytes are reversed vs what
// DOCA expects. Currently latent because validateHwOffloadExpressible
// enforces /32 (mask 0xFFFFFFFF is palindromic) and the C side ignores the
// mask arg anyway (loxilb_doca_flow.c:2447), but fixing for parity with the
// IP path and to avoid future surprises if either constraint loosens.
func ipMaskToUint32(mask net.IPMask) uint32 {
	if len(mask) == 0 {
		return 0xFFFFFFFF // default to /32 if no mask
	}
	m := mask
	if len(m) == 16 {
		m = m[12:] // IPv4-in-IPv6
	}
	// LSB-first byte-pack — same idiom as tk.IPtonl. On a little-endian
	// host, the resulting uint32 lands in memory as m[0..3] in order, which
	// is the NBO byte layout DOCA expects in struct doca_flow_match.outer.ip4.
	return uint32(m[0]) | uint32(m[1])<<8 | uint32(m[2])<<16 | uint32(m[3])<<24
}

// prefixLen returns the number of contiguous 1-bits in a net.IPMask (helper).
// Empty mask defaults to 32 (32 exact match).
func prefixLen(mask net.IPMask) int {
	if len(mask) == 0 {
		return 32
	}
	ones, _ := mask.Size()
	return ones
}

// portMaskForFwRule returns the per-entry port mask for a FwDpWorkQ port pair.
// Wildcard (0,0 or 0,65535) → 0x0000; exact (min==max≠0) → 0xFFFF.
// Caller has already passed validateHwOffloadExpressible / FwRuleAdd's local
// isPortOffloadable so port-range cases never reach here.
func portMaskForFwRule(min, max uint16) uint16 {
	if min == 0 && (max == 0 || max == 65535) {
		return 0x0000
	}
	return 0xFFFF
}

// buildAclMatch — (corrected): allocate the caller-owned em buffer
// from the FwDpWorkQ 5-tuple. Exact-IP values only — DOCA 2.9.4 BASIC pipes use
// the pipe-level template mask set at create time; per-entry CIDR masks were
// the original plan but the SDK's `doca_flow_pipe_add_entry` is 9-arg and
// does not accept one. `validateHwOffloadExpressible` rejects non-/32 prefixes,
// so the prefix-length args here are kept for future-proofing (UINT32_MAX for
// /32; harmless to ignore at the C layer for now).
//
// All multi-byte fields go in network byte order; port mask 0 = wildcard,
// 0xFFFF = exact. Returns nil on alloc failure. The buffer is heap-allocated
// on the C side; flushAclPending frees it via DocaAclMatchFree after the
// entry-add call returns.
func buildAclMatch(w *FwDpWorkQ) unsafe.Pointer {
	// IPv4 NBO byte-layout in a host uint32 — MUST use tk.IPtonl (or equivalent
	// LSB-first byte-pack), NOT binary.BigEndian.Uint32. Bug history (2026-05-18):
	// the prior `binary.BigEndian.Uint32(ip.To4)` returned the natural host
	// integer for the IP value (e.g. 10.99.0.2 → 0x0A630002), which on the BF2's
	// little-endian ARM64 lands in memory as [0x02,0x00,0x63,0x0A] — byte-reversed
	// vs the NBO layout DOCA's `outer.ip4.src_ip` expects. The entry then stored
	// "2.0.99.10" and never matched real packets carrying NBO bytes for 10.99.0.2.
	// CT pipes have always used tk.IPtonl (dpu_doca_bf2_helpers.go:327);
	// mirror that here to eliminate the byte-order divergence.
	srcIPbe := tk.IPtonl(w.SrcIP.IP)
	dstIPbe := tk.IPtonl(w.DstIP.IP)
	srcMaskbe := ipMaskToUint32(w.SrcIP.Mask)
	dstMaskbe := ipMaskToUint32(w.DstIP.Mask)
	srcPortMask := portMaskForFwRule(w.L4SrcMin, w.L4SrcMax)
	dstPortMask := portMaskForFwRule(w.L4DstMin, w.L4DstMax)
	// htons16 packs uint16 with NBO byte-layout — value-side already correct.
	var srcPort, dstPort uint16
	if srcPortMask != 0 {
		srcPort = htons16(w.L4SrcMin)
	}
	if dstPortMask != 0 {
		dstPort = htons16(w.L4DstMin)
	}

	em := DocaAclMatchAllocIP4(srcIPbe, srcMaskbe, dstIPbe, dstMaskbe,
		srcPort, srcPortMask, dstPort, dstPortMask)
	if em == nil {
		return nil
	}
	return em
}

// htons16 converts a host-order uint16 to network byte order.
func htons16(v uint16) uint16 {
	return (v<<8)&0xFF00 | (v>>8)&0x00FF
}

// cFree frees a C-side allocated match buffer via DocaAclMatchFree.
// Defined as a thin wrapper so the flushAclPending body reads cleanly.
func cFree(p unsafe.Pointer) {
	DocaAclMatchFree(p)
}

// ruleHashFor — : deterministic, ruleEnt-style string key for the
// aclDenyEntries / aclAllowEntries maps. Stable across restarts (no pointer,
// no time), embeds action+5-tuple+pref so two FwRuleAdds that differ only by
// pref or action produce distinct keys.
//
// Operator/kube-loxilb-driven re-POST after a loxilb restart re-enters this
// path via the same FwRuleAdd flow (no auto-replay code on the loxilb side);
// the deterministic key shape guarantees the post-restart entries land in the
// same map slots as before.
func ruleHashFor(w *FwDpWorkQ) string {
	return fmt.Sprintf("src=%s/%d,dst=%s/%d,sp=%d,dp=%d,pref=%d,act=%d",
		w.SrcIP.IP.String(), prefixLen(w.SrcIP.Mask),
		w.DstIP.IP.String(), prefixLen(w.DstIP.Mask),
		w.L4SrcMin, w.L4DstMin, w.Pref, w.FwType)
}

// ensureAclPipesUp — OPENING. Idempotent. Creates BOTH the DENY
// and ALLOW pipes (ALLOW first, DENY second — DENY's fwd_miss points at
// ALLOW) and re-dispatches the root pipe to target DENY. The C-side
// llb_doca_acl_pipes_create populates g_deny_pipe / g_allow_pipe before this
// returns; DocaRebuildRootPipe then reads C.llb_doca_get_deny_pipe and takes
// the OPEN branch.
//
// Lock-graph: aclLifecycleMu held throughout; NOT held across DocaBridge.submit
// — DocaAclPipesCreate / DocaRebuildRootPipe each take submit internally.
// fdbMtx is NOT acquired here (no map mutation).
func (d *DpDocaBf2) ensureAclPipesUp() error {
	d.aclLifecycleMu.Lock()
	defer d.aclLifecycleMu.Unlock()
	if d.aclPipesUp {
		return nil // idempotent
	}
	if err := DocaAclPipesCreate(); err != nil {
		return fmt.Errorf("acl pipes create: %w", err)
	}
	// At this point the C-side g_deny_pipe is non-NULL; DocaRebuildRootPipe will
	// take the OPEN branch (IPv4 root → DENY_PIPE).
	if err := DocaRebuildRootPipe(); err != nil {
		// Rollback: destroy the just-created pipes so the C-side globals go back
		// to NULL and a future ensureAclPipesUp can retry cleanly.
		if destroyErr := DocaAclPipesDestroy(); destroyErr != nil {
			logrus.WithError(destroyErr).Warn("acl-lifecycle: rollback pipes destroy failed after root rebuild error")
		}
		return fmt.Errorf("acl pipes root rebuild: %w", err)
	}
	d.aclPipesUp = true
	logrus.Info("acl-lifecycle: DENY_PIPE+ALLOW_PIPE created (lazy on first HwOffload=true rule)")
	return nil
}

// maybeTearDownAclPipes — CLOSING. Best-effort: if both maps are
// empty AND pipes are up, re-dispatches root away from DENY then destroys both
// pipes. Order is critical (root rebuild FIRST so no packet reaches a pipe
// about to be destroyed, pipe destroy SECOND).
//
// Acquires fdbMtx briefly under aclLifecycleMu for the emptiness re-check; the
// CGO submits happen outside fdbMtx (aclLifecycleMu held).
func (d *DpDocaBf2) maybeTearDownAclPipes() {
	d.aclLifecycleMu.Lock()
	defer d.aclLifecycleMu.Unlock()
	if !d.aclPipesUp {
		return
	}
	d.fdbMtx.Lock()
	empty := len(d.aclDenyEntries) == 0 && len(d.aclAllowEntries) == 0
	d.fdbMtx.Unlock()
	if !empty {
		return
	}
	// Flip aclPipesUp=false FIRST so a concurrent ensureAclPipesUp sees the
	// closed state and waits on aclLifecycleMu (it is held by us). Then root
	// rebuild — but C.llb_doca_get_deny_pipe still returns non-NULL until we
	// call destroy below. The CLOSED branch in DocaRebuildRootPipe is gated on
	// the C-side handle, so we must rebuild AFTER destroy. To keep the order
	// "root rebuild → destroy → re-rebuild" correct we instead:
	//   1) destroy the pipes (C-side g_deny_pipe / g_allow_pipe go NULL)
	//   2) re-dispatch root (CLOSED branch fires; targets fdb / CT_FWD direct)
	// This is safe because the root-pipe rebuild is itself atomic (save-old /
	// swap / destroy-old inside the C bridge), so traffic continues to hit the
	// stale DENY_PIPE entries for a microsecond window — those entries' actions
	// (FWD_DROP for deny, FWD_PIPE→CT_FWD for allow) remain semantically
	// correct (the in-flight rule has already been removed from eBPF in
	// FwRuleDel before this teardown runs, but for empty maps no in-flight
	// rule exists anyway).
	prev := d.aclPipesUp
	d.aclPipesUp = false
	if err := DocaAclPipesDestroy(); err != nil {
		// Roll back the flag so the next FwRuleAdd hits ensureAclPipesUp which
		// will idempotently return (the C side may have partially destroyed).
		d.aclPipesUp = prev
		logrus.WithError(err).Warn("acl-lifecycle: pipes destroy failed; leaving aclPipesUp=true")
		return
	}
	if err := DocaRebuildRootPipe(); err != nil {
		// Pipes are gone, but root still references them via stale dispatch.
		// Best-effort log; the next ensureAclPipesUp will re-rebuild root.
		logrus.WithError(err).Warn("acl-lifecycle: root rebuild on teardown failed; state may be inconsistent")
		return
	}
	logrus.Info("acl-lifecycle: DENY_PIPE+ALLOW_PIPE destroyed (last HwOffload=true rule removed)")
}

// scheduleAclFlush —. Re-armed time.AfterFunc; cap-cancels when
// aclBatchCap is hit (caller does synchronous flushAclPending). Mirrors the
// pattern of the retired scheduleACLRebuild but with the new
// debounce-window constant.
func (d *DpDocaBf2) scheduleAclFlush() {
	d.aclBatchMu.Lock()
	defer d.aclBatchMu.Unlock()
	if d.aclBatchTimer != nil {
		d.aclBatchTimer.Stop()
	}
	d.aclBatchTimer = time.AfterFunc(aclDebounceMs, d.flushAclPending)
}

// flushAclPending —. Drains aclPendingAdd / aclPendingDel, calls
// the per-entry CGO add / del, writes the resulting opaque handles into the
// aclDenyEntries / aclAllowEntries maps under fdbMtx, and updates the
// Prometheus gauges. CGO calls are NOT held across fdbMtx (lesson:
// PATTERNS FDB analog at :2113-2137 is the template).
//
// On a successful flush that empties both maps and the pipes are up, schedules
// maybeTearDownAclPipes asynchronously so the lifecycle CLOSE doesn't block
// the FwRuleAdd/Del caller.
func (d *DpDocaBf2) flushAclPending() {
	d.aclBatchMu.Lock()
	adds := d.aclPendingAdd
	dels := d.aclPendingDel
	d.aclPendingAdd = nil
	d.aclPendingDel = nil
	d.aclBatchMu.Unlock()

	if len(adds) == 0 && len(dels) == 0 {
		return
	}

	for _, p := range adds {
		var addFn func(em unsafe.Pointer, t uint32) (unsafe.Pointer, error)
		var pipeKey string
		if p.action == 1 {
			addFn = DocaAclAllowEntryAdd
			pipeKey = "acl_allow"
		} else {
			addFn = DocaAclDenyEntryAdd
			pipeKey = "acl_deny"
		}
		entry, err := addFn(p.em, 0)
		// Free the caller-allocated match buffer regardless of result (CGO
		// add-entry copies the contents under DOCA_FLOW_NO_WAIT before
		// returning).
		if p.em != nil {
			cFree(p.em)
		}
		if err != nil {
			docaOffloadInstallErrorsTotal.WithLabelValues("acl", docaErrorReason(err)).Inc()
			if p.onDone != nil {
				p.onDone <- err
				close(p.onDone)
			}
			continue
		}
		d.fdbMtx.Lock()
		if p.action == 1 {
			d.aclAllowEntries[p.hash] = &docaOffloadEntry{entry: entry, pipeKey: pipeKey}
			docaAclHwOffloadRulesTotal.WithLabelValues("allow").Inc()
		} else {
			d.aclDenyEntries[p.hash] = &docaOffloadEntry{entry: entry, pipeKey: pipeKey}
			docaAclHwOffloadRulesTotal.WithLabelValues("deny").Inc()
		}
		d.fdbMtx.Unlock()
		if p.onDone != nil {
			p.onDone <- nil
			close(p.onDone)
		}
	}

	for _, hash := range dels {
		d.fdbMtx.Lock()
		if oe, ok := d.aclDenyEntries[hash]; ok {
			d.fdbMtx.Unlock()
			if err := DocaAclDenyEntryDel(oe.entry); err != nil {
				logrus.WithError(err).Warn("acl-flush: deny entry del failed")
			}
			d.fdbMtx.Lock()
			delete(d.aclDenyEntries, hash)
			d.fdbMtx.Unlock()
			continue
		}
		if oe, ok := d.aclAllowEntries[hash]; ok {
			d.fdbMtx.Unlock()
			if err := DocaAclAllowEntryDel(oe.entry); err != nil {
				logrus.WithError(err).Warn("acl-flush: allow entry del failed")
			}
			d.fdbMtx.Lock()
			delete(d.aclAllowEntries, hash)
			d.fdbMtx.Unlock()
			continue
		}
		d.fdbMtx.Unlock()
	}

	// drain the DOCA per-pipe-queue NO_WAIT pending buffer. ACL
	// add/del entries use DOCA_FLOW_NO_WAIT and rely on this drain — without it
	// the queue saturates at ~128 pending entries (set_pipe_queues=1) and every
	// subsequent doca_flow_pipe_add_entry returns INVALID_VALUE. CT entries are
	// drained implicitly aging poll; ACL pipes have no aging so
	// they need this explicit per-flush drain.
	if len(adds) > 0 || len(dels) > 0 {
		if err := DocaEntriesDrain(50_000 /* 50ms */, 256); err != nil {
			logrus.WithError(err).Warn("acl-flush: entries_drain failed (silicon may still commit on next tick)")
		}
	}

	// Update per-pipe gauges from the post-flush map sizes.
	d.fdbMtx.Lock()
	denyCount := len(d.aclDenyEntries)
	allowCount := len(d.aclAllowEntries)
	d.fdbMtx.Unlock()
	docaAclHwDenyEntries.Set(float64(denyCount))
	docaAclHwAllowEntries.Set(float64(allowCount))

	if denyCount == 0 && allowCount == 0 {
		d.aclLifecycleMu.Lock()
		up := d.aclPipesUp
		d.aclLifecycleMu.Unlock()
		if up {
			go d.maybeTearDownAclPipes()
		}
	}
}

// FwRuleAdd — opt-IN gate + defence-in-depth + enqueue.
// Operator/kube-loxilb-driven re-POST after a loxilb restart re-enters this
// same path (no auto-replay code on the loxilb side); the deterministic
// ruleHashFor guarantees post-restart entries land in the same map slots
// .
func (d *DpDocaBf2) FwRuleAdd(w *FwDpWorkQ) error {
	// non-flagged rules stay eBPF-only.
	if !w.HwOffload {
		return nil
	}
	// defence-in-depth: the AddFwRule gate already rejects non-expressible
	// shapes, but a direct DP work-queue path (test seam, future REST extension)
	// could bypass it; keep the asserts local.
	if w.SrcIP.IP.To4() == nil || w.DstIP.IP.To4() == nil {
		return fmt.Errorf("FwRuleAdd: HwOffload=true with IPv6 src/dst is not expressible")
	}
	if !isPortOffloadable(w.L4SrcMin, w.L4SrcMax) || !isPortOffloadable(w.L4DstMin, w.L4DstMax) {
		return fmt.Errorf("FwRuleAdd: HwOffload=true with port range is not expressible")
	}
	if w.Proto != 0 {
		return fmt.Errorf("FwRuleAdd: HwOffload=true with protocol-specific rule is not expressible")
	}

	hash := ruleHashFor(w)
	var action byte
	if w.FwType != DpFwDrop {
		action = 1 // allow / forward / redirect / trap → ALLOW pipe (counter-only audit)
	}

	em := buildAclMatch(w)
	if em == nil {
		return fmt.Errorf("FwRuleAdd: failed to allocate match buffer")
	}

	done := make(chan error, 1)
	p := aclPending{hash: hash, action: action, em: em, onDone: done}

	d.aclBatchMu.Lock()
	d.aclPendingAdd = append(d.aclPendingAdd, p)
	full := len(d.aclPendingAdd) >= aclBatchCap
	d.aclBatchMu.Unlock()

	// Ensure the lazy DENY+ALLOW pipes exist before the next flush wakes; the
	// first HwOffload=true rule across the lifetime of this DpDocaBf2 triggers
	// pipe creation. Idempotent for subsequent calls.
	if err := d.ensureAclPipesUp(); err != nil {
		// Drain the just-enqueued pending entry and free its buffer; the caller
		// gets the lifecycle error directly (no flush will run for this entry).
		d.aclBatchMu.Lock()
		for i := range d.aclPendingAdd {
			if d.aclPendingAdd[i].hash == hash {
				d.aclPendingAdd = append(d.aclPendingAdd[:i], d.aclPendingAdd[i+1:]...)
				break
			}
		}
		d.aclBatchMu.Unlock()
		if em != nil {
			cFree(em)
		}
		return err
	}

	if full {
		d.flushAclPending()
	} else {
		d.scheduleAclFlush()
	}

	return <-done
}

// FwRuleDel — opt-IN gate + cancel-pending-on-Del.
func (d *DpDocaBf2) FwRuleDel(w *FwDpWorkQ) error {
	if !w.HwOffload {
		return nil
	}
	hash := ruleHashFor(w)

	// cancel-pending-on-Del: scan aclPendingAdd for a matching hash. If
	// found, splice out, free the buffers, signal the waiting FwRuleAdd, and
	// return nil — nothing is in HW yet.
	d.aclBatchMu.Lock()
	for i, p := range d.aclPendingAdd {
		if p.hash == hash {
			d.aclPendingAdd = append(d.aclPendingAdd[:i], d.aclPendingAdd[i+1:]...)
			d.aclBatchMu.Unlock()
			if p.em != nil {
				cFree(p.em)
			}
			if p.onDone != nil {
				close(p.onDone)
			}
			return nil
		}
	}

	// only enqueue a Del if the hash is actually in one of the
	// installed-entry maps. Otherwise the rule was never HW-offloaded (silent
	// silicon rejection — should be near-zero after queue-drain
	// fix, but possible if entry_status_cb fails). Return ErrFwRuleNotOffloaded
	// so ShadowFwRuleDel skips RecordOffloadRemove and the per-pipe active
	// counter doesn't underflow.
	d.fdbMtx.Lock()
	_, inDeny := d.aclDenyEntries[hash]
	_, inAllow := d.aclAllowEntries[hash]
	d.fdbMtx.Unlock()
	if !inDeny && !inAllow {
		d.aclBatchMu.Unlock()
		return ErrFwRuleNotOffloaded
	}

	d.aclPendingDel = append(d.aclPendingDel, hash)
	d.aclBatchMu.Unlock()

	// Flush will run on the next debounce tick; teardown (if both maps go
	// empty) is scheduled asynchronously by flushAclPending. FwRuleDel is
	// non-blocking on the result — the upstream rule table already removed
	// the rule from eBPF before invoking this plugin path.
	d.scheduleAclFlush()
	return nil
}

// NextHopAdd -- not supported.
func (d *DpDocaBf2) NextHopAdd(w *NextHopDpWorkQ) error {
	return ErrNotSupported
}

// NextHopDel -- not supported.
func (d *DpDocaBf2) NextHopDel(w *NextHopDpWorkQ) error {
	return ErrNotSupported
}

// fdbKeyString generates a unique key for FDB offload entry tracking.
func fdbKeyString(mac [6]byte) string {
	return fmt.Sprintf("fdb:%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// FdbFlowOffload offloads a unicast MAC to the DOCA FDB pipe.
// Multicast/broadcast MACs and tunnel FDB entries are skipped.
func (d *DpDocaBf2) FdbFlowOffload(fdb *FdbEnt) error {
	if !d.initialized || !d.circuitBreaker.allow() {
		return nil
	}

	// Guard: skip multicast/broadcast MACs (IEEE bit 0 of first octet)
	if fdb.FdbKey.MacAddr[0]&0x01 != 0 {
		return nil
	}

	// Guard: only physical FDB entries, not tunnel FDB
	if fdb.FdbAttr.FdbType != 0 { // cmn.FdbPhy = 0
		return nil
	}

	pipe := DocaGetFdbPipe()
	if pipe == nil {
		return nil // FDB pipe not created (non-fatal)
	}

	macKey := fdbKeyString(fdb.FdbKey.MacAddr)

	// A1: fdbMtx guards fdbEntries; userCtxMu acquired in lock-graph order
	// (fdbMtx → userCtxMu) for userCtxToKey writes.
	d.fdbMtx.Lock()
	if _, exists := d.fdbEntries[macKey]; exists {
		d.fdbMtx.Unlock()
		return nil // already offloaded
	}

	// Resolve DPDK port ID from interface index
	var dpdkPortID uint16
	var portFound bool
	if fdb.Port != nil {
		dpdkPortID, portFound = d.ifindexToPort[fdb.Port.SInfo.OsID]
	}
	if !portFound {
		d.fdbMtx.Unlock()
		return fmt.Errorf("fdb offload: no DPDK port for port %s", fdb.FdbAttr.Oif)
	}

	userCtx := d.allocUserCtx(macKey)
	d.fdbMtx.Unlock()

	// CGO call outside lock
	const fdbAgingSec = 300 // 5-minute bridge standard MAC aging
	entry, err := DocaFdbEntryAdd(pipe, fdb.FdbKey.MacAddr, dpdkPortID, fdbAgingSec, userCtx, 3000)
	if err != nil {
		d.fdbMtx.Lock()
		d.userCtxMu.Lock()
		delete(d.userCtxToKey, userCtx)
		d.userCtxMu.Unlock()
		d.fdbMtx.Unlock()
		d.circuitBreaker.recordFailure()
		// A2: per-pipe-per-reason install error.
		docaOffloadInstallErrorsTotal.WithLabelValues("fdb", docaErrorReason(err)).Inc()
		return fmt.Errorf("fdb offload failed: %w", err)
	}

	d.fdbMtx.Lock()
	d.fdbEntries[macKey] = &docaFdbOffloadEntry{
		pipe:      pipe,
		entry:     entry,
		userCtx:   userCtx,
		fwdPortID: dpdkPortID, // P49-R2: store for AllFdbStats label
	}
	d.fdbMtx.Unlock()
	d.circuitBreaker.recordSuccess()

	logrus.WithFields(logrus.Fields{
		"mac":     fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", fdb.FdbKey.MacAddr[0], fdb.FdbKey.MacAddr[1], fdb.FdbKey.MacAddr[2], fdb.FdbKey.MacAddr[3], fdb.FdbKey.MacAddr[4], fdb.FdbKey.MacAddr[5]),
		"port":    dpdkPortID,
		"userCtx": userCtx,
	}).Debug("FDB entry offloaded to DOCA")
	return nil
}

// FdbFlowRemove removes a MAC from the DOCA FDB pipe.
// A1: fdbMtx is the FDB-domain lock; userCtxMu acquired for userCtxToKey writes.
func (d *DpDocaBf2) FdbFlowRemove(fdb *FdbEnt) error {
	macKey := fdbKeyString(fdb.FdbKey.MacAddr)

	d.fdbMtx.Lock()
	oe, exists := d.fdbEntries[macKey]
	if !exists {
		d.fdbMtx.Unlock()
		return nil
	}
	// CAS guard: prevent double-eviction with aging
	if !oe.evicting.CompareAndSwap(0, 1) {
		d.fdbMtx.Unlock()
		return nil
	}
	delete(d.fdbEntries, macKey)
	d.userCtxMu.Lock()
	delete(d.userCtxToKey, oe.userCtx)
	d.userCtxMu.Unlock()
	pipe := oe.pipe
	entry := oe.entry
	d.fdbMtx.Unlock()

	// DOCA removal outside lock
	if err := DocaEntryRemove(pipe, entry); err != nil {
		logrus.WithError(err).Debug("FDB DOCA entry remove failed")
	}

	logrus.WithFields(logrus.Fields{
		"mac": fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", fdb.FdbKey.MacAddr[0], fdb.FdbKey.MacAddr[1], fdb.FdbKey.MacAddr[2], fdb.FdbKey.MacAddr[3], fdb.FdbKey.MacAddr[4], fdb.FdbKey.MacAddr[5]),
	}).Debug("FDB entry removed from DOCA")
	return nil
}

// handleAgedFdbEntry processes a DOCA-aged FDB entry: CAS guard, map cleanup, DOCA removal.
// No CT tombstone needed since FDB has no eBPF map entry.
// A1: fdbMtx is the FDB-domain lock; userCtxMu acquired in lock-graph order.
func (d *DpDocaBf2) handleAgedFdbEntry(macKey string, userCtx uint64) {
	d.fdbMtx.Lock()
	oe, exists := d.fdbEntries[macKey]
	if !exists {
		d.userCtxMu.Lock()
		delete(d.userCtxToKey, userCtx)
		d.userCtxMu.Unlock()
		d.fdbMtx.Unlock()
		return
	}
	if !oe.evicting.CompareAndSwap(0, 1) {
		d.fdbMtx.Unlock()
		return
	}
	delete(d.fdbEntries, macKey)
	d.userCtxMu.Lock()
	delete(d.userCtxToKey, userCtx)
	d.userCtxMu.Unlock()
	pipe := oe.pipe
	entry := oe.entry
	d.fdbMtx.Unlock()

	if err := DocaEntryRemove(pipe, entry); err != nil {
		logrus.WithError(err).Debug("FDB aged entry DOCA remove failed")
	}
	logrus.WithField("macKey", macKey).Debug("FDB entry aged out from DOCA")
}

// FlowStats queries DOCA hardware counters for a specific offloaded flow.
//
// statsRWMu.RLock is the outer drain guard;
// ctMtx is taken briefly to snapshot the entry handle, then released BEFORE
// DocaEntryQuery so concurrent scrapes do not serialize on the DOCA query.
// Holding only statsRWMu.RLock here would race against LBFlowOffload writers
// (which hold ctMtx) → Go runtime fatal "concurrent map iteration and map
// write".
func (d *DpDocaBf2) FlowStats(ct *DpCtInfo) (uint64, uint64, error) {
	flowKey := ct.Key()
	d.statsRWMu.RLock()
	defer d.statsRWMu.RUnlock()

	d.ctMtx.Lock()
	oe, exists := d.entries[flowKey]
	var entryHandle unsafe.Pointer
	if exists && oe != nil {
		entryHandle = oe.entry
	}
	d.ctMtx.Unlock()

	if !exists {
		return 0, 0, ErrNotSupported
	}
	if entryHandle == nil {
		return 0, 0, ErrNotSupported
	}

	bytes, pkts, err := DocaEntryQuery(entryHandle)
	if err != nil {
		return 0, 0, fmt.Errorf("doca-bf2 FlowStats query failed: %w", err)
	}
	return bytes, pkts, nil
}

// AllFlowStats returns HW counters for all currently offloaded flows.
//
// split single g_ct_pipe into per-direction g_ct_pipe (forward,
// uplink-ingress) and g_ct_rev_pipe (reply, VF-rep-ingress). The legacy
// single-pipe-bidir model exhibited counter-zero behavior on BF2 silicon
// when FWD_PORT actions were active for both directions in the same pipe.
// Per-direction split is expected to make HW counters report real packet
// counts. P52-04 validation confirms or escalates contingency.
//
// Until P52-04 closes, treat zero counters as INDETERMINATE rather than
// confirming HW offload — cross-check with Prometheus
// doca_pipe_hw_pkts_total{pipe="ct",direction="reply"} which uses
// NON_SHARED counter monitor on each per-direction pipe.
func (d *DpDocaBf2) AllFlowStats() []FlowHwStats {
	// outer statsRWMu.RLock preserves Shutdown drain;
	// ctMtx is the writer mutex for d.entries — held briefly to snapshot, then
	// released BEFORE DocaEntryQuery (anti-deadlock rule: never
	// hold a domain mutex across DOCA submit calls). Holding only statsRWMu
	// here would race against LBFlowOffload's ctMtx-guarded writes.
	d.statsRWMu.RLock()
	defer d.statsRWMu.RUnlock()

	type flowSnap struct {
		flowKey   string
		pipeKey   string
		direction string
		entry     unsafe.Pointer
	}

	d.ctMtx.Lock()
	snaps := make([]flowSnap, 0, len(d.entries))
	for flowKey, oe := range d.entries {
		if oe == nil || oe.entry == nil {
			continue
		}
		// propagate Direction from oe.Direction (single source of
		// truth set in pairedLBFlowOffload bookkeeping). Legacy / route / FDB /
		// ACL entries leave it as "" so per-direction-aware metrics keep their
		// flat-line baseline child.
		snaps = append(snaps, flowSnap{
			flowKey:   flowKey,
			pipeKey:   oe.pipeKey,
			direction: oe.Direction,
			entry:     oe.entry,
		})
	}
	d.ctMtx.Unlock()

	results := make([]FlowHwStats, 0, len(snaps))
	for _, s := range snaps {
		bytes, pkts, err := DocaEntryQuery(s.entry)
		if err != nil {
			continue
		}
		results = append(results, FlowHwStats{
			FlowKey:   s.flowKey,
			PipeKey:   s.pipeKey,
			Direction: s.direction,
			HwBytes:   bytes,
			HwPkts:    pkts,
		})
	}
	return results
}

// AllFdbStats returns per-FDB-entry HW counters for all tracked FDB entries.
// Mirrors AllFlowStats pattern: snapshot under fdbMtx (the writer mutex for
// d.fdbEntries), release, then DocaEntryQuery each entry outside the lock.
// Skip entries whose query fails (BF2 silicon FWD_PORT caveat — counters may
// return 0 or an error; surfaced as "0 / skipped" rather than crash).
// Each row carries MAC (stripped of "fdb:" prefix) and the DPDK forward-port ID
// captured at FdbFlowOffload time.
func (d *DpDocaBf2) AllFdbStats() []FdbHwStats {
	// outer statsRWMu.RLock for Shutdown drain;
	// fdbMtx is the writer mutex for d.fdbEntries — held briefly for snapshot,
	// released BEFORE DocaEntryQuery.
	d.statsRWMu.RLock()
	defer d.statsRWMu.RUnlock()

	type fdbSnap struct {
		macKey string
		port   uint16
		entry  unsafe.Pointer
	}

	d.fdbMtx.Lock()
	snaps := make([]fdbSnap, 0, len(d.fdbEntries))
	for macKey, oe := range d.fdbEntries {
		if oe == nil || oe.entry == nil {
			continue
		}
		snaps = append(snaps, fdbSnap{
			macKey: macKey,
			port:   oe.fwdPortID,
			entry:  oe.entry,
		})
	}
	d.fdbMtx.Unlock()

	results := make([]FdbHwStats, 0, len(snaps))
	for _, s := range snaps {
		bytes, pkts, err := DocaEntryQuery(s.entry)
		if err != nil {
			// BF2 BASIC + FWD_PORT silicon caveat: counters may return 0 or
			// error for active entries. Skip silently — operators are warned
			// in runbook.
			continue
		}
		// Strip "fdb:" prefix if present (fdbKeyString convention).
		mac := s.macKey
		if len(mac) > 4 && mac[:4] == "fdb:" {
			mac = mac[4:]
		}
		results = append(results, FdbHwStats{
			Mac:     mac,
			Port:    s.port,
			HwBytes: bytes,
			HwPkts:  pkts,
		})
	}
	return results
}

// AllRouteStats returns per-routed-flow HW counters. Filters d.entries where
// pipeKey == "route" — changes RouteFlowOffload to tag new entries
// with "route" (previously "ct"; LB path still tags "ct").
// (full FIB LPM) postponed to v7.1, so this surface reports the CT-path
// routed flows landed by RouteFlowOffload — not a separate LPM pipe. The
// destination CIDR / next-hop MAC / egress-port fields are not carried on
// docaOffloadEntry today; populate with empty/zero values and let
// (Prometheus wiring) extend the storage if fuller labeling is needed.
func (d *DpDocaBf2) AllRouteStats() []RouteHwStats {
	// outer statsRWMu.RLock for Shutdown drain;
	// ctMtx is the writer mutex for d.entries — held briefly for snapshot,
	// released BEFORE DocaEntryQuery.
	d.statsRWMu.RLock()
	defer d.statsRWMu.RUnlock()

	type routeSnap struct {
		entry unsafe.Pointer
	}

	d.ctMtx.Lock()
	snaps := make([]routeSnap, 0)
	for _, oe := range d.entries {
		if oe == nil || oe.entry == nil || oe.pipeKey != "route" {
			continue
		}
		snaps = append(snaps, routeSnap{entry: oe.entry})
	}
	d.ctMtx.Unlock()

	results := make([]RouteHwStats, 0, len(snaps))
	for _, s := range snaps {
		bytes, pkts, err := DocaEntryQuery(s.entry)
		if err != nil {
			continue
		}
		results = append(results, RouteHwStats{
			// TODO : plumb dst CIDR / nextHopMac / egressPort through
			// docaOffloadEntry. Empty values preserve the row schema for now.
			Dst:        "",
			NextHopMac: "",
			Port:       0,
			HwBytes:    bytes,
			HwPkts:     pkts,
		})
	}
	return results
}

// AllAclStats returns per-ACL-rule HW counters from both the DENY and ALLOW
// pipes. single-pipe `aclEntries` map is no
// longer populated; the new lazy pair (`aclDenyEntries` / `aclAllowEntries`)
// is the source of truth. Action label is "DROP" for DENY entries and
// "ALLOW" for ALLOW entries.
func (d *DpDocaBf2) AllAclStats() []AclHwStats {
	// outer statsRWMu.RLock for Shutdown drain;
	// fdbMtx is the writer mutex for d.aclDenyEntries / d.aclAllowEntries —
	// held briefly for snapshot, released BEFORE DocaEntryQuery.
	d.statsRWMu.RLock()
	defer d.statsRWMu.RUnlock()

	type aclSnap struct {
		action string
		entry  unsafe.Pointer
	}

	d.fdbMtx.Lock()
	snaps := make([]aclSnap, 0, len(d.aclDenyEntries)+len(d.aclAllowEntries))
	for _, e := range d.aclDenyEntries {
		if e == nil || e.entry == nil {
			continue
		}
		snaps = append(snaps, aclSnap{action: "DROP", entry: e.entry})
	}
	for _, e := range d.aclAllowEntries {
		if e == nil || e.entry == nil {
			continue
		}
		snaps = append(snaps, aclSnap{action: "ALLOW", entry: e.entry})
	}
	d.fdbMtx.Unlock()

	results := make([]AclHwStats, 0, len(snaps))
	for _, s := range snaps {
		bytes, pkts, err := DocaEntryQuery(s.entry)
		if err != nil {
			continue
		}
		results = append(results, AclHwStats{
			Action:  s.action,
			HwBytes: bytes,
			HwPkts:  pkts,
		})
	}
	return results
}

// LBFlowOffloadWithPipeKind implements the manager's optional lbFlowOffloadPipeKinder
// interface (dpu_manager.go). Lets DpuManager attribute LB offloads to pipeCT vs
// pipeUDPCT without heuristic-only Proto inference.
// Returns pipeCT for TCP/SCTP/other, pipeUDPCT for UDP.
func (d *DpDocaBf2) LBFlowOffloadWithPipeKind(ct *DpCtInfo, lbMark int) (pipeKind, error) {
	err := d.LBFlowOffload(ct, lbMark)
	pk := pipeCT
	if ct != nil && ct.Proto == "udp" {
		pk = pipeUDPCT
	}
	return pk, err
}

// PipeStats -- placeholder +.
func (d *DpDocaBf2) PipeStats(name string) (uint32, error) {
	return 0, ErrNotSupported
}

// MeterAdd configures a DOCA shared meter and tracks it for auto-attach and live update.
// meter_id = w.Mark - 1 (0-based), max 64 slots.
func (d *DpDocaBf2) MeterAdd(w *PolDpWorkQ) error {
	if d.bridge == nil {
		return ErrNotSupported
	}

	// Validate meter ID range (DOCA pre-allocates 64 shared meters, IDs 0..63)
	if w.Mark > 64 || w.Mark < 1 {
		docaMeterPoolExhaustedTotal.Inc()
		return fmt.Errorf("meter Mark %d exceeds DOCA shared meter limit (64 slots)", w.Mark)
	}

	meterID := uint32(w.Mark - 1) // convert 1-based Mark to 0-based DOCA ID

	// A1: ctMtx guards meterMap + lbMarkToMeter (CT-domain bookkeeping).
	d.ctMtx.Lock()
	defer d.ctMtx.Unlock()

	// Configure + bind shared meter via CGO bridge (thread-serialized)
	rc := DocaMeterAdd(meterID, w.Cir, w.Cbs, w.Ebs)
	if rc != 0 {
		return fmt.Errorf("DocaMeterAdd(%d) failed: rc=%d", meterID, rc)
	}

	// Track in local map for stats collection
	d.meterMap[meterID] = &docaMeterEntry{
		mark:   w.Mark,
		cir:    w.Cir,
		name:   w.Name,
		active: true,
	}

	// Populate lbMarkToMeter for reference (stats collection, future use)
	if w.TargetLBMark > 0 {
		d.lbMarkToMeter[w.TargetLBMark] = meterID
	}

	SetMeterOffloadActive(meterID, w.Name, true)

	// meter classification pipe creation retired
	// carry-forward: deleted g_l4_dispatch_pipe (the meter pipe's
	// miss target) AND retired DocaGetL4DispatchPipe / DocaSetMeterPipe
	// dependencies. The single ACL pipe that dispatched to meter_pipe
	// is also retired (replaced by the lazy DENY+ALLOW pair). The meter pool
	// itself (DocaMeterAdd above at line ~2769) is still bound to CT entries
	// via DocaEntryUpdateMeter — that path keeps working for shared-meter
	// per-flow policing. Per-VIP classification pipe + scheduleACLRebuild
	// would require re-architecting around the new DENY+ALLOW + CT_FWD chain
	// (out of scope; tracked for v7.1).
	_ = w.MeterDstIP // suppress unused-field linter

	logrus.WithFields(logrus.Fields{
		"meter_id":     meterID,
		"mark":         w.Mark,
		"name":         w.Name,
		"cir":          w.Cir,
		"targetLBMark": w.TargetLBMark,
	}).Info("doca-bf2: MeterAdd succeeded")
	return nil
}

// MeterDel removes a DOCA shared meter and cleans up tracking maps.
func (d *DpDocaBf2) MeterDel(w *PolDpWorkQ) error {
	if d.bridge == nil {
		return ErrNotSupported
	}

	if w.Mark > 64 || w.Mark < 1 {
		return fmt.Errorf("meter Mark %d out of range", w.Mark)
	}

	meterID := uint32(w.Mark - 1)

	// A1: ctMtx guards meterMap + lbMarkToMeter (CT-domain bookkeeping).
	d.ctMtx.Lock()
	defer d.ctMtx.Unlock()

	rc := DocaMeterDel(meterID)
	if rc != 0 {
		logrus.WithFields(logrus.Fields{
			"meter_id": meterID,
			"rc":       rc,
		}).Warn("doca-bf2: DocaMeterDel failed (best-effort)")
	}

	// Clean up meter pipe entry and tracking
	me, exists := d.meterMap[meterID]
	if exists {
		// Remove meter pipe entry if it was created
		if me.pipeEntry != nil {
			_ = DocaEntryRemove(me.pipe, me.pipeEntry)
		}
		SetMeterOffloadActive(meterID, me.name, false)
		delete(d.meterMap, meterID)
	}

	// Remove from lbMarkToMeter
	if w.TargetLBMark > 0 {
		delete(d.lbMarkToMeter, w.TargetLBMark)
	}

	logrus.WithFields(logrus.Fields{
		"meter_id": meterID,
		"mark":     w.Mark,
	}).Info("doca-bf2: MeterDel succeeded")
	return nil
}

// QueryMeterStats queries DOCA shared resource stats for a meter via DocaBridge.submit.
// Returns aggregate counts (BF2 does not provide per-color breakdown).
func (d *DpDocaBf2) QueryMeterStats(meterID uint32) (DocaMeterStats, error) {
	totalPkts, totalBytes, err := DocaMeterQuery(meterID)
	if err != nil {
		return DocaMeterStats{}, err
	}
	return DocaMeterStats{TotalPkts: totalPkts, TotalBytes: totalBytes}, nil
}

// ActiveMeters returns a snapshot of active meter IDs and names for stats collection.
// Called from PolTicker (via DpuManager) without holding d.ctMtx -- takes its own lock.
//
// outer statsRWMu.RLock for Shutdown drain; ctMtx
// is the writer mutex for d.meterMap (MeterAdd/MeterDel) — held briefly for
// snapshot, released BEFORE returning. Result is a pure-Go map copy so no
// DOCA call is needed outside the lock; the snapshot still happens under
// ctMtx so the iteration cannot race against a concurrent MeterAdd write.
func (d *DpDocaBf2) ActiveMeters() map[uint32]string {
	d.statsRWMu.RLock()
	defer d.statsRWMu.RUnlock()

	d.ctMtx.Lock()
	result := make(map[uint32]string, len(d.meterMap))
	for id, me := range d.meterMap {
		if me != nil && me.active {
			result[id] = me.name
		}
	}
	d.ctMtx.Unlock()

	return result
}
