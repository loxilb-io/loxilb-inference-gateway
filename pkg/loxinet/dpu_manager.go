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
	"errors"
	"sync"
	"sync/atomic"

	"github.com/loxilb-io/loxilb/api/restapi/handler"
	// logrus is used in Shadow* methods below
	"github.com/sirupsen/logrus"
)

// gracefulShutdowner is an optional capability implemented by plugins that
// support a ctx-bounded graceful shutdown. — only
// the BF2 DOCA plugin implements it today; other plugins fall back to the
// existing fire-and-forget DpuPlugin.Shutdown contract via DpuManager
// Shutdown(ctx)'s default branch.
type gracefulShutdowner interface {
	ShutdownCtx(ctx context.Context) error
}

// flowStatsProvider is implemented by plugins that support per-flow HW counter queries.
type flowStatsProvider interface {
	AllFlowStats() []FlowHwStats
}

// multiPipeStatsProvider is an optional interface implemented by plugins that
// can report per-pipe HW counters (FDB / Route / ACL). Parallels flowStatsProvider
// (CT/LB). Unexported so it is not part of the vendor-plugin contract — plugins
// that don't implement it are simply skipped during aggregation.
type multiPipeStatsProvider interface {
	AllFdbStats() []FdbHwStats
	AllRouteStats() []RouteHwStats
	AllAclStats() []AclHwStats
}

// lbFlowOffloadPipeKinder lets plugins that CAN distinguish TCP vs UDP CT pipes
// report the pipeKind back to the manager. Optional — plugins without this method
// fall back to pipeKind inference from DpCtInfo.Proto.
type lbFlowOffloadPipeKinder interface {
	LBFlowOffloadWithPipeKind(ct *DpCtInfo, lbMark int) (pipeKind, error)
}

// circuitBreakerProvider is implemented by plugins that guard offload with a
// circuit breaker (today only doca-bf2). Discovered via type assertion so
// non-CB plugins keep working without a forced no-op implementation. The
// handler.DpuDebugProvider surfaces CB state through /dpu/debug so CICD
// scripts (Scenario C degraded-path benchmark) can observe and drive it.
type circuitBreakerProvider interface {
	CircuitBreakerOpen() bool
	CircuitBreakerForce(mode string) error
}

// inferLBPipeKind maps DpCtInfo.Proto (string, e.g. "tcp"|"udp") to pipeKind
// for plugins that do not implement the pipeKinder optional interface.
// Unknown protos default to pipeCT (TCP).
func inferLBPipeKind(ct *DpCtInfo) pipeKind {
	if ct != nil && ct.Proto == "udp" {
		return pipeUDPCT
	}
	return pipeCT
}

// pipeKind identifies which DOCA pipe family a Shadow*Offload call targets.
// Bounded to 5 values (compile-time _Static_assert equivalent via pipeMax) so per-pipe
// counter arrays can be indexed directly without map locks.
// Stable index order locked by pipeKindNames — adding a new pipe requires bumping BOTH
// the enum AND the pipeKindNames array AND any fixed-size arrays indexed by it.
type pipeKind uint8

const (
	pipeCT    pipeKind = iota // TCP CT pipe (includes LB NAT)
	pipeUDPCT                 // UDP CT pipe
	pipeRoute                 // Pure-L3 routed flow (CT-path; P48 postponed)
	pipeFDB                   // L2 FDB pipe
	pipeACL                   // ACL/firewall BASIC pipe
	pipeMax                   // sentinel — MUST be last
)

// pipeKindNames maps pipeKind to stable string labels used in Prometheus and REST.
// Order matches the iota values above. These strings are the public API — changing
// them breaks Grafana dashboards and CICD scrape assertions.
var pipeKindNames = [pipeMax]string{
	"ct",     // pipeCT
	"udp_ct", // pipeUDPCT
	"route",  // pipeRoute
	"fdb",    // pipeFDB
	"acl",    // pipeACL
}

// DpuManager coordinates DPU plugin registration, capability queries,
// and offload dispatch. All Shadow* methods are fire-and-forget:
// they log errors but never return them to callers (graceful degradation).
type DpuManager struct {
	plugins        []DpuPlugin
	mtx            sync.RWMutex
	enabled        bool
	offloaded      sync.Map      // flow tracking: key=flow tuple string, value=offload info
	offloadSuccess atomic.Uint64 // legacy scalar — sum across pipes (total successful offloads)
	offloadFailure atomic.Uint64 // legacy scalar — sum across pipes (total failed offload attempts)
	offloadActive  atomic.Int64  // legacy scalar — sum across pipes (currently active offloaded flows)

	// P49-R2: per-pipe breakdown. Fixed-size arrays indexed by pipeKind
	// (not maps) — lock-free, compile-time bounds check. Updated exclusively via
	// RecordOffload so legacy scalars and per-pipe arrays stay in lockstep.
	offloadSuccessByPipe [pipeMax]atomic.Uint64
	offloadFailureByPipe [pipeMax]atomic.Uint64
	offloadActiveByPipe  [pipeMax]atomic.Int64
}

// DpuManagerInit creates a new DpuManager with no plugins registered.
func DpuManagerInit() *DpuManager {
	return &DpuManager{
		plugins: make([]DpuPlugin, 0),
		enabled: false,
	}
}

// Compile-time assertion: the dpuDebugProviderAdapter (defined in
// dpu_debug_adapter.go) MUST satisfy the extended handler.DpuDebugProvider
// interface. If a future refactor drops one of the per-pipe-family methods
// or changes a signature, the build breaks here — threat
// (silent back-compat drift) is blocked before tests run.
var _ handler.DpuDebugProvider = (*dpuDebugProviderAdapter)(nil)

// Register adds a DPU plugin to the manager and enables offload dispatch.
func (m *DpuManager) Register(p DpuPlugin) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	// D5 gating: the doca_*/loxilb_acl_hw_* metric families are only exposed
	// once a DPU plugin actually attaches.
	registerDpuMetrics()
	m.plugins = append(m.plugins, p)
	m.enabled = true
	logrus.WithFields(logrus.Fields{
		"plugin":       p.Name(),
		"capabilities": p.Capabilities(),
	}).Info("DPU plugin registered")
}

// IsEnabled returns true if at least one plugin is registered.
func (m *DpuManager) IsEnabled() bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	return m.enabled
}

// Shutdown is the ctx-bounded graceful shutdown for the layered shutdown
// sequencer. For each registered plugin that
// implements gracefulShutdowner (today: only the BF2 DOCA plugin), the
// plugin's ShutdownCtx is invoked with the supplied ctx. Plugins that
// only implement the legacy DpuPlugin.Shutdown contract are SKIPPED
// here (they will be torn down later in the eBPF stage / process exit)
// because the legacy contract has no ctx and could block past the
// 2-second DOCA-stage budget.
//
// Returns the FIRST non-nil error encountered (so the operator sees a
// representative failure in the stage log) but always attempts every
// plugin. The runShutdownStage helper above bounds the wall time
// regardless.
func (m *DpuManager) Shutdown(ctx context.Context) error {
	m.mtx.RLock()
	plugins := make([]DpuPlugin, len(m.plugins))
	copy(plugins, m.plugins)
	m.mtx.RUnlock()

	var firstErr error
	for _, p := range plugins {
		select {
		case <-ctx.Done():
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			return firstErr
		default:
		}
		gs, ok := p.(gracefulShutdowner)
		if !ok {
			// Legacy plugin without ctx-aware shutdown: skip — handled
			// by process exit / eBPF stage cleanup.
			continue
		}
		if err := gs.ShutdownCtx(ctx); err != nil {
			logrus.WithFields(logrus.Fields{
				"plugin": p.Name(),
				"error":  err,
			}).Warn("DPU plugin graceful shutdown error")
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// ShutdownAll shuts down all registered plugins.
func (m *DpuManager) ShutdownAll() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for _, p := range m.plugins {
		if err := p.Shutdown(); err != nil {
			logrus.WithFields(logrus.Fields{
				"plugin": p.Name(),
				"error":  err,
			}).Warn("DPU plugin shutdown error")
		}
	}
	m.plugins = m.plugins[:0]
	m.enabled = false
}

// Unregister removes a plugin by name, calls Shutdown, and disables if no plugins remain.
func (m *DpuManager) Unregister(name string) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	for i, p := range m.plugins {
		if p.Name() == name {
			if err := p.Shutdown(); err != nil {
				logrus.WithFields(logrus.Fields{
					"plugin": name,
					"error":  err,
				}).Warn("DPU plugin shutdown error during unregister")
			}
			m.plugins = append(m.plugins[:i], m.plugins[i+1:]...)
			if len(m.plugins) == 0 {
				m.enabled = false
			}
			logrus.WithField("plugin", name).Warn("DPU plugin unregistered")
			return
		}
	}
}

// PluginNames returns the names of all registered plugins.
func (m *DpuManager) PluginNames() []string {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	names := make([]string, 0, len(m.plugins))
	for _, p := range m.plugins {
		names = append(names, p.Name())
	}
	return names
}

// OffloadStats returns the current offload debug counters.
func (m *DpuManager) OffloadStats() (success, failure uint64, active int64) {
	return m.offloadSuccess.Load(), m.offloadFailure.Load(), m.offloadActive.Load()
}

// RecordOffload atomically updates both the legacy scalar counters and the per-pipe
// arrays for a single offload attempt. Intended as the ONLY write site for these
// counters — all Shadow*Offload handlers call it to keep legacy and per-pipe views
// consistent.
//
// err==nil -> success path: success++ (scalar + per-pipe), active++ (scalar + per-pipe).
// err!=nil -> failure path: failure++ (scalar + per-pipe). active is NOT decremented
//
//	on failure because the entry was never added.
//
// pk must be a valid pipeKind (< pipeMax). Invalid pk is silently ignored so a future
// pipe enum extension that lands without a full Shadow* update does not crash.
func (m *DpuManager) RecordOffload(pk pipeKind, err error) {
	if pk >= pipeMax {
		return
	}
	if err != nil {
		m.offloadFailure.Add(1)
		m.offloadFailureByPipe[pk].Add(1)
		return
	}
	m.offloadSuccess.Add(1)
	m.offloadSuccessByPipe[pk].Add(1)
	m.offloadActive.Add(1)
	m.offloadActiveByPipe[pk].Add(1)
}

// RecordOffloadRemove decrements the active counter (scalar + per-pipe) when an
// offloaded entry is torn down. Called from ShadowLBFlowRemove / ShadowFdbFlowRemove /
// ShadowFwRuleDel. No-op on pk >= pipeMax.
func (m *DpuManager) RecordOffloadRemove(pk pipeKind) {
	if pk >= pipeMax {
		return
	}
	m.offloadActive.Add(-1)
	m.offloadActiveByPipe[pk].Add(-1)
}

// OffloadStatsByPipe returns per-pipe counter snapshots for the new REST schema
// (P49-R1 offload_success_by_pipe / offload_failure_by_pipe / offload_active_by_pipe).
// The returned maps always contain all 5 pipe keys (ct, udp_ct, route, fdb, acl).
// The active map additionally contains a synthetic "total" key equal to the sum —
// this matches the top-level scalar offload_active for consistency and doubles as
// a self-test during golden-file schema assertions.
func (m *DpuManager) OffloadStatsByPipe() (success map[string]uint64, failure map[string]uint64, active map[string]int64) {
	success = make(map[string]uint64, pipeMax)
	failure = make(map[string]uint64, pipeMax)
	active = make(map[string]int64, pipeMax+1)
	var total int64
	for i := pipeKind(0); i < pipeMax; i++ {
		name := pipeKindNames[i]
		success[name] = m.offloadSuccessByPipe[i].Load()
		failure[name] = m.offloadFailureByPipe[i].Load()
		v := m.offloadActiveByPipe[i].Load()
		active[name] = v
		total += v
	}
	active["total"] = total
	return success, failure, active
}

// CircuitBreakerOpen returns true if ANY registered plugin that implements
// circuitBreakerProvider reports its offload circuit breaker as tripped.
// Plugins without a CB (e.g. pure eBPF build) contribute false. Surfaced
// through /netlox/v1/config/dpu/debug.circuit_breaker_open.
func (m *DpuManager) CircuitBreakerOpen() bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if cbp, ok := p.(circuitBreakerProvider); ok && cbp.CircuitBreakerOpen() {
			return true
		}
	}
	return false
}

// CircuitBreakerForce applies a test-only force-open or force-close override
// to every CB-capable plugin. mode is "open" or "close". A build with no
// CB-capable plugin is a benign no-op (returns nil). Reachable only via the
// debug REST endpoint — CICD scripts call it from the Scenario C path.
func (m *DpuManager) CircuitBreakerForce(mode string) error {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if cbp, ok := p.(circuitBreakerProvider); ok {
			if err := cbp.CircuitBreakerForce(mode); err != nil {
				return err
			}
		}
	}
	return nil
}

// AllFlowHwStats queries hardware counters for all offloaded flows across all plugins.
func (m *DpuManager) AllFlowHwStats() []handler.FlowHwStatsEntry {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	var results []handler.FlowHwStatsEntry
	for _, p := range m.plugins {
		if fsp, ok := p.(flowStatsProvider); ok {
			for _, fs := range fsp.AllFlowStats() {
				results = append(results, handler.FlowHwStatsEntry{
					FlowKey: fs.FlowKey,
					PipeKey: fs.PipeKey,
					HwBytes: fs.HwBytes,
					HwPkts:  fs.HwPkts,
				})
			}
		}
	}
	return results
}

// AllFdbHwStats aggregates per-FDB-entry HW counters across all plugins that
// implement multiPipeStatsProvider. Returns nil if manager disabled.
// (REST schema) consumes this directly and converts to handler.*Entry
// row types at the handler boundary — do NOT add an -Internal suffix here;
// the naming contract across Plans 03/04/05 is locked (see 49-03 plan frontmatter).
func (m *DpuManager) AllFdbHwStats() []FdbHwStats {
	if !m.enabled {
		return nil
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	var all []FdbHwStats
	for _, p := range m.plugins {
		if msp, ok := p.(multiPipeStatsProvider); ok {
			all = append(all, msp.AllFdbStats()...)
		}
	}
	return all
}

// AllRouteHwStats aggregates per-routed-flow HW counters across plugins.
// (full FIB LPM) is postponed — BF2 reports CT-path routed flows
// landed by RouteFlowOffload with pipeKey=="route".
func (m *DpuManager) AllRouteHwStats() []RouteHwStats {
	if !m.enabled {
		return nil
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	var all []RouteHwStats
	for _, p := range m.plugins {
		if msp, ok := p.(multiPipeStatsProvider); ok {
			all = append(all, msp.AllRouteStats()...)
		}
	}
	return all
}

// AllAclHwStats aggregates ACL rule per-entry HW counters across plugins.
// All offloaded rules are deny/DROP (BF2 only offloads proto=0 IPv4 deny).
func (m *DpuManager) AllAclHwStats() []AclHwStats {
	if !m.enabled {
		return nil
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	var all []AclHwStats
	for _, p := range m.plugins {
		if msp, ok := p.(multiPipeStatsProvider); ok {
			all = append(all, msp.AllAclStats()...)
		}
	}
	return all
}

// QueryDocaEntries implements filtered per-entry detail query for the REST debug endpoint.
// Delegates to the first DpDocaBf2 plugin found; returns nil if none registered.
func (m *DpuManager) QueryDocaEntries(pipeName, svc, ep string, limit int) []DocaEntryRow {
	if !m.enabled {
		return nil
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if bf2, ok := p.(*DpDocaBf2); ok {
			return bf2.QueryDocaEntries(pipeName, svc, ep, limit)
		}
	}
	return nil
}

// ReconcileCtFlowStats implements lazy-on-read CT reconciliation for the REST handler.
// Delegates to the first DpDocaBf2 plugin found. On !doca builds or when no plugin is
// registered, the stub ReconcileCtStats returns ReconciledStats{OffloadState: OffloadNone}
// which is the correct eBPF-only path.
// correction: total = eBPF (monotonic) + DOCA HW; no reset on offload.
// contract: MUST NOT fail — bridge errors treat HW count as zero (error counter bumped).
func (m *DpuManager) ReconcileCtFlowStats(ct *DpCtInfo) ReconciledStats {
	if !m.enabled || ct == nil {
		return ReconciledStats{OffloadState: OffloadNone}
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if bf2, ok := p.(*DpDocaBf2); ok {
			return bf2.ReconcileCtStats(ct)
		}
	}
	// No DpDocaBf2 plugin registered: eBPF-only path, no HW counters.
	return ReconciledStats{
		Pkts:         ct.Packets,
		Bytes:        ct.Bytes,
		OffloadState: OffloadNone,
	}
}

// ShadowLBFlowOffload dispatches LB flow offload to all plugins with LBOffload capability.
// Returns the last error encountered (nil if all succeeded or no plugins matched).
// -03: error return enables retry enqueue in goCtHwOffloadHandler.
// -01: routes counter updates through RecordOffload so per-pipe
// (pipeCT vs pipeUDPCT) breakdown stays in lockstep with legacy scalars.
func (m *DpuManager) ShadowLBFlowOffload(ct *DpCtInfo, lbMark int) error {
	if !m.enabled {
		return nil
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	var lastErr error
	for _, p := range m.plugins {
		if !p.Capabilities().LBOffload {
			continue
		}
		var (
			pk  pipeKind
			err error
		)
		if pkf, ok := p.(lbFlowOffloadPipeKinder); ok {
			pk, err = pkf.LBFlowOffloadWithPipeKind(ct, lbMark)
		} else {
			err = p.LBFlowOffload(ct, lbMark)
			pk = inferLBPipeKind(ct)
		}
		m.RecordOffload(pk, err)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"plugin": p.Name(),
				"error":  err,
			}).Warn("DPU LBFlowOffload failed")
			lastErr = err
		}
	}
	return lastErr
}

// PairOffloader is the optional capability for plugins implementing
// bidirectional paired CT offload. DpDocaBf2 implements this; other plugins
// (future vendors) can omit and fall back to ShadowLBFlowOffload.
//
// PairOrDispatch returns (paired, fwdKey, revKey) so the caller (eBPF dispatcher
// in goCtHwOffloadHandler) can populate dpuOffloadedFlows for both directions
// only AFTER the paired DOCA add succeeds (— de-dup write deferred).
type PairOffloader interface {
	PairOrDispatch(ct *DpCtInfo, lbMark int) (paired bool, fwdKey, revKey string)
	BidirEnabled() bool
}

// GetBidirEnabled reports whether ANY plugin has bidir mode on.
// The eBPF dispatcher uses this to gate the new path.
func (m *DpuManager) GetBidirEnabled() bool {
	if !m.enabled {
		return false
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if pp, ok := p.(PairOffloader); ok && pp.BidirEnabled() {
			return true
		}
	}
	return false
}

// ShadowPairOrDispatch routes a CT est event through any plugin implementing
// PairOffloader. If NO plugin implements it (e.g., a non-BF2 vendor plugin
// ships in the future), this method falls through to legacy per-direction
// offload via ShadowLBFlowOffload — preserving today's behavior unchanged.
// Resolves Open Question #4 (RESEARCH RESOLVED).
//
// Returns (paired, fwdKey, revKey) on success so the caller (goCtHwOffloadHandler)
// populates dpuOffloadedFlows for BOTH directions only after the paired DOCA
// add succeeds (— de-dup write deferred to success).
func (m *DpuManager) ShadowPairOrDispatch(ct *DpCtInfo, lbMark int) (paired bool, fwdKey, revKey string) {
	if !m.enabled {
		return false, "", ""
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	anyPaired := false
	for _, p := range m.plugins {
		if pp, ok := p.(PairOffloader); ok && pp.BidirEnabled() {
			done, fk, rk := pp.PairOrDispatch(ct, lbMark)
			anyPaired = true
			if done {
				return true, fk, rk
			}
		}
	}
	if !anyPaired {
		// No plugin supports paired offload — fall through to legacy path so
		// non-BF2 vendor plugins keep working. The caller has already gated
		// on GetBidirEnabled, so this branch handles the case where the bidir
		// flag was momentarily on but no plugin advertised the capability.
		_ = m.ShadowLBFlowOffload(ct, lbMark)
	}
	return false, "", ""
}

// ShadowLBFlowRemove dispatches LB flow remove to all plugins with LBOffload capability.
// -01: decrements active-flow counter (scalar + per-pipe) on successful removal.
func (m *DpuManager) ShadowLBFlowRemove(ct *DpCtInfo) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if !p.Capabilities().LBOffload {
			continue
		}
		if err := p.LBFlowRemove(ct); err != nil {
			logrus.WithFields(logrus.Fields{
				"plugin": p.Name(),
				"error":  err,
			}).Warn("DPU LBFlowRemove failed")
			continue
		}
		m.RecordOffloadRemove(inferLBPipeKind(ct))
	}
}

// ShadowRouteAdd dispatches route add to all plugins with CTRouteOffload capability.
func (m *DpuManager) ShadowRouteAdd(w *RouteDpWorkQ) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if p.Capabilities().CTRouteOffload {
			if err := p.RouteAdd(w); err != nil {
				logrus.WithFields(logrus.Fields{
					"plugin": p.Name(),
					"error":  err,
				}).Warn("DPU RouteAdd failed")
			}
		}
	}
}

// ShadowRouteDel dispatches route delete to all plugins with CTRouteOffload capability.
func (m *DpuManager) ShadowRouteDel(w *RouteDpWorkQ) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if p.Capabilities().CTRouteOffload {
			if err := p.RouteDel(w); err != nil {
				logrus.WithFields(logrus.Fields{
					"plugin": p.Name(),
					"error":  err,
				}).Warn("DPU RouteDel failed")
			}
		}
	}
}

// ShadowRouteFlowOffload dispatches non-NAT CT entry offload to all plugins with CTRouteOffload capability.
// Called from goCtHwOffloadHandler when an established flow has NatFlags==0 (pure routing/switching).
// Returns the last error encountered (nil if all succeeded or no plugins matched).
// -03: error return enables retry enqueue in goCtHwOffloadHandler.
// -01: fixes latent counter gap — success path previously never bumped
// m.offloadSuccess. Now routes through RecordOffload(pipeRoute, err) on both
// success and failure.
func (m *DpuManager) ShadowRouteFlowOffload(ct *DpCtInfo, rid int) error {
	if !m.enabled {
		return nil
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	var lastErr error
	for _, p := range m.plugins {
		if !p.Capabilities().CTRouteOffload {
			continue
		}
		err := p.RouteFlowOffload(ct, rid)
		m.RecordOffload(pipeRoute, err) // fix missing success bump
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"plugin": p.Name(),
				"error":  err,
			}).Warn("DPU RouteFlowOffload failed")
			lastErr = err
		}
	}
	return lastErr
}

// EnqueueRetry dispatches a failed offload to the retry queue of BF2 plugins.
// Called from goCtHwOffloadHandler when ShadowLBFlowOffload or ShadowRouteFlowOffload
// fails with a transient DOCA error.
func (m *DpuManager) EnqueueRetry(flowKey string, ct *DpCtInfo, isLB bool) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if bf2, ok := p.(*DpDocaBf2); ok {
			bf2.EnqueueRetry(flowKey, ct, isLB)
		}
	}
}

// ShadowFwRuleAdd dispatches firewall rule add to all plugins with ACLOffload capability.
// -01: fixes latent counter gap — previously bumped no counters at all.
// Now routes through RecordOffload(pipeACL, err) on both success and failure.
func (m *DpuManager) ShadowFwRuleAdd(w *FwDpWorkQ) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if !p.Capabilities().ACLOffload {
			continue
		}
		err := p.FwRuleAdd(w)
		m.RecordOffload(pipeACL, err) // close latent gap
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"plugin": p.Name(),
				"error":  err,
			}).Warn("DPU FwRuleAdd failed")
		}
	}
}

// ShadowFwRuleDel dispatches firewall rule delete to all plugins with ACLOffload capability.
// -01: decrements active-flow counter (scalar + per-pipe) on successful removal.
// treat ErrFwRuleNotOffloaded as a no-op (rule was never HW-installed,
// counter underflow prevention).
func (m *DpuManager) ShadowFwRuleDel(w *FwDpWorkQ) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if !p.Capabilities().ACLOffload {
			continue
		}
		if err := p.FwRuleDel(w); err != nil {
			if errors.Is(err, ErrFwRuleNotOffloaded) {
				// Rule was never in HW — skip RecordOffloadRemove to keep
				// offload_active_by_pipe.acl symmetric with the (skipped)
				// RecordOffload on the failed ShadowFwRuleAdd. No warn log;
				// this is expected when an Add silently fails at silicon.
				continue
			}
			logrus.WithFields(logrus.Fields{
				"plugin": p.Name(),
				"error":  err,
			}).Warn("DPU FwRuleDel failed")
			continue
		}
		m.RecordOffloadRemove(pipeACL)
	}
}

// ShadowPolAdd dispatches policer/meter add to all plugins with MeterOffload capability.
func (m *DpuManager) ShadowPolAdd(w *PolDpWorkQ) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if p.Capabilities().MeterOffload {
			if err := p.MeterAdd(w); err != nil {
				logrus.WithFields(logrus.Fields{
					"plugin":   p.Name(),
					"meter_id": w.Mark,
					"error":    err,
				}).Warn("DPU MeterAdd failed")
			}
		}
	}
}

// ShadowPolDel dispatches policer/meter delete to all plugins with MeterOffload capability.
func (m *DpuManager) ShadowPolDel(w *PolDpWorkQ) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if p.Capabilities().MeterOffload {
			if err := p.MeterDel(w); err != nil {
				logrus.WithFields(logrus.Fields{
					"plugin":   p.Name(),
					"meter_id": w.Mark,
					"error":    err,
				}).Warn("DPU MeterDel failed")
			}
		}
	}
}

// CollectMeterStats queries DOCA meter stats from all plugins with MeterOffload capability.
// Called from PolTicker periodically. All CGO calls go through DocaBridge.submit.
func (m *DpuManager) CollectMeterStats() {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if !p.Capabilities().MeterOffload {
			continue
		}
		bf2, ok := p.(*DpDocaBf2)
		if !ok {
			continue
		}
		meters := bf2.ActiveMeters()
		for meterID, name := range meters {
			stats, err := bf2.QueryMeterStats(meterID)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"meter_id": meterID,
					"error":    err,
				}).Debug("DPU meter stats query failed")
				continue
			}
			UpdateMeterStats(meterID, name, stats.TotalPkts, stats.TotalBytes)
		}
	}
}

// ShadowFdbFlowOffload dispatches FDB MAC offload to all plugins with L2Switching capability.
// -01: fixes latent counter gap — previously bumped no counters at all.
// Now routes through RecordOffload(pipeFDB, err) on both success and failure.
func (m *DpuManager) ShadowFdbFlowOffload(fdb *FdbEnt) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if !p.Capabilities().L2Switching {
			continue
		}
		err := p.FdbFlowOffload(fdb)
		m.RecordOffload(pipeFDB, err) // close latent gap
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"plugin": p.Name(),
				"error":  err,
			}).Debug("DPU FdbFlowOffload failed")
		}
	}
}

// ShadowFdbFlowRemove dispatches FDB MAC removal to all plugins with L2Switching capability.
// -01: decrements active-flow counter (scalar + per-pipe) on successful removal.
func (m *DpuManager) ShadowFdbFlowRemove(fdb *FdbEnt) {
	if !m.enabled {
		return
	}
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	for _, p := range m.plugins {
		if !p.Capabilities().L2Switching {
			continue
		}
		if err := p.FdbFlowRemove(fdb); err != nil {
			logrus.WithFields(logrus.Fields{
				"plugin": p.Name(),
				"error":  err,
			}).Debug("DPU FdbFlowRemove failed")
			continue
		}
		m.RecordOffloadRemove(pipeFDB)
	}
}
