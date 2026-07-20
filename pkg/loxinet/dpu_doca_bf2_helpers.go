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

// This file contains pure-Go helpers for the DOCA BF2 offload path that are
// build-tag agnostic (compile under both `doca` and `!doca`). Keeping them
// out of dpu_doca_bf2.go lets the `!doca` unit-test file exercise them on
// developer laptops without the DOCA toolchain.
//
// P47-R6 — cross-subnet next-hop ARP fix + proto filter helper.

package loxinet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	opts "github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// bf2TraceBidir gates the high-verbosity tracing added to debug
// bidirectional HW offload. Off by default (zero perf cost). Enable with:
//
//	BF2_TRACE_BIDIR=1 ./loxilb ...
//
// All trace lines use prefix "[bf2-trace]" so they can be grepped together.
var bf2TraceBidir = os.Getenv("BF2_TRACE_BIDIR") == "1"

// traceBidirEnabled reports whether bidir tracing is on. Cheap (read of a
// package-level bool); call sites should still wrap heavy formatting in
// `if traceBidirEnabled { }` to skip work entirely when off.
func traceBidirEnabled() bool { return bf2TraceBidir }

// uint32IPStr converts a network-order uint32 IP back to dotted-quad string
// for trace logs. Mirrors tk.IPtonl's inverse.
func uint32IPStr(ip uint32) string {
	b := make(net.IP, 4)
	b[0] = byte(ip)
	b[1] = byte(ip >> 8)
	b[2] = byte(ip >> 16)
	b[3] = byte(ip >> 24)
	return b.String()
}

// pairedFlowParamsTraceFields renders a pairedFlowParams as logrus.Fields for
// trace logging. Caller must have already verified traceBidirEnabled.
func pairedFlowParamsTraceFields(p *pairedFlowParams) logrus.Fields {
	return logrus.Fields{
		"match_dst":   fmt.Sprintf("%s:%d", uint32IPStr(p.matchDstIP), tk.Ntohs(p.matchDstPort)),
		"match_src":   fmt.Sprintf("%s:%d", uint32IPStr(p.matchSrcIP), tk.Ntohs(p.matchSrcPort)),
		"rewrite_dst": fmt.Sprintf("%s:%d", uint32IPStr(p.newDstIP), tk.Ntohs(p.newDstPort)),
		"rewrite_src": fmt.Sprintf("%s:%d", uint32IPStr(p.newSrcIP), tk.Ntohs(p.newSrcPort)),
		"src_mac":     net.HardwareAddr(p.newSrcMAC[:]).String(),
		"dst_mac":     net.HardwareAddr(p.newDstMAC[:]).String(),
		"fwd_port":    p.fwdPortID,
		"proto":       p.protoNum,
	}
}

// paired-offload sentinel errors. Returned from
// buildPairedFlowParams (and propagated by pairedLBFlowOffload) when ARP
// resolution misses on both the direct path and the FIB next-hop fallback.
// Connection stays on eBPF until next CT-scan retry.
var (
	errFwdARPMiss   = errors.New("phase51: forward ARP unresolvable after FIB fallback")
	errReplyARPMiss = errors.New("phase51: reply ARP unresolvable after FIB fallback")
)

// resolveFlowMACsFn is the indirection seam for unit tests. Production code
// calls resolveFlowMACsFn(d, ip) which delegates to d.resolveFlowMACs(ip);
// !doca tests overwrite this var with a spy that records call inputs so the
// invariants can be asserted without DOCA/netlink.
//
// Hot-path discipline: a single closure dispatch on the slow-path resolver —
// not on a per-packet path — is acceptable per RESEARCH §"Don't Hand-Roll".
var resolveFlowMACsFn = func(d *DpDocaBf2, ip net.IP) (uint16, [6]byte, [6]byte, bool) {
	return d.resolveFlowMACs(ip)
}

// pendingPair holds a half-or-full forward+reply CT pair awaiting paired DOCA dispatch.
// Lifecycle: created on first event, completed on second event,
// GC'd after 30s if only one direction ever arrives.
//
// Defined in the build-tag-agnostic helper file so unit tests under !doca can
// reference it directly without pulling in the DOCA toolchain.
type pendingPair struct {
	forward   *DpCtInfo
	reply     *DpCtInfo
	arrivedAt time.Time
}

// routeGetFn is the FIB walker used by nextHopForFlow.
// Wrapped in a package var so unit tests can inject a stub.
// Matches the pattern already used by pkg/loxinet/utils.go FindSysOifForHost.
var routeGetFn = netlink.RouteGet

// per-direction CT pipe seams. Test code may override
// these to install distinct fake pipe handles for forward vs reply
// paths and assert that pairedLBFlowOffload routes them correctly.
// Both seams are declared UNCONDITIONALLY in this build-tag-agnostic
// helpers file so the doca and !doca builds share the same indirection
// surface; the underlying DocaGetCTFwdPipe / DocaGetCTRevPipe selection
// (real CGO vs stub) is handled in dpu_doca_cgo.go / dpu_doca_cgo_stub.go.
// -06 (TX-2): renamed from docaGetCTPipeFn → docaGetCTFwdPipeFn
// in lockstep with the DocaGetCTPipe → DocaGetCTFwdPipe rename.
var docaGetCTFwdPipeFn = DocaGetCTFwdPipe
var docaGetCTRevPipeFn = DocaGetCTRevPipe

// nextHopForFlow returns the ARP-lookup target for a flow destination IP.
// For directly-attached destinations the FIB row carries no gateway (Gw == nil
// or IsUnspecified) and the flow's own destination is the correct ARP target.
// For cross-subnet destinations the FIB returns a non-zero Gw that MUST be
// used instead — ARP for the final host will never resolve because that host
// lives on a remote subnet reachable only via the gateway.
//
// On any FIB lookup error (netlink failure, no route) the function falls back
// to `dst`. The caller (RouteFlowOffload) treats a subsequent ARP miss as a
// benign "skip offload this round; eBPF handles it" condition.
//
// P47-R6 — fixes cross-subnet L3 offload.
func (d *DpDocaBf2) nextHopForFlow(dst net.IP) net.IP {
	if dst == nil {
		return dst
	}
	routes, err := routeGetFn(dst)
	if err != nil || len(routes) == 0 {
		logrus.WithFields(logrus.Fields{"dst": dst.String(), "err": err}).
			Debug("doca-bf2: nextHopForFlow FIB lookup missed — falling back to flow dst")
		return dst
	}
	gw := routes[0].Gw
	if gw == nil || gw.IsUnspecified() {
		// Direct-attached route — dst is on the oif's subnet.
		return dst
	}
	return gw
}

// pairOrDispatch slot-fills the pending-pair map with this CT event and, if both
// forward and reply are present, removes the entry from the map and dispatches
// the paired DOCA offload via pairedLBFlowOffload
//
// Slot extraction follows the snapshot-then-drain discipline: hold
// pairMu briefly to compute connKey + slot-fill + extract; release; THEN call
// pairedLBFlowOffload outside the mutex (DOCA submit must not run under
// pairMu, or the worker pthread self-deadlocks).
//
// Caller (goCtHwOffloadHandler) must already have verified d.bidirEnabled==true.
// Returns (paired, fwdKey, revKey) so the caller can populate dpuOffloadedFlows
// for both directions on success (— de-dup write deferred to success).
func (d *DpDocaBf2) pairOrDispatch(ct *DpCtInfo, lbMark int) (paired bool, fwdKey, revKey string) {
	if d == nil {
		return false, "", ""
	}
	key := connKeyFromEvent(ct)
	if key == "" {
		// Non-paired event (route CT, unknown NatFlags) — guard.
		return false, "", ""
	}

	if traceBidirEnabled() {
		logrus.WithFields(logrus.Fields{
			"connKey":  key,
			"natFlags": ct.NatFlags,
			"sip":      ct.SIP,
			"dip":      ct.DIP,
			"sport":    ct.Sport,
			"dport":    ct.Dport,
			"natIP":    ct.NatIP,
			"natRIP":   ct.NatRIP,
			"natPort":  ct.NatPort,
		}).Info("[bf2-trace] pairOrDispatch entry")
	}

	d.pairMu.Lock()
	if d.pendingPair == nil {
		d.pendingPair = make(map[string]*pendingPair)
	}
	slot, ok := d.pendingPair[key]
	if !ok {
		slot = &pendingPair{arrivedAt: time.Now()}
		d.pendingPair[key] = slot
	}
	switch ct.NatFlags {
	case 1, 3: // forward (DNAT, HDNAT)
		slot.forward = ct
	case 2, 4: // reply (SNAT, HSNAT)
		slot.reply = ct
	}
	var fwd, rev *DpCtInfo
	if slot.forward != nil && slot.reply != nil {
		fwd = slot.forward
		rev = slot.reply
		delete(d.pendingPair, key)
	}
	d.pairMu.Unlock()

	if fwd == nil || rev == nil {
		if traceBidirEnabled() {
			logrus.WithFields(logrus.Fields{
				"connKey":     key,
				"haveForward": slot.forward != nil,
				"haveReply":   slot.reply != nil,
			}).Info("[bf2-trace] pairOrDispatch HALF_PAIR — waiting for sibling")
		}
		return false, "", ""
	}

	if traceBidirEnabled() {
		logrus.WithField("connKey", key).
			Info("[bf2-trace] pairOrDispatch BOTH_PRESENT — dispatching paired offload")
	}

	if err := d.pairedLBFlowOffload(fwd, rev, lbMark); err != nil {
		if traceBidirEnabled() {
			logrus.WithError(err).WithField("connKey", key).
				Info("[bf2-trace] pairOrDispatch FAILED — staying on eBPF")
		}
		logrus.WithError(err).WithField("connKey", key).
			Debug("phase51: paired offload failed; staying on eBPF")
		return false, "", ""
	}
	if traceBidirEnabled() {
		logrus.WithFields(logrus.Fields{
			"connKey": key,
			"fwdKey":  fwd.Key(),
			"revKey":  rev.Key(),
		}).Info("[bf2-trace] pairOrDispatch SUCCESS")
	}
	return true, fwd.Key(), rev.Key()
}

// gcPendingPairs drops half-arrived pendingPair entries older than maxAge.
// Called from agingPollCycle (10s tick).
func (d *DpDocaBf2) gcPendingPairs(maxAge time.Duration) {
	if d == nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	d.pairMu.Lock()
	var dropped int
	for k, p := range d.pendingPair {
		if p.arrivedAt.Before(cutoff) {
			delete(d.pendingPair, k)
			dropped++
		}
	}
	d.pairMu.Unlock()
	if dropped > 0 {
		logrus.WithField("dropped", dropped).
			Debug("phase51: gcPendingPairs swept stale half-pairs")
	}
}

// pairedFlowParams holds the pre-computed match/rewrite/MAC/port values for
// one direction of a paired offload. Lives in the build-tag-agnostic helper
// file so the !doca unit tests reach it without the DOCA toolchain.
type pairedFlowParams struct {
	matchDstIP, matchSrcIP     uint32
	matchDstPort, matchSrcPort uint16
	newDstIP, newSrcIP         uint32
	newDstPort, newSrcPort     uint16
	newDstMAC, newSrcMAC       [6]byte
	fwdPortID                  uint16
	protoNum                   uint8
}

// buildPairedFlowParams computes match/rewrite/MAC/port params for one
// direction of a paired offload.
//
// `ct` is the per-direction CT (forward or reply); `fwd` is ALWAYS the
// forward-direction CT — required because the reply branch's ARP target is
// `fwd.SIP` (client IP), not the reply's own DIP. The DIP-based input
// today is the broken pattern that this plan replaces.
//
// logic per direction:
//
//	forward (forwardDir=true):
//	  ARP target = fwd.NatIP (backend IP) — same as today, correct.
//	  on direct miss, fall back to nextHopForFlow(fwd.NatIP) ONCE.
//
//	reply (forwardDir=false):
//
// ARP target = fwd.SIP (client IP) — architectural payload.
//   - DNAT: client is arpable on local subnet → resolves on direct call.
//   - OneArm/FullNAT: today's resolveFlowMACs(rev.DIP) targets loxilb-own-IP
//     (netlink does NOT return entries for the host's own IPs); using
//     fwd.SIP routes BOTH modes through the same uniform path.
//     on direct miss, fall back to nextHopForFlow(fwd.SIP) ONCE.
//
// Returns (params, err). On ARP miss after FIB fallback, returns
// errFwdARPMiss / errReplyARPMiss; caller propagates and the connection stays
// on eBPF (atomicity — neither direction is programmed).
//
// Build-tag-agnostic: !doca tests inject resolveFlowMACsFn / routeGetFn to
// exercise invariants without the DOCA toolchain.
func (d *DpDocaBf2) buildPairedFlowParams(ct, fwd *DpCtInfo, forwardDir bool) (pairedFlowParams, error) {
	var p pairedFlowParams
	if ct == nil || fwd == nil {
		return p, fmt.Errorf("phase51 buildPairedFlowParams: nil ct=%v fwd=%v", ct, fwd)
	}
	switch ct.Proto {
	case "tcp":
		p.protoNum = 6
	case "udp":
		p.protoNum = 17
	default:
		return p, fmt.Errorf("phase51 buildPairedFlowParams: unsupported proto %q", ct.Proto)
	}
	p.matchSrcIP = tk.IPtonl(ct.SIP)
	p.matchSrcPort = tk.Htons(ct.Sport)
	p.matchDstIP = tk.IPtonl(ct.DIP)
	p.matchDstPort = tk.Htons(ct.Dport)

	if forwardDir {
		// case 1,3 — DNAT/HDNAT origin direction.
		// DOCA template marks ALL fields changeable; pass-through preserves
		// non-NAT'd values. NatRIP override is the OneArm SNAT-to-VIP twist.
		p.newDstIP = tk.IPtonl(ct.NatIP)
		p.newDstPort = tk.Htons(ct.NatPort)
		p.newSrcIP = p.matchSrcIP
		p.newSrcPort = p.matchSrcPort
		if ct.NatRIP != nil && !ct.NatRIP.IsUnspecified() {
			p.newSrcIP = tk.IPtonl(ct.NatRIP)
		}
		// forward branch: direct call first; FIB fallback ONLY on miss.
		// The c15fd32 anti-pattern (always nextHopForFlow before resolve) is forbidden.
		if traceBidirEnabled() {
			logrus.WithFields(logrus.Fields{
				"dir":        "forward",
				"arp_target": fwd.NatIP,
			}).Info("[bf2-trace] buildParams forward ARP attempt")
		}
		portID, dstMAC, srcMAC, ok := resolveFlowMACsFn(d, fwd.NatIP)
		if !ok {
			gw := d.nextHopForFlow(fwd.NatIP)
			if traceBidirEnabled() {
				logrus.WithFields(logrus.Fields{
					"dir":        "forward",
					"arp_target": fwd.NatIP,
					"fib_gw":     gw,
				}).Info("[bf2-trace] buildParams forward ARP MISS — trying FIB fallback")
			}
			if gw == nil || gw.Equal(fwd.NatIP) {
				logrus.WithField("backend_ip", fwd.NatIP).
					Debug("phase51: forward ARP miss + no FIB gateway; staying on eBPF")
				return p, errFwdARPMiss
			}
			portID, dstMAC, srcMAC, ok = resolveFlowMACsFn(d, gw)
			if !ok {
				logrus.WithFields(logrus.Fields{"backend_ip": fwd.NatIP, "gw": gw}).
					Debug("phase51: forward ARP miss after FIB fallback; staying on eBPF")
				return p, errFwdARPMiss
			}
		}
		p.newDstMAC = dstMAC
		p.newSrcMAC = srcMAC
		p.fwdPortID = portID
		if traceBidirEnabled() {
			logrus.WithFields(logrus.Fields{
				"dir":        "forward",
				"arp_target": fwd.NatIP,
				"port_id":    portID,
				"dst_mac":    net.HardwareAddr(dstMAC[:]).String(),
				"src_mac":    net.HardwareAddr(srcMAC[:]).String(),
			}).Info("[bf2-trace] buildParams forward ARP RESOLVED")
			logrus.WithFields(pairedFlowParamsTraceFields(&p)).
				Info("[bf2-trace] buildParams forward FINAL params")
		}
		return p, nil
	}

	// case 2,4 — SNAT/HSNAT reply direction.
	p.newSrcIP = tk.IPtonl(ct.NatIP)
	p.newSrcPort = tk.Htons(ct.NatPort)
	p.newDstIP = p.matchDstIP
	p.newDstPort = p.matchDstPort
	if ct.NatRIP != nil && !ct.NatRIP.IsUnspecified() {
		p.newDstIP = tk.IPtonl(ct.NatRIP)
	}

	// === Reply MAC/port resolution ===
	//
	// ARP target = fwd.SIP (client IP), NOT rev.DIP.
	//   - DNAT: rev.DIP = client = arpable → today returns wrong port (route mismatch)
	//   - OneArm/FullNAT: rev.DIP = loxilb-own-IP → netlink ARP-miss (host's own IP)
	// - input: fwd.SIP = client = arpable on local subnet, returns
	//     client-facing DPDK port for ALL 3 modes uniformly.
	//
	// replyPortID is the client-facing DPDK port (resolveFlowMACs walks
	//   the ARP entry's LinkIndex → ifindexToPort map).
	//
	// FIB fallback ONLY when direct ARP misses. Same-subnet path is
	//   bit-for-bit identical to today's working OneArm/FullNAT forward path.
	//   The c15fd32 anti-pattern (always FIB-wrap, even on direct hit) is
	//   forbidden — see RESEARCH §"Anti-Patterns to Avoid (LANDMINES)" line 374.
	//
	// Both forward (above) and reply (here) MAC/port resolution happen
	//   inside pairedLBFlowOffload — symmetric pair-time. If either misses
	// after FIB fallback, return early; atomicity ensures no half-offload.
	if traceBidirEnabled() {
		logrus.WithFields(logrus.Fields{
			"dir":        "reply",
			"arp_target": fwd.SIP,
		}).Info("[bf2-trace] buildParams reply ARP attempt")
	}
	portID, dstMAC, srcMAC, ok := resolveFlowMACsFn(d, fwd.SIP)
	if !ok {
		gw := d.nextHopForFlow(fwd.SIP)
		if traceBidirEnabled() {
			logrus.WithFields(logrus.Fields{
				"dir":        "reply",
				"arp_target": fwd.SIP,
				"fib_gw":     gw,
			}).Info("[bf2-trace] buildParams reply ARP MISS — trying FIB fallback")
		}
		if gw == nil || gw.Equal(fwd.SIP) {
			logrus.WithField("client_ip", fwd.SIP).
				Debug("phase51: reply ARP miss + no FIB gateway; staying on eBPF")
			return p, errReplyARPMiss
		}
		portID, dstMAC, srcMAC, ok = resolveFlowMACsFn(d, gw)
		if !ok {
			logrus.WithFields(logrus.Fields{"client_ip": fwd.SIP, "gw": gw}).
				Debug("phase51: reply ARP miss after FIB fallback; staying on eBPF")
			return p, errReplyARPMiss
		}
	}
	p.newDstMAC = dstMAC
	p.newSrcMAC = srcMAC
	p.fwdPortID = portID
	if traceBidirEnabled() {
		logrus.WithFields(logrus.Fields{
			"dir":        "reply",
			"arp_target": fwd.SIP,
			"port_id":    portID,
			"dst_mac":    net.HardwareAddr(dstMAC[:]).String(),
			"src_mac":    net.HardwareAddr(srcMAC[:]).String(),
		}).Info("[bf2-trace] buildParams reply ARP RESOLVED")
		logrus.WithFields(pairedFlowParamsTraceFields(&p)).
			Info("[bf2-trace] buildParams reply FINAL params")
	}
	return p, nil
}

// PairOrDispatch implements PairOffloader
func (d *DpDocaBf2) PairOrDispatch(ct *DpCtInfo, lbMark int) (bool, string, string) {
	return d.pairOrDispatch(ct, lbMark)
}

// BidirEnabled implements PairOffloader
func (d *DpDocaBf2) BidirEnabled() bool {
	if d == nil {
		return false
	}
	return d.bidirEnabled
}

// connKeyFromEvent computes the canonical pairing key for a CT event.
// Both directions of a connection produce the same key because:
//   - RuleID: copied from atdat->ctd.rid in eBPF for BOTH events (llb_kern_ct.c).
//   - client_port: forward.Sport == reply.Dport (always, by 5-tuple symmetry).
//   - Proto: same string for both events.
//
// Returns "" for non-paired NatFlags values (route CT, etc.).
// Build-tag-agnostic so unit tests under !doca can exercise it
// without DOCA toolchain.
func connKeyFromEvent(ct *DpCtInfo) string {
	if ct == nil {
		return ""
	}
	var clientPort uint16
	switch ct.NatFlags {
	case 1, 3: // forward (DNAT, HDNAT)
		clientPort = ct.Sport
	case 2, 4: // reply (SNAT, HSNAT)
		clientPort = ct.Dport
	default:
		return ""
	}
	return fmt.Sprintf("rid=%d|cport=%d|proto=%s", ct.RuleID, clientPort, ct.Proto)
}

// protoNumForRouteOffload maps DpCtInfo.Proto string to the IP proto number
// accepted by the identity-rewrite CT offload path. Any proto where
// MAC rewrite + FWD_PORT is a valid DOCA action is eligible. Returns ok=false
// for protos that still must stay on the eBPF slow path (proto "none",
// unknown strings, or encapsulated L4 types we have not validated).
//
// P47-R6 — proto filter expansion.
func protoNumForRouteOffload(p string) (uint8, bool) {
	switch p {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "icmp":
		return 1, true
	case "sctp":
		return 132, true
	case "gre":
		return 47, true
	case "esp":
		return 50, true
	default:
		return 0, false
	}
}

// ---------------------------------------------------------------------------
// per-EP SHARED counter lifecycle skeleton.
// Gated by Glob.Doca.PerEpSharedCounters (default false) because no
// production BASIC pipe uses SHARED counters today (narrowing).
// Wiring into LBFlowOffload / LbEndPointRem is deferred to the first v6.x
// phase that introduces protocol-pipe SHARED counter pools.
// ---------------------------------------------------------------------------

// epSharedCounterKey is the in-memory key for the per-EP SHARED counter map.
// Format: "svc/ep" (matches the AllocSharedCounter scopeKey convention).
type epSharedCounterKey = string

// epSharedCounterEntry holds the allocated SHARED counter ID and a reference
// count so concurrent callers can share the same counter slot.
type epSharedCounterEntry struct {
	id     uint32
	refCnt int
}

// epSharedCounters is the per-DpDocaBf2 registry keyed by "svc/ep".
// Lazily initialised on first ensureEpSharedCounter call.
type epSharedCounterRegistry struct {
	mu      sync.Mutex
	entries map[epSharedCounterKey]*epSharedCounterEntry
}

// epCounterRegistries stores per-DpDocaBf2-instance registries.
// Using a sync.Map keyed by *DpDocaBf2 avoids adding a field to DpDocaBf2
// directly (which would require changes to the CGO-linked struct in doca build).
var epCounterRegistries sync.Map // key: *DpDocaBf2, value: *epSharedCounterRegistry

// getEpCounterRegistry returns (creating if needed) the per-instance registry.
func getEpCounterRegistry(d *DpDocaBf2) *epSharedCounterRegistry {
	if v, ok := epCounterRegistries.Load(d); ok {
		return v.(*epSharedCounterRegistry)
	}
	reg := &epSharedCounterRegistry{
		entries: make(map[epSharedCounterKey]*epSharedCounterEntry),
	}
	actual, _ := epCounterRegistries.LoadOrStore(d, reg)
	return actual.(*epSharedCounterRegistry)
}

// ensureEpSharedCounter lazily allocates a SHARED counter ID for the given
// (svc, ep) pair via d.AllocSharedCounter and stores it in the per-instance
// registry. Returns the existing ID on re-registration to preserve Prometheus
// label-set continuity. Thread-safe.
//
// Gate: returns (0, nil) immediately when Glob.Doca.PerEpSharedCounters == false.
//
// NOT wired into LBFlowOffload / LbEndPointRem — the skeleton
// is forward-compat only narrowing. Wiring activates when a future
// v6.x phase introduces protocol-pipe SHARED pools.
func (d *DpDocaBf2) ensureEpSharedCounter(svc, ep string) (uint32, error) {
	if !opts.Opts.DocaPerEpSharedCounters {
		// Feature gate is off: no SHARED counters on BASIC pipes today.
		return 0, nil
	}

	reg := getEpCounterRegistry(d)
	key := epSharedCounterKey(svc + "/" + ep)

	reg.mu.Lock()
	defer reg.mu.Unlock()

	if e, exists := reg.entries[key]; exists {
		e.refCnt++
		return e.id, nil
	}

	id, err := d.AllocSharedCounter(key)
	if err != nil {
		return 0, fmt.Errorf("ensureEpSharedCounter(%s, %s): AllocSharedCounter failed: %w", svc, ep, err)
	}

	reg.entries[key] = &epSharedCounterEntry{id: id, refCnt: 1}
	return id, nil
}

// releaseEpSharedCounter decrements the reference count for the given (svc, ep)
// pair. When the reference count reaches zero it calls d.FreeSharedCounter and
// removes the entry from the registry. Thread-safe.
//
// Gate: returns immediately when Glob.Doca.PerEpSharedCounters == false.
func (d *DpDocaBf2) releaseEpSharedCounter(svc, ep string) {
	if !opts.Opts.DocaPerEpSharedCounters {
		return
	}

	reg := getEpCounterRegistry(d)
	key := epSharedCounterKey(svc + "/" + ep)

	reg.mu.Lock()
	defer reg.mu.Unlock()

	e, exists := reg.entries[key]
	if !exists {
		return
	}

	e.refCnt--
	if e.refCnt <= 0 {
		d.FreeSharedCounter(e.id)
		delete(reg.entries, key)
	}
}
