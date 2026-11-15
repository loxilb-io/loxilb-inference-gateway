/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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
	"fmt"
	"os"
	"strconv"
	"strings"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
)

// fcRuleCfg is a rule's declared admission gate beyond the queue pair, as
// stored and as sent to the data plane: 0 on any field runs on the process
// environment or the product default, which the data plane resolves.
type fcRuleCfg struct {
	mode               uint8 // cmn.FcRuleMode*
	maxOutstanding     uint32
	epMaxInflight      uint32
	prefillMaxInflight uint32
	decodeMaxInflight  uint32
	telemetryStaleMs   uint32
	adaptive           uint8 // cmn.FcRuleAdaptive*
	warmupMs           uint32
	ttftTargetMs       uint32
	tenantSharePct     uint32
	exposeHeaders      uint8 // cmn.FcRuleAdaptive* encoding, enum fc_rule_expose
	// The priority bands. Triples are indexed by band (cmn.FcBand*); the
	// numeric knobs have no environment value, 0 is none.
	wakePolicy         uint8 // cmn.FcRuleWake*
	bandWeight         [cmn.FcBands]uint32
	bandMinSharePct    [cmn.FcBands]uint32
	criticalReservePct uint32
	bandWaitMs         [cmn.FcBands]uint32
	bandQueuePct       [cmn.FcBands]uint32
	shedQueue          uint8 // cmn.FcRuleAdaptive* encoding, enum fc_rule_switch
	tenantWake         uint8 // cmn.FcRuleTenantWake*
	llmdHeaders        uint8 // cmn.FcRuleAdaptive* encoding, enum fc_rule_switch
}

// fcRuleResolve returns the gate declaration a rule will store: on create
// the request's values, on a replace each field merged with the stored one
// (an omitted field keeps it; a present one, zero, "0:0:0" or "inherit"
// included, replaces it). The rules that span the band knobs are judged on
// the merged declaration.
func fcRuleResolve(eRule *ruleEnt, serv *cmn.LbServiceArg) (fcRuleCfg, error) {
	mode, err := cmn.FcModeToRule(serv.FcMode)
	if err != nil {
		return fcRuleCfg{}, err
	}
	adaptive, err := cmn.FcAdaptiveToRule(serv.FcAdaptive)
	if err != nil {
		return fcRuleCfg{}, err
	}
	expose, err := cmn.FcExposeHeadersToRule(serv.FcExposeHeaders)
	if err != nil {
		return fcRuleCfg{}, err
	}
	next := fcRuleCfg{
		mode:               mode,
		maxOutstanding:     serv.FcMaxOutstanding,
		epMaxInflight:      serv.FcEpMaxInflight,
		prefillMaxInflight: serv.FcPrefillMaxInflight,
		decodeMaxInflight:  serv.FcDecodeMaxInflight,
		telemetryStaleMs:   serv.FcTelemetryStaleMs,
		adaptive:           adaptive,
		warmupMs:           serv.FcWarmupMs,
		ttftTargetMs:       serv.FcTtftTargetMs,
		tenantSharePct:     serv.FcTenantMaxSharePct,
		exposeHeaders:      expose,
	}
	if eRule != nil {
		cur := eRule.fcCfg
		if !serv.FcModePresent && serv.FcMode == "" {
			next.mode = cur.mode
		}
		next.maxOutstanding = u32OnReplace(cur.maxOutstanding, serv.FcMaxOutstanding, serv.FcMaxOutstandingPresent)
		next.epMaxInflight = u32OnReplace(cur.epMaxInflight, serv.FcEpMaxInflight, serv.FcEpMaxInflightPresent)
		next.prefillMaxInflight = u32OnReplace(cur.prefillMaxInflight, serv.FcPrefillMaxInflight, serv.FcPrefillMaxInflightPresent)
		next.decodeMaxInflight = u32OnReplace(cur.decodeMaxInflight, serv.FcDecodeMaxInflight, serv.FcDecodeMaxInflightPresent)
		next.telemetryStaleMs = u32OnReplace(cur.telemetryStaleMs, serv.FcTelemetryStaleMs, serv.FcTelemetryStaleMsPresent)
		if !serv.FcAdaptivePresent && serv.FcAdaptive == "" {
			next.adaptive = cur.adaptive
		}
		next.warmupMs = u32OnReplace(cur.warmupMs, serv.FcWarmupMs, serv.FcWarmupMsPresent)
		next.ttftTargetMs = u32OnReplace(cur.ttftTargetMs, serv.FcTtftTargetMs, serv.FcTtftTargetMsPresent)
		next.tenantSharePct = u32OnReplace(cur.tenantSharePct, serv.FcTenantMaxSharePct, serv.FcTenantMaxSharePctPresent)
		if !serv.FcExposeHeadersPresent && serv.FcExposeHeaders == "" {
			next.exposeHeaders = cur.exposeHeaders
		}
	}
	for _, c := range []struct {
		name string
		v    uint32
	}{
		{"fc_max_outstanding", next.maxOutstanding},
		{"fc_ep_max_inflight", next.epMaxInflight},
		{"fc_prefill_max_inflight", next.prefillMaxInflight},
		{"fc_decode_max_inflight", next.decodeMaxInflight},
	} {
		if c.v > cmn.FcCapMax {
			return fcRuleCfg{}, cmn.NewValidationError(c.name,
				"%s must be within 0..%d", c.name, cmn.FcCapMax)
		}
	}
	if next.telemetryStaleMs > cmn.FcTelemetryStaleMsMax {
		return fcRuleCfg{}, cmn.NewValidationError("fc_telemetry_stale_ms",
			"fc_telemetry_stale_ms must be within 0..%d", cmn.FcTelemetryStaleMsMax)
	}
	if next.warmupMs > cmn.FcWarmupMsMax {
		return fcRuleCfg{}, cmn.NewValidationError("fc_warmup_ms",
			"fc_warmup_ms must be within 0..%d", cmn.FcWarmupMsMax)
	}
	if next.ttftTargetMs > cmn.FcTtftTargetMsMax {
		return fcRuleCfg{}, cmn.NewValidationError("fc_ttft_target_ms",
			"fc_ttft_target_ms must be within 0..%d", cmn.FcTtftTargetMsMax)
	}
	if next.tenantSharePct > cmn.FcTenantMaxSharePctMax {
		return fcRuleCfg{}, cmn.NewValidationError("fc_tenant_max_share_pct",
			"fc_tenant_max_share_pct must be within 0..%d", cmn.FcTenantMaxSharePctMax)
	}
	if err := fcBandResolve(eRule, serv, &next); err != nil {
		return fcRuleCfg{}, err
	}
	if err := next.bandErr(fcQueueDepthInForce(eRule, serv)); err != nil {
		return fcRuleCfg{}, err
	}
	return next, nil
}

// fcBandResolve reads the rule's band knobs into next with the replace
// rules of the rest of the gate. A triple is refused here when it is not
// three whole numbers or a value is out of its range, for callers without
// the handler's checks.
func fcBandResolve(eRule *ruleEnt, serv *cmn.LbServiceArg, next *fcRuleCfg) error {
	wake, err := cmn.FcWakePolicyToRule(serv.FcWakePolicy)
	if err != nil {
		return err
	}
	shedQueue, err := cmn.FcSwitchToRule("fc_shed_queue", serv.FcShedQueue)
	if err != nil {
		return err
	}
	tenantWake, err := cmn.FcTenantWakeToRule(serv.FcTenantWake)
	if err != nil {
		return err
	}
	llmdHeaders, err := cmn.FcSwitchToRule("fc_llmd_headers", serv.FcLlmdHeaders)
	if err != nil {
		return err
	}
	next.wakePolicy = wake
	next.shedQueue = shedQueue
	next.tenantWake = tenantWake
	next.llmdHeaders = llmdHeaders
	next.criticalReservePct = serv.FcCriticalReservePct
	var cur fcRuleCfg
	if eRule != nil {
		cur = eRule.fcCfg
		if !serv.FcWakePolicyPresent && serv.FcWakePolicy == "" {
			next.wakePolicy = cur.wakePolicy
		}
		if !serv.FcShedQueuePresent && serv.FcShedQueue == "" {
			next.shedQueue = cur.shedQueue
		}
		if !serv.FcTenantWakePresent && serv.FcTenantWake == "" {
			next.tenantWake = cur.tenantWake
		}
		if !serv.FcLlmdHeadersPresent && serv.FcLlmdHeaders == "" {
			next.llmdHeaders = cur.llmdHeaders
		}
		next.criticalReservePct = u32OnReplace(cur.criticalReservePct, serv.FcCriticalReservePct, serv.FcCriticalReservePctPresent)
	}
	if next.criticalReservePct > cmn.FcBandPctMax {
		return cmn.NewValidationError("fc_critical_reserve_pct",
			"fc_critical_reserve_pct must be within 0..%d", cmn.FcBandPctMax)
	}
	for _, f := range []struct {
		key     string
		v       string
		present bool
		limit   uint32
		dst     *[cmn.FcBands]uint32
		stored  [cmn.FcBands]uint32
	}{
		{"fc_band_weights", serv.FcBandWeights, serv.FcBandWeightsPresent, cmn.FcBandWeightMax, &next.bandWeight, cur.bandWeight},
		{"fc_band_min_share_pct", serv.FcBandMinSharePct, serv.FcBandMinSharePctPresent, cmn.FcBandPctMax, &next.bandMinSharePct, cur.bandMinSharePct},
		{"fc_band_wait_ms", serv.FcBandWaitMs, serv.FcBandWaitMsPresent, cmn.FcBandWaitMsMax, &next.bandWaitMs, cur.bandWaitMs},
		{"fc_band_queue_pct", serv.FcBandQueuePct, serv.FcBandQueuePctPresent, cmn.FcBandPctMax, &next.bandQueuePct, cur.bandQueuePct},
	} {
		if eRule != nil && !f.present && f.v == "" {
			*f.dst = f.stored
			continue
		}
		t, err := cmn.FcBandTripleParse(f.key, f.v, f.limit)
		if err != nil {
			return err
		}
		*f.dst = t
	}
	return nil
}

// fcQueueDepthInForce is the queue depth the rule will run on, for the
// band rules that need one: its own declaration after a replace is merged,
// else the process default (LLB_FC_MAX_QUEUE_DEPTH), else 0.
func fcQueueDepthInForce(eRule *ruleEnt, serv *cmn.LbServiceArg) uint32 {
	depth := serv.FcMaxQueueDepth
	if eRule != nil {
		depth = u32OnReplace(eRule.fcMaxQueueDepth, serv.FcMaxQueueDepth, serv.FcMaxQueueDepthPresent)
	}
	if depth != 0 {
		return depth
	}
	if v, err := strconv.ParseUint(os.Getenv("LLB_FC_MAX_QUEUE_DEPTH"), 10, 32); err == nil {
		return uint32(v)
	}
	return 0
}

// bandErr holds the rules that span the band knobs, on the declaration
// that will be stored. Weights declared under strict (or an inherited
// policy) are accepted and kept unused, so a later switch to weighted by
// replace finds them; band knobs with the gate off are accepted as well.
func (c fcRuleCfg) bandErr(queueDepth uint32) error {
	var weights uint32
	for _, w := range c.bandWeight {
		weights += w
	}
	if weights > cmn.FcBandRoundMax {
		return cmn.NewValidationError("fc_band_weights",
			"fc_band_weights must sum to at most %d", cmn.FcBandRoundMax)
	}
	// A zero weight is strict under another name: weights are none
	// (0:0:0) or at least 1 for every band, whatever the policy.
	weighted := c.wakePolicy == cmn.FcRuleWakeWeighted
	if weighted || c.bandWeight != ([cmn.FcBands]uint32{}) {
		for _, w := range c.bandWeight {
			if w != 0 {
				continue
			}
			if weighted {
				return cmn.NewValidationError("fc_band_weights",
					"fc_wake_policy weighted needs fc_band_weights of at least 1 for every band")
			}
			return cmn.NewValidationError("fc_band_weights",
				"fc_band_weights must be at least 1 for every band, or 0:0:0 for none")
		}
	}
	// Floors and the reserve are two mechanisms: a floor is a guarantee
	// under contention, the reserve a reservation. The three floors fit the
	// ceiling, and so do the reserve and the floors of the other two bands.
	var floors uint32
	for _, p := range c.bandMinSharePct {
		floors += p
	}
	if floors > cmn.FcBandPctMax {
		return cmn.NewValidationError("fc_band_min_share_pct",
			"fc_band_min_share_pct must sum to at most %d", cmn.FcBandPctMax)
	}
	if c.criticalReservePct+c.bandMinSharePct[cmn.FcBandStandard]+c.bandMinSharePct[cmn.FcBandSheddable] > cmn.FcBandPctMax {
		return cmn.NewValidationError("fc_critical_reserve_pct",
			"fc_critical_reserve_pct plus the standard and sheddable fc_band_min_share_pct must be at most %d", cmn.FcBandPctMax)
	}
	q := c.bandQueuePct
	if q[0] != 0 && q[1] != 0 && q[2] != 0 && q[0]+q[1]+q[2] > cmn.FcBandPctMax {
		return cmn.NewValidationError("fc_band_queue_pct",
			"fc_band_queue_pct must sum to at most %d when every band has a share", cmn.FcBandPctMax)
	}
	if c.shedQueue == cmn.FcRuleAdaptiveOn && queueDepth == 0 {
		return cmn.NewValidationError("fc_shed_queue",
			"fc_shed_queue on needs a queue: fc_max_queue_depth (or LLB_FC_MAX_QUEUE_DEPTH) is 0")
	}
	return nil
}

// bandKnobDeclared names the first band knob the declaration sets to other
// than its default, or "" when it sets none. fc_llmd_headers changes no
// admission decision and is not one of them.
func (c fcRuleCfg) bandKnobDeclared() string {
	var none [cmn.FcBands]uint32
	switch {
	case c.wakePolicy == cmn.FcRuleWakeWeighted:
		return "fc_wake_policy"
	case c.bandWeight != none:
		return "fc_band_weights"
	case c.bandMinSharePct != none:
		return "fc_band_min_share_pct"
	case c.criticalReservePct != 0:
		return "fc_critical_reserve_pct"
	case c.bandWaitMs != none:
		return "fc_band_wait_ms"
	case c.bandQueuePct != none:
		return "fc_band_queue_pct"
	case c.shedQueue == cmn.FcRuleAdaptiveOn:
		return "fc_shed_queue"
	case c.tenantWake == cmn.FcRuleTenantWakeRR:
		return "fc_tenant_wake"
	}
	return ""
}

// fcBandSockMapErr refuses the band knobs on a rule whose request
// direction the kernel may carry (sockMapMode both or request) and that is
// not an AI-gateway service: such requests would bypass the admission gate
// the bands order. An AI-gateway rule never pairs its request direction. A
// snapshot restore replay is let through with a warning, as
// fcExposeSockMapErr does.
func fcBandSockMapErr(serv *cmn.LbServiceArg, c fcRuleCfg, sockMapCode uint8, aiGw bool) error {
	if aiGw {
		return nil
	}
	field := c.bandKnobDeclared()
	if field == "" {
		return nil
	}
	if req, _ := sockMapDirs(sockMapCode); !req {
		return nil
	}
	if serv.RestoreReplay {
		tk.LogIt(tk.LogWarning, "lb-rule %s:%d: %s with sockMapMode %s restored: accelerated requests bypass the priority bands\n",
			serv.ServIP, serv.ServPort, field, cmn.SockMapCodeToMode(sockMapCode))
		return nil
	}
	return cmn.NewValidationError(field,
		"%s is refused with sockMapMode %s on a rule that is not an AI-gateway service: the request direction is not seen by the admission gate",
		field, cmn.SockMapCodeToMode(sockMapCode))
}

// toServ writes the stored declaration back onto a rule's service arguments
// for the read-back.
func (c fcRuleCfg) toServ(s *cmn.LbServiceArg) {
	s.FcMode = cmn.FcModeFromRule(c.mode)
	s.FcMaxOutstanding = c.maxOutstanding
	s.FcEpMaxInflight = c.epMaxInflight
	s.FcPrefillMaxInflight = c.prefillMaxInflight
	s.FcDecodeMaxInflight = c.decodeMaxInflight
	s.FcTelemetryStaleMs = c.telemetryStaleMs
	s.FcAdaptive = cmn.FcAdaptiveFromRule(c.adaptive)
	s.FcWarmupMs = c.warmupMs
	s.FcTtftTargetMs = c.ttftTargetMs
	s.FcTenantMaxSharePct = c.tenantSharePct
	s.FcExposeHeaders = cmn.FcAdaptiveFromRule(c.exposeHeaders)
	s.FcWakePolicy = cmn.FcWakePolicyFromRule(c.wakePolicy)
	s.FcBandWeights = cmn.FcBandTripleFormat(c.bandWeight)
	s.FcBandMinSharePct = cmn.FcBandTripleFormat(c.bandMinSharePct)
	s.FcCriticalReservePct = c.criticalReservePct
	s.FcBandWaitMs = cmn.FcBandTripleFormat(c.bandWaitMs)
	s.FcBandQueuePct = cmn.FcBandTripleFormat(c.bandQueuePct)
	s.FcShedQueue = cmn.FcAdaptiveFromRule(c.shedQueue)
	s.FcTenantWake = cmn.FcTenantWakeFromRule(c.tenantWake)
	s.FcLlmdHeaders = cmn.FcAdaptiveFromRule(c.llmdHeaders)
}

// fcExposeSockMapErr refuses the admission headers on a rule whose response
// direction the kernel may carry (sockMapMode both or response): the gateway
// never sees those responses, so it could not keep what the rule asks for.
// A snapshot restore replay is let through with a warning, as the sockmap
// checks do: the headers then appear only on responses the relay carries.
func fcExposeSockMapErr(serv *cmn.LbServiceArg, c fcRuleCfg, sockMapCode uint8) error {
	if c.exposeHeaders != cmn.FcRuleAdaptiveOn {
		return nil
	}
	if _, resp := sockMapDirs(sockMapCode); !resp {
		return nil
	}
	if serv.RestoreReplay {
		tk.LogIt(tk.LogWarning, "lb-rule %s:%d: fc_expose_headers on with sockMapMode %s restored: accelerated responses carry no admission headers\n",
			serv.ServIP, serv.ServPort, serv.SockMapMode)
		return nil
	}
	return cmn.NewValidationError("fc_expose_headers",
		"fc_expose_headers on is refused with sockMapMode %s: the response direction is not seen by the gateway",
		serv.SockMapMode)
}

// fcBandStat is one pool's band read-back as the data plane reports it,
// every triple indexed by band (cmn.FcBand*).
type fcBandStat struct {
	inflight    [cmn.FcBands]uint32
	queued      [cmn.FcBands]uint32
	waitMs      [cmn.FcBands]uint32
	queuePct    [cmn.FcBands]uint32
	minSharePct [cmn.FcBands]uint32
	weight      [cmn.FcBands]uint32
	reservePct  uint32
}

// fcFloorUnits is a share of the ceiling in force in whole service units, as
// the data plane's fc_floor_units rounds it: up, in the band's favour, but a
// share under 100 never reaches the whole ceiling; 0 without a ceiling or a
// share.
func fcFloorUnits(ceiling, pct uint32) uint32 {
	if ceiling == 0 || pct == 0 {
		return 0
	}
	if pct >= cmn.FcBandPctMax {
		return ceiling
	}
	u := uint32((uint64(ceiling)*uint64(pct) + 99) / 100)
	if u >= ceiling {
		u = ceiling - 1
	}
	return u
}

// fcFloorClaims is what the data plane enforces against a ceiling
// (fc_floor_claims): the floors by band and the reserve in units. The three
// claims never exceed the ceiling: they are clamped in rank order, critical
// first, which holds the larger of its floor and its reserve, then standard,
// then sheddable.
func fcFloorClaims(ceiling uint32, minSharePct [cmn.FcBands]uint32, reservePct uint32) (floor [cmn.FcBands]uint32, reserve uint32) {
	left := ceiling
	res := fcFloorUnits(ceiling, reservePct)
	crit := fcFloorUnits(ceiling, minSharePct[cmn.FcBandCritical])
	claim := res
	if crit > claim {
		claim = crit
	}
	// Each share is at most the ceiling, so critical's claim always fits.
	floor[cmn.FcBandCritical] = crit
	left -= claim
	for _, b := range []int{cmn.FcBandStandard, cmn.FcBandSheddable} {
		u := fcFloorUnits(ceiling, minSharePct[b])
		if u > left {
			u = left
		}
		floor[b] = u
		left -= u
	}
	return floor, res
}

// effective builds the per-band read-back against the ceiling in force:
// the floors and the reserve in units, as the gate enforces them, and each weight's share of the round in percent,
// rounded to the nearest (0 when no weight is set).
func (st fcBandStat) effective(ceiling uint32) cmn.FcBandsArg {
	var round uint32
	for _, w := range st.weight {
		round += w
	}
	floors, reserve := fcFloorClaims(ceiling, st.minSharePct, st.reservePct)
	band := func(b int) cmn.FcBandArg {
		out := cmn.FcBandArg{
			Inflight:    st.inflight[b],
			Queued:      st.queued[b],
			WaitMs:      st.waitMs[b],
			QueuePct:    st.queuePct[b],
			MinSharePct: st.minSharePct[b],
			FloorUnits:  floors[b],
			Weight:      st.weight[b],
		}
		if round != 0 {
			out.WeightPct = (st.weight[b]*100 + round/2) / round
		}
		return out
	}
	return cmn.FcBandsArg{
		CriticalReservePct:   st.reservePct,
		CriticalReserveUnits: reserve,
		Critical:             band(cmn.FcBandCritical),
		Standard:             band(cmn.FcBandStandard),
		Sheddable:            band(cmn.FcBandSheddable),
	}
}

// adaptiveInForce reports whether the rule's pool adapts its service
// ceiling: its own switch, or the process default when it declares none.
func (c fcRuleCfg) adaptiveInForce() bool {
	switch c.adaptive {
	case cmn.FcRuleAdaptiveOn:
		return true
	case cmn.FcRuleAdaptiveOff:
		return false
	}
	return strings.EqualFold(os.Getenv("LLB_FC_ADAPTIVE"), "on")
}

// syncVllmScraper runs the rule's vLLM metrics scraper while something
// reads what it scrapes: the P/D scorers, or the adaptive admission ceiling
// of an AI-gateway rule. The scraper addresses endpoints by their index in
// the rule, so a rule whose endpoints changed gets a fresh one.
func (r *ruleEnt) syncVllmScraper() {
	lbActs, ok := r.act.action.(*ruleLBActs)
	if !ok {
		return
	}
	want := r.pdDisaggMode || (r.aiGwMode() && r.fcCfg.adaptiveInForce())
	endpoints := make(map[int]string, len(lbActs.endPoints))
	if want {
		for i, ep := range lbActs.endPoints {
			endpoints[i] = fmt.Sprintf("%s:%d", ep.xIP.String(), ep.xPort)
		}
	}
	if r.vllmScraper != nil {
		if want && r.vllmScraper.sameEndpoints(endpoints) {
			return
		}
		r.vllmScraper.Stop()
		r.vllmScraper = nil
	}
	if !want {
		return
	}
	svcIP := tk.IPtonl(r.tuples.l3Dst.addr.IP)
	svcPort := r.tuples.l4Dst.valMin
	// updateFn mirrors samples into the Go-side worker-metrics cache so
	// the REST introspection/staleness APIs see the built-in scraper
	// (cache only — the data plane's queue-depth push happens inside the
	// sink).
	r.vllmScraper = NewVllmScraper(endpoints, svcIP, svcPort, 0,
		func(epIP string, m WorkerMetrics) {
			if mh.dpEbpf != nil {
				mh.dpEbpf.StoreWorkerMetricsCache(m.EndpointIP, m)
			}
		})
	// thread the mh-owned shutdown ctx so the scraper exits when the
	// workers stage cancels.
	go r.vllmScraper.Run(mh.shutdownCtx)
}
