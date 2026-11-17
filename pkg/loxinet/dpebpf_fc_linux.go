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

/*
#include <stdint.h>
#include <stdlib.h>
// The service key as the health updates declare it in dpebpf_linux.go: one
// cgo package shares one definition, and the sockproxy compares a key on
// these three fields only (cmp_proxy_ent), never on the full entry.
struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint8_t inv;
  uint8_t protocol;
};
#include "../../loxilb-ebpf/common/sockproxy_metrics.h"
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
)

// The capacity admission gate's read-back and drain, over the exports the
// sockproxy provides for them (loxilb-ebpf/common/sockproxy_metrics.h). The
// Prometheus collector reads the same rows for every pool; these are the
// two calls the management plane makes for one rule and for the process.

var fcModeNames = [...]string{"off", "observe", "enforce"}

// fcPoolLookupHost mirrors llb_conv_nat2proxy's default host identity.
func fcPoolLookupHost(svcIP net.IP, svcPort uint16, hostURL string) string {
	if hostURL != "" {
		return hostURL
	}
	return fmt.Sprintf("%s:%d", svcIP.String(), svcPort)
}

// DpFcStateGet - the gate's resolved state on the rule's model pool: the
// pool is the one the rule's host, path prefix and model name resolve to on
// the service. ok is false when the service or the pool does not exist in
// the data plane (a rule that has not been pushed, or an IPv6 service).
func (e *DpEbpfH) DpFcStateGet(svcIP net.IP, svcPort uint16, proto uint8,
	hostURL, pathPrefix, modelName string) (cmn.FcEffectiveArg, bool) {
	var key C.struct_proxy_ent
	var st C.proxy_fc_svc_stat_t

	if svcIP.To4() == nil {
		return cmn.FcEffectiveArg{}, false
	}
	key.xip = C.uint(tk.IPtonl(svcIP))
	key.xport = C.ushort(tk.Htons(svcPort))
	key.protocol = C.uchar(proto)

	// llb_conv_nat2proxy synthesizes VIP:port for an omitted host. Query the
	// installed pool identity, while retaining explicit host/path/model keys.
	cHost := C.CString(fcPoolLookupHost(svcIP, svcPort, hostURL))
	cPath := C.CString(pathPrefix)
	cModel := C.CString(modelName)
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cModel))

	if C.proxy_get_fc_state(&key, cHost, cPath, cModel, &st) != 0 {
		return cmn.FcEffectiveArg{}, false
	}
	mode := "unknown"
	if int(st.mode) < len(fcModeNames) {
		mode = fcModeNames[st.mode]
	}
	eff := cmn.FcEffectiveArg{
		Mode:                    mode,
		MaxOutstanding:          uint32(st.max_outstanding),
		EpMaxInflight:           uint32(st.ep_cap[0]),
		PrefillMaxInflight:      uint32(st.ep_cap[1]),
		DecodeMaxInflight:       uint32(st.ep_cap[2]),
		QueueDepth:              uint32(st.max_queue_depth),
		QueueWaitMs:             uint32(st.max_queue_wait_ms),
		Inflight:                uint32(st.inflight),
		Queued:                  uint32(st.queued),
		QueueMemoryBoundMib:     uint64(st.max_queue_depth),
		TelemetryStaleMs:        uint32(st.telemetry_stale_ms),
		Adaptive:                fcOnOff(st.adaptive),
		WarmupMs:                uint32(st.warmup_ms),
		TtftTargetMs:            uint32(st.ttft_target_ms),
		EffectiveMaxOutstanding: uint32(st.effective_max_outstanding),
		AdaptState:              fcNameOf(fcAdaptStateNames, uint8(st.adapt_state)),
		AdaptReason:             fcNameOf(fcAdaptReasonNames, uint8(st.adapt_reason)),
		WarmingEndpoints:        uint32(st.warming_eps),
		TenantMaxSharePct:       uint32(st.tenant_share_pct),
		TenantsActive:           uint32(st.tenants_active),
		TenantSlots:             uint32(st.tenant_slots),
		ExposeHeaders:           fcOnOff(st.expose_headers),
		WakePolicy:              fcNameOf(fcWakePolicyNames, uint8(st.wake_policy_cfg)),
		WakePolicyEffective:     fcNameOf(fcWakePolicyNames, uint8(st.wake_policy)),
		ShedQueue:               fcOnOff(st.shed_queue_cfg),
		ShedQueueEffective:      fcOnOff(st.shed_queue),
		TenantWake:              fcNameOf(fcTenantWakeNames, uint8(st.tenant_wake_cfg)),
		TenantWakeEffective:     fcNameOf(fcTenantWakeNames, uint8(st.tenant_wake)),
		BandFallbackReason:      fcNameOf(fcBandFallbackNames, uint8(st.band_fallback)),
		LlmdHeaders:             fcOnOff(st.llmd_headers),
		BandsConfigured:         st.bands != 0,
		Source: cmn.FcEffectiveSource{
			Mode:               fcSourceName(st.src[0]),
			MaxOutstanding:     fcSourceName(st.src[1]),
			EpMaxInflight:      fcSourceName(st.src[2]),
			PrefillMaxInflight: fcSourceName(st.src[3]),
			DecodeMaxInflight:  fcSourceName(st.src[4]),
			QueueDepth:         fcSourceName(st.src[5]),
			QueueWaitMs:        fcSourceName(st.src[6]),
			TelemetryStaleMs:   fcSourceName(st.src[7]),
			Adaptive:           fcSourceName(st.src_adapt[0]),
			WarmupMs:           fcSourceName(st.src_adapt[1]),
			TtftTargetMs:       fcSourceName(st.src_adapt[2]),
			TenantMaxSharePct:  fcSourceName(st.src_tenant),
			ExposeHeaders:      fcSourceName(st.src_expose),
			WakePolicy:         fcSourceName(st.src_band[0]),
			BandWeights:        fcSourceName(st.src_band[1]),
			BandMinSharePct:    fcSourceName(st.src_band[2]),
			CriticalReservePct: fcSourceName(st.src_band[3]),
			BandWaitMs:         fcSourceName(st.src_band[4]),
			BandQueuePct:       fcSourceName(st.src_band[5]),
			ShedQueue:          fcSourceName(st.src_band[6]),
			TenantWake:         fcSourceName(st.src_band[7]),
			LlmdHeaders:        fcSourceName(st.src_band[8]),
		},
	}
	// The band triples are indexed by band, as cmn.FcBand* is.
	var bands fcBandStat
	for b := 0; b < cmn.FcBands; b++ {
		bands.inflight[b] = uint32(st.band_inflight[b])
		bands.queued[b] = uint32(st.band_queued[b])
		bands.waitMs[b] = uint32(st.band_wait_ms[b])
		bands.queuePct[b] = uint32(st.band_queue_pct[b])
		bands.minSharePct[b] = uint32(st.band_min_share_pct[b])
		bands.weight[b] = uint32(st.band_weight[b])
	}
	bands.reservePct = uint32(st.critical_reserve_pct)
	eff.Bands = bands.effective(eff.EffectiveMaxOutstanding)
	eff.WeightsInUse = st.wake_policy == 1 && bands.weight != [cmn.FcBands]uint32{}
	return eff, true
}

// The data plane's enum fc_adapt_state and enum fc_adapt_reason, spelled
// as sockproxy_fc.c spells them, and enum fc_wake_policy and enum
// fc_tenant_wake as the rule arguments spell them.
var (
	fcAdaptStateNames  = []string{"off", "open", "tightened", "frozen"}
	fcAdaptReasonNames = []string{"none", "queued", "ttft", "clear", "stale"}
	fcWakePolicyNames  = []string{"strict", "weighted"}
	fcTenantWakeNames  = []string{"fifo", "rr"}
	// enum fc_band_fallback, as fc_band_fallback_name spells it.
	fcBandFallbackNames = []string{"none", "sockmap_request", "zero_weight", "no_queue"}
)

func fcNameOf(names []string, v uint8) string {
	if int(v) < len(names) {
		return names[v]
	}
	return "unknown"
}

// fcOnOff names the adaptive switch in force.
func fcOnOff(v C.uint8_t) string {
	if v != 0 {
		return "on"
	}
	return "off"
}

// fcSourceName names enum fc_src: where a value in force came from.
func fcSourceName(src C.uint8_t) string {
	switch src {
	case 1:
		return "env"
	case 2:
		return "rule"
	}
	return "default"
}

// DpFcInflightTotal - inference requests executing under the gate, summed
// over every gated pool.
func (e *DpEbpfH) DpFcInflightTotal() uint64 {
	return uint64(C.proxy_get_fc_inflight_total())
}

// DpFcDrainSet - enter or leave the data path's maintenance drain.
func (e *DpEbpfH) DpFcDrainSet(on bool) {
	v := C.int(0)
	if on {
		v = 1
	}
	C.proxy_fc_drain_set(v)
	tk.LogIt(tk.LogInfo, "[DP] capacity gate drain %v\n", on)
}
