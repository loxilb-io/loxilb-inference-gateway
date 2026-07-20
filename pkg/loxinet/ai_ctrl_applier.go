/*
 * Copyright (c) 2026 LoxiLB Authors
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

// the loxilb-side snapshot APPLIER — the thin cgo
// shim over pkg/aictrl.Session. Policy (validation, α decay, merge) lives in
// pure-Go pkg/aictrl; this file only bridges Sink writes to the 96-03 C
// atomics (llb_ai_ctrl_update_ep / llb_ai_ctrl_set_mode) and resolves local
// rule state (known EPs, local health).
package loxinet

/*
#include <stdint.h>

extern void llb_ai_ctrl_update_ep(uint32_t service_ip, uint16_t service_port,
                                  int ep_index, uint32_t packed);
extern void llb_ai_ctrl_set_mode(uint32_t service_ip, uint16_t service_port,
                                 uint8_t mode);
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	"github.com/loxilb-io/loxilb/pkg/aictrl"
	tk "github.com/loxilb-io/loxilib"
)

// AiCtrlApplierStart is the GLOBAL env-gated start hook for the AI-controller
// applier (called once from loxinet init — NOT per-rule, contrast the
// rules.go:3423 per-rule scraper: one controller stream per loxilb; snapshots
// carry service identity for the bridge walk).
func AiCtrlApplierStart(ctx context.Context) {
	// G3 / env bootstrap: LOXILB_AI_CTRL_ADDR unset ⇒ the
	// feature does not exist. Return BEFORE any allocation, goroutine or
	// dial — "off must not even subscribe". This getenv + empty-return MUST
	// remain the first statement block of this function.
	addr := os.Getenv("LOXILB_AI_CTRL_ADDR")
	if addr == "" {
		return
	}

	// Knob set (locked names) — all getenv-once at start.
	decayWindow := aiCtrlEnvSec("LOXILB_AI_CTRL_DECAY_WINDOW_SEC", 30) //
	hysteresis := aiCtrlEnvSec("LOXILB_AI_CTRL_HYSTERESIS_SEC", 5)
	ackTimeout := aiCtrlEnvSec("LOXILB_AI_CTRL_ACK_TIMEOUT_SEC", 10)
	jitterPct := aiCtrlEnvInt("LOXILB_AI_CTRL_APPLY_JITTER_PCT", 10) // P3 anti-herding

	gwID, _ := os.Hostname()
	if gwID == "" {
		gwID = "loxilb"
	}

	// Recording Sink wrapper: gauges refresh on every C write.
	// G3 note: promauto vars register at import time (fine — zero-valued
	// series ≠ behavior change); gauge REFRESH runs only here, i.e. only
	// when the env-gated applier is running.
	sink := &aiCtrlMetricsSink{inner: &aiCtrlCgoSink{}}

	tickN := 0
	cfg := aictrl.Config{
		Addr:        addr,
		GatewayID:   gwID,
		DecayWindow: decayWindow,
		Hysteresis:  hysteresis,
		AckTimeout:  ackTimeout,
		JitterPct:   jitterPct,
		Known:       aiCtrlKnownEps,
		Healthy:     aiCtrlEpHealthy,
		OnApplied: func(epoch uint64, serviceKeys []string) {
			prom.IncAictrlApplied()
			for _, svc := range serviceKeys {
				prom.SetAictrlEpoch(svc, float64(epoch))
			}
			tk.LogIt(tk.LogInfo, "[AI_CTRL] snapshot applied epoch=%d services=%d\n",
				epoch, len(serviceKeys))
		},
		OnRejected: func(epoch uint64, detail string) {
			prom.IncAictrlNack()
			tk.LogIt(tk.LogWarning, "[AI_CTRL] NACK epoch=%d: %s\n", epoch, detail)
		},
		OnOverride: func(serviceKey string, epIdx int) {
			// every local-health veto is counted (G4).
			prom.IncAictrlOverride()
		},
		OnTick: func(alpha float64, m aictrl.Mode) {
			// 1 Hz refresh of the ladder observables.
			prom.SetAictrlAlpha(alpha)
			prom.SetAictrlMode(float64(m))
			// lazy-vec guard: periodically re-pre-warm neutral
			// gauges for any EP that appeared after start (rule changes).
			if tickN%10 == 0 {
				sink.prewarm(aiCtrlKnownEps())
			}
			tickN++
		},
		OnModeChange: func(m aictrl.Mode) {
			tk.LogIt(tk.LogInfo, "[AI_CTRL] mode change -> %s\n", m.String())
		},
		Logf: func(format string, args ...interface{}) {
			tk.LogIt(tk.LogInfo, "[AI_CTRL] "+format+"\n", args...)
		},
	}

	sess := aictrl.NewSession(cfg, sink)
	tk.LogIt(tk.LogInfo, "[AI_CTRL] applier starting: addr=%s gateway_id=%s decay_window=%s hysteresis=%s ack_timeout=%s jitter_pct=%d\n",
		addr, gwID, decayWindow, hysteresis, ackTimeout, jitterPct)
	go func() {
		// Pre-warm: set state/weight gauges for all known EPs
		// to their neutral values (weight 100, state 0 none) so harness
		// asserts never hit lazy-vec absence; mode/alpha start Autonomous/0
		// (no snapshot yet).
		sink.prewarm(aiCtrlKnownEps())
		prom.SetAictrlMode(float64(aictrl.ModeAutonomous))
		prom.SetAictrlAlpha(0)
		_ = sess.Run(ctx)
		tk.LogIt(tk.LogInfo, "[AI_CTRL] applier stopped\n")
	}()
}

// aiCtrlMetricsSink is the recording Sink wrapper: it forwards to
// the cgo sink and mirrors every write into the Prometheus gauges, tracking
// which (service, ep_idx) series exist so prewarm never clobbers a live one.
type aiCtrlMetricsSink struct {
	inner aictrl.Sink
	mu    sync.Mutex
	seen  map[string]bool // "service|ep_idx" with a live gauge value
}

func (m *aiCtrlMetricsSink) markSeen(serviceKey string, epIdx int) {
	m.mu.Lock()
	if m.seen == nil {
		m.seen = make(map[string]bool)
	}
	m.seen[serviceKey+"|"+strconv.Itoa(epIdx)] = true
	m.mu.Unlock()
}

// UpdateEp forwards the packed word to C and refreshes the per-EP gauges
// with the effective (post-alpha) values actually written. markSeen runs
// BEFORE the gauge writes: a concurrent prewarm must never clobber a live
// value with the neutral prewarm value.
func (m *aiCtrlMetricsSink) UpdateEp(serviceKey string, epIdx int, packed uint32) {
	m.markSeen(serviceKey, epIdx)
	m.inner.UpdateEp(serviceKey, epIdx, packed)
	prom.SetAictrlEpWeight(serviceKey, epIdx, float64(packed&0xff))
	prom.SetAictrlEpState(serviceKey, epIdx, float64((packed>>24)&0xff))
}

// SetMode forwards the per-service mode scalar to C.
func (m *aiCtrlMetricsSink) SetMode(serviceKey string, mode uint8) {
	m.inner.SetMode(serviceKey, mode)
}

// prewarm sets NEUTRAL gauge values (weight 100 = arithmetic no-op, state 0
// = none) for every known EP whose series has not yet been written — the
// lazy-vec guard so harness asserts never hit absent series — and reaps the
// series of EPs that have VANISHED from the locally-known set (rule/EP
// removal), including the service's applied-epoch series when its last EP
// goes (series lifecycle, metrics audit). Runs at start and every ~10 ticks.
func (m *aiCtrlMetricsSink) prewarm(known map[string][]uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = make(map[string]bool)
	}
	knownKeys := make(map[string]bool)
	for svc, idxs := range known {
		for _, i := range idxs {
			key := svc + "|" + strconv.Itoa(int(i))
			knownKeys[key] = true
			if m.seen[key] {
				continue
			}
			prom.SetAictrlEpWeight(svc, int(i), 100) // neutral
			prom.SetAictrlEpState(svc, int(i), 0)    // none
			m.seen[key] = true
		}
	}
	for key := range m.seen {
		if knownKeys[key] {
			continue
		}
		// service_key is "xip:xport:proto" — never contains '|'.
		svc, idxStr, ok := strings.Cut(key, "|")
		if ok {
			if idx, err := strconv.Atoi(idxStr); err == nil {
				prom.DeleteAictrlEpSeries(svc, idx)
			}
			if _, live := known[svc]; !live {
				prom.DeleteAictrlEpochSeries(svc)
			}
		}
		delete(m.seen, key)
	}
}

// aiCtrlCgoSink bridges Session writes to C-side packed atomics.
// service_key "xip:xport:proto" (the xsync keying) is resolved once and
// cached; the C bridge functions themselves are PROXY_LOCK + atomic_store
// with pd_disagg/n_eps guards, so writes to non-P/D or vanished services are
// safely dropped C-side.
type aiCtrlCgoSink struct {
	mu    sync.Mutex
	cache map[string]aiCtrlSvcAddr
}

type aiCtrlSvcAddr struct {
	ip   uint32 // network byte order (tk.IPtonl)
	port uint16
	ok   bool
}

func (s *aiCtrlCgoSink) resolve(key string) (aiCtrlSvcAddr, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = make(map[string]aiCtrlSvcAddr)
	}
	if a, hit := s.cache[key]; hit {
		return a, a.ok
	}
	a := aiCtrlSvcAddr{}
	parts := strings.Split(key, ":")
	if len(parts) == 3 {
		ip := net.ParseIP(parts[0])
		port, perr := strconv.ParseUint(parts[1], 10, 16)
		if ip != nil && ip.To4() != nil && perr == nil {
			a = aiCtrlSvcAddr{ip: tk.IPtonl(ip), port: uint16(port), ok: true}
		}
	}
	if !a.ok {
		tk.LogIt(tk.LogWarning, "[AI_CTRL] unresolvable service_key %q (want \"xip:xport:proto\" IPv4)\n", key)
	}
	s.cache[key] = a
	return a, a.ok
}

// UpdateEp stores one packed instruction word (state<<24|weight) via the
// bridge.
func (s *aiCtrlCgoSink) UpdateEp(serviceKey string, epIdx int, packed uint32) {
	a, ok := s.resolve(serviceKey)
	if !ok {
		return
	}
	C.llb_ai_ctrl_update_ep(C.uint32_t(a.ip), C.uint16_t(a.port),
		C.int(epIdx), C.uint32_t(packed))
}

// SetMode stores the per-service controller mode scalar (0 = autonomous —
// the C hot path does ZERO controller work at 0; G3).
func (s *aiCtrlCgoSink) SetMode(serviceKey string, mode uint8) {
	a, ok := s.resolve(serviceKey)
	if !ok {
		return
	}
	C.llb_ai_ctrl_set_mode(C.uint32_t(a.ip), C.uint16_t(a.port), C.uint8_t(mode))
}

// aiCtrlRuleServiceKey renders a rule's identity as the "xip:xport:proto"
// service key (the same keying the xsync service_key / aictrl.v1
// ServiceSnapshot.service_key uses). Empty string for non-L4 protos.
func aiCtrlRuleServiceKey(r *ruleEnt) string {
	var proto string
	switch r.tuples.l4Prot.val {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	case 132:
		proto = "sctp"
	default:
		return ""
	}
	return fmt.Sprintf("%s:%d:%s", r.tuples.l3Dst.addr.IP.String(),
		r.tuples.l4Dst.valMin, proto)
}

// aiCtrlKnownEps returns the locally-known (service_key → ep indices) set for
// V5 snapshot validation — only P/D-disaggregated services (the controller's
// scope; the C bridge only writes pd_disagg_enabled epvals anyway). Dynamic:
// re-queried per snapshot so rule changes are picked up.
func aiCtrlKnownEps() map[string][]uint32 {
	known := make(map[string][]uint32)
	if mh.zr == nil || mh.zr.Rules == nil {
		return known
	}
	mh.mtx.RLock()
	defer mh.mtx.RUnlock()
	for _, r := range mh.zr.Rules.tables[RtLB].eMap {
		if r == nil || !r.pdDisaggMode {
			continue
		}
		acts, ok := r.act.action.(*ruleLBActs)
		if !ok {
			continue
		}
		key := aiCtrlRuleServiceKey(r)
		if key == "" {
			continue
		}
		idxs := make([]uint32, 0, len(acts.endPoints))
		for i := range acts.endPoints {
			idxs = append(idxs, uint32(i))
		}
		known[key] = idxs
	}
	return known
}

// aiCtrlEpHealthy reports LOCAL health for one EP of one P/D service.
// Local health always wins (P4/G4): a probe-down or admin-removed EP vetoes
// any controller directive Go-side (MergeVerdict pure intersection); the
// C-side CB/excluded_mask checks run per-tier AFTER controller fold-in as
// the second line of non-resurrection defense.
func aiCtrlEpHealthy(serviceKey string, epIdx int) bool {
	if mh.zr == nil || mh.zr.Rules == nil {
		return false
	}
	mh.mtx.RLock()
	defer mh.mtx.RUnlock()
	for _, r := range mh.zr.Rules.tables[RtLB].eMap {
		if r == nil || !r.pdDisaggMode {
			continue
		}
		if aiCtrlRuleServiceKey(r) != serviceKey {
			continue
		}
		acts, ok := r.act.action.(*ruleLBActs)
		if !ok || epIdx < 0 || epIdx >= len(acts.endPoints) {
			return false
		}
		ep := &acts.endPoints[epIdx]
		return !ep.inActiveEP && !ep.noService
	}
	return false
}

// aiCtrlEnvSec reads a whole-seconds env knob with a default.
func aiCtrlEnvSec(name string, def int) time.Duration {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		tk.LogIt(tk.LogWarning, "[AI_CTRL] invalid %s=%q, using default %ds\n", name, v, def)
	}
	return time.Duration(def) * time.Second
}

// aiCtrlEnvInt reads a non-negative integer env knob with a default.
func aiCtrlEnvInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
		tk.LogIt(tk.LogWarning, "[AI_CTRL] invalid %s=%q, using default %d\n", name, v, def)
	}
	return def
}
