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

// SotW snapshot generator (CTRL-02 emission semantics + P6 churn guard):
// turns decision-engine output into frozen loxilb.aictrl.v1 Snapshots.
//
//   - fleet-stale ⇒ emit NOTHING (the appliers ride the staleness-deadline
//     ladder to the autonomous baseline — CTRL-02).
//   - regenerate only when the decision OUTPUT changes, with a min
// inter-epoch interval even on change (P6 churn guard)…
//   - …EXCEPT a periodic identical re-anchor (default 60s) so late-joining
//     or reconnecting appliers converge (SotW-as-drift-insurance — the
//     sockproxy_sync.go periodic full-sync precedent).
//   - every emission: epoch++ (strictly monotonic per boot_id), fresh nonce,
// staleness_deadline = now + 3×epoch_period (: 30s at
//     default), one ServiceSnapshot with per-EP {ep_idx, ep_addr, role,
//     weight, state} in registry ep_idx order.
//
// The generator sets ONLY epoch/boot_id/deadline/nonce/min_applier_version
// and per-EP identity+weight+state — no-load-fields tripwire keeps
// the contract honest. State is ACTIVE in v1; DRAINING/DISABLED are
// operator/registry-driven states reserved for the fault harness's injected
// snapshots.

package engine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/loxilb-io/loxilb/pkg/aictrl"
)

// snapshotMinApplierVersion is the applier capability floor stamped into
// every snapshot (starts at 1 per the frozen contract notes).
const snapshotMinApplierVersion = 1

// GeneratorConfig parameterizes snapshot emission. Zero values fall back to
// defaults.
type GeneratorConfig struct {
	// EpochPeriod is the controller decision period (default 10s;
	// NewGenerator seeds it from the registry's epoch_period_sec). The
	// staleness deadline is 3×EpochPeriod ahead of emission.
	EpochPeriod time.Duration
	// MinEpochGap is the minimum inter-emission interval, enforced even
	// when the output CHANGES (P6 churn guard). Default = EpochPeriod.
	MinEpochGap time.Duration
	// ReanchorEvery re-emits an IDENTICAL SotW after this long without an
	// emission, so late joiners converge. Default 60s.
	ReanchorEvery time.Duration
}

func (c GeneratorConfig) withDefaults(reg *Registry) GeneratorConfig {
	if c.EpochPeriod <= 0 {
		if reg != nil && reg.EpochPeriodSec > 0 {
			c.EpochPeriod = time.Duration(reg.EpochPeriodSec) * time.Second
		} else {
			c.EpochPeriod = 10 * time.Second
		}
	}
	if c.MinEpochGap <= 0 {
		c.MinEpochGap = c.EpochPeriod
	}
	if c.ReanchorEvery <= 0 {
		// The identical-SotW re-anchor doubles as the applier's LIVENESS
		// HEARTBEAT: every emission refreshes the snapshot staleness deadline
		// (now + 3×EpochPeriod). It MUST fire well inside that deadline, or a
		// healthy but steady-state controller lets appliers decay to Autonomous
		// — false degradation / mode oscillation. A 60s re-anchor against a 30s
		// deadline (default) guaranteed that oscillation on any quiet
		// fleet; caught live validation. Heartbeat once per epoch so
		// the deadline is refreshed with 2 epochs of margin, exactly matching
		// "Stale after 3 missed epochs" model.
		c.ReanchorEvery = c.EpochPeriod
	}
	return c
}

// Generator produces loxilb.aictrl.v1 Snapshots from decision output. It is
// stateful (epoch counter, boot identity, last emission) and NOT safe for
// concurrent use — the controller drives it from its single decision loop.
type Generator struct {
	cfg GeneratorConfig
	reg *Registry

	// bootID is generated ONCE at construction; a controller restart mints
	// a new one, which resets the applier's epoch acceptance floor
	// (: accept iff boot_id != last || epoch > last_epoch).
	bootID string
	epoch  uint64 // last emitted epoch; first emission is 1

	emitted     bool
	lastEmit    time.Time
	lastWeights map[string]uint32
	lastStates  map[string]aictrl.EpState
}

// NewGenerator builds a Generator bound to a loaded registry. The boot_id
// is minted here (google/uuid, pinned) and never changes for the lifetime
// of the process.
func NewGenerator(reg *Registry, cfg GeneratorConfig) *Generator {
	return &Generator{
		cfg:    cfg.withDefaults(reg),
		reg:    reg,
		bootID: uuid.NewString(),
	}
}

// BootID returns the generator's per-process boot identity.
func (g *Generator) BootID() string { return g.bootID }

// Epoch returns the last emitted epoch (0 before the first emission).
func (g *Generator) Epoch() uint64 { return g.epoch }

// Maybe emits a snapshot when — and only when — one is due:
//
//   - fleetStale ⇒ nil, ALWAYS (CTRL-02: stop emitting; "no snapshot" is
//     safer than "wrong snapshot").
//   - within MinEpochGap of the last emission ⇒ nil, even if the output
//     changed (P6 churn guard).
//   - output identical to the last emission ⇒ nil, unless ReanchorEvery has
//     elapsed (identical SotW re-anchor for late joiners).
//
// weights/states are keyed by registry host IP; missing entries default to
// the neutral weight 100 / EP_STATE_ACTIVE (v1 SotW: every EP, every time).
func (g *Generator) Maybe(now time.Time, weights map[string]uint32,
	states map[string]aictrl.EpState, fleetStale bool) *aictrl.Snapshot {

	if fleetStale {
		return nil
	}

	// Normalize the desired output over the registry host set so map
	// presence/absence noise never fakes an output change.
	normW := make(map[string]uint32, len(g.reg.Hosts))
	normS := make(map[string]aictrl.EpState, len(g.reg.Hosts))
	for ip := range g.reg.Hosts {
		w, ok := weights[ip]
		if !ok {
			w = 100
		}
		normW[ip] = w
		st, ok := states[ip]
		if !ok || st == aictrl.EpState_EP_STATE_UNSPECIFIED {
			st = aictrl.EpState_EP_STATE_ACTIVE
		}
		normS[ip] = st
	}

	if g.emitted {
		if now.Sub(g.lastEmit) < g.cfg.MinEpochGap {
			return nil // min inter-epoch interval, even on output change
		}
		if g.sameOutput(normW, normS) && now.Sub(g.lastEmit) < g.cfg.ReanchorEvery {
			return nil // unchanged output, re-anchor not yet due
		}
	}

	snap := g.build(now, normW, normS)
	g.epoch = snap.GetEpoch()
	g.emitted = true
	g.lastEmit = now
	g.lastWeights = normW
	g.lastStates = normS
	return snap
}

func (g *Generator) sameOutput(w map[string]uint32, s map[string]aictrl.EpState) bool {
	for ip := range g.reg.Hosts {
		if g.lastWeights[ip] != w[ip] || g.lastStates[ip] != s[ip] {
			return false
		}
	}
	return true
}

func (g *Generator) build(now time.Time, w map[string]uint32,
	s map[string]aictrl.EpState) *aictrl.Snapshot {

	// Per-EP entries in registry ep_idx order (the loxilb EP-array order
	// frozen by golden fixture).
	ips := make([]string, 0, len(g.reg.Hosts))
	for ip := range g.reg.Hosts {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return g.reg.Hosts[ips[i]].EpIdx < g.reg.Hosts[ips[j]].EpIdx
	})

	eps := make([]*aictrl.EpEntry, 0, len(ips))
	for _, ip := range ips {
		h := g.reg.Hosts[ip]
		role := aictrl.Role_ROLE_PREFILL
		if h.Role == RoleDecode {
			role = aictrl.Role_ROLE_DECODE
		}
		eps = append(eps, &aictrl.EpEntry{
			EpIdx:  h.EpIdx,
			EpAddr: fmt.Sprintf("%s:%d", ip, h.Port),
			Role:   role,
			Weight: w[ip],
			State:  s[ip],
		})
	}

	return &aictrl.Snapshot{
		Epoch:  g.epoch + 1,
		BootId: g.bootID,
		// staleness deadline = 3× the epoch period (30s
		// defaults) — expiry walks appliers down the alpha ladder.
		StalenessDeadlineUnixMs: uint64(now.Add(3 * g.cfg.EpochPeriod).UnixMilli()),
		Services: []*aictrl.ServiceSnapshot{{
			ServiceKey: g.reg.Service.Key,
			Eps:        eps,
		}},
		MinApplierVersion: snapshotMinApplierVersion,
		Nonce:             newNonce(),
	}
}

// newNonce returns a random 16-hex-char per-snapshot token (echoed back in
// Ack.nonce for end-to-end apply-confirmation correlation).
func newNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable in practice; a timestamp
		// nonce keeps correlation useful rather than panicking the loop.
		return fmt.Sprintf("t%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
