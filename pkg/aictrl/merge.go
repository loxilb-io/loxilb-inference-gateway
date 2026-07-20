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

// Pure-intersection merge with local health (P4): local
// health ALWAYS wins. The controller is advisory — its directives can only
// SHRINK routing eligibility, never widen it.
package aictrl

// EpDirective is one controller instruction for one endpoint, post-α
// (Weight here is the EFFECTIVE weight the caller intends to write).
type EpDirective struct {
	ServiceKey string
	EpIdx      int
	// Weight is the effective routing weight [0,100] (already α-blended
	// via EffectiveWeight by the caller).
	Weight uint32
	// State is the desired lifecycle state (aictrl.v1 EpState; numeric
	// values 1/2/3 mirror the C packed-atomic encoding, 0 = no instruction).
	State EpState
}

// Packed renders the directive as the C-side pd_ctrl_ep[] instruction word:
// state in bits 31-24 (PD_CTRL_ST_*, lockstep with the frozen aictrl.v1
// EpState enum), weight in bits 7-0. A fully-zero word (0) means "no
// instruction" — every C selector guard skips it (contract).
func (d EpDirective) Packed() uint32 {
	return uint32(d.State)<<24 | (d.Weight & 0xff)
}

// MergeVerdict is the PURE-INTERSECTION merge of a controller directive with
// local health (P4/G4). If the EP is locally healthy the directive passes
// through unchanged. If the EP is locally UNHEALTHY (local CB open / probe
// down / locally excluded), the directive is neutered to the no-op zero word
// and overridden=true — the caller MUST suppress the Sink write entirely and
// increment loxilb_pd_ctrl_override_events_total.
//
// G4 INVARIANT (non-resurrection): the applier NEVER writes anything
// that could widen local eligibility. A snapshot weight/ACTIVE state can never
// convert a locally-unhealthy EP into a selectable one — local health checks
// also run per-tier AFTER controller fold-in on the C side, so this
// Go-side intersection is defense-in-depth, not the only line.
func MergeVerdict(d EpDirective, healthy bool) (apply EpDirective, overridden bool) {
	if healthy {
		return d, false
	}
	// Neutered no-op: zero weight + UNSPECIFIED state ⇒ Packed==0.
	// The caller suppresses the write (writing 0 could CLEAR a prior
	// controller DISABLED instruction — itself a widening — so suppression,
	// not zero-write, is the contract).
	return EpDirective{ServiceKey: d.ServiceKey, EpIdx: d.EpIdx}, true
}
