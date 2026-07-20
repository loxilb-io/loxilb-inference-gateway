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

// V5 snapshot validation: every snapshot from the
// controller→loxilb trust boundary is untrusted-until-validated. Invalid ⇒
// typed error (drives NACK ACK_STATUS_REJECTED with Ack.error_detail), and
// the applier keeps last-good state with the staleness clock running — a bad
// snapshot is EQUIVALENT to an absent controller. NEVER partial-apply.
package aictrl

import (
	"errors"
	"fmt"
	"time"
)

// ApplierVersion is the aictrl.v1 protocol capability version this applier
// implements (Snapshot.min_applier_version forward-compat gate; starts at 1
// per frozen contract).
const ApplierVersion uint32 = 1

// ErrEpochReplay is the typed rejection for a replayed or lower epoch on the
// same boot_id (tamper/replay). Its message surfaces verbatim in
// Ack.error_detail.
var ErrEpochReplay = errors.New("epoch replay on same boot_id")

// ValidateSnapshot enforces the V5 input-validation list on one snapshot:
//
//  1. min_applier_version ≤ ApplierVersion (forward-compat reject);
//  2. epoch acceptance: (boot_id != lastBootID) || (epoch > lastEpoch) —
//     replay/lower-epoch on same boot_id ⇒ ErrEpochReplay;
//     a boot_id change resets the epoch floor (controller restart);
//  3. staleness_deadline sane: strictly in the future and no more than
//     10× decayWindow ahead of now;
//  4. every (service_key, ep_idx) ⊆ the locally-known EP set, no duplicate
//     ep_idx per service;
//  5. per entry: weight ≤ 100; state ∈ {UNSPECIFIED, ACTIVE, DRAINING,
//     DISABLED} (UNSPECIFIED=0 is the frozen-contract "no instruction, leave
//     local state" value — see aictrl.proto EpState).
//
// now and decayWindow are injected (fake-clock testable). Any error ⇒ the
// caller must reject the WHOLE snapshot (never partial-apply) and NACK with
// the error text as Ack.error_detail.
func ValidateSnapshot(s *Snapshot, known map[string][]uint32,
	lastBootID string, lastEpoch uint64,
	now time.Time, decayWindow time.Duration) error {

	if s == nil {
		return errors.New("nil snapshot")
	}

	// (1) forward-compat version gate.
	if s.GetMinApplierVersion() > ApplierVersion {
		return fmt.Errorf("min_applier_version %d > mine %d",
			s.GetMinApplierVersion(), ApplierVersion)
	}

	// (2) epoch acceptance: (boot_id != last) || (epoch > last_epoch).
	if s.GetBootId() == lastBootID && s.GetEpoch() <= lastEpoch {
		return fmt.Errorf("%w: epoch %d <= last accepted %d (boot_id %q)",
			ErrEpochReplay, s.GetEpoch(), lastEpoch, s.GetBootId())
	}

	// (3) staleness deadline sanity.
	deadline := time.UnixMilli(int64(s.GetStalenessDeadlineUnixMs()))
	if !deadline.After(now) {
		return fmt.Errorf("staleness_deadline %s not in the future (now %s)",
			deadline.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	}
	if maxAhead := now.Add(10 * decayWindow); decayWindow > 0 && deadline.After(maxAhead) {
		return fmt.Errorf("staleness_deadline %s more than 10x decay window (%s) ahead",
			deadline.UTC().Format(time.RFC3339Nano), decayWindow)
	}

	// (4)+(5) per-service / per-EP checks.
	for _, svc := range s.GetServices() {
		idxs, ok := known[svc.GetServiceKey()]
		if !ok {
			return fmt.Errorf("unknown service %q", svc.GetServiceKey())
		}
		knownIdx := make(map[uint32]bool, len(idxs))
		for _, i := range idxs {
			knownIdx[i] = true
		}
		seen := make(map[uint32]bool, len(svc.GetEps()))
		for _, ep := range svc.GetEps() {
			if !knownIdx[ep.GetEpIdx()] {
				return fmt.Errorf("unknown ep_idx %d for service %q",
					ep.GetEpIdx(), svc.GetServiceKey())
			}
			if seen[ep.GetEpIdx()] {
				return fmt.Errorf("duplicate ep_idx %d for service %q",
					ep.GetEpIdx(), svc.GetServiceKey())
			}
			seen[ep.GetEpIdx()] = true
			if ep.GetWeight() > 100 {
				return fmt.Errorf("weight %d > 100 at service %q ep_idx %d",
					ep.GetWeight(), svc.GetServiceKey(), ep.GetEpIdx())
			}
			switch ep.GetState() {
			case EpState_EP_STATE_UNSPECIFIED, EpState_EP_STATE_ACTIVE,
				EpState_EP_STATE_DRAINING, EpState_EP_STATE_DISABLED:
				// valid — UNSPECIFIED(0) is the frozen "no instruction" value.
			default:
				return fmt.Errorf("invalid state %d at service %q ep_idx %d",
					ep.GetState(), svc.GetServiceKey(), ep.GetEpIdx())
			}
		}
	}
	return nil
}
