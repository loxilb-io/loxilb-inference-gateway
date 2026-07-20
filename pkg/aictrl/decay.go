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

// Package aictrl — : the continuous α(t) decay
// mechanism. ONE mechanism, not three code paths (P5): the
// applier rewrites effective_weight = 100 + α·(w−100) at 1 Hz; the
// Smart/Stale/Autonomous "mode" is a DERIVED OBSERVABLE LABEL of α, never a
// routing branch. Autonomous is reached by α→0 followed by ONE mode=0 write
// to the C side — after which behavior is byte-identical (G3).
//
// All functions in this file are pure (fake-clock testable, CGO_ENABLED=0,
// stdlib-only) — C stays dumb, Go owns policy.
package aictrl

import (
	"math"
	"time"
)

// Mode is the observable Smart/Stale/Autonomous label DERIVED from α.
// Numeric values match the Prometheus loxilb_pd_ctrl_mode gauge encoding
// : 0 autonomous / 1 stale / 2 smart. Mode is NEVER a code path —
// see the package comment.
type Mode int

const (
	// ModeAutonomous — α == 0: controller influence fully decayed; the data
	// plane behaves exactly as if the controller never existed.
	ModeAutonomous Mode = 0
	// ModeStale — 0 < α < 1: the staleness deadline passed; influence decays
	// linearly over the decay window (: 30s).
	ModeStale Mode = 1
	// ModeSmart — α == 1: the last accepted snapshot's deadline is unexpired.
	ModeSmart Mode = 2
)

// String returns the human-readable mode label.
func (m Mode) String() string {
	switch m {
	case ModeSmart:
		return "smart"
	case ModeStale:
		return "stale"
	default:
		return "autonomous"
	}
}

// ModeFromAlpha derives the observable mode label from the decay scalar.
// α==1 ⇒ Smart, 0<α<1 ⇒ Stale, α==0 ⇒ Autonomous.
func ModeFromAlpha(alpha float64) Mode {
	switch {
	case alpha >= 1.0:
		return ModeSmart
	case alpha > 0.0:
		return ModeStale
	default:
		return ModeAutonomous
	}
}

// Alpha returns the continuous controller-influence scalar α(t) ∈ [0,1]:
//
//	α = 1.0                                   while now < deadline   (Smart)
//	α = 1.0 − elapsed/decayWindow  over [deadline, deadline+window)  (Stale)
//	α = 0.0                        at/after deadline+window     (Autonomous)
//
// The function is CONTINUOUS at the deadline instant (α(deadline) == 1.0,
// then decays linearly) — no step change exactly when degraded (P5/G2).
// A non-positive decayWindow degrades to a step at the deadline (α=0 once
// expired) — callers always pass default 30s.
func Alpha(now, deadline time.Time, decayWindow time.Duration) float64 {
	if now.Before(deadline) {
		return 1.0
	}
	if decayWindow <= 0 {
		return 0.0
	}
	elapsed := now.Sub(deadline)
	if elapsed >= decayWindow {
		return 0.0
	}
	return 1.0 - float64(elapsed)/float64(decayWindow)
}

// EffectiveWeight blends a snapshot weight toward the neutral value 100 by
// the decay scalar α:
//
//	effective = round(100 + α·(w − 100)), clamped to [0,100]
//
// α=1 applies the snapshot weight verbatim (Smart); α=0 yields 100 — the
// arithmetic no-op vs controller-absent behavior (G3-friendly neutral);
// intermediate α interpolates linearly (Stale). Snapshot weights are already
// validated ≤ 100 (V5), so the result is monotone toward neutral, never an
// amplification.
func EffectiveWeight(w uint32, alpha float64) uint32 {
	if alpha < 0 {
		alpha = 0
	} else if alpha > 1 {
		alpha = 1
	}
	eff := math.Round(100.0 + alpha*(float64(w)-100.0))
	if eff < 0 {
		eff = 0
	} else if eff > 100 {
		eff = 100
	}
	return uint32(eff)
}
