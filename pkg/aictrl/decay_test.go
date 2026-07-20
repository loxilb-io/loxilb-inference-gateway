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

package aictrl

import (
	"math"
	"testing"
	"time"
)

// Fixed fake-clock anchors — explicit time.Time values, no wall clock.
var (
	tBase     = time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	tDeadline = tBase.Add(30 * time.Second) // deadline = 3× epoch (10s)
	tWindow   = 30 * time.Second            // decay window
)

func TestAlpha(t *testing.T) {
	cases := []struct {
		name string
		now  time.Time
		want float64
	}{
		{"well before deadline (Smart)", tBase, 1.0},
		{"1ns before deadline (Smart)", tDeadline.Add(-time.Nanosecond), 1.0},
		{"exactly at deadline (continuity boundary)", tDeadline, 1.0},
		{"1s into window", tDeadline.Add(1 * time.Second), 1.0 - 1.0/30.0},
		{"mid-window (Stale)", tDeadline.Add(15 * time.Second), 0.5},
		{"29s into window", tDeadline.Add(29 * time.Second), 1.0 - 29.0/30.0},
		{"exactly at window end (Autonomous)", tDeadline.Add(tWindow), 0.0},
		{"after window end (Autonomous)", tDeadline.Add(5 * time.Minute), 0.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Alpha(tc.now, tDeadline, tWindow)
			if math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("Alpha(%s) = %v, want %v", tc.now, got, tc.want)
			}
			if got < 0 || got > 1 {
				t.Fatalf("Alpha out of [0,1]: %v", got)
			}
		})
	}
}

func TestAlphaZeroWindow(t *testing.T) {
	// Degenerate window: step at deadline, never negative/NaN.
	if got := Alpha(tDeadline.Add(-time.Second), tDeadline, 0); got != 1.0 {
		t.Fatalf("pre-deadline zero-window Alpha = %v, want 1", got)
	}
	if got := Alpha(tDeadline, tDeadline, 0); got != 0.0 {
		t.Fatalf("at-deadline zero-window Alpha = %v, want 0", got)
	}
}

func TestAlphaContinuityAtDeadline(t *testing.T) {
	// P5/G2: NO step change at the deadline instant. Sample α densely across
	// the boundary; consecutive samples 100ms apart may differ by at most
	// window-slope*dt + epsilon.
	dt := 100 * time.Millisecond
	maxStep := float64(dt)/float64(tWindow) + 1e-9
	prev := Alpha(tDeadline.Add(-2*time.Second), tDeadline, tWindow)
	for off := -2 * time.Second; off <= 2*time.Second; off += dt {
		cur := Alpha(tDeadline.Add(off), tDeadline, tWindow)
		if math.Abs(cur-prev) > maxStep {
			t.Fatalf("discontinuity at offset %s: |%v - %v| > %v", off, cur, prev, maxStep)
		}
		prev = cur
	}
}

func TestEffectiveWeight(t *testing.T) {
	cases := []struct {
		name  string
		w     uint32
		alpha float64
		want  uint32
	}{
		{"alpha=1 applies snapshot weight verbatim", 30, 1.0, 30},
		{"alpha=1 weight 0", 0, 1.0, 0},
		{"alpha=1 weight 100 neutral", 100, 1.0, 100},
		{"alpha=0 always neutral 100", 30, 0.0, 100},
		{"alpha=0 weight 0 neutral", 0, 0.0, 100},
		{"alpha=0.5 halfway to neutral", 30, 0.5, 65},
		{"alpha=0.5 weight 0", 0, 0.5, 50},
		{"rounding: 0.25 of w=30", 30, 0.25, 83}, // 100 − 0.25·70 = 82.5, math.Round → 83
		{"clamped alpha > 1", 30, 1.5, 30},
		{"clamped alpha < 0", 30, -0.5, 100},
		{"out-of-range weight clamps to 100 at alpha=1", 250, 1.0, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveWeight(tc.w, tc.alpha)
			if got != tc.want {
				t.Fatalf("EffectiveWeight(%d, %v) = %d, want %d", tc.w, tc.alpha, got, tc.want)
			}
			if got > 100 {
				t.Fatalf("EffectiveWeight out of [0,100]: %d", got)
			}
		})
	}
}

// TestEffectiveWeightContinuity — the P5/G2 continuity property:
// |EffectiveWeight(w, α1) − EffectiveWeight(w, α2)| ≤ ceil(100·|α1−α2|)
// across the full α ladder for every weight, including the boundary instants
// around the deadline (no step change exactly when degraded).
func TestEffectiveWeightContinuity(t *testing.T) {
	weights := []uint32{0, 1, 30, 50, 99, 100}
	for _, w := range weights {
		// Walk α as the ladder actually produces it: via Alpha at 1s ticks
		// across [deadline−5s, deadline+window+5s].
		var prevAlpha float64
		first := true
		for off := -5 * time.Second; off <= tWindow+5*time.Second; off += time.Second {
			a := Alpha(tDeadline.Add(off), tDeadline, tWindow)
			if !first {
				e1 := float64(EffectiveWeight(w, prevAlpha))
				e2 := float64(EffectiveWeight(w, a))
				bound := math.Ceil(100.0 * math.Abs(prevAlpha-a))
				if math.Abs(e1-e2) > bound {
					t.Fatalf("w=%d: |EW(%v)−EW(%v)| = %v > ceil(100·Δα) = %v",
						w, prevAlpha, a, math.Abs(e1-e2), bound)
				}
			}
			prevAlpha = a
			first = false
		}
	}
}

func TestModeFromAlpha(t *testing.T) {
	cases := []struct {
		alpha float64
		want  Mode
	}{
		{1.0, ModeSmart},
		{0.999, ModeStale},
		{0.5, ModeStale},
		{0.001, ModeStale},
		{0.0, ModeAutonomous},
		{-0.1, ModeAutonomous},
	}
	for _, tc := range cases {
		if got := ModeFromAlpha(tc.alpha); got != tc.want {
			t.Fatalf("ModeFromAlpha(%v) = %v, want %v", tc.alpha, got, tc.want)
		}
	}
	// Metric encoding lockstep (loxilb_pd_ctrl_mode: 0/1/2).
	if ModeAutonomous != 0 || ModeStale != 1 || ModeSmart != 2 {
		t.Fatal("Mode numeric values must match the loxilb_pd_ctrl_mode gauge encoding")
	}
}
