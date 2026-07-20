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

package main

import (
	"os"
	"testing"
	"time"

	flags "github.com/jessevdk/go-flags"
)

// TestEffectiveReanchor locks BUG#1: the re-anchor is the applier liveness
// heartbeat and must never exceed one epoch, or steady-state appliers oscillate
// Smart→Autonomous. The regression that shipped live was the 60s default flag
// (options.go) SHADOWING engine.withDefaults — this test pins that the clamp,
// not withDefaults, is what enforces the invariant.
func TestEffectiveReanchor(t *testing.T) {
	const epoch = 10 * time.Second
	tests := []struct {
		name        string
		reanchorSec int
		epoch       time.Duration
		want        time.Duration
		wantClamped bool
	}{
		{"live-regression-60s-default-clamped", 60, epoch, epoch, true},
		{"just-over-one-epoch-clamped", 11, epoch, epoch, true},
		{"exactly-one-epoch-honored", 10, epoch, epoch, false},
		{"sub-epoch-honored", 5, epoch, 5 * time.Second, false},
		{"interim-workaround-10s-honored", 10, epoch, epoch, false},
		{"zero-is-auto-one-epoch", 0, epoch, epoch, false},
		{"negative-is-auto-one-epoch", -1, epoch, epoch, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, clamped := effectiveReanchor(tc.reanchorSec, tc.epoch)
			if got != tc.want {
				t.Errorf("effectiveReanchor(%d, %s) = %s; want %s", tc.reanchorSec, tc.epoch, got, tc.want)
			}
			if clamped != tc.wantClamped {
				t.Errorf("effectiveReanchor(%d, %s) clamped = %v; want %v", tc.reanchorSec, tc.epoch, clamped, tc.wantClamped)
			}
			// Invariant: the effective heartbeat must always fire strictly
			// inside the 3×epoch staleness deadline, with >=2 epochs of margin.
			if got > tc.epoch {
				t.Errorf("effectiveReanchor returned %s > one epoch %s — breaches heartbeat margin", got, tc.epoch)
			}
		})
	}
}

// TestCtrlOptionsLMCacheDefaults locks the LMC-03 default-OFF contract
// : with no env set, the LMCache cost term is OFF and the bounded
// max-points + staleness budget hold their locked 15/15 defaults. This is
// the flag-layer half of "unset AICTRL_LMC_COST => byte-identical to."
func TestCtrlOptionsLMCacheDefaults(t *testing.T) {
	// Ensure a clean environment so go-flags applies the struct-tag defaults
	// (unset + restore on cleanup; an empty string would break bool parsing).
	for _, k := range []string{"AICTRL_LMC_COST", "AICTRL_LMC_MAX_PTS", "AICTRL_LMC_STALE_SEC"} {
		if old, ok := os.LookupEnv(k); ok {
			os.Unsetenv(k)
			t.Cleanup(func() { os.Setenv(k, old) })
		}
	}

	var o CtrlOptions
	p := flags.NewParser(&o, flags.Default)
	if _, err := p.ParseArgs(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if o.LmcCostEnabled {
		t.Errorf("LmcCostEnabled default = true; want false (default-OFF contract)")
	}
	if o.LmcMaxPts != 15 {
		t.Errorf("LmcMaxPts default = %v; want 15", o.LmcMaxPts)
	}
	if o.LmcStaleSec != 15 {
		t.Errorf("LmcStaleSec default = %d; want 15", o.LmcStaleSec)
	}
}

// TestCtrlOptionsLMCacheEnvOverride proves the AICTRL_LMC_* env vars parse and
// override the defaults — the arm the LMC-04 A/B toggles.
func TestCtrlOptionsLMCacheEnvOverride(t *testing.T) {
	t.Setenv("AICTRL_LMC_COST", "true")
	t.Setenv("AICTRL_LMC_MAX_PTS", "22")
	t.Setenv("AICTRL_LMC_STALE_SEC", "9")

	var o CtrlOptions
	p := flags.NewParser(&o, flags.Default)
	if _, err := p.ParseArgs(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !o.LmcCostEnabled {
		t.Errorf("LmcCostEnabled = false; want true (AICTRL_LMC_COST=true)")
	}
	if o.LmcMaxPts != 22 {
		t.Errorf("LmcMaxPts = %v; want 22", o.LmcMaxPts)
	}
	if o.LmcStaleSec != 9 {
		t.Errorf("LmcStaleSec = %d; want 9", o.LmcStaleSec)
	}
}
