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

import "time"

// effectiveReanchor derives the SotW re-anchor / applier-liveness-heartbeat
// interval from the operator flag, clamping it to at most one epoch.
//
// BUG#1 (live W5/W6): the identical-SotW re-anchor doubles as the applier
// liveness heartbeat — every emission refreshes the snapshot staleness deadline
// (now + 3×epoch). It MUST fire well inside that deadline or a healthy
// steady-state controller lets appliers decay Smart→Stale→Autonomous (false
// degradation / mode oscillation). engine.GeneratorConfig.withDefaults only
// clamps when ReanchorEvery<=0, so main previously bypassed it by always passing
// a positive opts.ReanchorSec (default 60 against a 30s deadline = guaranteed
// oscillation on any quiet fleet). This clamp is the real fix. Returns the
// effective interval and whether a too-large value was clamped (caller warns).
func effectiveReanchor(reanchorSec int, epochPeriod time.Duration) (time.Duration, bool) {
	reanchor := time.Duration(reanchorSec) * time.Second
	if reanchor > epochPeriod {
		return epochPeriod, true // too large: would breach the heartbeat margin
	}
	if reanchor <= 0 {
		return epochPeriod, false // 0 = auto (one epoch); withDefaults parity
	}
	return reanchor, false
}

// CtrlOptions defines the loxilb-ai-controller CLI flags with env fallbacks
// (go-flags, the cmd/loxilb-kv-agent precedent). Damping/emission defaults
// mirror the locked pkg/aictrl/engine envelope.
//
// SECURITY: --grpc-addr must bind the PRIVATE bus in production —
// the deploy script passes 10.0.0.13:18856 and the container publishes ports
// on 10.0.0.13 only, NEVER 0.0.0.0 on a public interface. mTLS is a
// documented deferral to.
type CtrlOptions struct {
	GrpcAddr    string `long:"grpc-addr" env:"AICTRL_GRPC_ADDR" default:":18856" description:"gRPC snapshot-bus listen address (private bus bind in production)"`
	MetricsAddr string `long:"metrics-addr" env:"AICTRL_METRICS_ADDR" default:":18857" description:"Prometheus /metrics listen address (CTRL-05)"`
	Registry    string `long:"registry" env:"AICTRL_REGISTRY" default:"/etc/loxilb/ai-controller.yaml" description:"Capability-registry YAML path (bench/testbed/ai-controller.yaml shape)"`

	// epoch cadence + CTRL-02 staleness consumption.
	EpochPeriodSec    int `long:"epoch-period-sec" env:"AICTRL_EPOCH_PERIOD_SEC" default:"10" description:"Decision/emission epoch period seconds"`
	ScrapeIntervalSec int `long:"scrape-interval-sec" env:"AICTRL_SCRAPE_INTERVAL_SEC" default:"5" description:"vLLM /metrics scrape interval seconds"`
	StaleBudgetSec    int `long:"stale-budget-sec" env:"AICTRL_STALE_BUDGET_SEC" default:"15" description:"Per-source staleness budget seconds (stale => excluded, neutral-100)"`

	// Locked damping envelope (P2).
	EwmaAlpha  float64 `long:"ewma-alpha" env:"AICTRL_EWMA_ALPHA" default:"0.3" description:"EWMA smoothing factor alpha"`
	DeadBand   float64 `long:"dead-band" env:"AICTRL_DEAD_BAND" default:"5" description:"Dead-band hold width in weight points"`
	MaxStepPct uint32  `long:"max-step-pct" env:"AICTRL_MAX_STEP_PCT" default:"20" description:"Max weight movement per epoch in points"`

	// P6 churn guard / SotW re-anchor. The re-anchor doubles as the applier
	// liveness heartbeat and is clamped to one epoch in main.go (BUG#1): it must
	// fire well inside the 3×epoch staleness deadline or steady-state appliers
	// oscillate Smart→Autonomous. 0 = auto (one epoch); values > epoch are clamped.
	ReanchorSec int `long:"reanchor-sec" env:"AICTRL_REANCHOR_SEC" default:"0" description:"Identical-SotW re-anchor / applier heartbeat interval seconds (0=auto=one epoch; clamped to epoch to prevent mode oscillation)"`

	// VAL-02 negative control: HARNESS-ONLY, default off. Inverts
	// the weight ORDER over fresh prefill EPs AFTER the damping pipeline
	// (w'_i = min_w + max_w - w_i); logs loudly on every emission and exports
	// aictrl_negative_control_active=1 so the G1 harness can self-confirm.
	NegativeControlInvert bool `long:"negative-control-invert" env:"AICTRL_NEGATIVE_CONTROL_INVERT" description:"VAL-02 negative-control arm: invert fresh-prefill weight order (harness only)"`

	// LMC-02/LMC-03 LMCache cost-term sub-knobs. DEFAULT-OFF
	// discipline: with AICTRL_LMC_COST unset the engine's LMCache
	// cost term is inert and the emitted snapshot is byte-identical to
	// (the cost-active gauge reads 0). The lmcache:* families are
	// still COLLECTED off the existing vLLM /metrics body (Pattern 1
	// piggyback, LMC-02 lands live) even with the cost term OFF — collection
	// is independent of the cost knob. The /lookup poller is a second
	// default-OFF gate: an empty AICTRL_LMC_LOOKUP_URL means it is never
	// started (getenv+empty-return-first, ai_ctrl_applier.go discipline).
	LmcCostEnabled bool    `long:"lmc-cost" env:"AICTRL_LMC_COST" description:"LMC-03: enable the bounded LMCache cost term in ComputeWeights (default-OFF => byte-identical to)"`
	LmcMaxPts      float64 `long:"lmc-max-pts" env:"AICTRL_LMC_MAX_PTS" default:"15" description:"LMC-03: max weight points the LMCache cost term may bias an EP (bounded [-N,+N])"`
	LmcStaleSec    int     `long:"lmc-stale-sec" env:"AICTRL_LMC_STALE_SEC" default:"15" description:"LMC-03: LMCache-signal staleness budget seconds (stale/absent => cost term decays to neutral, never zero-fill)"`

	// TTFT-02/03 Expected-TTFT weight-term sub-knobs.
	// DEFAULT-OFF discipline mirrors the Lmc* block field-for-field:
	// with AICTRL_TTFT_WEIGHT unset the engine's TTFT term is inert and the
	// emitted snapshot is byte-identical (aictrl_ttft_active reads 0). An
	// empty AICTRL_TTFT_COEF_FILE means the coefficients model is NEVER
	// loaded — the term is STRUCTURALLY off (the LmcLookupURL
	// empty-never-started discipline). Arming (AICTRL_TTFT_WEIGHT set) with
	// NO coefficients file is a boot-time FATAL: a term armed without a
	// model is an operator misconfig, never a silent no-op.
	TtftEnabled         bool    `long:"ttft-weight" env:"AICTRL_TTFT_WEIGHT" description:"TTFT-03: enable the bounded Expected-TTFT weight term (default-OFF => byte-identical weights)"`
	TtftMaxPts          float64 `long:"ttft-max-pts" env:"AICTRL_TTFT_MAX_PTS" default:"15" description:"TTFT-03: max weight points the Expected-TTFT term may bias an EP (bounded [-N,+N])"`
	TtftStaleSec        int     `long:"ttft-stale-sec" env:"AICTRL_TTFT_STALE_SEC" default:"15" description:"TTFT-03: TTFT feature-carrier staleness budget seconds (stale/absent => term decays to neutral, never zero-fill)"`
	TtftCoefFile        string  `long:"ttft-coef-file" env:"AICTRL_TTFT_COEF_FILE" description:"TTFT-02: Expected-TTFT coefficients YAML path (fit-tool output; empty => model never loaded, term structurally OFF)"`
	TtftInvert          bool    `long:"ttft-invert" env:"AICTRL_TTFT_INVERT" description:"VAL-02: invert the Expected-TTFT term sign (negative-control harness arm — NEVER in the real arm)"`
	TtftRefPromptTokens int     `long:"ttft-ref-prompt-tokens" env:"AICTRL_TTFT_REF_PROMPT_TOKENS" default:"4096" description:"TTFT-02: workload REFERENCE prompt length (tokens) for the log_prompt_tokens feature slot (fit covariate only — shifts every EP identically)"`

	// FeatureSnapFile is the per-epoch per-EP feature-vector snapshot JSONL
	// (RESEARCH Open Question 3 — a FILE artifact on .13, deliberately NOT a
	// per-feature Prometheus series: cardinality). One line per EP per epoch
	// ({ts, epoch, ep, features{...}, alpha, armed} — the cmd/aictrl-ttft-fit
	// SnapshotRecord contract) makes the offline gate evaluation exactly
	// reproducible. Empty => the writer is NEVER started (no open, no write).
	FeatureSnapFile string `long:"feature-snap-file" env:"AICTRL_FEATURE_SNAP_FILE" description:": per-epoch per-EP feature-snapshot JSONL path (offline fit/gate reproducibility artifact; empty => never written, default-OFF)"`

	LogLevel string `long:"log-level" env:"AICTRL_LOG_LEVEL" default:"info" description:"Log level (trace|debug|info|warn|error)"`
}
