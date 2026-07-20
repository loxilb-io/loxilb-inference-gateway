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

// aictrl-ttft-fit — offline Expected-TTFT fit + gate-evaluation tool
// (TTFT-02).
//
// Pipeline: aiperf per-request TTFT (EP-attributed via
// x-request-id contract) + controller epoch feature snapshots
// AICTRL_FEATURE_SNAP_FILE JSONL) → censor the fat tail (§RQ5) → gonum
// QR-OLS on log-TTFT (§RQ6) → pre-registered Gate 1/2 + censored-fraction
// evaluation per regime cell (§RQ3/§RQ4) → versioned coefficients YAML
// (strict-loaded by pkg/aictrl/engine.LoadTtftModel) + human-readable gate
// report.
//
// Threshold DEFAULTS are the pre-registration (A4-A9, gates.go); overrides
// are flags whose use is printed into the gate report (— any
// deviation from the registration is visible in the artifact).
//
// Exit codes: 0 = fit + emission ok AND overall gate PASS;
//             3 = fit + emission ok but overall gate verdict is not PASS
// (the coefficients file is still emitted —
//                 observability posture consumes it unarmed);
//             1 = operational error (bad inputs, rank-deficient fit, IO).
//
// gonum NEVER enters the runtime dep graph — this standalone
// main package is the only importer.

package main

import (
	"fmt"
	"io"
	"os"
	"time"

	flags "github.com/jessevdk/go-flags"
	yaml "gopkg.in/yaml.v3"

	"github.com/loxilb-io/loxilb/pkg/aictrl/engine"
)

// FitOptions defines the CLI flags with env fallbacks (go-flags, the
// cmd/loxilb-ai-controller/options.go shape). Threshold fields carry NO
// go-flags `default` tags: they are pre-populated from the pre-registered
// gates.go consts by defaultOptions (single source of truth — a literal
// in a tag could silently drift from the registration).
type FitOptions struct {
	RequestsGlob  string `long:"requests-glob" env:"TTFTFIT_REQUESTS_GLOB" description:"Glob over aiperf per-request exports (profile_export.jsonl)" required:"true"`
	SnapshotsFile string `long:"snapshots-file" env:"TTFTFIT_SNAPSHOTS_FILE" description:"Controller epoch feature-snapshot JSONL (AICTRL_FEATURE_SNAP_FILE)" required:"true"`
	OutCoef       string `long:"out-coef" env:"TTFTFIT_OUT_COEF" default:"ttft-coefficients.yaml" description:"Output coefficients YAML path (TtftModel schema)"`
	GateReport    string `long:"gate-report" env:"TTFTFIT_GATE_REPORT" description:"Gate report output path (empty = stdout)"`

	// Pre-registered §RQ3/4/5 thresholds (defaults = A4-A9 consts).
	CensorSec       float64 `long:"censor-sec" env:"TTFTFIT_CENSOR_SEC" description:"Right-censor threshold seconds (A9 pre-registered 30)"`
	Gate1P50        float64 `long:"gate1-p50" env:"TTFTFIT_GATE1_P50" description:"Gate 1 P50 |rel err| threshold (A4 pre-registered 0.30)"`
	Gate1P90        float64 `long:"gate1-p90" env:"TTFTFIT_GATE1_P90" description:"Gate 1 P90 |rel err| threshold (A4 pre-registered 1.00)"`
	Gate2Accuracy   float64 `long:"gate2-accuracy" env:"TTFTFIT_GATE2_ACCURACY" description:"Gate 2 pooled pairwise ranking accuracy threshold (A5 pre-registered 0.70)"`
	KendallFlag     float64 `long:"kendall-flag" env:"TTFTFIT_KENDALL_FLAG" description:"Kendall tau report-only flag level (A6 pre-registered 0.3)"`
	CensoredFracMax float64 `long:"censored-frac-max" env:"TTFTFIT_CENSORED_FRAC_MAX" description:"Per-cell censored-fraction data-quality gate (A9 pre-registered 0.05)"`
	MinCellRequests int     `long:"min-cell-requests" env:"TTFTFIT_MIN_CELL_REQUESTS" description:"Gate 1 minimum uncensored requests per gated cell (A8 pre-registered 50)"`
	MinWindowPairs  int     `long:"min-window-pairs" env:"TTFTFIT_MIN_WINDOW_PAIRS" description:"Gate 2 minimum scored window-pairs per gated rate (A8 pre-registered 30)"`
	WindowSec       float64 `long:"window-sec" env:"TTFTFIT_WINDOW_SEC" description:"Gate 2 ranking window seconds (pre-registered 60)"`

	RefPromptTokens float64  `long:"ref-prompt-tokens" env:"TTFTFIT_REF_PROMPT_TOKENS" description:"Reference prompt length for Gate 2 predictions (0 = training-set median)"`
	InfoRates       []string `long:"info-rate" env:"TTFTFIT_INFO_RATES" env-delim:"," description:"Rate labels treated INFO-only (saturated — the G1 lesson; default 2.0)"`
	RateLabel       string   `long:"rate-label" env:"TTFTFIT_RATE_LABEL" description:"Force one rate label for ALL inputs (overrides path attribution)"`
	ModelVersion    int      `long:"model-version" env:"TTFTFIT_MODEL_VERSION" description:"Emitted model_version (default 1)"`
}

// defaultOptions returns FitOptions pre-populated with the PRE-REGISTERED
// gate defaults (gates.go A4-A9 consts). go-flags retains pre-populated
// values for flags the caller does not pass.
func defaultOptions() FitOptions {
	return FitOptions{
		CensorSec:       defaultCensorSeconds,
		Gate1P50:        defaultGate1P50RelErr,
		Gate1P90:        defaultGate1P90RelErr,
		Gate2Accuracy:   defaultGate2PairwiseAccuracy,
		KendallFlag:     defaultKendallFlagTau,
		CensoredFracMax: defaultCensoredFracMax,
		MinCellRequests: defaultMinCellRequests,
		MinWindowPairs:  defaultMinWindowPairs,
		WindowSec:       defaultWindowSeconds,
		InfoRates:       []string{defaultInfoRate},
		ModelVersion:    1,
	}
}

// thresholdOverrides lists every deviation from the pre-registered
// defaults for the gate report (: overrides must be VISIBLE).
func thresholdOverrides(o FitOptions) []string {
	var out []string
	add := func(name string, got, want float64) {
		if got != want {
			out = append(out, fmt.Sprintf("%s=%g (pre-registered %g)", name, got, want))
		}
	}
	add("censor-sec", o.CensorSec, defaultCensorSeconds)
	add("gate1-p50", o.Gate1P50, defaultGate1P50RelErr)
	add("gate1-p90", o.Gate1P90, defaultGate1P90RelErr)
	add("gate2-accuracy", o.Gate2Accuracy, defaultGate2PairwiseAccuracy)
	add("kendall-flag", o.KendallFlag, defaultKendallFlagTau)
	add("censored-frac-max", o.CensoredFracMax, defaultCensoredFracMax)
	add("min-cell-requests", float64(o.MinCellRequests), defaultMinCellRequests)
	add("min-window-pairs", float64(o.MinWindowPairs), defaultMinWindowPairs)
	add("window-sec", o.WindowSec, defaultWindowSeconds)
	return out
}

// marshalModel renders the coefficients YAML (engine.TtftModel schema).
func marshalModel(m *engine.TtftModel) ([]byte, error) {
	b, err := yaml.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("coefficients marshal: %w", err)
	}
	return b, nil
}

// refPromptTokens resolves the Gate 2 reference prompt length: the flag if
// given, else the training set's median prompt length (a data-driven
// reference, documented in the report).
func refPromptTokens(opts FitOptions, rows []Row, report io.Writer) float64 {
	if opts.RefPromptTokens > 0 {
		return opts.RefPromptTokens
	}
	v := make([]float64, 0, len(rows))
	for _, r := range rows {
		if !r.Censored {
			v = append(v, r.Req.PromptTokens)
		}
	}
	ref := medianOf(v)
	fmt.Fprintf(report, "REF prompt-tokens = training median %.0f (no --ref-prompt-tokens given)\n", ref)
	return ref
}

func run(opts FitOptions) (int, error) {
	report := os.Stdout
	if opts.GateReport != "" {
		f, err := os.Create(opts.GateReport)
		if err != nil {
			return 1, fmt.Errorf("gate report create: %w", err)
		}
		defer f.Close()
		report = f
	}

	reqs, _, err := ingestRequests(opts.RequestsGlob, opts.RateLabel, report)
	if err != nil {
		return 1, err
	}
	snaps, err := loadSnapshots(opts.SnapshotsFile)
	if err != nil {
		return 1, err
	}
	rows, _ := joinRows(reqs, snaps, opts.CensorSec, report)
	if len(rows) == 0 {
		return 1, fmt.Errorf("no joined rows — nothing to fit")
	}

	fit, err := fitOLS(rows, report)
	if err != nil {
		return 1, err
	}

	outcome := runGates(opts, fit, rows, snaps, report)

	provenance := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, r := range reqs {
		if !seen[r.Source] {
			seen[r.Source] = true
			provenance = append(provenance, r.Source)
		}
	}
	provenance = append(provenance, "snapshots:"+opts.SnapshotsFile,
		"ttft-unit:log-seconds")

	thresholds := engine.TtftGateThresholds{
		P50RelErr:        opts.Gate1P50,
		P90RelErr:        opts.Gate1P90,
		PairwiseAccuracy: opts.Gate2Accuracy,
		KendallFlag:      opts.KendallFlag,
		CensorSeconds:    opts.CensorSec,
		CensoredFracMax:  opts.CensoredFracMax,
	}
	model := buildModel(fit, thresholds, outcome.Verdicts, provenance,
		opts.ModelVersion, time.Now().UTC().Format(time.RFC3339))
	if err := emitModel(model, opts.OutCoef); err != nil {
		return 1, err
	}
	fmt.Fprintf(report, "EMIT coefficients=%s model_version=%d overall=%s\n",
		opts.OutCoef, opts.ModelVersion, outcome.Verdicts["overall"])

	if outcome.Verdicts["overall"] != verdictPass {
		return 3, nil
	}
	return 0, nil
}

func main() {
	opts := defaultOptions()
	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	if _, err := parser.Parse(); err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			fmt.Println(err)
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code, err := run(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aictrl-ttft-fit:", err)
	}
	os.Exit(code)
}
