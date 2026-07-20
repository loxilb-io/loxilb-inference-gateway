/*
 * Copyright (c) 2025 LoxiLB Authors
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

// expfmt.go — the CONTROLLER-ONLY full metric-family decoder (two-decoder
// split, locked in 96-PATTERNS). The global AI controller needs whole
// families (TTFT histograms, token counters, ...) that the narrow hot-path
// lineparser deliberately ignores. Per the locked "don't hand-roll" rule
// this wraps the hardened prometheus/common/expfmt TextParser —
// no hand-rolled histogram/label parsing.
//
// The loxilb loxinet shim must NEVER import this path: its hot path stays
// on the narrow lineparser.
package aimetrics

import (
	"io"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// DecodeFamilies decodes a full Prometheus text-exposition body into metric
// families keyed by family name (e.g. "vllm:time_to_first_token_seconds").
// It is a thin wrapper around expfmt.TextParser.TextToMetricFamilies —
// malformed bodies return an error rather than partial silent data.
func DecodeFamilies(r io.Reader) (map[string]*dto.MetricFamily, error) {
	var parser expfmt.TextParser
	return parser.TextToMetricFamilies(r)
}
