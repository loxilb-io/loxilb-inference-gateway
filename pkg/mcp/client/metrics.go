/*
 * Copyright (c) 2026 NetLOX Inc
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

package client

import (
	"fmt"
	"maps"
	"path"
	"sort"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// Sample is one time-series sample of a metric family.
type Sample struct {
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
}

// Family is a parsed Prometheus metric family, capped for LLM consumption.
type Family struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Help         string   `json:"help,omitempty"`
	TotalSamples int      `json:"total_samples"`
	Samples      []Sample `json:"samples"`
}

// DefaultMaxSamples caps samples returned per family unless overridden.
const DefaultMaxSamples = 200

// ParseFamilies parses Prometheus exposition text, keeping families whose
// name matches any glob (all families when globs is empty). Histogram and
// summary series are flattened into _count/_sum/_bucket(le)/quantile samples.
func ParseFamilies(text string, globs []string, maxSamples int) ([]Family, error) {
	if maxSamples <= 0 {
		maxSamples = DefaultMaxSamples
	}
	var parser expfmt.TextParser
	mfs, err := parser.TextToMetricFamilies(strings.NewReader(text))
	if err != nil {
		return nil, fmt.Errorf("parse metrics text: %w", err)
	}

	names := make([]string, 0, len(mfs))
	for name := range mfs {
		if matchesAnyGlob(globs, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	out := make([]Family, 0, len(names))
	for _, name := range names {
		mf := mfs[name]
		fam := Family{
			Name: name,
			Type: strings.ToLower(mf.GetType().String()),
			Help: mf.GetHelp(),
		}
		var samples []Sample
		for _, m := range mf.GetMetric() {
			labels := labelMap(m)
			switch mf.GetType() {
			case dto.MetricType_COUNTER:
				samples = append(samples, Sample{Labels: labels, Value: m.GetCounter().GetValue()})
			case dto.MetricType_GAUGE:
				samples = append(samples, Sample{Labels: labels, Value: m.GetGauge().GetValue()})
			case dto.MetricType_UNTYPED:
				samples = append(samples, Sample{Labels: labels, Value: m.GetUntyped().GetValue()})
			case dto.MetricType_HISTOGRAM:
				h := m.GetHistogram()
				samples = append(samples,
					Sample{Labels: withLabel(labels, "series", "count"), Value: float64(h.GetSampleCount())},
					Sample{Labels: withLabel(labels, "series", "sum"), Value: h.GetSampleSum()})
				for _, b := range h.GetBucket() {
					le := fmt.Sprintf("%g", b.GetUpperBound())
					samples = append(samples, Sample{
						Labels: withLabel(labels, "le", le),
						Value:  float64(b.GetCumulativeCount()),
					})
				}
			case dto.MetricType_SUMMARY:
				s := m.GetSummary()
				samples = append(samples,
					Sample{Labels: withLabel(labels, "series", "count"), Value: float64(s.GetSampleCount())},
					Sample{Labels: withLabel(labels, "series", "sum"), Value: s.GetSampleSum()})
				for _, q := range s.GetQuantile() {
					samples = append(samples, Sample{
						Labels: withLabel(labels, "quantile", fmt.Sprintf("%g", q.GetQuantile())),
						Value:  q.GetValue(),
					})
				}
			}
		}
		fam.TotalSamples = len(samples)
		if len(samples) > maxSamples {
			samples = samples[:maxSamples]
		}
		fam.Samples = samples
		out = append(out, fam)
	}
	return out, nil
}

func matchesAnyGlob(globs []string, name string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if ok, err := path.Match(g, name); err == nil && ok {
			return true
		}
	}
	return false
}

func labelMap(m *dto.Metric) map[string]string {
	if len(m.GetLabel()) == 0 {
		return nil
	}
	out := make(map[string]string, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		out[lp.GetName()] = lp.GetValue()
	}
	return out
}

func withLabel(base map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(base)+1)
	maps.Copy(out, base)
	out[k] = v
	return out
}
