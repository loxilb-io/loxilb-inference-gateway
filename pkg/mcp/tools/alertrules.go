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

package tools

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// promRulesFile mirrors the Prometheus alerting-rules file layout
// (deploy/monitoring/prometheus/rules/loxilb-alerts.yml).
type promRulesFile struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert       string            `yaml:"alert"`
			Record      string            `yaml:"record"`
			Expr        string            `yaml:"expr"`
			For         string            `yaml:"for"`
			Labels      map[string]string `yaml:"labels"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

// LoadAlertRules parses a Prometheus rules YAML into the catalog format,
// skipping recording rules.
func LoadAlertRules(path string) ([]AlertRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file promRulesFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse alert rules %s: %w", path, err)
	}
	var out []AlertRule
	for _, g := range file.Groups {
		for _, r := range g.Rules {
			if r.Alert == "" {
				continue // recording rule
			}
			out = append(out, AlertRule{
				Alert:       r.Alert,
				Expr:        r.Expr,
				For:         r.For,
				Severity:    r.Labels["severity"],
				Summary:     r.Annotations["summary"],
				Description: r.Annotations["description"],
				Group:       g.Name,
			})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no alerting rules found in %s", path)
	}
	return out, nil
}
