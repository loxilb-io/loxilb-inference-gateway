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

package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	tk "github.com/loxilb-io/loxilib"

	cmn "github.com/loxilb-io/loxilb/common"
)

const (
	firewallAPIPath    = "/netlox/v1/config/firewall"
	applierHTTPTimeout = 10 * time.Second
)

// RuleApplierConfig holds configuration for the rule applier.
type RuleApplierConfig struct {
	// LoxiLBURL is the base URL of the LoxiLB REST API.
	LoxiLBURL string
}

// ApplyResult summarizes the outcome of a rule application cycle.
// AddedKeys/DeletedKeys list the rule keys whose REST operation actually
// SUCCEEDED — the watcher caches exactly these (metrics audit: caching the
// intended diff instead of the outcome both overstated the rules gauge after
// a partial apply failure AND suppressed retries, since the failed rule
// looked already-applied to the next diff).
type ApplyResult struct {
	Added       int
	Deleted     int
	Errors      int
	AddedKeys   []DiffKey
	DeletedKeys []DiffKey
}

// RuleApplier sends firewall rule additions and deletions to the LoxiLB REST API.
type RuleApplier struct {
	config     RuleApplierConfig
	httpClient *http.Client
}

// NewRuleApplier creates a RuleApplier with a 10-second HTTP timeout.
// If LoxiLBURL is empty, it defaults to "http://localhost:11111".
func NewRuleApplier(config RuleApplierConfig) *RuleApplier {
	if config.LoxiLBURL == "" {
		config.LoxiLBURL = "http://localhost:11111"
	}
	return &RuleApplier{
		config: config,
		httpClient: &http.Client{
			Timeout: applierHTTPTimeout,
		},
	}
}

// Apply executes a two-phase apply: deletes removed rules, adds new rules.
// A single rule failure does not abort the remaining operations.
func (a *RuleApplier) Apply(ctx context.Context, diff DiffResult) ApplyResult {
	result := ApplyResult{}

	// DELETE removed rules
	for key, rule := range diff.ToDelete {
		if err := ctx.Err(); err != nil {
			tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] context cancelled, aborting apply\n")
			return result
		}
		if err := a.deleteRule(ctx, rule); err != nil {
			tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] failed to delete rule %s: %v\n", string(key), err)
			result.Errors++
			continue
		}
		result.Deleted++
		result.DeletedKeys = append(result.DeletedKeys, key)
	}

	// ADD new rules
	for key, rule := range diff.ToAdd {
		if err := ctx.Err(); err != nil {
			tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] context cancelled, aborting apply\n")
			return result
		}
		opt := diff.OptsToAdd[key]
		if err := a.addRule(ctx, rule, opt); err != nil {
			tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] failed to add rule %s: %v\n", string(key), err)
			result.Errors++
			continue
		}
		result.Added++
		result.AddedKeys = append(result.AddedKeys, key)
	}

	return result
}

// deleteRule sends a DELETE request with query parameters matching the rule fields.
func (a *RuleApplier) deleteRule(ctx context.Context, rule cmn.FwRuleArg) error {
	u, err := url.Parse(a.config.LoxiLBURL + firewallAPIPath)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}

	q := u.Query()
	q.Set("sourceIP", rule.SrcIP)
	q.Set("destinationIP", rule.DstIP)
	q.Set("minSourcePort", strconv.Itoa(int(rule.SrcPortMin)))
	q.Set("maxSourcePort", strconv.Itoa(int(rule.SrcPortMax)))
	q.Set("minDestinationPort", strconv.Itoa(int(rule.DstPortMin)))
	q.Set("maxDestinationPort", strconv.Itoa(int(rule.DstPortMax)))
	q.Set("protocol", strconv.Itoa(int(rule.Proto)))
	q.Set("preference", strconv.Itoa(int(rule.Pref)))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create DELETE request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("DELETE returned status %d", resp.StatusCode)
	}

	// ConfigDeleteFW returns HTTP 200 with {"result":"fail"} when the rule is not
	// found or deletion fails — check the body to catch this silent failure.
	var apiResult struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResult); err == nil {
		if apiResult.Result == "fail" {
			return fmt.Errorf("DELETE returned 'fail' (rule not found or deletion error)")
		}
	}
	return nil
}

// addRule sends a POST request with a JSON body matching the cmn.FwRuleMod structure.
func (a *RuleApplier) addRule(ctx context.Context, rule cmn.FwRuleArg, opt cmn.FwOptArg) error {
	mod := cmn.FwRuleMod{
		Rule: rule,
		Opts: opt,
	}

	body, err := json.Marshal(mod)
	if err != nil {
		return fmt.Errorf("marshal rule: %w", err)
	}

	reqURL := a.config.LoxiLBURL + firewallAPIPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST returned status %d", resp.StatusCode)
	}
	return nil
}
