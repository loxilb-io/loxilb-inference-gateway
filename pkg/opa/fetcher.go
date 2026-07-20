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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

const (
	// fetcherHTTPTimeout is the default HTTP client timeout for OPA requests.
	fetcherHTTPTimeout = 5 * time.Second
)

// PolicyFetcher retrieves L4 firewall policies from an OPA REST API endpoint.
type PolicyFetcher struct {
	opaURL     string
	policyPath string
	httpClient *http.Client
	cb         *CircuitBreaker
}

// NewPolicyFetcher creates a PolicyFetcher with a 5-second timeout HTTP client.
func NewPolicyFetcher(opaURL, policyPath string, cb *CircuitBreaker) *PolicyFetcher {
	return &PolicyFetcher{
		opaURL:     strings.TrimRight(opaURL, "/"),
		policyPath: strings.TrimLeft(policyPath, "/"),
		httpClient: &http.Client{
			Timeout: fetcherHTTPTimeout,
		},
		cb: cb,
	}
}

// Fetch retrieves the current L4 policy from OPA.
// It respects the circuit breaker state and records success or failure.
func (pf *PolicyFetcher) Fetch(ctx context.Context) (*OPAPolicyResponse, error) {
	if !pf.cb.AllowRequest() {
		return nil, fmt.Errorf("[OPA-L4] circuit breaker is open, request denied")
	}

	url := fmt.Sprintf("%s/v1/data/%s", pf.opaURL, pf.policyPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		pf.cb.RecordFailure()
		tk.LogIt(tk.LogError, "[OPA-L4] failed to create HTTP request: %v\n", err)
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := pf.httpClient.Do(req)
	if err != nil {
		pf.cb.RecordFailure()
		tk.LogIt(tk.LogError, "[OPA-L4] HTTP request failed: %v\n", err)
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		pf.cb.RecordFailure()
		tk.LogIt(tk.LogError, "[OPA-L4] OPA returned HTTP %d for %s\n", resp.StatusCode, url)
		return nil, fmt.Errorf("OPA returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		pf.cb.RecordFailure()
		tk.LogIt(tk.LogError, "[OPA-L4] failed to read response body: %v\n", err)
		return nil, fmt.Errorf("read body: %w", err)
	}

	var opaResp OPAPolicyResponse
	if err := json.Unmarshal(body, &opaResp); err != nil {
		pf.cb.RecordFailure()
		tk.LogIt(tk.LogError, "[OPA-L4] failed to parse OPA response: %v\n", err)
		return nil, fmt.Errorf("parse response: %w", err)
	}

	pf.cb.RecordSuccess()
	tk.LogIt(tk.LogDebug, "[OPA-L4] fetched %d rules from OPA\n", len(opaResp.Result.L4.FirewallAccessRules))

	return &opaResp, nil
}
