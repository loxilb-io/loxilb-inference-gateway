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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PromClient queries an external Prometheus server's HTTP API
// (docs/MCP-DESIGN.md §3.3; optional, enabled via prometheus_url).
type PromClient struct {
	base string
	hc   *http.Client
}

// NewPromClient validates the base URL and builds a client (no I/O).
func NewPromClient(baseURL string, timeout time.Duration) (*PromClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid prometheus url %q", baseURL)
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &PromClient{
		base: strings.TrimRight(baseURL, "/"),
		hc:   &http.Client{Timeout: timeout},
	}, nil
}

// promEnvelope is the Prometheus API response wrapper.
type promEnvelope struct {
	Status    string          `json:"status"`
	Data      json.RawMessage `json:"data"`
	ErrorType string          `json:"errorType"`
	Error     string          `json:"error"`
}

func (p *PromClient) call(ctx context.Context, path string, q url.Values) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		p.base+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("prometheus: read: %w", err)
	}
	var env promEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("prometheus: %s", statusSnippet(resp.StatusCode, raw))
	}
	if env.Status != "success" {
		return nil, fmt.Errorf("prometheus %s: %s", env.ErrorType, env.Error)
	}
	return env.Data, nil
}

// Query runs an instant PromQL query (ts optional, RFC3339 or unix seconds).
func (p *PromClient) Query(ctx context.Context, query, ts string) (json.RawMessage, error) {
	q := url.Values{"query": {query}}
	if ts != "" {
		q.Set("time", ts)
	}
	return p.call(ctx, "/api/v1/query", q)
}

// QueryRange runs a ranged PromQL query.
func (p *PromClient) QueryRange(ctx context.Context, query, start, end, step string) (json.RawMessage, error) {
	q := url.Values{"query": {query}, "start": {start}, "end": {end}, "step": {step}}
	return p.call(ctx, "/api/v1/query_range", q)
}

// AlertmanagerClient reads active alerts from an Alertmanager instance.
type AlertmanagerClient struct {
	base string
	hc   *http.Client
}

// NewAlertmanagerClient validates the base URL and builds a client (no I/O).
func NewAlertmanagerClient(baseURL string, timeout time.Duration) (*AlertmanagerClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid alertmanager url %q", baseURL)
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &AlertmanagerClient{
		base: strings.TrimRight(baseURL, "/"),
		hc:   &http.Client{Timeout: timeout},
	}, nil
}

// Alert is one Alertmanager v2 alert, loosely typed.
type Alert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
	Status      struct {
		State string `json:"state"`
	} `json:"status"`
}

// ActiveAlerts fetches firing (non-silenced, non-inhibited) alerts.
func (a *AlertmanagerClient) ActiveAlerts(ctx context.Context) ([]Alert, error) {
	q := url.Values{"active": {"true"}, "silenced": {"false"}, "inhibited": {"false"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		a.base+"/api/v2/alerts?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("alertmanager: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("alertmanager: read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("alertmanager: %s", statusSnippet(resp.StatusCode, raw))
	}
	var alerts []Alert
	if err := json.Unmarshal(raw, &alerts); err != nil {
		return nil, fmt.Errorf("alertmanager: decode: %w", err)
	}
	return alerts, nil
}
