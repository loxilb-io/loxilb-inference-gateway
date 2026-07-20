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
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb/pkg/mcp/guard"
)

// legacyMetricPaths is the closed allowlist of GET /metrics/{name} JSON
// endpoints (priority-tiered metric store). Tool args are validated against
// this map — never concatenated into the URL directly.
var legacyMetricPaths = map[string]string{
	"flowcount":          "/metrics/flowcount",
	"newflowcount":       "/metrics/newflowcount",
	"errorcount":         "/metrics/errorcount",
	"requestcount":       "/metrics/requestcount",
	"reqcountperclient":  "/metrics/reqcountperclient",
	"processedtraffic":   "/metrics/processedtraffic",
	"lbprocessedtraffic": "/metrics/lbprocessedtraffic",
	"lbrulecount":        "/metrics/lbrulecount",
	"fwdrops":            "/metrics/fwdrops",
	"hostcount":          "/metrics/hostcount",
	"epdisttraffic":      "/metrics/epdisttraffic",
	"servicedisttraffic": "/metrics/servicedisttraffic",
}

// RegisterMonitoring adds the Phase-1 monitoring read tools
// (docs/MCP-DESIGN.md §3.3). PromQL/Alertmanager tools register only when the
// corresponding backends are configured; alerts_catalog only when the rules
// file is loadable.
func RegisterMonitoring(s *sdk.Server, role guard.Role, pol *guard.Policy, deps *Deps) {
	permits := func(name string) bool {
		return pol.Permits(role, guard.ToolMeta{Name: name, Domain: domainMonitoring})
	}

	if permits("metrics_config_get") {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "metrics_config_get",
			Description: "Get the metrics subsystem configuration (GET /config/metrics).",
			Annotations: roAnnotations("Get metrics config"),
		}, deps.passthrough("metrics_config_get", "/config/metrics"))
	}
	if permits("metrics_legacy_get") {
		names := make([]string, 0, len(legacyMetricPaths))
		for n := range legacyMetricPaths {
			names = append(names, n)
		}
		sort.Strings(names)
		sdk.AddTool(s, &sdk.Tool{
			Name: "metrics_legacy_get",
			Description: "Get one JSON metric report from the priority-tiered store. " +
				"Available metrics: " + strings.Join(names, ", ") + ".",
			Annotations: roAnnotations("Get legacy JSON metric"),
		}, deps.metricsLegacyGet())
	}
	if deps.Prom != nil && permits("promql_query") {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "promql_query",
			Description: "Run an instant PromQL query against the configured Prometheus server.",
			Annotations: roAnnotations("PromQL instant query"),
		}, deps.promqlQuery())
	}
	if deps.Prom != nil && permits("promql_range") {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "promql_range",
			Description: "Run a ranged PromQL query (start/end RFC3339 or unix seconds, step like 30s or 5m).",
			Annotations: roAnnotations("PromQL range query"),
		}, deps.promqlRange())
	}
	if deps.Alertmanager != nil && permits("alerts_active") {
		sdk.AddTool(s, &sdk.Tool{
			Name:        "alerts_active",
			Description: "List currently firing alerts from Alertmanager (non-silenced, non-inhibited).",
			Annotations: roAnnotations("List firing alerts"),
		}, deps.alertsActive())
	}
	if len(deps.AlertRules) > 0 && permits("alerts_catalog") {
		sdk.AddTool(s, &sdk.Tool{
			Name: "alerts_catalog",
			Description: "Reference catalog of the loxilb alert rules (name, PromQL expression, " +
				"for-duration, severity, summary). Use to understand what a firing alert means.",
			Annotations: roAnnotations("Alert rules catalog"),
		}, deps.alertsCatalog())
	}
}

// ---- metrics_legacy_get ----

type legacyIn struct {
	Target string `json:"target,omitempty" jsonschema:"target loxilb instance name; omit for default"`
	Metric string `json:"metric" jsonschema:"metric report name, e.g. flowcount, errorcount, lbprocessedtraffic"`
}

func (d *Deps) metricsLegacyGet() sdk.ToolHandlerFor[legacyIn, map[string]any] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in legacyIn) (*sdk.CallToolResult, map[string]any, error) {
		path, ok := legacyMetricPaths[strings.ToLower(strings.TrimSpace(in.Metric))]
		if !ok {
			return nil, nil, fmt.Errorf("unknown metric %q", in.Metric)
		}
		c, err := d.Resolve(in.Target)
		if err != nil {
			return nil, nil, err
		}
		var raw any
		if err := c.Get(ctx, path, &raw); err != nil {
			d.audit("metrics_legacy_get", c.Name(), false, err.Error())
			return nil, nil, err
		}
		d.audit("metrics_legacy_get", c.Name(), true, "")
		return nil, map[string]any{
			"target": c.Name(),
			"metric": in.Metric,
			"data":   sanitizeAny(raw, 0),
		}, nil
	}
}

// ---- promql_query / promql_range ----

type promqlIn struct {
	Query string `json:"query" jsonschema:"PromQL expression"`
	Time  string `json:"time,omitempty" jsonschema:"evaluation timestamp (RFC3339 or unix seconds); omit for now"`
}

type promqlRangeIn struct {
	Query string `json:"query" jsonschema:"PromQL expression"`
	Start string `json:"start" jsonschema:"range start (RFC3339 or unix seconds)"`
	End   string `json:"end" jsonschema:"range end (RFC3339 or unix seconds)"`
	Step  string `json:"step" jsonschema:"resolution step, e.g. 30s, 5m"`
}

type promqlOut struct {
	Data any `json:"data"`
}

func promData(raw json.RawMessage) (promqlOut, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return promqlOut{}, err
	}
	return promqlOut{Data: sanitizeAny(v, 0)}, nil
}

func (d *Deps) promqlQuery() sdk.ToolHandlerFor[promqlIn, promqlOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in promqlIn) (*sdk.CallToolResult, promqlOut, error) {
		raw, err := d.Prom.Query(ctx, in.Query, in.Time)
		if err != nil {
			d.audit("promql_query", "prometheus", false, err.Error())
			return nil, promqlOut{}, err
		}
		d.audit("promql_query", "prometheus", true, "")
		out, err := promData(raw)
		return nil, out, err
	}
}

func (d *Deps) promqlRange() sdk.ToolHandlerFor[promqlRangeIn, promqlOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in promqlRangeIn) (*sdk.CallToolResult, promqlOut, error) {
		raw, err := d.Prom.QueryRange(ctx, in.Query, in.Start, in.End, in.Step)
		if err != nil {
			d.audit("promql_range", "prometheus", false, err.Error())
			return nil, promqlOut{}, err
		}
		d.audit("promql_range", "prometheus", true, "")
		out, err := promData(raw)
		return nil, out, err
	}
}

// ---- alerts_active ----

type alertsIn struct{}

type activeAlert struct {
	Name     string            `json:"name"`
	Severity string            `json:"severity,omitempty"`
	State    string            `json:"state"`
	StartsAt string            `json:"starts_at"`
	Summary  string            `json:"summary,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type alertsOut struct {
	Count  int           `json:"count"`
	Alerts []activeAlert `json:"alerts"`
}

func (d *Deps) alertsActive() sdk.ToolHandlerFor[alertsIn, alertsOut] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, _ alertsIn) (*sdk.CallToolResult, alertsOut, error) {
		alerts, err := d.Alertmanager.ActiveAlerts(ctx)
		if err != nil {
			d.audit("alerts_active", "alertmanager", false, err.Error())
			return nil, alertsOut{}, err
		}
		out := alertsOut{Count: len(alerts)}
		for i, a := range alerts {
			if i >= maxListItems {
				break
			}
			labels := make(map[string]string, len(a.Labels))
			for k, v := range a.Labels {
				labels[clean(k)] = clean(v)
			}
			out.Alerts = append(out.Alerts, activeAlert{
				Name:     clean(a.Labels["alertname"]),
				Severity: clean(a.Labels["severity"]),
				State:    clean(a.Status.State),
				StartsAt: clean(a.StartsAt),
				Summary:  clean(a.Annotations["summary"]),
				Labels:   labels,
			})
		}
		d.audit("alerts_active", "alertmanager", true, "")
		return nil, out, nil
	}
}

// ---- alerts_catalog ----

// AlertRule is one parsed Prometheus alerting rule.
type AlertRule struct {
	Alert       string `json:"alert"`
	Expr        string `json:"expr"`
	For         string `json:"for,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Summary     string `json:"summary,omitempty"`
	Description string `json:"description,omitempty"`
	Group       string `json:"group,omitempty"`
}

type catalogIn struct {
	Filter string `json:"filter,omitempty" jsonschema:"case-insensitive substring match on alert name"`
}

type catalogOut struct {
	Count int         `json:"count"`
	Rules []AlertRule `json:"rules"`
}

func (d *Deps) alertsCatalog() sdk.ToolHandlerFor[catalogIn, catalogOut] {
	return func(_ context.Context, _ *sdk.CallToolRequest, in catalogIn) (*sdk.CallToolResult, catalogOut, error) {
		filter := strings.ToLower(in.Filter)
		var out catalogOut
		for _, r := range d.AlertRules {
			if filter != "" && !strings.Contains(strings.ToLower(r.Alert), filter) {
				continue
			}
			out.Rules = append(out.Rules, r)
		}
		out.Count = len(out.Rules)
		return nil, out, nil
	}
}
