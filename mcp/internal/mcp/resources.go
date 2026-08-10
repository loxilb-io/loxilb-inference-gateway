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

package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/tools"
)

// metricsReferenceDoc is the curated metric-family reference served as
// loxilb://docs/metrics. Keep the caveats section in sync with
// docs/MCP-OPERATIONS.md
const metricsReferenceDoc = `# loxilb metric family reference (curated)

Scrape endpoint: GET /netlox/v1/metrics (Prometheus exposition text).
Use the metrics_snapshot tool with a families glob, or promql_query when a
Prometheus server is configured.

## Key families

- loxilb_l4_error_events_total (counter, labels: proto, reason) — always-on,
  unsampled L4 connection error events. Basis of the LoxilbL4ErrorBurst alert.
  Independent of the sampled L4 tracer (l4trace_status_get).
- loxilb_ai_* — AI-gateway families: request counts, token throughput,
  TTFB/TTFT latency histograms, rate-limit drops, per-model/tenant labels.
- loxilb_healthy_endpoints / loxilb_unhealthy_endpoints — endpoint probe
  results feeding the NoHealthyEndpoints/UnhealthyEndpoints alerts.
- loxilb_active_conntracks and flow/traffic families — dataplane load.

## Known caveats

- When loxilb runs --userservice, the metrics endpoint requires a bearer
  token; unauthenticated Prometheus scrapes receive 401. The bridge
  authenticates automatically, but external scrapers must be configured.
- Rate-limit denials are counted only in loxilb_ai_rate_limit_hits_total,
  not in loxilb_ai_requests_total. On gateway builds predating the non-SSE
  accounting fix, loxilb_ai_requests_total counts only SSE-terminated
  streams — cross-check with the L7 response counters.
`

// registerResources adds the MCP resources.
func (b *Bridge) registerResources(s *sdk.Server) {
	if len(b.alertRules) > 0 {
		s.AddResource(&sdk.Resource{
			URI:         "loxilb://docs/alerts",
			Name:        "loxilb-alert-rules",
			Description: "Catalog of loxilb Prometheus alert rules with expressions and severities.",
			MIMEType:    "text/markdown",
		}, staticResource("loxilb://docs/alerts", "text/markdown",
			renderAlertRulesDoc(b.alertRules)))
	}

	s.AddResource(&sdk.Resource{
		URI:         "loxilb://docs/metrics",
		Name:        "loxilb-metrics-reference",
		Description: "Curated reference of loxilb Prometheus metric families and known caveats.",
		MIMEType:    "text/markdown",
	}, staticResource("loxilb://docs/metrics", "text/markdown", metricsReferenceDoc))

	if b.cfg.OpenapiSpecPath != "" {
		s.AddResource(&sdk.Resource{
			URI:         "loxilb://spec/openapi",
			Name:        "loxilb-openapi-spec",
			Description: "The loxilb REST API swagger specification (source of truth for endpoint details).",
			MIMEType:    "application/yaml",
		}, b.fileResource("loxilb://spec/openapi", "application/yaml", b.cfg.OpenapiSpecPath))
	}
}

func staticResource(uri, mime, content string) sdk.ResourceHandler {
	return func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
		return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{
			{URI: uri, MIMEType: mime, Text: content},
		}}, nil
	}
}

// fileResource serves a fixed, operator-configured file path (never a
// client-supplied one).
func (b *Bridge) fileResource(uri, mime, path string) sdk.ResourceHandler {
	return func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", uri, err)
		}
		return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{
			{URI: uri, MIMEType: mime, Text: string(raw)},
		}}, nil
	}
}

func renderAlertRulesDoc(rules []tools.AlertRule) string {
	var sb strings.Builder
	sb.WriteString("# loxilb alert rules catalog\n\n")
	group := ""
	for _, r := range rules {
		if r.Group != group {
			group = r.Group
			fmt.Fprintf(&sb, "## group: %s\n\n", group)
		}
		fmt.Fprintf(&sb, "### %s\n", r.Alert)
		if r.Severity != "" {
			fmt.Fprintf(&sb, "- severity: %s\n", r.Severity)
		}
		if r.For != "" {
			fmt.Fprintf(&sb, "- for: %s\n", r.For)
		}
		fmt.Fprintf(&sb, "- expr: `%s`\n", strings.TrimSpace(r.Expr))
		if r.Summary != "" {
			fmt.Fprintf(&sb, "- summary: %s\n", r.Summary)
		}
		if r.Description != "" {
			fmt.Fprintf(&sb, "- description: %s\n", r.Description)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
