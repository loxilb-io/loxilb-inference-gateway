/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 */

package mcp

import (
	"context"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb/pkg/mcp/guard"
)

const repoAlertRules = "../../deploy/monitoring/prometheus/rules/loxilb-alerts.yml"

// listNames connects an in-memory MCP client and returns tool + resource names.
func listNames(t *testing.T, b *Bridge, role guard.Role) (tools, resources map[string]bool) {
	t.Helper()
	ctx := context.Background()
	st, ct := sdk.NewInMemoryTransports()
	srv := b.BuildServer(role)
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	tools = map[string]bool{}
	tl, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tl.Tools {
		tools[tool.Name] = true
	}
	resources = map[string]bool{}
	rl, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rl.Resources {
		resources[r.URI] = true
	}
	return tools, resources
}

func TestPhase1Registration(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:11111")
	cfg.AlertRulesPath = repoAlertRules
	b := newTestBridge(t, cfg)
	tools, resources := listNames(t, b, guard.RoleViewer)

	for _, want := range []string{
		// seed
		"version_get", "health_overview", "lb_list", "ct_list", "metrics_snapshot",
		// analysis
		"meta_get", "cluster_state_get", "trace_status_get", "l4trace_status_get",
		"trace_catalog_list", "nodegraph_get", "status_get", "logs_tail",
		"log_archives_list", "ipsec_status_get",
		// monitoring
		"metrics_config_get", "metrics_legacy_get", "alerts_catalog",
	} {
		if !tools[want] {
			t.Errorf("tool %s missing", want)
		}
	}
	// promql/alertmanager not configured -> tools absent
	for _, absent := range []string{"promql_query", "promql_range", "alerts_active"} {
		if tools[absent] {
			t.Errorf("tool %s registered without backend", absent)
		}
	}
	if !resources["loxilb://docs/alerts"] || !resources["loxilb://docs/metrics"] {
		t.Errorf("expected doc resources, got %v", resources)
	}
	if resources["loxilb://spec/openapi"] {
		t.Error("openapi resource registered without spec path")
	}
}

func TestPhase1BackendGatedTools(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:11111")
	cfg.PrometheusURL = "http://127.0.0.1:9090"
	cfg.AlertmanagerURL = "http://127.0.0.1:9093"
	cfg.OpenapiSpecPath = "../../api/swagger.yml"
	b := newTestBridge(t, cfg)
	tools, resources := listNames(t, b, guard.RoleAdmin)

	for _, want := range []string{"promql_query", "promql_range", "alerts_active"} {
		if !tools[want] {
			t.Errorf("tool %s missing with backend configured", want)
		}
	}
	if tools["alerts_catalog"] {
		t.Error("alerts_catalog registered without rules file")
	}
	if !resources["loxilb://spec/openapi"] {
		t.Error("openapi resource missing")
	}
}

func TestAlertsDocResourceContent(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:11111")
	cfg.AlertRulesPath = repoAlertRules
	b := newTestBridge(t, cfg)

	ctx := context.Background()
	st, ct := sdk.NewInMemoryTransports()
	if _, err := b.BuildServer(guard.RoleViewer).Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.ReadResource(ctx, &sdk.ReadResourceParams{URI: "loxilb://docs/alerts"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) != 1 || !strings.Contains(res.Contents[0].Text, "LoxilbL4ErrorBurst") {
		t.Error("alerts doc missing LoxilbL4ErrorBurst")
	}
	mref, err := cs.ReadResource(ctx, &sdk.ReadResourceParams{URI: "loxilb://docs/metrics"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mref.Contents[0].Text, "F12") {
		t.Error("metrics reference missing F12 caveat")
	}
}

func TestNewBridgeRejectsBadBackends(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:11111")
	cfg.PrometheusURL = "not a url"
	if _, err := NewBridge(cfg, nil, nil); err == nil {
		t.Error("bad prometheus url accepted")
	}
	cfg = testConfig("http://127.0.0.1:11111")
	cfg.AlertRulesPath = "/nonexistent/rules.yml"
	if _, err := NewBridge(cfg, nil, nil); err == nil {
		t.Error("missing rules file accepted")
	}
}
