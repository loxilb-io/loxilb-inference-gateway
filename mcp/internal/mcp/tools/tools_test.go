/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/client"
)

func newDeps(t *testing.T, mux *http.ServeMux) *Deps {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := client.New("mock", client.Options{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return &Deps{
		Resolve: func(name string) (*client.Client, error) { return c, nil },
		Targets: []string{"mock"},
	}
}

func TestLogsTailSanitizesUntrustedData(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/netlox/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("lines") != "10" {
			t.Errorf("lines param = %q", r.URL.Query().Get("lines"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"logs":      []string{"normal line", "evil\x1b[2Jline\x00with\x07controls"},
			"log_file":  "loxilb.log",
			"log_count": 2,
		})
	})
	d := newDeps(t, mux)
	_, out, err := d.logsTail()(context.Background(), nil, logsIn{Lines: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.UntrustedData) != 2 {
		t.Fatalf("got %d lines", len(out.UntrustedData))
	}
	if out.UntrustedData[1] != "evil[2Jlinewithcontrols" {
		t.Errorf("control chars not stripped: %q", out.UntrustedData[1])
	}
	if out.LogFile != "loxilb.log" || out.LogCount != 2 {
		t.Errorf("metadata wrong: %+v", out)
	}
}

func TestStatusGetSections(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/netlox/v1/status/process", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"processAttr": []map[string]any{{"pid": 1, "name": "loxilb"}},
		})
	})
	d := newDeps(t, mux)
	_, out, err := d.statusGet()(context.Background(), nil, statusIn{Section: "process"})
	if err != nil {
		t.Fatal(err)
	}
	if out["section"] != "process" {
		t.Errorf("section = %v", out["section"])
	}
	if _, _, err := d.statusGet()(context.Background(), nil, statusIn{Section: "bogus"}); err == nil {
		t.Error("bogus section accepted")
	}
}

func TestNodegraphGetValidatesService(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/netlox/v1/nodegraph/all", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"nodes": []any{}})
	})
	d := newDeps(t, mux)
	if _, _, err := d.nodegraphGet()(context.Background(), nil, nodegraphIn{}); err != nil {
		t.Fatalf("all: %v", err)
	}
	for _, bad := range []string{"../etc", "a/b", "x?y=1", "a%2Fb", strings.Repeat("s", 200)} {
		if _, _, err := d.nodegraphGet()(context.Background(), nil, nodegraphIn{Service: bad}); err == nil {
			t.Errorf("service %q accepted", bad)
		}
	}
}

func TestMetricsLegacyGetAllowlist(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/netlox/v1/metrics/flowcount", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"flows": 5})
	})
	d := newDeps(t, mux)
	_, out, err := d.metricsLegacyGet()(context.Background(), nil, legacyIn{Metric: "flowcount"})
	if err != nil {
		t.Fatal(err)
	}
	if out["metric"] != "flowcount" {
		t.Errorf("out = %v", out)
	}
	for _, bad := range []string{"", "nope", "../secret", "flowcount/extra"} {
		if _, _, err := d.metricsLegacyGet()(context.Background(), nil, legacyIn{Metric: bad}); err == nil {
			t.Errorf("metric %q accepted", bad)
		}
	}
}

func TestSanitizeAnyCapsAndDepth(t *testing.T) {
	big := make([]any, maxListItems+50)
	for i := range big {
		big[i] = i
	}
	got := sanitizeAny(big, 0).([]any)
	if len(got) != maxListItems+1 {
		t.Errorf("cap: got %d items", len(got))
	}
	if s, ok := got[maxListItems].(string); !ok || !strings.Contains(s, "TRUNCATED: 50") {
		t.Errorf("truncation marker missing: %v", got[maxListItems])
	}

	deep := any("leaf")
	for range 12 {
		deep = map[string]any{"k": deep}
	}
	out := sanitizeAny(deep, 0)
	if !strings.Contains(mustJSON(t, out), "too deep") {
		t.Error("depth bound not applied")
	}
}

func TestAlertsCatalogFilter(t *testing.T) {
	d := &Deps{AlertRules: []AlertRule{
		{Alert: "LoxilbL4ErrorBurst", Severity: "critical"},
		{Alert: "LoxilbHighTTFB", Severity: "warning"},
	}}
	_, out, err := d.alertsCatalog()(context.Background(), nil, catalogIn{Filter: "ttfb"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || out.Rules[0].Alert != "LoxilbHighTTFB" {
		t.Errorf("filter wrong: %+v", out)
	}
	_, all, _ := d.alertsCatalog()(context.Background(), nil, catalogIn{})
	if all.Count != 2 {
		t.Errorf("unfiltered count = %d", all.Count)
	}
}

// LoadAlertRules against the real rules file shipped in this repo.
func TestLoadAlertRulesRealFile(t *testing.T) {
	rules, err := LoadAlertRules("../../../deploy/monitoring/prometheus/rules/loxilb-alerts.yml")
	if err != nil {
		t.Fatalf("parse repo rules file: %v", err)
	}
	if len(rules) < 14 {
		t.Errorf("got %d rules, want >= 14 (T6 drill matrix)", len(rules))
	}
	found := false
	for _, r := range rules {
		if r.Alert == "LoxilbL4ErrorBurst" {
			found = true
			if r.Expr == "" || r.Group == "" {
				t.Errorf("rule missing fields: %+v", r)
			}
		}
	}
	if !found {
		t.Error("LoxilbL4ErrorBurst not found in catalog")
	}
}

func TestValidatePathSegment(t *testing.T) {
	if err := validatePathSegment("svc-web1"); err != nil {
		t.Errorf("valid segment rejected: %v", err)
	}
	for _, bad := range []string{"", "a/b", "..", "a..b", "a%b", "a#b", "a?b", "a\\b"} {
		if validatePathSegment(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
