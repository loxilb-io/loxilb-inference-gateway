/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 */

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPromClientQuery(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query().Get("query"); q != "up" {
			t.Errorf("query param = %q", q)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{"resultType": "vector", "result": []any{
				map[string]any{"metric": map[string]any{"job": "loxilb"}, "value": []any{1e9, "1"}},
			}},
		})
	})
	mux.HandleFunc("/api/v1/query_range", func(w http.ResponseWriter, r *http.Request) {
		for _, p := range []string{"query", "start", "end", "step"} {
			if r.URL.Query().Get(p) == "" {
				t.Errorf("missing param %s", p)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, err := NewPromClient(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := p.Query(context.Background(), "up", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "vector") {
		t.Errorf("data = %s", data)
	}
	if _, err := p.QueryRange(context.Background(), "up", "1", "2", "30s"); err != nil {
		t.Fatal(err)
	}
}

func TestPromClientErrorEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "error", "errorType": "bad_data", "error": "parse error at char 3",
		})
	}))
	defer srv.Close()

	p, _ := NewPromClient(srv.URL, 0)
	_, err := p.Query(context.Background(), "up{", "")
	if err == nil || !strings.Contains(err.Error(), "parse error") {
		t.Errorf("want prom error surfaced, got %v", err)
	}
}

func TestPromClientRejectsBadURL(t *testing.T) {
	if _, err := NewPromClient("not a url", 0); err == nil {
		t.Error("bad url accepted")
	}
	if _, err := NewAlertmanagerClient("gopher://x", 0); err == nil {
		t.Error("bad scheme accepted")
	}
}

func TestAlertmanagerActiveAlerts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("active") != "true" {
			t.Error("active filter missing")
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"labels":      map[string]string{"alertname": "LoxilbL4ErrorBurst", "severity": "critical"},
			"annotations": map[string]string{"summary": "L4 error burst"},
			"startsAt":    "2026-07-19T04:00:00Z",
			"status":      map[string]any{"state": "active"},
		}})
	}))
	defer srv.Close()

	a, err := NewAlertmanagerClient(srv.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := a.ActiveAlerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Labels["alertname"] != "LoxilbL4ErrorBurst" ||
		alerts[0].Status.State != "active" {
		t.Errorf("alerts = %+v", alerts)
	}
}
