/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase-3 gate tests: role visibility of the AI-ops and diagnose tools,
 * the ai_apikey_create secrets-to-file flow (§5.4 T5: no key material in the
 * response, 0600 file), the ai_apikey_delete confirm-token flow, the F12
 * caveat surfaced by ai_traffic_report, the diagnose evidence bundles against
 * a mock loxilb, and prompts list/get.
 */

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb/pkg/mcp/guard"
)

const testRawKey = "sk-live-verysecret-1234567890"

// aiMetricsText is a minimal exposition slice covering the families the
// Phase-3 composites consume.
const aiMetricsText = `# TYPE loxilb_ai_requests_total counter
loxilb_ai_requests_total{model="llama3",tenant="t1",status="200"} 90
loxilb_ai_requests_total{model="llama3",tenant="t1",status="500"} 10
# TYPE loxilb_ai_rate_limit_hits_total counter
loxilb_ai_rate_limit_hits_total{tenant="t1",reason="rps"} 7
# TYPE loxilb_ai_active_streams gauge
loxilb_ai_active_streams{model="llama3"} 3
# TYPE loxilb_ai_request_duration_seconds histogram
loxilb_ai_request_duration_seconds_bucket{model="llama3",tenant="t1",le="0.5"} 50
loxilb_ai_request_duration_seconds_bucket{model="llama3",tenant="t1",le="2"} 90
loxilb_ai_request_duration_seconds_bucket{model="llama3",tenant="t1",le="+Inf"} 100
loxilb_ai_request_duration_seconds_sum{model="llama3",tenant="t1"} 80
loxilb_ai_request_duration_seconds_count{model="llama3",tenant="t1"} 100
# TYPE loxilb_ai_pd_kv_params_found_total counter
loxilb_ai_pd_kv_params_found_total{model="llama3"} 5
# TYPE loxilb_ai_pd_kv_params_missing_total counter
loxilb_ai_pd_kv_params_missing_total{model="llama3"} 25
# TYPE loxilb_l4_error_events_total counter
loxilb_l4_error_events_total{proto="tcp",reason="rst_server"} 42
# TYPE loxilb_active_conntrack_entries gauge
loxilb_active_conntrack_entries 850
# TYPE loxilb_conntrack_max_entries gauge
loxilb_conntrack_max_entries 1000
`

// newAIMock is a loxilb REST stand-in for the Phase-3 AI/diagnose surface.
func newAIMock(t *testing.T) *mockLoxilb {
	t.Helper()
	m := &mockLoxilb{}
	mux := http.NewServeMux()
	mux.HandleFunc("/netlox/v1/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.requests = append(m.requests, r.Method+" "+r.URL.Path)
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/netlox/v1/metrics":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(aiMetricsText))
		case r.URL.Path == "/netlox/v1/config/ai/apikey" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"raw_key":"` + testRawKey + `","key_id":"key-123"}`))
		case r.URL.Path == "/netlox/v1/config/ai/apikey" && r.Method == http.MethodGet:
			w.Write([]byte(`[{"key_id":"key-123","tenant_id":"t1","name":"ci","enabled":true}]`))
		case strings.HasPrefix(r.URL.Path, "/netlox/v1/config/ai/apikey/"):
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Write([]byte(`{"key_id":"key-123","tenant_id":"t1","enabled":true}`))
		case r.URL.Path == "/netlox/v1/config/endpoint/all":
			w.Write([]byte(`{"Attr":[{"hostName":"10.0.0.1","currState":"ok","probeType":"tcp"},` +
				`{"hostName":"10.0.0.2","currState":"nok","probeType":"tcp"}]}`))
		case r.URL.Path == "/netlox/v1/config/conntrack/all":
			w.Write([]byte(`{"ctAttr":[{"destinationIP":"10.0.0.2","sourceIP":"1.1.1.1","protocol":"tcp","conntrackState":"est","servName":"web"}]}`))
		case r.URL.Path == "/netlox/v1/config/loadbalancer/all":
			w.Write([]byte(`{"lbAttr":[{"serviceArguments":{"externalIP":"1.2.3.4","port":80,"protocol":"tcp","name":"web"},` +
				`"endpoints":[{"endpointIP":"10.0.0.2","weight":1,"state":"active"}]}]}`))
		default:
			w.Write([]byte(`{"result":"Success"}`))
		}
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func aiTestBridge(t *testing.T, mock *mockLoxilb) *Bridge {
	t.Helper()
	cfg := testConfig(mock.srv.URL)
	cfg.SecretsDir = filepath.Join(t.TempDir(), "secrets")
	return newTestBridge(t, cfg)
}

// callTool invokes one tool over an in-memory session and returns the result.
func callTool(t *testing.T, cs *sdk.ClientSession, name string, args map[string]any) *sdk.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

// Role visibility: viewer sees AI read + diagnose tools only; operator adds
// AI mutations; ai_apikey_delete is admin-only.
func TestPhase3RoleVisibility(t *testing.T) {
	b := newTestBridge(t, testConfig("http://127.0.0.1:11111"))

	viewer, _ := listNames(t, b, guard.RoleViewer)
	for _, want := range []string{"ai_apikey_list", "ai_apikey_get", "ai_ratelimit_get",
		"ai_kv_inventory_get", "gpu_status", "gpu_worker_metrics_get", "llamafw_status",
		"llamafw_stats", "pii_status", "pii_stats", "ai_traffic_report",
		"diagnose_l4_errors", "diagnose_ai_latency", "diagnose_endpoint", "capacity_report"} {
		if !viewer[want] {
			t.Errorf("viewer: read tool %s missing", want)
		}
	}
	for name := range viewer {
		switch name {
		case "ai_apikey_create", "ai_apikey_update", "ai_apikey_delete", "ai_ratelimit_set",
			"gpu_mode_set", "gpu_conversations_cleanup", "llamafw_enable_set", "llamafw_configure",
			"llamafw_scanners_set", "llamafw_health_check", "pii_enable_set", "pii_configure",
			"pii_url_patterns_set":
			t.Errorf("viewer: mutating AI tool %s visible", name)
		}
	}

	operator, _ := listNames(t, b, guard.RoleOperator)
	for _, want := range []string{"ai_apikey_create", "ai_apikey_update", "ai_ratelimit_set",
		"gpu_mode_set", "gpu_conversations_cleanup", "llamafw_enable_set", "llamafw_configure",
		"llamafw_scanners_set", "llamafw_health_check", "pii_enable_set", "pii_configure",
		"pii_url_patterns_set"} {
		if !operator[want] {
			t.Errorf("operator: mutating tool %s missing", want)
		}
	}
	if operator["ai_apikey_delete"] {
		t.Error("operator: destructive ai_apikey_delete visible")
	}

	admin, _ := listNames(t, b, guard.RoleAdmin)
	if !admin["ai_apikey_delete"] {
		t.Error("admin: ai_apikey_delete missing")
	}

	// Read-only mode hides AI mutations even for admin.
	roCfg := testConfig("http://127.0.0.1:11111")
	roBridge, err := NewBridge(roCfg, &guard.Policy{ReadOnly: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	roAdmin, _ := listNames(t, roBridge, guard.RoleAdmin)
	if roAdmin["ai_apikey_create"] || roAdmin["ai_apikey_delete"] || roAdmin["gpu_mode_set"] {
		t.Error("read-only: mutating AI tools visible")
	}
	if !roAdmin["ai_traffic_report"] || !roAdmin["diagnose_l4_errors"] {
		t.Error("read-only: AI read/diagnose tools missing")
	}
}

// T5: ai_apikey_create default keeps key material out of the response and
// writes a 0600 file; reveal=true returns it inline on explicit request.
func TestPhase3ApikeyCreateSecretsToFile(t *testing.T) {
	mock := newAIMock(t)
	b := aiTestBridge(t, mock)
	cs := session(t, b, guard.RoleOperator)

	res := callTool(t, cs, "ai_apikey_create", map[string]any{"tenant_id": "t1", "name": "ci"})
	if res.IsError {
		t.Fatalf("create errored: %v", res.Content)
	}
	blob, _ := json.Marshal(res)
	if strings.Contains(string(blob), testRawKey) {
		t.Fatal("T5 violation: raw key material present in the default create response")
	}
	out := callOut(t, res)
	keyFile, _ := out["key_file"].(string)
	if keyFile == "" {
		t.Fatal("key_file missing from response")
	}
	st, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", st.Mode().Perm())
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != testRawKey {
		t.Error("key file does not hold the raw key")
	}

	// Generic secret-shape scan over the whole response (defense in depth).
	if regexp.MustCompile(`sk-[A-Za-z0-9-]{10,}`).Match(blob) {
		t.Error("secret-shaped string leaked in response")
	}

	// reveal=true returns the key inline (explicit opt-in). The mock returns
	// the same key_id, so the file already exists — reveal must not touch it.
	res = callTool(t, cs, "ai_apikey_create", map[string]any{
		"tenant_id": "t1", "reveal": true,
	})
	if res.IsError {
		t.Fatalf("reveal create errored: %v", res.Content)
	}
	out = callOut(t, res)
	if out["raw_key"] != testRawKey {
		t.Error("reveal=true did not return the raw key")
	}

	// No secrets dir configured and no reveal → refused before any REST call.
	noDir := testConfig(mock.srv.URL)
	b2 := newTestBridge(t, noDir)
	cs2 := session(t, b2, guard.RoleOperator)
	res = callTool(t, cs2, "ai_apikey_create", map[string]any{"tenant_id": "t1"})
	if !res.IsError {
		t.Fatal("create without secrets_dir and without reveal must fail")
	}
}

// ai_apikey_delete follows the preview → confirm-token → execute flow and
// only the confirmed call reaches loxilb.
func TestPhase3ApikeyDeleteConfirmFlow(t *testing.T) {
	mock := newAIMock(t)
	b := aiTestBridge(t, mock)
	cs := session(t, b, guard.RoleAdmin)

	res := callTool(t, cs, "ai_apikey_delete", map[string]any{"key_id": "key-123"})
	out := callOut(t, res)
	if out["action"] != "preview" {
		t.Fatalf("first call action = %v, want preview", out["action"])
	}
	token, _ := out["confirm_token"].(string)
	if token == "" {
		t.Fatal("no confirm_token in preview")
	}
	if mock.sawMutation("DELETE /netlox/v1/config/ai/apikey/") {
		t.Fatal("preview must not delete")
	}

	res = callTool(t, cs, "ai_apikey_delete", map[string]any{
		"key_id": "key-123", "confirm_token": token,
	})
	out = callOut(t, res)
	if out["action"] != "executed" {
		t.Fatalf("confirmed call action = %v, want executed", out["action"])
	}
	if !mock.sawMutation("DELETE /netlox/v1/config/ai/apikey/key-123") {
		t.Fatal("confirmed delete did not reach loxilb")
	}

	// Token is single-use.
	res = callTool(t, cs, "ai_apikey_delete", map[string]any{
		"key_id": "key-123", "confirm_token": token,
	})
	if !res.IsError {
		t.Fatal("replayed confirm_token must be rejected")
	}
}

// ai_traffic_report aggregates the metric families and surfaces caveat F12.
func TestPhase3AITrafficReport(t *testing.T) {
	mock := newAIMock(t)
	b := aiTestBridge(t, mock)
	cs := session(t, b, guard.RoleViewer)

	out := callOut(t, callTool(t, cs, "ai_traffic_report", nil))
	if got := out["requests_total"].(float64); got != 100 {
		t.Errorf("requests_total = %v, want 100", got)
	}
	if got := out["requests_non_2xx"].(float64); got != 10 {
		t.Errorf("requests_non_2xx = %v, want 10", got)
	}
	if got := out["error_ratio"].(float64); got != 0.1 {
		t.Errorf("error_ratio = %v, want 0.1", got)
	}
	if got := out["rate_limit_drops_total"].(float64); got != 7 {
		t.Errorf("rate_limit_drops_total = %v, want 7", got)
	}
	caveats, _ := json.Marshal(out["caveats"])
	if !strings.Contains(string(caveats), "F12") {
		t.Error("F12 caveat missing from ai_traffic_report")
	}
	dur, _ := out["request_duration"].(map[string]any)
	if dur == nil {
		t.Fatal("request_duration summary missing")
	}
	// p50 at target 50 with bucket{le=0.5}=50 → exactly 0.5.
	if got := dur["p50_seconds"].(float64); got != 0.5 {
		t.Errorf("p50 = %v, want 0.5", got)
	}
}

// diagnose tools return correlated evidence and suggested_actions against the
// mock; sections degrade independently.
func TestPhase3DiagnoseTools(t *testing.T) {
	mock := newAIMock(t)
	b := aiTestBridge(t, mock)
	cs := session(t, b, guard.RoleViewer)

	out := callOut(t, callTool(t, cs, "diagnose_l4_errors", nil))
	ev, _ := out["evidence"].(map[string]any)
	if ev == nil {
		t.Fatal("diagnose_l4_errors: no evidence")
	}
	if got := ev["l4_error_events_total"].(float64); got != 42 {
		t.Errorf("l4_error_events_total = %v, want 42", got)
	}
	acts, _ := out["suggested_actions"].([]any)
	found := false
	for _, aRaw := range acts {
		a, _ := aRaw.(map[string]any)
		if a["tool"] == "diagnose_endpoint" {
			found = true
			args, _ := a["args"].(map[string]any)
			if args["host"] != "10.0.0.2" {
				t.Errorf("suggested diagnose_endpoint host = %v, want 10.0.0.2", args["host"])
			}
		}
	}
	if !found {
		t.Error("unhealthy endpoint did not produce a diagnose_endpoint suggestion")
	}

	out = callOut(t, callTool(t, cs, "diagnose_ai_latency", nil))
	ev, _ = out["evidence"].(map[string]any)
	if got := ev["kv_params_missing"].(float64); got != 25 {
		t.Errorf("kv_params_missing = %v, want 25", got)
	}
	acts, _ = out["suggested_actions"].([]any)
	foundKV := false
	for _, aRaw := range acts {
		a, _ := aRaw.(map[string]any)
		if a["tool"] == "ai_kv_inventory_get" {
			foundKV = true
		}
	}
	if !foundKV {
		t.Error("kv_missing >> kv_found did not suggest ai_kv_inventory_get")
	}

	out = callOut(t, callTool(t, cs, "diagnose_endpoint", map[string]any{"host": "10.0.0.2"}))
	ev, _ = out["evidence"].(map[string]any)
	if got := ev["lb_rules_referencing_count"].(float64); got != 1 {
		t.Errorf("lb_rules_referencing_count = %v, want 1", got)
	}
	if got := ev["flows_toward_endpoint"].(float64); got != 1 {
		t.Errorf("flows_toward_endpoint = %v, want 1", got)
	}
	acts, _ = out["suggested_actions"].([]any)
	drain := false
	for _, aRaw := range acts {
		a, _ := aRaw.(map[string]any)
		if a["tool"] == "endpoint_host_state_set" {
			drain = true
			if a["risk"] != "medium" {
				t.Errorf("drain risk = %v, want medium", a["risk"])
			}
		}
	}
	if !drain {
		t.Error("failing probe did not suggest a drain action")
	}

	out = callOut(t, callTool(t, cs, "capacity_report", nil))
	ev, _ = out["evidence"].(map[string]any)
	if got := ev["conntrack_used_percent"].(float64); got != 85 {
		t.Errorf("conntrack_used_percent = %v, want 85", got)
	}
	acts, _ = out["suggested_actions"].([]any)
	if len(acts) == 0 {
		t.Error("capacity at 85% produced no suggested actions")
	}
}

// Prompts: all five are listed and render with arguments substituted.
func TestPhase3Prompts(t *testing.T) {
	b := newTestBridge(t, testConfig("http://127.0.0.1:11111"))
	cs := session(t, b, guard.RoleViewer)
	ctx := context.Background()

	pl, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range pl.Prompts {
		names[p.Name] = true
	}
	for _, want := range []string{"triage-alert", "rca-l4-errors", "rca-ai-latency",
		"capacity-report", "safe-lb-change"} {
		if !names[want] {
			t.Errorf("prompt %s missing", want)
		}
	}

	pr, err := cs.GetPrompt(ctx, &sdk.GetPromptParams{
		Name:      "triage-alert",
		Arguments: map[string]string{"alert": "LoxilbL4ErrorBurst", "target": "t1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pr.Messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(pr.Messages))
	}
	text := pr.Messages[0].Content.(*sdk.TextContent).Text
	if !strings.Contains(text, "LoxilbL4ErrorBurst") || !strings.Contains(text, "on target t1") {
		t.Error("triage-alert prompt did not substitute arguments")
	}
	if !strings.Contains(text, "diagnose_l4_errors") {
		t.Error("triage-alert prompt does not route to diagnose tools")
	}
}
