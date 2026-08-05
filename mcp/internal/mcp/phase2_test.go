/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase-2 gate tests: role visibility of management CRUD tools (§5.4 T3),
 * the confirm-token preview/execute flow end-to-end (T4), config_export
 * secret masking (T5), and filename traversal rejection (T10).
 */

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb-inference-gateway/mcp/internal/mcp/guard"
)

// mockLoxilb is a minimal loxilb REST stand-in that records mutating requests.
type mockLoxilb struct {
	mu       sync.Mutex
	requests []string // "METHOD path"
	srv      *httptest.Server
}

func newMockLoxilb(t *testing.T) *mockLoxilb {
	t.Helper()
	m := &mockLoxilb{}
	mux := http.NewServeMux()
	mux.HandleFunc("/netlox/v1/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.requests = append(m.requests, r.Method+" "+r.URL.Path)
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/netlox/v1/config/loadbalancer/all":
			w.Write([]byte(`{"lbAttr":[{"serviceArguments":{"externalIP":"1.2.3.4","port":80,"protocol":"tcp","name":"web"},"endpoints":[{"endpointIP":"10.0.0.1","weight":1,"state":"active"}]}]}`))
		case "/netlox/v1/config/export":
			w.Write([]byte(`{"loadbalancers":[{"name":"web"}],"auth":{"password":"hunter2","apiKey":"sk-secret-123"}}`))
		default:
			w.Write([]byte(`{"result":"Success"}`))
		}
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockLoxilb) sawMutation(prefix string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.requests {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

// session connects an in-memory MCP client to a per-role server.
func session(t *testing.T, b *Bridge, role guard.Role) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := sdk.NewInMemoryTransports()
	if _, err := b.BuildServer(role).Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// callOut unmarshals a tool result's structured content into a map.
func callOut(t *testing.T, res *sdk.CallToolResult) map[string]any {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// T3: tools/list per role — viewer sees no mutating tools, operator no
// destructive tools, admin everything; config_import only with AllowImport.
func TestPhase2RoleVisibility(t *testing.T) {
	b := newTestBridge(t, testConfig("http://127.0.0.1:11111"))

	viewer, _ := listNames(t, b, guard.RoleViewer)
	for _, want := range []string{"endpoint_list", "fw_list", "ipfilter_list", "secrate_get",
		"net_route_list", "net_vlan_list", "net_vxlan_list", "net_neighbor_list",
		"net_ip_list", "net_port_list", "bgp_neigh_list", "bgp_policy_list",
		"session_list", "session_ulcl_list", "config_export", "config_params_get",
		"log_archive_get"} {
		if !viewer[want] {
			t.Errorf("viewer: read tool %s missing", want)
		}
	}
	for name := range viewer {
		switch name {
		case "lb_create", "lb_delete", "fw_create", "fw_delete", "ipfilter_set",
			"secrate_set", "secrate_reset", "net_route_create", "net_route_delete",
			"bgp_neigh_set", "bgp_global_set", "bgp_policy_apply",
			"endpoint_host_state_set", "config_params_set", "config_import":
			t.Errorf("viewer: mutating tool %s visible", name)
		}
	}

	operator, _ := listNames(t, b, guard.RoleOperator)
	for _, want := range []string{"lb_create", "fw_create", "ipfilter_set", "secrate_set",
		"secrate_reset", "net_route_create", "bgp_neigh_set", "bgp_global_set",
		"bgp_policy_apply", "endpoint_host_state_set", "config_params_set"} {
		if !operator[want] {
			t.Errorf("operator: mutating tool %s missing", want)
		}
	}
	for _, absent := range []string{"lb_delete", "fw_delete", "net_route_delete", "config_import"} {
		if operator[absent] {
			t.Errorf("operator: destructive tool %s visible", absent)
		}
	}

	admin, _ := listNames(t, b, guard.RoleAdmin)
	for _, want := range []string{"lb_delete", "fw_delete", "net_route_delete"} {
		if !admin[want] {
			t.Errorf("admin: destructive tool %s missing", want)
		}
	}
	if admin["config_import"] {
		t.Error("config_import visible without --allow-import")
	}

	b.AllowImport = true
	adminImp, _ := listNames(t, b, guard.RoleAdmin)
	if !adminImp["config_import"] {
		t.Error("config_import missing with --allow-import for admin")
	}
}

// T3: read-only mode hides mutating tools even from admin.
func TestPhase2ReadOnlyHidesMutating(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:11111")
	b, err := NewBridge(cfg, &guard.Policy{ReadOnly: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := listNames(t, b, guard.RoleAdmin)
	for _, absent := range []string{"lb_create", "lb_delete", "fw_create", "fw_delete"} {
		if admin[absent] {
			t.Errorf("read-only mode: %s visible", absent)
		}
	}
	if !admin["lb_list"] || !admin["fw_list"] {
		t.Error("read-only mode removed read tools")
	}
}

// T3: a viewer session calling a mutating tool by name fails (not registered).
func TestPhase2ViewerCannotCallMutating(t *testing.T) {
	mock := newMockLoxilb(t)
	b := newTestBridge(t, testConfig(mock.srv.URL))
	cs := session(t, b, guard.RoleViewer)

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "lb_create",
		Arguments: map[string]any{"external_ip": "9.9.9.9", "port": 80, "protocol": "tcp",
			"endpoints": []map[string]any{{"ip": "10.0.0.1", "port": 8080}}},
	})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatal("viewer executed lb_create")
	}
	if mock.sawMutation("POST /netlox/v1/config/loadbalancer") {
		t.Fatal("mutating request reached loxilb from viewer session")
	}
}

// T4 end-to-end: preview issues a token and performs no delete; execute with
// the token deletes; replay and arg-swap both fail.
func TestPhase2ConfirmFlow(t *testing.T) {
	mock := newMockLoxilb(t)
	b := newTestBridge(t, testConfig(mock.srv.URL))
	cs := session(t, b, guard.RoleAdmin)
	ctx := context.Background()

	args := map[string]any{"external_ip": "1.2.3.4", "port": 80, "protocol": "tcp"}

	// Step 1: preview.
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "lb_delete", Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("preview call failed: %v %v", err, res)
	}
	out := callOut(t, res)
	if out["action"] != "preview" {
		t.Fatalf("want preview, got %v", out["action"])
	}
	token, _ := out["confirm_token"].(string)
	if token == "" {
		t.Fatal("no confirm_token in preview")
	}
	if prev, ok := out["preview"].(map[string]any); !ok || prev["match_count"] != float64(1) {
		t.Errorf("preview did not surface the matching rule: %v", out["preview"])
	}
	if mock.sawMutation("DELETE ") {
		t.Fatal("preview performed a DELETE")
	}

	// Step 2a: token with different args → rejected, nothing deleted.
	swapped := map[string]any{"external_ip": "1.2.3.4", "port": 81, "protocol": "tcp",
		"confirm_token": token}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "lb_delete", Arguments: swapped})
	if err == nil && !res.IsError {
		t.Fatal("swapped-args execute succeeded")
	}
	if mock.sawMutation("DELETE ") {
		t.Fatal("swapped-args execute performed a DELETE")
	}

	// The mismatch burned the token; get a fresh one.
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "lb_delete", Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("second preview failed: %v", err)
	}
	token, _ = callOut(t, res)["confirm_token"].(string)

	// Step 2b: correct token + identical args → executes.
	exec := map[string]any{"external_ip": "1.2.3.4", "port": 80, "protocol": "tcp",
		"confirm_token": token}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "lb_delete", Arguments: exec})
	if err != nil || res.IsError {
		t.Fatalf("execute failed: %v %+v", err, res)
	}
	if callOut(t, res)["action"] != "executed" {
		t.Fatalf("want executed, got %v", callOut(t, res)["action"])
	}
	if !mock.sawMutation("DELETE /netlox/v1/config/loadbalancer/externalipaddress/1.2.3.4") {
		t.Fatal("no DELETE reached loxilb on execute")
	}

	// Step 3: replay of the consumed token → rejected.
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "lb_delete", Arguments: exec})
	if err == nil && !res.IsError {
		t.Fatal("replayed token succeeded")
	}
}

// --no-confirm mode: destructive tools execute directly (CI).
func TestPhase2NoConfirmExecutesDirectly(t *testing.T) {
	mock := newMockLoxilb(t)
	b := newTestBridge(t, testConfig(mock.srv.URL))
	b.SetNoConfirm()
	cs := session(t, b, guard.RoleAdmin)

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "lb_delete",
		Arguments: map[string]any{"external_ip": "1.2.3.4", "port": 80, "protocol": "tcp"}})
	if err != nil || res.IsError {
		t.Fatalf("no-confirm delete failed: %v", err)
	}
	if callOut(t, res)["action"] != "executed" {
		t.Fatal("no-confirm delete did not execute")
	}
	if !mock.sawMutation("DELETE ") {
		t.Fatal("no DELETE reached loxilb")
	}
}

// T5: config_export masks secret-shaped fields.
func TestPhase2ConfigExportMasksSecrets(t *testing.T) {
	mock := newMockLoxilb(t)
	b := newTestBridge(t, testConfig(mock.srv.URL))
	cs := session(t, b, guard.RoleViewer)

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "config_export",
		Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("config_export failed: %v", err)
	}
	raw, _ := json.Marshal(callOut(t, res))
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "sk-secret-123") {
		t.Fatalf("config_export leaked secrets: %s", raw)
	}
	if !strings.Contains(string(raw), "[REDACTED]") {
		t.Fatalf("config_export did not mask: %s", raw)
	}
	if !strings.Contains(string(raw), "loadbalancers") {
		t.Fatal("config_export dropped non-secret content")
	}
}

// T10: traversal-shaped filenames are rejected bridge-side, before any
// request reaches loxilb.
func TestPhase2LogArchiveTraversal(t *testing.T) {
	mock := newMockLoxilb(t)
	b := newTestBridge(t, testConfig(mock.srv.URL))
	cs := session(t, b, guard.RoleViewer)

	for _, bad := range []string{"../../etc/passwd", "a/b", "..", "x%2f..%2fetc", ""} {
		res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
			Name: "log_archive_get", Arguments: map[string]any{"filename": bad}})
		if err == nil && (res == nil || !res.IsError) {
			t.Errorf("filename %q accepted", bad)
		}
	}
	if mock.sawMutation("GET /netlox/v1/log-archives/") {
		t.Fatal("traversal request reached loxilb")
	}
}

// Guard sanity: lb_create validates inputs before any REST call.
func TestPhase2LBCreateValidation(t *testing.T) {
	mock := newMockLoxilb(t)
	b := newTestBridge(t, testConfig(mock.srv.URL))
	cs := session(t, b, guard.RoleOperator)
	ctx := context.Background()

	bad := []map[string]any{
		{"external_ip": "not-an-ip", "port": 80, "protocol": "tcp",
			"endpoints": []map[string]any{{"ip": "10.0.0.1", "port": 80}}},
		{"external_ip": "9.9.9.9", "port": 99999, "protocol": "tcp",
			"endpoints": []map[string]any{{"ip": "10.0.0.1", "port": 80}}},
		{"external_ip": "9.9.9.9", "port": 80, "protocol": "bogus",
			"endpoints": []map[string]any{{"ip": "10.0.0.1", "port": 80}}},
		{"external_ip": "9.9.9.9", "port": 80, "protocol": "tcp"},
	}
	for i, args := range bad {
		res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "lb_create", Arguments: args})
		if err == nil && (res == nil || !res.IsError) {
			t.Errorf("bad input %d accepted", i)
		}
	}
	if mock.sawMutation("POST /netlox/v1/config/loadbalancer") {
		t.Fatal("invalid lb_create reached loxilb")
	}

	good := map[string]any{"external_ip": "9.9.9.9", "port": 80, "protocol": "tcp",
		"endpoints": []map[string]any{{"ip": "10.0.0.1", "port": 8080}}}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "lb_create", Arguments: good})
	if err != nil || res.IsError {
		t.Fatalf("valid lb_create failed: %v %+v", err, res)
	}
	if !mock.sawMutation("POST /netlox/v1/config/loadbalancer") {
		t.Fatal("valid lb_create never reached loxilb")
	}
}
