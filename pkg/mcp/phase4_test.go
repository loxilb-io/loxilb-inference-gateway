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
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/loxilb-io/loxilb/pkg/mcp/guard"
)

// Phase 4: autopilot exact-name matching is deliberate — no globs on a
// confirm-bypass surface.
func TestAutopilotAllowedExactOnly(t *testing.T) {
	var nilPol *guard.Policy
	if nilPol.AutopilotAllowed("lb_delete") {
		t.Error("nil policy must have no autopilot tools")
	}
	pol := &guard.Policy{Autopilot: []string{"lb_delete", " fw_delete "}}
	if !pol.AutopilotAllowed("lb_delete") {
		t.Error("exact name must match")
	}
	if !pol.AutopilotAllowed("fw_delete") {
		t.Error("names are trimmed")
	}
	if pol.AutopilotAllowed("lb_create") {
		t.Error("non-listed tool must not match")
	}
	glob := &guard.Policy{Autopilot: []string{"lb_*"}}
	if glob.AutopilotAllowed("lb_delete") {
		t.Error("glob patterns must NOT be honored for autopilot")
	}
}

// Phase 4: a destructive tool on the autopilot list executes without the
// preview→confirm step, the bypass is audited, and non-listed destructive
// tools still stop at the preview.
func TestPhase4AutopilotBypass(t *testing.T) {
	mock := newMockLoxilb(t)
	auditDir := t.TempDir()
	aud, err := guard.OpenAuditor(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aud.Close() })

	pol := &guard.Policy{Autopilot: []string{"lb_delete"}}
	b, err := NewBridge(testConfig(mock.srv.URL), pol, aud)
	if err != nil {
		t.Fatal(err)
	}
	cs := session(t, b, guard.RoleAdmin)
	ctx := context.Background()

	args := map[string]any{"external_ip": "1.2.3.4", "port": 80, "protocol": "tcp"}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "lb_delete", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("autopilot lb_delete errored: %v", res.Content)
	}
	out := callOut(t, res)
	if out["action"] != "executed" {
		t.Fatalf("autopilot lb_delete: want executed without token, got %v", out["action"])
	}
	if !mock.sawMutation("DELETE /netlox/v1/config/loadbalancer/") {
		t.Error("mock loxilb saw no DELETE")
	}

	// fw_delete is NOT on the list: must stop at the preview, no mutation.
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fw_delete",
		Arguments: map[string]any{"match": map[string]any{"source_ip": "0.0.0.0/0", "dest_ip": "1.2.3.4/32"}}})
	if err != nil {
		t.Fatal(err)
	}
	out = callOut(t, res)
	if out["action"] != "preview" {
		t.Fatalf("non-autopilot fw_delete: want preview, got %v", out["action"])
	}
	if mock.sawMutation("DELETE /netlox/v1/config/firewall") {
		t.Error("fw_delete mutated despite preview")
	}

	raw, err := os.ReadFile(filepath.Join(auditDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"kind":"autopilot_exec"`) {
		t.Error("audit log missing autopilot_exec event")
	}
	if !strings.Contains(string(raw), `"tool":"lb_delete"`) {
		t.Error("audit log missing lb_delete tool_call")
	}
}

// Phase 4: fan-out tools — targets_list marks the default target; a viewer
// may call both; fleet_overview degrades per target instead of failing.
func TestPhase4FleetTools(t *testing.T) {
	mock := newMockLoxilb(t)
	cfg := &Config{
		DefaultTarget: "up",
		Targets: map[string]Target{
			"up": {URL: mock.srv.URL},
			// TEST-NET-1 unroutable + 1s timeout keeps the probe failure fast.
			"down": {URL: "http://192.0.2.1:1", TimeoutSec: 1},
		},
		Clients: []ClientToken{{Name: "ci", Role: "viewer", Token: testToken}},
	}
	b := newTestBridge(t, cfg)
	cs := session(t, b, guard.RoleViewer)
	ctx := context.Background()

	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "targets_list"})
	if err != nil {
		t.Fatal(err)
	}
	out := callOut(t, res)
	targets, _ := out["targets"].([]any)
	if len(targets) != 2 {
		t.Fatalf("targets_list: want 2 targets, got %v", out)
	}
	first, _ := targets[0].(map[string]any) // sorted: "down" first
	if first["name"] != "down" || first["default"] == true {
		t.Errorf("targets_list[0]: want non-default 'down', got %v", first)
	}
	second, _ := targets[1].(map[string]any)
	if second["name"] != "up" || second["default"] != true {
		t.Errorf("targets_list[1]: want default 'up', got %v", second)
	}

	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fleet_overview"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("fleet_overview must not fail on one dead target: %v", res.Content)
	}
	out = callOut(t, res)
	if out["target_count"] != float64(2) || out["reachable"] != float64(1) {
		t.Fatalf("fleet_overview: want 2 targets / 1 reachable, got %v", out)
	}
	perTarget, _ := out["targets"].([]any)
	down, _ := perTarget[0].(map[string]any)
	if down["reachable"] == true || down["errors"] == nil {
		t.Errorf("dead target must be unreachable with errors, got %v", down)
	}
}

// Phase 4: autopilot list must not leak destructive tools to lower roles —
// the role tier check runs before any autopilot consideration.
func TestPhase4AutopilotDoesNotWidenRoles(t *testing.T) {
	mock := newMockLoxilb(t)
	pol := &guard.Policy{Autopilot: []string{"lb_delete"}}
	b, err := NewBridge(testConfig(mock.srv.URL), pol, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []guard.Role{guard.RoleViewer, guard.RoleOperator} {
		names, _ := listNames(t, b, role)
		if names["lb_delete"] {
			t.Errorf("%s must not see lb_delete even when autopilot-listed", role)
		}
	}
}
