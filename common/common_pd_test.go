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
package common

import (
	"encoding/json"
	"testing"
)

func TestPDDisaggModeJSONRoundTrip(t *testing.T) {
	arg := LbServiceArg{
		ServIP:       "10.0.0.1",
		ServPort:     8080,
		Proto:        "tcp",
		Sel:          LbSelRr,
		Mode:         LBModeFullProxy,
		PDDisaggMode: true,
	}

	data, err := json.Marshal(arg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded LbServiceArg
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !decoded.PDDisaggMode {
		t.Error("PDDisaggMode should be true after round-trip")
	}
}

func TestPDDisaggModeOmitEmpty(t *testing.T) {
	arg := LbServiceArg{
		ServIP:       "10.0.0.1",
		ServPort:     8080,
		Proto:        "tcp",
		PDDisaggMode: false,
	}

	data, err := json.Marshal(arg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}
	if _, exists := raw["pd_disagg_mode"]; exists {
		t.Error("pd_disagg_mode should be omitted when false (omitempty)")
	}
}

func TestEpRoleJSONValues(t *testing.T) {
	tests := []struct {
		name     string
		role     int
		wantJSON bool // whether ep_role should appear in JSON (omitempty: 0 is omitted)
	}{
		{"normal_omitted", 0, false},
		{"prefill", 1, true},
		{"decode", 2, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := LbEndPointArg{
				EpIP:   "10.0.0.2",
				EpPort: 8080,
				Weight: 1,
				EpRole: tt.role,
			}

			data, err := json.Marshal(ep)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("Unmarshal to map failed: %v", err)
			}

			_, exists := raw["ep_role"]
			if exists != tt.wantJSON {
				t.Errorf("ep_role presence=%v, want %v (role=%d)", exists, tt.wantJSON, tt.role)
			}

			// Round-trip verification
			var decoded LbEndPointArg
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if decoded.EpRole != tt.role {
				t.Errorf("EpRole=%d after round-trip, want %d", decoded.EpRole, tt.role)
			}
		})
	}
}

func TestPDConfigWithEndpoints(t *testing.T) {
	// Simulate a full P/D LB rule with prefill and decode endpoints
	rule := LbRuleMod{
		Serv: LbServiceArg{
			ServIP:       "10.0.0.1",
			ServPort:     8080,
			Proto:        "tcp",
			Sel:          LbSelRr,
			Mode:         LBModeFullProxy,
			PDDisaggMode: true,
		},
		Eps: []LbEndPointArg{
			{EpIP: "10.0.0.10", EpPort: 8001, Weight: 1, EpRole: 1}, // prefill
			{EpIP: "10.0.0.11", EpPort: 8002, Weight: 1, EpRole: 2}, // decode
		},
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded LbRuleMod
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !decoded.Serv.PDDisaggMode {
		t.Error("PDDisaggMode should be true")
	}
	if len(decoded.Eps) != 2 {
		t.Fatalf("Expected 2 endpoints, got %d", len(decoded.Eps))
	}
	if decoded.Eps[0].EpRole != 1 {
		t.Errorf("First endpoint role=%d, want 1 (prefill)", decoded.Eps[0].EpRole)
	}
	if decoded.Eps[1].EpRole != 2 {
		t.Errorf("Second endpoint role=%d, want 2 (decode)", decoded.Eps[1].EpRole)
	}
}

func TestPDDisaggModeFromJSON(t *testing.T) {
	// Test parsing P/D config from JSON (as REST API would receive it)
	jsonStr := `{
		"serviceArguments": {
			"externalIP": "10.0.0.1",
			"port": 8080,
			"protocol": "tcp",
			"sel": 0,
			"mode": 4,
			"pd_disagg_mode": true
		},
		"endpoints": [
			{"endpointIP": "10.0.0.10", "targetPort": 8001, "weight": 1, "ep_role": 1},
			{"endpointIP": "10.0.0.11", "targetPort": 8002, "weight": 1, "ep_role": 2}
		]
	}`

	var rule LbRuleMod
	if err := json.Unmarshal([]byte(jsonStr), &rule); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !rule.Serv.PDDisaggMode {
		t.Error("PDDisaggMode should be true from JSON")
	}
	if len(rule.Eps) != 2 {
		t.Fatalf("Expected 2 endpoints, got %d", len(rule.Eps))
	}
	if rule.Eps[0].EpRole != 1 {
		t.Errorf("First endpoint role=%d, want 1", rule.Eps[0].EpRole)
	}
	if rule.Eps[1].EpRole != 2 {
		t.Errorf("Second endpoint role=%d, want 2", rule.Eps[1].EpRole)
	}
}
