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

// loadbalancer_octavia_test.go — unit tests for the net-new
// read-side handler logic: shared rule serialization (id/adminStateUp surfacing,
// and operatingStatus derivation.
//
// The 200/404 responder glue (ConfigGetLoadbalancerByKey/ByID/Status) is thin and
// is validated on the remote gate via `make build` + behavioral curl; the genuinely
// new logic is exercised here without mocking the 81-method NetHookInterface.

package handler

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestSerializeLBRuleSurfacesIDAndAdminState: the shared serializer populates the
// opaque id and the resolved admin_state.
func TestSerializeLBRuleSurfacesIDAndAdminState(t *testing.T) {
	tru := true
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.1"
	lb.Serv.ServPort = 2020
	lb.Serv.Proto = "tcp"
	lb.Serv.Id = "abc-123"
	lb.Serv.AdminStateUp = &tru

	out := serializeLBRule(lb)
	if out.ServiceArguments == nil {
		t.Fatal("serializeLBRule returned nil serviceArguments")
	}
	if out.ServiceArguments.ID != "abc-123" {
		t.Fatalf("expected id 'abc-123', got %q", out.ServiceArguments.ID)
	}
	if out.ServiceArguments.AdminStateUp != true {
		t.Fatalf("expected adminStateUp true, got %v", out.ServiceArguments.AdminStateUp)
	}
}

// TestSerializeLBRuleAdminStateNilDefaultsEnabled: a nil AdminStateUp (legacy /
// POST-created rule) serializes as enabled=true — never paused (back-compat).
func TestSerializeLBRuleAdminStateNilDefaultsEnabled(t *testing.T) {
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.2"
	lb.Serv.ServPort = 80
	lb.Serv.Proto = "tcp"
	lb.Serv.AdminStateUp = nil

	out := serializeLBRule(lb)
	if out.ServiceArguments.AdminStateUp != true {
		t.Fatalf("nil AdminStateUp must serialize as enabled=true, got %v", out.ServiceArguments.AdminStateUp)
	}
}

// TestDeriveOperatingStatus covers vocabulary.
func TestDeriveOperatingStatus(t *testing.T) {
	mk := func(monitor bool, states ...string) cmn.LbRuleMod {
		lb := cmn.LbRuleMod{}
		lb.Serv.Monitor = monitor
		for _, s := range states {
			lb.Eps = append(lb.Eps, cmn.LbEndPointArg{State: s})
		}
		return lb
	}

	cases := []struct {
		name string
		lb   cmn.LbRuleMod
		want string
	}{
		{"no-monitor", mk(false, "active"), "NO_MONITOR"},
		{"all-up-online", mk(true, "active", "active"), "ONLINE"},
		{"some-down-degraded", mk(true, "active", "inactive"), "DEGRADED"},
		{"all-down-offline", mk(true, "inactive", "inactive"), "OFFLINE"},
		{"no-endpoints-offline", mk(true), "OFFLINE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := deriveOperatingStatus(c.lb); got != c.want {
				t.Fatalf("%s: expected %q, got %q", c.name, c.want, got)
			}
		})
	}
}
