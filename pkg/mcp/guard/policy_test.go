/*
 * Copyright (c) 2026 NetLOX Inc
 * SPDX-License-Identifier: Apache-2.0
 */

package guard

import "testing"

func TestPermitsRoleTiers(t *testing.T) {
	pol := &Policy{}
	ro := ToolMeta{Name: "lb_list", Domain: "mgmt"}
	mut := ToolMeta{Name: "lb_create", Domain: "mgmt", Mutating: true}
	destr := ToolMeta{Name: "lb_delete", Domain: "mgmt", Mutating: true, Destructive: true}

	cases := []struct {
		role Role
		meta ToolMeta
		want bool
	}{
		{RoleViewer, ro, true},
		{RoleViewer, mut, false},
		{RoleViewer, destr, false},
		{RoleOperator, ro, true},
		{RoleOperator, mut, true},
		{RoleOperator, destr, false},
		{RoleAdmin, destr, true},
	}
	for _, tc := range cases {
		if got := pol.Permits(tc.role, tc.meta); got != tc.want {
			t.Errorf("Permits(%s, %s) = %v, want %v", tc.role, tc.meta.Name, got, tc.want)
		}
	}
}

func TestPermitsReadOnlyMode(t *testing.T) {
	pol := &Policy{ReadOnly: true}
	if pol.Permits(RoleAdmin, ToolMeta{Name: "lb_create", Mutating: true}) {
		t.Error("read-only mode must block mutating tools even for admin")
	}
	if !pol.Permits(RoleAdmin, ToolMeta{Name: "lb_list"}) {
		t.Error("read-only mode must keep read tools")
	}
}

func TestPermitsDenyWinsOverAllow(t *testing.T) {
	pol := &Policy{Allow: []string{"lb_*"}, Deny: []string{"lb_delete"}}
	if pol.Permits(RoleAdmin, ToolMeta{Name: "lb_delete", Mutating: true, Destructive: true}) {
		t.Error("deny list must win over allow list")
	}
	if !pol.Permits(RoleAdmin, ToolMeta{Name: "lb_list"}) {
		t.Error("allow-listed tool must pass")
	}
	if pol.Permits(RoleAdmin, ToolMeta{Name: "ct_list"}) {
		t.Error("non-allow-listed tool must be blocked when allow list is set")
	}
}

func TestPermitsDomainGate(t *testing.T) {
	pol := &Policy{Domains: map[string]bool{"monitoring": true}}
	if pol.Permits(RoleAdmin, ToolMeta{Name: "lb_list", Domain: "mgmt"}) {
		t.Error("disabled domain must be blocked")
	}
	if !pol.Permits(RoleAdmin, ToolMeta{Name: "metrics_snapshot", Domain: "monitoring"}) {
		t.Error("enabled domain must pass")
	}
}

func TestVerifyToken(t *testing.T) {
	good := "0123456789abcdef0123456789abcdef"
	c, err := NewClient("ci", RoleOperator, good)
	if err != nil {
		t.Fatal(err)
	}
	clients := []Client{c}

	if got, ok := VerifyToken(clients, good); !ok || got.Name != "ci" || got.Role != RoleOperator {
		t.Errorf("valid token rejected: ok=%v got=%+v", ok, got)
	}
	if _, ok := VerifyToken(clients, "0123456789abcdef0123456789abcdeX"); ok {
		t.Error("wrong token accepted")
	}
	if _, ok := VerifyToken(clients, ""); ok {
		t.Error("empty token accepted")
	}
}

func TestNewClientRejectsShortToken(t *testing.T) {
	if _, err := NewClient("x", RoleViewer, "short"); err == nil {
		t.Error("short token must be rejected")
	}
}

func TestRedact(t *testing.T) {
	out := Redact(map[string]any{"api_key": "sekrit", "filter": "web", "password": "p"})
	if out["api_key"] != "[REDACTED]" || out["password"] != "[REDACTED]" {
		t.Errorf("secrets not redacted: %v", out)
	}
	if out["filter"] != "web" {
		t.Errorf("non-secret redacted: %v", out)
	}
}
