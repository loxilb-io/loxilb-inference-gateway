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

// loadbalancer_stats_test.go — unit tests for the Octavia
// per-service statistics endpoint: GET .../stats serializes the four-field quad
// {activeConnections, bytesIn, bytesOut, totalConnections} VERBATIM from the rule's
// in-memory counters, returns 404 for an absent composite key, and resolves a bracketed
// IPv6 path param (stripV6Brackets is applied at the /stats lookup so IPv6 stats work the
// moment the endpoint ships, ahead broader bracket-strip rollout).
//
// These tests run on the remote/AWS gate: the handler package compiles only against the
// go-swagger-regenerated operations.GetConfigLoadbalancerStatsParams / *Stats* responder
// types and the regenerated models.LoadbalanceStats. darwin cannot compile this package
// (Linux cgo / regen-dependent), the same deferral as every /73 handler test.
// The stubLbGetHook one-method NetLbRuleGet stub is shared from
// loadbalancer_octavia_datamodel_test.go (same package).

package handler

import (
	"net/http"
	"testing"

	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// newStatsParams builds a GetConfigLoadbalancerStatsParams with a non-nil HTTPRequest
// (the handler logs params.HTTPRequest.Method/URL) for the given composite key.
func newStatsParams(ip string, port float64, proto string) operations.GetConfigLoadbalancerStatsParams {
	req, _ := http.NewRequest("GET", "/config/loadbalancer/externalipaddress/"+ip+"/port/80/protocol/"+proto+"/stats", nil)
	return operations.GetConfigLoadbalancerStatsParams{
		HTTPRequest: req,
		IPAddress:   ip,
		Port:        port,
		Proto:       proto,
	}
}

// mkStatsRule builds an LB rule whose in-memory counters carry the known stats quad.
func mkStatsRule(ip string, port uint16, proto string, active, bytesIn, bytesOut, total uint64) cmn.LbRuleMod {
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = ip
	lb.Serv.ServPort = port
	lb.Serv.Proto = proto
	lb.Serv.ActiveConns = active
	lb.Serv.BytesIn = bytesIn
	lb.Serv.BytesOut = bytesOut
	lb.Serv.TotalConns = total
	return lb
}

// TestConfigGetLoadbalancerStatsSerializesQuad: a present rule's activeConns/bytesIn/
// bytesOut/totalConns serialize VERBATIM onto the LoadbalanceStats payload. The
// four fields must map one-to-one (no swap, no heuristic) to the rule's counters.
func TestConfigGetLoadbalancerStatsSerializesQuad(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	rule := mkStatsRule("20.20.20.10", 80, "tcp", 7, 1234, 5678, 42)
	ApiHooks = &stubLbGetHook{rules: []cmn.LbRuleMod{rule}}

	resp := ConfigGetLoadbalancerStats(newStatsParams("20.20.20.10", 80, "tcp"), nil)

	ok, isOK := resp.(*operations.GetConfigLoadbalancerStatsOK)
	if !isOK || ok.Payload == nil {
		t.Fatalf("expected GetConfigLoadbalancerStatsOK with payload, got %T", resp)
	}
	p := ok.Payload
	if p.ActiveConnections != 7 {
		t.Errorf("activeConnections: want 7, got %d", p.ActiveConnections)
	}
	if p.BytesIn != 1234 {
		t.Errorf("bytesIn: want 1234, got %d", p.BytesIn)
	}
	if p.BytesOut != 5678 {
		t.Errorf("bytesOut: want 5678, got %d", p.BytesOut)
	}
	if p.TotalConnections != 42 {
		t.Errorf("totalConnections: want 42, got %d", p.TotalConnections)
	}
}

// TestConfigGetLoadbalancerStatsNotFound: a GET for an absent composite key returns the
// 404 responder (NewGetConfigLoadbalancerStatsNotFound), NOT an error or an OK with zeros.
func TestConfigGetLoadbalancerStatsNotFound(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	// Seed one unrelated rule so the lookup walk runs and simply misses.
	ApiHooks = &stubLbGetHook{rules: []cmn.LbRuleMod{
		mkStatsRule("20.20.20.10", 80, "tcp", 1, 2, 3, 4),
	}}

	resp := ConfigGetLoadbalancerStats(newStatsParams("203.0.113.99", 80, "tcp"), nil)

	if _, isNF := resp.(*operations.GetConfigLoadbalancerStatsNotFound); !isNF {
		t.Fatalf("expected GetConfigLoadbalancerStatsNotFound for an absent key, got %T", resp)
	}
}

// TestConfigGetLoadbalancerStatsIPv6BracketResolves: a rule whose ServIP is stored bare
// ("2001:db8::1") is addressed with a bracketed IPv6 path param ("[2001:db8::1]"); the
// handler strips the brackets via stripV6Brackets BEFORE findLBRuleByKey, so the rule
// resolves (200, not 404) the moment /stats ships — no broken wave-3->wave-4 404 window.
func TestConfigGetLoadbalancerStatsIPv6BracketResolves(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	// ServIP is stored UNBRACKETED (net.IP.String).
	rule := mkStatsRule("2001:db8::1", 80, "tcp", 3, 100, 200, 9)
	ApiHooks = &stubLbGetHook{rules: []cmn.LbRuleMod{rule}}

	// Client addresses it RFC-bracketed.
	resp := ConfigGetLoadbalancerStats(newStatsParams("[2001:db8::1]", 80, "tcp"), nil)

	ok, isOK := resp.(*operations.GetConfigLoadbalancerStatsOK)
	if !isOK || ok.Payload == nil {
		t.Fatalf("bracketed IPv6 stats must resolve (no 404), got %T", resp)
	}
	if ok.Payload.ActiveConnections != 3 || ok.Payload.TotalConnections != 9 {
		t.Errorf("bracketed IPv6 stats served the wrong rule: %+v", ok.Payload)
	}
}

// TestStripV6BracketsIdempotent: stripV6Brackets strips RFC brackets from an IPv6 literal
// and is a no-op for IPv4 / already-bare input (the normalization the /stats lookup relies on).
func TestStripV6BracketsIdempotent(t *testing.T) {
	cases := map[string]string{
		"[2001:db8::1]": "2001:db8::1",
		"2001:db8::1":   "2001:db8::1",
		"10.0.0.1":      "10.0.0.1",
	}
	for in, want := range cases {
		if got := stripV6Brackets(in); got != want {
			t.Errorf("stripV6Brackets(%q): want %q, got %q", in, want, got)
		}
	}
}
