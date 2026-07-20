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

// loadbalancer_octavia_datamodel_test.go — unit tests for the
// Octavia data-model fidelity surface in the handler layer: verbatim round-trip of
// projectId + annotations incl. octaviaProtocol + structured secondaryVIPs
// + endpoint subnetId through serializeLBRule, and the ?projectId= filter on
// ConfigGetLoadbalancer /all, INCLUDING the explicit non-isolation assertion
// that a non-matching-projectId rule is still visible under an unfiltered (nil) GET.
//
// These tests run on the remote/AWS gate: the handler package compiles only against the
// go-swagger-regenerated models (ProjectID/Annotations/SecondaryVIPs/endpoint SubnetID) and
// the regenerated GetConfigLoadbalancerAllParams.ProjectID *string. darwin cannot compile
// this package (Linux cgo / regen-dependent), same deferral as every handler test.

package handler

import (
	"net/http"
	"testing"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// stubLbGetHook is a minimal cmn.NetHookInterface that overrides ONLY NetLbRuleGet by
// embedding the (nil) interface — calling any other method would panic, but the /all walk
// touches only NetLbRuleGet. This is the standard one-method stub for a wide interface.
type stubLbGetHook struct {
	cmn.NetHookInterface
	rules []cmn.LbRuleMod
}

func (s *stubLbGetHook) NetLbRuleGet() ([]cmn.LbRuleMod, error) {
	return s.rules, nil
}

func newAllParams(projectID *string) operations.GetConfigLoadbalancerAllParams {
	req, _ := http.NewRequest("GET", "/config/loadbalancer/all", nil)
	return operations.GetConfigLoadbalancerAllParams{
		HTTPRequest: req,
		ProjectID:   projectID,
	}
}

func allPayload(t *testing.T, r middleware.Responder) []string {
	t.Helper()
	ok, isOK := r.(*operations.GetConfigLoadbalancerAllOK)
	if !isOK || ok.Payload == nil {
		t.Fatalf("expected GetConfigLoadbalancerAllOK with payload, got %T", r)
	}
	ids := make([]string, 0, len(ok.Payload.LbAttr))
	for _, e := range ok.Payload.LbAttr {
		if e.ServiceArguments != nil {
			ids = append(ids, e.ServiceArguments.ID)
		}
	}
	return ids
}

// TestSerializeLBRuleProjectIDAnnotationsRoundTrip: a rule with projectId + an annotations
// map (incl. octaviaProtocol) survives serializeLBRule verbatim.
func TestSerializeLBRuleProjectIDAnnotationsRoundTrip(t *testing.T) {
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.9"
	lb.Serv.ServPort = 443
	lb.Serv.Proto = "tcp"
	lb.Serv.ProjectId = "p1"
	lb.Serv.Annotations = map[string]string{
		"octaviaProtocol": "TERMINATED_HTTPS",
		"foo":             "bar",
	}

	out := serializeLBRule(lb)
	if out.ServiceArguments.ProjectID != "p1" {
		t.Fatalf("projectId must round-trip verbatim, got %q", out.ServiceArguments.ProjectID)
	}
	if out.ServiceArguments.Annotations["octaviaProtocol"] != "TERMINATED_HTTPS" {
		t.Fatalf("annotations.octaviaProtocol must round-trip verbatim, got %q",
			out.ServiceArguments.Annotations["octaviaProtocol"])
	}
	if out.ServiceArguments.Annotations["foo"] != "bar" {
		t.Fatalf("annotations.foo must round-trip verbatim, got %q",
			out.ServiceArguments.Annotations["foo"])
	}
}

// TestSerializeLBRuleSecondaryVIPsRoundTrip: a rule with structured secondaryVIPs[] survives
// serializeLBRule with each address/subnetId/portId/proto preserved, INDEPENDENT of the flat
// secondaryIPs SCTP gate. (07)
func TestSerializeLBRuleSecondaryVIPsRoundTrip(t *testing.T) {
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.9"
	lb.Serv.ServPort = 443
	lb.Serv.Proto = "tcp" // NON-sctp on purpose: structured VIPs round-trip for all protos
	lb.SecVIPs = []cmn.LbSecVIPArg{
		{Address: "10.0.0.1", SubnetId: "sub-a", PortId: "port-a", Proto: "tcp"},
		{Address: "10.0.0.2", SubnetId: "sub-b", PortId: "port-b", Proto: "tcp"},
	}

	out := serializeLBRule(lb)
	if len(out.SecondaryVIPs) != 2 {
		t.Fatalf("expected 2 secondaryVIPs, got %d", len(out.SecondaryVIPs))
	}
	if out.SecondaryVIPs[0].Address != "10.0.0.1" || out.SecondaryVIPs[0].SubnetID != "sub-a" ||
		out.SecondaryVIPs[0].PortID != "port-a" || out.SecondaryVIPs[0].Proto != "tcp" {
		t.Fatalf("secondaryVIPs[0] must round-trip verbatim, got %+v", out.SecondaryVIPs[0])
	}
	if out.SecondaryVIPs[1].Address != "10.0.0.2" || out.SecondaryVIPs[1].SubnetID != "sub-b" {
		t.Fatalf("secondaryVIPs[1] must round-trip verbatim, got %+v", out.SecondaryVIPs[1])
	}
}

// TestSerializeLBRuleEndpointSubnetIDRoundTrip: an endpoint with subnetId survives
// serializeLBRule verbatim (round-trip only, never interpreted).
func TestSerializeLBRuleEndpointSubnetIDRoundTrip(t *testing.T) {
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.9"
	lb.Serv.ServPort = 443
	lb.Serv.Proto = "tcp"
	lb.Eps = append(lb.Eps, cmn.LbEndPointArg{
		EpIP:     "31.31.31.1",
		EpPort:   8080,
		Weight:   1,
		SubnetId: "member-subnet-1",
		State:    "active",
	})

	out := serializeLBRule(lb)
	if len(out.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(out.Endpoints))
	}
	if out.Endpoints[0].SubnetID != "member-subnet-1" {
		t.Fatalf("endpoint subnetId must round-trip verbatim, got %q", out.Endpoints[0].SubnetID)
	}
}

// TestConfigGetLoadbalancerProjectIDFilter: ConfigGetLoadbalancer with params.ProjectID="p1"
// returns ONLY rules whose projectId == "p1"; a nil ProjectID returns ALL rules.
func TestConfigGetLoadbalancerProjectIDFilter(t *testing.T) {
	mkRule := func(id, project string) cmn.LbRuleMod {
		lb := cmn.LbRuleMod{}
		lb.Serv.Id = id
		lb.Serv.ServIP = "20.20.20.9"
		lb.Serv.ServPort = 443
		lb.Serv.Proto = "tcp"
		lb.Serv.ProjectId = project
		return lb
	}
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	ApiHooks = &stubLbGetHook{rules: []cmn.LbRuleMod{
		mkRule("r-p1", "p1"),
		mkRule("r-p2", "p2"),
		mkRule("r-none", ""),
	}}

	// Filtered on p1 => only the p1 rule.
	p1 := "p1"
	gotP1 := allPayload(t, ConfigGetLoadbalancer(newAllParams(&p1), nil))
	if len(gotP1) != 1 || gotP1[0] != "r-p1" {
		t.Fatalf("?projectId=p1 must return only the p1 rule, got %v", gotP1)
	}

	// nil ProjectID (unfiltered) => ALL three rules.
	gotAll := allPayload(t, ConfigGetLoadbalancer(newAllParams(nil), nil))
	if len(gotAll) != 3 {
		t.Fatalf("unfiltered GET must return all 3 rules, got %v", gotAll)
	}
}

// TestConfigGetLoadbalancerProjectIDIsNotIsolation: a rule with a NON-matching projectId is
// STILL visible under an unfiltered (nil ProjectID) GET. This pins intentional
// non-isolation: ?projectId= is a convenience filter, NOT a tenant-isolation/authz boundary.
func TestConfigGetLoadbalancerProjectIDIsNotIsolation(t *testing.T) {
	mkRule := func(id, project string) cmn.LbRuleMod {
		lb := cmn.LbRuleMod{}
		lb.Serv.Id = id
		lb.Serv.ServIP = "20.20.20.9"
		lb.Serv.ServPort = 443
		lb.Serv.Proto = "tcp"
		lb.Serv.ProjectId = project
		return lb
	}
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	ApiHooks = &stubLbGetHook{rules: []cmn.LbRuleMod{
		mkRule("r-tenant-a", "tenant-a"),
		mkRule("r-tenant-b", "tenant-b"),
	}}

	// Unfiltered GET sees tenant-b even though a caller might "belong" to tenant-a — the
	// filter does NOT enforce isolation (Octavia RBAC stays driver-side).
	gotAll := allPayload(t, ConfigGetLoadbalancer(newAllParams(nil), nil))
	if len(gotAll) != 2 {
		t.Fatalf("unfiltered GET must expose rules of ALL projects (non-isolation), got %v", gotAll)
	}
	sawB := false
	for _, id := range gotAll {
		if id == "r-tenant-b" {
			sawB = true
		}
	}
	if !sawB {
		t.Fatalf("a non-matching-projectId rule (tenant-b) must be visible to an unfiltered GET")
	}
}
