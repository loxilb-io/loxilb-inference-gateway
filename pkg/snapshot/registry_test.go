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

package snapshot

import (
	"errors"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// unavailableHooks simulates a gateway where the optional BFD/BGP/IPsec
// subsystems are not running (loxinet nil-guard errors) -- capture and wipe
// must treat those domains as empty instead of failing (testbed E2E
// finding, 2026-07-20).
type unavailableHooks struct{ *mockHooks }

func (u unavailableHooks) NetBFDGet() ([]cmn.BFDMod, error) {
	return nil, errors.New("bfd session not running")
}
func (u unavailableHooks) NetGoBGPNeighGet() ([]cmn.GoBGPNeighGetMod, error) {
	return nil, errors.New("loxilb BGP mode is disabled")
}
func (u unavailableHooks) NetGoBGPGCGet() (cmn.GoBGPGlobalConfig, error) {
	return cmn.GoBGPGlobalConfig{}, errors.New("loxilb BGP mode is disabled")
}
func (u unavailableHooks) NetIPsecGetConfig() (*cmn.IPsecConfig, error) {
	return nil, errors.New("IPsec not initialized")
}
func (u unavailableHooks) NetIPsecTunnelGetAll() ([]*cmn.IPsecTunnel, error) {
	return nil, errors.New("IPsec not initialized")
}

func TestCaptureToleratesUnavailableSubsystems(t *testing.T) {
	hooks := unavailableHooks{newMockHooks()}
	doc, err := Capture(hooks, "0.9.8", "host", TriggerManual, nil)
	if err != nil {
		t.Fatalf("capture must tolerate not-running subsystems, got: %v", err)
	}
	if len(doc.Domains.BFD) != 0 || len(doc.Domains.BGP.Neighbors) != 0 ||
		doc.Domains.IPsec.Config != nil || len(doc.Domains.IPsec.Tunnels) != 0 {
		t.Fatalf("unavailable subsystems must capture as empty, got bfd=%v bgp=%v ipsec=%+v",
			doc.Domains.BFD, doc.Domains.BGP, doc.Domains.IPsec)
	}
}

func TestWipeToleratesUnavailableSubsystems(t *testing.T) {
	hooks := unavailableHooks{newMockHooks()}
	if _, err := Wipe(hooks, nil); err != nil {
		t.Fatalf("wipe must tolerate not-running subsystems, got: %v", err)
	}
}

func TestGetEndpointFiltersRuleManaged(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{
		{HostName: "1.1.1.1", Name: "user-ep"},
		{HostName: "2.2.2.2", Name: "2.2.2.2_tcp_80", RuleManaged: true},
	}
	doc := &Document{}
	if err := getEndpoint(hooks, doc); err != nil {
		t.Fatalf("getEndpoint: %v", err)
	}
	if len(doc.Domains.Endpoint) != 1 || doc.Domains.Endpoint[0].Name != "user-ep" {
		t.Fatalf("rule-managed endpoints must be excluded from capture, got %+v", doc.Domains.Endpoint)
	}
}

func domainNames(entries []DomainEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Name
	}
	return out
}

// TestRegistryOrder locks down the §4.1 apply order (dependencies first --
// endpoint before loadbalancer, session before sessionulcl) and verifies
// DeleteOrder is the exact reverse.
func TestRegistryOrder(t *testing.T) {
	want := []string{
		DomainEndpoint, DomainLoadBalancer, DomainKvExactBinding,
		DomainL7Policy, DomainFirewall, DomainPolicy,
		DomainMirror, DomainSession, DomainSessionUlCl, DomainIPFilter,
		DomainSecurityRate, DomainBFD, DomainBGP, DomainIPsec, DomainCORS,
		DomainTracing,
	}
	got := domainNames(ApplyOrder())
	if len(got) != len(want) {
		t.Fatalf("ApplyOrder length = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ApplyOrder[%d] = %q, want %q (full order: %v)", i, got[i], want[i], got)
		}
	}

	// endpoint before loadbalancer -- the specific ordering bug the design
	// doc calls out as fixed (§2 defect #5).
	epIdx, lbIdx := indexOf(got, DomainEndpoint), indexOf(got, DomainLoadBalancer)
	if epIdx < 0 || lbIdx < 0 || epIdx > lbIdx {
		t.Fatalf("expected endpoint (idx %d) before loadbalancer (idx %d)", epIdx, lbIdx)
	}
	sessIdx, ulclIdx := indexOf(got, DomainSession), indexOf(got, DomainSessionUlCl)
	if sessIdx < 0 || ulclIdx < 0 || sessIdx > ulclIdx {
		t.Fatalf("expected session (idx %d) before sessionulcl (idx %d)", sessIdx, ulclIdx)
	}

	del := domainNames(DeleteOrder())
	if len(del) != len(got) {
		t.Fatalf("DeleteOrder length = %d, want %d", len(del), len(got))
	}
	for i := range got {
		if del[i] != got[len(got)-1-i] {
			t.Fatalf("DeleteOrder is not the exact reverse of ApplyOrder at index %d: got %q, want %q", i, del[i], got[len(got)-1-i])
		}
	}
	// In particular: loadbalancer must be deleted before endpoint.
	delEpIdx, delLbIdx := indexOf(del, DomainEndpoint), indexOf(del, DomainLoadBalancer)
	if delLbIdx > delEpIdx {
		t.Fatalf("delete order should delete loadbalancer (idx %d) before endpoint (idx %d)", delLbIdx, delEpIdx)
	}
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func TestSelectAllWhenEmpty(t *testing.T) {
	got, err := Select(nil)
	if err != nil {
		t.Fatalf("Select(nil): %v", err)
	}
	if len(got) != len(Registry) {
		t.Fatalf("Select(nil) length = %d, want %d (all domains)", len(got), len(Registry))
	}

	got2, err := Select([]string{})
	if err != nil {
		t.Fatalf("Select([]): %v", err)
	}
	if len(got2) != len(Registry) {
		t.Fatalf("Select([]) length = %d, want %d (all domains)", len(got2), len(Registry))
	}
}

func TestSelectSubset(t *testing.T) {
	got, err := Select([]string{DomainFirewall, DomainEndpoint})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	names := domainNames(got)
	// Select returns entries in registry (apply) order, not request order.
	if len(names) != 2 || names[0] != DomainEndpoint || names[1] != DomainFirewall {
		t.Fatalf("Select([firewall,endpoint]) = %v, want registry-order [endpoint firewall]", names)
	}
}

func TestSelectUnknownDomain(t *testing.T) {
	_, err := Select([]string{"not-a-real-domain"})
	if err == nil {
		t.Fatalf("expected error for unknown domain")
	}
	if !strings.Contains(err.Error(), "not-a-real-domain") {
		t.Fatalf("error should name the offending domain, got: %v", err)
	}
}

// --- endpoint ---

func TestEndpointGetApplyDelete(t *testing.T) {
	hooks := newMockHooks()
	hooks.endpoints = []cmn.EndPointMod{{HostName: "10.0.0.1", Name: "ep1"}}

	doc := &Document{}
	if err := getEndpoint(hooks, doc); err != nil {
		t.Fatalf("getEndpoint: %v", err)
	}
	if len(doc.Domains.Endpoint) != 1 || doc.Domains.Endpoint[0].Name != "ep1" {
		t.Fatalf("unexpected endpoint capture: %+v", doc.Domains.Endpoint)
	}

	fresh := newMockHooks()
	n, _, err := applyEndpoint(fresh, doc, false)
	if err != nil || n != 1 {
		t.Fatalf("applyEndpoint: n=%d err=%v", n, err)
	}
	if len(fresh.endpoints) != 1 || fresh.endpoints[0].Name != "ep1" {
		t.Fatalf("applyEndpoint did not add via hooks: %+v", fresh.endpoints)
	}

	nDel, err := deleteEndpoint(fresh)
	if err != nil || nDel != 1 {
		t.Fatalf("deleteEndpoint: n=%d err=%v", nDel, err)
	}
	deleteCalled := false
	for _, c := range fresh.Calls {
		if c == "NetEpHostDel:ep1" {
			deleteCalled = true
		}
	}
	if !deleteCalled {
		t.Fatalf("expected NetEpHostDel to be called for ep1, calls: %v", fresh.Calls)
	}
}

// --- firewall SrcChk exclusion ---

func TestFirewallSrcChkMarkExcludedFromGetAndDelete(t *testing.T) {
	hooks := newMockHooks()
	hooks.fwRules = []cmn.FwRuleMod{
		{Rule: cmn.FwRuleArg{SrcIP: "1.1.1.1/32"}, Opts: cmn.FwOptArg{Mark: srcChkFwMark}},
		{Rule: cmn.FwRuleArg{SrcIP: "2.2.2.2/32"}, Opts: cmn.FwOptArg{Mark: 0}},
	}

	doc := &Document{}
	if err := getFirewall(hooks, doc); err != nil {
		t.Fatalf("getFirewall: %v", err)
	}
	if len(doc.Domains.Firewall) != 1 || doc.Domains.Firewall[0].Rule.SrcIP != "2.2.2.2/32" {
		t.Fatalf("expected only the non-SrcChk rule captured, got: %+v", doc.Domains.Firewall)
	}

	n, err := deleteFirewall(hooks)
	if err != nil {
		t.Fatalf("deleteFirewall: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleteFirewall should only delete the 1 non-SrcChk rule, deleted %d", n)
	}
}

// --- securityrate singleton Set semantics ---

func TestSecurityRateSingletonApplyAndDelete(t *testing.T) {
	hooks := newMockHooks()
	doc := &Document{
		Domains: Domains{
			SecurityRate: &cmn.SecurityRateState{
				Config: cmn.SecurityRateConfig{SYNEnabled: true, SYNThreshold: 42},
			},
		},
	}

	n, _, err := applySecurityRate(hooks, doc, false)
	if err != nil || n != 1 {
		t.Fatalf("applySecurityRate: n=%d err=%v", n, err)
	}
	if hooks.secRate == nil || !hooks.secRate.Config.SYNEnabled || hooks.secRate.Config.SYNThreshold != 42 {
		t.Fatalf("applySecurityRate did not Set the captured config: %+v", hooks.secRate)
	}

	// Delete: singleton has no per-item delete; the registry resets to the
	// zero-value (all-disabled) config via the same Set hook.
	if _, err := deleteSecurityRate(hooks); err != nil {
		t.Fatalf("deleteSecurityRate: %v", err)
	}
	if hooks.secRate.Config.SYNEnabled {
		t.Fatalf("deleteSecurityRate should reset config to disabled, got: %+v", hooks.secRate.Config)
	}
}

func TestSecurityRateApplyNilIsNoop(t *testing.T) {
	hooks := newMockHooks()
	doc := &Document{}
	n, _, err := applySecurityRate(hooks, doc, false)
	if err != nil || n != 0 {
		t.Fatalf("applySecurityRate with nil SecurityRate should no-op, got n=%d err=%v", n, err)
	}
	if len(hooks.Calls) != 0 {
		t.Fatalf("expected no hook calls, got: %v", hooks.Calls)
	}
}

// --- mirror Get/Add/Del type conversion ---

func TestMirrorGetModConvertsToMirrModForApplyAndDelete(t *testing.T) {
	hooks := newMockHooks()
	hooks.mirrors = []cmn.MirrGetMod{{Ident: "m1", Info: cmn.MirrInfo{MirrType: cmn.MirrTypeSpan}}}

	doc := &Document{}
	if err := getMirror(hooks, doc); err != nil {
		t.Fatalf("getMirror: %v", err)
	}

	fresh := newMockHooks()
	if _, _, err := applyMirror(fresh, doc, false); err != nil {
		t.Fatalf("applyMirror: %v", err)
	}
	found := false
	for _, c := range fresh.Calls {
		if c == "NetMirrorAdd:m1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected NetMirrorAdd:m1, calls: %v", fresh.Calls)
	}
}

// --- bgp defined_sets: must loop across every DefinedType, using name="all" ---

func TestBGPDefinedSetsGetLoopsOverEveryType(t *testing.T) {
	hooks := newMockHooks()
	hooks.bgpDefined["prefix"] = []cmn.GoBGPPolicyDefinedSetMod{{Name: "pfx1", DefinedTypeString: "prefix"}}
	hooks.bgpDefined["neigh"] = []cmn.GoBGPPolicyDefinedSetMod{{Name: "n1", DefinedTypeString: "neigh"}}

	doc := &Document{}
	if err := getBGP(hooks, doc); err != nil {
		t.Fatalf("getBGP: %v", err)
	}
	if len(doc.Domains.BGP.DefinedSets) != 2 {
		t.Fatalf("expected 2 defined sets aggregated across types, got %d: %+v", len(doc.Domains.BGP.DefinedSets), doc.Domains.BGP.DefinedSets)
	}

	for _, wantType := range bgpDefinedSetTypes {
		wantCall := "NetGoBGPPolicyDefinedSetGet:all:" + wantType
		found := false
		for _, c := range hooks.Calls {
			if c == wantCall {
				found = true
			}
		}
		if !found {
			t.Errorf("expected call %q, calls were: %v", wantCall, hooks.Calls)
		}
	}
}

// TestBGPGlobalConfigGapLeftNil documents the TODO(G-7) gap: getBGP has no
// Get hook for BGP global config, so it must always leave GlobalConfig nil,
// never fabricate a value.
func TestBGPGlobalConfigGapLeftNil(t *testing.T) {
	hooks := newMockHooks()
	doc := &Document{}
	if err := getBGP(hooks, doc); err != nil {
		t.Fatalf("getBGP: %v", err)
	}
	if doc.Domains.BGP.GlobalConfig != nil {
		t.Fatalf("expected BGP.GlobalConfig to stay nil (TODO(G-7)), got: %+v", doc.Domains.BGP.GlobalConfig)
	}
}

// TestBGPNeighborConversionFidelity: RemotePort and MultiHop round-trip
// through the Get shape into the Add shape -- restored neighbors keep
// their transport configuration. (This test previously PINNED the opposite:
// the Get shape could not carry these fields and the conversion zeroed
// them, silently reverting restored neighbors to defaults.)
func TestBGPNeighborConversionFidelity(t *testing.T) {
	got := bgpNeighGetModToMod(cmn.GoBGPNeighGetMod{Addr: "10.0.0.5", RemoteAS: 65010, RemotePort: 1790, MultiHop: true})
	if got.Addr == nil || got.Addr.String() != "10.0.0.5" {
		t.Fatalf("expected Addr to parse to 10.0.0.5, got %v", got.Addr)
	}
	if got.RemoteAS != 65010 {
		t.Fatalf("expected RemoteAS 65010, got %d", got.RemoteAS)
	}
	if got.RemotePort != 1790 || !got.MultiHop {
		t.Fatalf("expected RemotePort/MultiHop to round-trip (1790/true), got %+v", got)
	}
}

func TestApplyBGPGlobalConfigForwardCompat(t *testing.T) {
	hooks := newMockHooks()
	doc := &Document{
		Domains: Domains{
			BGP: BGPDomain{GlobalConfig: &cmn.GoBGPGlobalConfig{LocalAs: 65000, RouterID: "1.1.1.1"}},
		},
	}
	n, _, err := applyBGP(hooks, doc, false)
	if err != nil {
		t.Fatalf("applyBGP: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 item applied (global_config only), got %d", n)
	}
	if hooks.bgpGC == nil || hooks.bgpGC.LocalAs != 65000 {
		t.Fatalf("expected NetGoBGPGCAdd called with the document's GlobalConfig, got: %+v", hooks.bgpGC)
	}
}

// G-7: global config round-trips through get -> apply; unset (zero LocalAs)
// stays nil in the document.
func TestGetBGPGlobalConfigRoundTrip(t *testing.T) {
	hooks := newMockHooks()
	doc := &Document{}
	if err := getBGP(hooks, doc); err != nil {
		t.Fatalf("getBGP (unset gc): %v", err)
	}
	if doc.Domains.BGP.GlobalConfig != nil {
		t.Fatalf("expected nil GlobalConfig when unset, got %+v", doc.Domains.BGP.GlobalConfig)
	}

	hooks.bgpGC = &cmn.GoBGPGlobalConfig{LocalAs: 65001, RouterID: "2.2.2.2", SetNHSelf: true, ListenPort: 1790}
	if err := getBGP(hooks, doc); err != nil {
		t.Fatalf("getBGP: %v", err)
	}
	gc := doc.Domains.BGP.GlobalConfig
	if gc == nil || gc.LocalAs != 65001 || gc.RouterID != "2.2.2.2" || !gc.SetNHSelf || gc.ListenPort != 1790 {
		t.Fatalf("GlobalConfig not captured faithfully: %+v", gc)
	}

	fresh := newMockHooks()
	if _, _, err := applyBGP(fresh, doc, false); err != nil {
		t.Fatalf("applyBGP: %v", err)
	}
	if fresh.bgpGC == nil || *fresh.bgpGC != *gc {
		t.Fatalf("GlobalConfig did not round-trip: got %+v want %+v", fresh.bgpGC, gc)
	}
}

// --- ipsec: tunnels round-trip; certificates fail loudly (PEM data gap) ---

func TestIPsecTunnelGetApplyDelete(t *testing.T) {
	hooks := newMockHooks()
	hooks.ipsecTunnels = []*cmn.IPsecTunnel{{
		IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "tun1", LocalIP: "1.1.1.1", RemoteIP: "2.2.2.2", PSK: "supersecret"},
	}}

	doc := &Document{}
	if err := getIPsec(hooks, doc); err != nil {
		t.Fatalf("getIPsec: %v", err)
	}
	if len(doc.Domains.IPsec.Tunnels) != 1 || doc.Domains.IPsec.Tunnels[0].PSK != "supersecret" {
		t.Fatalf("expected tunnel with PSK captured (embeds IPsecTunnelMod), got: %+v", doc.Domains.IPsec.Tunnels)
	}

	fresh := newMockHooks()
	n, _, err := applyIPsec(fresh, doc, false)
	if err != nil {
		t.Fatalf("applyIPsec: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 tunnel applied, got %d", n)
	}
	found := false
	for _, c := range fresh.Calls {
		if c == "NetIPsecTunnelAdd:tun1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected NetIPsecTunnelAdd:tun1, calls: %v", fresh.Calls)
	}

	nDel, err := deleteIPsec(fresh)
	if err != nil {
		t.Fatalf("deleteIPsec: %v", err)
	}
	if nDel != 1 {
		t.Fatalf("expected 1 tunnel deleted, got %d", nDel)
	}
}

func TestIPsecCertificateRoundTripWithPEM(t *testing.T) {
	// G-3a: capture uses the PEM-bearing ExportAll hooks, so certificates
	// (cert + private-key PEM) and CA certificates round-trip through
	// get -> apply on a fresh backend.
	hooks := newMockHooks()
	if _, err := hooks.NetIPsecCACertificateAdd(&cmn.IPsecCACertificateMod{
		Name: "ca1", CertificatePEM: "CA-PEM", Description: "root ca",
	}); err != nil {
		t.Fatalf("seed CA: %v", err)
	}
	if _, err := hooks.NetIPsecCertificateAdd(&cmn.IPsecCertificateMod{
		Name: "cert1", CertificatePEM: "CERT-PEM", PrivateKeyPEM: "KEY-PEM", Description: "peer cert",
	}); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	doc := &Document{}
	if err := getIPsec(hooks, doc); err != nil {
		t.Fatalf("getIPsec: %v", err)
	}
	if len(doc.Domains.IPsec.Certificates) != 1 || doc.Domains.IPsec.Certificates[0].PrivateKeyPEM != "KEY-PEM" {
		t.Fatalf("capture must carry the private-key PEM, got %+v", doc.Domains.IPsec.Certificates)
	}
	if len(doc.Domains.IPsec.CACertificates) != 1 || doc.Domains.IPsec.CACertificates[0].CertificatePEM != "CA-PEM" {
		t.Fatalf("capture must carry the CA PEM, got %+v", doc.Domains.IPsec.CACertificates)
	}

	fresh := newMockHooks()
	if _, _, err := applyIPsec(fresh, doc, false); err != nil {
		t.Fatalf("applyIPsec: %v", err)
	}
	restored, err := fresh.NetIPsecCertificateExportAll()
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	if len(restored) != 1 || restored[0] != (cmn.IPsecCertificateMod{
		Name: "cert1", CertificatePEM: "CERT-PEM", PrivateKeyPEM: "KEY-PEM", Description: "peer cert",
	}) {
		t.Fatalf("certificate did not round-trip byte-equivalent: %+v", restored)
	}
}

func TestIPsecApplyOrderCertsBeforeTunnels(t *testing.T) {
	// Tunnels in certificate auth mode reference certs by CertName, so
	// apply order must be CA certs -> certs -> tunnels.
	hooks := newMockHooks()
	doc := &Document{
		Domains: Domains{
			IPsec: IPsecDomain{
				Tunnels:        []*cmn.IPsecTunnel{{IPsecTunnelMod: cmn.IPsecTunnelMod{Name: "tun1"}}},
				Certificates:   []cmn.IPsecCertificateMod{{Name: "cert1", CertificatePEM: "P", PrivateKeyPEM: "K"}},
				CACertificates: []cmn.IPsecCACertificateMod{{Name: "ca1", CertificatePEM: "C"}},
			},
		},
	}
	if _, _, err := applyIPsec(hooks, doc, false); err != nil {
		t.Fatalf("applyIPsec: %v", err)
	}
	order := map[string]int{}
	for i, c := range hooks.Calls {
		order[c] = i
	}
	if !(order["NetIPsecCACertificateAdd:ca1"] < order["NetIPsecCertificateAdd:cert1"] &&
		order["NetIPsecCertificateAdd:cert1"] < order["NetIPsecTunnelAdd:tun1"]) {
		t.Fatalf("apply order must be CA -> cert -> tunnel, calls: %v", hooks.Calls)
	}
}

func TestIPsecCertificateDeleteByNameStillWorks(t *testing.T) {
	// Deletion only needs the name (not PEM data).
	hooks := newMockHooks()
	hooks.ipsecCerts = []*cmn.IPsecCertificate{{Name: "cert1"}}
	hooks.ipsecCAs = []*cmn.IPsecCACertificate{{Name: "ca1"}}

	n, err := deleteIPsec(hooks)
	if err != nil {
		t.Fatalf("deleteIPsec: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 deletions (cert + ca), got %d", n)
	}
}
