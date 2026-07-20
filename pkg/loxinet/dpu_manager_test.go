/*
 * Copyright (c) 2022 NetLOX Inc
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

package loxinet

import (
	"fmt"
	"sync"
	"testing"
)

// MockDpuPlugin implements DpuPlugin for testing.
type MockDpuPlugin struct {
	name                  string
	caps                  DpuCapabilities
	initErr               error
	routeAddCalls         int
	routeFlowOffloadCalls int
	flowOffloadCalls      int
	flowRemoveCalls       int
	fwAddCalls            int
	shutdownCalls         int
}

func (m *MockDpuPlugin) Init(cfg DpuConfig) error      { return m.initErr }
func (m *MockDpuPlugin) Shutdown() error               { m.shutdownCalls++; return nil }
func (m *MockDpuPlugin) Name() string                  { return m.name }
func (m *MockDpuPlugin) Capabilities() DpuCapabilities { return m.caps }

func (m *MockDpuPlugin) LBFlowOffload(ct *DpCtInfo, lbMark int) error {
	m.flowOffloadCalls++
	return nil
}
func (m *MockDpuPlugin) LBFlowRemove(ct *DpCtInfo) error {
	m.flowRemoveCalls++
	return nil
}
func (m *MockDpuPlugin) RouteAdd(w *RouteDpWorkQ) error {
	m.routeAddCalls++
	return nil
}
func (m *MockDpuPlugin) RouteDel(w *RouteDpWorkQ) error { return ErrNotSupported }
func (m *MockDpuPlugin) RouteFlowOffload(ct *DpCtInfo, rid int) error {
	m.routeFlowOffloadCalls++
	return nil
}
func (m *MockDpuPlugin) FwRuleAdd(w *FwDpWorkQ) error       { m.fwAddCalls++; return nil }
func (m *MockDpuPlugin) FwRuleDel(w *FwDpWorkQ) error       { return ErrNotSupported }
func (m *MockDpuPlugin) FdbFlowOffload(fdb *FdbEnt) error   { return ErrNotSupported }
func (m *MockDpuPlugin) FdbFlowRemove(fdb *FdbEnt) error    { return ErrNotSupported }
func (m *MockDpuPlugin) NextHopAdd(w *NextHopDpWorkQ) error { return ErrNotSupported }
func (m *MockDpuPlugin) NextHopDel(w *NextHopDpWorkQ) error { return ErrNotSupported }
func (m *MockDpuPlugin) FlowStats(ct *DpCtInfo) (uint64, uint64, error) {
	return 0, 0, ErrNotSupported
}
func (m *MockDpuPlugin) PipeStats(name string) (uint32, error) {
	return 0, ErrNotSupported
}
func (m *MockDpuPlugin) MeterAdd(w *PolDpWorkQ) error { return ErrNotSupported }
func (m *MockDpuPlugin) MeterDel(w *PolDpWorkQ) error { return ErrNotSupported }

// TestDpuManagerRegistration verifies plugin registration and capability query.
func TestDpuManagerRegistration(t *testing.T) {
	mgr := DpuManagerInit()
	if mgr.IsEnabled() {
		t.Fatal("expected manager to be disabled before registration")
	}

	mock := &MockDpuPlugin{
		name: "test-plugin",
		caps: DpuCapabilities{LBOffload: true, CTRouteOffload: false},
	}
	mgr.Register(mock)

	if !mgr.IsEnabled() {
		t.Fatal("expected manager to be enabled after registration")
	}
	if mock.Name() != "test-plugin" {
		t.Fatalf("expected name 'test-plugin', got '%s'", mock.Name())
	}
	if !mock.Capabilities().LBOffload {
		t.Fatal("expected LBOffload capability to be true")
	}
	if mock.Capabilities().CTRouteOffload {
		t.Fatal("expected CTRouteOffload capability to be false")
	}
}

// TestDpuManagerDispatchRouting verifies capability-driven dispatch routing.
func TestDpuManagerDispatchRouting(t *testing.T) {
	mgr := DpuManagerInit()
	mock := &MockDpuPlugin{
		name: "routing-test",
		caps: DpuCapabilities{LBOffload: true, CTRouteOffload: false},
	}
	mgr.Register(mock)

	// ShadowLBFlowOffload should invoke plugin (LBOffload=true)
	mgr.ShadowLBFlowOffload(&DpCtInfo{}, 0)
	if mock.flowOffloadCalls != 1 {
		t.Fatalf("expected flowOffloadCalls=1, got %d", mock.flowOffloadCalls)
	}

	// ShadowRouteAdd should NOT invoke plugin (CTRouteOffload=false)
	mgr.ShadowRouteAdd(&RouteDpWorkQ{})
	if mock.routeAddCalls != 0 {
		t.Fatalf("expected routeAddCalls=0, got %d", mock.routeAddCalls)
	}

	// ShadowRouteFlowOffload should NOT invoke plugin (CTRouteOffload=false)
	mgr.ShadowRouteFlowOffload(&DpCtInfo{}, 0)
	if mock.routeFlowOffloadCalls != 0 {
		t.Fatalf("expected routeFlowOffloadCalls=0, got %d", mock.routeFlowOffloadCalls)
	}
}

// TestDpuManagerGracefulDegradation verifies error logging without panic.
func TestDpuManagerGracefulDegradation(t *testing.T) {
	mgr := DpuManagerInit()
	mock := &MockDpuPlugin{
		name: "error-test",
		caps: DpuCapabilities{LBOffload: true},
	}
	mgr.Register(mock)

	// Should not panic on flow offload dispatch
	mgr.ShadowLBFlowOffload(&DpCtInfo{}, 0)
	if mock.flowOffloadCalls != 1 {
		t.Fatalf("expected flowOffloadCalls=1, got %d", mock.flowOffloadCalls)
	}
}

// TestDpuManagerMultiPluginFanout verifies fan-out to multiple plugins.
func TestDpuManagerMultiPluginFanout(t *testing.T) {
	mgr := DpuManagerInit()
	mock1 := &MockDpuPlugin{
		name: "plugin-1",
		caps: DpuCapabilities{LBOffload: true},
	}
	mock2 := &MockDpuPlugin{
		name: "plugin-2",
		caps: DpuCapabilities{LBOffload: true},
	}
	mgr.Register(mock1)
	mgr.Register(mock2)

	mgr.ShadowLBFlowOffload(&DpCtInfo{}, 0)
	if mock1.flowOffloadCalls != 1 {
		t.Fatalf("expected plugin-1 flowOffloadCalls=1, got %d", mock1.flowOffloadCalls)
	}
	if mock2.flowOffloadCalls != 1 {
		t.Fatalf("expected plugin-2 flowOffloadCalls=1, got %d", mock2.flowOffloadCalls)
	}
}

// TestDpuManagerNotEnabled verifies no-op when no plugins are registered.
func TestDpuManagerNotEnabled(t *testing.T) {
	mgr := DpuManagerInit()

	// Should not panic with no plugins registered
	mgr.ShadowRouteAdd(&RouteDpWorkQ{})
	mgr.ShadowFwRuleAdd(&FwDpWorkQ{})
	mgr.ShadowLBFlowOffload(&DpCtInfo{}, 0)
	mgr.ShadowLBFlowRemove(&DpCtInfo{})
	mgr.ShadowRouteFlowOffload(&DpCtInfo{}, 0)
	mgr.ShadowRouteDel(&RouteDpWorkQ{})
	mgr.ShadowFwRuleDel(&FwDpWorkQ{})
}

// countingMockPlugin is a DpuPlugin that returns configurable errors from a slice
// (pop-from-front pattern) so tests can drive both success and failure paths
// deterministically through Shadow*Offload dispatchers. Used by TestOffloadStatsByPipe.
type countingMockPlugin struct {
	mu       sync.Mutex
	name     string
	caps     DpuCapabilities
	lbErrs   []error
	rtErrs   []error
	fdbErrs  []error
	aclErrs  []error // ShadowFwRuleAdd -> FwRuleAdd returns error (not int)
	initErr  error
	shutdown int
}

func (p *countingMockPlugin) Init(cfg DpuConfig) error      { return p.initErr }
func (p *countingMockPlugin) Shutdown() error               { p.shutdown++; return nil }
func (p *countingMockPlugin) Name() string                  { return p.name }
func (p *countingMockPlugin) Capabilities() DpuCapabilities { return p.caps }

// popErr pops the first element of errs (if any) and returns it.
// On empty slice returns nil (treated as success). Uses p.mu to guard
// concurrent pops from the race-detector test.
func (p *countingMockPlugin) popErr(errs *[]error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(*errs) == 0 {
		return nil
	}
	e := (*errs)[0]
	*errs = (*errs)[1:]
	return e
}

func (p *countingMockPlugin) LBFlowOffload(ct *DpCtInfo, lbMark int) error {
	return p.popErr(&p.lbErrs)
}
func (p *countingMockPlugin) LBFlowRemove(ct *DpCtInfo) error { return nil }
func (p *countingMockPlugin) RouteAdd(w *RouteDpWorkQ) error  { return nil }
func (p *countingMockPlugin) RouteDel(w *RouteDpWorkQ) error  { return nil }
func (p *countingMockPlugin) RouteFlowOffload(ct *DpCtInfo, rid int) error {
	return p.popErr(&p.rtErrs)
}
func (p *countingMockPlugin) FwRuleAdd(w *FwDpWorkQ) error { return p.popErr(&p.aclErrs) }
func (p *countingMockPlugin) FwRuleDel(w *FwDpWorkQ) error { return nil }
func (p *countingMockPlugin) FdbFlowOffload(fdb *FdbEnt) error {
	return p.popErr(&p.fdbErrs)
}
func (p *countingMockPlugin) FdbFlowRemove(fdb *FdbEnt) error { return nil }
func (p *countingMockPlugin) NextHopAdd(w *NextHopDpWorkQ) error {
	return ErrNotSupported
}
func (p *countingMockPlugin) NextHopDel(w *NextHopDpWorkQ) error {
	return ErrNotSupported
}
func (p *countingMockPlugin) FlowStats(ct *DpCtInfo) (uint64, uint64, error) {
	return 0, 0, ErrNotSupported
}
func (p *countingMockPlugin) PipeStats(name string) (uint32, error) {
	return 0, ErrNotSupported
}
func (p *countingMockPlugin) MeterAdd(w *PolDpWorkQ) error { return ErrNotSupported }
func (p *countingMockPlugin) MeterDel(w *PolDpWorkQ) error { return ErrNotSupported }

// TestOffloadStatsByPipe asserts per-pipe counter semantics and latent-gap fixes:
// - ShadowRouteFlowOffload success bumps success_by_pipe[route] (previously 0)
// - ShadowFdbFlowOffload success bumps success_by_pipe[fdb] (previously 0)
// - ShadowFwRuleAdd success bumps success_by_pipe[acl] (previously 0)
// - Failures bump failure_by_pipe[...] without touching active
// - UDP LB traffic routes to pipeUDPCT via inferLBPipeKind
// - Legacy OffloadStats sum equals OffloadStatsByPipe totals
func TestOffloadStatsByPipe(t *testing.T) {
	mgr := DpuManagerInit()
	mock := &countingMockPlugin{
		name: "mock-p49",
		caps: DpuCapabilities{
			LBOffload:      true,
			CTRouteOffload: true,
			L2Switching:    true,
			ACLOffload:     true,
		},
	}
	mgr.Register(mock)

	// 3 successful TCP LB offloads
	tcpCT := &DpCtInfo{Proto: "tcp"}
	for i := 0; i < 3; i++ {
		if err := mgr.ShadowLBFlowOffload(tcpCT, 0); err != nil {
			t.Fatalf("LB offload #%d unexpected error: %v", i, err)
		}
	}

	// 2 successful Route offloads (fixes latent gap)
	for i := 0; i < 2; i++ {
		if err := mgr.ShadowRouteFlowOffload(tcpCT, 100+i); err != nil {
			t.Fatalf("Route offload #%d unexpected error: %v", i, err)
		}
	}

	// 1 successful FDB + 1 failing FDB
	mock.fdbErrs = []error{nil, fmt.Errorf("simulated FDB failure")}
	mgr.ShadowFdbFlowOffload(&FdbEnt{})
	mgr.ShadowFdbFlowOffload(&FdbEnt{})

	// 1 successful ACL add + 1 failing
	mock.aclErrs = []error{nil, fmt.Errorf("simulated ACL failure")}
	mgr.ShadowFwRuleAdd(&FwDpWorkQ{})
	mgr.ShadowFwRuleAdd(&FwDpWorkQ{})

	success, failure, active := mgr.OffloadStatsByPipe()

	// success counts
	if got := success["ct"]; got != 3 {
		t.Errorf("success[ct]=%d want 3", got)
	}
	if got := success["route"]; got != 2 {
		t.Errorf("success[route]=%d want 2 (latent gap fix)", got)
	}
	if got := success["fdb"]; got != 1 {
		t.Errorf("success[fdb]=%d want 1 (latent gap fix)", got)
	}
	if got := success["acl"]; got != 1 {
		t.Errorf("success[acl]=%d want 1 (latent gap fix)", got)
	}
	if got := success["udp_ct"]; got != 0 {
		t.Errorf("success[udp_ct]=%d want 0 (no UDP in this test)", got)
	}

	// failure counts
	if got := failure["fdb"]; got != 1 {
		t.Errorf("failure[fdb]=%d want 1", got)
	}
	if got := failure["acl"]; got != 1 {
		t.Errorf("failure[acl]=%d want 1", got)
	}

	// active totals — failures do not increment active; successes do
	wantActive := int64(3 + 2 + 1 + 1) // ct + route + fdb + acl
	if got := active["total"]; got != wantActive {
		t.Errorf("active[total]=%d want %d", got, wantActive)
	}

	// legacy scalar parity: OffloadStats sum == OffloadStatsByPipe totals
	scSuccess, scFailure, scActive := mgr.OffloadStats()
	if scSuccess != 3+2+1+1 {
		t.Errorf("legacy scalar success=%d want %d", scSuccess, 3+2+1+1)
	}
	if scFailure != 1+1 {
		t.Errorf("legacy scalar failure=%d want %d", scFailure, 1+1)
	}
	if scActive != wantActive {
		t.Errorf("legacy scalar active=%d want %d", scActive, wantActive)
	}

	// UDP CT inference — ShadowLBFlowOffload with ct.Proto="udp" -> pipeUDPCT
	udpCT := &DpCtInfo{Proto: "udp"}
	if err := mgr.ShadowLBFlowOffload(udpCT, 0); err != nil {
		t.Fatalf("UDP LB offload unexpected error: %v", err)
	}
	success, _, _ = mgr.OffloadStatsByPipe()
	if success["udp_ct"] != 1 {
		t.Errorf("after UDP LB, success[udp_ct]=%d want 1", success["udp_ct"])
	}
	if success["ct"] != 3 {
		t.Errorf("UDP must not bump CT: success[ct]=%d want 3", success["ct"])
	}
}

// TestOffloadStatsByPipe_Race validates lock-free atomic counter semantics
// under concurrent Shadow* dispatch. Run with `go test -race`.
func TestOffloadStatsByPipe_Race(t *testing.T) {
	mgr := DpuManagerInit()
	mock := &countingMockPlugin{
		name: "mock-p49-race",
		caps: DpuCapabilities{
			LBOffload:      true,
			CTRouteOffload: true,
			L2Switching:    true,
			ACLOffload:     true,
		},
	}
	mgr.Register(mock)

	const N = 100
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(4)
		go func() { defer wg.Done(); mgr.ShadowLBFlowOffload(&DpCtInfo{Proto: "tcp"}, 0) }()
		go func() { defer wg.Done(); mgr.ShadowRouteFlowOffload(&DpCtInfo{Proto: "tcp"}, 0) }()
		go func() { defer wg.Done(); mgr.ShadowFdbFlowOffload(&FdbEnt{}) }()
		go func() { defer wg.Done(); mgr.ShadowFwRuleAdd(&FwDpWorkQ{}) }()
	}
	wg.Wait()

	success, _, active := mgr.OffloadStatsByPipe()
	want := uint64(N)
	for _, k := range []string{"ct", "route", "fdb", "acl"} {
		if success[k] != want {
			t.Errorf("success[%s]=%d want %d", k, success[k], want)
		}
	}
	if active["total"] != int64(4*N) {
		t.Errorf("active[total]=%d want %d", active["total"], 4*N)
	}
}
