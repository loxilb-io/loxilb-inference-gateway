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

// dpu_mock_test.go — shared DPU-debug test double.
//
// This is the ONE definition of mockDpuDebugProvider / registerMock. It lives in
// an UNTAGGED test file (no `//go:build doca`) on purpose: the actual DPU-debug
// handler tests (dpu_debug_p65_test.go, dpu_debug_e2e_test.go) are gated behind
// `//go:build doca` because they exercise the DOCA/DPU offload path and require
// that hardware/toolchain, but conntrack_p65_test.go is a pure-mock test of the
// conntrack JSON shape (DOCA-offload field presence + the provider==nil
// backward-compat path) that needs NO hardware. Keeping the test double here lets
// the default `go test` build compile conntrack_p65_test.go while the doca-tagged
// tests still find the same mock under `-tags doca`. The provider interface and
// all referenced types (DocaEntryDetail, DocaQueryFilter, *HwStatsEntry, CtFlowRef)
// are in the default (untagged) handler build, so this double needs no CGO.

package handler

// ---------------------------------------------------------------------------
// mockDpuDebugProvider — satisfies DpuDebugProvider without any CGO.
// ---------------------------------------------------------------------------

type mockDpuDebugProvider struct {
	// entries to return from QueryDocaEntries (nil = no-op)
	entries []DocaEntryDetail
	// queryErr to return from QueryDocaEntries (nil = no error)
	queryErr error
	// capturedFilter is set by QueryDocaEntries so callers can assert params.
	capturedFilter DocaQueryFilter
}

func (m *mockDpuDebugProvider) IsEnabled() bool                       { return true }
func (m *mockDpuDebugProvider) OffloadStats() (uint64, uint64, int64) { return 10, 2, 8 }
func (m *mockDpuDebugProvider) PluginNames() []string                 { return []string{"doca_bf2"} }
func (m *mockDpuDebugProvider) Unregister(_ string)                   {}
func (m *mockDpuDebugProvider) AllFlowHwStats() []FlowHwStatsEntry    { return nil }
func (m *mockDpuDebugProvider) AllFdbHwStats() []FdbHwStatsEntry      { return nil }
func (m *mockDpuDebugProvider) AllRouteHwStats() []RouteHwStatsEntry  { return nil }
func (m *mockDpuDebugProvider) AllAclHwStats() []AclHwStatsEntry      { return nil }
func (m *mockDpuDebugProvider) CircuitBreakerOpen() bool              { return false }
func (m *mockDpuDebugProvider) CircuitBreakerForce(_ string) error    { return nil }
func (m *mockDpuDebugProvider) OffloadStatsByPipe() (map[string]uint64, map[string]uint64, map[string]int64) {
	return map[string]uint64{"ct": 10}, map[string]uint64{"ct": 2}, map[string]int64{"ct": 8}
}
func (m *mockDpuDebugProvider) QueryDocaEntries(filter DocaQueryFilter) ([]DocaEntryDetail, error) {
	m.capturedFilter = filter
	return m.entries, m.queryErr
}
func (m *mockDpuDebugProvider) ReconcileCtFlowStats(_ CtFlowRef) (string, uint64, uint64) {
	return "none", 0, 0
}

// registerMock installs m as the dpuDebugProvider and returns a restore func.
func registerMock(m *mockDpuDebugProvider) func() {
	prev := dpuDebugProvider
	dpuDebugProvider = m
	return func() { dpuDebugProvider = prev }
}
