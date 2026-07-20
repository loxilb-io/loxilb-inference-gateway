package loxinet

// TestPipeMetricsCardinality — production body.
// Covers P49-R2 threat (Prometheus label-cardinality DoS).
//
// extended to assert the {pipe, direction} label set with
// 5 pipes x 3 directions = 15 children pre-instantiated on both
// doca_pipe_hw_pkts_total and doca_pipe_hw_bytes_total. The empty-string
// direction is a first-class value used by legacy LBFlowOffload, route, fdb,
// and acl entries. Co-evolves alongside TestPhase51_DirectionLabelInMetric;
// both must remain green.

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// DPU metric registration is gated on plugin attach (metrics audit D5);
// tests that gather the default registry need the families registered.
func init() {
	registerDpuMetrics()
}

func TestPipeMetricsCardinality(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("DefaultGatherer.Gather() failed: %v", err)
	}

	wantedPipes := map[string]bool{
		"ct": false, "udp_ct": false, "route": false, "fdb": false, "acl": false,
	}
	wantedDirections := map[string]bool{
		"forward": false, "reply": false, "": false,
	}

	matchedMetric := map[string]bool{
		"doca_pipe_hw_pkts_total":  false,
		"doca_pipe_hw_bytes_total": false,
	}

	for _, mf := range mfs {
		name := mf.GetName()
		if _, ok := matchedMetric[name]; !ok {
			continue
		}
		matchedMetric[name] = true

		children := mf.GetMetric()
		if got := len(children); got != 15 {
			t.Errorf("%s has %d label children, want 15 (5 pipes x 3 directions)", name, got)
		}

		seenForThisMetric := map[string]bool{}
		for _, child := range children {
			var pipeVal, directionVal string
			labels := child.GetLabel()
			if got := len(labels); got != 2 {
				t.Errorf("%s child has %d labels, want 2 (pipe + direction)", name, got)
			}
			for _, lp := range labels {
				switch lp.GetName() {
				case "pipe":
					pipeVal = lp.GetValue()
				case "direction":
					directionVal = lp.GetValue()
				default:
					t.Errorf("%s has unexpected label %q on child (only 'pipe' and 'direction' allowed)", name, lp.GetName())
				}
			}

			if _, ok := wantedPipes[pipeVal]; !ok {
				t.Errorf("%s has forbidden pipe value %q (allowed: ct, udp_ct, route, fdb, acl)", name, pipeVal)
			}
			if _, ok := wantedDirections[directionVal]; !ok {
				t.Errorf("%s has forbidden direction value %q (allowed: forward, reply, \"\")", name, directionVal)
			}

			tupleKey := pipeVal + "|" + directionVal
			if seenForThisMetric[tupleKey] {
				t.Errorf("%s has duplicate (pipe=%q, direction=%q) child", name, pipeVal, directionVal)
			}
			seenForThisMetric[tupleKey] = true
			wantedPipes[pipeVal] = true
			wantedDirections[directionVal] = true
		}
	}

	for metricName, seen := range matchedMetric {
		if !seen {
			t.Errorf("metric %q not present in Gather() output — var not registered at init", metricName)
		}
	}

	for pipe, seen := range wantedPipes {
		if !seen {
			t.Errorf("pipe label %q never appeared in scrape — pre-instantiation failed", pipe)
		}
	}

	for dir, seen := range wantedDirections {
		if !seen {
			t.Errorf("direction label %q never appeared in scrape — pre-instantiation failed", dir)
		}
	}
}

// TestDocaOffloadDeferredRetryTotal_AllChildrenPreInstantiated asserts that
// all 4 children of docaOffloadDeferredRetryTotal exist with a sample value
// of 0 immediately after package init (B23-02).
//
// Grafana panels that graph rate(doca_offload_deferred_retry_total{result="X"}
// [5m]) need this flat-line baseline so the first scrape after loxilb start
// does NOT render "no data" until a real event fires (-05
// pre-instantiation discipline).
//
// Closed-enum drift guard: if a future change introduces a new label value
// without also adding it to deferredRetryResultLabelValues, the new child
// will not be pre-instantiated and a graph would dip to "no data" for the
// new label. The "unexpected result label child" assertion catches that drift.
func TestDocaOffloadDeferredRetryTotal_AllChildrenPreInstantiated(t *testing.T) {
	want := map[string]bool{
		"queued":  false,
		"ok":      false,
		"failed":  false,
		"gave_up": false,
	}

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}

	var found bool
	for _, mf := range mfs {
		if mf.GetName() != "doca_offload_deferred_retry_total" {
			continue
		}
		found = true
		if mf.GetType() != dto.MetricType_COUNTER {
			t.Fatalf("doca_offload_deferred_retry_total is not a counter: %v", mf.GetType())
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "result" {
					if _, ok := want[lp.GetValue()]; ok {
						want[lp.GetValue()] = true
					} else {
						t.Errorf("unexpected result label child %q (closed-enum drift?)", lp.GetValue())
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("doca_offload_deferred_retry_total metric family not found in default registry")
	}

	var missing []string
	for k, present := range want {
		if !present {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("missing pre-instantiated children: %s (init() loop did not cover all 4)", strings.Join(missing, ", "))
	}
}

// TestDocaOffloadInstallErrorsTotal_42SeriesPreInstantiated — A2.
// Asserts: after init, the doca_offload_install_errors_total CounterVec
// has all 7 pipe × 6 reason = 42 children pre-instantiated at value 0.
// This is the install-time visibility gate for REQ-55-06: rate(...)[5m]
// must produce a flat-line baseline from first scrape, never "no data",
// for ALL 42 (pipe, reason) tuples.
func TestDocaOffloadInstallErrorsTotal_42SeriesPreInstantiated(t *testing.T) {
	wantPipes := map[string]bool{
		"ct": false, "ct_rev": false, "udp_ct": false, "route": false,
		"fdb": false, "acl": false, "egress_steer": false,
	}
	wantReasons := map[string]bool{
		"invalid_input": false, "capacity_full": false, "null_return": false,
		"timeout": false, "hw_busy": false, "paired_steer_failed": false,
	}

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}

	// Track unique (pipe, reason) tuples seen so we can assert exactly 42.
	tuples := map[string]struct{}{}
	var found bool
	for _, mf := range mfs {
		if mf.GetName() != "doca_offload_install_errors_total" {
			continue
		}
		found = true
		if mf.GetType() != dto.MetricType_COUNTER {
			t.Fatalf("doca_offload_install_errors_total is not a counter: %v", mf.GetType())
		}
		for _, m := range mf.GetMetric() {
			var pipe, reason string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "pipe":
					pipe = lp.GetValue()
					if _, ok := wantPipes[pipe]; ok {
						wantPipes[pipe] = true
					} else {
						t.Errorf("unexpected pipe label child %q (closed-enum drift?)", pipe)
					}
				case "reason":
					reason = lp.GetValue()
					if _, ok := wantReasons[reason]; ok {
						wantReasons[reason] = true
					} else {
						t.Errorf("unexpected reason label child %q (closed-enum drift?)", reason)
					}
				}
			}
			tuples[pipe+"|"+reason] = struct{}{}
			// All children must start at zero.
			if v := m.GetCounter().GetValue(); v != 0 {
				t.Errorf("pre-instantiated child {pipe=%s,reason=%s} has nonzero value %f", pipe, reason, v)
			}
		}
	}
	if !found {
		t.Fatal("doca_offload_install_errors_total metric family not found in default registry")
	}
	if len(tuples) != 42 {
		t.Errorf("expected 42 pre-instantiated (pipe,reason) tuples, got %d", len(tuples))
	}

	var missingPipes, missingReasons []string
	for k, present := range wantPipes {
		if !present {
			missingPipes = append(missingPipes, k)
		}
	}
	for k, present := range wantReasons {
		if !present {
			missingReasons = append(missingReasons, k)
		}
	}
	if len(missingPipes) > 0 {
		t.Errorf("missing pipe children: %s", strings.Join(missingPipes, ", "))
	}
	if len(missingReasons) > 0 {
		t.Errorf("missing reason children: %s", strings.Join(missingReasons, ", "))
	}
}

// ---------------------------------------------------------------------------
// C-4 — UpdateMeterStats delta discipline.
// The DOCA meter query returns CUMULATIVE lifetime totals; UpdateMeterStats
// must Add only the per-tick delta, never the cumulative (the pre-C-4 bug
// grew the counter quadratically: ~N/2x reality after N ticks).
// Meter IDs / names below are unique per test so the package-level
// lastMeterPkts / lastMeterBytes baselines never collide across tests.
// ---------------------------------------------------------------------------

// TestUpdateMeterStats_DeltaOnlyOnce asserts that two consecutive ticks with
// the SAME cumulative totals add the delta exactly once — the second call
// adds 0, and an advancing cumulative adds only the increment.
func TestUpdateMeterStats_DeltaOnlyOnce(t *testing.T) {
	const meterID, name = uint32(424201), "c4-delta"
	pkts := docaMeterPacketsTotal.WithLabelValues("424201", name)
	bytes := docaMeterBytesTotal.WithLabelValues("424201", name)

	// Tick 1: first observation primes the baseline from 0 — full cumulative
	// lands as the first delta (same first-tick semantics as
	// CollectHwOffloadStats' lastPipePktsByDir).
	UpdateMeterStats(meterID, name, 100, 1000)
	if got := testutil.ToFloat64(pkts); got != 100 {
		t.Errorf("pkts after tick 1 = %v, want 100", got)
	}
	if got := testutil.ToFloat64(bytes); got != 1000 {
		t.Errorf("bytes after tick 1 = %v, want 1000", got)
	}

	// Tick 2: identical cumulative — delta is 0, counter must NOT move.
	// The pre-C-4 Add(cumulative) bug would read 200 / 2000 here.
	UpdateMeterStats(meterID, name, 100, 1000)
	if got := testutil.ToFloat64(pkts); got != 100 {
		t.Errorf("pkts after identical tick 2 = %v, want 100 (Add(cumulative) regression?)", got)
	}
	if got := testutil.ToFloat64(bytes); got != 1000 {
		t.Errorf("bytes after identical tick 2 = %v, want 1000 (Add(cumulative) regression?)", got)
	}

	// Tick 3: cumulative advances — only the increment is added.
	UpdateMeterStats(meterID, name, 150, 1600)
	if got := testutil.ToFloat64(pkts); got != 150 {
		t.Errorf("pkts after tick 3 = %v, want 150", got)
	}
	if got := testutil.ToFloat64(bytes); got != 1600 {
		t.Errorf("bytes after tick 3 = %v, want 1600", got)
	}
}

// TestUpdateMeterStats_ResetReprimesBaseline asserts that a DECREASED
// cumulative (C-side meter reset / restart) adds nothing — Counter.Add would
// panic on negative — and re-primes the baseline so the next tick counts
// from the fresh cumulative.
func TestUpdateMeterStats_ResetReprimesBaseline(t *testing.T) {
	const meterID, name = uint32(424202), "c4-reset"
	pkts := docaMeterPacketsTotal.WithLabelValues("424202", name)
	bytes := docaMeterBytesTotal.WithLabelValues("424202", name)

	UpdateMeterStats(meterID, name, 100, 1000)

	// Cumulative shrinks (reset): skip the Add, re-prime baseline to 40/400.
	UpdateMeterStats(meterID, name, 40, 400)
	if got := testutil.ToFloat64(pkts); got != 100 {
		t.Errorf("pkts after reset tick = %v, want 100 (reset must add nothing)", got)
	}
	if got := testutil.ToFloat64(bytes); got != 1000 {
		t.Errorf("bytes after reset tick = %v, want 1000 (reset must add nothing)", got)
	}

	// Next tick counts from the re-primed baseline: delta = 10 / 50.
	UpdateMeterStats(meterID, name, 50, 450)
	if got := testutil.ToFloat64(pkts); got != 110 {
		t.Errorf("pkts after post-reset tick = %v, want 110 (baseline not re-primed)", got)
	}
	if got := testutil.ToFloat64(bytes); got != 1050 {
		t.Errorf("bytes after post-reset tick = %v, want 1050 (baseline not re-primed)", got)
	}
}

// ---------------------------------------------------------------------------
// H-25 — route rows must be counted from ONE source only.
// The BF2 plugin reports the same route entries through BOTH AllFlowStats
// (pipeKey=="route") and AllRouteStats; summing both doubled the cumulative
// aggregate, and a doubled cumulative produces a doubled per-tick delta on
// doca_pipe_hw_pkts_total{pipe="route"} / doca_pipe_hw_bytes_total.
// AllRouteStats is the authoritative route source; the AllFlowStats loop
// skips pipeKey=="route" rows.
// ---------------------------------------------------------------------------

// hwStatsMockPlugin is a no-op DpuPlugin that also implements
// flowStatsProvider + multiPipeStatsProvider with canned rows, mirroring the
// BF2 dual-surface reporting of route entries.
type hwStatsMockPlugin struct {
	flowRows  []FlowHwStats
	routeRows []RouteHwStats
}

var (
	_ DpuPlugin              = (*hwStatsMockPlugin)(nil)
	_ flowStatsProvider      = (*hwStatsMockPlugin)(nil)
	_ multiPipeStatsProvider = (*hwStatsMockPlugin)(nil)
)

func (p *hwStatsMockPlugin) Init(cfg DpuConfig) error                     { return nil }
func (p *hwStatsMockPlugin) Shutdown() error                              { return nil }
func (p *hwStatsMockPlugin) Name() string                                 { return "hw-stats-mock" }
func (p *hwStatsMockPlugin) Capabilities() DpuCapabilities                { return DpuCapabilities{} }
func (p *hwStatsMockPlugin) LBFlowOffload(ct *DpCtInfo, lbMark int) error { return nil }
func (p *hwStatsMockPlugin) LBFlowRemove(ct *DpCtInfo) error              { return nil }
func (p *hwStatsMockPlugin) RouteAdd(w *RouteDpWorkQ) error               { return nil }
func (p *hwStatsMockPlugin) RouteDel(w *RouteDpWorkQ) error               { return nil }
func (p *hwStatsMockPlugin) RouteFlowOffload(ct *DpCtInfo, rid int) error { return nil }
func (p *hwStatsMockPlugin) FdbFlowOffload(fdb *FdbEnt) error             { return nil }
func (p *hwStatsMockPlugin) FdbFlowRemove(fdb *FdbEnt) error              { return nil }
func (p *hwStatsMockPlugin) FwRuleAdd(w *FwDpWorkQ) error                 { return nil }
func (p *hwStatsMockPlugin) FwRuleDel(w *FwDpWorkQ) error                 { return nil }
func (p *hwStatsMockPlugin) NextHopAdd(w *NextHopDpWorkQ) error           { return nil }
func (p *hwStatsMockPlugin) NextHopDel(w *NextHopDpWorkQ) error           { return nil }
func (p *hwStatsMockPlugin) MeterAdd(w *PolDpWorkQ) error                 { return nil }
func (p *hwStatsMockPlugin) MeterDel(w *PolDpWorkQ) error                 { return nil }
func (p *hwStatsMockPlugin) FlowStats(ct *DpCtInfo) (uint64, uint64, error) {
	return 0, 0, nil
}
func (p *hwStatsMockPlugin) PipeStats(name string) (uint32, error) { return 0, nil }
func (p *hwStatsMockPlugin) AllFlowStats() []FlowHwStats           { return p.flowRows }
func (p *hwStatsMockPlugin) AllFdbStats() []FdbHwStats             { return nil }
func (p *hwStatsMockPlugin) AllRouteStats() []RouteHwStats         { return p.routeRows }
func (p *hwStatsMockPlugin) AllAclStats() []AclHwStats             { return nil }

// TestCollectHwOffloadStats_RouteCountedOnce presents the SAME route entry
// through both AllFlowStats and AllRouteStats across two ticks and asserts
// that the per-tick delta lands once (not 2x). A ct row rides along to prove
// the route skip in the AllFlowStats loop does not drop non-route entries.
func TestCollectHwOffloadStats_RouteCountedOnce(t *testing.T) {
	mock := &hwStatsMockPlugin{}
	m := &DpuManager{plugins: []DpuPlugin{mock}, enabled: true}

	routePkts := docaPipeHwPktsTotal.WithLabelValues("route", "")
	routeBytes := docaPipeHwBytesTotal.WithLabelValues("route", "")
	ctPkts := docaPipeHwPktsTotal.WithLabelValues("ct", "forward")

	// Tick 1 primes the package-level lastPipePktsByDir / lastPipeBytesByDir
	// baselines regardless of what earlier tests left behind — assertions
	// below compare tick-2 deltas, not absolute values.
	mock.flowRows = []FlowHwStats{
		{FlowKey: "r1", PipeKey: "route", Direction: "", HwPkts: 100, HwBytes: 1000},
		{FlowKey: "c1", PipeKey: "ct", Direction: "forward", HwPkts: 30, HwBytes: 300},
	}
	mock.routeRows = []RouteHwStats{
		{Dst: "10.0.0.0/24", HwPkts: 100, HwBytes: 1000},
	}
	m.CollectHwOffloadStats()

	routePktsT1 := testutil.ToFloat64(routePkts)
	routeBytesT1 := testutil.ToFloat64(routeBytes)
	ctPktsT1 := testutil.ToFloat64(ctPkts)

	// Tick 2: the same entry advances by 100 pkts / 1000 bytes on BOTH
	// surfaces. Pre-H-25 code summed both into pktsNow["route|"] and the
	// delta doubled to 200 / 2000.
	mock.flowRows = []FlowHwStats{
		{FlowKey: "r1", PipeKey: "route", Direction: "", HwPkts: 200, HwBytes: 2000},
		{FlowKey: "c1", PipeKey: "ct", Direction: "forward", HwPkts: 80, HwBytes: 800},
	}
	mock.routeRows = []RouteHwStats{
		{Dst: "10.0.0.0/24", HwPkts: 200, HwBytes: 2000},
	}
	m.CollectHwOffloadStats()

	if d := testutil.ToFloat64(routePkts) - routePktsT1; d != 100 {
		t.Errorf("route pkts tick-2 delta = %v, want 100 (200 means both sources still counted — H-25 regression)", d)
	}
	if d := testutil.ToFloat64(routeBytes) - routeBytesT1; d != 1000 {
		t.Errorf("route bytes tick-2 delta = %v, want 1000 (2000 means both sources still counted — H-25 regression)", d)
	}
	if d := testutil.ToFloat64(ctPkts) - ctPktsT1; d != 50 {
		t.Errorf("ct forward pkts tick-2 delta = %v, want 50 (route skip must not drop non-route rows)", d)
	}
}
