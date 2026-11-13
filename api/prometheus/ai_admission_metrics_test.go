/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

package prometheus

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAdmissionServiceLabel(t *testing.T) {
	if got := admissionServiceLabel(0x0a01a8c0, 8080); got != "192.168.1.10:8080" {
		t.Errorf("admissionServiceLabel = %q, want 192.168.1.10:8080", got)
	}
}

func TestAdmissionPoolLabel(t *testing.T) {
	cases := map[string]string{
		"":                      "-",
		"llm.example|/v1":       "llm.example__v1",
		"model-a":               "model-a",
		strings.Repeat("p", 80): strings.Repeat("p", 64),
	}
	for key, want := range cases {
		if got := admissionPoolLabel(key); got != want {
			t.Errorf("admissionPoolLabel(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestSortAndDedupeAdmissionSamples(t *testing.T) {
	samples := []admissionSample{
		{service: "10.0.0.2:80", pool: "a", inflight: 1},
		{service: "10.0.0.1:80", pool: "b", inflight: 2},
		{service: "10.0.0.1:80", pool: "a", inflight: 3},
		{service: "10.0.0.1:80", pool: "a", inflight: 4},
	}
	sortAdmissionSamples(samples)
	samples = dedupeAdmissionSamples(samples)

	want := []string{"10.0.0.1:80/a", "10.0.0.1:80/b", "10.0.0.2:80/a"}
	if len(samples) != len(want) {
		t.Fatalf("got %d samples, want %d", len(samples), len(want))
	}
	for i, w := range want {
		if got := samples[i].service + "/" + samples[i].pool; got != w {
			t.Errorf("sorted[%d] = %q, want %q", i, got, w)
		}
	}
	// The first of the two duplicate rows is the one kept.
	if samples[0].inflight != 3 {
		t.Errorf("duplicate resolution kept inflight=%v, want the first row (3)", samples[0].inflight)
	}
}

func withAdmissionStore(t *testing.T, samples []admissionSample, anomalies [5]float64) {
	t.Helper()
	admissionStoreMutex.Lock()
	savedStore, savedAnomalies := admissionStore, admissionAnomalies
	admissionStore, admissionAnomalies = samples, anomalies
	admissionStoreMutex.Unlock()
	t.Cleanup(func() {
		admissionStoreMutex.Lock()
		admissionStore, admissionAnomalies = savedStore, savedAnomalies
		admissionStoreMutex.Unlock()
	})
}

func TestAdmissionCollectorEmptyStore(t *testing.T) {
	withAdmissionStore(t, nil, [5]float64{})

	// No pool: only the process-wide anomaly counters, at zero, so "never
	// anomalous" and "not exported" are distinguishable.
	if n := testutil.CollectAndCount(admissionCollector{}); n != 5 {
		t.Errorf("empty store emitted %d metrics, want 5 (the anomaly counters)", n)
	}
	want := `
# HELP loxilb_ai_admission_anomalies_total Accounting anomalies in the capacity gate, process-wide: underflow (a release found its counter at zero), unknown_permit (an executing permit with no pool), tenant_table_full (a request whose tenant found the pool's tenant table full and shared the last slot with the other tenants past it), h2_deny_headers (an HTTP/2 refusal had more headers than its frame holds; the stream was reset instead) and expose_head_overflow (an HTTP/1.1 response head arrived in pieces and grew past 16 KiB before it ended; it was relayed as it came, without the admission headers). underflow, unknown_permit and h2_deny_headers are defects; tenant_table_full means more tenants than the table holds are active on one pool; expose_head_overflow means a backend sends response heads larger than the gateway assembles.
# TYPE loxilb_ai_admission_anomalies_total counter
loxilb_ai_admission_anomalies_total{kind="expose_head_overflow"} 0
loxilb_ai_admission_anomalies_total{kind="h2_deny_headers"} 0
loxilb_ai_admission_anomalies_total{kind="tenant_table_full"} 0
loxilb_ai_admission_anomalies_total{kind="underflow"} 0
loxilb_ai_admission_anomalies_total{kind="unknown_permit"} 0
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_anomalies_total"); err != nil {
		t.Errorf("anomaly series mismatch: %v", err)
	}
}

// Each anomaly kind is exported under its own label, in the order of the
// gate's enum fc_anomaly: the fifth, expose_head_overflow, is a split
// HTTP/1.1 response head that outgrew the assembly bound.
func TestAdmissionCollectorExportsEveryAnomalyKind(t *testing.T) {
	withAdmissionStore(t, nil, [5]float64{1, 2, 3, 4, 5})

	want := `
# HELP loxilb_ai_admission_anomalies_total Accounting anomalies in the capacity gate, process-wide: underflow (a release found its counter at zero), unknown_permit (an executing permit with no pool), tenant_table_full (a request whose tenant found the pool's tenant table full and shared the last slot with the other tenants past it), h2_deny_headers (an HTTP/2 refusal had more headers than its frame holds; the stream was reset instead) and expose_head_overflow (an HTTP/1.1 response head arrived in pieces and grew past 16 KiB before it ended; it was relayed as it came, without the admission headers). underflow, unknown_permit and h2_deny_headers are defects; tenant_table_full means more tenants than the table holds are active on one pool; expose_head_overflow means a backend sends response heads larger than the gateway assembles.
# TYPE loxilb_ai_admission_anomalies_total counter
loxilb_ai_admission_anomalies_total{kind="expose_head_overflow"} 5
loxilb_ai_admission_anomalies_total{kind="h2_deny_headers"} 4
loxilb_ai_admission_anomalies_total{kind="tenant_table_full"} 3
loxilb_ai_admission_anomalies_total{kind="underflow"} 1
loxilb_ai_admission_anomalies_total{kind="unknown_permit"} 2
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_anomalies_total"); err != nil {
		t.Errorf("anomaly series mismatch: %v", err)
	}
}

func TestAdmissionCollectorEmitsLabelledSeries(t *testing.T) {
	withAdmissionStore(t, []admissionSample{{
		service:        "192.168.1.10:8080",
		pool:           "llm",
		mode:           2,
		maxOutstanding: 64,
		inflight:       5,
		epCap:          [3]float64{8, 4, 0},
		epInflight:     [3]float64{5, 0, 0},
		decisions:      [14]float64{100, 7, 1, 0, 12, 30, 2, 3, 4, 5, 0, 6, 9, 11},
		queued:         3,
		queueDepth:     16,
		qwaitBuckets:   [8]uint64{10, 5, 0, 0, 2, 0, 0, 1},
		qwaitSumMs:     8_250,
		qwaitCount:     18,
		effectiveLimit: 51,
		adaptState:     2,
		adaptReason:    1,
		adaptMoves:     [2]float64{3, 1},
		warmingEps:     1,
		tenantsActive:  2,
		tenantSlots:    256,
	}}, [5]float64{0, 1, 0, 0, 0})

	want := `
# HELP loxilb_ai_admission_inflight Capacity units held right now. role="service" is the pool-wide count, one per executing inference request; the other roles sum the endpoint units held across the pool's endpoints for that role. Zero with the gate off.
# TYPE loxilb_ai_admission_inflight gauge
loxilb_ai_admission_inflight{pool="llm",role="decode",service="192.168.1.10:8080"} 0
loxilb_ai_admission_inflight{pool="llm",role="normal",service="192.168.1.10:8080"} 5
loxilb_ai_admission_inflight{pool="llm",role="prefill",service="192.168.1.10:8080"} 0
loxilb_ai_admission_inflight{pool="llm",role="service",service="192.168.1.10:8080"} 5
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_inflight"); err != nil {
		t.Errorf("inflight series mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_admission_limit Ceiling in force for the role: role="service" is the pool-wide bound on executing requests, role="queue" is the bound on requests waiting for a unit (0: over a ceiling is refused at once), the other roles are the per-endpoint bound for that role. 0 means unlimited at that level.
# TYPE loxilb_ai_admission_limit gauge
loxilb_ai_admission_limit{pool="llm",role="decode",service="192.168.1.10:8080"} 0
loxilb_ai_admission_limit{pool="llm",role="normal",service="192.168.1.10:8080"} 8
loxilb_ai_admission_limit{pool="llm",role="prefill",service="192.168.1.10:8080"} 4
loxilb_ai_admission_limit{pool="llm",role="queue",service="192.168.1.10:8080"} 16
loxilb_ai_admission_limit{pool="llm",role="service",service="192.168.1.10:8080"} 64
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_limit"); err != nil {
		t.Errorf("limit series mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_admission_queued Inference requests parked on the pool right now, waiting for a capacity unit. Zero with no queue depth configured.
# TYPE loxilb_ai_admission_queued gauge
loxilb_ai_admission_queued{pool="llm",service="192.168.1.10:8080"} 3
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_queued"); err != nil {
		t.Errorf("queued series mismatch: %v", err)
	}

	// The C side counts each wait once, in its bucket; the exposition is
	// cumulative, with the sum in seconds.
	want = `
# HELP loxilb_ai_admission_queue_wait_seconds Time a request waited in the pool's queue: one sample per park, taken when the park ends (admitted, expired, shed by eviction or cancelled) and measured from its first park, so a woken request that goes back to its place is one wait, not two. A request drained from the queue is not sampled.
# TYPE loxilb_ai_admission_queue_wait_seconds histogram
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.01"} 10
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.05"} 15
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.1"} 15
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.25"} 15
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="0.5"} 17
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="1"} 17
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="2.5"} 17
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="5"} 18
loxilb_ai_admission_queue_wait_seconds_bucket{pool="llm",service="192.168.1.10:8080",le="+Inf"} 18
loxilb_ai_admission_queue_wait_seconds_sum{pool="llm",service="192.168.1.10:8080"} 8.25
loxilb_ai_admission_queue_wait_seconds_count{pool="llm",service="192.168.1.10:8080"} 18
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_queue_wait_seconds"); err != nil {
		t.Errorf("queue wait histogram mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_admission_decisions_total Gate decisions per pool and reason: admitted, capacity_shed (429), no_healthy_capacity (503), observe_would_shed (admitted in observe mode where enforce would have refused, counted at each ceiling that would have refused it), bypass_non_inference (not an inference request, no unit taken), queued (parked to wait for a unit, once per park: a woken request that goes back to its place is the same park), queue_full (429, the queue at its depth), queue_timeout (504, waited the whole window), cancelled (the client left while waiting), drained (the pool or the process stopped taking work while it waited), observe_would_queue (admitted in observe mode where enforce would have parked it), draining (503, the process is draining for maintenance), tenant_share (429, the tenant holds its share of the ceiling or of the queue), shed (429 admission_shed, a sheddable request refused at a ceiling or evicted from the queue by band policy).
# TYPE loxilb_ai_admission_decisions_total counter
loxilb_ai_admission_decisions_total{pool="llm",reason="admitted",service="192.168.1.10:8080"} 100
loxilb_ai_admission_decisions_total{pool="llm",reason="bypass_non_inference",service="192.168.1.10:8080"} 12
loxilb_ai_admission_decisions_total{pool="llm",reason="cancelled",service="192.168.1.10:8080"} 4
loxilb_ai_admission_decisions_total{pool="llm",reason="capacity_shed",service="192.168.1.10:8080"} 7
loxilb_ai_admission_decisions_total{pool="llm",reason="drained",service="192.168.1.10:8080"} 5
loxilb_ai_admission_decisions_total{pool="llm",reason="draining",service="192.168.1.10:8080"} 6
loxilb_ai_admission_decisions_total{pool="llm",reason="no_healthy_capacity",service="192.168.1.10:8080"} 1
loxilb_ai_admission_decisions_total{pool="llm",reason="observe_would_queue",service="192.168.1.10:8080"} 0
loxilb_ai_admission_decisions_total{pool="llm",reason="observe_would_shed",service="192.168.1.10:8080"} 0
loxilb_ai_admission_decisions_total{pool="llm",reason="queue_full",service="192.168.1.10:8080"} 2
loxilb_ai_admission_decisions_total{pool="llm",reason="queue_timeout",service="192.168.1.10:8080"} 3
loxilb_ai_admission_decisions_total{pool="llm",reason="queued",service="192.168.1.10:8080"} 30
loxilb_ai_admission_decisions_total{pool="llm",reason="shed",service="192.168.1.10:8080"} 11
loxilb_ai_admission_decisions_total{pool="llm",reason="tenant_share",service="192.168.1.10:8080"} 9
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_decisions_total"); err != nil {
		t.Errorf("decisions series mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_admission_mode Capacity gate mode on the pool: 0 off (dispatch path unchanged), 1 observe (decisions counted, everything admitted), 2 enforce (over a ceiling is refused). Present for every model pool of an AI-gateway service.
# TYPE loxilb_ai_admission_mode gauge
loxilb_ai_admission_mode{pool="llm",service="192.168.1.10:8080"} 2
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_mode"); err != nil {
		t.Errorf("mode series mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_admission_effective_limit The pool-wide ceiling in force right now: the adaptive one while the pool adapts (at most the configured loxilb_ai_admission_limit{role="service"}), else the configured one. 0 means unlimited.
# TYPE loxilb_ai_admission_effective_limit gauge
loxilb_ai_admission_effective_limit{pool="llm",service="192.168.1.10:8080"} 51
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_effective_limit"); err != nil {
		t.Errorf("effective limit mismatch: %v", err)
	}

	// The state and the reason are state sets: exactly one member is 1.
	want = `
# HELP loxilb_ai_admission_adapt_state Where the adaptive ceiling stands, 1 for the current state and 0 for the others: off (not adaptive, or no ceiling), open (at the configured ceiling), tightened (below it, following fresh backpressure signals), frozen (below it with no fresh signal: held, never widened on stale telemetry).
# TYPE loxilb_ai_admission_adapt_state gauge
loxilb_ai_admission_adapt_state{pool="llm",service="192.168.1.10:8080",state="frozen"} 0
loxilb_ai_admission_adapt_state{pool="llm",service="192.168.1.10:8080",state="off"} 0
loxilb_ai_admission_adapt_state{pool="llm",service="192.168.1.10:8080",state="open"} 0
loxilb_ai_admission_adapt_state{pool="llm",service="192.168.1.10:8080",state="tightened"} 1
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_adapt_state"); err != nil {
		t.Errorf("adapt state mismatch: %v", err)
	}
	want = `
# HELP loxilb_ai_admission_adapt_reason Why the adaptive ceiling last moved or holds, 1 for the current reason: queued (an endpoint reported waiting requests), ttft (an endpoint's time to first token is over the target), clear (fresh signals without backpressure: widened), stale (no fresh signal: held), none.
# TYPE loxilb_ai_admission_adapt_reason gauge
loxilb_ai_admission_adapt_reason{pool="llm",reason="clear",service="192.168.1.10:8080"} 0
loxilb_ai_admission_adapt_reason{pool="llm",reason="none",service="192.168.1.10:8080"} 0
loxilb_ai_admission_adapt_reason{pool="llm",reason="queued",service="192.168.1.10:8080"} 1
loxilb_ai_admission_adapt_reason{pool="llm",reason="stale",service="192.168.1.10:8080"} 0
loxilb_ai_admission_adapt_reason{pool="llm",reason="ttft",service="192.168.1.10:8080"} 0
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_adapt_reason"); err != nil {
		t.Errorf("adapt reason mismatch: %v", err)
	}
	want = `
# HELP loxilb_ai_admission_adapt_moves_total Steps of the adaptive ceiling: direction="down" to four fifths on fresh backpressure, direction="up" by one on a fresh clear second.
# TYPE loxilb_ai_admission_adapt_moves_total counter
loxilb_ai_admission_adapt_moves_total{direction="down",pool="llm",service="192.168.1.10:8080"} 3
loxilb_ai_admission_adapt_moves_total{direction="up",pool="llm",service="192.168.1.10:8080"} 1
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_adapt_moves_total"); err != nil {
		t.Errorf("adapt moves mismatch: %v", err)
	}
	want = `
# HELP loxilb_ai_admission_warming_endpoints Endpoints of the pool inside their warm-up window, their ceilings ramping from a quarter to all of it after a return to service.
# TYPE loxilb_ai_admission_warming_endpoints gauge
loxilb_ai_admission_warming_endpoints{pool="llm",service="192.168.1.10:8080"} 1
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_warming_endpoints"); err != nil {
		t.Errorf("warming endpoints mismatch: %v", err)
	}
	want = `
# HELP loxilb_ai_admission_tenants_active Tenants holding a capacity unit or waiting on the pool right now, counted while the pool holds tenants to a share (fc_tenant_max_share_pct); zero otherwise. Requests without a tenant count as one.
# TYPE loxilb_ai_admission_tenants_active gauge
loxilb_ai_admission_tenants_active{pool="llm",service="192.168.1.10:8080"} 2
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_admission_tenants_active"); err != nil {
		t.Errorf("tenants active mismatch: %v", err)
	}

	want = `
# HELP loxilb_ai_fc_tenant_slots The tenant table of the capacity gate, per service: kind="max" is how many tenants a model pool tracks by name at once (LLB_FC_TENANT_SLOTS, fixed when the pool is created), kind="used" is how many hold a unit or wait right now on the service's fullest pool. used above max means tenants past the table are sharing one budget. used is zero while no pool of the service holds tenants to a share.
# TYPE loxilb_ai_fc_tenant_slots gauge
loxilb_ai_fc_tenant_slots{kind="max",service="192.168.1.10:8080"} 256
loxilb_ai_fc_tenant_slots{kind="used",service="192.168.1.10:8080"} 2
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_fc_tenant_slots"); err != nil {
		t.Errorf("tenant slots mismatch: %v", err)
	}

	// Per pool: 1 mode + 4 inflight + 5 limit + 1 queued + 1 wait histogram
	// + 14 decisions + 1 effective limit + 4 adapt states + 5 adapt reasons
	// + 2 adapt moves + 1 warming + 1 tenants = 40, plus the 2 tenant-table
	// series of its service and the 5 process-wide anomaly counters.
	if n := testutil.CollectAndCount(admissionCollector{}); n != 47 {
		t.Errorf("collected %d metrics for one pool, want 47", n)
	}
}

// The tenant-table gauge has one pair of series per service however many
// model pools the service has: the size, and the tenants on its fullest
// pool. A second service is reported on its own, and a service past its
// table reads used above max.
func TestAdmissionTenantSlotsArePerService(t *testing.T) {
	withAdmissionStore(t, []admissionSample{
		{service: "10.0.0.1:2020", pool: "llama", tenantsActive: 3, tenantSlots: 256},
		{service: "10.0.0.1:2020", pool: "qwen", tenantsActive: 40, tenantSlots: 256},
		{service: "10.0.0.1:2020", pool: "*", tenantsActive: 0, tenantSlots: 256},
		{service: "10.0.0.2:2021", pool: "llama", tenantsActive: 65, tenantSlots: 64},
		{service: "10.0.0.3:2022", pool: "llama", tenantsActive: 0, tenantSlots: 4096},
	}, [5]float64{})

	want := `
# HELP loxilb_ai_fc_tenant_slots The tenant table of the capacity gate, per service: kind="max" is how many tenants a model pool tracks by name at once (LLB_FC_TENANT_SLOTS, fixed when the pool is created), kind="used" is how many hold a unit or wait right now on the service's fullest pool. used above max means tenants past the table are sharing one budget. used is zero while no pool of the service holds tenants to a share.
# TYPE loxilb_ai_fc_tenant_slots gauge
loxilb_ai_fc_tenant_slots{kind="max",service="10.0.0.1:2020"} 256
loxilb_ai_fc_tenant_slots{kind="used",service="10.0.0.1:2020"} 40
loxilb_ai_fc_tenant_slots{kind="max",service="10.0.0.2:2021"} 64
loxilb_ai_fc_tenant_slots{kind="used",service="10.0.0.2:2021"} 65
loxilb_ai_fc_tenant_slots{kind="max",service="10.0.0.3:2022"} 4096
loxilb_ai_fc_tenant_slots{kind="used",service="10.0.0.3:2022"} 0
`
	if err := testutil.CollectAndCompare(admissionCollector{}, strings.NewReader(want),
		"loxilb_ai_fc_tenant_slots"); err != nil {
		t.Errorf("tenant slots per service mismatch: %v", err)
	}
	if n := testutil.CollectAndCount(admissionCollector{}, "loxilb_ai_fc_tenant_slots"); n != 6 {
		t.Errorf("collected %d tenant-table series for three services, want 6", n)
	}

	got := admissionTenantSlotsByService(nil)
	if len(got) != 0 {
		t.Errorf("no pools: got %v, want no reading", got)
	}
}

func TestAdmissionQwaitCumulative(t *testing.T) {
	got := admissionQwaitCumulative([8]uint64{1, 0, 2, 0, 0, 3, 0, 0})
	want := map[float64]uint64{0.01: 1, 0.05: 1, 0.1: 3, 0.25: 3, 0.5: 3, 1: 6, 2.5: 6, 5: 6}
	if len(got) != len(want) {
		t.Fatalf("got %d buckets, want %d", len(got), len(want))
	}
	for le, n := range want {
		if got[le] != n {
			t.Errorf("bucket le=%v = %d, want %d", le, got[le], n)
		}
	}
	// The reason vocabulary is the C enum's, in its order: a new reason
	// appended there must be appended here, never inserted.
	if admissionReasonLabels[5] != "queued" || admissionReasonLabels[11] != "draining" {
		t.Errorf("reason order drifted from enum fc_reason: %v", admissionReasonLabels)
	}
}

// A scrape that lands between a wait's bucket and its count still emits a
// histogram whose count covers every bucket; a settled one keeps its own
// count, which also covers waits past the last bound.
func TestAdmissionQwaitHistogramCountCoversBuckets(t *testing.T) {
	cases := []struct {
		name      string
		buckets   [8]uint64
		count     uint64
		wantCount uint64
	}{
		{"mid-update: a bucket ahead of the count", [8]uint64{1, 0, 2, 0, 0, 3, 0, 0}, 5, 6},
		{"settled", [8]uint64{1, 0, 2, 0, 0, 3, 0, 0}, 6, 6},
		{"waits past the last bound", [8]uint64{1, 0, 0, 0, 0, 0, 0, 1}, 4, 4},
		{"empty", [8]uint64{}, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			count, cum := admissionQwaitHistogram(c.buckets, c.count)
			if count != c.wantCount {
				t.Fatalf("count = %d, want %d", count, c.wantCount)
			}
			for le, n := range cum {
				if n > count {
					t.Errorf("bucket le=%v = %d exceeds the count %d", le, n, count)
				}
			}
		})
	}
}
