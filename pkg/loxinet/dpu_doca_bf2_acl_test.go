//go:build !doca

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

// Wave-0 ACL HW-offload state-machine tests.
//
// These tests exercise the Go control-plane state machine WITHOUT the DOCA SDK.
// The !doca-build mirror (dpu_doca_bf2_stub.go) treats every CGO call as a
// no-op success, so flushAclPending writes directly to aclDenyEntries /
// aclAllowEntries. The DOCA-build twin scenario (HW counters, hw_pkts>0) is
// validated by the operator runbook.
//
// Tests covered:
// - TestAclLazyLifecycle: — first FwRuleAdd(HwOffload=true) flips
//     aclPipesUp=true; last FwRuleDel flips back to false.
// - TestAclEntryMap: — deny / allow map routing; deterministic hash
//     across add-del-add cycles.
// - TestAclDebounce: — enqueue, sleep > aclDebounceMs, assert flush.
// - TestAclDebounceCancelOnDel: — Del before debounce fires cancels
//     the pending Add (no HW mutation).
// - TestAclBatchCapForcesFlush: — N=aclBatchCap entries force a
//     synchronous flush without waiting for the debounce window.
// - TestAclMetrics: — gauges and rules_total counter increment as
//     expected.
// - TestAclRestartReplay: — re-issuing the same rule set against a
//     fresh DpDocaBf2 returns the gauges to the same values.
// - TestAclHwOffloadFalseSkipsHw: — HwOffload=false short-circuits
//     before any map / lifecycle mutation.

package loxinet

import (
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// newTestBf2 returns a freshly-initialised DpDocaBf2 with empty maps and
// aclPipesUp=false. The !doca-build NewDpDocaBf2 returns nil, so tests
// construct the struct directly.
func newTestBf2() *DpDocaBf2 {
	return &DpDocaBf2{
		entries:         make(map[string]*docaOffloadEntry),
		aclDenyEntries:  make(map[string]*docaOffloadEntry),
		aclAllowEntries: make(map[string]*docaOffloadEntry),
		aclPipesUp:      false,
	}
}

// mkAclWork builds a FwDpWorkQ for the ACL state-machine tests. Defaults the
// not-relevant fields. CIDR strings must be valid; ParseCIDR errors fail the
// test immediately to keep the table-driven shape readable.
func mkAclWork(t *testing.T, srcCIDR, dstCIDR string, srcPort, dstPort uint16, fwType FwOpT, hw bool) *FwDpWorkQ {
	t.Helper()
	_, srcNet, err := net.ParseCIDR(srcCIDR)
	if err != nil {
		t.Fatalf("mkAclWork srcCIDR=%q: %v", srcCIDR, err)
	}
	_, dstNet, err := net.ParseCIDR(dstCIDR)
	if err != nil {
		t.Fatalf("mkAclWork dstCIDR=%q: %v", dstCIDR, err)
	}
	return &FwDpWorkQ{
		SrcIP:     *srcNet,
		DstIP:     *dstNet,
		L4SrcMin:  srcPort,
		L4SrcMax:  srcPort,
		L4DstMin:  dstPort,
		L4DstMax:  dstPort,
		Pref:      100,
		Proto:     0,
		FwType:    fwType,
		HwOffload: hw,
	}
}

// counterValue reads the current value of a counter child via dto.Metric.
func counterValue(t *testing.T, c interface {
	Write(*dto.Metric) error
}) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("counter.Write: %v", err)
	}
	if m.Counter != nil {
		return m.Counter.GetValue()
	}
	if m.Gauge != nil {
		return m.Gauge.GetValue()
	}
	return 0
}

func TestAclLazyLifecycle(t *testing.T) {
	d := newTestBf2()

	if d.aclPipesUp {
		t.Fatal("expected aclPipesUp=false at fresh init")
	}

	// First add — should flip aclPipesUp=true via ensureAclPipesUp.
	w := mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, 80, DpFwDrop, true)
	if err := d.FwRuleAdd(w); err != nil {
		t.Fatalf("FwRuleAdd: %v", err)
	}
	if !d.aclPipesUp {
		t.Fatal("expected aclPipesUp=true after first HwOffload=true add")
	}

	// Del — pipes should tear down via async maybeTearDownAclPipes.
	if err := d.FwRuleDel(w); err != nil {
		t.Fatalf("FwRuleDel: %v", err)
	}
	// FwRuleDel enqueues into aclPendingDel and arms scheduleAclFlush; wait
	// for the debounce window + the goroutine that maybeTearDownAclPipes spawns.
	time.Sleep(2 * aclDebounceMs)
	// Drain anything that's still pending (defence in depth — the timer may
	// have fired but we want a deterministic state for the assertion).
	d.flushAclPending()
	// Give the spawned maybeTearDownAclPipes goroutine a chance to run.
	time.Sleep(20 * time.Millisecond)
	if d.aclPipesUp {
		t.Fatalf("expected aclPipesUp=false after last HwOffload=true del; got true (maps: deny=%d allow=%d)",
			len(d.aclDenyEntries), len(d.aclAllowEntries))
	}
}

func TestAclEntryMap(t *testing.T) {
	t.Run("deny", func(t *testing.T) {
		d := newTestBf2()
		w := mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, 80, DpFwDrop, true)
		if err := d.FwRuleAdd(w); err != nil {
			t.Fatalf("FwRuleAdd: %v", err)
		}
		if len(d.aclDenyEntries) != 1 {
			t.Fatalf("expected 1 deny entry, got %d", len(d.aclDenyEntries))
		}
		if len(d.aclAllowEntries) != 0 {
			t.Fatalf("expected 0 allow entries, got %d", len(d.aclAllowEntries))
		}
	})

	t.Run("allow", func(t *testing.T) {
		d := newTestBf2()
		w := mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, 80, DpFwFwd, true)
		if err := d.FwRuleAdd(w); err != nil {
			t.Fatalf("FwRuleAdd: %v", err)
		}
		if len(d.aclAllowEntries) != 1 {
			t.Fatalf("expected 1 allow entry, got %d", len(d.aclAllowEntries))
		}
		if len(d.aclDenyEntries) != 0 {
			t.Fatalf("expected 0 deny entries, got %d", len(d.aclDenyEntries))
		}
	})

	t.Run("hash_stable", func(t *testing.T) {
		d := newTestBf2()
		w := mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, 80, DpFwDrop, true)
		hash1 := ruleHashFor(w)
		if err := d.FwRuleAdd(w); err != nil {
			t.Fatalf("FwRuleAdd #1: %v", err)
		}
		if err := d.FwRuleDel(w); err != nil {
			t.Fatalf("FwRuleDel: %v", err)
		}
		time.Sleep(2 * aclDebounceMs)
		d.flushAclPending()
		if err := d.FwRuleAdd(w); err != nil {
			t.Fatalf("FwRuleAdd #2: %v", err)
		}
		hash2 := ruleHashFor(w)
		if hash1 != hash2 {
			t.Fatalf("hash drift across add-del-add cycle: %q vs %q", hash1, hash2)
		}
	})
}

func TestAclDebounce(t *testing.T) {
	d := newTestBf2()
	w := mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, 80, DpFwDrop, true)
	// FwRuleAdd blocks on done channel — flushAclPending fires either on
	// debounce tick (50ms) or on cap (128). Single add will fire on tick.
	added := make(chan error, 1)
	go func() { added <- d.FwRuleAdd(w) }()

	select {
	case err := <-added:
		if err != nil {
			t.Fatalf("FwRuleAdd: %v", err)
		}
	case <-time.After(aclDebounceMs + 500*time.Millisecond):
		t.Fatal("FwRuleAdd did not complete within debounce + slack window")
	}

	if len(d.aclDenyEntries) != 1 {
		t.Fatalf("expected 1 deny entry after debounce flush, got %d", len(d.aclDenyEntries))
	}
}

func TestAclDebounceCancelOnDel(t *testing.T) {
	d := newTestBf2()
	w := mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, 80, DpFwDrop, true)

	// Enqueue Add, then Del before the debounce fires. The pending Add
	// should be canceled in-Go without map mutation.
	added := make(chan error, 1)
	go func() { added <- d.FwRuleAdd(w) }()

	// Tiny sleep to ensure the Add lands in aclPendingAdd before Del runs.
	time.Sleep(5 * time.Millisecond)
	if err := d.FwRuleDel(w); err != nil {
		t.Fatalf("FwRuleDel: %v", err)
	}

	// The Add's onDone is closed (not sent-to-with-nil) by FwRuleDel's
	// cancel-pending-on-Del path; <-done in FwRuleAdd returns the zero error.
	select {
	case err := <-added:
		if err != nil {
			t.Fatalf("FwRuleAdd: %v", err)
		}
	case <-time.After(aclDebounceMs + 500*time.Millisecond):
		t.Fatal("FwRuleAdd did not complete after cancel-on-del")
	}

	// Wait past the debounce window to make sure no late flush mutates maps.
	time.Sleep(2 * aclDebounceMs)
	if len(d.aclDenyEntries) != 0 || len(d.aclAllowEntries) != 0 {
		t.Fatalf("expected empty maps after cancel-on-del; deny=%d allow=%d",
			len(d.aclDenyEntries), len(d.aclAllowEntries))
	}
}

func TestAclBatchCapForcesFlush(t *testing.T) {
	d := newTestBf2()

	// Enqueue aclBatchCap entries in parallel. The aclBatchCap-th call should
	// trigger a synchronous flushAclPending without waiting for the debounce
	// window. The remaining adds complete via the normal debounce path.
	done := make(chan struct{}, aclBatchCap)
	for i := 0; i < aclBatchCap; i++ {
		// Make each rule unique so hashes differ (otherwise map dedup masks
		// the count assertion).
		srcCIDR := "10.0.0.0/24"
		dstCIDR := "192.168.1.0/24"
		w := mkAclWork(t, srcCIDR, dstCIDR, 0, uint16(8000+i), DpFwDrop, true)
		go func(w *FwDpWorkQ) {
			_ = d.FwRuleAdd(w)
			done <- struct{}{}
		}(w)
	}
	for i := 0; i < aclBatchCap; i++ {
		select {
		case <-done:
		case <-time.After(2 * aclDebounceMs):
			t.Fatalf("FwRuleAdd batch did not complete (got %d/%d so far)", i, aclBatchCap)
		}
	}

	// All aclBatchCap entries should be in the deny map (each rule's port
	// makes it unique).
	if len(d.aclDenyEntries) != aclBatchCap {
		t.Fatalf("expected %d deny entries after cap flush, got %d", aclBatchCap, len(d.aclDenyEntries))
	}
}

func TestAclMetrics(t *testing.T) {
	d := newTestBf2()

	denyBefore := counterValue(t, docaAclHwOffloadRulesTotal.WithLabelValues("deny"))
	allowBefore := counterValue(t, docaAclHwOffloadRulesTotal.WithLabelValues("allow"))

	// 3 deny + 2 allow rules.
	for i := 0; i < 3; i++ {
		w := mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, uint16(8000+i), DpFwDrop, true)
		if err := d.FwRuleAdd(w); err != nil {
			t.Fatalf("deny add #%d: %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		w := mkAclWork(t, "10.1.0.0/24", "192.168.2.0/24", 0, uint16(9000+i), DpFwFwd, true)
		if err := d.FwRuleAdd(w); err != nil {
			t.Fatalf("allow add #%d: %v", i, err)
		}
	}

	t.Run("deny_count", func(t *testing.T) {
		if got := counterValue(t, docaAclHwDenyEntries); got != 3 {
			t.Fatalf("docaAclHwDenyEntries gauge expected 3, got %v", got)
		}
	})
	t.Run("allow_count", func(t *testing.T) {
		if got := counterValue(t, docaAclHwAllowEntries); got != 2 {
			t.Fatalf("docaAclHwAllowEntries gauge expected 2, got %v", got)
		}
	})
	t.Run("rules_total_inc", func(t *testing.T) {
		denyAfter := counterValue(t, docaAclHwOffloadRulesTotal.WithLabelValues("deny"))
		allowAfter := counterValue(t, docaAclHwOffloadRulesTotal.WithLabelValues("allow"))
		if denyAfter-denyBefore < 3 {
			t.Fatalf("rules_total{deny} delta expected ≥3, got %v", denyAfter-denyBefore)
		}
		if allowAfter-allowBefore < 2 {
			t.Fatalf("rules_total{allow} delta expected ≥2, got %v", allowAfter-allowBefore)
		}
	})
}

func TestAclRestartReplay(t *testing.T) {
	// Pre-restart: install 2 deny rules.
	d1 := newTestBf2()
	rules := []*FwDpWorkQ{
		mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, 80, DpFwDrop, true),
		mkAclWork(t, "10.0.1.0/24", "192.168.2.0/24", 0, 443, DpFwDrop, true),
	}
	for _, w := range rules {
		if err := d1.FwRuleAdd(w); err != nil {
			t.Fatalf("pre-restart add: %v", err)
		}
	}
	preCount := len(d1.aclDenyEntries)
	if preCount != 2 {
		t.Fatalf("pre-restart expected 2 deny entries, got %d", preCount)
	}

	// "Restart": fresh DpDocaBf2, operator/kube-loxilb re-POSTs the same
	// rule set. The deterministic ruleHashFor guarantees the post-restart
	// entries land in the same map slots as before.
	d2 := newTestBf2()
	for _, w := range rules {
		if err := d2.FwRuleAdd(w); err != nil {
			t.Fatalf("post-restart add: %v", err)
		}
	}
	postCount := len(d2.aclDenyEntries)
	if postCount != preCount {
		t.Fatalf("post-restart count drift: pre=%d post=%d", preCount, postCount)
	}
	// Hashes must match across the two instances.
	for _, w := range rules {
		h := ruleHashFor(w)
		if _, ok := d2.aclDenyEntries[h]; !ok {
			t.Fatalf("post-restart map missing hash %q", h)
		}
	}
}

func TestAclHwOffloadFalseSkipsHw(t *testing.T) {
	d := newTestBf2()
	w := mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, 80, DpFwDrop, false) // hw=false
	if err := d.FwRuleAdd(w); err != nil {
		t.Fatalf("FwRuleAdd HwOffload=false: %v", err)
	}
	if d.aclPipesUp {
		t.Fatal("expected aclPipesUp=false (HwOffload=false should not trigger lazy create)")
	}
	if len(d.aclDenyEntries) != 0 || len(d.aclAllowEntries) != 0 {
		t.Fatalf("expected empty maps with HwOffload=false; deny=%d allow=%d",
			len(d.aclDenyEntries), len(d.aclAllowEntries))
	}

	// Also: del of a HwOffload=false rule is a no-op; aclPipesUp stays
	// false (no lifecycle transition triggered by either Add or Del).
	if err := d.FwRuleDel(w); err != nil {
		t.Fatalf("FwRuleDel HwOffload=false: %v", err)
	}
	time.Sleep(2 * aclDebounceMs)
	if d.aclPipesUp {
		t.Fatal("expected aclPipesUp=false after HwOffload=false Del (no lifecycle transition)")
	}
}

// TestAclMetricsLabelChildrenPreInstantiated — -05 / S2 discipline:
// CounterVec children for `action="deny"` and `action="allow"` are
// instantiated in init (dpu_metrics.go:306-307) so that rate panels
// show a flat-line baseline from the very first Prometheus scrape, not
// "no data". This test scrapes the default gatherer at test-init time
// (without any FwRuleAdd) and asserts BOTH label children are present in
// the registry.
//
// Decision references: (gauges + counter), (Linux !doca coverage).
func TestAclMetricsLabelChildrenPreInstantiated(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	var found *dto.MetricFamily
	for _, mf := range mfs {
		if mf.GetName() == "loxilb_acl_hw_offload_rules_total" {
			found = mf
			break
		}
	}
	if found == nil {
		t.Fatal("loxilb_acl_hw_offload_rules_total MetricFamily not found in gatherer — init() pre-instantiation missing")
	}

	seenDeny := false
	seenAllow := false
	for _, m := range found.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() != "action" {
				continue
			}
			switch lp.GetValue() {
			case "deny":
				seenDeny = true
			case "allow":
				seenAllow = true
			}
		}
	}
	if !seenDeny {
		t.Error("CounterVec child action=\"deny\" NOT pre-instantiated in init() — rate() panels will show \"no data\" until first deny rule")
	}
	if !seenAllow {
		t.Error("CounterVec child action=\"allow\" NOT pre-instantiated in init() — rate() panels will show \"no data\" until first allow rule")
	}

	// Also verify both gauges are registered (single-child families don't
	// need pre-instantiation in the same way — Gauge.Set on the value
	// publishes it — but Gather should still surface them as Type=GAUGE
	// MetricFamily entries after any code path has touched them, OR they
	// appear immediately because promauto.NewGauge registers the family on
	// declaration).
	var foundDenyG, foundAllowG bool
	for _, mf := range mfs {
		switch mf.GetName() {
		case "loxilb_acl_hw_deny_entries":
			foundDenyG = true
		case "loxilb_acl_hw_allow_entries":
			foundAllowG = true
		}
	}
	if !foundDenyG {
		t.Error("loxilb_acl_hw_deny_entries MetricFamily missing from gatherer")
	}
	if !foundAllowG {
		t.Error("loxilb_acl_hw_allow_entries MetricFamily missing from gatherer")
	}
}

// TestAclLifecycleIdempotent — thickening lifecycle
// contract: ensureAclPipesUp is idempotent on subsequent HwOffload=true
// Adds (no second `DENY_PIPE+ALLOW_PIPE created` event), and the lazy
// teardown only fires when BOTH the deny and allow maps are empty.
func TestAclLifecycleIdempotent(t *testing.T) {
	d := newTestBf2()

	// Add #1: triggers ensureAclPipesUp; aclPipesUp flips true.
	w1 := mkAclWork(t, "10.0.0.0/24", "192.168.1.0/24", 0, 80, DpFwDrop, true)
	if err := d.FwRuleAdd(w1); err != nil {
		t.Fatalf("FwRuleAdd #1: %v", err)
	}
	if !d.aclPipesUp {
		t.Fatal("expected aclPipesUp=true after first HwOffload=true Add")
	}

	// Add #2 (allow this time): aclPipesUp stays true; ensureAclPipesUp
	// is idempotent (no-op).
	w2 := mkAclWork(t, "10.1.0.0/24", "192.168.2.0/24", 0, 443, DpFwFwd, true)
	if err := d.FwRuleAdd(w2); err != nil {
		t.Fatalf("FwRuleAdd #2: %v", err)
	}
	if !d.aclPipesUp {
		t.Fatal("expected aclPipesUp=true after second HwOffload=true Add (idempotent)")
	}
	if len(d.aclDenyEntries) != 1 || len(d.aclAllowEntries) != 1 {
		t.Fatalf("expected 1 deny + 1 allow entry, got deny=%d allow=%d",
			len(d.aclDenyEntries), len(d.aclAllowEntries))
	}

	// Del #1 (the deny entry): aclPipesUp STAYS true because allow map is
	// non-empty.
	if err := d.FwRuleDel(w1); err != nil {
		t.Fatalf("FwRuleDel #1: %v", err)
	}
	time.Sleep(2 * aclDebounceMs)
	d.flushAclPending()
	time.Sleep(20 * time.Millisecond)
	if !d.aclPipesUp {
		t.Fatal("expected aclPipesUp=true after Del #1 (allow map still non-empty)")
	}

	// Del #2 (the allow entry): now both maps empty → maybeTearDownAclPipes
	// flips aclPipesUp=false.
	if err := d.FwRuleDel(w2); err != nil {
		t.Fatalf("FwRuleDel #2: %v", err)
	}
	time.Sleep(2 * aclDebounceMs)
	d.flushAclPending()
	time.Sleep(20 * time.Millisecond)
	if d.aclPipesUp {
		t.Fatalf("expected aclPipesUp=false after last Del (both maps empty); maps: deny=%d allow=%d",
			len(d.aclDenyEntries), len(d.aclAllowEntries))
	}
}
