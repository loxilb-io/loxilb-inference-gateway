// SPDX-License-Identifier: Apache 2.0
// Copyright (c) 2026 NetLOX Inc

// SGL-01 (Gate 2) regression tests — subscriber fan-out counting for
// KV-exact mode 1 (zmq P/D) vs mode 3 (zmq single-role, KvExactModeSingleRole),
// plus the teardown-clean registry baseline multi-rank work must
// preserve (: cancelFns re-keying happens inside the subscriber, the
// single service-scoped KvSubscriberStopAll call must keep working).
//
// NOTE: pkg/loxinet is a CGO package — these tests are AUTHORED here
// and validated on a remote GPU testbed
// spine:
//
//	go test ./pkg/loxinet/ -run 'TestKvSingleRole' -count=1
//
// darwin-local verification is structural only (gofmt + grep).
//
// The fan-out contract lives in kvSubscriberTargets (rules.go), a pure helper
// the mode-3 subscriber gate calls directly. The mode-1 gate keeps its shipped
// verbatim epRole==1 loop for byte-identity discipline; the helper's mode-1 arm
// is its semantic twin and this suite pins both arms so any future divergence
// is caught at the remote gate. Driving KvSubscriberStart directly here would
// need a full rule fixture (it spawns real ZMQ dial goroutines and arms the
// mh-owned metrics bridge), so the counting cases test the target-selection
// contract and the teardown case seeds the registry directly (the
// seedLoopService shape from ai_kv_reconnect_resync_test.go).

package loxinet

import (
	"testing"
)

// kvSrEps fabricates a rule endpoint slice with the given epRoles (0=normal,
// 1=prefill, 2=decode). Only epRole participates in the subscriber-target
// contract; all other ruleLBEp fields stay zero.
func kvSrEps(roles ...int) []ruleLBEp {
	eps := make([]ruleLBEp, len(roles))
	for i, r := range roles {
		eps[i].epRole = r
	}
	return eps
}

// TestKvSingleRoleSubscriberTargets counts which endpoints get a KV subscriber
// per kvExactMode over the canonical 4-EP fixture (roles {1,2,0,0}: one
// prefill, one decode, two role-less):
//   - mode 1: exactly 1 subscriber (epIdx 0, the prefill) — byte-identical to
//     the shipped KV-12 behavior
//   - mode 3: exactly 4 subscribers (ALL epIdx — single-role EPs have no roles)
//   - mode 0: zero subscribers (off)
//   - mode 2: zero subscribers (nats, reserved — not a subscriber mode)
func TestKvSingleRoleSubscriberTargets(t *testing.T) {
	eps := kvSrEps(1, 2, 0, 0)

	cases := []struct {
		name string
		mode uint8
		eps  []ruleLBEp
		want []int
	}{
		{"mode1-pd-prefill-only", 1, eps, []int{0}},
		{"mode3-single-role-all-eps", KvExactModeSingleRole, eps, []int{0, 1, 2, 3}},
		{"mode0-off-zero-subscribers", 0, eps, nil},
		{"mode2-nats-reserved-zero-subscribers", 2, eps, nil},
		{"mode3-empty-endpoint-set", KvExactModeSingleRole, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := kvSubscriberTargets(c.mode, c.eps)
			if len(got) != len(c.want) {
				t.Fatalf("kvSubscriberTargets(mode=%d): %d subscribers (%v), want %d (%v)",
					c.mode, len(got), got, len(c.want), c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("kvSubscriberTargets(mode=%d)[%d] = %d, want %d (full: got %v want %v)",
						c.mode, i, got[i], c.want[i], got, c.want)
				}
			}
		})
	}
}

// TestKvSingleRoleStopAllTeardown pins the teardown-clean baseline: after
// KvSubscriberStopAll(serviceID) the kvServices registry holds NO state for
// that service and every per-EP cancel fn was invoked exactly once. A second
// StopAll on the already-removed service must be a no-op (rule-delete paths
// may race a prior teardown). The multi-rank cancelFns re-keying must
// keep this green.
func TestKvSingleRoleStopAllTeardown(t *testing.T) {
	const serviceID uint32 = 990201

	svc := newKvServiceState(serviceID)
	svc.algo = "sha256_cbor"
	cancelled := make([]int, 4)
	for ep := 0; ep < 4; ep++ {
		epIdx := ep
		svc.inventories[epIdx] = newKvInventory()
		// re-keyed cancelFns by (epIdx, rank) — rank 0 here preserves the
		// exact pre- single-rank baseline this test pins.
		svc.cancelFns[kvEpRankKey{epIdx: epIdx, rank: 0}] = func() { cancelled[epIdx]++ }
	}
	kvServicesMu.Lock()
	kvServices[serviceID] = svc
	kvServicesMu.Unlock()

	KvSubscriberStopAll(serviceID)

	kvServicesMu.RLock()
	_, still := kvServices[serviceID]
	kvServicesMu.RUnlock()
	if still {
		t.Fatalf("KvSubscriberStopAll(%d): service still present in kvServices registry", serviceID)
	}
	for ep, n := range cancelled {
		if n != 1 {
			t.Fatalf("KvSubscriberStopAll(%d): ep %d cancel invoked %d times, want exactly 1", serviceID, ep, n)
		}
	}
	svc.mu.RLock()
	nCancel := len(svc.cancelFns)
	svc.mu.RUnlock()
	if nCancel != 0 {
		t.Fatalf("KvSubscriberStopAll(%d): %d cancelFns left on the detached state, want 0", serviceID, nCancel)
	}

	// Idempotence: a second StopAll on an already-removed service is a no-op.
	KvSubscriberStopAll(serviceID)
	for ep, n := range cancelled {
		if n != 1 {
			t.Fatalf("second KvSubscriberStopAll(%d): ep %d cancel invoked %d times, want still 1", serviceID, ep, n)
		}
	}
}
