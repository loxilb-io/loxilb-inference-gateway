// Copyright (c) 2026 LoxiLB Authors
// SPDX-License-Identifier: Apache-2.0

package loxinet

import (
	"testing"
	"time"
)

func TestHAFrontendHold(t *testing.T) {
	now := time.Now()
	h := haFrontendHold{}
	old := haFrontendSample{index: 10, up: true}
	next := haFrontendSample{index: 11, up: true}
	assert := func(after time.Duration, s haFrontendSample, eligible, wantDown, wantUp bool) {
		t.Helper()
		d, u := h.observe(now.Add(after), s, eligible)
		if d != wantDown || u != wantUp {
			t.Fatalf("at %s, down/up = %t/%t, want %t/%t", after, d, u, wantDown, wantUp)
		}
	}
	assert(0, old, false, false, false)
	assert(5*time.Second, old, false, false, true)
	assert(6*time.Second, haFrontendSample{}, true, false, false)
	assert(6200*time.Millisecond, old, true, false, false) // transient fault
	assert(7*time.Second, next, true, false, false)        // changed ifindex
	assert(7300*time.Millisecond, next, true, true, false)
	assert(7301*time.Millisecond, next, false, false, false)
	assert(12300*time.Millisecond, next, false, false, false)
	assert(12301*time.Millisecond, next, false, false, true)
}
