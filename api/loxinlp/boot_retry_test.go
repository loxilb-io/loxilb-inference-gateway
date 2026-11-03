/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package loxinlp

import (
	"testing"
	"time"
)

const bgpRefused = `apply bgp: prepare global_config: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 127.0.0.1:50052: connect: connection refused"`

// A snapshot that fails only because gobgpd is not up yet keeps retrying past
// the regular attempts until gobgpd has had time to start on a clustered node.
func TestBootRetryWaitsForGobgpd(t *testing.T) {
	errs := []string{bgpRefused}
	cases := []struct {
		attempt int
		elapsed time.Duration
		want    bool
	}{
		{1, 0, true},
		{bootRetries - 1, 28 * time.Second, true},
		{bootRetries, 30 * time.Second, true},
		{40, 100 * time.Second, true},
		{70, bootBGPStartWait - time.Second, true},
		{71, bootBGPStartWait, false},
	}
	for _, c := range cases {
		if got := bootRetryAllowed(c.attempt, c.elapsed, errs); got != c.want {
			t.Errorf("attempt %d at %v: retry=%v, want %v", c.attempt, c.elapsed, got, c.want)
		}
	}
}

// Other startup errors keep the regular attempt limit, and a real failure is
// never retried.
func TestBootRetryKeepsLimitsForOtherErrors(t *testing.T) {
	ipsec := []string{"apply ipsec: IPsec not initialized"}
	if !bootRetryAllowed(1, 0, ipsec) {
		t.Fatal("ipsec startup error not retried on the first attempt")
	}
	if bootRetryAllowed(bootRetries, 30*time.Second, ipsec) {
		t.Fatal("ipsec startup error retried past the regular attempts")
	}
	mixed := []string{bgpRefused, "apply ipsec: IPsec not initialized"}
	if bootRetryAllowed(bootRetries, 30*time.Second, mixed) {
		t.Fatal("a mixed failure retried past the regular attempts")
	}
	real := []string{"apply loadbalancer: invalid endpoint 300.1.1.1"}
	if bootRetryAllowed(1, 0, real) {
		t.Fatal("a real apply failure was retried")
	}
	if bootRetryAllowed(1, 0, nil) {
		t.Fatal("an empty error list was retried")
	}
}
