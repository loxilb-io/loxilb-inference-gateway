/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package loxinlp

import (
	"strings"
	"time"
)

const (
	bootRetries = 15
	// gobgpd is spawned only after the cluster sync wait (up to 90 s) and
	// a 5 s cool-off, so on a clustered node it can answer well after the
	// 15 regular attempts are spent. A snapshot that fails only on BGP
	// startup keeps retrying until this much time has passed since boot.
	bootBGPStartWait = 150 * time.Second
)

// bootRetryAllowed decides whether a failed boot restore is retried.
func bootRetryAllowed(attempt int, elapsed time.Duration, errs []string) bool {
	if !subsystemStartupErrors(errs) {
		return false
	}
	if attempt < bootRetries {
		return true
	}
	return elapsed < bootBGPStartWait && bgpStartupOnly(errs)
}

// bgpStartupOnly reports whether every error comes from applying the BGP
// domains, the only subsystem whose startup can outlast the regular attempts.
func bgpStartupOnly(errs []string) bool {
	for _, e := range errs {
		if !strings.HasPrefix(strings.ToLower(e), "apply bgp") {
			return false
		}
	}
	return len(errs) > 0
}
