// Copyright (c) 2026 NetLOX Inc
// SPDX-License-Identifier: Apache-2.0

package loxinet

import "testing"

func TestPeerOnlyShutdownHasNoDatapathRules(t *testing.T) {
	// This is the same cleanup called by the SIGTERM path; peer-only startup
	// intentionally leaves zr nil. It must return without a native call/panic.
	h := &loxiNetH{}
	h.shutdownDatapathRules()
}
