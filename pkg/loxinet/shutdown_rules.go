// Copyright (c) 2026 NetLOX Inc
// SPDX-License-Identifier: Apache-2.0

package loxinet

// Peer-only startup owns no datapath rule registry. The SIGTERM path shares
// this cleanup with native modes, so absence must be an ordinary no-op.
func (h *loxiNetH) shutdownDatapathRules() {
	if h.zr != nil {
		h.zr.Rules.RuleDestructAll()
	}
}
