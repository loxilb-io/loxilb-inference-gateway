//go:build !l4trace
// +build !l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * DP eBPF L4 Tracing Support (disabled build)
 */

package loxinet

import (
	tk "github.com/loxilb-io/loxilib"
)

// initL4TraceRingBuffer is a no-op when L4 tracing is disabled
func (ne *DpEbpfH) initL4TraceRingBuffer() {
	ne.l4TraceRingBufFD = -1
	tk.LogIt(tk.LogDebug, "L4 trace ring buffer disabled (not compiled with -tags l4trace)\n")
}

// initL4TraceConfig is a no-op when L4 tracing is disabled
func (ne *DpEbpfH) initL4TraceConfig() {
	tk.LogIt(tk.LogDebug, "L4 trace config disabled (not compiled with -tags l4trace)\n")
}
