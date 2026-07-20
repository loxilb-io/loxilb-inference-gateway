//go:build l4trace
// +build l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * DP eBPF L4 Tracing Support (enabled build)
 */

package loxinet

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common -DHAVE_L4_TRACE
#include <stdint.h>
#include <linux/types.h>
#include "../../../loxilb-ebpf/kernel/loxilb_libdp.h"

extern int llb_map2fd(int mapidx);
*/
import "C"

import (
	tk "github.com/loxilb-io/loxilib"
)

// initL4TraceRingBuffer initializes the L4 trace ring buffer file descriptor
// This function is only compiled when L4 tracing is enabled (tags l4trace)
func (ne *DpEbpfH) initL4TraceRingBuffer() {
	ne.l4TraceRingBufFD = int(C.llb_map2fd(C.LL_DP_L4_TRACE_RINGBUF))
	if ne.l4TraceRingBufFD > 0 {
		tk.LogIt(tk.LogDebug, "L4 trace ring buffer FD initialized: %d\n", ne.l4TraceRingBufFD)
	} else {
		tk.LogIt(tk.LogWarning, "L4 trace ring buffer not available (may not be compiled with -DHAVE_L4_TRACE)\n")
	}
}

// initL4TraceConfig initializes the L4 trace configuration (disabled by default)
// This function is only compiled when L4 tracing is enabled (tags l4trace)
func (ne *DpEbpfH) initL4TraceConfig() {
	if err := ne.DpL4TraceConfigSet(L4TraceConfig{
		Enabled:      false,
		SamplingRate: 100,
	}); err != nil {
		tk.LogIt(tk.LogDebug, "L4 trace config init skipped: %v (not compiled or not available)\n", err)
	} else {
		tk.LogIt(tk.LogInfo, "L4 trace initialized (disabled by default, sampling=100%%)\n")
	}
}
