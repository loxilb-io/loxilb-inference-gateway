//go:build !l4trace
// +build !l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * L4 Connection Tracing Initialization (disabled build)
 */

package loxinet

import (
	"fmt"

	tk "github.com/loxilb-io/loxilib"
)

// initL4Tracing is a no-op when L4 tracing is not compiled in
func (mh *loxiNetH) initL4Tracing() error {
	tk.LogIt(tk.LogWarning, "[L4Trace] L4 tracing not compiled (build with -tags l4trace or HAVE_L4_TRACE=1 make)\n")
	return fmt.Errorf("L4 tracing not compiled")
}

// l4TraceEventProcessor is a no-op when L4 tracing is not compiled in
func (mh *loxiNetH) l4TraceEventProcessor() {
	// No-op
}
