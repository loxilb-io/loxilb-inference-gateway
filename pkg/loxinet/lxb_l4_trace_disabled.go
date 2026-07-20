//go:build !l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSlause
 */

package loxinet

import (
	"fmt"

	tk "github.com/loxilb-io/loxilib"
)

// L4TraceStats holds L4 connection tracing statistics (disabled build)
type L4TraceStats struct {
	TotalEvents     uint64 `json:"total_events"`
	SampledEvents   uint64 `json:"sampled_events"`
	DroppedEvents   uint64 `json:"dropped_events"`
	TCPEvents       uint64 `json:"tcp_events"`
	SCTPEvents      uint64 `json:"sctp_events"`
	UDPEvents       uint64 `json:"udp_events"`
	ConnNew         uint64 `json:"conn_new"`
	ConnEstablished uint64 `json:"conn_established"`
	ConnClosed      uint64 `json:"conn_closed"`
	ConnTimeout     uint64 `json:"conn_timeout"`
	ConnReset       uint64 `json:"conn_reset"`
	ConnError       uint64 `json:"conn_error"`
}

// EnableL4Tracing returns error when L4 tracing is not compiled in
func EnableL4Tracing() error {
	tk.LogIt(tk.LogWarning, "[L4Trace] L4 tracing not compiled (build with -tags l4trace)\n")
	return fmt.Errorf("L4 tracing not compiled (build with -tags l4trace)")
}

// DisableL4Tracing returns error when L4 tracing is not compiled in
func DisableL4Tracing() error {
	return fmt.Errorf("L4 tracing not compiled")
}

// IsL4TracingEnabled always returns false when L4 tracing is not compiled in
func IsL4TracingEnabled() bool {
	return false
}

// SetL4TracingSamplingRate returns error when L4 tracing is not compiled in
func SetL4TracingSamplingRate(rate uint8) error {
	return fmt.Errorf("L4 tracing not compiled")
}

// GetL4TraceStats returns empty stats when L4 tracing is not compiled in
func GetL4TraceStats() L4TraceStats {
	return L4TraceStats{}
}

// ResetL4TraceStats is a no-op when L4 tracing is not compiled in
func ResetL4TraceStats() {
	// No-op
}
