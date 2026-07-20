//go:build l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

package loxinet

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>
#include <stdbool.h>

// L4 Tracing Runtime Control (Placeholder for Phase 1)
// These will be implemented in loxilb-ebpf/liblxb/lxb_l4_trace.c

// Enable/Disable L4 tracing at runtime
// Returns: 0 on success, -1 on error
extern int lxb_l4_trace_enable(uint8_t enabled);

// Get current L4 tracing status
// Returns: 1 if enabled, 0 if disabled
extern uint8_t lxb_l4_trace_is_enabled(void);

// Set sampling rate (0-100 percentage)
// Returns: 0 on success, -1 on invalid rate
extern int lxb_l4_trace_set_sampling_rate(uint8_t rate);

// Get L4 tracing statistics
// Returns: populated stats struct
struct l4_trace_stats {
    uint64_t total_events;      // Total L4 events emitted
    uint64_t sampled_events;    // Events that passed sampling
    uint64_t dropped_events;    // Ring buffer overflows
    uint64_t tcp_events;        // TCP state changes
    uint64_t sctp_events;       // SCTP state changes
    uint64_t udp_events;        // UDP state changes
    uint64_t conn_new;          // New connections
    uint64_t conn_established;  // Established connections
    uint64_t conn_closed;       // Clean closes
    uint64_t conn_timeout;      // Timeout closes
    uint64_t conn_reset;        // RST/ABORT closes
    uint64_t conn_error;        // Error events
};

extern struct l4_trace_stats lxb_l4_trace_get_stats(void);

// Reset L4 tracing statistics
extern void lxb_l4_trace_reset_stats(void);
*/
import "C"

import (
	"fmt"
	"sync/atomic"

	tk "github.com/loxilb-io/loxilib"
)

// L4TraceStats holds L4 connection tracing statistics
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

var (
	// Global L4 tracing enable flag (atomic for thread-safe REST API)
	l4TracingEnabled uint32 = 0 // 0 = disabled, 1 = enabled
)

// EnableL4Tracing enables L4 connection tracing at runtime
func EnableL4Tracing() error {
	if !atomic.CompareAndSwapUint32(&l4TracingEnabled, 0, 1) {
		return fmt.Errorf("L4 tracing already enabled")
	}

	// Call C function to enable in eBPF side
	ret := C.lxb_l4_trace_enable(1)
	if ret != 0 {
		atomic.StoreUint32(&l4TracingEnabled, 0)
		return fmt.Errorf("failed to enable L4 tracing in eBPF")
	}

	tk.LogIt(tk.LogInfo, "[L4Trace] L4 tracing enabled\n")
	return nil
}

// DisableL4Tracing disables L4 connection tracing at runtime
func DisableL4Tracing() error {
	if !atomic.CompareAndSwapUint32(&l4TracingEnabled, 1, 0) {
		return fmt.Errorf("L4 tracing already disabled")
	}

	// Call C function to disable in eBPF side
	ret := C.lxb_l4_trace_enable(0)
	if ret != 0 {
		atomic.StoreUint32(&l4TracingEnabled, 1)
		return fmt.Errorf("failed to disable L4 tracing in eBPF")
	}

	tk.LogIt(tk.LogInfo, "[L4Trace] L4 tracing disabled\n")
	return nil
}

// IsL4TracingEnabled returns current L4 tracing status
func IsL4TracingEnabled() bool {
	return atomic.LoadUint32(&l4TracingEnabled) == 1
}

// SetL4TracingSamplingRate configures sampling rate (0-100%)
func SetL4TracingSamplingRate(rate uint8) error {
	if rate > 100 {
		return fmt.Errorf("invalid sampling rate: %d (must be 0-100)", rate)
	}

	ret := C.lxb_l4_trace_set_sampling_rate(C.uint8_t(rate))
	if ret != 0 {
		return fmt.Errorf("failed to set L4 sampling rate")
	}

	tk.LogIt(tk.LogInfo, "[L4Trace] Sampling rate set to %d%%\n", rate)
	return nil
}

// GetL4TraceStats retrieves L4 tracing statistics from eBPF
func GetL4TraceStats() L4TraceStats {
	cStats := C.lxb_l4_trace_get_stats()

	return L4TraceStats{
		TotalEvents:     uint64(cStats.total_events),
		SampledEvents:   uint64(cStats.sampled_events),
		DroppedEvents:   uint64(cStats.dropped_events),
		TCPEvents:       uint64(cStats.tcp_events),
		SCTPEvents:      uint64(cStats.sctp_events),
		UDPEvents:       uint64(cStats.udp_events),
		ConnNew:         uint64(cStats.conn_new),
		ConnEstablished: uint64(cStats.conn_established),
		ConnClosed:      uint64(cStats.conn_closed),
		ConnTimeout:     uint64(cStats.conn_timeout),
		ConnReset:       uint64(cStats.conn_reset),
		ConnError:       uint64(cStats.conn_error),
	}
}

// ResetL4TraceStats resets all L4 tracing statistics
func ResetL4TraceStats() {
	C.lxb_l4_trace_reset_stats()
	tk.LogIt(tk.LogInfo, "[L4Trace] Statistics reset\n")
}
