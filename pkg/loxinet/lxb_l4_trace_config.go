//go:build l4trace
// +build l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * L4 Connection Tracing: Runtime Configuration
 *
 * This file provides eBPF map configuration for L4 tracing control.
 * Follows the pattern of DpSecurityRateConfigSet (dpebpf_linux.go:3155-3420)
 */

package loxinet

/*
#cgo CFLAGS: -DHAVE_L4_TRACE -I../../loxilb-ebpf/kernel -I../../loxilb-ebpf/liblxb -I../../loxilb-ebpf/common
#include <stdlib.h>
#include <stdint.h>
#include "loxilb_libdp.h"
#include "llb_dpapi.h"

// Access to BPF map operations
extern int llb_map2fd(int);
extern int bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags);
extern int bpf_map_lookup_elem(int fd, const void *key, void *value);
*/
import "C"
import (
	"fmt"
	"unsafe"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// L4TraceConfig - Runtime configuration for L4 tracing
type L4TraceConfig struct {
	Enabled      bool   `json:"enabled"`
	SamplingRate uint32 `json:"samplingRate"` // 0-100 percentage
	Version      uint32 `json:"version"`      // Config version from eBPF map
}

// DpL4TraceConfigSet - Update L4 trace configuration in eBPF map
// Pattern: Follows DpSecurityRateConfigSet (dpebpf_linux.go:3155)
func (e *DpEbpfH) DpL4TraceConfigSet(config L4TraceConfig) error {
	// Get config map file descriptor
	configFd := C.llb_map2fd(C.int(C.LL_DP_L4_TRACE_CONFIG_MAP))
	if configFd < 0 {
		return fmt.Errorf("failed to get l4_trace_cfg map fd")
	}

	// C structure matches: struct dp_l4_trace_config (llb_kern_cdefs.h:82)
	type dpL4TraceConfig struct {
		Version      uint32
		Enabled      uint32
		SamplingRate uint32
		Reserved     uint32
	}

	var currentCfg dpL4TraceConfig
	var key C.uint = 0

	// Read current config to get version
	var newVersion uint32 = 1
	if C.bpf_map_lookup_elem(C.int(configFd), unsafe.Pointer(&key), unsafe.Pointer(&currentCfg)) == 0 {
		// Increment version for potential future per-CPU cache
		newVersion = currentCfg.Version + 1
		if newVersion == 0 {
			newVersion = 1 // Avoid wrapping to 0
		}
	}

	// Prepare new configuration
	cfgData := dpL4TraceConfig{
		Version:      newVersion,
		Enabled:      0,
		SamplingRate: config.SamplingRate,
		Reserved:     0,
	}

	if config.Enabled {
		cfgData.Enabled = 1
	}

	// Validate sampling rate
	if cfgData.SamplingRate > 100 {
		cfgData.SamplingRate = 100
	}

	// Update eBPF map at index 0
	ret := C.bpf_map_update_elem(C.int(configFd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&cfgData),
		C.BPF_ANY)

	if ret != 0 {
		return fmt.Errorf("failed to update l4_trace_cfg map: ret=%d", ret)
	}

	tk.LogIt(tk.LogInfo, "[L4Trace] Config updated: version=%d enabled=%v sampling=%d%%\n",
		newVersion, config.Enabled, cfgData.SamplingRate)

	return nil
}

// DpL4TraceConfigGet - Get current L4 trace configuration from eBPF map
func (e *DpEbpfH) DpL4TraceConfigGet() (L4TraceConfig, error) {
	configFd := C.llb_map2fd(C.int(C.LL_DP_L4_TRACE_CONFIG_MAP))
	if configFd < 0 {
		// Return defaults if map not found
		return L4TraceConfig{
			Enabled:      false,
			SamplingRate: 100,
		}, nil
	}

	type dpL4TraceConfig struct {
		Version      uint32
		Enabled      uint32
		SamplingRate uint32
		Reserved     uint32
	}

	var cfgData dpL4TraceConfig
	var key C.uint = 0

	// Read from map
	if C.bpf_map_lookup_elem(C.int(configFd), unsafe.Pointer(&key), unsafe.Pointer(&cfgData)) != 0 {
		// Return defaults if not found
		return L4TraceConfig{
			Enabled:      false,
			SamplingRate: 100,
		}, nil
	}

	// Convert to Go structure
	config := L4TraceConfig{
		Enabled:      cfgData.Enabled == 1,
		SamplingRate: cfgData.SamplingRate,
		Version:      cfgData.Version,
	}

	return config, nil
}

// DpL4TraceStatsGet - Read L4 tracing statistics from C library
func (e *DpEbpfH) DpL4TraceStatsGet() (*cmn.L4TraceStats, error) {
	// Get stats from C library (aggregates from all workers)
	stats := GetL4TraceStats()

	// Convert to common.L4TraceStats
	return &cmn.L4TraceStats{
		TotalEvents:     stats.TotalEvents,
		SampledEvents:   stats.SampledEvents,
		DroppedEvents:   stats.DroppedEvents,
		TCPEvents:       stats.TCPEvents,
		SCTPEvents:      stats.SCTPEvents,
		UDPEvents:       stats.UDPEvents,
		ConnNew:         stats.ConnNew,
		ConnEstablished: stats.ConnEstablished,
		ConnClosed:      stats.ConnClosed,
		ConnTimeout:     stats.ConnTimeout,
		ConnReset:       stats.ConnReset,
		ConnError:       stats.ConnError,
	}, nil
}
