//go:build !l4trace
// +build !l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * L4 Connection Tracing: Runtime Configuration (Disabled Stub)
 */

package loxinet

import (
	"fmt"

	cmn "github.com/loxilb-io/loxilb/common"
)

// L4TraceConfig stub
type L4TraceConfig struct {
	Enabled      bool   `json:"enabled"`
	SamplingRate uint32 `json:"samplingRate"`
	Version      uint32 `json:"version"` // Config version (always 0 when disabled)
}

// DpL4TraceConfigSet stub - always returns error when L4 tracing is disabled
func (e *DpEbpfH) DpL4TraceConfigSet(config L4TraceConfig) error {
	return fmt.Errorf("L4 tracing not enabled at build time")
}

// DpL4TraceConfigGet stub - returns disabled config
func (e *DpEbpfH) DpL4TraceConfigGet() (L4TraceConfig, error) {
	return L4TraceConfig{
		Enabled:      false,
		SamplingRate: 0,
		Version:      0,
	}, nil
}

// DpL4TraceStatsGet stub - returns empty statistics when L4 tracing is disabled
func (e *DpEbpfH) DpL4TraceStatsGet() (*cmn.L4TraceStats, error) {
	return &cmn.L4TraceStats{
		TotalEvents:     0,
		SampledEvents:   0,
		DroppedEvents:   0,
		TCPEvents:       0,
		SCTPEvents:      0,
		UDPEvents:       0,
		ConnNew:         0,
		ConnEstablished: 0,
		ConnClosed:      0,
		ConnTimeout:     0,
		ConnReset:       0,
		ConnError:       0,
	}, nil
}
