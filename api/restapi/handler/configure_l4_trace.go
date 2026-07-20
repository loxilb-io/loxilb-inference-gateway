/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handler

import (
	"fmt"

	"github.com/go-openapi/runtime/middleware"
	tk "github.com/loxilb-io/loxilib"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations/l4_tracing"
)

// ConfigEnableL4Trace enables L4 TCP/SCTP/UDP connection tracing
// POST /config/l4trace/enable
func ConfigEnableL4Trace(params l4_tracing.PostConfigL4traceEnableParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] POST /config/l4trace/enable\n")

	// Default sampling rate: 100%
	samplingRate := uint32(100)
	if params.Attr.SamplingRate != nil {
		samplingRate = uint32(*params.Attr.SamplingRate)
	}

	// Validate sampling rate
	if samplingRate > 100 {
		tk.LogIt(tk.LogWarning, "[API] Invalid sampling rate: %d (must be 0-100)\n", samplingRate)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(fmt.Sprintf("Invalid sampling rate: %d (must be 0-100)", samplingRate))}
	}

	// Enable L4 tracing via API hooks
	if err := ApiHooks.NetL4TraceEnable(samplingRate); err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to enable L4 tracing: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(fmt.Sprintf("Failed to enable L4 tracing: %v", err))}
	}

	tk.LogIt(tk.LogInfo, "[API] L4 tracing enabled (sampling: %d%%)\n", samplingRate)
	return &ResultResponse{Result: fmt.Sprintf("L4 connection tracing enabled (sampling: %d%%)", samplingRate)}
}

// ConfigDisableL4Trace disables L4 TCP/SCTP/UDP connection tracing
// POST /config/l4trace/disable
func ConfigDisableL4Trace(params l4_tracing.PostConfigL4traceDisableParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] POST /config/l4trace/disable\n")

	// Disable L4 tracing via API hooks
	if err := ApiHooks.NetL4TraceDisable(); err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to disable L4 tracing: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(fmt.Sprintf("Failed to disable L4 tracing: %v", err))}
	}

	tk.LogIt(tk.LogInfo, "[API] L4 tracing disabled\n")
	return &ResultResponse{Result: "L4 connection tracing disabled"}
}

// ConfigGetL4TraceStatus returns current L4 tracing status and statistics
// GET /config/l4trace/status
func ConfigGetL4TraceStatus(params l4_tracing.GetConfigL4traceStatusParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] GET /config/l4trace/status\n")

	// Get status via API hooks
	status, err := ApiHooks.NetL4TraceGetStatus()
	if err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to get L4 trace status: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(fmt.Sprintf("Failed to get L4 trace status: %v", err))}
	}

	// Convert to swagger model
	response := &models.L4TraceStatusResponse{
		Enabled:       status.Enabled,
		SamplingRate:  int64(status.SamplingRate),
		ConfigVersion: int64(status.ConfigVersion),
		Stats: &models.L4TraceStats{
			TotalEvents:     int64(status.Stats.TotalEvents),
			SampledEvents:   int64(status.Stats.SampledEvents),
			DroppedEvents:   int64(status.Stats.DroppedEvents),
			TCPEvents:       int64(status.Stats.TCPEvents),
			SctpEvents:      int64(status.Stats.SCTPEvents),
			UDPEvents:       int64(status.Stats.UDPEvents),
			ConnNew:         int64(status.Stats.ConnNew),
			ConnEstablished: int64(status.Stats.ConnEstablished),
			ConnClosed:      int64(status.Stats.ConnClosed),
			ConnTimeout:     int64(status.Stats.ConnTimeout),
			ConnReset:       int64(status.Stats.ConnReset),
			ConnError:       int64(status.Stats.ConnError),
		},
	}

	tk.LogIt(tk.LogInfo, "[API] L4 trace status: enabled=%v sampling=%d%%\n", status.Enabled, status.SamplingRate)
	return l4_tracing.NewGetConfigL4traceStatusOK().WithPayload(response)
}

// ConfigUpdateL4TraceSampling updates L4 tracing sampling rate
// PUT /config/l4trace/sampling
func ConfigUpdateL4TraceSampling(params l4_tracing.PutConfigL4traceSamplingParams, principal interface{}) middleware.Responder {
	samplingRate := uint32(*params.Attr.SamplingRate)
	tk.LogIt(tk.LogDebug, "[API] PUT /config/l4trace/sampling (rate=%d%%)\n", samplingRate)

	// Validate sampling rate
	if samplingRate > 100 {
		tk.LogIt(tk.LogWarning, "[API] Invalid sampling rate: %d (must be 0-100)\n", samplingRate)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(fmt.Sprintf("Invalid sampling rate: %d (must be 0-100)", samplingRate))}
	}

	// Update sampling rate via API hooks
	if err := ApiHooks.NetL4TraceUpdateSampling(samplingRate); err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to update sampling rate: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(fmt.Sprintf("Failed to update sampling rate: %v", err))}
	}

	tk.LogIt(tk.LogInfo, "[API] L4 sampling rate updated to %d%%\n", samplingRate)
	return &ResultResponse{Result: fmt.Sprintf("L4 sampling rate updated to %d%%", samplingRate)}
}

// ConfigResetL4TraceStats resets L4 tracing statistics counters
// POST /config/l4trace/stats/reset
func ConfigResetL4TraceStats(params l4_tracing.PostConfigL4traceStatsResetParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] POST /config/l4trace/stats/reset\n")

	// Reset stats via API hooks
	if err := ApiHooks.NetL4TraceResetStats(); err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to reset L4 trace stats: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(fmt.Sprintf("Failed to reset statistics: %v", err))}
	}

	tk.LogIt(tk.LogInfo, "[API] L4 tracing statistics reset\n")
	return &ResultResponse{Result: "L4 tracing statistics reset successfully"}
}
