/*
 * Copyright (c) 2025 NetLOX Inc
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
	"reflect"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	tk "github.com/loxilb-io/loxilib"
)

// WorkerMetricsRequest matches the Swagger definition (vLLM 0.9.x)
type WorkerMetricsRequest struct {
	EndpointIP       string    `json:"endpoint_ip"`
	QueuedRequests   uint32    `json:"queued_requests"`
	SwappedRequests  uint32    `json:"swapped_requests"`
	KVCacheUsagePerc uint32    `json:"kv_cache_usage_perc"`
	NumGPUBlocks     uint32    `json:"num_gpu_blocks"`
	Timestamp        time.Time `json:"timestamp"`
}

// WorkerMetricsResponse for GET requests
type WorkerMetricsResponse struct {
	Workers           []WorkerMetricsRequest `json:"workers"`
	MonitoringEnabled bool                   `json:"monitoring_enabled"`
}

// ConfigPostGPUEnable handles POST /config/gpu/enable
func ConfigPostGPUEnable(params operations.PostConfigGpuEnableParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] POST /config/gpu/enable\n")

	// Check if already enabled
	if ApiHooks.NetDpEbpfIsGPUMonitoringEnabled() {
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    400,
				Message: "GPU monitoring already enabled",
				Result:  "GPU monitoring is already active",
			},
		}
	}

	// Enable GPU monitoring
	if err := ApiHooks.NetDpEbpfEnableGPUMonitoring(); err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to enable GPU monitoring: %v\n", err)
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    500,
				Message: "Failed to enable GPU monitoring",
				Result:  err.Error(),
			},
		}
	}

	tk.LogIt(tk.LogInfo, "[API] GPU-aware load balancing enabled\n")

	// Build response with all required fields (pointers)
	enabled := true
	routingMode := "gpu_aware"
	message := "GPU monitoring enabled successfully"

	response := &models.GPUEnableResponse{
		Enabled:     &enabled,
		RoutingMode: &routingMode,
		Message:     &message,
	}

	return operations.NewPostConfigGpuEnableOK().WithPayload(response)
}

// ConfigPostGPUDisable handles POST /config/gpu/disable
func ConfigPostGPUDisable(params operations.PostConfigGpuDisableParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] POST /config/gpu/disable\n")

	// Check if already disabled
	if !ApiHooks.NetDpEbpfIsGPUMonitoringEnabled() {
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    400,
				Message: "GPU monitoring already disabled",
				Result:  "GPU monitoring is not active",
			},
		}
	}

	// Disable GPU monitoring
	if err := ApiHooks.NetDpEbpfDisableGPUMonitoring(); err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to disable GPU monitoring: %v\n", err)
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    500,
				Message: "Failed to disable GPU monitoring",
				Result:  err.Error(),
			},
		}
	}

	tk.LogIt(tk.LogInfo, "[API] GPU-aware load balancing disabled, falling back to standard CHWBL\n")

	// Build response with all required fields (pointers)
	enabled := false
	routingMode := "standard_chwbl"
	message := "GPU monitoring disabled successfully"

	response := &models.GPUEnableResponse{
		Enabled:     &enabled,
		RoutingMode: &routingMode,
		Message:     &message,
	}

	return operations.NewPostConfigGpuDisableOK().WithPayload(response)
}

// ConfigGetGPUStatus handles GET /config/gpu/status
func ConfigGetGPUStatus(params operations.GetConfigGpuStatusParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] GET /config/gpu/status\n")

	statusInterface := ApiHooks.NetDpEbpfGetGPUMonitoringStatus()
	if statusInterface == nil {
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    500,
				Message: "Failed to get GPU monitoring status",
				Result:  "Status is nil",
			},
		}
	}

	// Convert from loxinet.GPUMonitoringStatus to models.GPUMonitoringStatus using reflection
	// This avoids import cycle issues with the loxinet package
	response := &models.GPUMonitoringStatus{}

	v := reflect.ValueOf(statusInterface)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	tk.LogIt(tk.LogDebug, "[API] Extracting GPU status, type: %v, kind: %v\n", v.Type(), v.Kind())

	// Extract fields using reflection with better error handling
	if enabled := v.FieldByName("Enabled"); enabled.IsValid() && enabled.CanInterface() {
		response.Enabled = enabled.Bool()
		tk.LogIt(tk.LogDebug, "[API] Enabled: %v\n", response.Enabled)
	} else {
		tk.LogIt(tk.LogWarning, "[API] Failed to extract Enabled field\n")
	}

	if routingMode := v.FieldByName("RoutingMode"); routingMode.IsValid() && routingMode.CanInterface() {
		response.RoutingMode = routingMode.String()
		tk.LogIt(tk.LogDebug, "[API] RoutingMode: %v\n", response.RoutingMode)
	} else {
		tk.LogIt(tk.LogWarning, "[API] Failed to extract RoutingMode field\n")
	}

	if workerCount := v.FieldByName("WorkerCount"); workerCount.IsValid() && workerCount.CanInterface() {
		response.WorkerCount = int64(workerCount.Int())
		tk.LogIt(tk.LogDebug, "[API] WorkerCount: %v\n", response.WorkerCount)
	} else {
		tk.LogIt(tk.LogWarning, "[API] Failed to extract WorkerCount field\n")
	}

	if lastUpdate := v.FieldByName("LastMetricsUpdate"); lastUpdate.IsValid() && lastUpdate.CanInterface() {
		if t, ok := lastUpdate.Interface().(time.Time); ok {
			response.LastMetricsUpdate = strfmt.DateTime(t)
			tk.LogIt(tk.LogDebug, "[API] LastMetricsUpdate: %v\n", response.LastMetricsUpdate)
		}
	} else {
		tk.LogIt(tk.LogWarning, "[API] Failed to extract LastMetricsUpdate field\n")
	}

	if ebpfMapLoaded := v.FieldByName("EbpfMapLoaded"); ebpfMapLoaded.IsValid() && ebpfMapLoaded.CanInterface() {
		response.EbpfMapLoaded = ebpfMapLoaded.Bool()
		tk.LogIt(tk.LogDebug, "[API] EbpfMapLoaded: %v\n", response.EbpfMapLoaded)
	} else {
		tk.LogIt(tk.LogWarning, "[API] Failed to extract EbpfMapLoaded field\n")
	}

	return operations.NewGetConfigGpuStatusOK().WithPayload(response)
}

// ConfigPostConfigWorkerMetrics handles POST /config/worker/metrics
func ConfigPostConfigWorkerMetrics(params operations.PostConfigWorkerMetricsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] POST /config/worker/metrics\n")

	// CRITICAL: Check if GPU monitoring is enabled
	if !ApiHooks.NetDpEbpfIsGPUMonitoringEnabled() {
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    400,
				Message: "GPU monitoring is disabled",
				Result:  "GPU monitoring must be enabled first. Use: POST /config/gpu/enable",
			},
		}
	}

	// Validate required fields
	if params.Attr.EndpointIP == nil || *params.Attr.EndpointIP == "" {
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    400,
				Message: "Missing required field",
				Result:  "endpoint_ip is required",
			},
		}
	}

	if params.Attr.QueuedRequests == nil {
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    400,
				Message: "Missing required field",
				Result:  "queued_requests is required",
			},
		}
	}

	if params.Attr.KvCacheUsagePerc == nil {
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    400,
				Message: "Missing required field",
				Result:  "kv_cache_usage_perc is required",
			},
		}
	}

	// Parse timestamp - strfmt.DateTime is a value type, not pointer
	var timestamp time.Time
	timestamp = time.Time(params.Attr.Timestamp)

	// Validate timestamp (reject stale metrics if provided)
	if !timestamp.IsZero() {
		age := time.Since(timestamp)
		if age > 10*time.Second {
			return &ErrorResponse{
				Payload: &models.Error{
					Code:    400,
					Message: "Metrics too old",
					Result:  "metrics age exceeds 10 seconds: " + age.String(),
				},
			}
		}
	} else {
		timestamp = time.Now()
	}

	// Build metrics request (vLLM 0.9.x)
	req := &WorkerMetricsRequest{
		EndpointIP:       *params.Attr.EndpointIP,
		QueuedRequests:   uint32(*params.Attr.QueuedRequests),
		KVCacheUsagePerc: uint32(*params.Attr.KvCacheUsagePerc),
		Timestamp:        timestamp,
	}

	// Optional fields (vLLM 0.9.x)
	if params.Attr.SwappedRequests != nil {
		req.SwappedRequests = uint32(*params.Attr.SwappedRequests)
	}
	if params.Attr.NumGpuBlocks != nil {
		req.NumGPUBlocks = uint32(*params.Attr.NumGpuBlocks)
	}

	// Convert API request to backend WorkerMetrics struct
	// NOTE: Backend expects a different struct with LastUpdate instead of Timestamp
	backendMetrics := struct {
		EndpointIP       string
		QueuedRequests   uint32
		SwappedRequests  uint32
		KVCacheUsagePerc uint32
		NumGPUBlocks     uint32
		LastUpdate       time.Time
		IsOverloaded     bool
		OverloadStart    time.Time
	}{
		EndpointIP:       req.EndpointIP,
		QueuedRequests:   req.QueuedRequests,
		SwappedRequests:  req.SwappedRequests,
		KVCacheUsagePerc: req.KVCacheUsagePerc,
		NumGPUBlocks:     req.NumGPUBlocks,
		LastUpdate:       timestamp,
		IsOverloaded:     false, // Will be set by backend
		OverloadStart:    time.Time{},
	}

	// Update worker metrics
	if err := ApiHooks.NetDpEbpfUpdateWorkerMetrics(req.EndpointIP, &backendMetrics); err != nil {
		tk.LogIt(tk.LogError, "[API] Failed to update worker metrics: %v\n", err)
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    500,
				Message: "Failed to update metrics",
				Result:  err.Error(),
			},
		}
	}

	tk.LogIt(tk.LogDebug, "[API] Worker metrics updated: ep=%s queue=%d swapped=%d kv_cache=%d%%\n",
		req.EndpointIP, req.QueuedRequests, req.SwappedRequests, req.KVCacheUsagePerc)

	// Build response with all required fields (pointers)
	queuedRequests := int64(req.QueuedRequests)
	message := "Metrics updated successfully"

	response := &models.WorkerMetricsUpdateResponse{
		EndpointIP:     &req.EndpointIP,
		QueuedRequests: &queuedRequests,
		Message:        &message,
	}

	return operations.NewPostConfigWorkerMetricsOK().WithPayload(response)
}

// ConfigGetConfigWorkerMetrics handles GET /config/worker/metrics (vLLM 0.9.x)
func ConfigGetConfigWorkerMetrics(params operations.GetConfigWorkerMetricsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] GET /config/worker/metrics\n")

	// Retrieve all worker metrics
	workers := ApiHooks.NetDpEbpfGetAllWorkerMetrics()

	// Convert []interface{} to []*models.WorkerMetricsEntry (vLLM 0.9.x)
	entries := make([]*models.WorkerMetricsEntry, 0, len(workers))
	for _, w := range workers {
		// Use reflection to extract fields from backend's WorkerMetrics struct
		rv := reflect.ValueOf(w)
		if rv.Kind() == reflect.Ptr {
			rv = rv.Elem()
		}

		if rv.Kind() != reflect.Struct {
			tk.LogIt(tk.LogWarning, "[API] Skipping non-struct worker metrics entry\n")
			continue
		}

		// Extract fields using reflection
		var endpointIP string
		var queuedRequests, kvCacheUsagePerc, swappedRequests, numGPUBlocks int64
		var timestamp time.Time

		if field := rv.FieldByName("EndpointIP"); field.IsValid() && field.CanInterface() {
			endpointIP = field.String()
		}
		if field := rv.FieldByName("QueuedRequests"); field.IsValid() && field.CanInterface() {
			queuedRequests = int64(field.Uint())
		}
		if field := rv.FieldByName("KVCacheUsagePerc"); field.IsValid() && field.CanInterface() {
			kvCacheUsagePerc = int64(field.Uint())
		}
		if field := rv.FieldByName("SwappedRequests"); field.IsValid() && field.CanInterface() {
			swappedRequests = int64(field.Uint())
		}
		if field := rv.FieldByName("NumGPUBlocks"); field.IsValid() && field.CanInterface() {
			numGPUBlocks = int64(field.Uint())
		}
		if field := rv.FieldByName("LastUpdate"); field.IsValid() && field.CanInterface() {
			if t, ok := field.Interface().(time.Time); ok {
				timestamp = t
			}
		}

		// Convert to API model format
		ts := strfmt.DateTime(timestamp)
		modelEntry := &models.WorkerMetricsEntry{
			Timestamp:        ts,
			EndpointIP:       &endpointIP,
			QueuedRequests:   &queuedRequests,
			KvCacheUsagePerc: &kvCacheUsagePerc,
			SwappedRequests:  &swappedRequests,
			NumGpuBlocks:     &numGPUBlocks,
		}
		entries = append(entries, modelEntry)

		tk.LogIt(tk.LogDebug, "[API] Retrieved metrics: ep=%s queue=%d kv_cache=%d%%\n",
			endpointIP, queuedRequests, kvCacheUsagePerc)
	}

	// Convert to response format
	response := &models.WorkerMetricsResponse{
		Workers: entries,
	}

	return operations.NewGetConfigWorkerMetricsOK().WithPayload(response)
}

// ConfigPostConfigGPUConversationsCleanup handles POST /config/gpu/conversations/cleanup
func ConfigPostConfigGPUConversationsCleanup(params operations.PostConfigGpuConversationsCleanupParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "[API] POST /config/gpu/conversations/cleanup\n")

	// CRITICAL: Check if GPU monitoring is enabled
	if !ApiHooks.NetDpEbpfIsGPUMonitoringEnabled() {
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    400,
				Message: "GPU monitoring is disabled",
				Result:  "Conversation cleanup requires GPU monitoring to be enabled",
			},
		}
	}

	// Parse max_age_hours parameter (default: 1)
	maxAgeHours := 1
	if params.MaxAgeHours != nil {
		maxAgeHours = int(*params.MaxAgeHours)
		if maxAgeHours < 0 {
			return &ErrorResponse{
				Payload: &models.Error{
					Code:    400,
					Message: "Invalid parameter",
					Result:  "max_age_hours must be non-negative",
				},
			}
		}
	}

	// Calculate cutoff timestamp
	cutoffTime := time.Now().Add(-time.Duration(maxAgeHours) * time.Hour)

	// Trigger cleanup
	deletedCount, oldestRemainingHours, err := ApiHooks.NetDpEbpfCleanupStaleConversations(cutoffTime)
	if err != nil {
		tk.LogIt(tk.LogError, "[API] Conversation cleanup failed: %v\n", err)
		return &ErrorResponse{
			Payload: &models.Error{
				Code:    500,
				Message: "Cleanup operation failed",
				Result:  err.Error(),
			},
		}
	}

	tk.LogIt(tk.LogInfo, "[API] Manual conversation cleanup completed: max_age=%dh, deleted=%d, oldest_remaining=%.1fh\n",
		maxAgeHours, deletedCount, oldestRemainingHours)

	// Build response with all required fields (pointers)
	deletedCountPtr := int64(deletedCount)
	oldestRemainingPtr := float32(oldestRemainingHours)
	messagePtr := "Cleanup completed successfully"

	response := &models.ConversationCleanupResponse{
		DeletedCount:         &deletedCountPtr,
		OldestRemainingHours: &oldestRemainingPtr,
		Message:              &messagePtr,
	}

	return operations.NewPostConfigGpuConversationsCleanupOK().WithPayload(response)
}
