/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * LlamaFirewall AI Security REST API Handlers
 * Provides runtime configuration endpoints for LlamaFirewall security scanning
 */
package handler

import (
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	"github.com/loxilb-io/loxilb/pkg/llamafirewall"
	tk "github.com/loxilb-io/loxilib"
)

// ConfigPostLlamaFirewallEnable - Enable/disable LlamaFirewall AI security scanning
func ConfigPostLlamaFirewallEnable(params operations.PostConfigLlamafirewallEnableParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: LlamaFirewall Enable %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	// Check if params.Attr and params.Attr.Enabled are valid
	if params.Attr.Enabled == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("enabled field is required")}
	}

	enabled := *params.Attr.Enabled

	// Get current config from config manager
	cfgMgr := llamafirewall.GlobalConfigMgr()
	if cfgMgr == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("LlamaFirewall config manager not initialized")}
	}
	config, err := cfgMgr.GetConfig()
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("LlamaFirewall not initialized: " + err.Error())}
	}

	// Update enabled flag
	config.Enabled = enabled

	// Apply config
	if err := cfgMgr.UpdateConfig(*config); err != nil {
		tk.LogIt(tk.LogError, "[LlamaFirewall] Failed to update config: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall] ✓ LlamaFirewall %s\n",
		map[bool]string{true: "enabled", false: "disabled"}[enabled])
	return &ResultResponse{Result: "Success"}
}

// ConfigPostLlamaFirewallConfigure - Update LlamaFirewall configuration
func ConfigPostLlamaFirewallConfigure(params operations.PostConfigLlamafirewallConfigureParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: LlamaFirewall Configure %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	// Get current config from config manager
	cfgMgr := llamafirewall.GlobalConfigMgr()
	if cfgMgr == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("LlamaFirewall config manager not initialized")}
	}
	config, err := cfgMgr.GetConfig()
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("LlamaFirewall not initialized: " + err.Error())}
	}

	// Update fields from request
	if params.Attr.ServerURL != "" {
		config.ServerURL = params.Attr.ServerURL
	}
	if params.Attr.TimeoutSec != nil {
		config.TimeoutSec = int(*params.Attr.TimeoutSec)
	}
	if params.Attr.FailClosed != nil {
		config.FailClosed = *params.Attr.FailClosed
	}
	if params.Attr.BlockThreshold != nil {
		config.BlockThreshold = float32(*params.Attr.BlockThreshold)
	}
	if params.Attr.CacheEnabled != nil {
		config.CacheEnabled = *params.Attr.CacheEnabled
	}
	if params.Attr.CacheTTLSec != nil {
		config.CacheTTLSec = int(*params.Attr.CacheTTLSec)
	}
	if params.Attr.ConnectionPoolSize != nil {
		config.ConnectionPoolSize = int(*params.Attr.ConnectionPoolSize)
	}
	if params.Attr.ScanPatterns != nil {
		config.ScanPatterns = params.Attr.ScanPatterns
	}
	if params.Attr.SkipPatterns != nil {
		config.SkipPatterns = params.Attr.SkipPatterns
	}

	// Apply config
	if err := cfgMgr.UpdateConfig(*config); err != nil {
		tk.LogIt(tk.LogError, "[LlamaFirewall] Failed to update config: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall] ✓ Configuration updated (server=%s, threshold=%.2f)\n",
		config.ServerURL, config.BlockThreshold)
	return &ResultResponse{Result: "Success"}
}

// ConfigPostLlamaFirewallScanners - Configure individual scanner settings
func ConfigPostLlamaFirewallScanners(params operations.PostConfigLlamafirewallScannersParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: LlamaFirewall Scanners %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	// Get current config from config manager
	cfgMgr := llamafirewall.GlobalConfigMgr()
	if cfgMgr == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("LlamaFirewall config manager not initialized")}
	}
	config, err := cfgMgr.GetConfig()
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("LlamaFirewall not initialized: " + err.Error())}
	}

	// Update scanner flags
	if params.Attr.PromptGuard != nil {
		config.ScannerPromptGuard = *params.Attr.PromptGuard
	}
	if params.Attr.CodeShield != nil {
		config.ScannerCodeShield = *params.Attr.CodeShield
	}
	if params.Attr.Regex != nil {
		config.ScannerRegex = *params.Attr.Regex
	}
	if params.Attr.HiddenASCII != nil {
		config.ScannerHiddenASCII = *params.Attr.HiddenASCII
	}
	if params.Attr.AgentAlignment != nil {
		config.ScannerAgentAlignment = *params.Attr.AgentAlignment
	}
	if params.Attr.PiiDetection != nil {
		config.ScannerPIIDetection = *params.Attr.PiiDetection
	}

	// Apply config
	if err := cfgMgr.UpdateConfig(*config); err != nil {
		tk.LogIt(tk.LogError, "[LlamaFirewall] Failed to update scanners: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall] ✓ Scanners updated (PromptGuard=%v, CodeShield=%v, Regex=%v)\n",
		config.ScannerPromptGuard, config.ScannerCodeShield, config.ScannerRegex)
	return &ResultResponse{Result: "Success"}
}

// ConfigGetLlamaFirewallStatus - Get current LlamaFirewall status and configuration
func ConfigGetLlamaFirewallStatus(params operations.GetConfigLlamafirewallStatusParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: LlamaFirewall Status %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	// Get current config from config manager
	cfgMgr := llamafirewall.GlobalConfigMgr()
	if cfgMgr == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("LlamaFirewall config manager not initialized")}
	}
	config, err := cfgMgr.GetConfig()
	if err != nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("LlamaFirewall not initialized: " + err.Error())}
	}

	// Get connection status (still using loxinet for now as it has bridge functions)
	status := llamafirewall.GetStatus()

	// Build scanner status
	scannersStatus := &models.LlamaFirewallScannersStatus{
		PromptGuard:    config.ScannerPromptGuard,
		CodeShield:     config.ScannerCodeShield,
		Regex:          config.ScannerRegex,
		HiddenASCII:    config.ScannerHiddenASCII,
		AgentAlignment: config.ScannerAgentAlignment,
		PiiDetection:   config.ScannerPIIDetection,
	}

	// Build response
	threshold := config.BlockThreshold
	cacheTTL := int64(config.CacheTTLSec)
	lastHealthCheck := ""
	if status.LastHealthCheck != nil {
		lastHealthCheck = status.LastHealthCheck.Format(time.RFC3339)
	}

	response := &models.LlamaFirewallStatusResponse{
		Enabled:         config.Enabled,
		ServerURL:       config.ServerURL,
		Connected:       status.Connected,
		FailClosed:      config.FailClosed,
		BlockThreshold:  threshold,
		Scanners:        scannersStatus,
		CacheEnabled:    config.CacheEnabled,
		CacheTTLSec:     cacheTTL,
		ScanPatterns:    config.ScanPatterns,
		SkipPatterns:    config.SkipPatterns,
		LastHealthCheck: lastHealthCheck,
	}

	return operations.NewGetConfigLlamafirewallStatusOK().WithPayload(response)
}

// ConfigGetLlamaFirewallStats - Get LlamaFirewall statistics
func ConfigGetLlamaFirewallStats(params operations.GetConfigLlamafirewallStatsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: LlamaFirewall Stats %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	// Get statistics from ai_security.go
	stats := llamafirewall.GetStats()
	if stats == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("LlamaFirewall not initialized")}
	}

	// Build individual scanner stats
	promptGuardStats := &models.LlamaFirewallIndividualScannerStats{
		Scans:        stats.ScannerStats.PromptGuard.Scans,
		Detections:   stats.ScannerStats.PromptGuard.Detections,
		AvgLatencyMs: stats.ScannerStats.PromptGuard.AvgLatencyMs,
		Errors:       stats.ScannerStats.PromptGuard.Errors,
	}
	codeShieldStats := &models.LlamaFirewallIndividualScannerStats{
		Scans:        stats.ScannerStats.CodeShield.Scans,
		Detections:   stats.ScannerStats.CodeShield.Detections,
		AvgLatencyMs: stats.ScannerStats.CodeShield.AvgLatencyMs,
		Errors:       stats.ScannerStats.CodeShield.Errors,
	}
	regexStats := &models.LlamaFirewallIndividualScannerStats{
		Scans:        stats.ScannerStats.Regex.Scans,
		Detections:   stats.ScannerStats.Regex.Detections,
		AvgLatencyMs: stats.ScannerStats.Regex.AvgLatencyMs,
		Errors:       stats.ScannerStats.Regex.Errors,
	}
	hiddenAsciiStats := &models.LlamaFirewallIndividualScannerStats{
		Scans:        stats.ScannerStats.HiddenASCII.Scans,
		Detections:   stats.ScannerStats.HiddenASCII.Detections,
		AvgLatencyMs: stats.ScannerStats.HiddenASCII.AvgLatencyMs,
		Errors:       stats.ScannerStats.HiddenASCII.Errors,
	}
	agentAlignmentStats := &models.LlamaFirewallIndividualScannerStats{
		Scans:        stats.ScannerStats.AgentAlignment.Scans,
		Detections:   stats.ScannerStats.AgentAlignment.Detections,
		AvgLatencyMs: stats.ScannerStats.AgentAlignment.AvgLatencyMs,
		Errors:       stats.ScannerStats.AgentAlignment.Errors,
	}
	piiDetectionStats := &models.LlamaFirewallIndividualScannerStats{
		Scans:        stats.ScannerStats.PIIDetection.Scans,
		Detections:   stats.ScannerStats.PIIDetection.Detections,
		AvgLatencyMs: stats.ScannerStats.PIIDetection.AvgLatencyMs,
		Errors:       stats.ScannerStats.PIIDetection.Errors,
	}

	scannerStats := &models.LlamaFirewallScannerStats{
		PromptGuard:    promptGuardStats,
		CodeShield:     codeShieldStats,
		Regex:          regexStats,
		HiddenASCII:    hiddenAsciiStats,
		AgentAlignment: agentAlignmentStats,
		PiiDetection:   piiDetectionStats,
	}

	// Build decision stats
	decisionStats := &models.LlamaFirewallDecisionStats{
		Allow: stats.Decisions.Allow,
		Block: stats.Decisions.Block,
		Hitl:  stats.Decisions.HITL,
	}

	// Build response
	response := &models.LlamaFirewallStatsResponse{
		TotalScans:       stats.TotalScans,
		RequestsScanned:  stats.RequestsScanned,
		ResponsesScanned: stats.ResponsesScanned,
		ThreatsDetected:  stats.ThreatsDetected,
		RequestsBlocked:  stats.RequestsBlocked,
		ScanErrors:       stats.ScanErrors,
		AvgLatencyMs:     stats.AvgLatencyMs,
		CacheHits:        stats.CacheHits,
		ScannerStats:     scannerStats,
		Decisions:        decisionStats,
	}

	return operations.NewGetConfigLlamafirewallStatsOK().WithPayload(response)
}

// ConfigPostLlamaFirewallHealth - Trigger LlamaFirewall health check
func ConfigPostLlamaFirewallHealth(params operations.PostConfigLlamafirewallHealthParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: LlamaFirewall Health %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	// Trigger health check
	healthResult := llamafirewall.HealthCheck()

	// Build response
	response := &models.LlamaFirewallHealthResponse{
		Healthy:   healthResult.Healthy,
		ServerURL: healthResult.ServerURL,
		Connected: healthResult.Connected,
		LatencyMs: healthResult.LatencyMs,
		Message:   healthResult.Message,
		Timestamp: healthResult.Timestamp.Format(time.RFC3339),
	}

	if healthResult.Healthy {
		tk.LogIt(tk.LogInfo, "[LlamaFirewall] ✓ Health check passed (latency=%dms)\n", healthResult.LatencyMs)
		return operations.NewPostConfigLlamafirewallHealthOK().WithPayload(response)
	} else {
		tk.LogIt(tk.LogError, "[LlamaFirewall] ✗ Health check failed: %s\n", healthResult.Message)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(healthResult.Message)}
	}
}
