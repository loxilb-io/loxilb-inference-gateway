/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * PII Detection REST API Handlers
 * Provides runtime configuration endpoints for Presidio PII detection
 */
package handler

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	"github.com/loxilb-io/loxilb/pkg/presidio"
	tk "github.com/loxilb-io/loxilib"
)

// ConfigPostPIIEnable - Enable/disable PII detection
func ConfigPostPIIEnable(params operations.PostConfigPiiEnableParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: PII Enable %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	if presidio.GlobalConfigMgr() == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("PII detection not initialized")}
	}

	// Get current config
	currentCfg, err := presidio.GlobalConfigMgr().GetConfig()
	if err != nil {
		tk.LogIt(tk.LogError, "[PII] Failed to get current config: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	// Update enabled flag
	enabled := false
	if params.Attr.Enabled != nil {
		enabled = *params.Attr.Enabled
	}
	currentCfg.Enabled = enabled

	// Write back to shared memory
	if err := presidio.GlobalConfigMgr().UpdateConfig(*currentCfg); err != nil {
		tk.LogIt(tk.LogError, "[PII] Failed to update config: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[PII] ✓ PII detection %s\n", map[bool]string{true: "enabled", false: "disabled"}[enabled])
	return &ResultResponse{Result: "Success"}
}

// ConfigPostPIIConfigure - Update PII detection configuration
func ConfigPostPIIConfigure(params operations.PostConfigPiiConfigureParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: PII Configure %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	if presidio.GlobalConfigMgr() == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("PII detection not initialized")}
	}

	// Get current config
	currentCfg, err := presidio.GlobalConfigMgr().GetConfig()
	if err != nil {
		tk.LogIt(tk.LogError, "[PII] Failed to get current config: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	// Update fields from request (generated models have non-pointer strings)
	if params.Attr.Mode != "" {
		currentCfg.Mode = params.Attr.Mode
	}
	if params.Attr.Direction != "" {
		currentCfg.Direction = params.Attr.Direction
	}
	if params.Attr.FailMode != "" {
		currentCfg.FailMode = params.Attr.FailMode
	}
	if params.Attr.AnalyzerURL != "" {
		currentCfg.AnalyzerURL = params.Attr.AnalyzerURL
	}
	if params.Attr.AnonymizerURL != "" {
		currentCfg.AnonymizerURL = params.Attr.AnonymizerURL
	}
	if params.Attr.ScoreThreshold != nil {
		currentCfg.ScoreThreshold = *params.Attr.ScoreThreshold
	}
	if params.Attr.TimeoutMs != nil {
		currentCfg.TimeoutMs = uint32(*params.Attr.TimeoutMs)
	}
	if params.Attr.MaxBodySize != nil {
		currentCfg.MaxBodySize = uint32(*params.Attr.MaxBodySize)
	}
	if params.Attr.MinBodySize != nil {
		currentCfg.MinBodySize = uint32(*params.Attr.MinBodySize)
	}

	// Circuit breaker settings
	if params.Attr.CircuitBreaker != nil {
		if params.Attr.CircuitBreaker.Threshold != nil {
			currentCfg.CircuitBreaker.Threshold = uint32(*params.Attr.CircuitBreaker.Threshold)
		}
		if params.Attr.CircuitBreaker.TimeoutSec != nil {
			currentCfg.CircuitBreaker.TimeoutSec = uint32(*params.Attr.CircuitBreaker.TimeoutSec)
		}
		if params.Attr.CircuitBreaker.SuccessThreshold != nil {
			currentCfg.CircuitBreaker.SuccessThreshold = uint32(*params.Attr.CircuitBreaker.SuccessThreshold)
		}
	}

	// Retry settings
	if params.Attr.Retry != nil {
		if params.Attr.Retry.MaxRetries != nil {
			currentCfg.Retry.MaxRetries = uint32(*params.Attr.Retry.MaxRetries)
		}
		if params.Attr.Retry.BackoffMs != nil {
			currentCfg.Retry.BackoffMs = uint32(*params.Attr.Retry.BackoffMs)
		}
	}

	// Write to shared memory
	if err := presidio.GlobalConfigMgr().UpdateConfig(*currentCfg); err != nil {
		tk.LogIt(tk.LogError, "[PII] Failed to update config: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[PII] ✓ Configuration updated (mode=%s, direction=%s)\n",
		currentCfg.Mode, currentCfg.Direction)
	return &ResultResponse{Result: "Success"}
}

// ConfigPostPIIURLPatterns - Add/update URL patterns for PII scanning
func ConfigPostPIIURLPatterns(params operations.PostConfigPiiURLPatternsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: PII URL Patterns %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	if presidio.GlobalConfigMgr() == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("PII detection not initialized")}
	}

	// Get current config
	currentCfg, err := presidio.GlobalConfigMgr().GetConfig()
	if err != nil {
		tk.LogIt(tk.LogError, "[PII] Failed to get current config: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	// Parse mode (add, replace, clear)
	mode := "replace"
	if params.Attr.Mode != nil {
		mode = *params.Attr.Mode
	}

	switch mode {
	case "clear":
		currentCfg.URLPatterns = nil
	case "add":
		// Append to existing patterns
		if params.Attr.Patterns != nil {
			for _, p := range params.Attr.Patterns {
				pattern := presidio.PresidioURLPattern{
					Pattern:   *p.Pattern,
					IsExclude: p.IsExclude,
				}
				currentCfg.URLPatterns = append(currentCfg.URLPatterns, pattern)
			}
		}
	case "replace":
		// Replace all patterns
		currentCfg.URLPatterns = nil
		if params.Attr.Patterns != nil {
			for _, p := range params.Attr.Patterns {
				pattern := presidio.PresidioURLPattern{
					Pattern:   *p.Pattern,
					IsExclude: p.IsExclude,
				}
				currentCfg.URLPatterns = append(currentCfg.URLPatterns, pattern)
			}
		}
	default:
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid mode: must be 'add', 'replace', or 'clear'")}
	}

	// Validate pattern count (max 64)
	if len(currentCfg.URLPatterns) > 64 {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("too many URL patterns (max 64)")}
	}

	// Write to shared memory
	if err := presidio.GlobalConfigMgr().UpdateConfig(*currentCfg); err != nil {
		tk.LogIt(tk.LogError, "[PII] Failed to update URL patterns: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[PII] ✓ URL patterns updated (mode=%s, count=%d)\n",
		mode, len(currentCfg.URLPatterns))
	return &ResultResponse{Result: "Success"}
}

// ConfigGetPIIStatus - Get current PII detection status and configuration
func ConfigGetPIIStatus(params operations.GetConfigPiiStatusParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: PII Status %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	if presidio.GlobalConfigMgr() == nil {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("PII detection not initialized")}
	}

	// Get current config
	currentCfg, err := presidio.GlobalConfigMgr().GetConfig()
	if err != nil {
		tk.LogIt(tk.LogError, "[PII] Failed to get current config: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	// Build response model
	threshold := int64(currentCfg.CircuitBreaker.Threshold)
	timeoutSec := int64(currentCfg.CircuitBreaker.TimeoutSec)
	successThreshold := int64(currentCfg.CircuitBreaker.SuccessThreshold)
	circuitBreaker := &models.PIICircuitBreaker{
		Threshold:        &threshold,
		TimeoutSec:       &timeoutSec,
		SuccessThreshold: &successThreshold,
	}

	maxRetries := int64(currentCfg.Retry.MaxRetries)
	backoffMs := int64(currentCfg.Retry.BackoffMs)
	retry := &models.PIIRetry{
		MaxRetries: &maxRetries,
		BackoffMs:  &backoffMs,
	}

	var urlPatterns []*models.PIIURLPattern
	for _, p := range currentCfg.URLPatterns {
		pattern := p.Pattern
		urlPatterns = append(urlPatterns, &models.PIIURLPattern{
			Pattern:   &pattern,
			IsExclude: p.IsExclude,
		})
	}

	response := &models.PIIStatusResponse{
		Enabled:         currentCfg.Enabled,
		Mode:            currentCfg.Mode,
		Direction:       currentCfg.Direction,
		FailMode:        currentCfg.FailMode,
		AnalyzerURL:     currentCfg.AnalyzerURL,
		AnonymizerURL:   currentCfg.AnonymizerURL,
		ScoreThreshold:  currentCfg.ScoreThreshold,
		TimeoutMs:       int64(currentCfg.TimeoutMs),
		MaxBodySize:     int64(currentCfg.MaxBodySize),
		MinBodySize:     int64(currentCfg.MinBodySize),
		CircuitBreaker:  circuitBreaker,
		Retry:           retry,
		URLPatterns:     urlPatterns,
		URLPatternCount: int64(len(urlPatterns)),
	}

	return operations.NewGetConfigPiiStatusOK().WithPayload(response)
}

// ConfigGetPIIStats - Get PII detection statistics
func ConfigGetPIIStats(params operations.GetConfigPiiStatsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: PII Stats %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	// TODO: Implement statistics retrieval from C layer
	// For now, return placeholder values

	response := &models.PIIStatsResponse{
		TotalScans:  0,
		PiiDetected: 0,
		PiiBlocked:  0,
		Errors:      0,
	}

	return operations.NewGetConfigPiiStatsOK().WithPayload(response)
}
