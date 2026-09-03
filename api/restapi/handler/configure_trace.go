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

/*
#include <string.h>

// CRITICAL FIX: Import real trace control functions from sockproxy.c
// DO NOT use stub implementations - they manipulate separate variables!
// These extern declarations link to the actual g_trace_enabled in sockproxy.c

extern int lxb_trace_enable(void);
extern int lxb_trace_disable(void);
extern int lxb_trace_is_enabled(void);

// CGO struct for trace statistics
typedef struct {
    unsigned long long total_events;
    unsigned long long dropped_events;
    unsigned int ring_utilization[4];
} lxb_trace_stats_t;

static lxb_trace_stats_t lxb_trace_get_stats(void) {
    lxb_trace_stats_t stats;
    memset(&stats, 0, sizeof(stats));
 // consumer will provide real statistics via GetStats
    return stats;
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/restapi/operations/tracing"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
)

// OtlpConfig holds OTLP endpoint configuration
type OtlpConfig struct {
	Endpoint      string            `json:"endpoint"`                  // e.g., "localhost:4317"
	Protocol      string            `json:"protocol"`                  // "grpc" or "http"
	UseTLS        bool              `json:"use_tls"`                   // Enable TLS/HTTPS (default: true)
	TLSSkipVerify bool              `json:"tls_skip_verify,omitempty"` // Skip TLS verification (insecure, dev only)
	Connected     bool              `json:"connected"`                 // Connection status
	Headers       map[string]string `json:"headers,omitempty"`         // Optional headers (e.g., API keys)
}

// TraceStatusResponse represents the trace status response
type TraceStatusResponse struct {
	Enabled         bool    `json:"enabled"`
	TotalEvents     int64   `json:"total_events,omitempty"`
	DroppedEvents   int64   `json:"dropped_events,omitempty"`
	RingUtilization []int32 `json:"ring_utilization,omitempty"`
	OtlpEndpoint    string  `json:"otlp_endpoint,omitempty"`
	OtlpProtocol    string  `json:"otlp_protocol,omitempty"`
	OtlpConnected   bool    `json:"otlp_connected"`
	OtlpUseTLS      bool    `json:"otlp_use_tls"`
	OtlpTLSVerify   bool    `json:"otlp_tls_verify"`
}

// Global OTLP configuration (protected by mutex)
var (
	otlpConfig = OtlpConfig{
		Endpoint:      "localhost:4317",        // Default Jaeger OTLP/gRPC endpoint
		Protocol:      "grpc",                  // Default protocol
		UseTLS:        true,                    // Enable TLS by default (secure)
		TLSSkipVerify: false,                   // Verify TLS certificates by default
		Connected:     false,                   // Will be set consumer
		Headers:       make(map[string]string), // Optional auth headers
	}
	otlpMutex sync.RWMutex

	// otlpBootDefault is the configuration as of process start (compiled
	// defaults + LOXILB_OTLP_* env overrides), frozen at the end of init().
	otlpBootDefault OtlpConfig

	// otlpConfigured records whether an EXPLICIT configuration (REST POST
	// or snapshot restore) replaced the boot default. Only explicit
	// configuration is desired state: it is what the snapshot captures
	// and what a wipe clears.
	otlpConfigured bool

	// Callback function for OTLP reconnection (set by loxinet package to avoid import cycle)
	ReconnectOTLPCallback func() error

	// Callback functions for lazy initialization and state management
	InitTracingCallback     func() error // Initialize tracing subsystem if not already done
	IsTracingInitialized    func() bool  // Check if tracing subsystem is initialized
	ShutdownTracingCallback func()       // Shutdown tracing subsystem
)

// Validation regex patterns
var (
	// host:port format validation
	endpointRegex = regexp.MustCompile(`^([a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]+$`)
	// Allowed header names (alphanumeric, dash, underscore)
	headerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// init initializes OTLP configuration from environment variables
func init() {
	// Read OTLP endpoint from environment
	if endpoint := os.Getenv("LOXILB_OTLP_ENDPOINT"); endpoint != "" {
		otlpConfig.Endpoint = endpoint
		tk.LogIt(tk.LogInfo, "[OTLP_INIT] Using endpoint from env: %s\n", endpoint)
	}

	// Read OTLP protocol from environment
	if protocol := os.Getenv("LOXILB_OTLP_PROTOCOL"); protocol != "" {
		if protocol == "grpc" || protocol == "http" {
			otlpConfig.Protocol = protocol
			tk.LogIt(tk.LogInfo, "[OTLP_INIT] Using protocol from env: %s\n", protocol)
		} else {
			tk.LogIt(tk.LogWarning, "[OTLP_INIT] Invalid protocol '%s' (must be 'grpc' or 'http'), using default: %s\n",
				protocol, otlpConfig.Protocol)
		}
	}

	// Read TLS setting from environment
	if tlsEnabled := os.Getenv("LOXILB_OTLP_TLS_ENABLED"); tlsEnabled != "" {
		if tlsEnabled == "false" || tlsEnabled == "0" {
			otlpConfig.UseTLS = false
			tk.LogIt(tk.LogInfo, "[OTLP_INIT] TLS disabled via env (INSECURE)\n")
		} else if tlsEnabled == "true" || tlsEnabled == "1" {
			otlpConfig.UseTLS = true
			tk.LogIt(tk.LogInfo, "[OTLP_INIT] TLS enabled via env\n")
		}
	}

	// Read TLS skip verify from environment (optional)
	if tlsSkipVerify := os.Getenv("LOXILB_OTLP_TLS_SKIP_VERIFY"); tlsSkipVerify != "" {
		if tlsSkipVerify == "true" || tlsSkipVerify == "1" {
			otlpConfig.TLSSkipVerify = true
			tk.LogIt(tk.LogWarning, "[OTLP_INIT] TLS certificate verification disabled (INSECURE)\n")
		}
	}

	tk.LogIt(tk.LogInfo, "[OTLP_INIT] Configuration: endpoint=%s protocol=%s tls=%v verify=%v\n",
		otlpConfig.Endpoint, otlpConfig.Protocol, otlpConfig.UseTLS, !otlpConfig.TLSSkipVerify)

	// Freeze the node's boot default (compiled defaults + env overrides):
	// OtlpResetConfig (the snapshot wipe path) returns to exactly this
	// state, and OtlpExportConfig reports nil until an explicit
	// configuration replaces it -- env/boot config is node-local, not
	// desired state.
	otlpBootDefault = otlpConfig
}

// GetOtlpConfig returns the current OTLP configuration (for consumer)
func GetOtlpConfig() OtlpConfig {
	otlpMutex.RLock()
	defer otlpMutex.RUnlock()
	return otlpConfig
}

// SetOtlpConnected updates the OTLP connection status (called by consumer)
func SetOtlpConnected(connected bool) {
	otlpMutex.Lock()
	defer otlpMutex.Unlock()
	otlpConfig.Connected = connected
}

// ConfigEnableTrace enables HTTP/HTTPS protocol tracing
// POST /config/trace/enable
func ConfigEnableTrace(params tracing.PostConfigTraceEnableParams, principal interface{}) middleware.Responder {
	// CRITICAL: Enable eBPF tracing FIRST - this creates the ring buffer files
	// The ring buffers must exist before we can initialize the RingConsumer
	ret := C.lxb_trace_enable()
	if ret != 0 {
		tk.LogIt(tk.LogError, "[TRACE_ENABLE] Failed to enable eBPF tracing\n")
		return &ResultResponse{Result: "failed to enable tracing"}
	}
	tk.LogIt(tk.LogInfo, "[TRACE_ENABLE] eBPF tracing enabled, ring buffers created\n")

	// Give eBPF a moment to create the ring buffer files (they're created asynchronously)
	time.Sleep(500 * time.Millisecond)

	// Debug: Check if ring files actually exist
	currentPID := os.Getpid()
	pattern := fmt.Sprintf("/dev/shm/loxilb-trace-ring-%d-*", currentPID)
	files, err := filepath.Glob(pattern)
	if err != nil {
		tk.LogIt(tk.LogError, "[TRACE_ENABLE] Failed to glob ring files: %v\n", err)
	} else if len(files) == 0 {
		tk.LogIt(tk.LogWarning, "[TRACE_ENABLE] No ring files found yet (pattern: %s). Checking /dev/shm/...\n", pattern)
		// List all ring files in /dev/shm for debugging
		allFiles, _ := filepath.Glob("/dev/shm/loxilb-trace-ring-*")
		if len(allFiles) > 0 {
			tk.LogIt(tk.LogInfo, "[TRACE_ENABLE] Found %d ring files in /dev/shm (may be from different PID):\n", len(allFiles))
			for _, f := range allFiles {
				tk.LogIt(tk.LogInfo, "  - %s\n", f)
			}
		} else {
			tk.LogIt(tk.LogWarning, "[TRACE_ENABLE] No ring files at all in /dev/shm - eBPF may not have created them\n")
		}
	} else {
		tk.LogIt(tk.LogInfo, "[TRACE_ENABLE] Found %d ring files for PID %d\n", len(files), currentPID)
	}

	// Now lazy initialize tracing subsystem if not already done
	// This will find the ring buffer files created above
	if InitTracingCallback != nil && (IsTracingInitialized == nil || !IsTracingInitialized()) {
		tk.LogIt(tk.LogInfo, "[TRACE_ENABLE] Initializing tracing subsystem (lazy initialization)\n")
		if err := InitTracingCallback(); err != nil {
			tk.LogIt(tk.LogError, "[TRACE_ENABLE] Failed to initialize tracing: %v\n", err)
			// Try to disable eBPF tracing since initialization failed
			C.lxb_trace_disable()
			return &ResultResponse{Result: fmt.Sprintf("failed to initialize tracing: %v", err)}
		}
		tk.LogIt(tk.LogInfo, "[TRACE_ENABLE] Tracing subsystem initialized successfully\n")
	}

	tk.LogIt(tk.LogInfo, "[TRACE_ENABLE] HTTP/HTTPS tracing enabled successfully\n")
	return &ResultResponse{Result: "HTTP/HTTPS tracing enabled"}
}

// ConfigDisableTrace disables HTTP/HTTPS protocol tracing
// POST /config/trace/disable
func ConfigDisableTrace(params tracing.PostConfigTraceDisableParams, principal interface{}) middleware.Responder {
	ret := C.lxb_trace_disable()
	if ret != 0 {
		tk.LogIt(tk.LogError, "[TRACE_DISABLE] Failed to disable eBPF tracing\n")
		return &ResultResponse{Result: "failed to disable tracing"}
	}

	tk.LogIt(tk.LogInfo, "[TRACE_DISABLE] HTTP/HTTPS tracing disabled successfully\n")
	return &ResultResponse{Result: "HTTP/HTTPS tracing disabled"}
}

// ConfigGetTraceStatus returns current tracing status and statistics
// GET /config/trace/status
func ConfigGetTraceStatus(params tracing.GetConfigTraceStatusParams, principal interface{}) middleware.Responder {
	enabled := C.lxb_trace_is_enabled()

	response := TraceStatusResponse{
		Enabled: enabled != 0,
	}

	// If tracing is enabled, get statistics
	if enabled != 0 {
		stats := C.lxb_trace_get_stats()
		response.TotalEvents = int64(stats.total_events)
		response.DroppedEvents = int64(stats.dropped_events)

		// Convert ring utilization array
		response.RingUtilization = make([]int32, 4)
		for i := 0; i < 4; i++ {
			response.RingUtilization[i] = int32(stats.ring_utilization[i])
		}
	}

	// Add OTLP configuration info
	otlpMutex.RLock()
	response.OtlpEndpoint = otlpConfig.Endpoint
	response.OtlpProtocol = otlpConfig.Protocol
	// Note: Connected status is updated by OTLP exporter after first successful export
	// or when connection fails. Default is false until proven connected.
	// If tracing is enabled but not initialized, connection will be false.
	response.OtlpConnected = otlpConfig.Connected
	response.OtlpUseTLS = otlpConfig.UseTLS
	response.OtlpTLSVerify = !otlpConfig.TLSSkipVerify

	// Add warning if enabled but not connected
	if enabled != 0 && !otlpConfig.Connected {
		if IsTracingInitialized == nil || !IsTracingInitialized() {
			tk.LogIt(tk.LogDebug, "[TRACE_STATUS] Tracing enabled but subsystem not initialized (use 'loxicmd set trace enable' to initialize)\n")
		} else {
			tk.LogIt(tk.LogDebug, "[TRACE_STATUS] Tracing enabled but OTLP not connected yet (check endpoint: %s)\n", otlpConfig.Endpoint)
		}
	}
	otlpMutex.RUnlock()

	// Return custom response
	return CustomResponder(func(rw http.ResponseWriter, producer runtime.Producer) {
		rw.WriteHeader(200)
		producer.Produce(rw, response)
	})
}

// validateEndpoint validates OTLP endpoint format and performs security checks
func validateEndpoint(endpoint string) error {
	// Check for empty endpoint
	if endpoint == "" {
		return fmt.Errorf("endpoint cannot be empty")
	}

	// Validate host:port format
	if !endpointRegex.MatchString(endpoint) {
		return fmt.Errorf("invalid endpoint format: must be 'host:port' (e.g., 'localhost:4317')")
	}

	// Split host and port
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %v", err)
	}

	// Validate port range (1-65535)
	if port == "" || port == "0" {
		return fmt.Errorf("invalid port: must be between 1 and 65535")
	}

	// Security: Prevent localhost injection attacks
	if strings.Contains(host, "..") || strings.Contains(host, "//") {
		return fmt.Errorf("invalid host: contains suspicious characters")
	}

	// Validate host is not empty
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	// Try to resolve hostname (non-blocking check)
	// This validates DNS names and catches obvious typos
	if net.ParseIP(host) == nil {
		// Not an IP address, validate as hostname
		if len(host) > 253 {
			return fmt.Errorf("hostname too long (max 253 characters)")
		}
		// Basic hostname validation (alphanumeric, dots, dashes)
		for _, ch := range host {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
				return fmt.Errorf("invalid hostname: contains invalid character '%c'", ch)
			}
		}
	}

	return nil
}

// validateHeaders validates OTLP headers for security
func validateHeaders(headers map[string]string) error {
	if len(headers) > 20 {
		return fmt.Errorf("too many headers: maximum 20 allowed")
	}

	for name, value := range headers {
		// Validate header name
		if !headerNameRegex.MatchString(name) {
			return fmt.Errorf("invalid header name '%s': must contain only alphanumeric, dash, or underscore", name)
		}

		// Prevent header injection attacks
		if strings.Contains(value, "\r") || strings.Contains(value, "\n") {
			return fmt.Errorf("invalid header value for '%s': contains newline", name)
		}

		// Limit header value length
		if len(value) > 1024 {
			return fmt.Errorf("header value too long for '%s': maximum 1024 characters", name)
		}
	}

	return nil
}

// ConfigSetOtlpEndpoint configures OTLP endpoint for trace export
// POST /config/trace/otlp
func ConfigSetOtlpEndpoint(params tracing.PostConfigTraceOtlpParams, principal interface{}) middleware.Responder {
	// Dereference and validate protocol
	if params.Attr.Protocol == nil || params.Attr.Endpoint == nil {
		return &ResultResponse{Result: "protocol and endpoint are required"}
	}

	protocol := *params.Attr.Protocol
	if protocol != "grpc" && protocol != "http" {
		return &ResultResponse{Result: "invalid protocol: must be 'grpc' or 'http'"}
	}

	// Validate endpoint format with security checks
	endpoint := *params.Attr.Endpoint
	if err := validateEndpoint(endpoint); err != nil {
		tk.LogIt(tk.LogWarning, "[OTLP_CONFIG] Endpoint validation failed: %v (from %s)\n",
			err, params.HTTPRequest.RemoteAddr)
		return &ResultResponse{Result: fmt.Sprintf("invalid endpoint: %v", err)}
	}

	// Get optional TLS settings (default: secure)
	useTLS := true
	tlsSkipVerify := false
	if params.Attr.UseTLS != nil {
		useTLS = *params.Attr.UseTLS
	}
	if params.Attr.TLSSkipVerify != nil {
		tlsSkipVerify = *params.Attr.TLSSkipVerify
	}

	// Security: Warn if TLS is disabled or verification is skipped
	if !useTLS {
		tk.LogIt(tk.LogWarning, "[OTLP_CONFIG] TLS disabled for %s - trace data will be sent in plaintext (INSECURE)\n", endpoint)
	}
	if tlsSkipVerify {
		tk.LogIt(tk.LogWarning, "[OTLP_CONFIG] TLS verification skipped for %s - vulnerable to MITM attacks (INSECURE)\n", endpoint)
	}

	// Validate optional headers (e.g., API keys)
	headers := make(map[string]string)
	if params.Attr.Headers != nil {
		headers = params.Attr.Headers
		if err := validateHeaders(headers); err != nil {
			tk.LogIt(tk.LogWarning, "[OTLP_CONFIG] Header validation failed: %v\n", err)
			return &ResultResponse{Result: fmt.Sprintf("invalid headers: %v", err)}
		}
	}

	// Update configuration
	otlpMutex.Lock()
	otlpConfig.Endpoint = endpoint
	otlpConfig.Protocol = protocol
	otlpConfig.UseTLS = useTLS
	otlpConfig.TLSSkipVerify = tlsSkipVerify
	otlpConfig.Headers = headers
	otlpConfig.Connected = false // Reset connection status on config change
	otlpConfigured = true        // explicit configuration = desired state (persisted)
	otlpMutex.Unlock()

	// Persist the header VALUES node-locally (0600, next to the snapshot)
	// so they survive a restart: the snapshot document itself carries only
	// the header names (secret split). A persist failure is surfaced, not
	// swallowed -- otherwise the operator only finds out at the reboot
	// that lost the credentials.
	if err := writeOtlpHeaderSecrets(headers); err != nil {
		tk.LogIt(tk.LogError, "[OTLP_CONFIG] header secret persist failed: %v\n", err)
		return &ResultResponse{Result: fmt.Sprintf("OTLP endpoint configured, but header secrets could not be persisted (will not survive restart): %v", err)}
	}

	// Audit log with correct TLS settings
	if useTLS {
		tk.LogIt(tk.LogInfo, "[OTLP_CONFIG] Endpoint configured: %s (%s, TLS=true, verify=%v) by %s\n",
			endpoint, protocol, !tlsSkipVerify, params.HTTPRequest.RemoteAddr)
	} else {
		tk.LogIt(tk.LogInfo, "[OTLP_CONFIG] Endpoint configured: %s (%s, TLS=false) by %s\n",
			endpoint, protocol, params.HTTPRequest.RemoteAddr)
	}

	// Reconnect OTLP exporter with new endpoint (supports both L4 and L7 tracing)
	if ReconnectOTLPCallback != nil {
		if err := ReconnectOTLPCallback(); err != nil {
			tk.LogIt(tk.LogError, "[OTLP_CONFIG] Failed to reconnect OTLP exporter: %v\n", err)
			return &ResultResponse{Result: fmt.Sprintf("OTLP endpoint configured, but reconnection failed: %v", err)}
		}
		tk.LogIt(tk.LogInfo, "[OTLP_CONFIG] OTLP exporter reconnected successfully\n")
	} else {
		tk.LogIt(tk.LogWarning, "[OTLP_CONFIG] OTLP reconnection callback not set (tracing may not be initialized yet)\n")
	}

	return &ResultResponse{Result: "OTLP endpoint configured successfully"}
}

// ConfigGetOtlpEndpoint returns current OTLP endpoint configuration
// GET /config/trace/otlp
func ConfigGetOtlpEndpoint(params tracing.GetConfigTraceOtlpParams, principal interface{}) middleware.Responder {
	otlpMutex.RLock()
	config := otlpConfig
	otlpMutex.RUnlock()

	// Security: Redact sensitive header values before returning
	redactedConfig := config
	if len(config.Headers) > 0 {
		redactedConfig.Headers = make(map[string]string)
		for name := range config.Headers {
			redactedConfig.Headers[name] = "***REDACTED***"
		}
	}

	// Return custom response
	return CustomResponder(func(rw http.ResponseWriter, producer runtime.Producer) {
		rw.WriteHeader(200)
		producer.Produce(rw, redactedConfig)
	})
}

// ---------------------------------------------------------------------
// Config-persistence surface (the snapshot "tracing" domain, reached via
// the NetTracingGet/Set/Reset hooks in pkg/loxinet).
//
// Secret split: the snapshot document carries the OTLP product config and
// the auth header NAMES only. The header VALUES are written to a
// node-local 0600 file under the gateway config directory
// (otlp-headers.json) on every successful explicit configuration, and
// re-joined by name on restore. A document restored onto a node that
// lacks a value for a named header applies the rest of the config and
// WARNS loudly -- credentials must be re-provisioned there, never
// silently invented or dropped without a trace.
// ---------------------------------------------------------------------

// otlpHeaderSecretFile is the node-local header-value store, relative to
// the gateway config directory (opts.Opts.ConfigPath).
const otlpHeaderSecretFile = "otlp-headers.json"

func otlpHeaderSecretPath() string {
	return filepath.Join(opts.Opts.ConfigPath, otlpHeaderSecretFile)
}

// writeOtlpHeaderSecrets persists the header name->value map node-locally
// (0600, temp-file-then-rename). An empty map removes the file.
func writeOtlpHeaderSecrets(headers map[string]string) error {
	path := otlpHeaderSecretPath()
	if len(headers) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(headers)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readOtlpHeaderSecrets loads the node-local header value store; a
// missing file is an empty map, not an error.
func readOtlpHeaderSecrets() (map[string]string, error) {
	data, err := os.ReadFile(otlpHeaderSecretPath())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	out := map[string]string{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("otlp header secret store corrupt: %w", err)
	}
	return out, nil
}

// OtlpExportConfig returns the explicit OTLP desired configuration for
// snapshot capture (header names only, sorted), or nil while only the
// boot default is in effect -- boot/env config is node-local, not desired
// state.
func OtlpExportConfig() *cmn.TracingConfig {
	otlpMutex.RLock()
	defer otlpMutex.RUnlock()
	if !otlpConfigured {
		return nil
	}
	out := &cmn.TracingConfig{
		Endpoint:      otlpConfig.Endpoint,
		Protocol:      otlpConfig.Protocol,
		UseTLS:        otlpConfig.UseTLS,
		TLSSkipVerify: otlpConfig.TLSSkipVerify,
	}
	for name := range otlpConfig.Headers {
		out.HeaderNames = append(out.HeaderNames, name)
	}
	sort.Strings(out.HeaderNames)
	return out
}

// OtlpApplyConfig applies a restored OTLP configuration (overwrite/Set
// semantics), re-joining header values from the node-local secret store.
// Validation mirrors the REST intake -- a hand-edited document's bad
// endpoint or header name fails loudly here. The exporter reconnect is
// ATTEMPTED but its failure does not fail the apply: the collector is an
// external dependency, and a boot replay must not be held hostage by a
// telemetry backend that is still starting (the exporter machinery
// retries on its own).
func OtlpApplyConfig(cfg *cmn.TracingConfig) error {
	if cfg == nil {
		return fmt.Errorf("tracing: nil config (use reset for the boot default)")
	}
	if cfg.Protocol != "grpc" && cfg.Protocol != "http" {
		return fmt.Errorf("tracing: invalid protocol %q (must be 'grpc' or 'http')", cfg.Protocol)
	}
	if err := validateEndpoint(cfg.Endpoint); err != nil {
		return fmt.Errorf("tracing: invalid endpoint: %w", err)
	}
	for _, name := range cfg.HeaderNames {
		if !headerNameRegex.MatchString(name) {
			return fmt.Errorf("tracing: invalid header name %q", name)
		}
	}

	stored, err := readOtlpHeaderSecrets()
	if err != nil {
		return fmt.Errorf("tracing: %w", err)
	}
	headers := make(map[string]string, len(cfg.HeaderNames))
	var missing []string
	for _, name := range cfg.HeaderNames {
		if v, ok := stored[name]; ok {
			headers[name] = v
		} else {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		tk.LogIt(tk.LogWarning, "[OTLP_CONFIG] restore: no node-local secret for header(s) %v -- re-provision them via POST /config/trace/otlp on this node\n", missing)
	}

	otlpMutex.Lock()
	otlpConfig.Endpoint = cfg.Endpoint
	otlpConfig.Protocol = cfg.Protocol
	otlpConfig.UseTLS = cfg.UseTLS
	otlpConfig.TLSSkipVerify = cfg.TLSSkipVerify
	otlpConfig.Headers = headers
	otlpConfig.Connected = false
	otlpConfigured = true
	otlpMutex.Unlock()

	if ReconnectOTLPCallback != nil {
		if err := ReconnectOTLPCallback(); err != nil {
			tk.LogIt(tk.LogWarning, "[OTLP_CONFIG] restore: exporter reconnect failed (will retry): %v\n", err)
		}
	}
	return nil
}

// OtlpResetConfig returns the OTLP configuration to the node's boot
// default (compiled defaults + env overrides, frozen at init). The
// node-local header secret file is deliberately kept: it is node
// material (like certificate keys on disk), and the apply that follows a
// snapshot wipe must still be able to re-join values by name.
func OtlpResetConfig() {
	otlpMutex.Lock()
	otlpConfig = otlpBootDefault
	otlpConfig.Headers = make(map[string]string)
	otlpConfig.Connected = false
	otlpConfigured = false
	otlpMutex.Unlock()
}
