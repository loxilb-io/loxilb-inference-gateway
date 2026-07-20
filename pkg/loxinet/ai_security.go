/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * AI Security: Go Bridge Layer (CGO Exports)
 *
 * This file provides CGO exports that bridge C layer (sockproxy_llamafirewall.c)
 * with Go layer (gRPC client to LlamaFirewall service). Follows Presidio pattern.
 *
 * Features:
 * - Prompt injection detection (PromptGuard)
 * - Insecure code detection (CodeShield)
 * - Credential leak detection (Regex)
 * - Hidden character attacks (HiddenASCII)
 * - Agent alignment checking (AgentAlignment)
 * - PII detection (complementary to Presidio)
 */

package loxinet

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Security scan result structure (matches C layer)
typedef struct {
    uint8_t decision;        // 0=unspecified, 1=allow, 2=block, 3=hitl
    char *reason;            // Explanation string (caller must free)
    float score;             // Confidence score (0.0-1.0)
    uint8_t status;          // 0=unspecified, 1=success, 2=error, 3=partial
    int scanner_count;       // Number of scanner results
    char error_msg[256];     // Error description
} security_scan_result_t;

// Individual scanner result
typedef struct {
    uint8_t scanner_type;    // Scanner enum value
    uint8_t decision;        // Scanner-specific decision
    char *reason;            // Scanner explanation (caller must free)
    float score;             // Scanner confidence score
    int64_t latency_ms;      // Scanner execution time
} scanner_result_t;
*/
import "C"

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	pb "github.com/loxilb-io/loxilb/pkg/loxinet/llamafirewall_pb"
	tk "github.com/loxilb-io/loxilib"
)

// LlamaFirewallClient manages connection to LlamaFirewall gRPC service
type LlamaFirewallClient struct {
	conn          *grpc.ClientConn
	client        pb.SecurityScannerClient
	addr          string
	connected     bool
	lastConnError time.Time
	timeout       time.Duration
}

var globalLlamaFirewallClient *LlamaFirewallClient

// LlamaFirewallConfig holds configuration for LlamaFirewall integration
type LlamaFirewallConfig struct {
	Enabled            bool
	ServerURL          string
	TimeoutSec         int
	FailClosed         bool
	BlockThreshold     float32
	CacheEnabled       bool
	CacheTTLSec        int
	ConnectionPoolSize int
	ScanPatterns       []string
	SkipPatterns       []string
	Scanners           LlamaFirewallScanners
}

// LlamaFirewallScanners holds individual scanner enable flags
type LlamaFirewallScanners struct {
	PromptGuard    bool
	CodeShield     bool
	Regex          bool
	HiddenASCII    bool
	AgentAlignment bool
	PIIDetection   bool
}

// LlamaFirewallStatus holds runtime status information
type LlamaFirewallStatus struct {
	Connected       bool
	LastHealthCheck *time.Time
}

// LlamaFirewallStats holds scanning statistics
type LlamaFirewallStats struct {
	TotalScans       int64
	RequestsScanned  int64
	ResponsesScanned int64
	ThreatsDetected  int64
	RequestsBlocked  int64
	ScanErrors       int64
	AvgLatencyMs     int64
	CacheHits        int64
	ScannerStats     LlamaFirewallScannerStatsDetail
	Decisions        LlamaFirewallDecisionStatsDetail
}

// LlamaFirewallScannerStatsDetail holds per-scanner statistics
type LlamaFirewallScannerStatsDetail struct {
	PromptGuard    LlamaFirewallIndividualScannerStat
	CodeShield     LlamaFirewallIndividualScannerStat
	Regex          LlamaFirewallIndividualScannerStat
	HiddenASCII    LlamaFirewallIndividualScannerStat
	AgentAlignment LlamaFirewallIndividualScannerStat
	PIIDetection   LlamaFirewallIndividualScannerStat
}

// LlamaFirewallIndividualScannerStat holds statistics for a single scanner
type LlamaFirewallIndividualScannerStat struct {
	Scans        int64
	Detections   int64
	AvgLatencyMs int64
	Errors       int64
}

// LlamaFirewallDecisionStatsDetail holds decision statistics
type LlamaFirewallDecisionStatsDetail struct {
	Allow int64
	Block int64
	HITL  int64
}

// LlamaFirewallHealthResult holds health check results
type LlamaFirewallHealthResult struct {
	Healthy   bool
	ServerURL string
	Connected bool
	LatencyMs int64
	Message   string
	Timestamp time.Time
}

// Global configuration
var globalLlamaFirewallConfig = &LlamaFirewallConfig{
	Enabled:            false,
	ServerURL:          "localhost:50052",
	TimeoutSec:         15,
	FailClosed:         false,
	BlockThreshold:     0.9,
	CacheEnabled:       true,
	CacheTTLSec:        300,
	ConnectionPoolSize: 10,
	ScanPatterns:       []string{},
	SkipPatterns:       []string{"/health", "/metrics"},
	Scanners: LlamaFirewallScanners{
		PromptGuard:    true,
		CodeShield:     true,
		Regex:          true,
		HiddenASCII:    true,
		AgentAlignment: false,
		PIIDetection:   false,
	},
}

// Global statistics (in-memory for now, can be moved to shared memory if needed)
var globalLlamaFirewallStats = &LlamaFirewallStats{}

// InitLlamaFirewallClient initializes gRPC connection to LlamaFirewall service
func InitLlamaFirewallClient(addr string) error {
	if globalLlamaFirewallClient != nil && globalLlamaFirewallClient.connected {
		return nil // Already initialized
	}

	globalLlamaFirewallClient = &LlamaFirewallClient{
		addr:      addr,
		connected: false,
		timeout:   15 * time.Second, // Longer timeout for ML models (PromptGuard)
	}

	return globalLlamaFirewallClient.connect()
}

// connect establishes gRPC connection to LlamaFirewall
func (lfc *LlamaFirewallClient) connect() error {
	if lfc.addr == "" {
		lfc.addr = "localhost:50052" // Default (avoid Presidio port 50051)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Production-ready dial options (similar to Presidio)
	conn, err := grpc.DialContext(ctx, lfc.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second, // Send keepalive every 30s
			Timeout:             10 * time.Second, // Wait 10s for keepalive ack
			PermitWithoutStream: false,            // Only send keepalive during active RPCs
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(50*1024*1024), // 50MB max response (larger for conversation traces)
			grpc.MaxCallSendMsgSize(50*1024*1024), // 50MB max request
		),
	)
	if err != nil {
		lfc.lastConnError = time.Now()
		tk.LogIt(tk.LogError, "[LlamaFirewall] Failed to connect to %s: %v\n", lfc.addr, err)
		return fmt.Errorf("failed to connect to LlamaFirewall: %w", err)
	}

	lfc.client = pb.NewSecurityScannerClient(conn)
	lfc.conn = conn
	lfc.connected = true
	tk.LogIt(tk.LogInfo, "[LlamaFirewall] ✓ Connected to: %s (keepalive=30s)\n", lfc.addr)
	return nil
}

// reconnectIfNeeded attempts to reconnect if connection is lost
func (lfc *LlamaFirewallClient) reconnectIfNeeded() error {
	if lfc.connected {
		return nil
	}

	// Rate limit reconnection attempts (1 per 10 seconds)
	if time.Since(lfc.lastConnError) < 10*time.Second {
		return fmt.Errorf("reconnection rate limited")
	}

	return lfc.connect()
}

// Close closes gRPC connection
func (lfc *LlamaFirewallClient) Close() error {
	lfc.connected = false
	if lfc.conn != nil {
		return lfc.conn.Close()
	}
	return nil
}

// IsHealthy checks if connection is healthy
func (lfc *LlamaFirewallClient) IsHealthy() bool {
	return lfc.connected && lfc.conn != nil
}

// ForceReconnect closes existing connection and reconnects
func (lfc *LlamaFirewallClient) ForceReconnect() error {
	if lfc.conn != nil {
		lfc.conn.Close()
	}
	lfc.connected = false
	return lfc.connect()
}

// parseScannerTypes parses comma-separated scanner names to proto enum
func parseScannerTypes(scanners string) []pb.ScannerType {
	if scanners == "" {
		// Default: PromptGuard + Regex (fast, high value)
		return []pb.ScannerType{
			pb.ScannerType_SCANNER_PROMPT_GUARD,
			pb.ScannerType_SCANNER_REGEX,
		}
	}

	parts := strings.Split(scanners, ",")
	result := make([]pb.ScannerType, 0, len(parts))

	for _, part := range parts {
		scanner := strings.TrimSpace(strings.ToLower(part))
		switch scanner {
		case "prompt_guard", "promptguard":
			result = append(result, pb.ScannerType_SCANNER_PROMPT_GUARD)
		case "code_shield", "codeshield":
			result = append(result, pb.ScannerType_SCANNER_CODE_SHIELD)
		case "regex":
			result = append(result, pb.ScannerType_SCANNER_REGEX)
		case "hidden_ascii", "hiddenascii":
			result = append(result, pb.ScannerType_SCANNER_HIDDEN_ASCII)
		case "agent_alignment", "agentalignment":
			result = append(result, pb.ScannerType_SCANNER_AGENT_ALIGNMENT)
		case "pii_detection", "piidetection", "pii":
			result = append(result, pb.ScannerType_SCANNER_PII_DETECTION)
		}
	}

	if len(result) == 0 {
		// Fallback to default
		result = []pb.ScannerType{
			pb.ScannerType_SCANNER_PROMPT_GUARD,
			pb.ScannerType_SCANNER_REGEX,
		}
	}

	return result
}

// ============================================================================
// CGO EXPORTS FOR C LAYER (llb_llamafirewall_* functions)
// These match the extern declarations in sockproxy_llamafirewall.h
// ============================================================================

// llb_llamafirewall_init - Initialize LlamaFirewall client connection
//
//export llb_llamafirewall_init
func llb_llamafirewall_init(serverURL *C.char) C.int {
	addr := C.GoString(serverURL)
	if addr == "" {
		addr = "localhost:50052"
	}

	if err := InitLlamaFirewallClient(addr); err != nil {
		tk.LogIt(tk.LogError, "[LlamaFirewall] Init failed: %v\n", err)
		return -1
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall] Initialized with server: %s\n", addr)
	return 0
}

// llb_llamafirewall_update_config - Update gRPC client when config changes
// Called when server_url changes via API (weak symbol from C layer)
//
//export llb_llamafirewall_update_config
func llb_llamafirewall_update_config(serverURL *C.char) C.int {
	if globalLlamaFirewallClient == nil {
		// Not initialized yet, just initialize
		return llb_llamafirewall_init(serverURL)
	}

	newAddr := C.GoString(serverURL)

	// Check if URL actually changed
	if globalLlamaFirewallClient.addr == newAddr {
		tk.LogIt(tk.LogDebug, "[LlamaFirewall] URL unchanged, keeping connection\n")
		return 0 // No change needed
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall] 🔄 Server URL changed: %s → %s\n",
		globalLlamaFirewallClient.addr, newAddr)

	// Close old connection
	if err := globalLlamaFirewallClient.Close(); err != nil {
		tk.LogIt(tk.LogWarning, "[LlamaFirewall] Error closing old connection: %v\n", err)
	}

	// Initialize with new URL
	if err := InitLlamaFirewallClient(newAddr); err != nil {
		tk.LogIt(tk.LogError, "[LlamaFirewall] Failed to reconnect with new URL: %v\n", err)
		return -1
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall] ✓ Successfully reconnected to new URL: %s\n", newAddr)
	return 0
}

// llb_llamafirewall_scan - Scan content for security threats
//
//export llb_llamafirewall_scan
func llb_llamafirewall_scan(
	content *C.char,
	role C.int,
	scanners *C.char,
	result *C.security_scan_result_t,
) C.int {
	if globalLlamaFirewallClient == nil {
		result.decision = 1 // DECISION_ALLOW (fail-open by default)
		result.status = 2   // STATUS_ERROR
		C.strcpy((*C.char)(unsafe.Pointer(&result.error_msg[0])), C.CString("LlamaFirewall client not initialized"))
		return -1
	}

	// Attempt reconnection if needed
	if err := globalLlamaFirewallClient.reconnectIfNeeded(); err != nil {
		result.decision = 1 // DECISION_ALLOW (fail-open)
		result.status = 2   // STATUS_ERROR
		C.strcpy((*C.char)(unsafe.Pointer(&result.error_msg[0])), C.CString(fmt.Sprintf("Connection error: %v", err)))
		return -1
	}

	// Parse parameters
	contentStr := C.GoString(content)
	scannersStr := C.GoString(scanners)
	scannerTypes := parseScannerTypes(scannersStr)

	// Map C role to proto enum
	var protoRole pb.Role
	switch role {
	case 1:
		protoRole = pb.Role_ROLE_USER
	case 2:
		protoRole = pb.Role_ROLE_ASSISTANT
	case 3:
		protoRole = pb.Role_ROLE_SYSTEM
	case 4:
		protoRole = pb.Role_ROLE_TOOL
	case 5:
		protoRole = pb.Role_ROLE_MEMORY
	default:
		protoRole = pb.Role_ROLE_USER
	}

	// Create scan request
	req := &pb.ScanRequest{
		Message: &pb.Message{
			Role:    protoRole,
			Content: contentStr,
		},
		Scanners: scannerTypes,
	}

	// Execute scan with timeout
	ctx, cancel := context.WithTimeout(context.Background(), globalLlamaFirewallClient.timeout)
	defer cancel()

	startTime := time.Now()
	resp, err := globalLlamaFirewallClient.client.Scan(ctx, req)
	latency := time.Since(startTime).Milliseconds()

	if err != nil {
		result.decision = 1 // DECISION_ALLOW (fail-open)
		result.status = 2   // STATUS_ERROR
		result.score = 0.0
		errMsg := fmt.Sprintf("Scan failed: %v", err)
		C.strcpy((*C.char)(unsafe.Pointer(&result.error_msg[0])), C.CString(errMsg))
		tk.LogIt(tk.LogError, "[LlamaFirewall] %s (latency=%dms)\n", errMsg, latency)
		return -1
	}

	// Populate result
	result.decision = C.uint8_t(resp.Decision)
	result.score = C.float(resp.Score)
	result.status = C.uint8_t(resp.Status)
	result.scanner_count = C.int(len(resp.ScannerResults))

	// Allocate reason string (caller must free)
	if resp.Reason != "" {
		result.reason = C.CString(resp.Reason)
	} else {
		result.reason = nil
	}

	// Log result
	decisionStr := "ALLOW"
	if resp.Decision == pb.ScanDecision_DECISION_BLOCK {
		decisionStr = "BLOCK"
	} else if resp.Decision == pb.ScanDecision_DECISION_HUMAN_IN_THE_LOOP {
		decisionStr = "HITL"
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall] Scan result: %s (score=%.2f, latency=%dms, scanners=%d)\n",
		decisionStr, resp.Score, latency, len(resp.ScannerResults))

	if resp.Decision == pb.ScanDecision_DECISION_BLOCK {
		tk.LogIt(tk.LogWarning, "[LlamaFirewall] Request blocked: %s\n", resp.Reason)
	}

	return 0
}

// llb_llamafirewall_health_check - Check server health
//
//export llb_llamafirewall_health_check
func llb_llamafirewall_health_check() C.int {
	if globalLlamaFirewallClient == nil {
		tk.LogIt(tk.LogError, "[LlamaFirewall] Health check failed: client not initialized\n")
		return -1
	}

	if err := globalLlamaFirewallClient.reconnectIfNeeded(); err != nil {
		tk.LogIt(tk.LogError, "[LlamaFirewall] Health check failed: %v\n", err)
		return -1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.HealthCheckRequest{}
	resp, err := globalLlamaFirewallClient.client.HealthCheck(ctx, req)
	if err != nil {
		tk.LogIt(tk.LogError, "[LlamaFirewall] Health check RPC failed: %v\n", err)
		return -1
	}

	if resp.Status != pb.HealthCheckResponse_SERVING {
		tk.LogIt(tk.LogError, "[LlamaFirewall] Server not healthy: %s\n", resp.Message)
		return -1
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall] ✓ Health check passed\n")
	return 0
}

// llb_llamafirewall_free_result - Free scan result memory
//
//export llb_llamafirewall_free_result
func llb_llamafirewall_free_result(result *C.security_scan_result_t) {
	if result.reason != nil {
		C.free(unsafe.Pointer(result.reason))
		result.reason = nil
	}
}

// llb_llamafirewall_close - Close client connection
//
//export llb_llamafirewall_close
func llb_llamafirewall_close() C.int {
	if globalLlamaFirewallClient != nil {
		if err := globalLlamaFirewallClient.Close(); err != nil {
			tk.LogIt(tk.LogError, "[LlamaFirewall] Close failed: %v\n", err)
			return -1
		}
		globalLlamaFirewallClient = nil
		tk.LogIt(tk.LogInfo, "[LlamaFirewall] Connection closed\n")
	}
	return 0
}

// ============================================================================
// PUBLIC API FUNCTIONS FOR REST HANDLERS
// ============================================================================

// GetLlamaFirewallConfig returns current configuration
func GetLlamaFirewallConfig() *LlamaFirewallConfig {
	return globalLlamaFirewallConfig
}

// SetLlamaFirewallConfig updates configuration and reinitializes if needed
func SetLlamaFirewallConfig(config *LlamaFirewallConfig) error {
	globalLlamaFirewallConfig = config

	// If server URL changed, reinitialize connection
	if globalLlamaFirewallClient != nil && globalLlamaFirewallClient.addr != config.ServerURL {
		if err := globalLlamaFirewallClient.Close(); err != nil {
			tk.LogIt(tk.LogWarning, "[LlamaFirewall] Failed to close old connection: %v\n", err)
		}
		globalLlamaFirewallClient = nil
	}

	// Initialize if enabled and not already initialized
	if config.Enabled && globalLlamaFirewallClient == nil {
		if err := InitLlamaFirewallClient(config.ServerURL); err != nil {
			return err
		}
	}

	return nil
}

// GetLlamaFirewallStatus returns current runtime status
func GetLlamaFirewallStatus() *LlamaFirewallStatus {
	status := &LlamaFirewallStatus{
		Connected: false,
	}

	if globalLlamaFirewallClient != nil {
		status.Connected = globalLlamaFirewallClient.connected
		now := time.Now()
		status.LastHealthCheck = &now
	}

	return status
}

// GetLlamaFirewallStats returns current statistics
func GetLlamaFirewallStats() *LlamaFirewallStats {
	// Return copy of global stats
	// In production, this would be read from shared memory or aggregated from eBPF maps
	return globalLlamaFirewallStats
}

// LlamaFirewallHealthCheck triggers health check and returns result
func LlamaFirewallHealthCheck() *LlamaFirewallHealthResult {
	result := &LlamaFirewallHealthResult{
		Healthy:   false,
		ServerURL: globalLlamaFirewallConfig.ServerURL,
		Connected: false,
		Timestamp: time.Now(),
	}

	if globalLlamaFirewallClient == nil {
		result.Message = "LlamaFirewall client not initialized"
		return result
	}

	// Reconnect if needed
	if err := globalLlamaFirewallClient.reconnectIfNeeded(); err != nil {
		result.Message = fmt.Sprintf("Connection failed: %v", err)
		return result
	}

	// Perform health check
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.HealthCheckRequest{}
	resp, err := globalLlamaFirewallClient.client.HealthCheck(ctx, req)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		result.Message = fmt.Sprintf("Health check RPC failed: %v", err)
		result.LatencyMs = latency
		return result
	}

	result.Connected = true
	result.LatencyMs = latency

	if resp.Status == pb.HealthCheckResponse_SERVING {
		result.Healthy = true
		result.Message = "LlamaFirewall server is healthy"
	} else {
		result.Message = resp.Message
	}

	return result
}
