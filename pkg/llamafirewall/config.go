//go:build llamafirewall
// +build llamafirewall

/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * LlamaFirewall Configuration: Shared Memory Writer (Go Layer)
 * Following Presidio pattern for C-Go coordination with file-backed /dev/shm
 */

package llamafirewall

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "llamafirewall_config.h"
*/
import "C"

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	tk "github.com/loxilb-io/loxilib"
)

const (
	llamafirewallSharedMemPath = "/dev/shm/loxilb_llamafirewall_config"
	llamafirewallConfigSize    = C.sizeof_llamafirewall_config_shm_t
)

// LlamaFirewallConfigManager manages shared memory for LlamaFirewall configuration
type LlamaFirewallConfigManager struct {
	sharedMem []byte
	config    *C.llamafirewall_config_shm_t
}

var globalLlamaFirewallConfigMgr *LlamaFirewallConfigManager

// GlobalConfigMgr returns the global LlamaFirewall configuration manager
func GlobalConfigMgr() *LlamaFirewallConfigManager {
	return globalLlamaFirewallConfigMgr
}

// NewLlamaFirewallConfigManager creates shared memory manager
func NewLlamaFirewallConfigManager() (*LlamaFirewallConfigManager, error) {
	lfcm := &LlamaFirewallConfigManager{}

	if err := lfcm.initSharedMemory(); err != nil {
		return nil, err
	}

	// Initialize with default configuration
	if err := lfcm.writeDefaultConfig(); err != nil {
		tk.LogIt(tk.LogWarning, "[LlamaFirewall-Config] Failed to write defaults: %v\n", err)
	}

	globalLlamaFirewallConfigMgr = lfcm
	return lfcm, nil
}

// initSharedMemory creates and maps shared memory
func (lfcm *LlamaFirewallConfigManager) initSharedMemory() error {
	// Open/create shared memory file
	file, err := os.OpenFile(llamafirewallSharedMemPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open shared memory file: %w", err)
	}
	defer file.Close()

	// Truncate to required size
	if err := file.Truncate(int64(llamafirewallConfigSize)); err != nil {
		return fmt.Errorf("failed to truncate shared memory: %w", err)
	}

	// Memory-map the file
	sharedMem, err := unix.Mmap(
		int(file.Fd()),
		0,
		int(llamafirewallConfigSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
	)
	if err != nil {
		return fmt.Errorf("failed to mmap shared memory: %w", err)
	}

	lfcm.sharedMem = sharedMem
	lfcm.config = (*C.llamafirewall_config_shm_t)(unsafe.Pointer(&sharedMem[0]))

	tk.LogIt(tk.LogInfo, "[LlamaFirewall-Config] ✓ Initialized shared memory: path=%s size=%d bytes\n",
		llamafirewallSharedMemPath, llamafirewallConfigSize)

	return nil
}

// writeDefaultConfig initializes shared memory with default values
func (lfcm *LlamaFirewallConfigManager) writeDefaultConfig() error {
	if lfcm.config == nil {
		return fmt.Errorf("shared memory not initialized")
	}

	// Zero out the structure
	C.memset(unsafe.Pointer(lfcm.config), 0, C.sizeof_llamafirewall_config_shm_t)

	// Set defaults (matching llamafirewall_config.c defaults)
	lfcm.config.enabled = 0 // Disabled by default

	// Set default server URL
	serverURL := "localhost:50052"
	cStr := C.CString(serverURL)
	defer C.free(unsafe.Pointer(cStr))
	C.strncpy(&lfcm.config.server_url[0], cStr, 255)

	lfcm.config.timeout_sec = 15
	lfcm.config.fail_closed = 0 // Fail-open by default
	lfcm.config.block_threshold = 0.9

	// Circuit breaker defaults
	lfcm.config.circuit_breaker_threshold = 5
	lfcm.config.circuit_breaker_timeout_sec = 60
	lfcm.config.circuit_breaker_success_threshold = 3

	// Scanner defaults (all enabled except agent_alignment and pii_detection)
	lfcm.config.scanner_prompt_guard = 1
	lfcm.config.scanner_code_shield = 1
	lfcm.config.scanner_regex = 1
	lfcm.config.scanner_hidden_ascii = 1
	lfcm.config.scanner_agent_alignment = 0
	lfcm.config.scanner_pii_detection = 0

	// Performance defaults
	lfcm.config.cache_enabled = 1
	lfcm.config.cache_ttl_sec = 300
	lfcm.config.connection_pool_size = 10

	// Initialize version
	lfcm.config.config_version = 1
	lfcm.config.last_update_ts = C.uint64_t(time.Now().Unix())

	// Sync to disk
	if err := unix.Msync(lfcm.sharedMem, unix.MS_SYNC); err != nil {
		return fmt.Errorf("failed to sync shared memory: %w", err)
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall-Config] ✓ Default configuration written (version=1, enabled=false)\n")
	return nil
}

// LlamaFirewallConfig represents runtime configuration
type LlamaFirewallConfig struct {
	Enabled        bool    `json:"enabled"`
	ServerURL      string  `json:"server_url"`
	TimeoutSec     int     `json:"timeout_sec"`
	FailClosed     bool    `json:"fail_closed"`
	BlockThreshold float32 `json:"block_threshold"`

	// Circuit breaker settings
	CircuitBreakerThreshold        uint32 `json:"circuit_breaker_threshold,omitempty"`
	CircuitBreakerTimeoutSec       uint32 `json:"circuit_breaker_timeout_sec,omitempty"`
	CircuitBreakerSuccessThreshold uint32 `json:"circuit_breaker_success_threshold,omitempty"`

	// Scanner configuration
	ScannerPromptGuard    bool `json:"scanner_prompt_guard"`
	ScannerCodeShield     bool `json:"scanner_code_shield"`
	ScannerRegex          bool `json:"scanner_regex"`
	ScannerHiddenASCII    bool `json:"scanner_hidden_ascii"`
	ScannerAgentAlignment bool `json:"scanner_agent_alignment"`
	ScannerPIIDetection   bool `json:"scanner_pii_detection"`

	// Performance settings
	CacheEnabled       bool `json:"cache_enabled"`
	CacheTTLSec        int  `json:"cache_ttl_sec"`
	ConnectionPoolSize int  `json:"connection_pool_size"`

	// Patterns (stored separately from shared memory)
	ScanPatterns []string `json:"scan_patterns,omitempty"`
	SkipPatterns []string `json:"skip_patterns,omitempty"`
}

// UpdateConfig updates shared memory configuration
func (lfcm *LlamaFirewallConfigManager) UpdateConfig(cfg LlamaFirewallConfig) error {
	if lfcm.config == nil {
		return fmt.Errorf("shared memory not initialized")
	}

	// Update enabled flag
	if cfg.Enabled {
		lfcm.config.enabled = 1
	} else {
		lfcm.config.enabled = 0
	}

	// Update server URL
	if cfg.ServerURL != "" {
		cStr := C.CString(cfg.ServerURL)
		defer C.free(unsafe.Pointer(cStr))
		C.strncpy(&lfcm.config.server_url[0], cStr, 255)
	}

	// Update timeout and thresholds
	if cfg.TimeoutSec > 0 {
		lfcm.config.timeout_sec = C.uint32_t(cfg.TimeoutSec)
	}

	if cfg.FailClosed {
		lfcm.config.fail_closed = 1
	} else {
		lfcm.config.fail_closed = 0
	}

	if cfg.BlockThreshold > 0 {
		lfcm.config.block_threshold = C.float(cfg.BlockThreshold)
	}

	// Update circuit breaker settings
	if cfg.CircuitBreakerThreshold > 0 {
		lfcm.config.circuit_breaker_threshold = C.uint32_t(cfg.CircuitBreakerThreshold)
	}
	if cfg.CircuitBreakerTimeoutSec > 0 {
		lfcm.config.circuit_breaker_timeout_sec = C.uint32_t(cfg.CircuitBreakerTimeoutSec)
	}
	if cfg.CircuitBreakerSuccessThreshold > 0 {
		lfcm.config.circuit_breaker_success_threshold = C.uint32_t(cfg.CircuitBreakerSuccessThreshold)
	}

	// Update scanner flags
	if cfg.ScannerPromptGuard {
		lfcm.config.scanner_prompt_guard = 1
	} else {
		lfcm.config.scanner_prompt_guard = 0
	}
	if cfg.ScannerCodeShield {
		lfcm.config.scanner_code_shield = 1
	} else {
		lfcm.config.scanner_code_shield = 0
	}
	if cfg.ScannerRegex {
		lfcm.config.scanner_regex = 1
	} else {
		lfcm.config.scanner_regex = 0
	}
	if cfg.ScannerHiddenASCII {
		lfcm.config.scanner_hidden_ascii = 1
	} else {
		lfcm.config.scanner_hidden_ascii = 0
	}
	if cfg.ScannerAgentAlignment {
		lfcm.config.scanner_agent_alignment = 1
	} else {
		lfcm.config.scanner_agent_alignment = 0
	}
	if cfg.ScannerPIIDetection {
		lfcm.config.scanner_pii_detection = 1
	} else {
		lfcm.config.scanner_pii_detection = 0
	}

	// Update performance settings
	if cfg.CacheEnabled {
		lfcm.config.cache_enabled = 1
	} else {
		lfcm.config.cache_enabled = 0
	}
	if cfg.CacheTTLSec > 0 {
		lfcm.config.cache_ttl_sec = C.uint32_t(cfg.CacheTTLSec)
	}
	if cfg.ConnectionPoolSize > 0 {
		lfcm.config.connection_pool_size = C.uint32_t(cfg.ConnectionPoolSize)
	}

	// Increment version
	lfcm.config.config_version++
	lfcm.config.last_update_ts = C.uint64_t(time.Now().Unix())

	// Sync to disk
	if err := unix.Msync(lfcm.sharedMem, unix.MS_SYNC); err != nil {
		return fmt.Errorf("failed to sync shared memory: %w", err)
	}

	tk.LogIt(tk.LogInfo, "[LlamaFirewall-Config] ✓ Configuration updated (version=%d, enabled=%v, server=%s)\n",
		lfcm.config.config_version, cfg.Enabled, cfg.ServerURL)

	return nil
}

// GetConfig reads current configuration from shared memory
func (lfcm *LlamaFirewallConfigManager) GetConfig() (*LlamaFirewallConfig, error) {
	if lfcm.config == nil {
		return nil, fmt.Errorf("shared memory not initialized")
	}

	cfg := &LlamaFirewallConfig{
		Enabled:        lfcm.config.enabled == 1,
		ServerURL:      C.GoString(&lfcm.config.server_url[0]),
		TimeoutSec:     int(lfcm.config.timeout_sec),
		FailClosed:     lfcm.config.fail_closed == 1,
		BlockThreshold: float32(lfcm.config.block_threshold),

		CircuitBreakerThreshold:        uint32(lfcm.config.circuit_breaker_threshold),
		CircuitBreakerTimeoutSec:       uint32(lfcm.config.circuit_breaker_timeout_sec),
		CircuitBreakerSuccessThreshold: uint32(lfcm.config.circuit_breaker_success_threshold),

		ScannerPromptGuard:    lfcm.config.scanner_prompt_guard == 1,
		ScannerCodeShield:     lfcm.config.scanner_code_shield == 1,
		ScannerRegex:          lfcm.config.scanner_regex == 1,
		ScannerHiddenASCII:    lfcm.config.scanner_hidden_ascii == 1,
		ScannerAgentAlignment: lfcm.config.scanner_agent_alignment == 1,
		ScannerPIIDetection:   lfcm.config.scanner_pii_detection == 1,

		CacheEnabled:       lfcm.config.cache_enabled == 1,
		CacheTTLSec:        int(lfcm.config.cache_ttl_sec),
		ConnectionPoolSize: int(lfcm.config.connection_pool_size),

		ScanPatterns: make([]string, 0),
		SkipPatterns: make([]string, 0),
	}

	return cfg, nil
}

// Close unmaps shared memory
func (lfcm *LlamaFirewallConfigManager) Close() error {
	if lfcm.sharedMem != nil {
		if err := unix.Munmap(lfcm.sharedMem); err != nil {
			return err
		}
		lfcm.sharedMem = nil
		lfcm.config = nil
	}
	return nil
}

// ============================================================================
// API TYPES AND FUNCTIONS (to avoid import cycles with loxinet)
// ============================================================================

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

// Global statistics storage (can be updated by loxinet)
var globalStatus = &LlamaFirewallStatus{
	Connected: false,
}

var globalStats = &LlamaFirewallStats{}

// GetStatus returns LlamaFirewall connection status
func GetStatus() *LlamaFirewallStatus {
	return globalStatus
}

// GetStats returns LlamaFirewall statistics
func GetStats() *LlamaFirewallStats {
	return globalStats
}

// HealthCheck triggers health check and returns result
// Note: Actual implementation will be provided by loxinet through CGO bridge
func HealthCheck() *LlamaFirewallHealthResult {
	result := &LlamaFirewallHealthResult{
		Healthy:   false,
		Connected: globalStatus.Connected,
		Timestamp: time.Now(),
	}

	// Read config to get server URL
	cfgMgr := GlobalConfigMgr()
	if cfgMgr == nil {
		result.Message = "LlamaFirewall config manager not initialized"
		return result
	}
	config, err := cfgMgr.GetConfig()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to read config: %v", err)
		return result
	}
	result.ServerURL = config.ServerURL

	// This reports the tracked connection state, not a live probe of the
	// scanner server — a request-driven health check is not implemented yet.
	if globalStatus.Connected {
		result.Healthy = true
		result.Message = "LlamaFirewall server is connected"
		result.LatencyMs = 0
	} else {
		result.Message = "LlamaFirewall server is not connected"
	}

	return result
}

// UpdateStatus updates the global status (called from loxinet)
func UpdateStatus(connected bool, lastCheck *time.Time) {
	globalStatus.Connected = connected
	globalStatus.LastHealthCheck = lastCheck
}

// UpdateStats updates the global stats (called from loxinet)
func UpdateStats(stats *LlamaFirewallStats) {
	if stats != nil {
		globalStats = stats
	}
}
