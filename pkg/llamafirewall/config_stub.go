//go:build !llamafirewall
// +build !llamafirewall

/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * LlamaFirewall Stub: Disabled build (no CGO dependencies)
 */

package llamafirewall

import (
	"fmt"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

// LlamaFirewallConfig - Configuration stub
type LlamaFirewallConfig struct {
	Enabled               bool
	ServerURL             string
	TimeoutSec            int
	FailClosed            bool
	BlockThreshold        float32
	CacheEnabled          bool
	CacheTTLSec           int
	ConnectionPoolSize    int
	ScanPatterns          []string
	SkipPatterns          []string
	ScannerPromptGuard    bool
	ScannerCodeShield     bool
	ScannerRegex          bool
	ScannerHiddenASCII    bool
	ScannerAgentAlignment bool
	ScannerPIIDetection   bool
	CircuitBreaker        CircuitBreakerConfig
	Scanners              ScannersConfig
	PresidioEnabled       bool
	PresidioURL           string
	PresidioTimeout       uint32
	ConcurrentRequests    uint32
	ConcurrentConnLimit   uint32
}

// CircuitBreakerConfig - Circuit breaker stub
type CircuitBreakerConfig struct {
	Threshold        uint32
	TimeoutSec       uint32
	SuccessThreshold uint32
}

// ScannersConfig - Scanners configuration stub
type ScannersConfig struct {
	PromptGuard    bool
	CodeShield     bool
	Regex          bool
	HiddenASCII    bool
	AgentAlignment bool
	PIIDetection   bool
}

// LlamaFirewallStats - Statistics stub
type LlamaFirewallStats struct {
	TotalScans       int64
	RequestsScanned  int64
	ResponsesScanned int64
	ThreatsDetected  int64
	RequestsBlocked  int64
	ScanErrors       int64
	AvgLatencyMs     int64
	CacheHits        int64
	ScannerStats     ScannerStatsGroup
	Decisions        DecisionStats
}

// ScannerStatsGroup - Individual scanner statistics
type ScannerStatsGroup struct {
	PromptGuard    IndividualScannerStats
	CodeShield     IndividualScannerStats
	Regex          IndividualScannerStats
	HiddenASCII    IndividualScannerStats
	AgentAlignment IndividualScannerStats
	PIIDetection   IndividualScannerStats
}

// IndividualScannerStats - Stats for a single scanner
type IndividualScannerStats struct {
	Scans        int64
	Detections   int64
	AvgLatencyMs int64
	Errors       int64
}

// DecisionStats - Decision statistics
type DecisionStats struct {
	Allow int64
	Block int64
	HITL  int64
}

// Status - LlamaFirewall status
type Status struct {
	Connected       bool
	LastHealthCheck *time.Time
}

// HealthResult - Health check result
type HealthResult struct {
	Healthy   bool
	ServerURL string
	Connected bool
	LatencyMs int64
	Message   string
	Timestamp time.Time
}

// Manager - Stub manager
type Manager struct{}

// LlamaFirewallConfigManager - Stub config manager (alias for backward compatibility)
type LlamaFirewallConfigManager = Manager

var globalManager *Manager

// NewManager - Create stub manager
func NewManager() *Manager {
	tk.LogIt(tk.LogWarning, "[LlamaFirewall] Stub mode - build with -tags llamafirewall to enable\n")
	globalManager = &Manager{}
	return globalManager
}

// NewLlamaFirewallConfigManager returns a stub manager (no-op)
func NewLlamaFirewallConfigManager() (*LlamaFirewallConfigManager, error) {
	tk.LogIt(tk.LogDebug, "[LlamaFirewall] Not compiled (build with -tags llamafirewall)\n")
	return &LlamaFirewallConfigManager{}, nil
}

// GlobalConfigMgr - Get global config manager (stub)
func GlobalConfigMgr() *Manager {
	if globalManager == nil {
		globalManager = &Manager{}
	}
	return globalManager
}

// UpdateConfig - Stub update config
func (m *Manager) UpdateConfig(cfg LlamaFirewallConfig) error {
	return fmt.Errorf("LlamaFirewall not compiled (rebuild with -tags llamafirewall)")
}

// GetConfig - Stub get config
func (m *Manager) GetConfig() (*LlamaFirewallConfig, error) {
	return &LlamaFirewallConfig{Enabled: false}, nil
}

// GetStats - Stub get stats (method)
func (m *Manager) GetStats() (*LlamaFirewallStats, error) {
	return &LlamaFirewallStats{}, nil
}

// Enable - Stub enable
func (m *Manager) Enable(enabled bool) error {
	if enabled {
		return fmt.Errorf("LlamaFirewall not compiled (rebuild with -tags llamafirewall)")
	}
	return nil
}

// IsEnabled - Stub check if enabled
func (m *Manager) IsEnabled() bool {
	return false
}

// HealthCheck - Stub health check (method)
func (m *Manager) HealthCheck() error {
	return fmt.Errorf("LlamaFirewall not compiled")
}

// Close - Stub close
func (m *Manager) Close() error {
	return nil
}

// GetStatus - Get status (package-level function)
func GetStatus() Status {
	return Status{
		Connected:       false,
		LastHealthCheck: nil,
	}
}

// GetStats - Get stats (package-level function)
func GetStats() *LlamaFirewallStats {
	return &LlamaFirewallStats{}
}

// HealthCheck - Health check (package-level function)
func HealthCheck() HealthResult {
	return HealthResult{
		Healthy:   false,
		ServerURL: "",
		Connected: false,
		LatencyMs: 0,
		Message:   "LlamaFirewall not compiled (rebuild with -tags llamafirewall)",
		Timestamp: time.Now(),
	}
}
