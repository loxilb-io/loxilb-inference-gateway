//go:build !piidetection
// +build !piidetection

/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * PII Detection: Stub implementation when PII detection is disabled
 */

package presidio

import tk "github.com/loxilb-io/loxilib"

// PresidioConfigManager stub (no-op when PII detection disabled)
type PresidioConfigManager struct{}

// GlobalConfigMgr returns nil when PII detection is disabled
func GlobalConfigMgr() *PresidioConfigManager {
	return nil
}

// NewPresidioConfigManager returns a stub manager (no-op)
func NewPresidioConfigManager() (*PresidioConfigManager, error) {
	tk.LogIt(tk.LogDebug, "[Presidio] PII detection not compiled (build without piidetection tag)\n")
	return &PresidioConfigManager{}, nil
}

// Stub methods for backward compatibility
func (pcm *PresidioConfigManager) GetConfig() (*PresidioConfig, error) {
	return &PresidioConfig{}, nil
}

func (pcm *PresidioConfigManager) UpdateConfig(cfg PresidioConfig) error {
	return nil
}

func (pcm *PresidioConfigManager) Close() error {
	return nil
}

func (pcm *PresidioConfigManager) GetExcludeFields() []string {
	return nil
}

func (pcm *PresidioConfigManager) GetScoreThreshold() float32 {
	return 0.7 // Default score threshold
}

// Stub types - must match real definitions for API compatibility
type PresidioConfig struct {
	Enabled        bool                 `json:"enabled"`
	Mode           string               `json:"mode"`
	Direction      string               `json:"direction"`
	FailMode       string               `json:"fail_mode"`
	AnalyzerURL    string               `json:"analyzer_url"`
	AnonymizerURL  string               `json:"anonymizer_url,omitempty"`
	ScoreThreshold float32              `json:"score_threshold"`
	TimeoutMs      uint32               `json:"timeout_ms"`
	MaxBodySize    uint32               `json:"max_body_size"`
	MinBodySize    uint32               `json:"min_body_size"`
	URLPatterns    []PresidioURLPattern `json:"url_patterns,omitempty"`
	CircuitBreaker CircuitBreakerConfig `json:"circuit_breaker,omitempty"`
	Retry          RetryConfig          `json:"retry,omitempty"`
}

type PresidioURLPattern struct {
	Pattern   string `json:"pattern"`
	IsExclude bool   `json:"is_exclude"`
}

type CircuitBreakerConfig struct {
	Threshold        uint32 `json:"threshold"`
	TimeoutSec       uint32 `json:"timeout_sec"`
	SuccessThreshold uint32 `json:"success_threshold"`
}

type RetryConfig struct {
	MaxRetries uint32 `json:"max_retries"`
	BackoffMs  uint32 `json:"backoff_ms"`
}
