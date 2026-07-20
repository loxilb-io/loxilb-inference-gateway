//go:build piidetection
// +build piidetection

/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * PII Detection: Shared Memory Configuration (Go Writer)
 *
 * This file writes presidio_config_shm_t to /dev/shm/loxilb_presidio_config
 * following the exact same pattern as catalog_sync.go for L4/L7 trace config.
 */

package presidio

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "presidio_config.h"
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
	presidioSharedMemPath = "/dev/shm/loxilb_presidio_config"
	presidioConfigSize    = C.sizeof_presidio_config_shm_t // ~20KB
)

// PresidioConfigManager manages shared memory for Presidio configuration
type PresidioConfigManager struct {
	sharedMem []byte
	config    *C.presidio_config_shm_t
}

var globalPresidioConfigMgr *PresidioConfigManager

// GlobalConfigMgr returns the global Presidio configuration manager
func GlobalConfigMgr() *PresidioConfigManager {
	return globalPresidioConfigMgr
}

// NewPresidioConfigManager creates shared memory manager
func NewPresidioConfigManager() (*PresidioConfigManager, error) {
	pcm := &PresidioConfigManager{}

	if err := pcm.initSharedMemory(); err != nil {
		return nil, err
	}

	// Initialize with default configuration
	if err := pcm.writeDefaultConfig(); err != nil {
		tk.LogIt(tk.LogWarning, "[PresidioConfig] Failed to write defaults: %v\n", err)
	}

	globalPresidioConfigMgr = pcm
	return pcm, nil
}

// initSharedMemory creates and maps shared memory
func (pcm *PresidioConfigManager) initSharedMemory() error {
	// Open/create shared memory file
	file, err := os.OpenFile(presidioSharedMemPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open shared memory file: %w", err)
	}
	defer file.Close()

	// Truncate to required size
	if err := file.Truncate(int64(presidioConfigSize)); err != nil {
		return fmt.Errorf("failed to truncate shared memory: %w", err)
	}

	// Memory-map the file
	sharedMem, err := unix.Mmap(
		int(file.Fd()),
		0,
		int(presidioConfigSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
	)
	if err != nil {
		return fmt.Errorf("failed to mmap shared memory: %w", err)
	}

	pcm.sharedMem = sharedMem
	pcm.config = (*C.presidio_config_shm_t)(unsafe.Pointer(&sharedMem[0]))

	tk.LogIt(tk.LogInfo, "[PresidioConfig] ✓ Initialized shared memory: path=%s size=%d bytes\n",
		presidioSharedMemPath, presidioConfigSize)

	return nil
}

// writeDefaultConfig initializes shared memory with default values
func (pcm *PresidioConfigManager) writeDefaultConfig() error {
	if pcm.config == nil {
		return fmt.Errorf("shared memory not initialized")
	}

	// Zero out the structure
	C.memset(unsafe.Pointer(pcm.config), 0, C.sizeof_presidio_config_shm_t)

	// Set defaults (matching presidio_config.c defaults)
	pcm.config.enabled = 0 // Disabled by default
	pcm.config.mode = C.PRESIDIO_MODE_MASK_IN_PLACE
	pcm.config.direction = C.PRESIDIO_DIR_BOTH
	pcm.config.fail_mode = C.PRESIDIO_FAIL_OPEN
	pcm.config.scan_mode = C.PRESIDIO_SCAN_MODE_TRUNCATE // Default to truncate mode
	pcm.config.score_threshold = 0.7
	pcm.config.timeout_ms = 100
	pcm.config.max_body_size = 65536
	pcm.config.min_body_size = 100
	pcm.config.enable_json_detection = 1 // Enable JSON mode by default

	// Set default analyzer URL
	analyzerURL := "localhost:50051"
	C.strncpy(&pcm.config.analyzer_url[0], C.CString(analyzerURL), C.sizeof_presidio_config_shm_t-1)

	// Circuit breaker defaults
	pcm.config.circuit_breaker_threshold = 5
	pcm.config.circuit_breaker_timeout_sec = 60
	pcm.config.circuit_breaker_success_threshold = 3

	// Retry defaults
	pcm.config.max_retries = 1
	pcm.config.retry_backoff_ms = 100

	// URL pattern mode: 0 = scan all
	pcm.config.url_mode = 0
	pcm.config.num_url_patterns = 0

	// Initialize version
	pcm.config.config_version = 1
	pcm.config.last_update_ts = C.uint64_t(time.Now().Unix())

	// Sync to disk
	if err := unix.Msync(pcm.sharedMem, unix.MS_SYNC); err != nil {
		return fmt.Errorf("failed to sync shared memory: %w", err)
	}

	tk.LogIt(tk.LogInfo, "[PresidioConfig] ✓ Default configuration written (version=1, enabled=false)\n")
	return nil
}

// PresidioConfig represents runtime configuration
type PresidioConfig struct {
	Enabled             bool                 `json:"enabled"`
	Mode                string               `json:"mode"`      // "detect", "mask", "redact", "anonymize"
	Direction           string               `json:"direction"` // "both", "request", "response"
	FailMode            string               `json:"fail_mode"` // "open", "closed"
	ScanMode            string               `json:"scan_mode"` // "full", "truncate", "skip"
	AnalyzerURL         string               `json:"analyzer_url"`
	AnonymizerURL       string               `json:"anonymizer_url,omitempty"`
	ScoreThreshold      float32              `json:"score_threshold"`
	TimeoutMs           uint32               `json:"timeout_ms"`
	MaxBodySize         uint32               `json:"max_body_size"`
	MinBodySize         uint32               `json:"min_body_size"`
	EnableJSONDetection bool                 `json:"enable_json_detection"` // Enable JSON-aware anonymization
	URLPatterns         []PresidioURLPattern `json:"url_patterns,omitempty"`
	CircuitBreaker      CircuitBreakerConfig `json:"circuit_breaker,omitempty"`
	Retry               RetryConfig          `json:"retry,omitempty"`
	ExcludeFields       []string             `json:"exclude_fields,omitempty"` // JSON paths to exclude from PII detection
}

// PresidioURLPattern represents a URL pattern for filtering
type PresidioURLPattern struct {
	Pattern   string `json:"pattern"`
	IsExclude bool   `json:"is_exclude"`
}

// CircuitBreakerConfig represents circuit breaker settings
type CircuitBreakerConfig struct {
	Threshold        uint32 `json:"threshold"`
	TimeoutSec       uint32 `json:"timeout_sec"`
	SuccessThreshold uint32 `json:"success_threshold"`
}

// RetryConfig represents retry settings
type RetryConfig struct {
	MaxRetries uint32 `json:"max_retries"`
	BackoffMs  uint32 `json:"backoff_ms"`
}

// UpdateConfig updates shared memory configuration
func (pcm *PresidioConfigManager) UpdateConfig(cfg PresidioConfig) error {
	if pcm.config == nil {
		return fmt.Errorf("shared memory not initialized")
	}

	// Update enabled flag
	if cfg.Enabled {
		pcm.config.enabled = 1
	} else {
		pcm.config.enabled = 0
	}

	// Update mode
	switch cfg.Mode {
	case "detect":
		pcm.config.mode = C.PRESIDIO_MODE_DETECT_ONLY
	case "mask":
		pcm.config.mode = C.PRESIDIO_MODE_MASK_IN_PLACE
	case "redact":
		pcm.config.mode = C.PRESIDIO_MODE_REDACT_FULL
	case "anonymize":
		pcm.config.mode = C.PRESIDIO_MODE_ANONYMIZE
	}

	// Update direction
	switch cfg.Direction {
	case "both":
		pcm.config.direction = C.PRESIDIO_DIR_BOTH
	case "request":
		pcm.config.direction = C.PRESIDIO_DIR_REQUEST_ONLY
	case "response":
		pcm.config.direction = C.PRESIDIO_DIR_RESPONSE_ONLY
	}

	// Update fail mode
	switch cfg.FailMode {
	case "open":
		pcm.config.fail_mode = C.PRESIDIO_FAIL_OPEN
	case "closed":
		pcm.config.fail_mode = C.PRESIDIO_FAIL_CLOSED
	}

	// Update scan mode
	switch cfg.ScanMode {
	case "full":
		pcm.config.scan_mode = C.PRESIDIO_SCAN_MODE_FULL
	case "truncate":
		pcm.config.scan_mode = C.PRESIDIO_SCAN_MODE_TRUNCATE
	default:
		// Default to truncate for backward compatibility and security
		pcm.config.scan_mode = C.PRESIDIO_SCAN_MODE_TRUNCATE
	}

	// Update URLs
	if cfg.AnalyzerURL != "" {
		cStr := C.CString(cfg.AnalyzerURL)
		defer C.free(unsafe.Pointer(cStr))
		C.strncpy(&pcm.config.analyzer_url[0], cStr, 255)
	}

	if cfg.AnonymizerURL != "" {
		cStr := C.CString(cfg.AnonymizerURL)
		defer C.free(unsafe.Pointer(cStr))
		C.strncpy(&pcm.config.anonymizer_url[0], cStr, 255)
	}

	// Update thresholds and limits
	pcm.config.score_threshold = C.float(cfg.ScoreThreshold)
	pcm.config.timeout_ms = C.uint32_t(cfg.TimeoutMs)
	pcm.config.max_body_size = C.uint32_t(cfg.MaxBodySize)
	pcm.config.min_body_size = C.uint32_t(cfg.MinBodySize)

	// Always enable JSON detection mode (required for field exclusion)
	pcm.config.enable_json_detection = 1

	// Update URL patterns
	if len(cfg.URLPatterns) > 0 {
		pcm.config.url_mode = 1 // Enable pattern matching
		pcm.config.num_url_patterns = C.uint8_t(len(cfg.URLPatterns))
		if pcm.config.num_url_patterns > 64 {
			pcm.config.num_url_patterns = 64
		}

		for i := 0; i < int(pcm.config.num_url_patterns); i++ {
			pattern := &cfg.URLPatterns[i]
			cPattern := C.CString(pattern.Pattern)
			defer C.free(unsafe.Pointer(cPattern))

			C.strncpy(&pcm.config.url_patterns[i].pattern[0], cPattern, 127)
			pcm.config.url_patterns[i].enabled = 1
			if pattern.IsExclude {
				pcm.config.url_patterns[i].is_exclude = 1
			} else {
				pcm.config.url_patterns[i].is_exclude = 0
			}
		}
	} else {
		pcm.config.url_mode = 0 // Scan all
		pcm.config.num_url_patterns = 0
	}

	// Update circuit breaker settings
	if cfg.CircuitBreaker.Threshold > 0 {
		pcm.config.circuit_breaker_threshold = C.uint32_t(cfg.CircuitBreaker.Threshold)
	}
	if cfg.CircuitBreaker.TimeoutSec > 0 {
		pcm.config.circuit_breaker_timeout_sec = C.uint32_t(cfg.CircuitBreaker.TimeoutSec)
	}
	if cfg.CircuitBreaker.SuccessThreshold > 0 {
		pcm.config.circuit_breaker_success_threshold = C.uint32_t(cfg.CircuitBreaker.SuccessThreshold)
	}

	// Update retry settings
	if cfg.Retry.MaxRetries > 0 {
		pcm.config.max_retries = C.uint32_t(cfg.Retry.MaxRetries)
	}
	if cfg.Retry.BackoffMs > 0 {
		pcm.config.retry_backoff_ms = C.uint32_t(cfg.Retry.BackoffMs)
	}

	// Increment version
	pcm.config.config_version++
	pcm.config.last_update_ts = C.uint64_t(time.Now().Unix())

	// Sync to disk
	if err := unix.Msync(pcm.sharedMem, unix.MS_SYNC); err != nil {
		return fmt.Errorf("failed to sync shared memory: %w", err)
	}

	tk.LogIt(tk.LogInfo, "[PresidioConfig] ✓ Configuration updated (version=%d, enabled=%v, mode=%s)\n",
		pcm.config.config_version, cfg.Enabled, cfg.Mode)

	return nil
}

// GetConfig reads current configuration from shared memory
func (pcm *PresidioConfigManager) GetConfig() (*PresidioConfig, error) {
	if pcm.config == nil {
		return nil, fmt.Errorf("shared memory not initialized")
	}

	cfg := &PresidioConfig{
		Enabled:             pcm.config.enabled == 1,
		AnalyzerURL:         C.GoString(&pcm.config.analyzer_url[0]),
		AnonymizerURL:       C.GoString(&pcm.config.anonymizer_url[0]),
		ScoreThreshold:      float32(pcm.config.score_threshold),
		TimeoutMs:           uint32(pcm.config.timeout_ms),
		MaxBodySize:         uint32(pcm.config.max_body_size),
		MinBodySize:         uint32(pcm.config.min_body_size),
		EnableJSONDetection: pcm.config.enable_json_detection == 1,
	}

	// Convert mode
	switch pcm.config.mode {
	case C.PRESIDIO_MODE_DETECT_ONLY:
		cfg.Mode = "detect"
	case C.PRESIDIO_MODE_MASK_IN_PLACE:
		cfg.Mode = "mask"
	case C.PRESIDIO_MODE_REDACT_FULL:
		cfg.Mode = "redact"
	case C.PRESIDIO_MODE_ANONYMIZE:
		cfg.Mode = "anonymize"
	}

	// Convert direction
	switch pcm.config.direction {
	case C.PRESIDIO_DIR_BOTH:
		cfg.Direction = "both"
	case C.PRESIDIO_DIR_REQUEST_ONLY:
		cfg.Direction = "request"
	case C.PRESIDIO_DIR_RESPONSE_ONLY:
		cfg.Direction = "response"
	}

	// Convert fail mode
	switch pcm.config.fail_mode {
	case C.PRESIDIO_FAIL_OPEN:
		cfg.FailMode = "open"
	case C.PRESIDIO_FAIL_CLOSED:
		cfg.FailMode = "closed"
	}

	// Convert scan mode
	switch pcm.config.scan_mode {
	case C.PRESIDIO_SCAN_MODE_FULL:
		cfg.ScanMode = "full"
	case C.PRESIDIO_SCAN_MODE_TRUNCATE:
		cfg.ScanMode = "truncate"
	default:
		cfg.ScanMode = "truncate" // Default
	}

	// Get URL patterns
	if pcm.config.num_url_patterns > 0 {
		cfg.URLPatterns = make([]PresidioURLPattern, 0, pcm.config.num_url_patterns)
		for i := 0; i < int(pcm.config.num_url_patterns); i++ {
			if pcm.config.url_patterns[i].enabled == 1 {
				pattern := PresidioURLPattern{
					Pattern:   C.GoString(&pcm.config.url_patterns[i].pattern[0]),
					IsExclude: pcm.config.url_patterns[i].is_exclude == 1,
				}
				cfg.URLPatterns = append(cfg.URLPatterns, pattern)
			}
		}
	}

	// Get circuit breaker settings
	cfg.CircuitBreaker = CircuitBreakerConfig{
		Threshold:        uint32(pcm.config.circuit_breaker_threshold),
		TimeoutSec:       uint32(pcm.config.circuit_breaker_timeout_sec),
		SuccessThreshold: uint32(pcm.config.circuit_breaker_success_threshold),
	}

	// Get retry settings
	cfg.Retry = RetryConfig{
		MaxRetries: uint32(pcm.config.max_retries),
		BackoffMs:  uint32(pcm.config.retry_backoff_ms),
	}
	// Read exclude_fields from JSON config
	cfg.ExcludeFields = make([]string, 0)
	for i := 0; i < int(pcm.config.json_config.num_exclude_fields) && i < C.PRESIDIO_MAX_JSON_FIELDS; i++ {
		field := C.GoString(&pcm.config.json_config.exclude_fields[i][0])
		if field != "" {
			cfg.ExcludeFields = append(cfg.ExcludeFields, field)
		}
	}
	return cfg, nil
}

// GetExcludeFields reads exclude_fields from json_config section of shared memory
// (populated by C code from presidio_json_fields.json)
func (pcm *PresidioConfigManager) GetExcludeFields() []string {
	if pcm.config == nil {
		return nil
	}

	// Force memory sync to see C's updates to json_config section
	unix.Msync(pcm.sharedMem, unix.MS_INVALIDATE|unix.MS_SYNC)

	excludeFields := make([]string, 0)
	for i := 0; i < int(pcm.config.json_config.num_exclude_fields) && i < C.PRESIDIO_MAX_JSON_FIELDS; i++ {
		field := C.GoString(&pcm.config.json_config.exclude_fields[i][0])
		if field != "" {
			excludeFields = append(excludeFields, field)
		}
	}
	return excludeFields
}

// GetScoreThreshold reads the score_threshold from shared memory
func (pcm *PresidioConfigManager) GetScoreThreshold() float32 {
	if pcm.config == nil {
		return 0.7 // Default fallback
	}

	// Force memory sync to see C's updates
	unix.Msync(pcm.sharedMem, unix.MS_INVALIDATE|unix.MS_SYNC)

	return float32(pcm.config.score_threshold)
}

// Close unmaps shared memory
func (pcm *PresidioConfigManager) Close() error {
	if pcm.sharedMem != nil {
		if err := unix.Munmap(pcm.sharedMem); err != nil {
			return err
		}
		pcm.sharedMem = nil
		pcm.config = nil
	}
	return nil
}
