/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSlause
 */

package loxinet

import (
	"fmt"
	"os"
	"strconv"
	"time"

	tk "github.com/loxilb-io/loxilib"
)

// TraceConfig holds all configurable parameters for HTTP/HTTPS Protocol Analyzer
//
// All parameters support environment variable overrides with validation and
// graceful fallback to defaults. This enables zero-downtime configuration
// changes across production/staging/development environments.
type TraceConfig struct {
	// Ring Buffer Consumer Configuration
	EventChannelSize int // Event channel buffer size (default: 10000)
	ConsumerPollMs   int // epoll timeout for graceful shutdown (default: 1ms)
	DrainLogInterval int // Log every N drained events (default: 100)

	// Span Assembler Configuration
	SpanTTL         time.Duration // Incomplete span timeout (default: 5 minutes)
	CleanupInterval time.Duration // Cleanup goroutine interval (default: 1 minute)
	MaxPendingSpans int           // Memory limit for openSpans map (default: 100000)

	// OTLP Exporter Configuration
	BatchSize      int           // Max spans per batch (default: 512)
	BatchTimeout   time.Duration // Max wait time before flush (default: 5 seconds)
	ExportRetries  int           // Retry attempts on export failure (default: 5)
	RetryBackoffMs int           // Initial retry backoff in milliseconds (default: 1000)

	// Multi-Instance Support
	InstanceID string // Unique identifier for this loxilb instance (default: "loxilb-default")
}

// DefaultTraceConfig returns production-grade default configuration.
//
// These defaults are optimized for:
// - Medium traffic: 1K-10K requests/sec
// - 4 worker threads (PROXY_MAX_THREADS)
// - Jaeger OTLP endpoint on localhost
// - Balanced latency/throughput tradeoff
func DefaultTraceConfig() TraceConfig {
	return TraceConfig{
		// Ring Buffer Consumer defaults
		EventChannelSize: 10000, // 10 seconds of buffering at 1K req/s
		ConsumerPollMs:   1,     // 1ms epoll timeout (fast shutdown, low CPU)
		DrainLogInterval: 100,   // Reduce log spam

		// Span Assembler defaults
		SpanTTL:         5 * time.Minute, // 5 minutes for slow backends
		CleanupInterval: 1 * time.Minute, // Cleanup every minute
		MaxPendingSpans: 100000,          // ~100MB memory for 100K spans

		// OTLP Exporter defaults
		BatchSize:      512,             // Balanced: 5s × 100 req/s = 500 spans
		BatchTimeout:   5 * time.Second, // Export every 5 seconds
		ExportRetries:  5,               // Retry 5 times on failure
		RetryBackoffMs: 1000,            // 1s initial backoff (1s → 2s → 4s → 8s → 16s)

		// Instance ID (override in Kubernetes/multi-instance)
		InstanceID: "loxilb-default",
	}
}

// LoadTraceConfig loads configuration from environment variables with validation.
//
// Environment Variables:
//   - LOXILB_TRACE_EVENT_CHANNEL_SIZE (int, 1-100000): Event channel buffer
//   - LOXILB_TRACE_CONSUMER_POLL_MS (int, 1-1000): epoll timeout
//   - LOXILB_TRACE_DRAIN_LOG_INTERVAL (int, 1-10000): Log frequency
//   - LOXILB_TRACE_SPAN_TTL_SEC (int, 10-3600): Span timeout
//   - LOXILB_TRACE_CLEANUP_INTERVAL_SEC (int, 10-600): Cleanup interval
//   - LOXILB_TRACE_MAX_PENDING_SPANS (int, 1000-1000000): Memory limit
//   - LOXILB_TRACE_BATCH_SIZE (int, 1-10000): OTLP batch size
//   - LOXILB_TRACE_BATCH_TIMEOUT_MS (int, 100-60000): Batch timeout
//   - LOXILB_TRACE_EXPORT_RETRIES (int, 0-10): Retry attempts
//   - LOXILB_TRACE_RETRY_BACKOFF_MS (int, 100-10000): Retry backoff
//   - LOXILB_INSTANCE_ID (string): Unique instance identifier
//
// Invalid values trigger warnings and fallback to defaults.
func LoadTraceConfig() TraceConfig {
	cfg := DefaultTraceConfig()

	// Ring Buffer Consumer
	if v := os.Getenv("LOXILB_TRACE_EVENT_CHANNEL_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 100000 {
			cfg.EventChannelSize = n
			tk.LogIt(tk.LogInfo, "[TraceConfig] EventChannelSize=%d (from env)\n", n)
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_EVENT_CHANNEL_SIZE='%s' (must be 1-100000), using default %d\n",
				v, cfg.EventChannelSize)
		}
	}

	if v := os.Getenv("LOXILB_TRACE_CONSUMER_POLL_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 1000 {
			cfg.ConsumerPollMs = n
			tk.LogIt(tk.LogInfo, "[TraceConfig] ConsumerPollMs=%d (from env)\n", n)
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_CONSUMER_POLL_MS='%s' (must be 1-1000), using default %d\n",
				v, cfg.ConsumerPollMs)
		}
	}

	if v := os.Getenv("LOXILB_TRACE_DRAIN_LOG_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10000 {
			cfg.DrainLogInterval = n
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_DRAIN_LOG_INTERVAL='%s', using default %d\n",
				v, cfg.DrainLogInterval)
		}
	}

	// Span Assembler
	if v := os.Getenv("LOXILB_TRACE_SPAN_TTL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 && n <= 3600 {
			cfg.SpanTTL = time.Duration(n) * time.Second
			tk.LogIt(tk.LogInfo, "[TraceConfig] SpanTTL=%ds (from env)\n", n)
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_SPAN_TTL_SEC='%s' (must be 10-3600), using default %ds\n",
				v, int(cfg.SpanTTL.Seconds()))
		}
	}

	if v := os.Getenv("LOXILB_TRACE_CLEANUP_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 && n <= 600 {
			cfg.CleanupInterval = time.Duration(n) * time.Second
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_CLEANUP_INTERVAL_SEC='%s', using default %ds\n",
				v, int(cfg.CleanupInterval.Seconds()))
		}
	}

	if v := os.Getenv("LOXILB_TRACE_MAX_PENDING_SPANS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1000 && n <= 1000000 {
			cfg.MaxPendingSpans = n
			tk.LogIt(tk.LogInfo, "[TraceConfig] MaxPendingSpans=%d (from env)\n", n)
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_MAX_PENDING_SPANS='%s' (must be 1000-1000000), using default %d\n",
				v, cfg.MaxPendingSpans)
		}
	}

	// OTLP Exporter
	if v := os.Getenv("LOXILB_TRACE_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10000 {
			cfg.BatchSize = n
			tk.LogIt(tk.LogInfo, "[TraceConfig] BatchSize=%d (from env)\n", n)
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_BATCH_SIZE='%s' (must be 1-10000), using default %d\n",
				v, cfg.BatchSize)
		}
	}

	if v := os.Getenv("LOXILB_TRACE_BATCH_TIMEOUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 100 && n <= 60000 {
			cfg.BatchTimeout = time.Duration(n) * time.Millisecond
			tk.LogIt(tk.LogInfo, "[TraceConfig] BatchTimeout=%dms (from env)\n", n)
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_BATCH_TIMEOUT_MS='%s' (must be 100-60000), using default %dms\n",
				v, cfg.BatchTimeout.Milliseconds())
		}
	}

	if v := os.Getenv("LOXILB_TRACE_EXPORT_RETRIES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 10 {
			cfg.ExportRetries = n
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_EXPORT_RETRIES='%s' (must be 0-10), using default %d\n",
				v, cfg.ExportRetries)
		}
	}

	if v := os.Getenv("LOXILB_TRACE_RETRY_BACKOFF_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 100 && n <= 10000 {
			cfg.RetryBackoffMs = n
		} else {
			tk.LogIt(tk.LogWarning, "[TraceConfig] Invalid LOXILB_TRACE_RETRY_BACKOFF_MS='%s' (must be 100-10000), using default %d\n",
				v, cfg.RetryBackoffMs)
		}
	}

	// Instance ID (for multi-instance deployments like Kubernetes)
	if v := os.Getenv("LOXILB_INSTANCE_ID"); v != "" {
		cfg.InstanceID = v
		tk.LogIt(tk.LogInfo, "[TraceConfig] InstanceID=%s (from env)\n", v)
	}

	// Validate final configuration
	if err := cfg.Validate(); err != nil {
		tk.LogIt(tk.LogError, "[TraceConfig] Validation failed: %v, using defaults\n", err)
		return DefaultTraceConfig()
	}

	// Log final configuration summary
	tk.LogIt(tk.LogInfo, "[TraceConfig] Loaded: BatchSize=%d BatchTimeout=%dms SpanTTL=%ds MaxPending=%d\n",
		cfg.BatchSize, cfg.BatchTimeout.Milliseconds(), int(cfg.SpanTTL.Seconds()), cfg.MaxPendingSpans)

	return cfg
}

// Validate checks configuration constraints and returns error if invalid.
//
// This prevents silent misconfigurations that could cause production issues
// (e.g., negative timeouts, excessive memory usage, invalid batch sizes).
func (cfg *TraceConfig) Validate() error {
	// Ring Buffer Consumer validation
	if cfg.EventChannelSize < 1 || cfg.EventChannelSize > 100000 {
		return fmt.Errorf("EventChannelSize must be 1-100000, got %d", cfg.EventChannelSize)
	}
	if cfg.ConsumerPollMs < 1 || cfg.ConsumerPollMs > 1000 {
		return fmt.Errorf("ConsumerPollMs must be 1-1000, got %d", cfg.ConsumerPollMs)
	}

	// Span Assembler validation
	if cfg.SpanTTL < 10*time.Second || cfg.SpanTTL > 1*time.Hour {
		return fmt.Errorf("SpanTTL must be 10s-1h, got %v", cfg.SpanTTL)
	}
	if cfg.CleanupInterval < 10*time.Second || cfg.CleanupInterval > 10*time.Minute {
		return fmt.Errorf("CleanupInterval must be 10s-10m, got %v", cfg.CleanupInterval)
	}
	if cfg.MaxPendingSpans < 1000 || cfg.MaxPendingSpans > 1000000 {
		return fmt.Errorf("MaxPendingSpans must be 1000-1000000, got %d", cfg.MaxPendingSpans)
	}

	// OTLP Exporter validation
	if cfg.BatchSize < 1 || cfg.BatchSize > 10000 {
		return fmt.Errorf("BatchSize must be 1-10000, got %d", cfg.BatchSize)
	}
	if cfg.BatchTimeout < 100*time.Millisecond || cfg.BatchTimeout > 60*time.Second {
		return fmt.Errorf("BatchTimeout must be 100ms-60s, got %v", cfg.BatchTimeout)
	}
	if cfg.ExportRetries < 0 || cfg.ExportRetries > 10 {
		return fmt.Errorf("ExportRetries must be 0-10, got %d", cfg.ExportRetries)
	}
	if cfg.RetryBackoffMs < 100 || cfg.RetryBackoffMs > 10000 {
		return fmt.Errorf("RetryBackoffMs must be 100-10000, got %d", cfg.RetryBackoffMs)
	}

	// Instance ID validation
	if cfg.InstanceID == "" {
		return fmt.Errorf("InstanceID cannot be empty")
	}

	return nil
}

// String returns human-readable configuration summary for logging.
func (cfg *TraceConfig) String() string {
	return fmt.Sprintf("TraceConfig{EventChan=%d, Poll=%dms, SpanTTL=%ds, BatchSize=%d, BatchTimeout=%dms, Instance=%s}",
		cfg.EventChannelSize, cfg.ConsumerPollMs, int(cfg.SpanTTL.Seconds()),
		cfg.BatchSize, cfg.BatchTimeout.Milliseconds(), cfg.InstanceID)
}
