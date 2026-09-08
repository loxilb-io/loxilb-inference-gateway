/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSlause
 */

package loxinet

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/loxilb-io/loxilb/api/restapi/handler"
	tk "github.com/loxilb-io/loxilib"
)

// connectionTrackingExporter wraps an OpenTelemetry exporter to track connection status
type connectionTrackingExporter struct {
	inner sdktrace.SpanExporter
}

// ExportSpans implements sdktrace.SpanExporter interface
func (e *connectionTrackingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := e.inner.ExportSpans(ctx, spans)
	if err != nil {
		// Export failed - mark as disconnected
		handler.SetOtlpConnected(false)
		tk.LogIt(tk.LogError, "[OTLP] Export failed, marking as disconnected: %v\n", err)
	} else {
		// Export succeeded - mark as connected
		handler.SetOtlpConnected(true)
		tk.LogIt(tk.LogInfo, "[OTLP] Successfully exported %d spans to collector\n", len(spans))
	}
	return err
}

// Shutdown implements sdktrace.SpanExporter interface
func (e *connectionTrackingExporter) Shutdown(ctx context.Context) error {
	return e.inner.Shutdown(ctx)
}

// CircuitBreakerState represents circuit breaker states
type CircuitBreakerState int32

const (
	CircuitClosed   CircuitBreakerState = 0 // Normal operation
	CircuitOpen     CircuitBreakerState = 1 // Failing, drop exports
	CircuitHalfOpen CircuitBreakerState = 2 // Testing recovery
)

// OTLPCircuitBreaker implements circuit breaker pattern for OTLP exports
//
// Protection:
// - Opens after 5 consecutive failures → drops all exports
// - Waits 30 seconds → transitions to HalfOpen
// - HalfOpen allows 1 test export → Close on success, reopen on failure
//
// This prevents cascading failures when Jaeger/OTLP endpoint is unavailable.
type OTLPCircuitBreaker struct {
	state               atomic.Int32
	consecutiveFailures atomic.Int32
	lastFailureTime     atomic.Int64
	failureThreshold    int32
	openTimeout         time.Duration
	mu                  sync.RWMutex
}

// NewOTLPCircuitBreaker creates a circuit breaker with production-grade defaults
func NewOTLPCircuitBreaker() *OTLPCircuitBreaker {
	cb := &OTLPCircuitBreaker{
		failureThreshold: 5,
		openTimeout:      30 * time.Second,
	}
	cb.state.Store(int32(CircuitClosed))
	return cb
}

// AllowExport checks if export is allowed based on circuit state
func (cb *OTLPCircuitBreaker) AllowExport() bool {
	state := CircuitBreakerState(cb.state.Load())

	switch state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if timeout elapsed
		lastFailure := time.Unix(cb.lastFailureTime.Load(), 0)
		if time.Since(lastFailure) > cb.openTimeout {
			// Transition to HalfOpen for test
			if cb.state.CompareAndSwap(int32(CircuitOpen), int32(CircuitHalfOpen)) {
				tk.LogIt(tk.LogInfo, "[CircuitBreaker] State: HALF_OPEN (testing recovery)\n")
			}
			return true // Allow test export
		}
		return false // Still open, drop exports
	case CircuitHalfOpen:
		return true // Allow test export
	default:
		return false
	}
}

// RecordFailure records export failure and may open circuit
func (cb *OTLPCircuitBreaker) RecordFailure() {
	failures := cb.consecutiveFailures.Add(1)
	cb.lastFailureTime.Store(time.Now().Unix())

	if failures >= cb.failureThreshold {
		if cb.state.CompareAndSwap(int32(CircuitClosed), int32(CircuitOpen)) ||
			cb.state.CompareAndSwap(int32(CircuitHalfOpen), int32(CircuitOpen)) {
			tk.LogIt(tk.LogError, "[CircuitBreaker] State: OPEN (failures: %d)\n", failures)
		}
	}
}

// RecordSuccess records export success and may close circuit
func (cb *OTLPCircuitBreaker) RecordSuccess() {
	cb.consecutiveFailures.Store(0)

	// Close circuit if in HalfOpen state
	if cb.state.CompareAndSwap(int32(CircuitHalfOpen), int32(CircuitClosed)) {
		tk.LogIt(tk.LogInfo, "[CircuitBreaker] State: CLOSED (recovered)\n")
	}
}

// GetState returns current circuit state (for monitoring)
func (cb *OTLPCircuitBreaker) GetState() CircuitBreakerState {
	return CircuitBreakerState(cb.state.Load())
}

// GetFailureCount returns consecutive failure count
func (cb *OTLPCircuitBreaker) GetFailureCount() int32 {
	return cb.consecutiveFailures.Load()
}

// OTLPExporter manages OpenTelemetry OTLP export with fault tolerance
type OTLPExporter struct {
	tracerProvider *sdktrace.TracerProvider
	exporter       sdktrace.SpanExporter
	circuitBreaker *OTLPCircuitBreaker
	cfg            TraceConfig

	// Statistics (atomic for thread-safety)
	spansExported atomic.Uint64
	spansFailed   atomic.Uint64
	spansDropped  atomic.Uint64
	exportCount   atomic.Uint64

	mu sync.RWMutex
}

// NewOTLPExporter creates OTLP exporter with secure configuration
//
// Integration with REST API:
// - Retrieves OTLP config via handler.GetOtlpConfig
// - Supports TLS encryption (default: enabled)
// - Supports custom authentication headers
// - Updates connection status via handler.SetOtlpConnected
//
// Returns TracerProvider for span creation.
func NewOTLPExporter() (*OTLPExporter, error) {
	// Get configuration REST API handler
	otlpCfg := handler.GetOtlpConfig()
	traceCfg := LoadTraceConfig()

	tk.LogIt(tk.LogInfo, "[OTLP] Initializing exporter: endpoint=%s protocol=%s tls=%v\n",
		otlpCfg.Endpoint, otlpCfg.Protocol, otlpCfg.UseTLS)

	// Create OTLP span exporter based on protocol
	var exporter sdktrace.SpanExporter
	var err error

	switch otlpCfg.Protocol {
	case "grpc":
		exporter, err = createGRPCExporter(otlpCfg)
	case "http":
		exporter, err = createHTTPExporter(otlpCfg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s (must be 'grpc' or 'http')", otlpCfg.Protocol)
	}

	if err != nil {
		handler.SetOtlpConnected(false)
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Wrap exporter to track connection status
	wrappedExporter := &connectionTrackingExporter{
		inner: exporter,
	}

	// Create resource with service metadata
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName("loxilb"),
			semconv.ServiceVersion("1.0.0"), // TODO: Get from build metadata
			semconv.ServiceInstanceID(traceCfg.InstanceID),
		),
	)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[OTLP] Failed to create resource: %v, using default\n", err)
		res = resource.Default()
	}

	// Create tracer provider with batch processor
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(wrappedExporter,
			sdktrace.WithMaxExportBatchSize(traceCfg.BatchSize), // Default: 512
			sdktrace.WithBatchTimeout(traceCfg.BatchTimeout),    // Default: 5s
			sdktrace.WithExportTimeout(30*time.Second),          // Hard timeout
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()), // Sampling decision already made in C dataplane
	)

	// Set as global tracer provider
	otel.SetTracerProvider(tp)

	// Start with disconnected state - will be set to true after first successful export
	handler.SetOtlpConnected(false)

	oe := &OTLPExporter{
		tracerProvider: tp,
		exporter:       exporter,
		circuitBreaker: NewOTLPCircuitBreaker(),
		cfg:            traceCfg,
	}

	tk.LogIt(tk.LogInfo, "[OTLP] TracerProvider initialized: batch_size=%d batch_timeout=%dms instance=%s\n",
		traceCfg.BatchSize, traceCfg.BatchTimeout.Milliseconds(), traceCfg.InstanceID)

	// Log security warnings
	if otlpCfg.UseTLS && otlpCfg.TLSSkipVerify {
		tk.LogIt(tk.LogWarning, "[OTLP] TLS certificate verification disabled - INSECURE\n")
	}
	if !otlpCfg.UseTLS {
		tk.LogIt(tk.LogWarning, "[OTLP] TLS encryption disabled - INSECURE\n")
	}

	return oe, nil
}

// exportableHeaders drops headers whose value is empty: an empty value
// marks a document-declared header whose secret is not provisioned on
// this node (restore re-join miss) — the NAME must stay in desired state,
// but sending an empty credential to the collector helps nobody.
func exportableHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, v := range headers {
		if v != "" {
			out[name] = v
		}
	}
	return out
}

// createGRPCExporter creates OTLP/gRPC exporter with TLS and auth
func createGRPCExporter(cfg handler.OtlpConfig) (sdktrace.SpanExporter, error) {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithHeaders(exportableHeaders(cfg.Headers)),
	}

	// TLS configuration
	if cfg.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12, // Enforce TLS 1.2+
		}
		opts = append(opts, otlptracegrpc.WithTLSCredentials(
			credentials.NewTLS(tlsConfig),
		))
	} else {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	// Additional gRPC options for production
	// Note: Conservative keepalive settings to avoid "too_many_pings" errors
	// Most OTLP servers (Jaeger, Tempo) expect keepalive intervals >= 60s
	opts = append(opts, otlptracegrpc.WithDialOption(
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                120 * time.Second, // Send keepalive pings every 120s (doubled from 60s)
			Timeout:             30 * time.Second,  // Wait 30s for keepalive response
			PermitWithoutStream: false,             // Only send pings when there are active streams
		}),
	))

	// Connection pooling: keep connection alive longer to reuse it
	opts = append(opts, otlptracegrpc.WithDialOption(
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(10*1024*1024), // 10 MB max message size
		),
	))

	return otlptracegrpc.New(context.Background(), opts...)
}

// createHTTPExporter creates OTLP/HTTP exporter with TLS and auth
func createHTTPExporter(cfg handler.OtlpConfig) (sdktrace.SpanExporter, error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.Endpoint),
		otlptracehttp.WithHeaders(exportableHeaders(cfg.Headers)),
	}

	// TLS configuration
	if cfg.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		opts = append(opts, otlptracehttp.WithTLSClientConfig(tlsConfig))
	} else {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	return otlptracehttp.New(context.Background(), opts...)
}

// Shutdown gracefully shuts down the OTLP exporter
func (oe *OTLPExporter) Shutdown(ctx context.Context) error {
	tk.LogIt(tk.LogInfo, "[OTLP] Shutting down exporter (exported=%d failed=%d dropped=%d)\n",
		oe.spansExported.Load(), oe.spansFailed.Load(), oe.spansDropped.Load())

	// Flush pending spans with timeout
	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := oe.tracerProvider.ForceFlush(flushCtx); err != nil {
		tk.LogIt(tk.LogWarning, "[OTLP] ForceFlush failed: %v\n", err)
	}

	// Shutdown tracer provider (closes exporter)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := oe.tracerProvider.Shutdown(shutdownCtx); err != nil {
		tk.LogIt(tk.LogError, "[OTLP] Shutdown failed: %v\n", err)
		return err
	}

	handler.SetOtlpConnected(false)
	return nil
}

// GetTracerProvider returns the OpenTelemetry tracer provider
func (oe *OTLPExporter) GetTracerProvider() *sdktrace.TracerProvider {
	return oe.tracerProvider
}

// GetTracer returns a named tracer
func (oe *OTLPExporter) GetTracer(name string) trace.Tracer {
	return oe.tracerProvider.Tracer(name)
}

// GetStats returns exporter statistics
func (oe *OTLPExporter) GetStats() OTLPExporterStats {
	return OTLPExporterStats{
		SpansExported:    oe.spansExported.Load(),
		SpansFailed:      oe.spansFailed.Load(),
		SpansDropped:     oe.spansDropped.Load(),
		ExportCount:      oe.exportCount.Load(),
		CircuitState:     oe.circuitBreaker.GetState(),
		ConsecutiveFails: oe.circuitBreaker.GetFailureCount(),
	}
}

// OTLPExporterStats holds exporter statistics
type OTLPExporterStats struct {
	SpansExported    uint64
	SpansFailed      uint64
	SpansDropped     uint64
	ExportCount      uint64
	CircuitState     CircuitBreakerState
	ConsecutiveFails int32
}

// isRetryableError checks if error is transient and retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()

	// Network errors (retryable)
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"503 Service Unavailable",
		"502 Bad Gateway",
		"504 Gateway Timeout",
		"429 Too Many Requests",
		"UNAVAILABLE",
		"DEADLINE_EXCEEDED",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(strings.ToLower(errMsg), strings.ToLower(pattern)) {
			return true
		}
	}

	// Non-retryable errors
	nonRetryablePatterns := []string{
		"401 Unauthorized",
		"403 Forbidden",
		"400 Bad Request",
		"invalid argument",
		"INVALID_ARGUMENT",
		"UNAUTHENTICATED",
		"PERMISSION_DENIED",
	}

	for _, pattern := range nonRetryablePatterns {
		if strings.Contains(strings.ToLower(errMsg), strings.ToLower(pattern)) {
			return false
		}
	}

	// Default: retry unknown errors
	return true
}

// logExportError logs export errors with appropriate severity
func (oe *OTLPExporter) logExportError(err error, attempt int, maxRetries int) {
	if isRetryableError(err) {
		if attempt < maxRetries {
			tk.LogIt(tk.LogWarning, "[OTLP] Export failed (attempt %d/%d): %v\n", attempt, maxRetries, err)
		} else {
			tk.LogIt(tk.LogError, "[OTLP] Export failed after %d retries: %v\n", maxRetries, err)
		}
	} else {
		tk.LogIt(tk.LogError, "[OTLP] Export failed (non-retryable): %v\n", err)
	}
}

// CircuitStateName returns human-readable circuit state name
func CircuitStateName(state CircuitBreakerState) string {
	switch state {
	case CircuitClosed:
		return "CLOSED"
	case CircuitOpen:
		return "OPEN"
	case CircuitHalfOpen:
		return "HALF_OPEN"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}
