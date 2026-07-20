/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSlause
 */

package loxinet

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	tk "github.com/loxilb-io/loxilib"
)

// SpanKey uniquely identifies a span
type SpanKey struct {
	TraceIDHi uint64
	TraceIDLo uint64
	SpanID    uint64
}

// PendingSpan tracks an in-progress span
type PendingSpan struct {
	Span      trace.Span
	StartTime time.Time
	Context   context.Context
	Event     *TraceEvent // Original start event for delayed attribute addition
}

// SpanAssembler correlates events into OpenTelemetry spans
//
// Architecture:
// - REQ_START → Create root span (loxilb.http.request)
// - UP_START → Create child span (loxilb.upstream)
// - TLS_HS → Create child span (loxilb.tls.handshake)
// - REQ_END/UP_END → Close corresponding span
// - STREAM_MARK → Add streaming metrics to root span
//
// Memory Management:
// - openSpans map grows with concurrent requests
// - Cleanup goroutine removes stale spans (>5 min TTL)
// - Memory pressure: force close oldest 10% if exceeds limit
type SpanAssembler struct {
	tracer            trace.Tracer
	openSpans         map[SpanKey]*PendingSpan
	mu                sync.RWMutex
	cfg               TraceConfig
	cleanupTicker     *time.Ticker
	stopChan          chan struct{}
	wg                sync.WaitGroup
	tracingCatalogMgr *TracingCatalogManager // Tracing catalog manager for deep inspection
	parserRegistry    *TraceParserRegistry   // Parser registry for payload parsing

	// Statistics
	spansCreated   uint64
	spansCompleted uint64
	spansTimedOut  uint64
}

// NewSpanAssembler creates a span assembler with cleanup goroutine
func NewSpanAssembler(tracer trace.Tracer, cfg TraceConfig, tracingCatalogMgr *TracingCatalogManager, parserRegistry *TraceParserRegistry) *SpanAssembler {
	sa := &SpanAssembler{
		tracer:            tracer,
		openSpans:         make(map[SpanKey]*PendingSpan),
		cfg:               cfg,
		cleanupTicker:     time.NewTicker(cfg.CleanupInterval),
		stopChan:          make(chan struct{}),
		tracingCatalogMgr: tracingCatalogMgr,
		parserRegistry:    parserRegistry,
	}

	// Start cleanup goroutine
	sa.wg.Add(1)
	go sa.cleanupLoop()

	tk.LogIt(tk.LogInfo, "[SpanAssembler] Started (SpanTTL=%ds MaxPending=%d CleanupInterval=%ds)\n",
		int(cfg.SpanTTL.Seconds()), cfg.MaxPendingSpans, int(cfg.CleanupInterval.Seconds()))

	return sa
}

// SetTracer updates the tracer (for OTLP reconnection)
func (sa *SpanAssembler) SetTracer(tracer trace.Tracer) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	sa.tracer = tracer
	tk.LogIt(tk.LogInfo, "[SpanAssembler] Tracer updated for OTLP reconnection\n")
}

// Stop gracefully stops the span assembler
func (sa *SpanAssembler) Stop() {
	close(sa.stopChan)
	sa.wg.Wait()
	sa.cleanupTicker.Stop()

	// Force close all remaining spans
	sa.mu.Lock()
	remaining := len(sa.openSpans)
	for key, pending := range sa.openSpans {
		pending.Span.SetStatus(codes.Error, "shutdown")
		pending.Span.End()
		delete(sa.openSpans, key)
	}
	sa.mu.Unlock()

	tk.LogIt(tk.LogInfo, "[SpanAssembler] Stopped. Created=%d Completed=%d TimedOut=%d Remaining=%d\n",
		sa.spansCreated, sa.spansCompleted, sa.spansTimedOut, remaining)
}

// ProcessEvent processes a trace event and updates spans
func (sa *SpanAssembler) ProcessEvent(evt *TraceEvent) {
	switch evt.EventType {
	case 1: // REQ_START
		sa.handleReqStart(evt)
	case 2: // REQ_END
		sa.handleReqEnd(evt)
	case 3: // UP_START
		sa.handleUpStart(evt)
	case 4: // UP_END
		sa.handleUpEnd(evt)
	case 5: // TLS_HS
		sa.handleTLSHandshake(evt)
	case 6: // STREAM_MARK
		sa.handleStreamMark(evt)
	default:
		tk.LogIt(tk.LogWarning, "[SpanAssembler] Unknown event type: %d\n", evt.EventType)
	}
}

// handleReqStart creates root span for HTTP request
func (sa *SpanAssembler) handleReqStart(evt *TraceEvent) {
	// Check memory pressure before creating new span
	sa.mu.Lock()
	if len(sa.openSpans) >= sa.cfg.MaxPendingSpans {
		tk.LogIt(tk.LogError, "[SpanAssembler] Memory pressure: %d open spans (max=%d), forcing cleanup\n",
			len(sa.openSpans), sa.cfg.MaxPendingSpans)
		sa.forceCloseOldestSpans(len(sa.openSpans) / 10) // Close oldest 10%
	}
	sa.mu.Unlock()

	// Convert trace ID to OpenTelemetry format
	traceID := trace.TraceID{}
	binary.BigEndian.PutUint64(traceID[0:8], evt.TraceIDHi)
	binary.BigEndian.PutUint64(traceID[8:16], evt.TraceIDLo)

	spanID := trace.SpanID{}
	binary.BigEndian.PutUint64(spanID[:], evt.SpanID)

	// Create span context (for W3C Trace Context propagation)
	spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.TraceFlags(evt.Flags & 0x01), // Sampled flag
		Remote:     evt.ParentSpanID != 0,              // Remote if has parent
	})

	// Create root context with span context
	ctx := trace.ContextWithSpanContext(context.Background(), spanCtx)

	// Start root span
	startTime := time.Unix(0, int64(evt.TimestampNs))

	// Determine scheme based on TLS version (0 = HTTP, non-zero = HTTPS)
	scheme := "http"
	if evt.TLSVersion != 0 {
		scheme = "https"
	}

	// Format HTTP version as http.flavor (e.g., "1.1", "2.0")
	httpFlavor := fmt.Sprintf("%d.%d", evt.HTTPMajor, evt.HTTPMinor)

	_, span := sa.tracer.Start(ctx, "loxilb.http.request",
		trace.WithTimestamp(startTime),
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			// HTTP Semantic Conventions (OpenTelemetry)
			attribute.String("http.method", evt.HTTPMethod),
			attribute.String("http.target", evt.HTTPTarget),
			attribute.String("http.host", evt.HTTPHost),
			attribute.String("http.scheme", scheme),
			attribute.String("http.flavor", httpFlavor),
			attribute.Int("http.request.body.size", int(evt.ContentLength)),
			attribute.String("http.request.content_type", evt.ContentType),

			// Network Attributes
			attribute.String("net.peer.ip", ipToString(evt.ClientIP)),
			attribute.Int("net.peer.port", int(evt.ClientPort)),

			// Session Tracking Attributes (for session-level tracing)
			attribute.String("loxilb.session.header_name", evt.SessionHeaderName),
			attribute.String("loxilb.session.header_value", evt.SessionHeaderValue),
			attribute.String("loxilb.session.conversation_id", evt.ConversationID),

			// Service Attributes
			attribute.String("service.name", "loxilb"),
			attribute.Int("loxilb.catalog_id", int(evt.CatalogID)),
		),
	)
	// Add backend attributes if available (indicates connection failure to backend)
	if evt.BackendIP != 0 {
		span.SetAttributes(
			attribute.String("net.peer.backend.ip", ipToString(evt.BackendIP)),
			attribute.Int("net.peer.backend.port", int(evt.BackendPort)),
			attribute.Int("loxilb.backend_id", int(evt.BackendID)),
		)
	}
	// Attach protocol-specific attributes from parser (MCP, OpenAI, etc.)
	if evt.ParsedAttributes != nil && len(evt.ParsedAttributes) > 0 {
		var otlpAttrs []attribute.KeyValue
		for key, value := range evt.ParsedAttributes {
			// Convert parsed attributes to OTLP attributes
			switch v := value.(type) {
			case string:
				otlpAttrs = append(otlpAttrs, attribute.String(key, v))
			case int:
				otlpAttrs = append(otlpAttrs, attribute.Int(key, v))
			case int64:
				otlpAttrs = append(otlpAttrs, attribute.Int64(key, v))
			case float64:
				otlpAttrs = append(otlpAttrs, attribute.Float64(key, v))
			case bool:
				otlpAttrs = append(otlpAttrs, attribute.Bool(key, v))
			default:
				// Fallback to string representation for unknown types
				otlpAttrs = append(otlpAttrs, attribute.String(key, fmt.Sprintf("%v", v)))
			}
		}
		span.SetAttributes(otlpAttrs...)
		tk.LogIt(tk.LogDebug, "[SpanAssembler] Attached %d parsed attributes to span=%x\n",
			len(otlpAttrs), evt.SpanID)
	}

	// Store pending span
	key := SpanKey{
		TraceIDHi: evt.TraceIDHi,
		TraceIDLo: evt.TraceIDLo,
		SpanID:    evt.SpanID,
	}

	sa.mu.Lock()
	sa.openSpans[key] = &PendingSpan{
		Span:      span,
		StartTime: startTime,
		Context:   trace.ContextWithSpan(ctx, span),
		Event:     evt,
	}
	sa.spansCreated++
	sa.mu.Unlock()

	tk.LogIt(tk.LogDebug, "[SpanAssembler] REQ_START: trace=%016x%016x span=%016x method=%s target=%s | ✓ Stored in openSpans[%016x%016x:%016x]\n",
		evt.TraceIDHi, evt.TraceIDLo, evt.SpanID, evt.HTTPMethod, evt.HTTPTarget, key.TraceIDHi, key.TraceIDLo, key.SpanID)
}

// handleReqEnd closes root span with response attributes
func (sa *SpanAssembler) handleReqEnd(evt *TraceEvent) {
	key := SpanKey{
		TraceIDHi: evt.TraceIDHi,
		TraceIDLo: evt.TraceIDLo,
		SpanID:    evt.SpanID,
	}

	sa.mu.Lock()
	pending := sa.openSpans[key]
	delete(sa.openSpans, key)
	sa.mu.Unlock()

	if pending == nil {
		tk.LogIt(tk.LogWarning, "[SpanAssembler] REQ_END without REQ_START: span=%016x\n", evt.SpanID)
		return
	}

	// Add response attributes
	pending.Span.SetAttributes(
		attribute.Int("http.status_code", int(evt.HTTPStatusCode)),
		attribute.Int64("http.response.body.size", int64(evt.ContentLength)),
	)

	// Add backend attributes if available (connection failure case)
	if evt.BackendIP != 0 {
		pending.Span.SetAttributes(
			attribute.String("net.peer.backend.ip", ipToString(evt.BackendIP)),
			attribute.Int("net.peer.backend.port", int(evt.BackendPort)),
			attribute.Int("loxilb.backend_id", int(evt.BackendID)),
		)
	}

	// Set span status based on HTTP status code
	if evt.HTTPStatusCode >= 500 {
		pending.Span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", evt.HTTPStatusCode))
	} else if evt.HTTPStatusCode >= 400 {
		pending.Span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", evt.HTTPStatusCode))
	} else {
		pending.Span.SetStatus(codes.Ok, "")
	}

	// Add error details if present
	if evt.ErrorClass != 0 {
		pending.Span.SetAttributes(
			attribute.Int("loxilb.error_class", int(evt.ErrorClass)),
			attribute.Int("loxilb.error_code", int(evt.ErrorCode)),
		)
	}

	// Deep inspection: Enrich span with payload data if available
	// Use the original REQ_START event (pending.Event) which has the HTTP method,
	// but merge in the status code and content length from REQ_END
	enrichEvent := *pending.Event // Copy the start event
	enrichEvent.HTTPStatusCode = evt.HTTPStatusCode
	enrichEvent.ContentLength = evt.ContentLength
	// CRITICAL FIX: Body file info comes from REQ_START, NOT REQ_END
	// Only overwrite if REQ_END explicitly has body info (fallback case)
	if evt.HasBodyFile && evt.BodyFilePath != "" {
		enrichEvent.HasBodyFile = evt.HasBodyFile
		enrichEvent.BodyFilePath = evt.BodyFilePath
	}
	// Otherwise keep REQ_START's body file info (pending.Event already has it)
	EnrichSpanWithPayload(&enrichEvent, pending.Span, sa.tracingCatalogMgr, sa.parserRegistry)

	// End span with accurate timestamp
	endTime := time.Unix(0, int64(evt.TimestampNs))
	pending.Span.End(trace.WithTimestamp(endTime))

	sa.spansCompleted++

	tk.LogIt(tk.LogDebug, "[SpanAssembler] REQ_END: trace=%016x%016x duration=%dus status=%d\n",
		evt.TraceIDHi, evt.TraceIDLo, evt.DurationUs, evt.HTTPStatusCode)
}

// handleUpStart creates child span for upstream connection
func (sa *SpanAssembler) handleUpStart(evt *TraceEvent) {
	// Find parent span (root span)
	parentKey := SpanKey{
		TraceIDHi: evt.TraceIDHi,
		TraceIDLo: evt.TraceIDLo,
		SpanID:    evt.ParentSpanID,
	}

	sa.mu.RLock()
	parent := sa.openSpans[parentKey]
	mapSize := len(sa.openSpans)
	sa.mu.RUnlock()

	if parent == nil {
		tk.LogIt(tk.LogWarning, "[SpanAssembler] UP_START without parent span: parent=%016x | ✗ Lookup key[%016x%016x:%016x] not found in openSpans (size=%d)\n",
			evt.ParentSpanID, parentKey.TraceIDHi, parentKey.TraceIDLo, parentKey.SpanID, mapSize)
		return
	}

	tk.LogIt(tk.LogDebug, "[SpanAssembler] UP_START: trace=%016x%016x span=%016x parent=%016x | ✓ Found parent in openSpans\n",
		evt.TraceIDHi, evt.TraceIDLo, evt.SpanID, evt.ParentSpanID)

	// Debug: Log ALL IP/port fields from event
	tk.LogIt(tk.LogDebug, "[SpanAssembler] UP_START_DEBUG: client=%s:%d backend=%s:%d\n",
		ipToString(evt.ClientIP), evt.ClientPort,
		ipToString(evt.BackendIP), evt.BackendPort)

	// Start upstream span
	startTime := time.Unix(0, int64(evt.TimestampNs))

	_, span := sa.tracer.Start(parent.Context, "loxilb.upstream",
		trace.WithTimestamp(startTime),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("net.peer.ip", ipToString(evt.BackendIP)),
			attribute.Int("net.peer.port", int(evt.BackendPort)),
			attribute.Int("loxilb.catalog_id", int(evt.CatalogID)),
		),
	)

	// Store pending span
	key := SpanKey{
		TraceIDHi: evt.TraceIDHi,
		TraceIDLo: evt.TraceIDLo,
		SpanID:    evt.SpanID,
	}

	sa.mu.Lock()
	sa.openSpans[key] = &PendingSpan{
		Span:      span,
		StartTime: startTime,
		Context:   trace.ContextWithSpan(parent.Context, span),
		Event:     evt,
	}
	sa.spansCreated++
	sa.mu.Unlock()

	tk.LogIt(tk.LogDebug, "[SpanAssembler] UP_START: span=%016x backend=%s:%d\n",
		evt.SpanID, ipToString(evt.BackendIP), evt.BackendPort)
}

// handleUpEnd closes upstream span
func (sa *SpanAssembler) handleUpEnd(evt *TraceEvent) {
	key := SpanKey{
		TraceIDHi: evt.TraceIDHi,
		TraceIDLo: evt.TraceIDLo,
		SpanID:    evt.SpanID,
	}

	sa.mu.Lock()
	pending := sa.openSpans[key]
	delete(sa.openSpans, key)
	sa.mu.Unlock()

	if pending == nil {
		// UP_END without UP_START can happen if backend closes immediately
		tk.LogIt(tk.LogDebug, "[SpanAssembler] UP_END without UP_START: span=%016x\n", evt.SpanID)
		return
	}

	// Set status
	if evt.ErrorClass != 0 {
		pending.Span.SetStatus(codes.Error, fmt.Sprintf("error_class=%d error_code=%d", evt.ErrorClass, evt.ErrorCode))
		pending.Span.SetAttributes(
			attribute.Int("loxilb.error_class", int(evt.ErrorClass)),
			attribute.Int("loxilb.error_code", int(evt.ErrorCode)),
		)
	} else {
		pending.Span.SetStatus(codes.Ok, "")
	}

	// End span
	endTime := time.Unix(0, int64(evt.TimestampNs))
	pending.Span.End(trace.WithTimestamp(endTime))

	sa.spansCompleted++

	tk.LogIt(tk.LogDebug, "[SpanAssembler] UP_END: span=%016x duration=%dus\n", evt.SpanID, evt.DurationUs)
}

// handleTLSHandshake creates child span for TLS handshake
func (sa *SpanAssembler) handleTLSHandshake(evt *TraceEvent) {
	// Find parent span (may be root or upstream)
	parentKey := SpanKey{
		TraceIDHi: evt.TraceIDHi,
		TraceIDLo: evt.TraceIDLo,
		SpanID:    evt.ParentSpanID,
	}

	sa.mu.RLock()
	parent := sa.openSpans[parentKey]
	sa.mu.RUnlock()

	var parentCtx context.Context
	if parent != nil {
		parentCtx = parent.Context
	} else {
		// TLS handshake may happen before REQ_START, use background context
		parentCtx = context.Background()
	}

	// TLS_HS is a completed event (has duration), so create+end immediately
	startTime := time.Unix(0, int64(evt.TimestampNs-uint64(evt.DurationUs)*1000))
	endTime := time.Unix(0, int64(evt.TimestampNs))

	// Determine if frontend or backend TLS
	spanName := "loxilb.tls.handshake.frontend"
	if evt.Flags&0x04 != 0 { // LXB_FLAG_TLS_BACKEND
		spanName = "loxilb.tls.handshake.backend"
	}

	_, span := sa.tracer.Start(parentCtx, spanName,
		trace.WithTimestamp(startTime),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("tls.version", tlsVersionName(evt.TLSVersion)),
			attribute.String("tls.cipher", tlsCipherName(evt.TLSCipher)),
			attribute.Int("tls.version_code", int(evt.TLSVersion)),
			attribute.Int("tls.cipher_code", int(evt.TLSCipher)),
		),
	)

	// Set status
	if evt.ErrorClass != 0 {
		span.SetStatus(codes.Error, fmt.Sprintf("tls_error_class=%d error_code=%d", evt.ErrorClass, evt.ErrorCode))
		span.SetAttributes(
			attribute.Int("loxilb.error_class", int(evt.ErrorClass)),
			attribute.Int("loxilb.error_code", int(evt.ErrorCode)),
		)
	} else {
		span.SetStatus(codes.Ok, "")
	}

	// End span immediately (TLS_HS is a single event)
	span.End(trace.WithTimestamp(endTime))

	sa.spansCreated++
	sa.spansCompleted++

	tk.LogIt(tk.LogDebug, "[SpanAssembler] TLS_HS: span=%016x version=%s cipher=0x%04x duration=%dus\n",
		evt.SpanID, tlsVersionName(evt.TLSVersion), evt.TLSCipher, evt.DurationUs)
}

// handleStreamMark adds streaming metrics to parent span
func (sa *SpanAssembler) handleStreamMark(evt *TraceEvent) {
	// Find parent span
	key := SpanKey{
		TraceIDHi: evt.TraceIDHi,
		TraceIDLo: evt.TraceIDLo,
		SpanID:    evt.ParentSpanID,
	}

	sa.mu.RLock()
	pending := sa.openSpans[key]
	sa.mu.RUnlock()

	if pending == nil {
		tk.LogIt(tk.LogDebug, "[SpanAssembler] STREAM_MARK without parent span: parent=%016x\n", evt.ParentSpanID)
		return
	}

	// Add streaming metrics (extracted from body_file_path or tags)
	pending.Span.AddEvent("streaming.chunk",
		trace.WithTimestamp(time.Unix(0, int64(evt.TimestampNs))),
		trace.WithAttributes(
			attribute.Int("chunk.bytes", int(evt.ContentLength)),
			attribute.Int("chunk.duration_us", int(evt.DurationUs)),
		),
	)

	tk.LogIt(tk.LogDebug, "[SpanAssembler] STREAM_MARK: parent=%016x bytes=%d\n", evt.ParentSpanID, evt.ContentLength)
}

// cleanupLoop removes stale spans periodically
func (sa *SpanAssembler) cleanupLoop() {
	defer sa.wg.Done()

	for {
		select {
		case <-sa.cleanupTicker.C:
			sa.cleanupStaleSpans()
		case <-sa.stopChan:
			return
		}
	}
}

// cleanupStaleSpans removes spans older than SpanTTL
func (sa *SpanAssembler) cleanupStaleSpans() {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for key, pending := range sa.openSpans {
		age := now.Sub(pending.StartTime)

		if age > sa.cfg.SpanTTL {
			// Span incomplete after TTL, force close with error
			pending.Span.SetStatus(codes.Error, "span_timeout")
			pending.Span.SetAttributes(
				attribute.Bool("span.incomplete", true),
				attribute.Int64("span.age_sec", int64(age.Seconds())),
			)
			pending.Span.End()

			delete(sa.openSpans, key)
			cleaned++
			sa.spansTimedOut++
		}
	}

	if cleaned > 0 {
		tk.LogIt(tk.LogWarning, "[SpanAssembler] Cleaned %d stale spans (TTL=%ds, total_open=%d)\n",
			cleaned, int(sa.cfg.SpanTTL.Seconds()), len(sa.openSpans))
	}
}

// forceCloseOldestSpans closes N oldest spans (called under lock)
func (sa *SpanAssembler) forceCloseOldestSpans(count int) {
	// Sort spans by age
	type spanAge struct {
		key SpanKey
		age time.Duration
	}

	ages := make([]spanAge, 0, len(sa.openSpans))
	now := time.Now()

	for key, pending := range sa.openSpans {
		ages = append(ages, spanAge{key, now.Sub(pending.StartTime)})
	}

	// Simple sort (oldest first)
	for i := 0; i < len(ages)-1; i++ {
		for j := i + 1; j < len(ages); j++ {
			if ages[j].age > ages[i].age {
				ages[i], ages[j] = ages[j], ages[i]
			}
		}
	}

	// Force close oldest N spans
	closed := 0
	for i := 0; i < count && i < len(ages); i++ {
		pending := sa.openSpans[ages[i].key]
		pending.Span.SetStatus(codes.Error, "memory_pressure")
		pending.Span.SetAttributes(
			attribute.Bool("span.force_closed", true),
			attribute.Int64("span.age_sec", int64(ages[i].age.Seconds())),
		)
		pending.Span.End()
		delete(sa.openSpans, ages[i].key)
		closed++
	}

	tk.LogIt(tk.LogError, "[SpanAssembler] Force closed %d oldest spans due to memory pressure\n", closed)
}

// GetPendingCount returns number of open spans
func (sa *SpanAssembler) GetPendingCount() int {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	return len(sa.openSpans)
}

// Helper: Convert IPv4 uint32 to string
func ipToString(ip uint32) string {
	// IP addresses from C are in network byte order (big-endian)
	// We need to convert to host byte order for correct display
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}

// Helper: TLS version name
func tlsVersionName(ver uint16) string {
	switch ver {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", ver)
	}
}

// Helper: TLS cipher name (subset)
func tlsCipherName(cipher uint16) string {
	switch cipher {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0xC02F:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0xC030:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	default:
		return fmt.Sprintf("0x%04x", cipher)
	}
}
