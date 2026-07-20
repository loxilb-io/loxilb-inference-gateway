//go:build l4trace
// +build l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * L4 Connection Tracing: Span Assembler
 *
 * This component tracks L4 connection lifecycle from NEW → EST → CLOSE/ERROR
 * and assembles complete OTLP spans with connection-level metrics.
 */

package loxinet

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	tk "github.com/loxilb-io/loxilib"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// Protocol constants (IANA assigned numbers)
	IPPROTO_TCP  = 6
	IPPROTO_UDP  = 17
	IPPROTO_SCTP = 132
)

const (
	// Span assembly configuration
	L4_SPAN_TABLE_SIZE       = 65536            // Max concurrent connections tracked
	L4_SPAN_CLEANUP_INTERVAL = 60 * time.Second // Cleanup stale spans
	L4_SPAN_TIMEOUT          = 5 * time.Minute  // Span timeout (no updates)

	// Production features
	L4_PERIODIC_EXPORT_INTERVAL = 5 * time.Minute  // Export long-lived connections
	L4_BATCH_EXPORT_SIZE        = 100              // Max spans to batch
	L4_BATCH_EXPORT_TIMEOUT     = 10 * time.Second // Max wait before flushing batch
	L4_MAX_RETRY_ATTEMPTS       = 5                // Max retry attempts
	L4_INITIAL_RETRY_DELAY      = 1 * time.Second  // Initial retry delay (exponential backoff)
)

// L4 connection states (must match eBPF definitions)
// NOTE: Only states actually used in Go layer error detection are defined here.
// BPF layer tracks full state machine, but Go only needs states for error detection.
const (
	// TCP states (used for handshake failure detection and state display)
	CT_TCP_CLOSED = 0x0 // CLOSED - Used to detect orphaned handshake failures
	CT_TCP_SS     = 0x1 // SYN_SENT - Used for SYN_SENT→CLOSED detection (connection refused)
	CT_TCP_SA     = 0x2 // SYN_ACK - Used for SYN_ACK→CLOSED detection
	CT_TCP_EST    = 0x4 // ESTABLISHED - Used to mark connection as established
	// Note: CT_TCP_PEST (0x200) exists in eBPF but overflows uint8 ring buffer
	CT_TCP_FINI  = 0x10 // FIN_WAIT_1 - FIN sent, waiting for ACK
	CT_TCP_FINI2 = 0x20 // FIN_WAIT_2 - FIN acknowledged, waiting for peer FIN
	CT_TCP_FINI3 = 0x40 // CLOSING - Both FINs exchanged
	CT_TCP_CW    = 0x80 // CLOSE_WAIT - Used for RST detection

	// SCTP states (used for handshake failure detection)
	// CRITICAL: uint8 limitation means states > 255 will be truncated!
	// Use error_code field instead of state for SCTP error detection.
	CT_SCTP_CLOSED = 0x0  // CLOSED (0) - Used to detect orphaned handshake failures
	CT_SCTP_INIT   = 0x1  // INIT (1) - Used for INIT→CLOSED detection
	CT_SCTP_INITA  = 0x2  // INIT_ACK (2) - Used for INIT_ACK→CLOSED detection (0x9 variant)
	CT_SCTP_COOKIE = 0x4  // COOKIE_ECHO (4) - Used for COOKIE→CLOSED detection
	CT_SCTP_EST    = 0x40 // ESTABLISHED (64) - Used to mark connection as established
	CT_SCTP_SHUT   = 0x80 // SHUTDOWN (128) - Used for graceful shutdown detection

	// UDP states (basic tracking only)
	CT_UDP_EST = 0x2 // Established - Used to mark connection as established
)

// L4 event types (must match eBPF definitions)
const (
	LXB_L4_EVENT_CONN_NEW     = 10
	LXB_L4_EVENT_STATE_CHANGE = 11
	LXB_L4_EVENT_CONN_CLOSE   = 12
	LXB_L4_EVENT_CONN_TIMEOUT = 13
	LXB_L4_EVENT_CONN_RESET   = 14
	LXB_L4_EVENT_CONN_ERROR   = 15
)

// L4 error code constants (must match eBPF definitions)
const (
	LXB_L4_ERROR_NONE                = 0
	LXB_L4_ERROR_RST_CLIENT          = 1
	LXB_L4_ERROR_RST_SERVER          = 2
	LXB_L4_ERROR_SCTP_ABORT          = 3
	LXB_L4_ERROR_CT_TIMEOUT          = 4
	LXB_L4_ERROR_MAP_FULL            = 5
	LXB_L4_ERROR_SYN_TIMEOUT         = 6
	LXB_L4_ERROR_SCTP_HANDSHAKE_FAIL = 7 // SCTP handshake failed (INIT->CLOSED)

	// Backend/Network Error Codes (Pre-CT failures)
	LXB_L4_ERROR_NO_BACKEND      = 10 // No healthy backend available
	LXB_L4_ERROR_BACKEND_DOWN    = 11 // Backend marked down by health check
	LXB_L4_ERROR_BACKEND_REFUSED = 12 // Connection refused by backend
	LXB_L4_ERROR_NO_ROUTE        = 13 // No route to backend
	LXB_L4_ERROR_BACKEND_TIMEOUT = 14 // Backend connection timeout
	LXB_L4_ERROR_PORT_MISMATCH   = 15 // Backend port misconfiguration
	LXB_L4_ERROR_LB_FAILURE      = 16 // Load balancer selection failed
	LXB_L4_ERROR_NAT_FAILURE     = 17 // NAT transformation failed
)

// L4 event flag constants (must match eBPF definitions)
const (
	LXB_L4_FLAG_SAMPLED           = 0x01
	LXB_L4_FLAG_ERROR             = 0x02
	LXB_L4_FLAG_NAT_APPLIED       = 0x04
	LXB_L4_FLAG_TRACED            = 0x08
	LXB_L4_FLAG_BACKEND_SELECTED  = 0x10
	LXB_L4_FLAG_BACKEND_UNHEALTHY = 0x20
	LXB_L4_FLAG_PRECT_FAILURE     = 0x40
)

// L4 sampling algorithm constants (must match eBPF definitions)
const (
	LXB_L4_SAMPLING_NONE       = 0 // Trace all (100%)
	LXB_L4_SAMPLING_RANDOM     = 1 // Random sampling
	LXB_L4_SAMPLING_HASH_BASED = 2 // Hash-based deterministic
	LXB_L4_SAMPLING_ADAPTIVE   = 3 // Adaptive based on load
)

// L4ConnectionSpan tracks a single connection's lifecycle
type L4ConnectionSpan struct {
	SpanID   uint64
	Protocol uint8
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Zone     uint16

	// Backend Selection (Load Balancer)
	BackendIP   string
	BackendPort uint16
	BackendID   uint16

	// Lifecycle timestamps
	StartTime  time.Time
	LastUpdate time.Time
	EndTime    time.Time

	// State tracking
	CurrentState    uint8
	PrevState       uint8
	InitialState    uint8 // Track very first state (never changes)
	IsEstablished   bool
	IsClosed        bool
	TransitionCount uint32

	// Traffic statistics
	TotalBytesSent   uint64
	TotalBytesRecv   uint64
	TotalPacketsSent uint64
	TotalPacketsRecv uint64

	// Performance metrics
	MinRTT           uint32
	MaxRTT           uint32
	AvgRTT           uint32
	RTTCount         uint32
	TotalRetransSent uint32
	TotalRetransRecv uint32
	MaxWindowSize    uint32

	// TCP Specific
	TCPFlags uint8
	MSS      uint32

	// Error tracking
	ErrorCode  uint8
	ErrorCount uint32
	HasError   bool // Connection had error/reset/timeout

	// Event flags
	Flags uint8

	// OTLP trace context
	TraceSpan trace.Span

	// Track last export for periodic updates
	LastExport time.Time
}

// connectionKey represents a 5-tuple for bidirectional flow matching
type connectionKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// clientEndpointKey represents client-side endpoint for NAT correlation
type clientEndpointKey struct {
	IP    string
	Port  uint16
	Proto uint8
}

// L4SpanAssembler assembles connection lifecycle spans from events
type L4SpanAssembler struct {
	spans      map[uint64]*L4ConnectionSpan // span_id -> span
	connKeys   map[connectionKey]uint64     // connection 5-tuple -> span_id (bidirectional)
	clientKeys map[clientEndpointKey]uint64 // client endpoint -> span_id (for NAT correlation)
	spanMutex  sync.RWMutex

	EventChan chan *L4TraceEvent
	stopChan  chan struct{}
	wg        sync.WaitGroup

	// OTLP tracer
	tracer trace.Tracer

	// Statistics
	totalSpans   uint64
	activeSpans  uint64
	closedSpans  uint64
	errorSpans   uint64
	timeoutSpans uint64

	// Memory leak prevention counters (for production monitoring)
	orphanedConnKeys   uint64 // Cleaned up orphaned connKeys entries
	orphanedClientKeys uint64 // Cleaned up orphaned clientKeys entries
	lateEvents         uint64 // Late error/close events ignored (no active span)

	// Batching and retry
	spanBatch      []*L4ConnectionSpan
	batchMutex     sync.Mutex
	batchTimer     *time.Timer
	retryQueue     []*L4ConnectionSpan
	retryMutex     sync.Mutex
	exportFailures uint64
	exportRetries  uint64
}

// NewL4SpanAssembler creates a new span assembler
func NewL4SpanAssembler(eventChan chan *L4TraceEvent) *L4SpanAssembler {
	tk.LogIt(tk.LogInfo, "[L4_SPAN_ASSEMBLER] Creating L4 span assembler\n")

	tracer := otel.Tracer("loxilb-l4-tracer")

	return &L4SpanAssembler{
		spans:      make(map[uint64]*L4ConnectionSpan, L4_SPAN_TABLE_SIZE),
		connKeys:   make(map[connectionKey]uint64, L4_SPAN_TABLE_SIZE*2),   // 2x for forward+reverse
		clientKeys: make(map[clientEndpointKey]uint64, L4_SPAN_TABLE_SIZE), // Client endpoint tracking
		EventChan:  eventChan,
		stopChan:   make(chan struct{}),
		tracer:     tracer,
		spanBatch:  make([]*L4ConnectionSpan, 0, L4_BATCH_EXPORT_SIZE),
		retryQueue: make([]*L4ConnectionSpan, 0),
	}
}

// SetTracer updates the tracer (for OTLP reconnection)
func (sa *L4SpanAssembler) SetTracer(tracer trace.Tracer) {
	sa.spanMutex.Lock()
	defer sa.spanMutex.Unlock()
	sa.tracer = tracer
	tk.LogIt(tk.LogInfo, "[L4SpanAssembler] Tracer updated for OTLP reconnection\n")
}

// Start begins processing events
func (sa *L4SpanAssembler) Start() {
	tk.LogIt(tk.LogInfo, "[L4_SPAN_ASSEMBLER] Starting span assembler with production features\n")

	sa.wg.Add(1)
	go sa.eventLoop()

	sa.wg.Add(1)
	go sa.cleanupLoop()

	// Periodic export for long-lived connections
	sa.wg.Add(1)
	go sa.periodicExportLoop()

	// Retry loop for failed exports
	sa.wg.Add(1)
	go sa.retryLoop()
}

// Stop gracefully shuts down the assembler
func (sa *L4SpanAssembler) Stop() {
	tk.LogIt(tk.LogInfo, "[L4_SPAN_ASSEMBLER] Stopping span assembler\n")

	// Signal all goroutines to stop
	close(sa.stopChan)

	// Wait for all goroutines to finish (eventLoop, cleanupLoop, periodicExportLoop, retryLoop)
	// CRITICAL: This prevents goroutine leaks
	sa.wg.Wait()

	// Flush pending batches
	sa.flushBatch()

	// Close all active spans
	sa.spanMutex.Lock()
	openSpans := len(sa.spans)
	for _, span := range sa.spans {
		if !span.IsClosed && span.TraceSpan != nil {
			sa.finalizeSpanWithRetry(span, "assembler_shutdown")
		}
	}
	// Clear all maps to prevent memory leaks
	// CRITICAL: Prevents retaining references to closed spans
	sa.spans = make(map[uint64]*L4ConnectionSpan)
	sa.connKeys = make(map[connectionKey]uint64)
	sa.clientKeys = make(map[clientEndpointKey]uint64)
	sa.spanMutex.Unlock()

	tk.LogIt(tk.LogInfo, "[L4_SPAN_ASSEMBLER] Span assembler stopped (closed_spans=%d open_spans=%d exported=%d failed=%d retried=%d)\n",
		openSpans, sa.closedSpans, sa.exportFailures, sa.exportRetries, openSpans)
}

// eventLoop processes events from ring consumer
func (sa *L4SpanAssembler) eventLoop() {
	defer sa.wg.Done()

	tk.LogIt(tk.LogDebug, "[L4_SPAN_ASSEMBLER] Event loop started\n")

	for {
		select {
		case <-sa.stopChan:
			tk.LogIt(tk.LogDebug, "[L4_SPAN_ASSEMBLER] Event loop stopping\n")
			return
		case event := <-sa.EventChan:
			if event != nil {
				sa.processEvent(event)
			}
		}
	}
}

// makeConnectionKey creates a connection key from event
func makeConnectionKey(event *L4TraceEvent) connectionKey {
	return connectionKey{
		SrcIP:   event.SrcIP.String(),
		DstIP:   event.DstIP.String(),
		SrcPort: event.SrcPort,
		DstPort: event.DstPort,
		Proto:   event.Protocol,
	}
}

// makeReverseKey creates the reverse connection key for bidirectional lookup
func makeReverseKey(key connectionKey) connectionKey {
	return connectionKey{
		SrcIP:   key.DstIP,
		DstIP:   key.SrcIP,
		SrcPort: key.DstPort,
		DstPort: key.SrcPort,
		Proto:   key.Proto,
	}
}

// extractClientEndpointKeysForLookup extracts client endpoint keys for correlation lookup
// Checks both source and destination since client could be in either position:
// - Client→VIP: client is source
// - Backend→Client: client is destination
func extractClientEndpointKeysForLookup(event *L4TraceEvent) []clientEndpointKey {
	return []clientEndpointKey{
		{IP: event.SrcIP.String(), Port: event.SrcPort, Proto: event.Protocol},
		{IP: event.DstIP.String(), Port: event.DstPort, Proto: event.Protocol},
	}
}

// extractClientEndpointKeyForStorage extracts the client endpoint key for span creation
// Only stores source (client IP:port in client→VIP direction) to avoid VIP collision
func extractClientEndpointKeyForStorage(event *L4TraceEvent) clientEndpointKey {
	return clientEndpointKey{
		IP:    event.SrcIP.String(),
		Port:  event.SrcPort,
		Proto: event.Protocol,
	}
}

// findSpanByConnection looks up span using bidirectional 5-tuple matching + client endpoint correlation
func (sa *L4SpanAssembler) findSpanByConnection(event *L4TraceEvent) (*L4ConnectionSpan, bool) {
	// Try direct span ID lookup first
	if span, exists := sa.spans[event.SpanID]; exists {
		return span, true
	}

	// Try forward direction 5-tuple
	forwardKey := makeConnectionKey(event)
	if spanID, exists := sa.connKeys[forwardKey]; exists {
		if span, exists := sa.spans[spanID]; exists {
			tk.LogIt(tk.LogDebug, "[L4_SPAN_MATCH] Found span via forward key: span_id=%016x event_span=%016x\n",
				spanID, event.SpanID)
			return span, true
		} else {
			// Orphaned entry - span was deleted but key remains. Clean up to prevent memory leak.
			delete(sa.connKeys, forwardKey)
			sa.orphanedConnKeys++
			tk.LogIt(tk.LogDebug, "[L4_SPAN_CLEANUP] Removed orphaned connKey (forward): span_id=%016x\n", spanID)
		}
	}

	// Try reverse direction 5-tuple
	reverseKey := makeReverseKey(forwardKey)
	if spanID, exists := sa.connKeys[reverseKey]; exists {
		if span, exists := sa.spans[spanID]; exists {
			tk.LogIt(tk.LogDebug, "[L4_SPAN_MATCH] Found span via reverse key: span_id=%016x event_span=%016x\n",
				spanID, event.SpanID)
			return span, true
		} else {
			// Orphaned entry - clean up to prevent memory leak
			delete(sa.connKeys, reverseKey)
			sa.orphanedConnKeys++
			tk.LogIt(tk.LogDebug, "[L4_SPAN_CLEANUP] Removed orphaned connKey (reverse): span_id=%016x\n", spanID)
		}
	}

	// Try client endpoint correlation (for NAT scenarios where IPs differ)
	clientKeys := extractClientEndpointKeysForLookup(event)
	for _, clientKey := range clientKeys {
		if spanID, exists := sa.clientKeys[clientKey]; exists {
			if span, exists := sa.spans[spanID]; exists {
				// CRITICAL: Don't reuse closed spans for new connections
				// If span IDs don't match AND the found span is closed, this is a new connection
				// PRODUCTION FIX: Clean up ALL keys for the closed span to prevent memory leak
				if spanID != event.SpanID && span.IsClosed {
					tk.LogIt(tk.LogDebug, "[L4_SPAN_STALE] Found closed span, cleaning up all keys: span_id=%016x event_span=%016x client=%s:%d\n",
						spanID, event.SpanID, clientKey.IP, clientKey.Port)

					// Clean up the closed span and ALL its keys immediately
					sa.cleanupClosedSpan(span)

					// Return nil to force creation of new span
					return nil, false
				}
				tk.LogIt(tk.LogDebug, "[L4_SPAN_MATCH] Found span via client endpoint: span_id=%016x event_span=%016x client=%s:%d\n",
					spanID, event.SpanID, clientKey.IP, clientKey.Port)
				return span, true
			} else {
				// Orphaned entry - clean up to prevent memory leak
				delete(sa.clientKeys, clientKey)
				sa.orphanedClientKeys++
				tk.LogIt(tk.LogDebug, "[L4_SPAN_CLEANUP] Removed orphaned clientKey: span_id=%016x client=%s:%d\n",
					spanID, clientKey.IP, clientKey.Port)
			}
		}
	}

	return nil, false
}

// processEvent processes a single L4 trace event
func (sa *L4SpanAssembler) processEvent(event *L4TraceEvent) {
	sa.spanMutex.Lock()
	defer sa.spanMutex.Unlock()

	// Use bidirectional connection key lookup
	span, exists := sa.findSpanByConnection(event)

	if !exists {
		// Don't create new spans for error/close events that arrive late.
		// These are often part of already-closed connections (e.g., RST during TCP teardown).
		// Creating new spans for these causes false positive errors.
		if event.EventType == LXB_L4_EVENT_CONN_RESET ||
			event.EventType == LXB_L4_EVENT_CONN_TIMEOUT ||
			event.EventType == LXB_L4_EVENT_CONN_ERROR ||
			event.EventType == LXB_L4_EVENT_CONN_CLOSE {
			sa.lateEvents++
			tk.LogIt(tk.LogDebug, "[L4_SPAN_LATE_EVENT] Ignoring late %s event (no active span): span_id=%016x\n",
				eventTypeName(event.EventType), event.SpanID)
			return
		}

		// New connection - create spans for:
		// 1. NEW events
		// 2. ESTABLISHED states (successful connections)
		// 3. SCTP INIT states (to track handshake failures)
		// 4. TCP handshake failure transitions (orphaned backend failures)
		//    SYN_SENT→CLOSED: connection refused/unreachable
		//    SYN_ACK→CLOSED: handshake timeout/reset
		isTCPHandshakeFailure := event.Protocol == IPPROTO_TCP &&
			event.NewState == CT_TCP_CLOSED &&
			(event.OldState == CT_TCP_SS || event.OldState == CT_TCP_SA)

		// 5. SCTP handshake failure transitions (INIT_ACK→CLOSED without span = backend failure)
		isSCTPHandshakeFailure := event.Protocol == IPPROTO_SCTP &&
			event.NewState == CT_SCTP_CLOSED &&
			(event.OldState == CT_SCTP_INIT || event.OldState == CT_SCTP_INITA ||
				event.OldState == CT_SCTP_COOKIE || event.OldState == 0x9)

		if event.EventType == LXB_L4_EVENT_CONN_NEW ||
			event.NewState == CT_TCP_EST ||
			event.NewState == CT_SCTP_EST ||
			event.NewState == CT_UDP_EST ||
			(event.Protocol == IPPROTO_SCTP && event.NewState == CT_SCTP_INIT) ||
			isTCPHandshakeFailure || isSCTPHandshakeFailure {
			span = sa.createSpan(event)
			sa.spans[event.SpanID] = span

			// Register both forward and reverse connection keys
			forwardKey := makeConnectionKey(event)
			reverseKey := makeReverseKey(forwardKey)
			sa.connKeys[forwardKey] = event.SpanID
			sa.connKeys[reverseKey] = event.SpanID

			// Register client endpoint key for NAT correlation
			// Only store source (client IP:port) to avoid VIP collision
			clientKey := extractClientEndpointKeyForStorage(event)
			sa.clientKeys[clientKey] = event.SpanID

			sa.activeSpans++
			sa.totalSpans++

			tk.LogIt(tk.LogDebug, "[L4_SPAN_NEW] Created new connection span: span_id=%016x proto=%s src=%s:%d dst=%s:%d (bidirectional + client tracking)\n",
				event.SpanID, protocolName(event.Protocol),
				event.SrcIP, event.SrcPort, event.DstIP, event.DstPort)
		}
		return
	}

	// Update existing connection
	span.LastUpdate = time.Now()

	// Record state transition as span event if state changed
	if span.CurrentState != event.NewState {
		span.TraceSpan.AddEvent("state_transition",
			trace.WithTimestamp(span.LastUpdate),
			trace.WithAttributes(
				attribute.String("l4.old_state", stateName(event.Protocol, span.CurrentState)),
				attribute.String("l4.new_state", stateName(event.Protocol, event.NewState)),
				attribute.String("l4.event_type", eventTypeName(event.EventType)),
				attribute.Int64("l4.bytes_sent", int64(event.BytesSent)),
				attribute.Int64("l4.bytes_recv", int64(event.BytesRecv)),
				attribute.Int64("l4.packets_sent", int64(event.PacketsSent)),
				attribute.Int64("l4.packets_recv", int64(event.PacketsRecv)),
			),
		)
		span.TransitionCount++
	}

	span.PrevState = span.CurrentState
	span.CurrentState = event.NewState

	// Detect SCTP handshake failures: transition to CLOSED from INIT states without reaching ESTABLISHED
	// CRITICAL FIX: Distinguish real backend failures from partial NAT spans
	if event.Protocol == IPPROTO_SCTP &&
		event.NewState == CT_SCTP_CLOSED &&
		!span.IsEstablished &&
		(span.PrevState == CT_SCTP_INIT || span.PrevState == CT_SCTP_INITA ||
			span.PrevState == CT_SCTP_COOKIE || span.PrevState == 0x9) {

		// Determine if this is a real failure or a partial NAT span
		// Real failures: Quick closure (<100ms) OR started from early handshake states
		// Partial spans: Longer-lived (>100ms) AND started mid-connection (e.g., ESTABLISHED)
		duration := time.Since(span.StartTime)
		isQuickFailure := duration < 100*time.Millisecond

		// Consider any of these initial states as "early handshake":
		// CLOSED(0x0), INIT(0x1), INIT_ACK(0x2), COOKIE(0x4), INIT_ACK from backend(0x9)
		isFromEarlyHandshake := span.InitialState == CT_SCTP_CLOSED ||
			span.InitialState == CT_SCTP_INIT ||
			span.InitialState == CT_SCTP_INITA ||
			span.InitialState == CT_SCTP_COOKIE ||
			span.InitialState == 0x9

		// Real backend failure: quick CLOSED OR started from handshake states
		if isQuickFailure || isFromEarlyHandshake {
			span.HasError = true
			span.ErrorCode = uint8(LXB_L4_ERROR_SCTP_HANDSHAKE_FAIL)
			span.IsClosed = true
			span.EndTime = time.Now()
			tk.LogIt(tk.LogDebug, "[L4_SPAN_SCTP_FAIL] Handshake failed: span_id=%016x prev=%s init=%s duration=%v backend=%s\n",
				event.SpanID, stateName(event.Protocol, span.PrevState),
				stateName(event.Protocol, span.InitialState), duration, span.BackendIP)

			// Finalize the error span
			sa.finalizeSpanWithRetry(span, "handshake_failed")

			// CRITICAL: Clean up ALL keys immediately to prevent reuse
			sa.cleanupClosedSpan(span)
			sa.activeSpans--
		} else {
			// Partial NAT span (successful connection, but we only saw one direction)
			// This happens at <100% sampling when the reverse flow wasn't sampled
			tk.LogIt(tk.LogDebug, "[L4_SPAN_PARTIAL] Suppressing false positive for partial NAT span: span_id=%016x backend=%s duration=%v transitions=%d\n",
				event.SpanID, span.BackendIP, duration, span.TransitionCount)
			span.IsClosed = true
			span.EndTime = time.Now()

			// Also clean up keys for partial spans to prevent reuse
			sa.cleanupClosedSpan(span)
			sa.activeSpans--
		}
		return
	}

	// Update traffic statistics
	span.TotalBytesSent += event.BytesSent
	span.TotalBytesRecv += event.BytesRecv
	span.TotalPacketsSent += uint64(event.PacketsSent)
	span.TotalPacketsRecv += uint64(event.PacketsRecv)

	// Update RTT metrics
	if event.RTTMicros > 0 {
		if span.RTTCount == 0 {
			span.MinRTT = event.RTTMicros
			span.MaxRTT = event.RTTMicros
			span.AvgRTT = event.RTTMicros
		} else {
			if event.RTTMicros < span.MinRTT {
				span.MinRTT = event.RTTMicros
			}
			if event.RTTMicros > span.MaxRTT {
				span.MaxRTT = event.RTTMicros
			}
			// Running average
			span.AvgRTT = uint32((uint64(span.AvgRTT)*uint64(span.RTTCount) + uint64(event.RTTMicros)) / uint64(span.RTTCount+1))
		}
		span.RTTCount++
	}

	// Update retransmission counters
	span.TotalRetransSent += event.RetransSent
	span.TotalRetransRecv += event.RetransRecv

	// Track max window size
	if event.WindowSize > span.MaxWindowSize {
		span.MaxWindowSize = event.WindowSize
	}

	// Update backend info if newly available
	if event.BackendPort > 0 && span.BackendPort == 0 {
		span.BackendIP = event.BackendIP.String()
		span.BackendPort = event.BackendPort
		span.BackendID = event.BackendID
		tk.LogIt(tk.LogDebug, "[L4_SPAN_BACKEND] Backend selected: span_id=%016x backend=%s:%d id=%d\n",
			span.SpanID, span.BackendIP, span.BackendPort, span.BackendID)
	}

	// Track established state
	if (event.NewState == CT_TCP_EST ||
		event.NewState == CT_SCTP_EST ||
		event.NewState == CT_UDP_EST) && !span.IsEstablished {
		span.IsEstablished = true
		tk.LogIt(tk.LogDebug, "[L4_SPAN_EST] Connection established: span_id=%016x duration_ms=%d\n",
			event.SpanID, time.Since(span.StartTime).Milliseconds())
	}

	// Protocol-specific error detection
	sa.detectProtocolErrors(span, event)

	// Handle connection close/error
	if event.EventType == LXB_L4_EVENT_CONN_CLOSE ||
		event.EventType == LXB_L4_EVENT_CONN_TIMEOUT ||
		event.EventType == LXB_L4_EVENT_CONN_RESET ||
		event.EventType == LXB_L4_EVENT_CONN_ERROR {

		span.IsClosed = true
		span.EndTime = time.Now()
		if event.ErrorCode != LXB_L4_ERROR_NONE {
			span.ErrorCode = uint8(event.ErrorCode)
		}

		reason := eventTypeName(event.EventType)

		// For NATLB: if event has backend info but span doesn't match event span_id,
		// this means findSpanByConnection found a correlated span (backend→client)
		// instead of the original event span (client→VIP). Create proper VIP span for export.
		// NOTE: If span IDs match, it means direct lookup succeeded (TCP case) - no action needed.
		if event.BackendPort > 0 && span.SpanID != event.SpanID {
			tk.LogIt(tk.LogDebug, "[L4_SPAN_NATLB_MISMATCH] Event span != found span: event=%016x found=%016x proto=%s - will create VIP span\n",
				event.SpanID, span.SpanID, protocolName(event.Protocol))

			// This is a correlated span (backend→client), but event is from client→VIP span
			// Create a new span representing the client→VIP connection for proper export
			// CRITICAL: Use correlated span's IPs (client→VIP direction) not event's IPs (backend→client)
			vipSpan := &L4ConnectionSpan{
				SpanID:          event.SpanID,
				Protocol:        event.Protocol,
				SrcIP:           span.SrcIP,   // From correlated span: client IP
				SrcPort:         span.SrcPort, // From correlated span: client port
				DstIP:           span.DstIP,   // From correlated span: VIP
				DstPort:         span.DstPort, // From correlated span: VIP port
				Zone:            event.Zone,
				BackendIP:       event.BackendIP.String(),
				BackendPort:     event.BackendPort,
				BackendID:       event.BackendID,
				StartTime:       span.StartTime, // Copy from correlated span
				EndTime:         span.EndTime,
				IsEstablished:   span.IsEstablished,
				CurrentState:    span.CurrentState,
				PrevState:       span.PrevState,
				InitialState:    span.InitialState,
				TotalBytesSent:  span.TotalBytesSent,
				TotalBytesRecv:  span.TotalBytesRecv,
				TransitionCount: span.TransitionCount,
				TraceSpan:       span.TraceSpan, // Transfer OTLP span
				IsClosed:        true,
				HasError:        span.HasError,
				ErrorCode:       span.ErrorCode,
			}

			tk.LogIt(tk.LogDebug, "[L4_SPAN_NATLB] Using VIP span for export: vip_span=%016x correlated=%016x vip=%s:%d→%s:%d backend=%s:%d\n",
				event.SpanID, span.SpanID, event.SrcIP, event.SrcPort, event.DstIP, event.DstPort,
				event.BackendIP, event.BackendPort)

			// Finalize the VIP span instead
			sa.finalizeSpanWithRetry(vipSpan, reason)

			// Clean up the correlated span AND its keys to prevent memory leak
			delete(sa.spans, span.SpanID)

			// Remove correlated span's connection keys
			correlatedForward := connectionKey{
				SrcIP:   span.SrcIP,
				DstIP:   span.DstIP,
				SrcPort: span.SrcPort,
				DstPort: span.DstPort,
				Proto:   span.Protocol,
			}
			correlatedReverse := makeReverseKey(correlatedForward)
			delete(sa.connKeys, correlatedForward)
			delete(sa.connKeys, correlatedReverse)

			// Remove correlated span's client endpoint keys
			correlatedClient1 := clientEndpointKey{IP: span.SrcIP, Port: span.SrcPort, Proto: span.Protocol}
			correlatedClient2 := clientEndpointKey{IP: span.DstIP, Port: span.DstPort, Proto: span.Protocol}
			delete(sa.clientKeys, correlatedClient1)
			delete(sa.clientKeys, correlatedClient2)
		} else {
			// Normal case or span already matches event
			sa.finalizeSpanWithRetry(span, reason)
		}

		// Remove from active spans
		delete(sa.spans, event.SpanID)
		sa.activeSpans--

		// Remove connection keys
		forwardKey := connectionKey{
			SrcIP:   span.SrcIP,
			DstIP:   span.DstIP,
			SrcPort: span.SrcPort,
			DstPort: span.DstPort,
			Proto:   span.Protocol,
		}
		reverseKey := makeReverseKey(forwardKey)
		delete(sa.connKeys, forwardKey)
		delete(sa.connKeys, reverseKey)

		// Remove client endpoint key (source only = client IP:port)
		clientKey := clientEndpointKey{IP: span.SrcIP, Port: span.SrcPort, Proto: span.Protocol}
		delete(sa.clientKeys, clientKey)

		if event.EventType == LXB_L4_EVENT_CONN_CLOSE {
			sa.closedSpans++
		} else if event.EventType == LXB_L4_EVENT_CONN_TIMEOUT {
			sa.timeoutSpans++
		} else {
			sa.errorSpans++
		}

		tk.LogIt(tk.LogDebug, "[L4_SPAN_CLOSE] Connection closed: span_id=%016x reason=%s duration_ms=%d bytes_sent=%d bytes_recv=%d\n",
			event.SpanID, reason, span.EndTime.Sub(span.StartTime).Milliseconds(),
			span.TotalBytesSent, span.TotalBytesRecv)
	}
}

// createSpan creates a new connection span
func (sa *L4SpanAssembler) createSpan(event *L4TraceEvent) *L4ConnectionSpan {
	now := time.Now()

	span := &L4ConnectionSpan{
		SpanID:       event.SpanID,
		Protocol:     event.Protocol,
		SrcIP:        event.SrcIP.String(),
		SrcPort:      event.SrcPort,
		DstIP:        event.DstIP.String(),
		DstPort:      event.DstPort,
		Zone:         event.Zone,
		BackendIP:    event.BackendIP.String(),
		BackendPort:  event.BackendPort,
		BackendID:    event.BackendID,
		StartTime:    now,
		LastUpdate:   now,
		CurrentState: event.NewState,
		PrevState:    event.OldState,
		InitialState: event.OldState, // Preserve first state
		Flags:        event.Flags,
		TCPFlags:     event.TCPFlags,
		MSS:          event.MSS,
	}

	// Create OTLP span (set attributes only at finalization)
	ctx := context.Background()
	_, traceSpan := sa.tracer.Start(ctx, "l4.connection",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithTimestamp(now),
	)

	// Record initial state transition as span event
	traceSpan.AddEvent("state_transition",
		trace.WithTimestamp(now),
		trace.WithAttributes(
			attribute.String("l4.old_state", stateName(event.Protocol, event.OldState)),
			attribute.String("l4.new_state", stateName(event.Protocol, event.NewState)),
			attribute.String("l4.event_type", eventTypeName(event.EventType)),
		),
	)
	span.TransitionCount = 1

	span.TraceSpan = traceSpan

	return span
}

// cleanupClosedSpan removes a closed span and ALL its associated keys
// PRODUCTION CRITICAL: Must clean up all references to prevent memory leaks
func (sa *L4SpanAssembler) cleanupClosedSpan(span *L4ConnectionSpan) {
	// Remove from spans map
	delete(sa.spans, span.SpanID)

	// Remove connection keys (forward and reverse) using span's IP/port
	forwardKey := connectionKey{
		SrcIP:   span.SrcIP,
		DstIP:   span.DstIP,
		SrcPort: span.SrcPort,
		DstPort: span.DstPort,
		Proto:   span.Protocol,
	}
	reverseKey := makeReverseKey(forwardKey)
	delete(sa.connKeys, forwardKey)
	delete(sa.connKeys, reverseKey)

	// Remove client endpoint key using span's source IP/port (client)
	clientKey := clientEndpointKey{IP: span.SrcIP, Port: span.SrcPort, Proto: span.Protocol}
	delete(sa.clientKeys, clientKey)

	tk.LogIt(tk.LogDebug, "[L4_SPAN_CLEANUP_FULL] Cleaned up closed span and all keys: span_id=%016x\n", span.SpanID)
}

// detectProtocolErrors performs protocol-specific error detection
func (sa *L4SpanAssembler) detectProtocolErrors(span *L4ConnectionSpan, event *L4TraceEvent) {
	// Common error conditions for all protocols:

	// 1. Always mark as error: TIMEOUT and ERROR events
	if event.EventType == LXB_L4_EVENT_CONN_TIMEOUT ||
		event.EventType == LXB_L4_EVENT_CONN_ERROR {
		span.HasError = true
		return
	}

	// 2. Error codes (any non-zero error code indicates a problem)
	if event.ErrorCode != LXB_L4_ERROR_NONE {
		span.HasError = true
		span.ErrorCode = uint8(event.ErrorCode)
		tk.LogIt(tk.LogDebug, "[L4_SPAN_ERROR] Error code present: span_id=%016x code=%d name=%s\n",
			event.SpanID, event.ErrorCode, errorCodeName(uint8(event.ErrorCode)))
		return
	}

	// 3. Error flags (LXB_L4_FLAG_ERROR, LXB_L4_FLAG_BACKEND_UNHEALTHY, LXB_L4_FLAG_PRECT_FAILURE)
	if (event.Flags&LXB_L4_FLAG_ERROR) != 0 ||
		(event.Flags&LXB_L4_FLAG_BACKEND_UNHEALTHY) != 0 ||
		(event.Flags&LXB_L4_FLAG_PRECT_FAILURE) != 0 {
		span.HasError = true
		tk.LogIt(tk.LogDebug, "[L4_SPAN_ERROR] Error flags detected: span_id=%016x flags=%s\n",
			event.SpanID, l4FlagsToString(event.Flags))
		return
	}

	// 4. Connection closed/reset before establishing (failed handshake)
	// CRITICAL: Quick failures (<100ms) are real errors, longer ones may be partial NAT spans
	if !span.IsEstablished &&
		(event.EventType == LXB_L4_EVENT_CONN_CLOSE ||
			event.EventType == LXB_L4_EVENT_CONN_RESET) {
		duration := time.Since(span.StartTime)
		isQuickFailure := duration < 100*time.Millisecond

		// For TCP SYN_SENT→CLOSED: always an error (connection refused/unreachable)
		// For other protocols: use duration heuristic
		isTCPConnectionRefused := span.Protocol == IPPROTO_TCP && span.PrevState == CT_TCP_SS

		if isQuickFailure || isTCPConnectionRefused {
			span.HasError = true
			tk.LogIt(tk.LogDebug, "[L4_SPAN_ERROR] Connection closed without establishing: span_id=%016x event=%s duration=%v state=%s\n",
				event.SpanID, eventTypeName(event.EventType), duration, stateName(span.Protocol, span.PrevState))
		} else {
			// Longer duration without establishing: likely partial NAT span from sampling
			tk.LogIt(tk.LogDebug, "[L4_SPAN_PARTIAL_CLOSE] Not marking as error (possible NAT partial): span_id=%016x duration=%v\n",
				event.SpanID, duration)
		}
		return
	}

	// Protocol-specific RESET handling
	if event.EventType == LXB_L4_EVENT_CONN_RESET {
		switch span.Protocol {
		case 6: // TCP
			// TCP RESET after establishment can be error or graceful depending on context
			// If connection was established and has no error code/flags, treat as graceful
			// (e.g., client/server closing with RST instead of FIN for faster teardown)
			if !span.IsEstablished {
				span.HasError = true
				tk.LogIt(tk.LogDebug, "[L4_SPAN_ERROR] TCP RESET before establishment: span_id=%016x\n",
					event.SpanID)
			}
			// After establishment: only error if explicit error code/flags (already checked above)

		case 132: // SCTP
			// SCTP graceful shutdown sequence: ESTABLISHED → SHUTDOWN → (optional RESET)
			// SHUTDOWN followed by RESET is NORMAL graceful close, not an error
			// Only mark as error if RESET occurs before ESTABLISHED or during early states
			if span.PrevState == CT_SCTP_EST || span.CurrentState == CT_SCTP_SHUT {
				// Normal graceful shutdown - not an error
				tk.LogIt(tk.LogDebug, "[L4_SPAN_SCTP] Graceful shutdown with RESET: span_id=%016x state=%s\n",
					event.SpanID, stateName(span.Protocol, span.CurrentState))
			} else if !span.IsEstablished {
				// RESET before establishment is an error
				span.HasError = true
				tk.LogIt(tk.LogDebug, "[L4_SPAN_ERROR] SCTP RESET before establishment: span_id=%016x\n",
					event.SpanID)
			}
			// After establishment but before shutdown: only error if explicit error code/flags

		case 17: // UDP
			// UDP RESET is less common but can occur with ICMP unreachable
			// Treat as error only if connection never established
			if !span.IsEstablished {
				span.HasError = true
				tk.LogIt(tk.LogDebug, "[L4_SPAN_ERROR] UDP RESET before establishment: span_id=%016x\n",
					event.SpanID)
			}
		}
	}
}

// finalizeSpan completes a connection span and emits OTLP
func (sa *L4SpanAssembler) finalizeSpan(span *L4ConnectionSpan, reason string) {
	if span.TraceSpan == nil {
		return
	}

	duration := span.EndTime.Sub(span.StartTime)

	// Log span details before finalization
	tk.LogIt(tk.LogDebug, "[L4_SPAN_FINALIZE_ATTRS] span_id=%016x src=%s:%d dst=%s:%d zone=%d proto=%s\n",
		span.SpanID, span.SrcIP, span.SrcPort, span.DstIP, span.DstPort, span.Zone, protocolName(span.Protocol))

	// Set final attributes with human-readable values
	span.TraceSpan.SetAttributes(
		attribute.String("l4.span_id", fmt.Sprintf("%016x", span.SpanID)),
		attribute.String("l4.protocol", protocolName(span.Protocol)),
		attribute.String("net.peer.ip", span.SrcIP),
		attribute.Int64("net.peer.port", int64(span.SrcPort)),
		attribute.String("net.host.ip", span.DstIP),
		attribute.Int64("net.host.port", int64(span.DstPort)),
		attribute.Int64("l4.zone", int64(span.Zone)),
		attribute.String("l4.close_reason", reason),
		attribute.Int64("l4.duration_ms", duration.Milliseconds()),
		attribute.Int64("l4.bytes_sent", int64(span.TotalBytesSent)),
		attribute.Int64("l4.bytes_recv", int64(span.TotalBytesRecv)),
		attribute.Int64("l4.packets_sent", int64(span.TotalPacketsSent)),
		attribute.Int64("l4.packets_recv", int64(span.TotalPacketsRecv)),
		attribute.Bool("l4.established", span.IsEstablished),
		attribute.String("l4.initial_state", stateName(span.Protocol, span.InitialState)),
		attribute.String("l4.final_state", stateName(span.Protocol, span.CurrentState)),
		attribute.Int64("l4.state_transitions", int64(span.TransitionCount)),
	)

	// Add RTT metrics if available
	if span.RTTCount > 0 {
		span.TraceSpan.SetAttributes(
			attribute.Int64("l4.rtt_min_us", int64(span.MinRTT)),
			attribute.Int64("l4.rtt_max_us", int64(span.MaxRTT)),
			attribute.Int64("l4.rtt_avg_us", int64(span.AvgRTT)),
		)
	}

	// Add error code information if present
	if span.ErrorCode != LXB_L4_ERROR_NONE {
		span.TraceSpan.SetAttributes(
			attribute.Int64("l4.error_code", int64(span.ErrorCode)),
			attribute.String("l4.error_name", errorCodeName(span.ErrorCode)),
		)
	}

	// Add event flags information
	if span.Flags != 0 {
		span.TraceSpan.SetAttributes(
			attribute.String("l4.flags", l4FlagsToString(span.Flags)),
		)
	}

	// End span
	span.TraceSpan.End(trace.WithTimestamp(span.EndTime))

	tk.LogIt(tk.LogInfo, "[L4_SPAN_FINALIZE] Emitted OTLP span: span_id=%016x duration_ms=%d bytes=%d established=%v\n",
		span.SpanID, duration.Milliseconds(),
		span.TotalBytesSent+span.TotalBytesRecv, span.IsEstablished)
}

// cleanupLoop periodically cleans up stale spans
func (sa *L4SpanAssembler) cleanupLoop() {
	defer sa.wg.Done()

	ticker := time.NewTicker(L4_SPAN_CLEANUP_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-sa.stopChan:
			return
		case <-ticker.C:
			sa.cleanupStaleSpans()
		}
	}
}

// cleanupStaleSpans removes spans with no updates for L4_SPAN_TIMEOUT
func (sa *L4SpanAssembler) cleanupStaleSpans() {
	sa.spanMutex.Lock()
	defer sa.spanMutex.Unlock()

	now := time.Now()
	staleSpans := make([]*L4ConnectionSpan, 0)

	for spanID, span := range sa.spans {
		if now.Sub(span.LastUpdate) > L4_SPAN_TIMEOUT {
			staleSpans = append(staleSpans, span)
			delete(sa.spans, spanID)

			// Remove connection keys
			forwardKey := connectionKey{
				SrcIP:   span.SrcIP,
				DstIP:   span.DstIP,
				SrcPort: span.SrcPort,
				DstPort: span.DstPort,
				Proto:   span.Protocol,
			}
			reverseKey := makeReverseKey(forwardKey)
			delete(sa.connKeys, forwardKey)
			delete(sa.connKeys, reverseKey)

			// Remove client endpoint key (source only = client IP:port)
			clientKey := clientEndpointKey{IP: span.SrcIP, Port: span.SrcPort, Proto: span.Protocol}
			delete(sa.clientKeys, clientKey)

			sa.activeSpans--
			sa.timeoutSpans++
		}
	}

	// Finalize stale spans outside lock
	sa.spanMutex.Unlock()
	for _, span := range staleSpans {
		span.IsClosed = true
		span.EndTime = now
		sa.finalizeSpanWithRetry(span, "stale_timeout")
	}
	sa.spanMutex.Lock()

	if len(staleSpans) > 0 {
		tk.LogIt(tk.LogInfo, "[L4_SPAN_CLEANUP] Cleaned up %d stale spans\n", len(staleSpans))
	}
}

// periodicExportLoop exports long-lived connection metrics periodically
func (sa *L4SpanAssembler) periodicExportLoop() {
	defer sa.wg.Done()

	ticker := time.NewTicker(L4_PERIODIC_EXPORT_INTERVAL)
	defer ticker.Stop()

	tk.LogIt(tk.LogDebug, "[L4_PERIODIC_EXPORT] Starting periodic export loop (interval=%v)\n", L4_PERIODIC_EXPORT_INTERVAL)

	for {
		select {
		case <-sa.stopChan:
			return
		case <-ticker.C:
			sa.exportLongLivedConnections()
		}
	}
}

// exportLongLivedConnections exports spans for connections that haven't been exported recently
func (sa *L4SpanAssembler) exportLongLivedConnections() {
	sa.spanMutex.RLock()
	now := time.Now()
	spansToExport := make([]*L4ConnectionSpan, 0)

	for _, span := range sa.spans {
		// Export if established and not exported in the last interval
		if span.IsEstablished && !span.IsClosed {
			if span.LastExport.IsZero() || now.Sub(span.LastExport) >= L4_PERIODIC_EXPORT_INTERVAL {
				spansToExport = append(spansToExport, span)
			}
		}
	}
	sa.spanMutex.RUnlock()

	if len(spansToExport) > 0 {
		tk.LogIt(tk.LogInfo, "[L4_PERIODIC_EXPORT] Exporting %d long-lived connections\n", len(spansToExport))

		for _, span := range spansToExport {
			sa.exportIntermediateSpanData(span)

			sa.spanMutex.Lock()
			span.LastExport = now
			sa.spanMutex.Unlock()
		}
	}
}

// exportIntermediateSpanData emits current metrics for a long-lived connection
func (sa *L4SpanAssembler) exportIntermediateSpanData(span *L4ConnectionSpan) {
	if span.TraceSpan == nil {
		return
	}

	// Add event with current metrics (not ending the span)
	duration := time.Since(span.StartTime)
	span.TraceSpan.AddEvent("l4.metrics.snapshot",
		trace.WithAttributes(
			attribute.Int64("l4.duration_ms", duration.Milliseconds()),
			attribute.Int64("l4.bytes_sent", int64(span.TotalBytesSent)),
			attribute.Int64("l4.bytes_recv", int64(span.TotalBytesRecv)),
			attribute.Int64("l4.packets_sent", int64(span.TotalPacketsSent)),
			attribute.Int64("l4.packets_recv", int64(span.TotalPacketsRecv)),
			attribute.String("l4.current_state", stateName(span.Protocol, span.CurrentState)),
		),
	)

	// Add RTT snapshot if available
	if span.RTTCount > 0 {
		span.TraceSpan.AddEvent("l4.rtt.snapshot",
			trace.WithAttributes(
				attribute.Int64("l4.rtt_min_us", int64(span.MinRTT)),
				attribute.Int64("l4.rtt_max_us", int64(span.MaxRTT)),
				attribute.Int64("l4.rtt_avg_us", int64(span.AvgRTT)),
				attribute.Int64("l4.rtt_samples", int64(span.RTTCount)),
			),
		)
	}

	tk.LogIt(tk.LogDebug, "[L4_PERIODIC_EXPORT] Exported snapshot: span_id=%016x duration_ms=%d bytes=%d\n",
		span.SpanID, duration.Milliseconds(), span.TotalBytesSent+span.TotalBytesRecv)
}

// finalizeSpanWithRetry adds span to batch for export with retry support
func (sa *L4SpanAssembler) finalizeSpanWithRetry(span *L4ConnectionSpan, reason string) {
	if span.TraceSpan == nil {
		return
	}

	duration := span.EndTime.Sub(span.StartTime)

	// Log span details before finalization
	tk.LogIt(tk.LogDebug, "[L4_SPAN_FINALIZE_ATTRS] span_id=%016x src=%s:%d dst=%s:%d zone=%d proto=%s\n",
		span.SpanID, span.SrcIP, span.SrcPort, span.DstIP, span.DstPort, span.Zone, protocolName(span.Protocol))

	// Set final attributes with human-readable values for OTLP/Jaeger
	span.TraceSpan.SetAttributes(
		attribute.String("l4.span_id", fmt.Sprintf("%016x", span.SpanID)),
		attribute.String("l4.protocol", protocolName(span.Protocol)),
		attribute.String("net.peer.ip", span.SrcIP),
		attribute.Int64("net.peer.port", int64(span.SrcPort)),
		attribute.String("net.host.ip", span.DstIP),
		attribute.Int64("net.host.port", int64(span.DstPort)),
		attribute.Int64("l4.zone", int64(span.Zone)),
		attribute.String("l4.close_reason", reason),
		attribute.Int64("l4.duration_ms", duration.Milliseconds()),
		attribute.Int64("l4.bytes_sent", int64(span.TotalBytesSent)),
		attribute.Int64("l4.bytes_recv", int64(span.TotalBytesRecv)),
		attribute.Int64("l4.packets_sent", int64(span.TotalPacketsSent)),
		attribute.Int64("l4.packets_recv", int64(span.TotalPacketsRecv)),
		attribute.Bool("l4.established", span.IsEstablished),
		attribute.String("l4.initial_state", stateName(span.Protocol, span.InitialState)),
		attribute.String("l4.final_state", stateName(span.Protocol, span.CurrentState)),
		attribute.Int64("l4.state_transitions", int64(span.TransitionCount)),
	)

	// Add backend selection info if available
	if span.BackendPort > 0 {
		span.TraceSpan.SetAttributes(
			attribute.String("lb.backend.ip", span.BackendIP),
			attribute.Int64("lb.backend.port", int64(span.BackendPort)),
			attribute.Int64("lb.backend.id", int64(span.BackendID)),
		)
	}

	// Add retransmission metrics if present
	if span.TotalRetransSent > 0 || span.TotalRetransRecv > 0 {
		span.TraceSpan.SetAttributes(
			attribute.Int64("l4.retrans_sent", int64(span.TotalRetransSent)),
			attribute.Int64("l4.retrans_recv", int64(span.TotalRetransRecv)),
		)
	}

	// Add TCP specific metrics
	if span.Protocol == 6 {
		if span.MaxWindowSize > 0 {
			span.TraceSpan.SetAttributes(
				attribute.Int64("tcp.max_window", int64(span.MaxWindowSize)),
			)
		}
		if span.MSS > 0 {
			span.TraceSpan.SetAttributes(
				attribute.Int64("tcp.mss", int64(span.MSS)),
			)
		}
		if span.TCPFlags != 0 {
			span.TraceSpan.SetAttributes(
				attribute.String("tcp.flags", fmt.Sprintf("0x%02x", span.TCPFlags)),
			)
		}
	}

	// Add RTT metrics if available
	if span.RTTCount > 0 {
		span.TraceSpan.SetAttributes(
			attribute.Int64("l4.rtt_min_us", int64(span.MinRTT)),
			attribute.Int64("l4.rtt_max_us", int64(span.MaxRTT)),
			attribute.Int64("l4.rtt_avg_us", int64(span.AvgRTT)),
		)
	}

	// Set error status if connection had errors (reset/timeout/error)
	// Similar to HTTP/L7 tracing - mark errors for Jaeger visibility
	if span.HasError {
		// Build error description from available information
		errorDesc := "Connection error"
		if span.ErrorCode != LXB_L4_ERROR_NONE {
			errorDesc = fmt.Sprintf("Connection error: %s", errorCodeName(span.ErrorCode))
		} else if span.Flags != 0 {
			errorDesc = fmt.Sprintf("Connection error: %s", l4FlagsToString(span.Flags))
		}
		span.TraceSpan.SetStatus(codes.Error, errorDesc)
		span.TraceSpan.SetAttributes(
			attribute.Bool("error", true),
		)
	} else {
		span.TraceSpan.SetStatus(codes.Ok, "")
	}

	// End span
	span.TraceSpan.End(trace.WithTimestamp(span.EndTime))

	// Add to batch for export
	sa.addToBatch(span)

	tk.LogIt(tk.LogInfo, "[L4_SPAN_FINALIZE] Queued span for export: span_id=%016x duration_ms=%d bytes=%d established=%v\n",
		span.SpanID, duration.Milliseconds(),
		span.TotalBytesSent+span.TotalBytesRecv, span.IsEstablished)
}

// addToBatch adds a span to the export batch
func (sa *L4SpanAssembler) addToBatch(span *L4ConnectionSpan) {
	sa.batchMutex.Lock()
	defer sa.batchMutex.Unlock()

	sa.spanBatch = append(sa.spanBatch, span)

	// Flush if batch size reached
	if len(sa.spanBatch) >= L4_BATCH_EXPORT_SIZE {
		sa.flushBatchUnlocked()
		return
	}

	// Start timer for batch timeout
	if sa.batchTimer == nil {
		sa.batchTimer = time.AfterFunc(L4_BATCH_EXPORT_TIMEOUT, func() {
			sa.flushBatch()
		})
	}
}

// flushBatch exports all batched spans
func (sa *L4SpanAssembler) flushBatch() {
	sa.batchMutex.Lock()
	defer sa.batchMutex.Unlock()
	sa.flushBatchUnlocked()
}

func (sa *L4SpanAssembler) flushBatchUnlocked() {
	if len(sa.spanBatch) == 0 {
		return
	}

	// Stop timer
	if sa.batchTimer != nil {
		sa.batchTimer.Stop()
		sa.batchTimer = nil
	}

	batchSize := len(sa.spanBatch)
	tk.LogIt(tk.LogInfo, "[L4_BATCH_EXPORT] Flushing batch of %d spans\n", batchSize)

	// OTLP SDK automatically batches spans, so we just need to ensure they're ended
	// The actual batching and compression is handled by the OTLP exporter

	// Clear batch
	sa.spanBatch = sa.spanBatch[:0]

	tk.LogIt(tk.LogDebug, "[L4_BATCH_EXPORT] Batch flushed successfully\n")
}

// retryLoop handles failed span exports with exponential backoff
func (sa *L4SpanAssembler) retryLoop() {
	defer sa.wg.Done()

	ticker := time.NewTicker(10 * time.Second) // Check retry queue every 10s
	defer ticker.Stop()

	for {
		select {
		case <-sa.stopChan:
			return
		case <-ticker.C:
			sa.processRetryQueue()
		}
	}
}

// processRetryQueue attempts to re-export failed spans
func (sa *L4SpanAssembler) processRetryQueue() {
	sa.retryMutex.Lock()
	defer sa.retryMutex.Unlock()

	if len(sa.retryQueue) == 0 {
		return
	}

	tk.LogIt(tk.LogInfo, "[L4_RETRY] Processing retry queue: %d spans pending\n", len(sa.retryQueue))

	// For, we rely on OTLP SDK's built-in retry mechanism
	// This is a placeholder for custom retry logic if needed
	// The OTLP exporter already implements exponential backoff

	// Clear retry queue after processing
	sa.retryQueue = sa.retryQueue[:0]
}

// GetStats returns current statistics
func (sa *L4SpanAssembler) GetStats() L4SpanAssemblerStats {
	sa.spanMutex.RLock()
	connKeysSize := uint64(len(sa.connKeys))
	clientKeysSize := uint64(len(sa.clientKeys))
	sa.spanMutex.RUnlock()

	sa.retryMutex.Lock()
	retryQueueSize := uint64(len(sa.retryQueue))
	sa.retryMutex.Unlock()

	return L4SpanAssemblerStats{
		TotalSpans:         sa.totalSpans,
		ActiveSpans:        sa.activeSpans,
		ClosedSpans:        sa.closedSpans,
		ErrorSpans:         sa.errorSpans,
		TimeoutSpans:       sa.timeoutSpans,
		ExportFailures:     sa.exportFailures,
		ExportRetries:      sa.exportRetries,
		RetryQueueSize:     retryQueueSize,
		OrphanedConnKeys:   sa.orphanedConnKeys,
		OrphanedClientKeys: sa.orphanedClientKeys,
		LateEvents:         sa.lateEvents,
		ConnKeysMapSize:    connKeysSize,
		ClientKeysMapSize:  clientKeysSize,
	}
}

// L4SpanAssemblerStats holds assembler statistics
type L4SpanAssemblerStats struct {
	TotalSpans     uint64
	ActiveSpans    uint64
	ClosedSpans    uint64
	ErrorSpans     uint64
	TimeoutSpans   uint64
	ExportFailures uint64
	ExportRetries  uint64
	RetryQueueSize uint64

	// Memory health monitoring (production readiness)
	OrphanedConnKeys   uint64 // Number of orphaned connKeys cleaned up
	OrphanedClientKeys uint64 // Number of orphaned clientKeys cleaned up
	LateEvents         uint64 // Late error/close events ignored (prevents false positives)
	ConnKeysMapSize    uint64 // Current size of connKeys map
	ClientKeysMapSize  uint64 // Current size of clientKeys map
}

// Helper functions
func protocolName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 132:
		return "SCTP"
	default:
		return fmt.Sprintf("PROTO_%d", proto)
	}
}

func errorCodeName(errorCode uint8) string {
	switch errorCode {
	case LXB_L4_ERROR_NONE:
		return "NONE"
	case LXB_L4_ERROR_RST_CLIENT:
		return "RST_CLIENT"
	case LXB_L4_ERROR_RST_SERVER:
		return "RST_SERVER"
	case LXB_L4_ERROR_SCTP_ABORT:
		return "SCTP_ABORT"
	case LXB_L4_ERROR_CT_TIMEOUT:
		return "CT_TIMEOUT"
	case LXB_L4_ERROR_MAP_FULL:
		return "MAP_FULL"
	case LXB_L4_ERROR_SYN_TIMEOUT:
		return "SYN_TIMEOUT"
	case LXB_L4_ERROR_SCTP_HANDSHAKE_FAIL:
		return "SCTP_HANDSHAKE_FAIL"
	case LXB_L4_ERROR_NO_BACKEND:
		return "NO_BACKEND"
	case LXB_L4_ERROR_BACKEND_DOWN:
		return "BACKEND_DOWN"
	case LXB_L4_ERROR_BACKEND_REFUSED:
		return "BACKEND_REFUSED"
	case LXB_L4_ERROR_NO_ROUTE:
		return "NO_ROUTE"
	case LXB_L4_ERROR_BACKEND_TIMEOUT:
		return "BACKEND_TIMEOUT"
	case LXB_L4_ERROR_PORT_MISMATCH:
		return "PORT_MISMATCH"
	case LXB_L4_ERROR_LB_FAILURE:
		return "LB_FAILURE"
	case LXB_L4_ERROR_NAT_FAILURE:
		return "NAT_FAILURE"
	default:
		return fmt.Sprintf("ERROR_%d", errorCode)
	}
}

func stateName(proto uint8, state uint8) string {
	if proto == 6 { // TCP
		switch state {
		case CT_TCP_CLOSED:
			return "CLOSED"
		case CT_TCP_SS:
			return "SYN_SENT"
		case CT_TCP_SA:
			return "SYN_ACK"
		case CT_TCP_EST:
			return "ESTABLISHED"
		case CT_TCP_FINI:
			return "FIN_WAIT_1"
		case CT_TCP_FINI2:
			return "FIN_WAIT_2"
		case CT_TCP_FINI3:
			return "CLOSING"
		case CT_TCP_CW:
			return "CLOSE_WAIT"
		default:
			// Note: CT_TCP_ERR (0x100) overflows uint8, handled in default case
			return fmt.Sprintf("TCP_STATE_0x%x", state)
		}
	} else if proto == 17 { // UDP
		switch state {
		case CT_UDP_EST:
			return "ESTABLISHED"
		default:
			// Removed unused UDP state constants during refactoring
			// BPF only emits EST state for UDP in practice
			return fmt.Sprintf("UDP_STATE_0x%x", state)
		}
	} else if proto == 132 { // SCTP
		switch state {
		case CT_SCTP_CLOSED:
			return "CLOSED"
		case CT_SCTP_INIT:
			return "INIT"
		case CT_SCTP_INITA:
			return "INIT_ACK"
		case CT_SCTP_COOKIE:
			return "COOKIE_ECHO"
		case CT_SCTP_EST:
			return "ESTABLISHED"
		case CT_SCTP_SHUT:
			return "SHUTDOWN"
		case 0x9:
			return "INIT_FAIL" // Transient error state during handshake
		case 0x81:
			return "SHUTDOWN+CLOSED" // Combined state during teardown
		default:
			// Note: States > 255 overflow uint8, will show as truncated hex
			return fmt.Sprintf("SCTP_STATE_0x%x", state)
		}
	}
	return fmt.Sprintf("STATE_%d", state)
}

func eventTypeName(eventType uint8) string {
	switch eventType {
	case LXB_L4_EVENT_CONN_NEW:
		return "new"
	case LXB_L4_EVENT_STATE_CHANGE:
		return "state_change"
	case LXB_L4_EVENT_CONN_CLOSE:
		return "close"
	case LXB_L4_EVENT_CONN_TIMEOUT:
		return "timeout"
	case LXB_L4_EVENT_CONN_RESET:
		return "reset"
	case LXB_L4_EVENT_CONN_ERROR:
		return "error"
	default:
		return fmt.Sprintf("event_%d", eventType)
	}
}

func l4FlagsToString(flags uint8) string {
	if flags == 0 {
		return "NONE"
	}

	var parts []string
	if (flags & LXB_L4_FLAG_SAMPLED) != 0 {
		parts = append(parts, "SAMPLED")
	}
	if (flags & LXB_L4_FLAG_ERROR) != 0 {
		parts = append(parts, "ERROR")
	}
	if (flags & LXB_L4_FLAG_NAT_APPLIED) != 0 {
		parts = append(parts, "NAT")
	}
	if (flags & LXB_L4_FLAG_TRACED) != 0 {
		parts = append(parts, "TRACED")
	}
	if (flags & LXB_L4_FLAG_BACKEND_SELECTED) != 0 {
		parts = append(parts, "BACKEND_SELECTED")
	}
	if (flags & LXB_L4_FLAG_BACKEND_UNHEALTHY) != 0 {
		parts = append(parts, "BACKEND_UNHEALTHY")
	}
	if (flags & LXB_L4_FLAG_PRECT_FAILURE) != 0 {
		parts = append(parts, "PRECT_FAILURE")
	}

	if len(parts) == 0 {
		return fmt.Sprintf("0x%02x", flags)
	}
	return fmt.Sprintf("%s (0x%02x)", strings.Join(parts, "|"), flags)
}
