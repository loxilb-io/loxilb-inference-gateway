/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */

package loxinet

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>
#include "lxb_trace_event.h"
#include "lxb_ring.h"

// Inline C functions for atomic operations (CGO-compatible)
static inline uint32_t atomic_load_relaxed(volatile uint32_t *ptr) {
    return __atomic_load_n(ptr, __ATOMIC_RELAXED);
}

static inline uint32_t atomic_load_acquire(volatile uint32_t *ptr) {
    return __atomic_load_n(ptr, __ATOMIC_ACQUIRE);
}

static inline void atomic_store_release(volatile uint32_t *ptr, uint32_t val) {
    __atomic_store_n(ptr, val, __ATOMIC_RELEASE);
}

// Note: Event type and flag constants are now imported from lxb_trace_event.h
// No need to redefine them here
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/loxilb-io/loxilb/pkg/plugins/mcp"
	"github.com/loxilb-io/loxilb/pkg/plugins/openai"
	tk "github.com/loxilb-io/loxilib"
)

const (
	LXB_RING_CAP = 8192
)

// TraceEvent is the Go-friendly representation of lxb_trace_event_t
type TraceEvent struct {
	// Trace Context (W3C)
	TraceIDHi    uint64
	TraceIDLo    uint64
	SpanID       uint64
	ParentSpanID uint64
	TimestampNs  uint64
	DurationUs   uint32

	// Event Metadata
	EventType uint8
	Flags     uint8
	CatalogID uint16

	// HTTP Semantic Attributes
	HTTPMethod     string
	HTTPMajor      uint8
	HTTPMinor      uint8
	HTTPTarget     string
	HTTPHost       string
	HTTPStatusCode uint16
	ContentLength  uint32
	ContentType    string

	// Connection Attributes
	ClientIP    uint32
	ClientPort  uint16
	BackendID   uint16
	BackendIP   uint32
	BackendPort uint16

	// TLS Attributes
	TLSVersion uint16
	TLSCipher  uint16

	// Error Attributes
	ErrorClass uint16
	ErrorCode  uint16

	// PHASE 1: Hybrid Body Storage (inline + file fallback)
	BodyLen       uint16 // Actual bytes in BodyData (0-280)
	BodyTruncated bool   // true if body > 280 bytes (file fallback active)
	IsStreaming   bool   // true if Transfer-Encoding: chunked
	IsJSON        bool   // true if Content-Type: application/json
	BodyData      []byte // Inline body preview (first 280 bytes, max)

	// Deep Inspection (optional, for large bodies)
	HasBodyFile  bool
	BodyFilePath string // Relative filename if has_body_file=true

	// Session Tracking (for session-level tracing)
	SessionHeaderName  string // Custom session header name (e.g., "mcp-session-id")
	SessionHeaderValue string // Session header value
	ConversationID     string // Conversation ID for OpenAI/MCP

	// Protocol Attributes (extracted by parsers)
	ParsedAttributes map[string]interface{} // MCP, OpenAI, etc. protocol-specific attributes
}

// RingBuffer represents a memory-mapped ring buffer
type RingBuffer struct {
	WorkerID int
	Path     string
	Data     []byte        // mmap'd memory
	Ring     *C.lxb_ring_t // Pointer to C struct
	EventFD  int           // eventfd for notifications
	Capacity uint32        // Ring capacity (8192)

	// Statistics
	drained     uint64 // Total events drained (atomic)
	lastDrained uint64 // Last log timestamp
}

// RingConsumer manages multiple ring buffers with efficient epoll-based polling
type RingConsumer struct {
	Rings     []*RingBuffer
	EventChan chan *TraceEvent
	StopChan  chan struct{}
	wg        sync.WaitGroup
	cfg       TraceConfig

	// PHASE 2: Parser Infrastructure
	parserRegistry *TraceParserRegistry

	// Statistics
	totalDrained uint64 // Total events across all rings (atomic)
	totalDropped uint64 // Total dropped events (atomic)
}

// NewRingConsumer discovers and mmaps all ring buffers
//
// Discovery Process:
// 1. Glob /dev/shm/loxilb-trace-ring-<pid>-* files
// 2. Open each file with O_RDWR (shared memory)
// 3. mmap into Go memory space (zero-copy access)
// 4. Extract eventfd from ring header for epoll
//
// Returns error if no ring files found or all mmap operations fail.
func NewRingConsumer() (*RingConsumer, error) {
	cfg := LoadTraceConfig()

	rc := &RingConsumer{
		EventChan: make(chan *TraceEvent, cfg.EventChannelSize),
		StopChan:  make(chan struct{}),
		cfg:       cfg,
	}

	// Discover ring files for CURRENT process only (pattern: /dev/shm/loxilb-trace-ring-<pid>-<worker>)
	// Filter by current PID to avoid stale files from previous loxilb instances
	currentPID := os.Getpid()
	pattern := fmt.Sprintf("/dev/shm/loxilb-trace-ring-%d-*", currentPID)
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("[RingConsumer] Failed to discover ring files: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("[RingConsumer] No ring files found (pattern: %s, pid=%d). Is tracing enabled?", pattern, currentPID)
	}

	tk.LogIt(tk.LogInfo, "[RingConsumer] Found %d ring buffer file(s) for PID %d\n", len(files), currentPID)

	// Open and mmap each ring
	for _, path := range files {
		rb, err := openRingBuffer(path)
		if err != nil {
			tk.LogIt(tk.LogWarning, "[RingConsumer] Failed to open %s: %v\n", path, err)
			continue
		}
		rc.Rings = append(rc.Rings, rb)
		tk.LogIt(tk.LogInfo, "[RingConsumer] Opened ring[%d]: path=%s eventfd=%d cap=%d\n",
			rb.WorkerID, rb.Path, rb.EventFD, rb.Capacity)
	}

	if len(rc.Rings) == 0 {
		return nil, fmt.Errorf("[RingConsumer] Failed to open any ring buffers")
	}

	// PHASE 2 & 3: Initialize parser registry with production parsers
	rc.parserRegistry = NewTraceParserRegistry()

	// PHASE 3: Register production parsers (OpenAI, MCP)
	rc.registerProductionParsers()

	// Register mock parser as fallback for unknown protocols
	mockParser := newInternalMockParser()
	rc.parserRegistry.RegisterDefaultParser(mockParser)

	tk.LogIt(tk.LogInfo, "[RingConsumer] Initialized parser registry with OpenAI, MCP, and mock parsers\n")

	return rc, nil
}

// openRingBuffer mmaps a single ring buffer file
func openRingBuffer(path string) (*RingBuffer, error) {
	// Open shared memory file (created by C dataplane)
	fd, err := unix.Open(path, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open failed: %w", err)
	}
	defer unix.Close(fd) // fd no longer needed after mmap

	// Get file size
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat failed: %w", err)
	}

	// CRITICAL FIX: Validate file size matches expected ring buffer struct size
	// This detects corrupted/incomplete files from crashed instances
	expectedSize := int64(unsafe.Sizeof(C.lxb_ring_t{}))
	if stat.Size() != expectedSize {
		return nil, fmt.Errorf("invalid ring file size: got %d bytes, expected %d bytes (corrupted file?)",
			stat.Size(), expectedSize)
	}

	// mmap the file (zero-copy access to C dataplane memory)
	data, err := unix.Mmap(fd, 0, int(stat.Size()),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap failed: %w", err)
	}

	// Cast to C struct (unsafe pointer conversion)
	ring := (*C.lxb_ring_t)(unsafe.Pointer(&data[0]))

	// CRITICAL FIX: Validate ring structure integrity
	// Capacity should match expected value (LXB_RING_CAP = 8192)
	capacity := uint32(ring.cap)
	if capacity == 0 || capacity > 65536 {
		unix.Munmap(data)
		return nil, fmt.Errorf("invalid ring capacity: %d (corrupted structure?)", capacity)
	}

	// Extract metadata
	eventfd := int(ring.eventfd)

	// Parse worker ID from filename (format: loxilb-trace-ring-<pid>-<worker>)
	basename := filepath.Base(path)
	parts := filepath.SplitList(basename)
	workerID := 0
	if len(parts) > 0 {
		// Extract last number from filename: "loxilb-trace-ring-46240-3" -> 3
		lastDash := -1
		for i := len(basename) - 1; i >= 0; i-- {
			if basename[i] == '-' {
				lastDash = i
				break
			}
		}
		if lastDash > 0 && lastDash < len(basename)-1 {
			fmt.Sscanf(basename[lastDash+1:], "%d", &workerID)
		}
	}

	return &RingBuffer{
		WorkerID: workerID,
		Path:     path,
		Data:     data,
		Ring:     ring,
		EventFD:  eventfd,
		Capacity: capacity,
	}, nil
}

// registerProductionParsers registers OpenAI and MCP parsers with path-based routing
// Called during RingConsumer initialization
func (rc *RingConsumer) registerProductionParsers() {
	// Create parser instances
	openaiParser := openai.NewOpenAIParser()
	mcpParser := mcp.NewMCPParser()

	// Register parsers by name for dynamic catalog mapping
	rc.parserRegistry.RegisterParserByName("openai", openaiParser)
	rc.parserRegistry.RegisterParserByName("mcp", mcpParser)
	rc.parserRegistry.RegisterParserByName("mock", newInternalMockParser())

	tk.LogIt(tk.LogInfo, "[RingConsumer] Registered parsers by name: openai, mcp, mock\n")

	// Register OpenAI parser for typical OpenAI API paths
	// These paths are standard across OpenAI-compatible APIs (OpenAI, Azure OpenAI, vLLM, etc.)
	rc.parserRegistry.RegisterPathParser("/v1/chat/completions", openaiParser)
	rc.parserRegistry.RegisterPathParser("/v1/completions", openaiParser)
	rc.parserRegistry.RegisterPathParser("/v1/embeddings", openaiParser)
	rc.parserRegistry.RegisterPathParser("/v1/engines", openaiParser)
	rc.parserRegistry.RegisterPathParser("/v1/models", openaiParser)

	tk.LogIt(tk.LogInfo, "[RingConsumer] Registered OpenAI parser for /v1/* paths\n")

	// Register MCP parser for Model Context Protocol endpoints
	// MCP can be hosted at various paths depending on deployment
	rc.parserRegistry.RegisterPathParser("/mcp", mcpParser)
	rc.parserRegistry.RegisterPathParser("/mcp-server", mcpParser)
	rc.parserRegistry.RegisterPathParser("/.well-known/mcp", mcpParser)

	tk.LogIt(tk.LogInfo, "[RingConsumer] Registered MCP parser for /mcp* paths\n")

	// NOTE: Catalog-based routing is now dynamic via YAML parser_type field
	// Hard-coded catalog ID mappings removed - use SyncCatalogParser instead
	// Parser selection priority:
	//   1. catalog_id lookup (populated from YAML parser_type)
	//   2. URL path prefix match (static registrations above)
	//   3. Default mock parser (fallback)

	// Debug: Log parser registration details if trace debug is enabled
	if os.Getenv("LOXILB_TRACE_DEBUG") != "" {
		tk.LogIt(tk.LogDebug, "[RingConsumer] Parser registry initialized:\n")
		tk.LogIt(tk.LogDebug, "  - Available parsers: %v\n", rc.parserRegistry.ListAvailableParsers())
		tk.LogIt(tk.LogDebug, "  - OpenAI parser: 5 path patterns\n")
		tk.LogIt(tk.LogDebug, "  - MCP parser: 3 path patterns\n")
		tk.LogIt(tk.LogDebug, "  - Mock parser: default fallback\n")
		tk.LogIt(tk.LogDebug, "  - Catalog mappings: synced from YAML at runtime\n")
	}
}

// Start begins consuming events from all rings using epoll
//
// Architecture:
// 1. Create epoll instance for monitoring all eventfds
// 2. Add all ring eventfds to epoll interest list
// 3. Start consumer goroutine with configurable timeout
// 4. On eventfd notification, drain all available events
// 5. Non-blocking send to EventChan (drop if full)
func (rc *RingConsumer) Start() error {
	// Create epoll instance
	epfd, err := unix.EpollCreate1(0)
	if err != nil {
		return fmt.Errorf("[RingConsumer] Failed to create epoll: %w", err)
	}

	// Add all eventfds to epoll
	for _, rb := range rc.Rings {
		if rb.EventFD >= 0 {
			event := unix.EpollEvent{
				Events: unix.EPOLLIN,
				Fd:     int32(rb.EventFD),
			}
			if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, rb.EventFD, &event); err != nil {
				tk.LogIt(tk.LogWarning, "[RingConsumer] Failed to add eventfd %d to epoll: %v\n",
					rb.EventFD, err)
			}
		}
	}

	// Start consumer goroutine
	rc.wg.Add(1)
	go rc.consumerLoop(epfd)

	tk.LogIt(tk.LogInfo, "[RingConsumer] Started consumer loop (epoll_fd=%d, rings=%d)\n",
		epfd, len(rc.Rings))

	return nil
}

// Stop gracefully stops the consumer
func (rc *RingConsumer) Stop() {
	close(rc.StopChan)
	rc.wg.Wait()

	// Final drain of all rings
	for _, rb := range rc.Rings {
		rc.drainRing(rb)
	}

	// Unmap all rings (but don't delete shm files yet - CleanupCRings does that)
	for _, rb := range rc.Rings {
		if err := unix.Munmap(rb.Data); err != nil {
			tk.LogIt(tk.LogWarning, "[RingConsumer] Failed to munmap ring[%d]: %v\n", rb.WorkerID, err)
		}
	}

	close(rc.EventChan)

	tk.LogIt(tk.LogInfo, "[RingConsumer] Stopped. Total drained=%d dropped=%d\n",
		atomic.LoadUint64(&rc.totalDrained), atomic.LoadUint64(&rc.totalDropped))
}

// CleanupCRings calls the C cleanup function to delete shm files
// MUST be called AFTER Stop to ensure memory is unmapped first
// This is necessary because os.Exit doesn't trigger atexit handlers
func (rc *RingConsumer) CleanupCRings() {
	// Call C cleanup function directly
	C.lxb_ring_cleanup()
	tk.LogIt(tk.LogInfo, "[RingConsumer] Called C ring cleanup (shm files deleted)\n")
}

// consumerLoop polls eventfds and drains rings
func (rc *RingConsumer) consumerLoop(epfd int) {
	defer rc.wg.Done()
	defer unix.Close(epfd)

	events := make([]unix.EpollEvent, len(rc.Rings))
	timeoutMs := rc.cfg.ConsumerPollMs

	for {
		select {
		case <-rc.StopChan:
			tk.LogIt(tk.LogInfo, "[RingConsumer] Stopping consumer loop\n")
			return
		default:
		}

		// epoll_wait with configurable timeout (default: 1ms)
		n, err := unix.EpollWait(epfd, events, timeoutMs)
		if err != nil {
			if err == unix.EINTR {
				continue // Interrupted by signal, retry
			}
			tk.LogIt(tk.LogError, "[RingConsumer] epoll_wait failed: %v\n", err)
			time.Sleep(100 * time.Millisecond) // Backoff on error
			continue
		}

		if n > 0 {
			// Drain all rings (not just notified ones, for completeness)
			for _, rb := range rc.Rings {
				rc.drainRing(rb)
			}

			// Consume eventfd values to reset edge-triggered notifications
			for i := 0; i < n; i++ {
				fd := int(events[i].Fd)
				var val uint64
				unix.Read(fd, (*(*[8]byte)(unsafe.Pointer(&val)))[:])
			}
		}
	}
}

// drainRing drains all available events from a ring buffer
func (rc *RingConsumer) drainRing(rb *RingBuffer) {
	drained := 0
	dropped := 0

	for {
		// Atomic read of ring indices using GCC built-ins
		r := uint32(C.atomic_load_relaxed(&rb.Ring.r))
		w := uint32(C.atomic_load_acquire(&rb.Ring.w))

		if r == w {
			break // Ring empty
		}

		// Read event from ring
		cEvt := &rb.Ring.ev[r]
		goEvt := rc.convertEvent(cEvt)

		// DEBUG: Log body capture details for REQ_START events
		if goEvt.EventType == 1 { // LXB_EVENT_REQ_START
			tk.LogIt(tk.LogDebug, "[BODY_DEBUG] REQ_START event: BodyLen=%d HasBodyFile=%v BodyFilePath='%s'\n",
				goEvt.BodyLen, goEvt.HasBodyFile, goEvt.BodyFilePath)
		}

		// PHASE 2: Dispatch to parser if body data present
		if goEvt.BodyLen > 0 || goEvt.HasBodyFile {
			rc.parseEventBody(goEvt)
		}

		// Non-blocking send to event channel
		select {
		case rc.EventChan <- goEvt:
			drained++
			atomic.AddUint64(&rb.drained, 1)
			atomic.AddUint64(&rc.totalDrained, 1)
		default:
			// Channel full, drop event
			dropped++
			atomic.AddUint64(&rc.totalDropped, 1)

			// Throttled logging (every 100 drops)
			if dropped%100 == 1 {
				tk.LogIt(tk.LogWarning, "[RingConsumer] Event channel full, dropped %d events from ring[%d]\n",
					dropped, rb.WorkerID)
			}
		}

		// Advance read index (release barrier for producer visibility)
		r = (r + 1) & (LXB_RING_CAP - 1)
		C.atomic_store_release(&rb.Ring.r, C.uint(r))
	}

	// Adaptive logging (every N events or every 10 seconds)
	if drained > 0 {
		now := uint64(time.Now().Unix())
		if drained >= rc.cfg.DrainLogInterval || (now-rb.lastDrained) >= 10 {
			tk.LogIt(tk.LogDebug, "[RingConsumer] Drained %d events from ring[%d] (total=%d)\n",
				drained, rb.WorkerID, atomic.LoadUint64(&rb.drained))
			rb.lastDrained = now
		}
	}

	// Alert on high drop rate
	if dropped > 0 && dropped > drained/10 {
		tk.LogIt(tk.LogError, "[RingConsumer] High drop rate: %d/%d (%.1f%%) in ring[%d]\n",
			dropped, drained+dropped, float64(dropped)*100/float64(drained+dropped), rb.WorkerID)
	}
}

// parseEventBody dispatches event to parser and merges extracted attributes
func (rc *RingConsumer) parseEventBody(evt *TraceEvent) {
	if rc.parserRegistry == nil {
		return // Parser not initialized
	}

	// Build parser context from event metadata
	ctx := TraceParserContext{
		CatalogID:   evt.CatalogID,
		ContentType: evt.ContentType,
		Method:      evt.HTTPMethod,
		URLPath:     evt.HTTPTarget,
		IsStreaming: evt.IsStreaming,
		IsJSON:      evt.IsJSON,
	}

	// Determine request vs. response direction
	isRequest := (evt.EventType == C.LXB_EVENT_REQ_START || evt.EventType == C.LXB_EVENT_REQ_END)

	// Prepare body file path (if file-based)
	bodyFilePath := ""
	if evt.HasBodyFile && evt.BodyFilePath != "" {
		// Construct full path: /dev/shm/<filename>
		bodyFilePath = "/dev/shm/" + evt.BodyFilePath
	}

	tk.LogIt(tk.LogDebug, "[PARSER_INVOKE] Dispatching to parser: catalog_id=%d method=%s path=%s body_len=%d is_request=%v\n",
		ctx.CatalogID, ctx.Method, ctx.URLPath, len(evt.BodyData), isRequest)

	// Dispatch to parser registry
	attrs := rc.parserRegistry.Parse(ctx, evt.BodyData, bodyFilePath, isRequest)

	if attrs != nil && len(attrs) > 0 {
		// Store parsed attributes in event for SpanAssembler to attach to spans
		evt.ParsedAttributes = attrs
		tk.LogIt(tk.LogDebug, "[PARSER_INVOKE_SUCCESS] Parsed %d attributes for trace_id=%x-%x catalog_id=%d: %+v\n",
			len(attrs), evt.TraceIDHi, evt.TraceIDLo, evt.CatalogID, attrs)
	} else {
		tk.LogIt(tk.LogDebug, "[PARSER_INVOKE_EMPTY] No attributes extracted for catalog_id=%d trace_id=%x-%x\n",
			ctx.CatalogID, evt.TraceIDHi, evt.TraceIDLo)
	}
}

// convertEvent converts C event to Go event (zero-alloc where possible)
func (rc *RingConsumer) convertEvent(cEvt *C.lxb_trace_event_t) *TraceEvent {
	// DEBUG: Log raw C struct fields to diagnose type mismatch
	eventType := uint8(cEvt.event_type)
	if eventType == 0 {
		tk.LogIt(tk.LogError, "[RingConsumer] BUG: event_type=0 detected! Raw C struct dump:\n"+
			"  trace_id_hi=%x trace_id_lo=%x\n"+
			"  span_id=%x timestamp=%d\n"+
			"  duration_us=%d event_type=%d flags=%x catalog_id=%d\n"+
			"  http_method='%s' http_target='%s'\n"+
			"  STRUCT SIZE=%d bytes\n",
			uint64(cEvt.trace_id_hi), uint64(cEvt.trace_id_lo),
			uint64(cEvt.span_id), uint64(cEvt.timestamp_ns),
			uint32(cEvt.duration_us), uint8(cEvt.event_type), uint8(cEvt.flags), uint16(cEvt.catalog_id),
			C.GoString((*C.char)(unsafe.Pointer(&cEvt.http_method[0]))),
			C.GoString((*C.char)(unsafe.Pointer(&cEvt.http_target[0]))),
			unsafe.Sizeof(*cEvt))
	}

	return &TraceEvent{
		// Trace Context
		TraceIDHi:    uint64(cEvt.trace_id_hi),
		TraceIDLo:    uint64(cEvt.trace_id_lo),
		SpanID:       uint64(cEvt.span_id),
		ParentSpanID: uint64(cEvt.parent_span_id),
		TimestampNs:  uint64(cEvt.timestamp_ns),
		DurationUs:   uint32(cEvt.duration_us),

		// Event Metadata
		EventType: eventType,
		Flags:     uint8(cEvt.flags),
		CatalogID: uint16(cEvt.catalog_id),

		// HTTP Attributes (convert C strings to Go strings)
		HTTPMethod:     C.GoString((*C.char)(unsafe.Pointer(&cEvt.http_method[0]))),
		HTTPTarget:     C.GoString((*C.char)(unsafe.Pointer(&cEvt.http_target[0]))),
		HTTPHost:       C.GoString((*C.char)(unsafe.Pointer(&cEvt.http_host[0]))),
		HTTPStatusCode: uint16(cEvt.http_status_code),
		ContentLength:  uint32(cEvt.content_length),
		ContentType:    C.GoString((*C.char)(unsafe.Pointer(&cEvt.content_type[0]))),

		// Connection Attributes
		ClientIP:    uint32(cEvt.client_ip),
		ClientPort:  uint16(cEvt.client_port),
		BackendID:   uint16(cEvt.backend_id),
		BackendIP:   uint32(cEvt.backend_ip),
		BackendPort: uint16(cEvt.backend_port),

		// TLS Attributes
		TLSVersion: uint16(cEvt.tls_version),
		TLSCipher:  uint16(cEvt.tls_cipher),

		// Error Attributes
		ErrorClass: uint16(cEvt.error_class),
		ErrorCode:  uint16(cEvt.error_code),

		// PHASE 1: Hybrid Body Storage
		BodyLen:       uint16(cEvt.body_len),
		BodyTruncated: uint8(cEvt.body_truncated) != 0,
		IsStreaming:   uint8(cEvt.is_streaming) != 0,
		IsJSON:        uint8(cEvt.is_json) != 0,
		// Copy inline body data (only if present)
		BodyData: func() []byte {
			if cEvt.body_len > 0 {
				// Create slice from C array without copying (zero-alloc)
				return C.GoBytes(unsafe.Pointer(&cEvt.body_data[0]), C.int(cEvt.body_len))
			}
			return nil
		}(),

		// Session Tracking
		SessionHeaderName:  C.GoString((*C.char)(unsafe.Pointer(&cEvt.session_header_name[0]))),
		SessionHeaderValue: C.GoString((*C.char)(unsafe.Pointer(&cEvt.session_header_value[0]))),
		ConversationID:     C.GoString((*C.char)(unsafe.Pointer(&cEvt.conversation_id[0]))),

		// Deep Inspection (optional)
		HasBodyFile:  uint8(cEvt.has_body_file) != 0,
		BodyFilePath: C.GoString((*C.char)(unsafe.Pointer(&cEvt.body_file_path[0]))),
	}
}

// GetStats returns per-ring statistics
func (rc *RingConsumer) GetStats() []RingStats {
	stats := make([]RingStats, len(rc.Rings))
	for i, rb := range rc.Rings {
		r := uint32(C.atomic_load_relaxed(&rb.Ring.r))
		w := uint32(C.atomic_load_relaxed(&rb.Ring.w))
		dropped := uint32(C.atomic_load_relaxed(&rb.Ring.dropped))

		pending := uint32(0)
		if w >= r {
			pending = w - r
		} else {
			pending = LXB_RING_CAP - r + w
		}

		stats[i] = RingStats{
			WorkerID:  rb.WorkerID,
			Drained:   atomic.LoadUint64(&rb.drained),
			Pending:   pending,
			Dropped:   uint64(dropped),
			FillRatio: float64(pending) / float64(LXB_RING_CAP),
		}
	}
	return stats
}

// GetParserRegistry returns the parser registry for dynamic configuration
// Used by CatalogSyncManager to sync catalog_id -> parser mappings
func (rc *RingConsumer) GetParserRegistry() *TraceParserRegistry {
	return rc.parserRegistry
}

// RingStats holds per-ring statistics
type RingStats struct {
	WorkerID  int
	Drained   uint64
	Pending   uint32
	Dropped   uint64
	FillRatio float64
}

// EventTypeName returns human-readable event type name
func EventTypeName(typ uint8) string {
	switch typ {
	case C.LXB_EVENT_REQ_START:
		return "REQ_START"
	case C.LXB_EVENT_REQ_END:
		return "REQ_END"
	case C.LXB_EVENT_UP_START:
		return "UP_START"
	case C.LXB_EVENT_UP_END:
		return "UP_END"
	case C.LXB_EVENT_TLS_HS:
		return "TLS_HS"
	case C.LXB_EVENT_STREAM_MARK:
		return "STREAM_MARK"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", typ)
	}
}
