//go:build l4trace
// +build l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * L4 Connection Tracing: Ring Buffer Consumer
 *
 * This file implements the Go-side consumer for L4 tracing events from eBPF
 * ring buffers. It follows the same architecture as L7 HTTP tracing but is
 * specialized for L4 connection lifecycle events.
 */

package loxinet

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "lxb_l4_trace_event.h"

// Inline C functions for atomic operations (CGO-compatible)
static inline uint32_t l4_atomic_load_relaxed(volatile uint32_t *ptr) {
    return __atomic_load_n(ptr, __ATOMIC_RELAXED);
}

static inline uint32_t l4_atomic_load_acquire(volatile uint32_t *ptr) {
    return __atomic_load_n(ptr, __ATOMIC_ACQUIRE);
}

static inline void l4_atomic_store_release(volatile uint32_t *ptr, uint32_t val) {
    __atomic_store_n(ptr, val, __ATOMIC_RELEASE);
}
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	tk "github.com/loxilb-io/loxilib"
	"golang.org/x/sys/unix"
)

const (
	// Ring buffer configuration
	L4_RING_CAP = 2 * 1024 * 1024 // 2MB per worker (matches eBPF definition)

	// Poll configuration
	L4_POLL_TIMEOUT_MS = 1  // 1ms epoll timeout
	L4_BATCH_SIZE      = 64 // Process up to 64 events per poll

	// Statistics logging interval
	L4_STATS_LOG_INTERVAL = 10 * time.Second
)

// L4TraceEvent is the Go-friendly representation of lxb_l4_trace_event_t
type L4TraceEvent struct {
	// Trace Context
	TimestampNs uint64
	SpanID      uint64

	// Event Metadata
	EventType uint8
	Protocol  uint8
	OldState  uint8
	NewState  uint8
	Zone      uint16
	ErrorCode uint32
	Flags     uint8

	// Connection 5-tuple
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16

	// Backend Selection (Load Balancer)
	BackendIP   net.IP
	BackendPort uint16
	BackendID   uint16

	// Traffic Statistics
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint32
	PacketsRecv uint32

	// Performance Metrics
	RTTMicros   uint32
	RetransSent uint32
	RetransRecv uint32
	WindowSize  uint32

	// TCP Specific
	TCPFlags uint8
	MSS      uint32

	// Sampling Metadata
	SamplingAlgorithm uint8
	SamplingRate      uint8
}

// L4RingBuffer represents a memory-mapped L4 trace ring buffer
type L4RingBuffer struct {
	WorkerID int
	Path     string
	Data     []byte // mmap'd data area
	Capacity uint32

	// Ring buffer pointers (into separate mmap regions)
	// BPF ring buffer uses unsigned long (64-bit) for cursors
	Producer *uint64 // Consumer-side read of producer position
	Consumer *uint64 // Consumer-side write of consumer position

	// mmap regions for cleanup
	consumerPage []byte // Consumer page mmap
	producerData []byte // Producer+data pages mmap

	// Statistics
	Drained     uint64 // Total events drained (atomic)
	LastDrained uint64 // Last log timestamp
	Errors      uint64 // Parse errors (atomic)
}

// L4RingConsumer manages L4 ring buffer with polling
type L4RingConsumer struct {
	Rings     []*L4RingBuffer
	EventChan chan *L4TraceEvent
	StopChan  chan struct{}
	wg        sync.WaitGroup

	// Statistics (atomic)
	TotalDrained    uint64 // Total events across all rings
	TotalDropped    uint64 // Ring buffer full events
	TCPEvents       uint64 // TCP protocol events
	SCTPEvents      uint64 // SCTP protocol events
	UDPEvents       uint64 // UDP protocol events
	ConnNew         uint64 // New connection events
	ConnEstablished uint64 // Established connection events
	ConnClosed      uint64 // Clean close events
	ConnTimeout     uint64 // Timeout events
	ConnReset       uint64 // Reset events
	ConnError       uint64 // Error events

	// Span assembler reference
	assembler *L4SpanAssembler
}

// NewL4RingConsumer creates a ring buffer consumer using the provided eBPF map FD
//
// Discovery Process:
// 1. Accept ring buffer FD from DpEbpfH (obtained via llb_map2fd)
// 2. If FD <= 0, return no-op consumer (L4 tracing not compiled)
// 3. Otherwise, setup ring buffer access via FD
//
// Returns error if mmap fails.
func NewL4RingConsumer(assembler *L4SpanAssembler, ringBufFD int) (*L4RingConsumer, error) {
	tk.LogIt(tk.LogInfo, "[L4_TRACE_CONSUMER] Starting L4 ring buffer consumer\n")

	// Check if ring buffer is available
	if ringBufFD <= 0 {
		tk.LogIt(tk.LogWarning, "[L4_TRACE_CONSUMER] No L4 trace ring buffer FD (FD=%d) - L4 tracing not compiled or not available\n", ringBufFD)
		// Return consumer with no rings - will be no-op
		return &L4RingConsumer{
			Rings:     make([]*L4RingBuffer, 0),
			EventChan: assembler.EventChan,
			StopChan:  make(chan struct{}),
			assembler: assembler,
		}, nil
	}

	tk.LogIt(tk.LogInfo, "[L4_TRACE_CONSUMER] Found L4 ring buffer FD: %d\n", ringBufFD)

	// Create consumer
	consumer := &L4RingConsumer{
		Rings:     make([]*L4RingBuffer, 0, 1),
		EventChan: assembler.EventChan,
		StopChan:  make(chan struct{}),
		assembler: assembler,
	}

	// Open ring buffer using FD
	ring, err := openL4RingBufferByFD(ringBufFD, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open ring buffer FD %d: %w", ringBufFD, err)
	}

	consumer.Rings = append(consumer.Rings, ring)
	tk.LogIt(tk.LogInfo, "[L4_TRACE_CONSUMER] Mapped ring buffer: FD=%d capacity=%d\n", ringBufFD, ring.Capacity)

	return consumer, nil
}

// openL4RingBufferByFD opens and mmaps a ring buffer using an existing FD
func openL4RingBufferByFD(fd int, workerID int) (*L4RingBuffer, error) {
	// BPF ring buffers require two separate mmap calls:
	// 1. Consumer page (offset 0, one page, read-write)
	// 2. Producer + data pages (offset page_size, 2*ring_size, read-only)

	pageSize := unix.Getpagesize()

	// Map consumer page (writable) at offset 0
	consumerPage, err := unix.Mmap(fd, 0, pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap consumer page: %w", err)
	}

	// Map producer page + data (read-only) at offset page_size
	// Size = page_size (producer) + 2*L4_RING_CAP (data, doubled for wrap-around)
	producerDataSize := pageSize + 2*L4_RING_CAP
	producerData, err := unix.Mmap(fd, int64(pageSize), producerDataSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(consumerPage)
		return nil, fmt.Errorf("failed to mmap producer+data pages: %w", err)
	}

	// Ring buffer layout:
	// Consumer page: [0-7] = consumer position (uint64)
	// Producer page: [0-7] = producer position (uint64)
	// Data area: starts at producerData[pageSize:]

	ring := &L4RingBuffer{
		WorkerID:     workerID,
		Path:         fmt.Sprintf("FD:%d", fd),
		Data:         producerData[pageSize:], // Point to data area only
		Capacity:     L4_RING_CAP,
		Producer:     (*uint64)(unsafe.Pointer(&producerData[0])),
		Consumer:     (*uint64)(unsafe.Pointer(&consumerPage[0])),
		consumerPage: consumerPage, // Store for cleanup
		producerData: producerData, // Store for cleanup
	}

	return ring, nil
}

// openL4RingBuffer opens and mmaps a single ring buffer file
func openL4RingBuffer(path string, workerID int) (*L4RingBuffer, error) {
	// Open BPF map file
	fd, err := unix.Open(path, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open failed: %w", err)
	}
	defer unix.Close(fd)

	// Get file size
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat failed: %w", err)
	}

	size := int(stat.Size())
	if size < 4096 {
		return nil, fmt.Errorf("ring buffer too small: %d bytes", size)
	}

	// Memory-map the file
	data, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap failed: %w", err)
	}

	ring := &L4RingBuffer{
		WorkerID: workerID,
		Path:     path,
		Data:     data,
		Capacity: uint32(size),
	}

	// Setup ring buffer pointers (eBPF ringbuf uses 64-bit cursors)
	ring.Producer = (*uint64)(unsafe.Pointer(&data[0]))
	ring.Consumer = (*uint64)(unsafe.Pointer(&data[8]))

	return ring, nil
}

// Start begins consuming events from all ring buffers
func (rc *L4RingConsumer) Start() {
	if len(rc.Rings) == 0 {
		tk.LogIt(tk.LogWarning, "[L4_TRACE_CONSUMER] No rings to consume, consumer is no-op\n")
		return
	}

	tk.LogIt(tk.LogInfo, "[L4_TRACE_CONSUMER] Starting ring consumer with polling\n")

	// Start both poll loop and stats loop
	rc.wg.Add(2)
	go rc.pollLoop()
	go rc.statsLoop()
}

// Stop gracefully shuts down the consumer
func (rc *L4RingConsumer) Stop() {
	tk.LogIt(tk.LogInfo, "[L4_TRACE_CONSUMER] Stopping L4 ring consumer\n")

	// Signal all goroutines to stop
	close(rc.StopChan)

	// Wait for all goroutines (pollLoop + statsLoop) to finish
	rc.wg.Wait()

	// Unmap all ring buffers (both consumer page and producer+data pages)
	// BPF ring buffers automatically clean up via kernel when unmapped
	for _, ring := range rc.Rings {
		if err := unix.Munmap(ring.consumerPage); err != nil {
			tk.LogIt(tk.LogError, "[L4_TRACE_CONSUMER] Failed to munmap consumer page %d: %v\n", ring.WorkerID, err)
		}
		if err := unix.Munmap(ring.producerData); err != nil {
			tk.LogIt(tk.LogError, "[L4_TRACE_CONSUMER] Failed to munmap producer+data %d: %v\n", ring.WorkerID, err)
		}
	}

	// Close event channel to signal span assembler
	close(rc.EventChan)

	tk.LogIt(tk.LogInfo, "[L4_TRACE_CONSUMER] L4 ring consumer stopped (goroutines=%d, rings=%d unmapped)\n",
		2, len(rc.Rings)) // pollLoop + statsLoop
}

// pollLoop continuously polls ring buffers for new events
func (rc *L4RingConsumer) pollLoop() {
	defer rc.wg.Done()

	ticker := time.NewTicker(time.Millisecond * L4_POLL_TIMEOUT_MS)
	defer ticker.Stop()

	tk.LogIt(tk.LogDebug, "[L4_TRACE_CONSUMER] Poll loop started\n")

	for {
		select {
		case <-rc.StopChan:
			tk.LogIt(tk.LogDebug, "[L4_TRACE_CONSUMER] Poll loop stopping\n")
			return
		case <-ticker.C:
			// Poll all rings
			for _, ring := range rc.Rings {
				rc.drainRing(ring)
			}
		}
	}
}

// drainRing drains events from a single ring buffer
func (rc *L4RingConsumer) drainRing(ring *L4RingBuffer) {
	// BPF ring buffer uses 64-bit cursors (not 32-bit!)
	// Read producer position (written by eBPF) - unsigned long in kernel
	prod := *(*uint64)(unsafe.Pointer(ring.Producer))

	// Read consumer position (written by us)
	cons := *(*uint64)(unsafe.Pointer(ring.Consumer))

	// Consumer should never be ahead of producer
	// If it is, reset consumer to producer (caught up)
	if cons >= prod {
		if cons > prod {
			tk.LogIt(tk.LogWarning, "[L4_TRACE_DRAIN] Consumer ahead of producer! ring=%d prod=%d cons=%d - resetting\n",
				ring.WorkerID, prod, cons)
			*(*uint64)(unsafe.Pointer(ring.Consumer)) = prod
		}
		// No new events
		return
	}

	available := prod - cons
	tk.LogIt(tk.LogDebug, "[L4_TRACE_DRAIN] ring=%d prod=%d cons=%d available=%d\n",
		ring.WorkerID, prod, cons, available)

	eventsParsed := 0

	// Process up to L4_BATCH_SIZE events
	for i := 0; i < L4_BATCH_SIZE && cons < prod; i++ {
		// BPF ring buffer: contiguous data area with wrap-around
		// Offset into data area (mod ring capacity for wrap)
		offset := cons & (uint64(ring.Capacity) - 1)

		// BPF ring buffer format: [8-byte header][event data][padding]
		// Header: [4 bytes: length][4 bytes: flags/reserved]
		// We need to read the header to get the actual event length
		if offset+8 > uint64(len(ring.Data)) {
			tk.LogIt(tk.LogError, "[L4_TRACE_DRAIN] Cannot read header at offset=%d len=%d\n", offset, len(ring.Data))
			break
		}

		// Read event length from header (first 4 bytes, little-endian)
		eventLen := uint64(binary.LittleEndian.Uint32(ring.Data[offset : offset+4]))

		// Total record size = 8 (header) + eventLen + padding to 8-byte boundary
		recordSize := (8 + eventLen + 7) &^ 7

		if offset+recordSize > uint64(len(ring.Data)) {
			tk.LogIt(tk.LogError, "[L4_TRACE_DRAIN] Invalid record at offset=%d len=%d recordSize=%d\n",
				offset, len(ring.Data), recordSize)
			break
		}

		// Skip 8-byte header, read actual event data
		eventData := ring.Data[offset+8 : offset+8+eventLen]

		// Parse event from ring buffer
		event, err := rc.parseL4Event(eventData)
		if err != nil {
			tk.LogIt(tk.LogError, "[L4_TRACE_DRAIN] Parse error at offset=%d: %v\n", offset, err)
			atomic.AddUint64(&ring.Errors, 1)
			cons += recordSize
			continue
		}

		// Send to event channel (non-blocking)
		select {
		case rc.EventChan <- event:
			eventsParsed++
			// Track protocol-specific statistics
			rc.updateEventStatistics(event)
		default:
			// Channel full, drop event
			atomic.AddUint64(&rc.TotalDropped, 1)
			tk.LogIt(tk.LogWarning, "[L4_TRACE_DRAIN] Event channel full, dropping event\n")
		}

		cons += recordSize
	}

	// Update consumer position (store full 64-bit value)
	*(*uint64)(unsafe.Pointer(ring.Consumer)) = cons

	if eventsParsed > 0 {
		atomic.AddUint64(&ring.Drained, uint64(eventsParsed))
		atomic.AddUint64(&rc.TotalDrained, uint64(eventsParsed))

		tk.LogIt(tk.LogDebug, "[L4_TRACE_DRAIN] ring=%d drained=%d new_cons=%d\n",
			ring.WorkerID, eventsParsed, cons)
	}
}

// parseL4Event converts C event structure to Go TraceEvent
func (rc *L4RingConsumer) parseL4Event(data []byte) (*L4TraceEvent, error) {
	if len(data) < 256 {
		return nil, fmt.Errorf("event data too short: %d bytes", len(data))
	}

	// Cast to C struct pointer
	cEvent := (*C.lxb_l4_trace_event_t)(unsafe.Pointer(&data[0]))

	// Convert to Go struct
	// Note: Ports are in network byte order (big endian) from kernel, need to swap to host order
	event := &L4TraceEvent{
		TimestampNs:       uint64(cEvent.timestamp_ns),
		SpanID:            uint64(cEvent.span_id),
		EventType:         uint8(cEvent.event_type),
		Protocol:          uint8(cEvent.protocol),
		OldState:          uint8(cEvent.old_state),
		NewState:          uint8(cEvent.new_state),
		Zone:              uint16(cEvent.catalog_id),
		ErrorCode:         uint32(cEvent.error_code),
		Flags:             uint8(cEvent.flags),
		SrcPort:           binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&cEvent.client_port))[:]),
		DstPort:           binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&cEvent.server_port))[:]),
		BytesSent:         uint64(cEvent.bytes_out),
		BytesRecv:         uint64(cEvent.bytes_in),
		PacketsSent:       uint32(cEvent.packets_out),
		PacketsRecv:       uint32(cEvent.packets_in),
		RTTMicros:         uint32(cEvent.rtt_us),
		SamplingAlgorithm: 0,
		SamplingRate:      0,
	}

	// Convert IP addresses (handle both IPv4 and IPv6)
	event.SrcIP = parseL4IPAddress(cEvent.client_ip[:])
	event.DstIP = parseL4IPAddress(cEvent.server_ip[:])
	event.BackendIP = parseL4IPAddress(cEvent.backend_ip[:])

	// Parse backend info
	event.BackendPort = uint16(C.ntohs(cEvent.backend_port))
	event.BackendID = uint16(cEvent.backend_id)

	// Parse performance metrics
	event.RetransSent = uint32(cEvent.retrans_out)
	event.RetransRecv = uint32(cEvent.retrans_in)
	event.WindowSize = uint32(cEvent.window_size)

	// Parse TCP specific fields (cEvent.proto is a union represented as [32]byte)
	if event.Protocol == 6 { // TCP
		// TCP union layout: seq_in(4) seq_out(4) ack_in(4) ack_out(4) mss(4) tcp_flags(1) _pad(11)
		protoBytes := (*[32]byte)(unsafe.Pointer(&cEvent.proto[0]))
		event.MSS = binary.LittleEndian.Uint32(protoBytes[16:20])
		event.TCPFlags = protoBytes[20]
	}

	// Log with backend info if available
	if event.BackendPort > 0 {
		tk.LogIt(tk.LogDebug, "[L4_TRACE_PARSE] span=%016x event=%s proto=%s state=%s→%s %s:%d→%s:%d backend=%s:%d bytes=%d\n",
			event.SpanID,
			l4EventTypeName(event.EventType),
			l4ProtocolName(event.Protocol),
			l4StateName(event.Protocol, event.OldState),
			l4StateName(event.Protocol, event.NewState),
			event.SrcIP, event.SrcPort, event.DstIP, event.DstPort,
			event.BackendIP, event.BackendPort,
			event.BytesSent)
	} else {
		tk.LogIt(tk.LogDebug, "[L4_TRACE_PARSE] span=%016x event=%s proto=%s state=%s→%s %s:%d→%s:%d bytes=%d\n",
			event.SpanID,
			l4EventTypeName(event.EventType),
			l4ProtocolName(event.Protocol),
			l4StateName(event.Protocol, event.OldState),
			l4StateName(event.Protocol, event.NewState),
			event.SrcIP, event.SrcPort, event.DstIP, event.DstPort,
			event.BytesSent)
	}

	return event, nil
}

// parseL4IPAddress converts C uint32_t[4] to net.IP
func parseL4IPAddress(addr []C.uint32_t) net.IP {
	// Check if IPv4 (first 3 uint32_t are zero)
	if addr[1] == 0 && addr[2] == 0 && addr[3] == 0 {
		// IPv4: addr[0] contains IP in network byte order (__be32 from kernel)
		// We need to extract bytes in host order, then write to IP in network order
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(addr[0]))
		return ip
	}

	// IPv6
	ip := make(net.IP, 16)
	binary.LittleEndian.PutUint32(ip[0:4], uint32(addr[0]))
	binary.LittleEndian.PutUint32(ip[4:8], uint32(addr[1]))
	binary.LittleEndian.PutUint32(ip[8:12], uint32(addr[2]))
	binary.LittleEndian.PutUint32(ip[12:16], uint32(addr[3]))
	return ip
}

// statsLoop periodically logs statistics
func (rc *L4RingConsumer) statsLoop() {
	defer rc.wg.Done()

	ticker := time.NewTicker(L4_STATS_LOG_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-rc.StopChan:
			return
		case <-ticker.C:
			rc.logStats()
		}
	}
}

// logStats logs current statistics
func (rc *L4RingConsumer) logStats() {
	totalDrained := atomic.LoadUint64(&rc.TotalDrained)
	totalDropped := atomic.LoadUint64(&rc.TotalDropped)

	tk.LogIt(tk.LogInfo, "[L4_TRACE_STATS] Total: drained=%d dropped=%d rings=%d\n",
		totalDrained, totalDropped, len(rc.Rings))

	for _, ring := range rc.Rings {
		drained := atomic.LoadUint64(&ring.Drained)
		errors := atomic.LoadUint64(&ring.Errors)
		tk.LogIt(tk.LogDebug, "[L4_TRACE_STATS] ring=%d drained=%d errors=%d\n",
			ring.WorkerID, drained, errors)
	}
}

// GetStats returns current statistics
func (rc *L4RingConsumer) GetStats() L4TraceStats {
	return L4TraceStats{
		TotalEvents:     atomic.LoadUint64(&rc.TotalDrained),
		DroppedEvents:   atomic.LoadUint64(&rc.TotalDropped),
		TCPEvents:       atomic.LoadUint64(&rc.TCPEvents),
		SCTPEvents:      atomic.LoadUint64(&rc.SCTPEvents),
		UDPEvents:       atomic.LoadUint64(&rc.UDPEvents),
		ConnNew:         atomic.LoadUint64(&rc.ConnNew),
		ConnEstablished: atomic.LoadUint64(&rc.ConnEstablished),
		ConnClosed:      atomic.LoadUint64(&rc.ConnClosed),
		ConnTimeout:     atomic.LoadUint64(&rc.ConnTimeout),
		ConnReset:       atomic.LoadUint64(&rc.ConnReset),
		ConnError:       atomic.LoadUint64(&rc.ConnError),
	}
}

// Human-readable helper functions for L4 events
func l4ProtocolName(proto uint8) string {
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

func l4StateName(proto uint8, state uint8) string {
	if proto == 6 { // TCP
		switch state {
		case 0: // CT_TCP_CLOSED
			return "CLOSED"
		case 1: // CT_TCP_SS
			return "SYN_SENT"
		case 2: // CT_TCP_SA
			return "SYN_ACK"
		case 4: // CT_TCP_EST (0x4)
			return "ESTABLISHED"
		case 0x10: // CT_TCP_FINI (16)
			return "FIN_WAIT_1"
		case 0x20: // CT_TCP_FINI2 (32)
			return "FIN_WAIT_2"
		case 0x40: // CT_TCP_FINI3 (64)
			return "FIN_WAIT_3"
		case 0x80: // CT_TCP_CW (128)
			return "CLOSE_WAIT"
		// Note: CT_TCP_ERR (0x100) and CT_TCP_PEST (0x200) overflow uint8, handled in default
		default:
			return fmt.Sprintf("TCP_STATE_0x%x", state)
		}
	} else if proto == 132 { // SCTP
		switch state {
		case 0x0: // CT_SCTP_CLOSED
			return "CLOSED"
		case 0x40: // CT_SCTP_EST (64)
			return "ESTABLISHED"
		case 0x80: // CT_SCTP_SHUT (128)
			return "SHUTDOWN"
		default:
			// Note: SCTP states > 255 overflow uint8 in trace events
			return fmt.Sprintf("SCTP_STATE_0x%x", state)
		}
	} else if proto == 17 { // UDP
		switch state {
		case 0x0: // CT_UDP_CNI
			return "CONNECTION_INITIATED"
		case 0x1: // CT_UDP_UEST
			return "UNIDIRECTIONAL_EST"
		case 0x2: // CT_UDP_EST
			return "ESTABLISHED"
		case 0x8: // CT_UDP_FINI
			return "FINISHING"
		case 0x10: // CT_UDP_CW
			return "CLOSE_WAIT"
		default:
			return fmt.Sprintf("UDP_STATE_0x%x", state)
		}
	}
	return fmt.Sprintf("STATE_%d", state)
}

func l4EventTypeName(eventType uint8) string {
	switch eventType {
	case 10: // LXB_L4_EVENT_CONN_NEW
		return "CONN_NEW"
	case 11: // LXB_L4_EVENT_STATE_CHANGE
		return "STATE_CHANGE"
	case 12: // LXB_L4_EVENT_CONN_CLOSE
		return "CONN_CLOSE"
	case 13: // LXB_L4_EVENT_CONN_TIMEOUT
		return "CONN_TIMEOUT"
	case 14: // LXB_L4_EVENT_CONN_RESET
		return "CONN_RESET"
	case 15: // LXB_L4_EVENT_CONN_ERROR
		return "CONN_ERROR"
	default:
		return fmt.Sprintf("EVENT_%d", eventType)
	}
}

func l4ErrorCodeName(errorCode uint32) string {
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

// updateEventStatistics tracks protocol-specific and event-type statistics
// This is called for each successfully parsed event to maintain counters
func (rc *L4RingConsumer) updateEventStatistics(event *L4TraceEvent) {
	// Update protocol-specific counters
	switch event.Protocol {
	case 6: // TCP (IPPROTO_TCP)
		atomic.AddUint64(&rc.TCPEvents, 1)
	case 132: // SCTP (IPPROTO_SCTP)
		atomic.AddUint64(&rc.SCTPEvents, 1)
	case 17: // UDP (IPPROTO_UDP)
		atomic.AddUint64(&rc.UDPEvents, 1)
	}

	// Update event-type specific counters based on event type
	switch event.EventType {
	case LXB_L4_EVENT_CONN_NEW:
		atomic.AddUint64(&rc.ConnNew, 1)
	case LXB_L4_EVENT_STATE_CHANGE:
		atomic.AddUint64(&rc.ConnEstablished, 1)
	case LXB_L4_EVENT_CONN_CLOSE:
		atomic.AddUint64(&rc.ConnClosed, 1)
	case LXB_L4_EVENT_CONN_TIMEOUT:
		atomic.AddUint64(&rc.ConnTimeout, 1)
	case LXB_L4_EVENT_CONN_RESET:
		atomic.AddUint64(&rc.ConnReset, 1)
	case LXB_L4_EVENT_CONN_ERROR:
		atomic.AddUint64(&rc.ConnError, 1)
	}
}
