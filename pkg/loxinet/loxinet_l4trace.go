//go:build l4trace
// +build l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * L4 Connection Tracing Initialization (enabled build)
 */

package loxinet

import (
	"fmt"
	"time"

	"github.com/loxilb-io/loxilb/api/restapi/handler"
	tk "github.com/loxilb-io/loxilib"
)

// initL4Tracing initializes the L4 Connection Tracing subsystem
//
// Architecture:
// 1. Reuse OTLP exporter from HTTP tracing (shared infrastructure)
// 2. Create event channel for ring consumer → assembler communication
// 3. Create L4 span assembler (connection lifecycle correlation)
// 4. Create L4 ring buffer consumer (mmap + epoll for l4_trace_ringbuf)
// 5. Start consumer → assembler → OTLP pipeline
//
// Returns error if initialization fails (non-fatal, L4 tracing will be disabled).
func (mh *loxiNetH) initL4Tracing() error {
	// 1. Get or create OTLP exporter (shared with HTTP tracing)
	if mh.otlpExporter == nil {
		otlpExporter, err := NewOTLPExporter()
		if err != nil {
			return fmt.Errorf("OTLP exporter creation failed: %w", err)
		}
		mh.otlpExporter = otlpExporter
	}

	// 2. Create event channel for ring consumer → assembler pipeline
	eventChan := make(chan *L4TraceEvent, 10000) // Buffer 10K events

	// 3. Create L4 span assembler first (consumer needs this)
	l4SpanAssembler := NewL4SpanAssembler(eventChan)
	mh.l4SpanAssembler = l4SpanAssembler

	// 4. Create L4 ring buffer consumer (needs assembler and ring buffer FD)
	ringBufFD := mh.dpEbpf.l4TraceRingBufFD
	l4RingConsumer, err := NewL4RingConsumer(l4SpanAssembler, ringBufFD)
	if err != nil {
		close(eventChan)
		return fmt.Errorf("L4 ring consumer creation failed: %w", err)
	}
	mh.l4RingConsumer = l4RingConsumer

	// 5. Start consumer (starts polling ring buffers)
	l4RingConsumer.Start()

	// 6. Start L4 span assembler
	l4SpanAssembler.Start()

	// 7. Start L4 event processing goroutine for statistics
	mh.wg.Add(1)
	go mh.l4TraceEventProcessor()

	mh.l4TracingEnabled = true
	tk.LogIt(tk.LogInfo, "[L4Trace] Pipeline started: ring_consumer → span_assembler → OTLP\n")

	// Register OTLP reconnection callback if not already registered
	if handler.ReconnectOTLPCallback == nil {
		handler.ReconnectOTLPCallback = mh.ReconnectOTLPExporter
	}

	return nil
}

// l4TraceEventProcessor monitors L4 tracing statistics
// Runs as goroutine, exits on shutdown
func (mh *loxiNetH) l4TraceEventProcessor() {
	defer mh.wg.Done()

	tk.LogIt(tk.LogInfo, "[L4Trace] Event processor started\n")

	statsTicker := time.NewTicker(10 * time.Second)
	defer statsTicker.Stop()

	for {
		select {
		case <-statsTicker.C:
			// Log periodic statistics
			stats := mh.l4RingConsumer.GetStats()
			tk.LogIt(tk.LogDebug, "[L4Trace] Stats: events=%d dropped=%d\n",
				stats.TotalEvents, stats.DroppedEvents)

		case <-mh.tDone:
			tk.LogIt(tk.LogInfo, "[L4Trace] Shutdown signal received, processor exiting\n")
			return
		}
	}
}
