//go:build !l4trace
// +build !l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * L4 Connection Tracing: Ring Buffer Consumer (Disabled Stub)
 *
 * This file provides stub implementations when L4 tracing is not enabled.
 */

package loxinet

// L4TraceEvent stub
type L4TraceEvent struct{}

// L4RingBuffer stub
type L4RingBuffer struct{}

// L4RingConsumer stub
type L4RingConsumer struct {
	EventChan chan *L4TraceEvent
	StopChan  chan struct{}
}

// NewL4RingConsumer returns a no-op consumer when L4 tracing is disabled
func NewL4RingConsumer(assembler *L4SpanAssembler, ringBufFD int) (*L4RingConsumer, error) {
	return &L4RingConsumer{
		EventChan: make(chan *L4TraceEvent),
		StopChan:  make(chan struct{}),
	}, nil
}

// Start is a no-op when L4 tracing is disabled
func (rc *L4RingConsumer) Start() {}

// Stop is a no-op when L4 tracing is disabled
func (rc *L4RingConsumer) Stop() {
	close(rc.StopChan)
	close(rc.EventChan)
}

// GetStats returns empty stats when L4 tracing is disabled
func (rc *L4RingConsumer) GetStats() L4TraceStats {
	return L4TraceStats{}
}
