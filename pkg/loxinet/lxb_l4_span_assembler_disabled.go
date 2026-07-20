//go:build !l4trace
// +build !l4trace

/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 * SPDX short identifier: BSlause
 *
 * L4 Connection Tracing: Span Assembler (Disabled Stub)
 */

package loxinet

// L4SpanAssembler stub
type L4SpanAssembler struct{}

// L4SpanAssemblerStats stub
type L4SpanAssemblerStats struct {
	TotalSpans   uint64
	ActiveSpans  uint64
	ClosedSpans  uint64
	ErrorSpans   uint64
	TimeoutSpans uint64
}

// SetTracer is a no-op for disabled builds
func (sa *L4SpanAssembler) SetTracer(tracer interface{}) {
	// No-op for disabled build
}

// NewL4SpanAssembler returns a no-op assembler when L4 tracing is disabled
func NewL4SpanAssembler(eventChan chan *L4TraceEvent) *L4SpanAssembler {
	return &L4SpanAssembler{}
}

// Start is a no-op when L4 tracing is disabled
func (sa *L4SpanAssembler) Start() {}

// Stop is a no-op when L4 tracing is disabled
func (sa *L4SpanAssembler) Stop() {}

// GetStats returns empty stats when L4 tracing is disabled
func (sa *L4SpanAssembler) GetStats() L4SpanAssemblerStats {
	return L4SpanAssemblerStats{}
}
