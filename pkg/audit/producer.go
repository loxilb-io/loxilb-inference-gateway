/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package audit

import (
	"sync/atomic"
	"time"
)

// Drop reasons, as written into dropped_by_reason and the producer gap
// records.
const (
	DropQueueFull   = "queue_full"
	DropWriterDown  = "writer_down"
	DropInvalid     = "invalid"
	DropDiskReserve = "disk_reserve"
)

var dropReasons = [...]string{DropQueueFull, DropWriterDown, DropInvalid, DropDiskReserve}

const (
	dropIdxQueueFull = iota
	dropIdxWriterDown
	dropIdxInvalid
	dropIdxDiskReserve
	numDropReasons
)

// UnattributedProducer is the producer identity recorded when the data
// plane could not say which worker emitted a record.
const UnattributedProducer = "w?"

// dropRingSize bounds the per-producer drop ring. It is a power of two.
const dropRingSize = 256

// dropEntry is one dropped pseq with its reason.
type dropEntry struct {
	pseq   uint64
	reason uint8
}

// dropRing is a single-producer, single-consumer ring: the owning producer
// pushes, the writer drains. Overflow is counted, never blocked on.
type dropRing struct {
	head     atomic.Uint64 // next slot to write (producer)
	tail     atomic.Uint64 // next slot to read (writer)
	overflow atomic.Uint64
	slots    [dropRingSize]dropEntry
}

func (r *dropRing) push(e dropEntry) {
	h := r.head.Load()
	if h-r.tail.Load() >= dropRingSize {
		r.overflow.Add(1)
		return
	}
	r.slots[h&(dropRingSize-1)] = e
	r.head.Store(h + 1)
}

// drain hands every queued entry to fn in push order.
func (r *dropRing) drain(fn func(dropEntry)) {
	t := r.tail.Load()
	h := r.head.Load()
	for ; t != h; t++ {
		fn(r.slots[t&(dropRingSize-1)])
	}
	r.tail.Store(t)
}

// Producer is one emitting identity on a channel stream: a data-plane
// worker. A producer's sends are sequential on its own thread, so its
// pseq values arrive at the writer in order and a hole in them is a real
// drop, which the producer also records itself.
type Producer struct {
	id     string
	stream Stream
	w      *Writer

	pseq     atomic.Uint64
	accepted atomic.Uint64
	dropped  [numDropReasons]atomic.Uint64
	ring     dropRing

	// overflowSeen is the ring overflow count at the writer's last drain;
	// owned by the writer goroutine.
	overflowSeen uint64
}

// ID returns the producer identity written into producer_id.
func (p *Producer) ID() string { return p.id }

// Emit stamps the record with this producer's identity and next sequence
// and hands it to the writer without blocking. It returns false when the
// record was dropped; the drop is already counted and ringed, so the
// caller has nothing else to do. The record belongs to the writer after a
// successful Emit and must not be touched again.
func (p *Producer) Emit(r *Record) bool {
	pseq := p.pseq.Add(1)
	r.producerID = p.id
	r.pseq = pseq
	if r.Stream == "" {
		r.Stream = p.stream
	}
	if r.TS.IsZero() {
		r.TS = time.Now()
	}
	if r.Validate() != nil {
		p.drop(pseq, dropIdxInvalid)
		p.w.release(r)
		return false
	}
	if !p.w.running.Load() {
		p.drop(pseq, dropIdxWriterDown)
		p.w.release(r)
		return false
	}
	select {
	case p.w.queueFor(r) <- r:
		p.accepted.Add(1)
		return true
	default:
		p.drop(pseq, dropIdxQueueFull)
		p.w.release(r)
		return false
	}
}

func (p *Producer) drop(pseq uint64, reason uint8) {
	p.dropped[reason].Add(1)
	p.ring.push(dropEntry{pseq: pseq, reason: reason})
}

// ProducerStats is one producer's counters since boot.
type ProducerStats struct {
	ID                string
	Stream            Stream
	PseqHigh          uint64
	Accepted          uint64
	Dropped           map[string]uint64
	DropRingOverflows uint64
}

func (p *Producer) stats() ProducerStats {
	s := ProducerStats{
		ID:                p.id,
		Stream:            p.stream,
		PseqHigh:          p.pseq.Load(),
		Accepted:          p.accepted.Load(),
		Dropped:           make(map[string]uint64, numDropReasons),
		DropRingOverflows: p.ring.overflow.Load(),
	}
	for i := range dropReasons {
		if n := p.dropped[i].Load(); n != 0 {
			s.Dropped[dropReasons[i]] = n
		}
	}
	return s
}
