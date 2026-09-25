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
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Errors returned by the durable management path. A caller that receives
// any of them must refuse the mutation it was about to make.
var (
	// ErrUnavailable means the writer is not running or did not complete
	// the write within the caller's deadline.
	ErrUnavailable = errors.New("audit: writer unavailable")
	// ErrWriteFailed means the append or fsync itself failed.
	ErrWriteFailed = errors.New("audit: durable write failed")
	// ErrDiskReserve means the audit filesystem is below its reserve and
	// no new management record is accepted until space is recovered.
	ErrDiskReserve = errors.New("audit: disk reserve breached")
	// ErrInvalid means the record does not satisfy the schema rules.
	ErrInvalid = errors.New("audit: invalid record")
)

// Defaults.
const (
	DefaultQueueSize         = 8192
	DefaultHeartbeatInterval = 30 * time.Second
	DefaultMaxSegmentBytes   = 64 << 20
	DefaultMaxSegmentAge     = 24 * time.Hour
	DefaultInstanceID        = "loxilb-default"

	// maxBatch bounds how many queued records are appended between fsyncs.
	maxBatch = 512
	// panicMsgLimit bounds the panic text carried by the restart record.
	panicMsgLimit = 512
	// maxRestartBackoff caps the supervisor's restart delay.
	maxRestartBackoff = time.Second
)

// stallNanos is how long the writer.stall fault point holds the writer per
// record, in nanoseconds; tests shorten it.
var stallNanos atomic.Int64

func init() { stallNanos.Store(int64(time.Second)) }

// Config configures a Writer.
type Config struct {
	// Dir is the audit directory. It must be 0700 (or absent with
	// CreateDir set). Default /var/log/loxilb/audit.
	Dir string
	// CreateDir creates Dir 0700 when it does not exist.
	CreateDir bool
	// InstanceID is written into every record and segment header.
	InstanceID string
	// QueueSize is the capacity of each asynchronous channel (data,
	// security, control).
	QueueSize int
	// HeartbeatInterval is the idle liveness cadence; it is also the
	// retention pass cadence.
	HeartbeatInterval time.Duration
	// MaxSegmentBytes seals the active segment before it exceeds this.
	MaxSegmentBytes int64
	// MaxSegmentAge seals the active segment once it is this old.
	MaxSegmentAge time.Duration
	// Retention is the local-tier prune policy.
	Retention Retention
	// Logf receives the operational fallback lines (the ones that must be
	// visible when the audit writer itself is the thing failing). Default
	// stderr.
	Logf func(format string, args ...any)
	// ConfigGeneration reports the configuration mutation watermark. It is
	// read once at start and stamped on every orphaned-intent record so an
	// investigator can tell whether the intent's mutation landed.
	ConfigGeneration func() uint64

	now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.Dir == "" {
		c.Dir = "/var/log/loxilb/audit"
	}
	if c.InstanceID == "" {
		c.InstanceID = DefaultInstanceID
	}
	if c.QueueSize <= 0 {
		c.QueueSize = DefaultQueueSize
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if c.MaxSegmentBytes <= 0 {
		c.MaxSegmentBytes = DefaultMaxSegmentBytes
	}
	if c.MaxSegmentAge <= 0 {
		c.MaxSegmentAge = DefaultMaxSegmentAge
	}
	c.Retention = c.Retention.withDefaults()
	if c.Logf == nil {
		c.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// Asynchronous queues. The security queue is separate from the data queue
// so an inference flood cannot displace a security decision; the control
// queue carries management results and audit_system records.
const (
	qData = iota
	qSecurity
	qControl
	numQueues
)

var queueNames = [numQueues]string{"data", "security", "control"}

type streamIdx int

const (
	sMgmt streamIdx = iota
	sData
	sSystem
	numStreams
)

var streamByIdx = [numStreams]Stream{StreamMgmt, StreamData, StreamSystem}

func idxOf(s Stream) streamIdx {
	switch s {
	case StreamData:
		return sData
	case StreamSystem:
		return sSystem
	}
	return sMgmt
}

type syncReq struct {
	r    *Record
	done chan error
}

type writerStats struct {
	orphanedIntents atomic.Uint64
	accepted        [numStreams]atomic.Uint64
	dropped         [numStreams][numDropReasons]atomic.Uint64
	writeFailures   atomic.Uint64
	syncFailures    atomic.Uint64
	mgmtTimeouts    atomic.Uint64
	panics          atomic.Uint64
	restarts        atomic.Uint64
	pathSanitized   atomic.Uint64
	unattributed    atomic.Uint64
	pruned          atomic.Uint64
	reserveBreaches atomic.Uint64
	heartbeats      atomic.Uint64
	rotations       atomic.Uint64
}

// failInterval tracks a run of write failures so the writer can record
// it retroactively once writing resumes.
type failInterval struct {
	first, last time.Time
	count       uint64
	class       string
}

type panicInfo struct {
	lastSeq uint64
	msg     string
	restart uint64
}

// Writer is the audit subsystem's single writer.
type Writer struct {
	cfg    Config
	bootID string
	now    func() time.Time
	logf   func(string, ...any)

	queues [numQueues]chan *Record
	hwm    [numQueues]atomic.Uint64
	syncq  chan syncReq
	sealq  chan chan error
	ctl    chan func()

	stopCh   chan struct{}
	stopOnce sync.Once
	done     chan struct{}
	started  atomic.Bool
	running  atomic.Bool

	seq       atomic.Uint64
	lastWrite atomic.Int64
	lastBeat  atomic.Int64 // when the writer goroutine last proved itself alive
	written   atomic.Int64 // record bytes appended by this process
	startedAt time.Time
	seg       *segmenter
	enc       *encoder
	pool      sync.Pool
	faults    faults

	pmu       sync.Mutex
	producers atomic.Pointer[[]*Producer]
	arrivals  map[string]uint64 // last pseq seen per producer

	holdMu sync.Mutex
	holds  map[string]string

	retention       atomic.Pointer[Retention]
	reserveBreached atomic.Bool
	sealedBytes     atomic.Int64
	lastOrphan      atomic.Pointer[string]

	stats writerStats

	// Writer-goroutine state.
	pending []syncReq
	failing *failInterval
	// appended is set by a successful append and cleared by the flush that
	// synced it; it is what lets last_write mean what it says.
	appended  bool
	recovered *recovery
	pendingP  *panicInfo
	sysDepth  int
}

// New validates the directory, recovers any segment the previous process
// left unsealed, opens the active segment and returns a writer ready to
// Start. Errors here are the "refuse to start" signal for a deployment
// that mandates auditing.
func New(cfg Config) (*Writer, error) {
	cfg = cfg.withDefaults()
	if err := checkDir(cfg.Dir, cfg.CreateDir); err != nil {
		return nil, err
	}
	w := &Writer{
		cfg:      cfg,
		bootID:   newUUID(),
		now:      cfg.now,
		logf:     cfg.Logf,
		syncq:    make(chan syncReq, cfg.QueueSize),
		sealq:    make(chan chan error),
		ctl:      make(chan func()),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
		enc:      newEncoder(),
		arrivals: make(map[string]uint64),
		holds:    make(map[string]string),
	}
	w.startedAt = w.now()
	for i := range w.queues {
		w.queues[i] = make(chan *Record, cfg.QueueSize)
	}
	w.pool.New = func() any { return &Record{pooled: true} }
	ret := cfg.Retention
	w.retention.Store(&ret)
	empty := []*Producer{}
	w.producers.Store(&empty)

	w.seg = newSegmenter(cfg.Dir, cfg.InstanceID, w.bootID, cfg.MaxSegmentBytes, cfg.MaxSegmentAge,
		w.now, w.logf, w.faults.armed)
	w.seg.onAsync = func(r *Record) { w.enqueueSystem(r) }
	rec, err := w.seg.start(1)
	if err != nil {
		return nil, err
	}
	w.recovered = rec
	return w, nil
}

// Start launches the supervised writer goroutine. It is safe to call once.
func (w *Writer) Start() {
	if !w.started.CompareAndSwap(false, true) {
		return
	}
	go w.supervise()
}

// Close stops the writer: queued records are drained, the active segment
// is sealed and the compression worker finishes. ctx bounds the wait.
func (w *Writer) Close(ctx context.Context) error {
	w.stopOnce.Do(func() { close(w.stopCh) })
	if !w.started.Load() {
		return w.seg.close()
	}
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// BootID identifies this process start in every record.
func (w *Writer) BootID() string { return w.bootID }

// Running reports whether the writer goroutine is alive and accepting.
func (w *Writer) Running() bool { return w.running.Load() }

// SeqHigh is the last sequence written.
func (w *Writer) SeqHigh() uint64 { return w.seq.Load() }

// LastWriteUnix is the time of the last successful flush, in Unix seconds;
// the liveness gauge a watchdog alarms on.
func (w *Writer) LastWriteUnix() int64 { return w.lastWrite.Load() }

// Producer returns the producer with the given identity, creating it on
// first use. Producers are cheap and long-lived; one per emitting worker.
func (w *Writer) Producer(id string, stream Stream) *Producer {
	if id == "" {
		id = UnattributedProducer
	}
	w.pmu.Lock()
	defer w.pmu.Unlock()
	cur := *w.producers.Load()
	for _, p := range cur {
		if p.id == id && p.stream == stream {
			return p
		}
	}
	p := &Producer{id: id, stream: stream, w: w}
	next := make([]*Producer, len(cur)+1)
	copy(next, cur)
	next[len(cur)] = p
	w.producers.Store(&next)
	return p
}

// AcquireRecord returns a pooled record. A record obtained here is
// returned to the pool by the writer once written or dropped; the caller
// must not touch it after Emit, Append or Write.
func (w *Writer) AcquireRecord() *Record {
	r := w.pool.Get().(*Record)
	r.Reset()
	return r
}

func (w *Writer) release(r *Record) {
	if r != nil && r.pooled {
		w.pool.Put(r)
	}
}

func (w *Writer) queueFor(r *Record) chan *Record {
	switch {
	case r.Stream == StreamData && r.Class == ClassSecurity:
		return w.queues[qSecurity]
	case r.Stream == StreamData:
		return w.queues[qData]
	}
	return w.queues[qControl]
}

// Write appends the record and returns once it is durable (appended and
// fsynced). It is the management intent path: on any error the caller
// refuses the mutation. A management result may use it too when the
// caller wants durability before answering.
func (w *Writer) Write(ctx context.Context, r *Record) error {
	if r.TS.IsZero() {
		r.TS = w.now()
	}
	if err := r.Validate(); err != nil {
		w.stats.dropped[idxOf(r.Stream)][dropIdxInvalid].Add(1)
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !w.running.Load() {
		w.stats.dropped[idxOf(r.Stream)][dropIdxWriterDown].Add(1)
		return ErrUnavailable
	}
	if w.reserveBreached.Load() {
		w.stats.dropped[idxOf(r.Stream)][dropIdxDiskReserve].Add(1)
		return ErrDiskReserve
	}
	req := syncReq{r: r, done: make(chan error, 1)}
	select {
	case w.syncq <- req:
	case <-ctx.Done():
		w.stats.mgmtTimeouts.Add(1)
		return fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
	case <-w.stopCh:
		return ErrUnavailable
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		w.stats.mgmtTimeouts.Add(1)
		return fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
	}
}

// Append enqueues a management or audit_system record without waiting.
// It is the result-phase path: the mutation has happened, so the response
// is not held for the record, but a failure to enqueue is counted and
// reported to the caller so it can alarm. It returns false when dropped.
func (w *Writer) Append(r *Record) bool {
	if r.TS.IsZero() {
		r.TS = w.now()
	}
	if r.Validate() != nil {
		w.stats.dropped[idxOf(r.Stream)][dropIdxInvalid].Add(1)
		w.release(r)
		return false
	}
	if !w.running.Load() {
		w.stats.dropped[idxOf(r.Stream)][dropIdxWriterDown].Add(1)
		w.release(r)
		return false
	}
	select {
	case w.queueFor(r) <- r:
		return true
	default:
		w.stats.dropped[idxOf(r.Stream)][dropIdxQueueFull].Add(1)
		w.release(r)
		return false
	}
}

// enqueueSystem is Append for records the subsystem generates off the
// writer goroutine (the compression worker).
func (w *Writer) enqueueSystem(r *Record) {
	r.TS = w.now()
	select {
	case w.queues[qControl] <- r:
	default:
		w.stats.dropped[sSystem][dropIdxQueueFull].Add(1)
	}
}

// SealNow seals the active segment and opens the next one.
func (w *Writer) SealNow(ctx context.Context) error {
	if !w.running.Load() {
		return ErrUnavailable
	}
	done := make(chan error, 1)
	select {
	case w.sealq <- done:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// onLoop runs fn on the writer goroutine and waits for it. It is the
// hook for operations that must be ordered with the writer's own work.
func (w *Writer) onLoop(ctx context.Context, fn func()) error {
	done := make(chan struct{})
	wrapped := func() { fn(); close(done) }
	select {
	case w.ctl <- wrapped:
	case <-ctx.Done():
		return ctx.Err()
	case <-w.stopCh:
		return ErrUnavailable
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// supervise runs the writer loop and restarts it after a panic. A panic
// is counted, logged through the fallback logger and recorded as the
// first records of the next run.
func (w *Writer) supervise() {
	defer close(w.done)
	var restarts uint64
	for {
		info, panicked := w.runGuarded()
		if !panicked {
			return
		}
		restarts++
		info.restart = restarts
		w.stats.panics.Add(1)
		w.stats.restarts.Add(1)
		w.logf("audit: writer panic, restart %d after seq %d: %s", restarts, info.lastSeq, info.msg)
		w.pendingP = &info
		backoff := time.Duration(restarts) * 50 * time.Millisecond
		if backoff > maxRestartBackoff {
			backoff = maxRestartBackoff
		}
		select {
		case <-w.stopCh:
			w.seg.close()
			return
		case <-time.After(backoff):
		}
	}
}

func (w *Writer) runGuarded() (info panicInfo, panicked bool) {
	defer func() {
		if p := recover(); p != nil {
			panicked = true
			w.running.Store(false)
			msg := fmt.Sprintf("%v", p)
			if len(msg) > panicMsgLimit {
				msg = msg[:panicMsgLimit]
			}
			info = panicInfo{lastSeq: w.seq.Load(), msg: msg}
			w.logf("audit: writer panic: %s\n%s", msg, debug.Stack())
			w.failPending(ErrUnavailable)
			w.sysDepth = 0
		}
	}()
	w.run()
	return info, false
}

func (w *Writer) run() {
	// Starting is the first proof of life; the heartbeat keeps it current.
	w.lastBeat.Store(w.now().Unix())
	w.running.Store(true)
	w.startRecords()

	hb := time.NewTicker(w.cfg.HeartbeatInterval)
	defer hb.Stop()

	for {
		select {
		case <-w.stopCh:
			w.drainAll()
			w.flush()
			w.running.Store(false)
			w.drainAll()
			w.failPending(ErrUnavailable)
			if err := w.seg.close(); err != nil {
				w.logf("audit: close: %v", err)
			}
			w.countLate()
			return
		case fn := <-w.ctl:
			fn()
		case r := <-w.queues[qSecurity]:
			w.write(r)
			w.drainBatch()
		case r := <-w.queues[qControl]:
			w.write(r)
			w.drainBatch()
		case r := <-w.queues[qData]:
			w.write(r)
			w.drainBatch()
		case sr := <-w.syncq:
			w.handleSync(sr)
			w.drainBatch()
		case done := <-w.sealq:
			err := w.rotate()
			w.flush()
			done <- err
		case <-hb.C:
			w.heartbeat()
			w.prunePass()
			w.flush()
		}
	}
}

// startRecords writes the records that open a run: the start record on
// the first run, panic and restart records after a restart, and the
// recovery record when the previous process left a segment unsealed.
func (w *Writer) startRecords() {
	if w.pendingP != nil {
		p := w.pendingP
		w.pendingP = nil
		w.writeSystem(sysRecord("sys.writer.panic", "writer", &SysDetail{
			PanicMsg: p.msg, LastSeqBefore: p.lastSeq,
		}))
		w.writeSystem(sysRecord("sys.writer.restart", "writer", &SysDetail{
			LastSeqBefore: p.lastSeq, RestartCount: p.restart,
		}))
	} else {
		w.writeSystem(sysRecord("sys.writer.start", "writer", &SysDetail{BootID: w.bootID}))
		if rec := w.recovered; rec != nil {
			w.recovered = nil
			w.writeSystem(sysRecord("sys.segment.recovered", "audit_segment:"+rec.uuid, &SysDetail{
				RecordsRecovered: rec.records, TruncatedTailByte: rec.truncatedTail, Recovered: true,
			}))
		}
		w.writeSystem(sysRecord("sys.segment.open", "audit_segment:"+w.seg.uuid, &SysDetail{
			PrevSegmentUUID: w.seg.prevUUID, FirstSeq: w.seg.firstSeq,
		}))
		w.scanOrphans()
	}
	w.flush()
}

// drainBatch pulls whatever is already queued, up to maxBatch, then
// flushes once. Under load this is what turns one fsync per record into
// one fsync per batch.
func (w *Writer) drainBatch() {
	w.sampleDepth()
	n := 1
	for n < maxBatch {
		select {
		case r := <-w.queues[qSecurity]:
			w.write(r)
		case r := <-w.queues[qControl]:
			w.write(r)
		case r := <-w.queues[qData]:
			w.write(r)
		case sr := <-w.syncq:
			w.handleSync(sr)
		default:
			w.flush()
			return
		}
		n++
	}
	w.flush()
}

// sampleDepth records the queue high-water marks as seen by the writer.
func (w *Writer) sampleDepth() {
	for i := range w.queues {
		if d := uint64(len(w.queues[i])); d > w.hwm[i].Load() {
			w.hwm[i].Store(d)
		}
	}
}

// countLate counts records that slipped into a queue after the final
// drain. The channel is no longer read, so they are lost, and a lost
// record is counted, never silent.
func (w *Writer) countLate() {
	for i := range w.queues {
		for drained := false; !drained; {
			select {
			case r := <-w.queues[i]:
				w.stats.dropped[idxOf(r.Stream)][dropIdxWriterDown].Add(1)
				w.release(r)
			default:
				drained = true
			}
		}
	}
}

// drainAll empties the queues at shutdown without waiting for more.
func (w *Writer) drainAll() {
	for {
		select {
		case r := <-w.queues[qSecurity]:
			w.write(r)
		case r := <-w.queues[qControl]:
			w.write(r)
		case r := <-w.queues[qData]:
			w.write(r)
		case sr := <-w.syncq:
			w.handleSync(sr)
		default:
			return
		}
	}
}

func (w *Writer) handleSync(sr syncReq) {
	if err := w.write(sr.r); err != nil {
		sr.done <- fmt.Errorf("%w: %v", ErrWriteFailed, err)
		return
	}
	w.pending = append(w.pending, sr)
}

// flush fsyncs the active segment and answers the durable requests that
// were appended since the last flush.
func (w *Writer) flush() {
	if len(w.pending) == 0 && w.seg.f == nil {
		return
	}
	err := w.seg.sync()
	if err != nil {
		w.stats.syncFailures.Add(1)
		w.noteWriteFailure(err)
		w.failPending(fmt.Errorf("%w: %v", ErrWriteFailed, err))
		return
	}
	// last_write means a record reached the disk. A flush that had nothing
	// to sync (every append since the last one failed) must not move it, or
	// the staleness the metric exists to show would be hidden by the very
	// ticker that fires while the disk is unwritable.
	if w.appended {
		w.lastWrite.Store(w.now().Unix())
		w.appended = false
	}
	for _, sr := range w.pending {
		sr.done <- nil
	}
	w.pending = w.pending[:0]
}

func (w *Writer) failPending(err error) {
	for _, sr := range w.pending {
		sr.done <- err
	}
	w.pending = w.pending[:0]
}

// write stamps, encodes and appends one record. The record is released to
// the pool afterwards whether or not the append succeeded.
func (w *Writer) write(r *Record) error {
	defer w.release(r)
	if w.faults.armed(FaultWriterPanic) {
		panic("audit: fault " + FaultWriterPanic)
	}
	if w.faults.armed(FaultWriterStall) {
		time.Sleep(time.Duration(stallNanos.Load()))
	}
	if r.EventID == "" {
		r.EventID = newUUID()
	}
	if r.TS.IsZero() {
		r.TS = w.now()
	}
	if r.sanitize() {
		w.stats.pathSanitized.Add(1)
	}
	if r.producerID != "" {
		w.noteArrival(r)
	}
	seq := w.seq.Load() + 1
	line, err := w.enc.encode(r, stamp{w.cfg.InstanceID, w.bootID, w.seg.uuid, seq})
	if err != nil {
		w.stats.dropped[idxOf(r.Stream)][dropIdxInvalid].Add(1)
		return err
	}
	if w.seg.needsRotate(len(line)) {
		if rerr := w.rotate(); rerr != nil {
			w.logf("audit: rotate: %v", rerr)
		}
		// The segment (and so the stamp) may have changed; re-encode.
		seq = w.seq.Load() + 1
		line, _ = w.enc.encode(r, stamp{w.cfg.InstanceID, w.bootID, w.seg.uuid, seq})
	}
	if err := w.seg.append(line, seq, r.TS); err != nil {
		w.noteWriteFailure(err)
		return err
	}
	w.seq.Store(seq)
	w.appended = true
	w.written.Add(int64(len(line)))
	w.stats.accepted[idxOf(r.Stream)].Add(1)
	if w.failing != nil && w.sysDepth == 0 {
		w.recordWriteFailureEnd()
	}
	return nil
}

// writeSystem appends an audit_system record from the writer goroutine.
func (w *Writer) writeSystem(r *Record) {
	r.TS = w.now()
	w.sysDepth++
	defer func() { w.sysDepth-- }()
	if err := w.write(r); err != nil {
		w.logf("audit: %s not written: %v", r.EventType, err)
	}
}

// writeSystemDurable appends and fsyncs an audit_system record; the
// pre-action records (prune) use it.
func (w *Writer) writeSystemDurable(r *Record) error {
	r.TS = w.now()
	w.sysDepth++
	defer func() { w.sysDepth-- }()
	if err := w.write(r); err != nil {
		return err
	}
	if err := w.seg.sync(); err != nil {
		w.stats.syncFailures.Add(1)
		w.noteWriteFailure(err)
		return err
	}
	w.lastWrite.Store(w.now().Unix())
	return nil
}

// noteWriteFailure counts a failed append or fsync and opens or extends
// the failure interval. The fallback line goes out once per interval so
// a failing disk does not flood the operational log.
func (w *Writer) noteWriteFailure(err error) {
	w.stats.writeFailures.Add(1)
	now := w.now()
	if w.failing == nil {
		w.failing = &failInterval{first: now, class: errnoClass(err)}
		w.logf("audit: write failed (%s): %v", w.failing.class, err)
	}
	w.failing.last = now
	w.failing.count++
}

// recordWriteFailureEnd writes the retroactive record for a failure
// interval once an append has succeeded again.
func (w *Writer) recordWriteFailureEnd() {
	fi := w.failing
	w.failing = nil
	w.logf("audit: writing resumed after %d failures between %s and %s",
		fi.count, formatTS(fi.first), formatTS(fi.last))
	w.writeSystem(sysRecord("sys.writer.write_failed", "writer", &SysDetail{
		ErrnoClass: fi.class, FirstTS: formatTS(fi.first), LastTS: formatTS(fi.last), Count: fi.count,
	}))
}

// rotate seals the active segment, opens the next one and records both.
func (w *Writer) rotate() error {
	sealed, count, err := w.seg.rotate(w.seq.Load() + 1)
	if err != nil {
		w.writeSystem(sysRecord("sys.segment.rotation_failed", "audit_segment:"+sealed, &SysDetail{
			ErrnoClass: errnoClass(err),
		}))
		return err
	}
	w.stats.rotations.Add(1)
	w.writeSystem(sysRecord("sys.segment.seal", "audit_segment:"+sealed, &SysDetail{
		RecordCount: count, LastSeq: w.seq.Load(),
	}))
	w.writeSystem(sysRecord("sys.segment.open", "audit_segment:"+w.seg.uuid, &SysDetail{
		PrevSegmentUUID: sealed, FirstSeq: w.seg.firstSeq,
	}))
	return nil
}

// noteArrival tracks each producer's pseq as seen by the writer so a hole
// can be cross-checked against the producer's own drop ring.
func (w *Writer) noteArrival(r *Record) {
	if r.producerID == UnattributedProducer {
		w.stats.unattributed.Add(1)
	}
	w.arrivals[r.producerID] = r.pseq
}

// heartbeat writes the liveness record with every counter since boot and
// drains the producers' drop rings into gap records.
func (w *Writer) heartbeat() {
	w.stats.heartbeats.Add(1)
	w.lastBeat.Store(w.now().Unix())
	w.emitProducerGaps()
	w.writeSystem(sysRecord("sys.heartbeat", "writer", &SysDetail{Heartbeat: w.heartbeatPayload()}))
}

func (w *Writer) heartbeatPayload() *Heartbeat {
	hb := &Heartbeat{
		SeqHigh:           w.seq.Load(),
		Accepted:          make(map[Stream]uint64, numStreams),
		QueueDepth:        make(map[string]uint64, numQueues),
		QueueHWM:          make(map[string]uint64, numQueues),
		UnattributedTotal: w.stats.unattributed.Load(),
		WriteFailures:     w.stats.writeFailures.Load(),
	}
	for i := range streamByIdx {
		hb.Accepted[streamByIdx[i]] = w.stats.accepted[i].Load()
		for j := range dropReasons {
			if n := w.stats.dropped[i][j].Load(); n != 0 {
				hb.Dropped = append(hb.Dropped, DropCount{Stream: streamByIdx[i], Reason: dropReasons[j], Count: n})
			}
		}
	}
	w.sampleDepth()
	for i := range w.queues {
		hb.QueueDepth[queueNames[i]] = uint64(len(w.queues[i]))
		hb.QueueHWM[queueNames[i]] = w.hwm[i].Load()
	}
	for _, p := range *w.producers.Load() {
		hb.PseqHigh = append(hb.PseqHigh, ProducerSeq{ProducerID: p.id, Stream: p.stream, Pseq: p.pseq.Load()})
		for j := range dropReasons {
			if n := p.dropped[j].Load(); n != 0 {
				hb.Dropped = append(hb.Dropped, DropCount{ProducerID: p.id, Stream: p.stream, Reason: dropReasons[j], Count: n})
			}
		}
		if n := p.ring.overflow.Load(); n != 0 {
			hb.DropRingOverflows = append(hb.DropRingOverflows, ProducerCount{ProducerID: p.id, Count: n})
		}
	}
	return hb
}

// emitProducerGaps drains every producer's drop ring and writes one gap
// record per contiguous run of dropped sequences. The ring is the
// producer's own evidence, so exact is true unless the ring overflowed
// since the last drain, in which case the record says so.
func (w *Writer) emitProducerGaps() {
	for _, p := range *w.producers.Load() {
		var runs []dropRun
		p.ring.drain(func(e dropEntry) {
			if n := len(runs); n > 0 && runs[n-1].reason == e.reason && runs[n-1].to+1 == e.pseq {
				runs[n-1].to = e.pseq
				return
			}
			runs = append(runs, dropRun{from: e.pseq, to: e.pseq, reason: e.reason})
		})
		overflow := p.ring.overflow.Load()
		exact := overflow == p.overflowSeen
		p.overflowSeen = overflow
		if len(runs) == 0 {
			continue
		}
		for _, run := range runs {
			ex := exact
			w.writeSystem(sysRecord("sys.producer.gap", "producer:"+p.id, &SysDetail{
				ProducerID: p.id, Stream: p.stream, PseqFrom: run.from, PseqTo: run.to,
				Reason: dropReasons[run.reason], Exact: &ex, CounterDelta: run.to - run.from + 1,
			}))
		}
	}
}

type dropRun struct {
	from, to uint64
	reason   uint8
}

// Stats is a point-in-time snapshot of the writer's counters. It is the
// source for the status endpoint and the metrics collector.
type Stats struct {
	BootID        string
	Running       bool
	SeqHigh       uint64
	LastWriteUnix int64
	// LastHeartbeatUnix is when the writer goroutine last wrote its
	// liveness record; a value that stops advancing is a writer that is
	// not running, whatever the counters say.
	LastHeartbeatUnix int64

	Accepted map[Stream]uint64
	Dropped  []DropCount

	QueueDepth map[string]int
	QueueHWM   map[string]int

	WriteFailures   uint64
	SyncFailures    uint64
	MgmtTimeouts    uint64
	Panics          uint64
	Restarts        uint64
	Heartbeats      uint64
	Rotations       uint64
	PathSanitized   uint64
	Unattributed    uint64
	PermRepaired    uint64
	RotationFailed  uint64
	CompressFailed  uint64
	CompressSkipped uint64
	Pruned          uint64
	ReserveBreaches uint64
	ReserveBreached bool
	SealedBytes     int64

	// OrphanedIntents counts management intents of the previous boot that
	// had no result when this writer started; LastOrphanEventID names the
	// most recent one.
	OrphanedIntents   uint64
	LastOrphanEventID string

	// The active segment: identity, when it was opened, and what it holds.
	SegmentUUID       string
	SegmentOpenedUnix int64
	SegmentRecords    uint64
	SegmentBytes      int64

	// StartedUnix is when this writer was created and BytesWritten the
	// record bytes it has appended since, before compression; together
	// they give the write rate the retention projection rests on.
	StartedUnix  int64
	BytesWritten int64
	Retention    Retention

	Producers []ProducerStats
}

// Streams lists the record streams in a fixed order, for a consumer that
// reports every stream whether or not it has seen a record.
func Streams() []Stream { return append([]Stream(nil), streamByIdx[:]...) }

// DropReasons lists the drop reasons in a fixed order, for the same
// consumer: a reason reported at zero is distinguishable from one nobody
// asked about.
func DropReasons() []string { return append([]string(nil), dropReasons[:]...) }

// Stats returns a snapshot. It is safe from any goroutine.
func (w *Writer) Stats() Stats {
	s := Stats{
		BootID:            w.bootID,
		Running:           w.running.Load(),
		SeqHigh:           w.seq.Load(),
		LastWriteUnix:     w.lastWrite.Load(),
		LastHeartbeatUnix: w.lastBeat.Load(),
		Accepted:          make(map[Stream]uint64, numStreams),
		QueueDepth:        make(map[string]int, numQueues),
		QueueHWM:          make(map[string]int, numQueues),
		WriteFailures:     w.stats.writeFailures.Load(),
		SyncFailures:      w.stats.syncFailures.Load(),
		MgmtTimeouts:      w.stats.mgmtTimeouts.Load(),
		Panics:            w.stats.panics.Load(),
		Restarts:          w.stats.restarts.Load(),
		Heartbeats:        w.stats.heartbeats.Load(),
		Rotations:         w.stats.rotations.Load(),
		PathSanitized:     w.stats.pathSanitized.Load(),
		Unattributed:      w.stats.unattributed.Load(),
		PermRepaired:      w.seg.stats.permRepaired.Load(),
		RotationFailed:    w.seg.stats.rotationFailed.Load(),
		CompressFailed:    w.seg.stats.compressFailed.Load(),
		CompressSkipped:   w.seg.stats.compressSkipped.Load(),
		Pruned:            w.stats.pruned.Load(),
		ReserveBreaches:   w.stats.reserveBreaches.Load(),
		ReserveBreached:   w.reserveBreached.Load(),
		SealedBytes:       w.sealedBytes.Load(),
		SegmentUUID:       w.seg.currentUUID(),
		OrphanedIntents:   w.stats.orphanedIntents.Load(),
		StartedUnix:       w.startedAt.Unix(),
		BytesWritten:      w.written.Load(),
		Retention:         *w.retention.Load(),
	}
	s.SegmentOpenedUnix, s.SegmentRecords, s.SegmentBytes = w.seg.current()
	if id := w.lastOrphan.Load(); id != nil {
		s.LastOrphanEventID = *id
	}
	// Every drop, wherever it was counted. The writer counts the ones it
	// refuses itself; a record turned away because its queue was full is
	// counted by the producer that could not hand it over, and that is the
	// shape every data-path drop takes. Reporting only the writer's own
	// counters left the stream totals reading zero while the producers
	// behind them had lost thousands — and a lost record is exactly what
	// these totals exist to report. Per-producer detail stays in
	// s.Producers; this is the sum per stream and reason.
	dropPerStream := make(map[Stream]map[string]uint64, numStreams)
	for i := range streamByIdx {
		s.Accepted[streamByIdx[i]] = w.stats.accepted[i].Load()
		for j := range dropReasons {
			if n := w.stats.dropped[i][j].Load(); n != 0 {
				if dropPerStream[streamByIdx[i]] == nil {
					dropPerStream[streamByIdx[i]] = make(map[string]uint64, numDropReasons)
				}
				dropPerStream[streamByIdx[i]][dropReasons[j]] += n
			}
		}
	}
	for _, p := range *w.producers.Load() {
		for j := range dropReasons {
			if n := p.dropped[j].Load(); n != 0 {
				if dropPerStream[p.stream] == nil {
					dropPerStream[p.stream] = make(map[string]uint64, numDropReasons)
				}
				dropPerStream[p.stream][dropReasons[j]] += n
			}
		}
	}
	for i := range streamByIdx {
		for j := range dropReasons {
			if n := dropPerStream[streamByIdx[i]][dropReasons[j]]; n != 0 {
				s.Dropped = append(s.Dropped, DropCount{Stream: streamByIdx[i], Reason: dropReasons[j], Count: n})
			}
		}
	}
	for i := range w.queues {
		s.QueueDepth[queueNames[i]] = len(w.queues[i])
		s.QueueHWM[queueNames[i]] = int(w.hwm[i].Load())
	}
	for _, p := range *w.producers.Load() {
		s.Producers = append(s.Producers, p.stats())
	}
	sort.Slice(s.Producers, func(i, j int) bool { return s.Producers[i].ID < s.Producers[j].ID })
	return s
}

// removeFile is os.Remove behind a name the tests can read.
func removeFile(path string) error { return os.Remove(path) }
