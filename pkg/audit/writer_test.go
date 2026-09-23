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
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// line is one decoded JSONL line from a segment, plus the file it came from.
type line struct {
	file string
	m    map[string]any
}

func (l line) str(k string) string {
	v, _ := l.m[k].(string)
	return v
}

func (l line) num(k string) float64 {
	v, _ := l.m[k].(float64)
	return v
}

func (l line) detail() map[string]any {
	d, _ := l.m["detail"].(map[string]any)
	return d
}

// readDir decodes every segment in dir, sealed segments oldest first and
// the active one last, header and footer lines included.
func readDir(t *testing.T, dir string) []line {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if _, _, ok := parseSegmentName(e.Name()); ok {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if _, err := os.Stat(filepath.Join(dir, ActiveSegmentName)); err == nil {
		names = append(names, ActiveSegmentName)
	}
	var out []line
	for _, n := range names {
		out = append(out, readSegment(t, filepath.Join(dir, n))...)
	}
	return out
}

func readSegment(t *testing.T, path string) []line {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, gzipExt) {
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer zr.Close()
		r = zr
	}
	var out []line
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("%s: bad line %q: %v", path, sc.Bytes(), err)
		}
		out = append(out, line{file: filepath.Base(path), m: m})
	}
	return out
}

func records(ls []line) []line {
	var out []line
	for _, l := range ls {
		if _, isMeta := l.m["kind"]; !isMeta {
			out = append(out, l)
		}
	}
	return out
}

func ofType(ls []line, eventType string) []line {
	var out []line
	for _, l := range records(ls) {
		if l.str("event_type") == eventType {
			out = append(out, l)
		}
	}
	return out
}

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Dir:               filepath.Join(t.TempDir(), "audit"),
		CreateDir:         true,
		InstanceID:        "igw-test",
		QueueSize:         64,
		HeartbeatInterval: time.Hour,
		MaxSegmentBytes:   1 << 20,
		Logf:              func(format string, args ...any) { t.Logf(format, args...) },
	}
}

func startWriter(t *testing.T, cfg Config) *Writer {
	t.Helper()
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	waitFor(t, "writer running", func() bool { return w.Running() })
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Close(ctx)
	})
	return w
}

func closeWriter(t *testing.T, w *Writer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func mgmtIntent(path string) *Record {
	return &Record{
		Stream:    StreamMgmt,
		EventType: "mgmt.config.mutate",
		Phase:     PhaseIntent,
		Actor:     Actor{Auth: AuthSession, User: "admin", Remote: "127.0.0.1:1"},
		Outcome:   Outcome{Reason: ReasonOK},
		Mgmt:      &MgmtDetail{Method: "POST", Path: path, Resource: "loadbalancer", Action: "create"},
	}
}

func dataRecord() *Record {
	return &Record{
		Stream:    StreamData,
		EventType: "data.ai.complete",
		RequestID: "req",
		Actor:     Actor{Auth: AuthAPIKey, KeyID: "k1"},
		Outcome:   Outcome{Status: 200, OK: true, Reason: ReasonOK},
		Data:      &DataDetail{Service: "chat", Model: "m"},
	}
}

// TestWriteDurableRoundTrip: a durable write lands in the active segment
// after the start records, stamped with the segment's UUID and a
// monotonic seq; a graceful close seals the segment with a consistent
// footer.
func TestWriteDurableRoundTrip(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := w.Write(ctx, mgmtIntent("/netlox/v1/config/loadbalancer")); err != nil {
			t.Fatal(err)
		}
	}
	if w.LastWriteUnix() == 0 {
		t.Fatal("last write gauge not stamped")
	}
	closeWriter(t, w)

	ls := readDir(t, cfg.Dir)
	if len(ls) < 5 {
		t.Fatalf("too few lines: %d", len(ls))
	}
	hdr, ftr := ls[0], ls[len(ls)-1]
	if hdr.str("kind") != kindHeader || ftr.str("kind") != kindFooter {
		t.Fatalf("segment not framed: first %v last %v", hdr.m, ftr.m)
	}
	if hdr.str("boot_id") != w.BootID() || hdr.str("instance_id") != "igw-test" {
		t.Fatalf("header identity wrong: %v", hdr.m)
	}
	recs := records(ls)
	if recs[0].str("event_type") != "sys.writer.start" {
		t.Fatalf("first record is %s, want sys.writer.start", recs[0].str("event_type"))
	}
	for i, r := range recs {
		if r.num("seq") != float64(i+1) {
			t.Fatalf("seq of record %d is %v", i, r.m["seq"])
		}
		if r.str("segment_uuid") != hdr.str("segment_uuid") {
			t.Fatalf("record %d carries segment %s, header says %s", i, r.str("segment_uuid"), hdr.str("segment_uuid"))
		}
		if r.str("boot_id") != w.BootID() || r.num("schema_version") != SchemaVersion {
			t.Fatalf("record %d envelope wrong: %v", i, r.m)
		}
	}
	intents := ofType(ls, "mgmt.config.mutate")
	if len(intents) != 3 {
		t.Fatalf("got %d intents, want 3", len(intents))
	}
	if intents[0].str("event_id") == "" || intents[0].str("event_id") == intents[1].str("event_id") {
		t.Fatalf("event ids not assigned uniquely: %v", intents[0].m)
	}
	if ftr.num("record_count") != float64(len(recs)) || ftr.num("last_seq") != float64(len(recs)) {
		t.Fatalf("footer %v does not match %d records", ftr.m, len(recs))
	}
	if ftr.m["recovered"] != false {
		t.Fatalf("graceful seal marked recovered: %v", ftr.m)
	}
}

// TestFailClosedWhenNotRunning: without a running writer the durable path
// refuses, the best-effort path reports the drop, and both are counted.
func TestFailClosedWhenNotRunning(t *testing.T) {
	cfg := testConfig(t)
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(context.Background())
	if err := w.Write(context.Background(), mgmtIntent("/x")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Write on a stopped writer: %v, want ErrUnavailable", err)
	}
	if w.Append(mgmtIntent("/x")) {
		t.Fatal("Append on a stopped writer succeeded")
	}
	p := w.Producer("w0", StreamData)
	if p.Emit(dataRecord()) {
		t.Fatal("Emit on a stopped writer succeeded")
	}
	st := w.Stats()
	var mgmtDown, dataDown uint64
	for _, d := range st.Dropped {
		if d.Reason == DropWriterDown && d.Stream == StreamMgmt {
			mgmtDown = d.Count
		}
	}
	for _, ps := range st.Producers {
		dataDown = ps.Dropped[DropWriterDown]
	}
	if mgmtDown != 2 || dataDown != 1 {
		t.Fatalf("drop accounting: mgmt writer_down %d (want 2), producer writer_down %d (want 1)", mgmtDown, dataDown)
	}
}

// TestWriteInvalidRefused: a record outside the schema never reaches the
// file, and the refusal names the rule.
func TestWriteInvalidRefused(t *testing.T) {
	w := startWriter(t, testConfig(t))
	r := mgmtIntent("/x")
	r.Outcome.Reason = "free text"
	if err := w.Write(context.Background(), r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

// TestProducerDropAccounting is T2's unit form: with the writer stalled
// and a small queue, the producer's sends fail fast, each drop consumes a
// pseq, the counters move, and the writer later reports the exact ranges
// from the producer's ring rather than inferring them.
func TestProducerDropAccounting(t *testing.T) {
	old := stallNanos.Swap(int64(30 * time.Millisecond))
	defer stallNanos.Store(old)

	cfg := testConfig(t)
	cfg.QueueSize = 4
	w := startWriter(t, cfg)
	w.faults.arm(FaultWriterStall)
	// Wake the writer so it is inside a stall while we flood the queue.
	w.Append(mgmtIntent("/wake"))
	time.Sleep(5 * time.Millisecond)

	p := w.Producer("w1", StreamData)
	const n = 40
	accepted := 0
	for i := 0; i < n; i++ {
		if p.Emit(dataRecord()) {
			accepted++
		}
	}
	if accepted == n || accepted == 0 {
		t.Fatalf("expected a partial drop, accepted %d of %d", accepted, n)
	}
	w.faults.arm("")
	ps := p.stats()
	if ps.PseqHigh != n {
		t.Fatalf("pseq high %d, want %d (drops must consume a pseq)", ps.PseqHigh, n)
	}
	if ps.Accepted != uint64(accepted) || ps.Dropped[DropQueueFull] != uint64(n-accepted) {
		t.Fatalf("producer counters accepted %d dropped %v, want %d / %d", ps.Accepted, ps.Dropped, accepted, n-accepted)
	}

	// Heartbeat drains the ring into gap records.
	waitFor(t, "queue drained", func() bool { return w.Stats().QueueDepth["data"] == 0 })
	w.heartbeatNow(t)
	closeWriter(t, w)

	ls := readDir(t, cfg.Dir)
	gaps := ofType(ls, "sys.producer.gap")
	if len(gaps) == 0 {
		t.Fatal("no sys.producer.gap record")
	}
	var covered uint64
	for _, g := range gaps {
		d := g.detail()
		if d["producer_id"] != "w1" || d["reason"] != DropQueueFull || d["exact"] != true {
			t.Fatalf("gap record %v", d)
		}
		covered += uint64(d["pseq_to"].(float64)-d["pseq_from"].(float64)) + 1
	}
	if covered != uint64(n-accepted) {
		t.Fatalf("gap records cover %d drops, producer counted %d", covered, n-accepted)
	}
	// Every accepted data record carries its producer identity.
	dataRecs := ofType(ls, "data.ai.complete")
	if len(dataRecs) != accepted {
		t.Fatalf("%d data records written, %d accepted", len(dataRecs), accepted)
	}
	for _, r := range dataRecs {
		if r.str("producer_id") != "w1" || r.num("pseq") == 0 {
			t.Fatalf("data record without producer identity: %v", r.m)
		}
	}
	hbs := ofType(ls, "sys.heartbeat")
	if len(hbs) == 0 {
		t.Fatal("no heartbeat")
	}
	hb := hbs[len(hbs)-1].detail()["heartbeat"].(map[string]any)
	if hb["pseq_high"] == nil || hb["dropped_by_reason"] == nil {
		t.Fatalf("heartbeat lacks producer fields: %v", hb)
	}
}

// heartbeatNow runs one heartbeat on the writer goroutine.
func (w *Writer) heartbeatNow(t *testing.T) {
	t.Helper()
	before := w.Stats().Heartbeats
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.onLoop(ctx, func() { w.heartbeat(); w.flush() }); err != nil {
		t.Fatal(err)
	}
	if w.Stats().Heartbeats != before+1 {
		t.Fatal("heartbeat did not run")
	}
}

// TestSupervisorRestartsAfterPanic is T17's unit form: a panic in the
// writer is counted, the durable path refuses meanwhile, the writer comes
// back on its own and the first records of the new run say what happened.
func TestSupervisorRestartsAfterPanic(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	if err := w.Write(context.Background(), mgmtIntent("/before")); err != nil {
		t.Fatal(err)
	}
	seqBefore := w.SeqHigh()
	w.faults.arm(FaultWriterPanic)
	w.Append(mgmtIntent("/boom"))
	waitFor(t, "writer down", func() bool { return !w.Running() })
	w.faults.arm("")
	waitFor(t, "writer back", func() bool { return w.Running() })
	if err := w.Write(context.Background(), mgmtIntent("/after")); err != nil {
		t.Fatalf("write after restart: %v", err)
	}
	st := w.Stats()
	if st.Panics != 1 || st.Restarts != 1 {
		t.Fatalf("panics %d restarts %d, want 1/1", st.Panics, st.Restarts)
	}
	closeWriter(t, w)

	ls := readDir(t, cfg.Dir)
	panics := ofType(ls, "sys.writer.panic")
	restarts := ofType(ls, "sys.writer.restart")
	if len(panics) != 1 || len(restarts) != 1 {
		t.Fatalf("panic records %d restart records %d", len(panics), len(restarts))
	}
	if panics[0].detail()["last_seq_before"] != float64(seqBefore) {
		t.Fatalf("panic record last_seq_before %v, want %d", panics[0].detail()["last_seq_before"], seqBefore)
	}
	if restarts[0].detail()["restart_count"] != float64(1) {
		t.Fatalf("restart record %v", restarts[0].detail())
	}
	if !strings.Contains(panics[0].detail()["panic_msg"].(string), FaultWriterPanic) {
		t.Fatalf("panic message lost: %v", panics[0].detail())
	}
	// seq continues across the restart.
	after := ofType(ls, "mgmt.config.mutate")
	if after[len(after)-1].num("seq") <= float64(seqBefore) {
		t.Fatal("seq did not continue across the restart")
	}
}

// TestWriteFailureIsRecordedRetroactively is T19's unit form.
func TestWriteFailureIsRecordedRetroactively(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	w.faults.arm(FaultWriterWriteFailed)
	for i := 0; i < 3; i++ {
		if err := w.Write(context.Background(), mgmtIntent("/fail")); !errors.Is(err, ErrWriteFailed) {
			t.Fatalf("got %v, want ErrWriteFailed", err)
		}
	}
	if w.Stats().WriteFailures != 3 {
		t.Fatalf("write failures %d, want 3", w.Stats().WriteFailures)
	}
	w.faults.arm("")
	if err := w.Write(context.Background(), mgmtIntent("/ok")); err != nil {
		t.Fatal(err)
	}
	closeWriter(t, w)
	ls := readDir(t, cfg.Dir)
	wf := ofType(ls, "sys.writer.write_failed")
	if len(wf) != 1 {
		t.Fatalf("write_failed records %d, want 1", len(wf))
	}
	d := wf[0].detail()
	if d["count"] != float64(3) || d["errno_class"] != "EIO" || d["first_ts"] == "" {
		t.Fatalf("retroactive record %v", d)
	}
	if len(ofType(ls, "mgmt.config.mutate")) != 1 {
		t.Fatal("a refused intent reached the file")
	}
}

// TestRotationFramesAndPermissions: rotation by size produces sealed,
// compressed 0600 segments whose header links the predecessor and whose
// footer counts match; the active file stays 0600; the debug-log API's
// name filter never matches.
func TestRotationFramesAndPermissions(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxSegmentBytes = 4096
	w := startWriter(t, cfg)
	for i := 0; i < 60; i++ {
		if err := w.Write(context.Background(), mgmtIntent("/netlox/v1/config/loadbalancer")); err != nil {
			t.Fatal(err)
		}
	}
	if w.Stats().Rotations == 0 {
		t.Fatal("no rotation happened")
	}
	closeWriter(t, w)

	entries, err := os.ReadDir(cfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var sealed int
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm() != fileMode {
			t.Errorf("%s mode %04o, want %04o", e.Name(), info.Mode().Perm(), fileMode)
		}
		if strings.HasPrefix(e.Name(), "loxilb") || strings.HasSuffix(e.Name(), ".log") || strings.HasSuffix(e.Name(), ".log.gz") {
			t.Errorf("%s would be visible to the debug-log API", e.Name())
		}
		if _, gz, ok := parseSegmentName(e.Name()); ok {
			sealed++
			if !gz {
				t.Errorf("%s was not compressed", e.Name())
			}
		}
	}
	if sealed < 2 {
		t.Fatalf("only %d sealed segments", sealed)
	}
	ls := readDir(t, cfg.Dir)
	var prev string
	var count float64
	var lastSeq float64
	for _, l := range ls {
		switch l.str("kind") {
		case kindHeader:
			if l.str("prev_segment_uuid") != prev {
				t.Fatalf("segment %s links to %q, previous sealed was %q", l.str("segment_uuid"), l.str("prev_segment_uuid"), prev)
			}
			count = 0
		case kindFooter:
			if l.num("record_count") != count {
				t.Fatalf("footer of %s counts %v, saw %v records", l.file, l.num("record_count"), count)
			}
			if l.num("last_seq") != lastSeq {
				t.Fatalf("footer of %s last_seq %v, saw %v", l.file, l.num("last_seq"), lastSeq)
			}
			prev = l.str("segment_uuid")
		default:
			count++
			if l.num("seq") != lastSeq+1 {
				t.Fatalf("seq hole at %v after %v", l.num("seq"), lastSeq)
			}
			lastSeq = l.num("seq")
		}
	}
	seals := ofType(ls, "sys.segment.seal")
	opens := ofType(ls, "sys.segment.open")
	if len(seals) != sealed-1 || len(opens) != sealed {
		// The last seal is the graceful close and has no record after it.
		t.Fatalf("seal records %d open records %d for %d sealed segments", len(seals), len(opens), sealed)
	}
}

// TestDirectoryModeRefused: a group- or world-readable audit directory is a
// start-up error, not a warning.
func TestDirectoryModeRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Dir: dir}); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("got %v, want a mode error", err)
	}
	if _, err := New(Config{Dir: filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("missing directory without CreateDir was accepted")
	}
	cfg := testConfig(t)
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close(context.Background())
	st, _ := os.Stat(cfg.Dir)
	if st.Mode().Perm() != dirMode {
		t.Fatalf("created dir mode %04o", st.Mode().Perm())
	}
	// The active file's mode is repaired if something widened it.
	if err := os.Chmod(filepath.Join(cfg.Dir, ActiveSegmentName), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := w.seg.verifyMode(w.seg.f); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Stat(filepath.Join(cfg.Dir, ActiveSegmentName))
	if st.Mode().Perm() != fileMode || w.Stats().PermRepaired != 1 {
		t.Fatalf("mode %04o repaired %d", st.Mode().Perm(), w.Stats().PermRepaired)
	}
}

// TestRecoveryOfUnsealedSegment: a segment the previous process never
// sealed is closed at start with a footer marked recovered, its torn tail
// dropped and named, the new segment links to it, and the run records it.
func TestRecoveryOfUnsealedSegment(t *testing.T) {
	cfg := testConfig(t)
	// First life: write records, then "crash" by abandoning the writer.
	w1, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w1.Start()
	waitFor(t, "running", w1.Running)
	for i := 0; i < 5; i++ {
		if err := w1.Write(context.Background(), mgmtIntent("/life1")); err != nil {
			t.Fatal(err)
		}
	}
	uuid1 := w1.seg.uuid
	// Simulate the crash: stop the goroutine without sealing, then tear
	// the tail of the active file.
	w1.stopOnce.Do(func() { close(w1.stopCh) })
	<-w1.done
	active := filepath.Join(cfg.Dir, ActiveSegmentName)
	// Close() sealed it; undo that to model a crash: rename back and strip
	// the footer, then append a torn line.
	segs, _ := w1.seg.listSealed()
	if len(segs) != 1 {
		t.Fatalf("expected one sealed segment, got %d", len(segs))
	}
	waitFor(t, "compressed", func() bool {
		s, _ := w1.seg.listSealed()
		return len(s) == 1 && s[0].Compressed
	})
	segs, _ = w1.seg.listSealed()
	plain := decompressTo(t, segs[0].Path, active)
	os.Remove(segs[0].Path)
	stripFooterAndTear(t, plain)

	// Second life.
	w2 := startWriter(t, cfg)
	if err := w2.Write(context.Background(), mgmtIntent("/life2")); err != nil {
		t.Fatal(err)
	}
	closeWriter(t, w2)

	ls := readDir(t, cfg.Dir)
	var footers []line
	for _, l := range ls {
		if l.str("kind") == kindFooter {
			footers = append(footers, l)
		}
	}
	if len(footers) != 2 {
		t.Fatalf("footers %d, want 2", len(footers))
	}
	rec := footers[0]
	if rec.m["recovered"] != true || rec.num("truncated_tail_bytes") == 0 || rec.str("segment_uuid") != uuid1 {
		t.Fatalf("recovered footer %v", rec.m)
	}
	if rec.num("record_count") != 6 { // start + open + 5 intents, minus the torn one = 6
		t.Fatalf("recovered footer counts %v", rec.num("record_count"))
	}
	var headers []line
	for _, l := range ls {
		if l.str("kind") == kindHeader {
			headers = append(headers, l)
		}
	}
	if headers[1].str("prev_segment_uuid") != uuid1 {
		t.Fatalf("new segment links to %q, want %q", headers[1].str("prev_segment_uuid"), uuid1)
	}
	recs := ofType(ls, "sys.segment.recovered")
	if len(recs) != 1 || recs[0].detail()["records_recovered"] != float64(6) || recs[0].detail()["truncated_tail_bytes"] == nil {
		t.Fatalf("recovery record %v", recs)
	}
}

func decompressTo(t *testing.T, gzPath, dst string) string {
	t.Helper()
	in, err := os.Open(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, zr); err != nil {
		t.Fatal(err)
	}
	out.Close()
	return dst
}

// stripFooterAndTear removes the footer line and the last record, then
// appends half of that record, modelling a crash mid-append.
func stripFooterAndTear(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatal("segment too short to tear")
	}
	last := lines[len(lines)-2] // the last record before the footer
	kept := lines[:len(lines)-2]
	content := strings.Join(kept, "\n") + "\n" + last[:len(last)/2]
	if err := os.WriteFile(path, []byte(content), fileMode); err != nil {
		t.Fatal(err)
	}
}

// TestRetentionPrunesOneAnnouncedSegmentPerPass is T16's unit form: the
// quota prunes oldest first, one per pass, each prune preceded by its
// record; a held segment survives; a policy change deletes nothing at once.
func TestRetentionPrunesOneAnnouncedSegmentPerPass(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := w.Write(ctx, mgmtIntent("/seg")); err != nil {
			t.Fatal(err)
		}
		if err := w.SealNow(ctx); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "four compressed segments", func() bool {
		s, _ := w.seg.listSealed()
		n := 0
		for _, x := range s {
			if x.Compressed {
				n++
			}
		}
		return n == 4
	})
	segs, _ := w.seg.listSealed()
	oldest := w.seg.uuidOf(segs[0].Path)
	second := w.seg.uuidOf(segs[1].Path)
	w.Hold(oldest, "hold-1")

	// A quota below the total: without the hold the oldest would go first.
	w.SetRetention(Retention{MaxBytes: 1})
	w.prunePassNow(t)
	segs, _ = w.seg.listSealed()
	if len(segs) != 3 {
		t.Fatalf("after one pass %d segments, want 3 (one prune per pass)", len(segs))
	}
	if w.seg.uuidOf(segs[0].Path) != oldest {
		t.Fatal("held segment was pruned")
	}
	w.prunePassNow(t)
	segs, _ = w.seg.listSealed()
	if len(segs) != 2 || w.seg.uuidOf(segs[0].Path) != oldest {
		t.Fatalf("after two passes: %d segments, first %s", len(segs), w.seg.uuidOf(segs[0].Path))
	}
	w.ReleaseHold(oldest)
	w.prunePassNow(t)
	segs, _ = w.seg.listSealed()
	if len(segs) != 1 || w.seg.uuidOf(segs[0].Path) == oldest {
		t.Fatalf("after release: %d segments, first %s", len(segs), w.seg.uuidOf(segs[0].Path))
	}
	if w.Stats().Pruned != 3 {
		t.Fatalf("pruned %d, want 3", w.Stats().Pruned)
	}
	closeWriter(t, w)

	ls := readDir(t, cfg.Dir)
	prunes := ofType(ls, "sys.segment.prune")
	if len(prunes) != 3 {
		t.Fatalf("prune records %d, want 3", len(prunes))
	}
	if prunes[0].detail()["resource"] != "audit_segment:"+second {
		t.Fatalf("first prune named %v, want the second-oldest %s", prunes[0].detail()["resource"], second)
	}
	for _, p := range prunes {
		d := p.detail()
		if d["hold"] != false || d["bytes"] == nil {
			t.Fatalf("prune record %v", d)
		}
	}
}

// prunePassNow runs one retention pass on the writer goroutine.
func (w *Writer) prunePassNow(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.onLoop(ctx, func() { w.prunePass(); w.flush() }); err != nil {
		t.Fatal(err)
	}
}

// TestHeartbeatWhenIdle: an idle writer still produces heartbeats and
// stamps the liveness gauge, so a dead writer can never be mistaken for
// an idle one.
func TestHeartbeatWhenIdle(t *testing.T) {
	cfg := testConfig(t)
	cfg.HeartbeatInterval = 20 * time.Millisecond
	w := startWriter(t, cfg)
	waitFor(t, "three heartbeats", func() bool { return w.Stats().Heartbeats >= 3 })
	if w.LastWriteUnix() == 0 {
		t.Fatal("liveness gauge never stamped")
	}
	closeWriter(t, w)
	hbs := ofType(readDir(t, cfg.Dir), "sys.heartbeat")
	if len(hbs) < 3 {
		t.Fatalf("heartbeat records %d", len(hbs))
	}
	hb := hbs[0].detail()["heartbeat"].(map[string]any)
	for _, k := range []string{"seq_high", "accepted", "queue_depth", "queue_hwm", "unattributed_total"} {
		if _, ok := hb[k]; !ok {
			t.Errorf("heartbeat lacks %s: %v", k, hb)
		}
	}
}

// TestAppendResultIsCounted: the best-effort path never drops silently.
func TestAppendResultIsCounted(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	r := mgmtIntent("/x")
	r.Phase = PhaseResult
	r.Outcome = Outcome{Status: 200, OK: true, Reason: ReasonOK}
	if !w.Append(r) {
		t.Fatal("append refused")
	}
	waitFor(t, "result written", func() bool { return w.Stats().Accepted[StreamMgmt] >= 1 })
	closeWriter(t, w)
	res := ofType(readDir(t, cfg.Dir), "mgmt.config.mutate")
	if len(res) != 1 || res[0].str("phase") != string(PhaseResult) {
		t.Fatalf("result record %v", res)
	}
}

// TestUnattributedProducerIsCounted: a record without a worker identity
// is written under the unattributed producer and counted.
func TestUnattributedProducerIsCounted(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	p := w.Producer("", StreamData)
	if p.ID() != UnattributedProducer {
		t.Fatalf("producer id %q", p.ID())
	}
	if !p.Emit(dataRecord()) {
		t.Fatal("emit refused")
	}
	waitFor(t, "written", func() bool { return w.Stats().Unattributed == 1 })
}

// TestDurableWriteTimesOut: a caller's deadline bounds the durable wait
// and the timeout is counted.
func TestDurableWriteTimesOut(t *testing.T) {
	old := stallNanos.Swap(int64(200 * time.Millisecond))
	defer stallNanos.Store(old)
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	w.faults.arm(FaultWriterStall)
	w.Append(mgmtIntent("/wake"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := w.Write(ctx, mgmtIntent("/slow"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
	w.faults.arm("")
	if w.Stats().MgmtTimeouts != 1 {
		t.Fatalf("timeouts %d", w.Stats().MgmtTimeouts)
	}
}
