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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// rawRecords is the oracle: every record line in the directory, read the
// plain way, sealed segments by name and the active one last. A sealed
// segment is compressed behind the writer's back, so a name the listing
// returned can be gone by the time it is opened; the directory is then
// read again from the start.
func rawRecords(t *testing.T, dir string) [][]byte {
	t.Helper()
	for attempt := 0; ; attempt++ {
		out, err := rawRecordsOnce(t, dir)
		if err == nil {
			return out
		}
		if !errors.Is(err, os.ErrNotExist) || attempt == 20 {
			t.Fatal(err)
		}
	}
}

func rawRecordsOnce(t *testing.T, dir string) ([][]byte, error) {
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
	sort.Slice(names, func(i, j int) bool {
		return strings.TrimSuffix(names[i], gzipExt) < strings.TrimSuffix(names[j], gzipExt)
	})
	if _, err := os.Stat(filepath.Join(dir, ActiveSegmentName)); err == nil {
		names = append(names, ActiveSegmentName)
	}
	var out [][]byte
	for _, n := range names {
		f, err := os.Open(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		var rd io.Reader = f
		if strings.HasSuffix(n, gzipExt) {
			zr, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			rd = zr
		}
		sc := bufio.NewScanner(rd)
		sc.Buffer(make([]byte, 64*1024), maxLineBytes)
		for sc.Scan() {
			var lk lineKind
			if json.Unmarshal(sc.Bytes(), &lk) != nil || lk.Kind != "" {
				continue
			}
			out = append(out, append([]byte(nil), sc.Bytes()...))
		}
		f.Close()
	}
	return out, nil
}

// drain reads until the reader is idle and returns copies of what it got.
func drain(t *testing.T, r *TrailReader) []TrailLine {
	t.Helper()
	var out []TrailLine
	for {
		l, err := r.Next()
		if errors.Is(err, ErrTrailIdle) {
			return out
		}
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		l.Raw = append([]byte(nil), l.Raw...)
		out = append(out, l)
	}
}

func sameLines(t *testing.T, what string, got []TrailLine, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d records, want %d", what, len(got), len(want))
	}
	for i := range got {
		if !bytes.Equal(got[i].Raw, want[i]) {
			t.Fatalf("%s: record %d differs\n got %s\nwant %s", what, i, got[i].Raw, want[i])
		}
	}
}

func writeN(t *testing.T, w *Writer, n int, tag string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < n; i++ {
		if err := w.Write(ctx, mgmtIntent(fmt.Sprintf("/%s/%d", tag, i))); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func sealNow(t *testing.T, w *Writer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.SealNow(ctx); err != nil {
		t.Fatalf("seal: %v", err)
	}
}

// waitCompressed waits until no plain sealed segment is left.
func waitCompressed(t *testing.T, dir string) {
	t.Helper()
	waitFor(t, "sealed segments compressed", func() bool {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return false
		}
		gz := 0
		for _, e := range entries {
			if _, isGz, ok := parseSegmentName(e.Name()); ok {
				if !isGz {
					return false
				}
				gz++
			}
		}
		return gz > 0
	})
}

func TestTrailReaderFollowsTheActiveSegment(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	r := NewTrailReader(cfg.Dir, Position{})
	defer r.Close()

	writeN(t, w, 3, "a")
	got := drain(t, r)
	sameLines(t, "first read", got, rawRecords(t, cfg.Dir))
	seen := len(got)

	if _, err := r.Next(); !errors.Is(err, ErrTrailIdle) {
		t.Fatalf("caught up: got %v, want ErrTrailIdle", err)
	}

	writeN(t, w, 2, "b")
	more := drain(t, r)
	sameLines(t, "second read", more, rawRecords(t, cfg.Dir)[seen:])
	if len(more) < 2 {
		t.Fatalf("second read returned %d records, want at least the 2 written", len(more))
	}
	for i := 1; i < len(more); i++ {
		if more[i].Pos.Seq != more[i-1].Pos.Seq+1 {
			t.Fatalf("seq not contiguous: %d after %d", more[i].Pos.Seq, more[i-1].Pos.Seq)
		}
	}
}

func TestTrailReaderFollowsASealedSegmentToItsEnd(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)

	// The reader is behind by two rotations before it reads anything.
	writeN(t, w, 5, "one")
	sealNow(t, w)
	writeN(t, w, 5, "two")
	sealNow(t, w)
	writeN(t, w, 3, "three")

	r := NewTrailReader(cfg.Dir, Position{})
	defer r.Close()
	got := drain(t, r)
	sameLines(t, "behind by two rotations", got, rawRecords(t, cfg.Dir))

	uuids := map[string]bool{}
	for _, l := range got {
		uuids[l.Pos.SegmentUUID] = true
	}
	if len(uuids) != 3 {
		t.Fatalf("records came from %d segments, want 3", len(uuids))
	}
}

func TestTrailReaderRotationUnderAnOpenReader(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	r := NewTrailReader(cfg.Dir, Position{})
	defer r.Close()

	writeN(t, w, 4, "one")
	first, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	got := []TrailLine{{Pos: first.Pos, Raw: append([]byte(nil), first.Raw...)}}

	// The segment the reader holds open is sealed, renamed, compressed
	// and its plain file removed, with most of it unread.
	sealNow(t, w)
	waitCompressed(t, cfg.Dir)
	writeN(t, w, 2, "two")

	got = append(got, drain(t, r)...)
	sameLines(t, "sealed and compressed under the reader", got, rawRecords(t, cfg.Dir))
}

func TestTrailReaderReadsCompressedSegments(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 6, "one")
	sealNow(t, w)
	writeN(t, w, 6, "two")
	sealNow(t, w)
	waitCompressed(t, cfg.Dir)
	writeN(t, w, 1, "three")

	r := NewTrailReader(cfg.Dir, Position{})
	defer r.Close()
	sameLines(t, "compressed segments", drain(t, r), rawRecords(t, cfg.Dir))
}

func TestTrailReaderResumesAfterAPosition(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 4, "one")
	sealNow(t, w)
	writeN(t, w, 4, "two")

	all := rawRecords(t, cfg.Dir)
	r := NewTrailReader(cfg.Dir, Position{})
	var pos Position
	const taken = 3
	for i := 0; i < taken; i++ {
		l, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		pos = l.Pos
	}
	r.Close()

	// Resuming inside a sealed segment, then inside a compressed one,
	// continues with the record after the position either way.
	r2 := NewTrailReader(cfg.Dir, pos)
	sameLines(t, "resume in a sealed segment", drain(t, r2), all[taken:])
	r2.Close()

	waitCompressed(t, cfg.Dir)
	r3 := NewTrailReader(cfg.Dir, pos)
	defer r3.Close()
	sameLines(t, "resume in a compressed segment", drain(t, r3), rawRecords(t, cfg.Dir)[taken:])
}

func TestTrailReaderCrossesARestartOfTheWriter(t *testing.T) {
	cfg := testConfig(t)
	w1 := startWriter(t, cfg)
	writeN(t, w1, 3, "boot1")
	r := NewTrailReader(cfg.Dir, Position{})
	defer r.Close()
	got := drain(t, r)

	closeWriter(t, w1)
	w2 := startWriter(t, cfg)
	writeN(t, w2, 3, "boot2")

	got = append(got, drain(t, r)...)
	sameLines(t, "across a restart", got, rawRecords(t, cfg.Dir))

	// seq restarts with the boot, so only the segment tells two records
	// with one seq apart.
	bySeq := map[uint64]string{}
	restarted := false
	for _, l := range got {
		if u, dup := bySeq[l.Pos.Seq]; dup && u != l.Pos.SegmentUUID {
			restarted = true
		}
		bySeq[l.Pos.Seq] = l.Pos.SegmentUUID
	}
	if !restarted {
		t.Fatal("no seq was seen in two segments: the second boot's records were not read as a new sequence")
	}
}

func TestTrailReaderPositionLost(t *testing.T) {
	cfg := testConfig(t)
	w := startWriter(t, cfg)
	writeN(t, w, 3, "one")
	sealNow(t, w)
	writeN(t, w, 3, "two")

	r := NewTrailReader(cfg.Dir, Position{})
	first, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	pos := first.Pos
	r.Close()

	// Retention removes the segment the position is in. The directory is
	// listed once compression has finished: a segment removed while it is
	// being compressed comes back under its compressed name.
	waitCompressed(t, cfg.Dir)
	entries, _ := os.ReadDir(cfg.Dir)
	removed := 0
	for _, e := range entries {
		if _, _, ok := parseSegmentName(e.Name()); ok {
			if err := os.Remove(filepath.Join(cfg.Dir, e.Name())); err != nil {
				t.Fatal(err)
			}
			removed++
		}
	}
	if removed == 0 {
		t.Fatal("no sealed segment to remove")
	}

	r2 := NewTrailReader(cfg.Dir, pos)
	defer r2.Close()
	if _, err := r2.Next(); !errors.Is(err, ErrPositionLost) {
		t.Fatalf("got %v, want ErrPositionLost", err)
	}
	// The loss is reported once per attempt and never papered over.
	if _, err := r2.Next(); !errors.Is(err, ErrPositionLost) {
		t.Fatalf("second call: got %v, want ErrPositionLost", err)
	}
	r2.Seek(Position{})
	sameLines(t, "from the oldest segment left", drain(t, r2), rawRecords(t, cfg.Dir))
}

// handSegment writes a segment file by hand, so that shapes the writer
// only leaves behind after a failure can be put in front of the reader.
type handSegment struct {
	uuid, prev string
	first      uint64
	records    int
	footer     bool
}

func recordLine(uuid string, seq uint64, pad int) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":1,"event_id":"e-%s-%d","boot_id":"b","segment_uuid":%q,"seq":%d,"stream":"mgmt","pad":%q}`,
		uuid, seq, uuid, seq, strings.Repeat("x", pad)))
}

func writeHandSegment(t *testing.T, path string, s handSegment) {
	t.Helper()
	var b bytes.Buffer
	hdr, _ := json.Marshal(segmentHeader{Kind: kindHeader, SchemaVersion: SchemaVersion,
		SegmentUUID: s.uuid, PrevSegmentUUID: s.prev, BootID: "b", FirstSeq: s.first})
	b.Write(hdr)
	b.WriteByte('\n')
	for i := 0; i < s.records; i++ {
		b.Write(recordLine(s.uuid, s.first+uint64(i), 0))
		b.WriteByte('\n')
	}
	if s.footer {
		ft, _ := json.Marshal(segmentFooter{Kind: kindFooter, SegmentUUID: s.uuid, RecordCount: uint64(s.records)})
		b.Write(ft)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, b.Bytes(), fileMode); err != nil {
		t.Fatal(err)
	}
}

func appendRaw(t *testing.T, path string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

func seqs(ls []TrailLine) []uint64 {
	out := make([]uint64, len(ls))
	for i, l := range ls {
		out[i] = l.Pos.Seq
	}
	return out
}

func TestTrailReaderNeverReturnsATornLine(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, ActiveSegmentName)
	writeHandSegment(t, active, handSegment{uuid: "u1", first: 1, records: 2})
	r := NewTrailReader(dir, Position{})
	defer r.Close()
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[1 2]" {
		t.Fatalf("got %v, want [1 2]", got)
	}

	// The head of a record lands and the filesystem fills: no newline.
	st, _ := os.Stat(active)
	torn := recordLine("u1", 3, 0)
	appendRaw(t, active, torn[:len(torn)/2])
	if got := drain(t, r); len(got) != 0 {
		t.Fatalf("a line without its newline was returned: %s", got[0].Raw)
	}

	// The writer cuts the file back and a different record takes the
	// place: the reader must return that one, whole, and nothing of the
	// torn one.
	if err := os.Truncate(active, st.Size()); err != nil {
		t.Fatal(err)
	}
	want := recordLine("u1", 3, 40)
	appendRaw(t, active, append(append([]byte(nil), want...), '\n'))
	sameLines(t, "after the cut-back", drain(t, r), [][]byte{want})
}

func TestTrailReaderLineLongerThanTheChunk(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, ActiveSegmentName)
	writeHandSegment(t, active, handSegment{uuid: "u1", first: 1, records: 1})
	long := recordLine("u1", 2, 3*trailChunk)
	appendRaw(t, active, append(append([]byte(nil), long...), '\n'))
	appendRaw(t, active, append(recordLine("u1", 3, 0), '\n'))

	r := NewTrailReader(dir, Position{})
	defer r.Close()
	got := drain(t, r)
	if fmt.Sprint(seqs(got)) != "[1 2 3]" {
		t.Fatalf("got %v, want [1 2 3]", seqs(got))
	}
	if !bytes.Equal(got[1].Raw, long) {
		t.Fatalf("the long line came back as %d bytes, want %d", len(got[1].Raw), len(long))
	}
}

func TestTrailReaderSealedSegmentWithoutAFooter(t *testing.T) {
	// A seal whose footer could not be written leaves a sealed name with
	// no footer. The next segment exists, so the reader must move on.
	dir := t.TempDir()
	writeHandSegment(t, filepath.Join(dir, "audit-20260101-000000.000.jsonl"),
		handSegment{uuid: "u1", first: 1, records: 3})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName),
		handSegment{uuid: "u2", prev: "u1", first: 4, records: 2})

	r := NewTrailReader(dir, Position{})
	defer r.Close()
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[1 2 3 4 5]" {
		t.Fatalf("got %v, want [1 2 3 4 5]", got)
	}
}

func TestTrailReaderStaysOnTheActiveSegmentWithoutASuccessor(t *testing.T) {
	// The active segment has no footer and nothing follows it. A reader
	// that left it would never see what is appended next.
	dir := t.TempDir()
	active := filepath.Join(dir, ActiveSegmentName)
	writeHandSegment(t, filepath.Join(dir, "audit-20260101-000000.000.jsonl"),
		handSegment{uuid: "u1", first: 1, records: 1, footer: true})
	writeHandSegment(t, active, handSegment{uuid: "u2", prev: "u1", first: 2, records: 1})

	r := NewTrailReader(dir, Position{})
	defer r.Close()
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[1 2]" {
		t.Fatalf("got %v, want [1 2]", got)
	}
	appendRaw(t, active, append(recordLine("u2", 3, 0), '\n'))
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[3]" {
		t.Fatalf("after an append: got %v, want [3]", got)
	}
}

func TestTrailReaderLostLinkFallsBackToDirectoryOrder(t *testing.T) {
	// The second segment names a predecessor that is not in the
	// directory, which is what a recovery without a readable header
	// leaves. The first segment is finished, so the reader goes on in
	// directory order instead of stopping there for good.
	dir := t.TempDir()
	writeHandSegment(t, filepath.Join(dir, "audit-20260101-000000.000.jsonl"),
		handSegment{uuid: "u1", first: 1, records: 2, footer: true})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName),
		handSegment{uuid: "u2", prev: "gone", first: 1, records: 2})

	r := NewTrailReader(dir, Position{})
	defer r.Close()
	got := drain(t, r)
	if len(got) != 4 || got[0].Pos.SegmentUUID != "u1" || got[3].Pos.SegmentUUID != "u2" {
		t.Fatalf("got %d records %v, want 2 from u1 then 2 from u2", len(got), got)
	}
}

func TestTrailReaderLostLinkAndNoFooter(t *testing.T) {
	// Both failures at once: the first segment was sealed without a
	// footer and nothing names it as a predecessor. It is not the active
	// file, so nothing more will be appended to it, and staying would be
	// for good.
	dir := t.TempDir()
	writeHandSegment(t, filepath.Join(dir, "audit-20260101-000000.000.jsonl"),
		handSegment{uuid: "u1", first: 1, records: 2})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName),
		handSegment{uuid: "u2", prev: "gone", first: 1, records: 1})

	r := NewTrailReader(dir, Position{})
	defer r.Close()
	if got := drain(t, r); len(got) != 3 || got[2].Pos.SegmentUUID != "u2" {
		t.Fatalf("got %d records %v, want 2 from u1 then 1 from u2", len(got), got)
	}
}

func TestTrailReaderStopsAtASegmentWhoseHeaderCannotBeRead(t *testing.T) {
	// A sealed file that is there and does not say which segment it is
	// held records. A reader that went on in directory order would pass
	// over them without a word.
	dir := t.TempDir()
	damaged := filepath.Join(dir, "audit-20260101-000001.000.jsonl")
	writeHandSegment(t, filepath.Join(dir, "audit-20260101-000000.000.jsonl"),
		handSegment{uuid: "u1", first: 1, records: 2, footer: true})
	if err := os.WriteFile(damaged, []byte("not a segment\n"), fileMode); err != nil {
		t.Fatal(err)
	}
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName),
		handSegment{uuid: "u3", prev: "u2", first: 5, records: 2})

	r := NewTrailReader(dir, Position{})
	defer r.Close()
	var got []uint64
	var err error
	for {
		var l TrailLine
		if l, err = r.Next(); err != nil {
			break
		}
		got = append(got, l.Pos.Seq)
	}
	if fmt.Sprint(got) != "[1 2]" {
		t.Fatalf("got %v before the damaged segment, want [1 2]", got)
	}
	if !errors.Is(err, errSegmentUnreadable) || !strings.Contains(err.Error(), filepath.Base(damaged)) {
		t.Fatalf("got %v, want the damaged segment named", err)
	}
	// It stays there for as long as the file does.
	if _, err := r.Next(); !errors.Is(err, errSegmentUnreadable) {
		t.Fatalf("a second read got %v", err)
	}
	// A position inside the segment before it is found as before, and
	// leads to the same place.
	r2 := NewTrailReader(dir, Position{SegmentUUID: "u1", Seq: 1})
	defer r2.Close()
	if l, err := r2.Next(); err != nil || l.Pos.Seq != 2 {
		t.Fatalf("resume before the damaged segment: %v %v", l.Pos, err)
	}
	// A position that is in no readable segment may be in the damaged
	// one; it is not called lost.
	r3 := NewTrailReader(dir, Position{SegmentUUID: "u2", Seq: 3})
	defer r3.Close()
	if _, err := r3.Next(); !errors.Is(err, errSegmentUnreadable) {
		t.Fatalf("a position in no readable segment got %v", err)
	}

	// With the file gone the reader continues with what is left.
	if err := os.Remove(damaged); err != nil {
		t.Fatal(err)
	}
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[5 6]" {
		t.Fatalf("after the removal: got %v, want [5 6]", got)
	}
}

func TestTrailReaderDamagedSegmentBehindTheReaderIsNotInItsWay(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "audit-20260101-000000.000.jsonl"), []byte("not a segment\n"), fileMode); err != nil {
		t.Fatal(err)
	}
	writeHandSegment(t, filepath.Join(dir, "audit-20260101-000001.000.jsonl"),
		handSegment{uuid: "u2", prev: "u1", first: 3, records: 2, footer: true})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName),
		handSegment{uuid: "u3", prev: "u2", first: 5, records: 1})

	r := NewTrailReader(dir, Position{SegmentUUID: "u2", Seq: 3})
	defer r.Close()
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[4 5]" {
		t.Fatalf("got %v, want [4 5]", got)
	}
	if held, err := r.Holds("u2"); err != nil || !held {
		t.Fatalf("Holds(u2) = %v, %v", held, err)
	}
}

func TestTrailReaderSegmentListedInBothForms(t *testing.T) {
	// Between the compressed file's rename and the plain file's removal
	// one segment is listed twice. Its records are returned once.
	dir := t.TempDir()
	plain := filepath.Join(dir, "audit-20260101-000000.000.jsonl")
	writeHandSegment(t, plain, handSegment{uuid: "u1", first: 1, records: 3, footer: true})
	raw, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(raw)
	zw.Close()
	if err := os.WriteFile(plain+gzipExt, z.Bytes(), fileMode); err != nil {
		t.Fatal(err)
	}
	writeHandSegment(t, filepath.Join(dir, "audit-20260101-000001.000.jsonl"),
		handSegment{uuid: "u2", prev: "gone", first: 1, records: 2, footer: true})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName),
		handSegment{uuid: "u3", prev: "u2", first: 3, records: 1})

	r := NewTrailReader(dir, Position{})
	defer r.Close()
	got := drain(t, r)
	var from []string
	for _, l := range got {
		from = append(from, fmt.Sprintf("%s:%d", l.Pos.SegmentUUID, l.Pos.Seq))
	}
	if want := "[u1:1 u1:2 u1:3 u2:1 u2:2 u3:3]"; fmt.Sprint(from) != want {
		t.Fatalf("got %v, want %s", from, want)
	}
}

func TestTrailReaderSegmentRemovedWhileBeingRead(t *testing.T) {
	// Retention removes the segment under the reader and the one after
	// it. What the reader holds is read out; then the loss is reported
	// with the place it got to, and is not turned into a silent jump.
	dir := t.TempDir()
	s1 := filepath.Join(dir, "audit-20260101-000000.000.jsonl")
	s2 := filepath.Join(dir, "audit-20260101-000001.000.jsonl")
	writeHandSegment(t, s1, handSegment{uuid: "u1", first: 1, records: 3, footer: true})
	writeHandSegment(t, s2, handSegment{uuid: "u2", prev: "u1", first: 4, records: 2, footer: true})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName),
		handSegment{uuid: "u3", prev: "u2", first: 6, records: 1})

	r := NewTrailReader(dir, Position{})
	defer r.Close()
	if l, err := r.Next(); err != nil || l.Pos.Seq != 1 {
		t.Fatalf("first: %v %v", l.Pos, err)
	}
	if err := os.Remove(s1); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s2); err != nil {
		t.Fatal(err)
	}
	var got []uint64
	var err error
	for {
		var l TrailLine
		if l, err = r.Next(); err != nil {
			break
		}
		got = append(got, l.Pos.Seq)
	}
	if fmt.Sprint(got) != "[2 3]" || !errors.Is(err, ErrPositionLost) {
		t.Fatalf("got %v then %v, want [2 3] then ErrPositionLost", got, err)
	}
	if _, err := r.Next(); !errors.Is(err, ErrPositionLost) {
		t.Fatalf("again: got %v, want ErrPositionLost", err)
	}
	r.Seek(Position{})
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[6]" {
		t.Fatalf("from the oldest left: got %v, want [6]", got)
	}
}

// onceAfterList runs fn in the gap of the next scan only: after the
// directory was listed and before the files it listed are read.
func onceAfterList(t *testing.T, fn func()) {
	t.Helper()
	fired := false
	trailAfterList = func() {
		if !fired {
			fired = true
			fn()
		}
	}
	t.Cleanup(func() { trailAfterList = func() {} })
}

// sealByHand does to the active segment what the writer's seal does first:
// the footer and the rename. The next segment is not there yet.
func sealByHand(t *testing.T, dir, uuid, sealedName string) {
	t.Helper()
	active := filepath.Join(dir, ActiveSegmentName)
	ft, _ := json.Marshal(segmentFooter{Kind: kindFooter, SegmentUUID: uuid})
	appendRaw(t, active, append(ft, '\n'))
	if err := os.Rename(active, filepath.Join(dir, sealedName)); err != nil {
		t.Fatal(err)
	}
}

// compressByHand replaces a sealed segment by its compressed form, as the
// writer's compression does.
func compressByHand(t *testing.T, path string) {
	t.Helper()
	plain, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+gzipExt, b.Bytes(), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func TestTrailReaderSegmentSealedBetweenTheListingAndTheRead(t *testing.T) {
	// The reader has read the active segment out and looks at the
	// directory. The listing still has the segment under the active name;
	// before that file's header is read the writer seals it. The scan
	// finds it under neither name. It was renamed, not removed, and the
	// reader's place in it is not lost.
	dir := t.TempDir()
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName), handSegment{uuid: "u1", first: 1, records: 2})
	r := NewTrailReader(dir, Position{})
	defer r.Close()
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[1 2]" {
		t.Fatalf("got %v, want [1 2]", got)
	}

	onceAfterList(t, func() { sealByHand(t, dir, "u1", "audit-20260101-000000.000.jsonl") })
	if l, err := r.Next(); !errors.Is(err, ErrTrailIdle) {
		t.Fatalf("got %v %v, want ErrTrailIdle: the segment is still in the directory", l.Pos, err)
	}

	// The writer opens the next segment, and the reader goes on into it.
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName), handSegment{uuid: "u2", prev: "u1", first: 3, records: 2})
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[3 4]" {
		t.Fatalf("got %v, want [3 4]", got)
	}
}

func TestTrailReaderResumesInASegmentSealedBetweenTheListingAndTheRead(t *testing.T) {
	// The same gap, for a reader that starts from a saved position in the
	// segment being sealed.
	dir := t.TempDir()
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName), handSegment{uuid: "u1", first: 1, records: 3})
	r := NewTrailReader(dir, Position{SegmentUUID: "u1", Seq: 1})
	defer r.Close()

	onceAfterList(t, func() { sealByHand(t, dir, "u1", "audit-20260101-000000.000.jsonl") })
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[2 3]" {
		t.Fatalf("got %v, want [2 3]", got)
	}
}

func TestTrailReaderResumesInASegmentCompressedBetweenTheListingAndTheRead(t *testing.T) {
	// A reader that has not seen the sealed file before has to read its
	// header to know which segment it is. The listing has the plain name;
	// before the header is read compression replaces the file. The header
	// is then read from the compressed file, and the segment is found.
	dir := t.TempDir()
	s1 := filepath.Join(dir, "audit-20260101-000000.000.jsonl")
	writeHandSegment(t, s1, handSegment{uuid: "u1", first: 1, records: 3, footer: true})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName), handSegment{uuid: "u2", prev: "u1", first: 4, records: 1})
	r := NewTrailReader(dir, Position{SegmentUUID: "u1", Seq: 1})
	defer r.Close()

	onceAfterList(t, func() { compressByHand(t, s1) })
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[2 3 4]" {
		t.Fatalf("got %v, want [2 3 4]", got)
	}
}

func TestTrailReaderStartsAtTheOldestSegmentThoughItIsBeingCompressed(t *testing.T) {
	// A reader starting from nothing begins at the oldest segment. With
	// that one compressed between the listing and the read of its header,
	// the scan's oldest is the segment after it; beginning there would
	// pass over a whole segment without a word.
	dir := t.TempDir()
	s1 := filepath.Join(dir, "audit-20260101-000000.000.jsonl")
	writeHandSegment(t, s1, handSegment{uuid: "u1", first: 1, records: 3, footer: true})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName), handSegment{uuid: "u2", prev: "u1", first: 4, records: 1})
	r := NewTrailReader(dir, Position{})
	defer r.Close()

	onceAfterList(t, func() { compressByHand(t, s1) })
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[1 2 3 4]" {
		t.Fatalf("got %v, want [1 2 3 4]", got)
	}
}

func TestTrailReaderHoldsASegmentMovedDuringTheScan(t *testing.T) {
	dir := t.TempDir()
	s1 := filepath.Join(dir, "audit-20260101-000000.000.jsonl")
	writeHandSegment(t, s1, handSegment{uuid: "u1", first: 1, records: 1, footer: true})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName), handSegment{uuid: "u2", prev: "u1", first: 2, records: 1})
	r := NewTrailReader(dir, Position{})
	defer r.Close()

	onceAfterList(t, func() { compressByHand(t, s1) })
	if held, err := r.Holds("u1"); err != nil || !held {
		t.Fatalf("held=%v err=%v: the segment was compressed, not removed", held, err)
	}
	onceAfterList(t, func() { sealByHand(t, dir, "u2", "audit-20260101-000001.000.jsonl") })
	if held, err := r.Holds("u2"); err != nil || !held {
		t.Fatalf("held=%v err=%v: the segment was sealed, not removed", held, err)
	}
	if held, err := r.Holds("u9"); err != nil || held {
		t.Fatalf("held=%v err=%v for a segment that was never there", held, err)
	}
}

func TestTrailReaderRecordsAppendedJustBeforeTheSeal(t *testing.T) {
	// The reader finds nothing more in the active segment. Before it
	// looks at the directory the writer appends two records, seals the
	// segment and opens the next one. The successor is there, and so are
	// two records the reader has not returned.
	dir := t.TempDir()
	active := filepath.Join(dir, ActiveSegmentName)
	writeHandSegment(t, active, handSegment{uuid: "u1", first: 1, records: 1})
	r := NewTrailReader(dir, Position{})
	defer r.Close()
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[1]" {
		t.Fatalf("got %v, want [1]", got)
	}

	fired := false
	trailBeforeScan = func() {
		if fired {
			return
		}
		fired = true
		appendRaw(t, active, append(recordLine("u1", 2, 0), '\n'))
		appendRaw(t, active, append(recordLine("u1", 3, 0), '\n'))
		ft, _ := json.Marshal(segmentFooter{Kind: kindFooter, SegmentUUID: "u1", RecordCount: 3})
		appendRaw(t, active, append(ft, '\n'))
		if err := os.Rename(active, filepath.Join(dir, "audit-20260101-000000.000.jsonl")); err != nil {
			t.Fatal(err)
		}
		writeHandSegment(t, active, handSegment{uuid: "u2", prev: "u1", first: 4, records: 1})
	}
	defer func() { trailBeforeScan = func() {} }()

	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[2 3 4]" {
		t.Fatalf("got %v, want [2 3 4]", got)
	}
}

func TestTrailReaderFollowsTheLinkNotTheName(t *testing.T) {
	// Sealed names carry the wall clock at the seal. A clock stepped
	// backwards gives a later segment an earlier name; the header's link
	// to its predecessor is what still has the order right.
	dir := t.TempDir()
	writeHandSegment(t, filepath.Join(dir, "audit-20260102-000000.000.jsonl"),
		handSegment{uuid: "u1", first: 1, records: 2, footer: true})
	writeHandSegment(t, filepath.Join(dir, "audit-20260101-000000.000.jsonl"),
		handSegment{uuid: "u2", prev: "u1", first: 3, records: 2, footer: true})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName),
		handSegment{uuid: "u3", prev: "u2", first: 5, records: 1})

	r := NewTrailReader(dir, Position{})
	defer r.Close()
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[1 2 3 4 5]" {
		t.Fatalf("got %v, want [1 2 3 4 5]", got)
	}
}

func TestTrailReaderContinuesAfterClose(t *testing.T) {
	dir := t.TempDir()
	writeHandSegment(t, filepath.Join(dir, "audit-20260101-000000.000.jsonl"),
		handSegment{uuid: "u1", first: 1, records: 3, footer: true})
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName),
		handSegment{uuid: "u2", prev: "u1", first: 4, records: 2})

	r := NewTrailReader(dir, Position{})
	// Closed before anything was opened, in the middle of a segment, and
	// at the first record of the next one: each time the reader goes on
	// with the record after the last one it returned.
	r.Close()
	var got []uint64
	for i := 0; i < 5; i++ {
		l, err := r.Next()
		if err != nil {
			t.Fatalf("record %d: %v", i+1, err)
		}
		got = append(got, l.Pos.Seq)
		if i == 1 || i == 3 {
			r.Close()
			r.Close()
		}
	}
	if fmt.Sprint(got) != "[1 2 3 4 5]" {
		t.Fatalf("got %v, want [1 2 3 4 5]", got)
	}
	r.Close()
	if _, err := r.Next(); !errors.Is(err, ErrTrailIdle) {
		t.Fatalf("after the last record: got %v, want ErrTrailIdle", err)
	}
}

func TestTrailReaderEmptyDirectoryIsIdle(t *testing.T) {
	dir := t.TempDir()
	r := NewTrailReader(dir, Position{})
	defer r.Close()
	if _, err := r.Next(); !errors.Is(err, ErrTrailIdle) {
		t.Fatalf("got %v, want ErrTrailIdle", err)
	}
	writeHandSegment(t, filepath.Join(dir, ActiveSegmentName), handSegment{uuid: "u1", first: 1, records: 1})
	if got := seqs(drain(t, r)); fmt.Sprint(got) != "[1]" {
		t.Fatalf("got %v, want [1]", got)
	}
}
