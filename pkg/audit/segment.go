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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/loxilb-io/loxilb/pkg/logrotate"
)

const (
	// ActiveSegmentName is the file the writer appends to. Sealed segments
	// are named audit-<UTC timestamp>.jsonl, then .jsonl.gz once compressed.
	// Neither matches the operational log family the debug-log API serves.
	ActiveSegmentName = "audit.jsonl"

	segmentPrefix = "audit-"
	segmentExt    = ".jsonl"
	gzipExt       = ".gz"

	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600

	kindHeader = "segment_header"
	kindFooter = "segment_footer"

	// maxLineBytes bounds a single line during recovery scanning.
	maxLineBytes = 4 << 20
)

// segmentHeader is the first line of every segment.
type segmentHeader struct {
	Kind            string `json:"kind"`
	SchemaVersion   int    `json:"schema_version"`
	SegmentUUID     string `json:"segment_uuid"`
	PrevSegmentUUID string `json:"prev_segment_uuid"`
	PrevSeal        string `json:"prev_seal"`
	InstanceID      string `json:"instance_id"`
	BootID          string `json:"boot_id"`
	OpenedTS        string `json:"opened_ts"`
	FirstSeq        uint64 `json:"first_seq"`
}

// segmentFooter is the last line of a sealed segment.
type segmentFooter struct {
	Kind               string `json:"kind"`
	SegmentUUID        string `json:"segment_uuid"`
	RecordCount        uint64 `json:"record_count"`
	FirstSeq           uint64 `json:"first_seq"`
	LastSeq            uint64 `json:"last_seq"`
	FirstTS            string `json:"first_ts"`
	LastTS             string `json:"last_ts"`
	SealedTS           string `json:"sealed_ts"`
	Recovered          bool   `json:"recovered"`
	TruncatedTailBytes int64  `json:"truncated_tail_bytes"`
}

// lineKind is the minimal decode used to classify a line during recovery.
type lineKind struct {
	Kind string `json:"kind"`
	Seq  uint64 `json:"seq"`
	TS   string `json:"ts"`
}

// SegmentInfo describes one sealed segment on disk.
type SegmentInfo struct {
	Name       string
	Path       string
	Bytes      int64
	SealedAt   time.Time
	Compressed bool
}

// recovery describes what was found at start in a segment the previous
// process never sealed.
type recovery struct {
	uuid          string
	records       uint64
	truncatedTail int64
	alreadySealed bool
}

type segStats struct {
	permRepaired    atomic.Uint64
	rotationFailed  atomic.Uint64
	compressFailed  atomic.Uint64
	compressSkipped atomic.Uint64
}

// segmenter owns the audit directory: the active segment, sealing and
// rotation, the single compression worker and the listing the retention
// policy works from.
type segmenter struct {
	dir        string
	active     string
	instanceID string
	bootID     string
	maxBytes   int64
	maxAge     time.Duration
	now        func() time.Time
	logf       func(string, ...any)
	fault      func(string) bool
	onAsync    func(*Record)

	f        *os.File
	size     int64
	uuid     string
	prevUUID string
	opened   time.Time
	count    uint64
	firstSeq uint64
	lastSeq  uint64
	firstTS  time.Time
	lastTS   time.Time

	compressQ    chan string
	compressDone chan struct{}

	// uuids caches sealed file name -> segment UUID. The compression
	// worker renames files, so it shares the cache with the writer.
	uuidMu sync.Mutex
	uuids  map[string]string
	// curUUID mirrors uuid for readers off the writer goroutine; the
	// three counters below mirror opened, count and size the same way.
	curUUID    atomic.Pointer[string]
	curOpened  atomic.Int64
	curRecords atomic.Uint64
	curBytes   atomic.Int64

	stats segStats
}

func (s *segmenter) cacheUUID(name, u string) {
	s.uuidMu.Lock()
	s.uuids[name] = u
	s.uuidMu.Unlock()
}

func (s *segmenter) cachedUUID(name string) (string, bool) {
	s.uuidMu.Lock()
	defer s.uuidMu.Unlock()
	u, ok := s.uuids[name]
	return u, ok
}

// currentUUID is the active segment's UUID, safe from any goroutine.
func (s *segmenter) currentUUID() string {
	if p := s.curUUID.Load(); p != nil {
		return *p
	}
	return ""
}

// checkDir validates the audit directory: it exists (created 0700 when
// create is set), is a directory, and is not readable by group or others.
func checkDir(dir string, create bool) error {
	st, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) && create {
		if err = os.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("audit: create dir %s: %w", dir, err)
		}
		// MkdirAll honours the umask; make the mode explicit.
		if err = os.Chmod(dir, dirMode); err != nil {
			return fmt.Errorf("audit: chmod dir %s: %w", dir, err)
		}
		st, err = os.Stat(dir)
	}
	if err != nil {
		return fmt.Errorf("audit: dir %s: %w", dir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("audit: %s is not a directory", dir)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("audit: dir %s mode %04o, want %04o", dir, perm, dirMode)
	}
	return nil
}

func newSegmenter(dir, instanceID, bootID string, maxBytes int64, maxAge time.Duration,
	now func() time.Time, logf func(string, ...any), fault func(string) bool) *segmenter {
	return &segmenter{
		dir:          dir,
		active:       filepath.Join(dir, ActiveSegmentName),
		instanceID:   instanceID,
		bootID:       bootID,
		maxBytes:     maxBytes,
		maxAge:       maxAge,
		now:          now,
		logf:         logf,
		fault:        fault,
		compressQ:    make(chan string, 16),
		compressDone: make(chan struct{}),
		uuids:        make(map[string]string),
	}
}

// start recovers an unsealed active segment left by a previous process,
// links the new segment to its predecessor and opens it. It returns the
// recovery report when there was something to recover.
func (s *segmenter) start(firstSeq uint64) (*recovery, error) {
	var rec *recovery
	if _, err := os.Stat(s.active); err == nil {
		r, err := s.recoverActive()
		if err != nil {
			return nil, err
		}
		rec = r
		s.prevUUID = r.uuid
	} else {
		s.prevUUID = s.latestSealedUUID()
	}
	go s.compressWorker()
	if err := s.openActive(firstSeq); err != nil {
		return rec, err
	}
	return rec, nil
}

// recoverActive closes a segment the previous process did not seal: it
// drops a torn final line, appends a footer marked recovered and moves
// the file to its sealed name.
func (s *segmenter) recoverActive() (*recovery, error) {
	f, err := os.OpenFile(s.active, os.O_RDWR, fileMode)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s for recovery: %w", s.active, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	rec := &recovery{}
	var (
		hdr      segmentHeader
		validEnd int64
		count    uint64
		first    lineKind
		last     lineKind
		gotFirst bool
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	lineNo := 0
	for sc.Scan() {
		line := sc.Bytes()
		// Scanner strips the newline; a final line without one is torn.
		end := validEnd + int64(len(line)) + 1
		if end > st.Size() {
			break
		}
		var lk lineKind
		if json.Unmarshal(line, &lk) != nil {
			break
		}
		lineNo++
		if lineNo == 1 && lk.Kind == kindHeader {
			_ = json.Unmarshal(line, &hdr)
		} else if lk.Kind == kindFooter {
			rec.alreadySealed = true
		} else if lk.Kind == "" {
			count++
			if !gotFirst {
				first, gotFirst = lk, true
			}
			last = lk
		}
		validEnd = end
	}
	rec.uuid = hdr.SegmentUUID
	if rec.uuid == "" {
		rec.uuid = newUUID()
	}
	rec.records = count
	rec.truncatedTail = st.Size() - validEnd
	if rec.truncatedTail > 0 {
		if err := f.Truncate(validEnd); err != nil {
			return nil, fmt.Errorf("audit: truncate torn tail of %s: %w", s.active, err)
		}
	}
	if !rec.alreadySealed {
		ft := segmentFooter{
			Kind: kindFooter, SegmentUUID: rec.uuid, RecordCount: count,
			FirstSeq: first.Seq, LastSeq: last.Seq, FirstTS: first.TS, LastTS: last.TS,
			SealedTS: formatTS(s.now()), Recovered: true, TruncatedTailBytes: rec.truncatedTail,
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return nil, err
		}
		if err := writeJSONLine(f, ft); err != nil {
			return nil, fmt.Errorf("audit: footer for recovered %s: %w", s.active, err)
		}
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	bak := s.sealedName()
	if err := os.Rename(s.active, bak); err != nil {
		return nil, fmt.Errorf("audit: seal recovered %s: %w", s.active, err)
	}
	s.cacheUUID(filepath.Base(bak), rec.uuid)
	s.enqueueCompress(bak)
	return rec, nil
}

// openActive creates the active segment 0600 and writes its header.
func (s *segmenter) openActive(firstSeq uint64) error {
	f, err := os.OpenFile(s.active, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, fileMode)
	if errors.Is(err, os.ErrExist) {
		// Something re-created the path between rename and open. Take it
		// over rather than lose records; the mode check below repairs it.
		f, err = os.OpenFile(s.active, os.O_WRONLY|os.O_APPEND, fileMode)
	}
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", s.active, err)
	}
	if err := s.verifyMode(f); err != nil {
		f.Close()
		return err
	}
	s.f = f
	s.uuid = newUUID()
	u := s.uuid
	s.curUUID.Store(&u)
	s.opened = s.now()
	s.size = 0
	s.count = 0
	s.curOpened.Store(s.opened.Unix())
	s.curRecords.Store(0)
	s.firstSeq = firstSeq
	s.lastSeq = 0
	s.firstTS = time.Time{}
	s.lastTS = time.Time{}
	hdr := segmentHeader{
		Kind: kindHeader, SchemaVersion: SchemaVersion, SegmentUUID: s.uuid,
		PrevSegmentUUID: s.prevUUID, InstanceID: s.instanceID, BootID: s.bootID,
		OpenedTS: formatTS(s.opened), FirstSeq: firstSeq,
	}
	n, err := writeJSONLineN(f, hdr)
	s.size += int64(n)
	s.curBytes.Store(s.size)
	if err != nil {
		return fmt.Errorf("audit: header for %s: %w", s.active, err)
	}
	return nil
}

// verifyMode re-checks the active file's permissions and repairs them.
// The umask or a foreign create can widen them; the file must stay 0600.
func (s *segmenter) verifyMode(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Mode().Perm() != fileMode {
		if err := f.Chmod(fileMode); err != nil {
			return fmt.Errorf("audit: chmod %s: %w", s.active, err)
		}
		s.stats.permRepaired.Add(1)
	}
	return nil
}

// needsRotate reports whether appending n more bytes should first seal the
// active segment. A segment with no records never rotates, so one record
// larger than the limit still lands.
func (s *segmenter) needsRotate(n int) bool {
	if s.f == nil || s.count == 0 {
		return false
	}
	if s.maxBytes > 0 && s.size+int64(n) > s.maxBytes {
		return true
	}
	if s.maxAge > 0 && s.now().Sub(s.opened) >= s.maxAge {
		return true
	}
	return false
}

// append writes one encoded record line to the active segment.
func (s *segmenter) append(line []byte, seq uint64, ts time.Time) error {
	if s.f == nil {
		// A previous rotation lost the handle; try to get one back.
		if err := s.openActive(seq); err != nil {
			return err
		}
	}
	if s.fault(FaultWriterWriteFailed) {
		return syscall.EIO
	}
	n, err := s.f.Write(line)
	s.size += int64(n)
	s.curBytes.Store(s.size)
	if err != nil {
		return err
	}
	if s.count == 0 {
		s.firstSeq = seq
		s.firstTS = ts
	}
	s.count++
	s.curRecords.Store(s.count)
	s.lastSeq = seq
	s.lastTS = ts
	return nil
}

// current describes the active segment for readers off the writer
// goroutine: when it was opened, how many records it holds and its size
// on disk including the header.
func (s *segmenter) current() (openedUnix int64, records uint64, bytes int64) {
	return s.curOpened.Load(), s.curRecords.Load(), s.curBytes.Load()
}

func (s *segmenter) sync() error {
	if s.f == nil {
		return os.ErrClosed
	}
	return s.f.Sync()
}

// seal closes the active segment under its sealed name. The rename happens
// first, while the handle is open, so a failed rename leaves an active
// segment with no footer that simply keeps receiving records; the footer
// is written through the handle after the rename. It returns the sealed
// segment's UUID and record count for the seal event.
func (s *segmenter) seal() (uuidSealed string, count uint64, err error) {
	if s.f == nil {
		return "", 0, os.ErrClosed
	}
	bak := s.sealedName()
	if s.fault(FaultSegmentRotateFailed) {
		err = syscall.EIO
	} else {
		err = os.Rename(s.active, bak)
	}
	if err != nil {
		s.stats.rotationFailed.Add(1)
		return s.uuid, s.count, fmt.Errorf("audit: rename %s: %w", s.active, err)
	}
	ft := segmentFooter{
		Kind: kindFooter, SegmentUUID: s.uuid, RecordCount: s.count,
		FirstSeq: s.firstSeq, LastSeq: s.lastSeq,
		FirstTS: formatTS(s.firstTS), LastTS: formatTS(s.lastTS),
		SealedTS: formatTS(s.now()),
	}
	if s.count == 0 {
		ft.FirstSeq, ft.FirstTS, ft.LastTS = 0, "", ""
	}
	werr := writeJSONLine(s.f, ft)
	serr := s.f.Sync()
	cerr := s.f.Close()
	uuidSealed, count = s.uuid, s.count
	s.cacheUUID(filepath.Base(bak), uuidSealed)
	s.prevUUID = uuidSealed
	s.f = nil
	if werr != nil {
		return uuidSealed, count, fmt.Errorf("audit: footer %s: %w", bak, werr)
	}
	if serr != nil {
		return uuidSealed, count, serr
	}
	if cerr != nil {
		return uuidSealed, count, cerr
	}
	s.enqueueCompress(bak)
	return uuidSealed, count, nil
}

// sealedName returns the name the active segment is sealed under. Names
// carry millisecond timestamps; two seals inside one millisecond must not
// collide, so the time is advanced until the name is free.
func (s *segmenter) sealedName() string {
	t := s.now()
	for {
		bak := logrotate.BackupName(s.active, t)
		if _, err := os.Stat(bak); errors.Is(err, os.ErrNotExist) {
			if _, err := os.Stat(bak + gzipExt); errors.Is(err, os.ErrNotExist) {
				return bak
			}
		}
		t = t.Add(time.Millisecond)
	}
}

// rotate seals the active segment and opens the next one.
func (s *segmenter) rotate(nextFirstSeq uint64) (sealed string, count uint64, err error) {
	sealed, count, err = s.seal()
	if err != nil && s.f != nil {
		// The rename failed; the old handle is still good.
		return sealed, count, err
	}
	if oerr := s.openActive(nextFirstSeq); oerr != nil && err == nil {
		err = oerr
	}
	return sealed, count, err
}

// close seals the active segment and stops the compression worker after
// it has drained.
func (s *segmenter) close() error {
	var err error
	if s.f != nil {
		_, _, err = s.seal()
		if s.f != nil {
			// Rename failed: close the handle; the file is recovered at
			// the next start.
			s.f.Close()
			s.f = nil
		}
	}
	close(s.compressQ)
	<-s.compressDone
	return err
}

func (s *segmenter) enqueueCompress(path string) {
	select {
	case s.compressQ <- path:
	default:
		// The worker is behind; the plain segment stays readable and
		// counts toward the quota at its uncompressed size.
		s.stats.compressSkipped.Add(1)
	}
}

// compressWorker is the single bounded compression worker.
func (s *segmenter) compressWorker() {
	defer close(s.compressDone)
	for p := range s.compressQ {
		var err error
		if s.fault(FaultSegmentGzipFailed) {
			err = syscall.EIO
		} else {
			err = logrotate.GzipFile(p, fileMode)
		}
		if err == nil {
			if u, ok := s.cachedUUID(filepath.Base(p)); ok {
				s.cacheUUID(filepath.Base(p)+gzipExt, u)
			}
			continue
		}
		s.stats.compressFailed.Add(1)
		s.logf("audit: compress %s: %v", p, err)
		if s.onAsync != nil {
			s.onAsync(sysRecord("sys.segment.compress_failed", "audit_segment:"+s.uuidOf(p), &SysDetail{
				ErrnoClass: errnoClass(err),
			}))
		}
	}
}

// listSealed returns the sealed segments oldest first.
func (s *segmenter) listSealed() ([]SegmentInfo, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []SegmentInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ts, gz, ok := parseSegmentName(name)
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, SegmentInfo{
			Name: name, Path: filepath.Join(s.dir, name), Bytes: info.Size(),
			SealedAt: ts, Compressed: gz,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// parseSegmentName recognises audit-<ts>.jsonl and audit-<ts>.jsonl.gz.
func parseSegmentName(name string) (ts time.Time, gz bool, ok bool) {
	if !strings.HasPrefix(name, segmentPrefix) {
		return ts, false, false
	}
	rest := strings.TrimPrefix(name, segmentPrefix)
	if strings.HasSuffix(rest, gzipExt) {
		gz = true
		rest = strings.TrimSuffix(rest, gzipExt)
	}
	if !strings.HasSuffix(rest, segmentExt) {
		return ts, false, false
	}
	rest = strings.TrimSuffix(rest, segmentExt)
	t, err := time.Parse("20060102-150405.000", rest)
	if err != nil {
		return ts, false, false
	}
	return t, gz, true
}

// uuidOf returns the segment UUID recorded in the header of a sealed
// segment file, reading and caching it on first use.
func (s *segmenter) uuidOf(path string) string {
	name := filepath.Base(path)
	if u, ok := s.cachedUUID(name); ok {
		return u
	}
	u := readHeaderUUID(path)
	if u != "" {
		s.cacheUUID(name, u)
	}
	return u
}

// latestSealedUUID finds the newest sealed segment's UUID so the first
// segment of a new boot links to it.
func (s *segmenter) latestSealedUUID() string {
	segs, err := s.listSealed()
	if err != nil || len(segs) == 0 {
		return ""
	}
	return s.uuidOf(segs[len(segs)-1].Path)
}

func readHeaderUUID(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, gzipExt) {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return ""
		}
		defer zr.Close()
		r = zr
	}
	br := bufio.NewReaderSize(r, 4096)
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return ""
	}
	var hdr segmentHeader
	if json.Unmarshal(bytes.TrimSpace(line), &hdr) != nil || hdr.Kind != kindHeader {
		return ""
	}
	return hdr.SegmentUUID
}

func writeJSONLine(w io.Writer, v any) error {
	_, err := writeJSONLineN(w, v)
	return err
}

func writeJSONLineN(w io.Writer, v any) (int, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	return w.Write(append(b, '\n'))
}

// newUUID returns a time-ordered UUID (version 7), falling back to a
// random one if the clock or entropy source refuses.
func newUUID() string {
	u, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return u.String()
}

// errnoClass folds an error into the small vocabulary the audit_system
// records use.
func errnoClass(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENOSPC:
			return "ENOSPC"
		case syscall.EIO:
			return "EIO"
		case syscall.EACCES, syscall.EPERM:
			return "EACCES"
		case syscall.EROFS:
			return "EROFS"
		}
	}
	if errors.Is(err, os.ErrClosed) {
		return "EBADF"
	}
	return "other"
}

// sysRecord builds an audit_system record with the system actor.
func sysRecord(eventType, resource string, d *SysDetail) *Record {
	if d == nil {
		d = &SysDetail{}
	}
	d.Resource = resource
	return &Record{
		Stream:    StreamSystem,
		EventType: eventType,
		Actor:     Actor{Auth: AuthNone, User: "system"},
		Outcome:   Outcome{OK: true, Reason: ReasonOK},
		Sys:       d,
	}
}
