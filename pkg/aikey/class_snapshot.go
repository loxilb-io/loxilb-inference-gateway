/*
 * Copyright (c) 2025 LoxiLB Authors
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

package aikey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	tk "github.com/loxilb-io/loxilb/internal/tk"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/pgstore"
)

// ClassSnapshot is everything the store says about objectives and classes,
// as of one read. Immutable once published: readers hold the pointer and
// never lock.
type ClassSnapshot struct {
	Objectives map[string]cmn.AIObjectiveEntry
	// Tenants and Keys hold only the rows that set a class field.
	Tenants map[string]cmn.AIClassPolicy
	Keys    map[string]cmn.AIClassPolicy
	// ReadAt is when the store answered with this content.
	ReadAt time.Time
	// Source is cmn.AIClassSourceStore or cmn.AIClassSourceLKG.
	Source string
	// Gen orders the snapshots of the store: the ticket its read took
	// before it asked anything. A snapshot is published only over one of a
	// lower Gen, so a read that started before a write never replaces the
	// read the write made. The file's snapshot is 0.
	Gen uint64

	// limits are the limit rows read with it, for the file only.
	limits *limitRows
}

// Configured reports whether the snapshot holds anything a request's class
// could depend on. With nothing configured no request is looked at.
func (c *ClassSnapshot) Configured() bool {
	return c != nil && (len(c.Objectives) > 0 || len(c.Tenants) > 0 || len(c.Keys) > 0)
}

// The last-known-good file: the content of the last snapshot the store
// answered with, kept beside the configuration snapshot so that a gateway
// that starts while the store is unreachable serves the classes it served
// before, not none.
const (
	// ClassLKGFileName is the file's name under the configuration directory.
	ClassLKGFileName = "aigw-lkg.json"
	// classLKGVersion is the file's format version: 2 added the limit rows.
	// A file of version 1 is read for its classes; one of any other version
	// is not read.
	classLKGVersion  = 2
	classLKGVersion1 = 1

	classRefreshEnv        = "LLB_AI_OBJECTIVE_REFRESH_SEC"
	classRefreshDefaultSec = 10
)

type classLKGFile struct {
	Version int `json:"version"`
	// SourceTimestamp is when the store answered with this content.
	SourceTimestamp time.Time                    `json:"source_timestamp"`
	Objectives      []cmn.AIObjectiveEntry       `json:"objectives"`
	Tenants         map[string]cmn.AIClassPolicy `json:"tenants"`
	Keys            map[string]cmn.AIClassPolicy `json:"keys"`
	// The limit rows (class_lkg_limits.go); version 2 on.
	TenantLimits      []lkgTenantLimit      `json:"tenant_limits"`
	TenantModelLimits []lkgTenantModelLimit `json:"tenant_model_limits"`
	RateLimitDefaults []lkgDefaults         `json:"rate_limit_defaults"`
}

// classState is the class side of a Service. Its own struct so the zero
// Service the tests build keeps working.
type classState struct {
	snap atomic.Pointer[ClassSnapshot]
	// dir is the configuration directory the file lives in; "" = no file.
	dir atomic.Pointer[string]
	// written is the content of the file as last written or read, without
	// its timestamp: an unchanged read does not rewrite the file.
	written atomic.Pointer[[]byte]
	// lkgTicks counts refresh intervals served from the file.
	lkgTicks atomic.Uint64
	// onChange is told after every published snapshot.
	onChange atomic.Pointer[func(*ClassSnapshot)]
	started  atomic.Bool
	// budgetClamped records that the refresh budget's clamp was logged, so
	// a misconfiguration is reported once rather than every interval.
	budgetClamped atomic.Bool
	// readGen hands each store read its ticket (ClassSnapshot.Gen).
	readGen atomic.Uint64
	// pubMu makes "newer than what is published" and the publication one
	// step, and keeps the change hook's calls in publication order.
	pubMu sync.Mutex
	// fileMu orders the writes of the file. It is not pubMu: a write waits
	// on the disk, and publishing must not.
	fileMu sync.Mutex
	// lkgLimits are the file's limit rows while the file is served: from
	// the start of a process the store has not answered for, until it
	// answers once.
	lkgLimits atomic.Pointer[lkgLimitSet]
	// health is what the latest read of the store said: whether it
	// answered, and when one last did.
	health storeHealth
}

// storeHealth is the outcome of the latest read of the store, by ticket: a
// slow read that fails after a later one answered does not mark the store
// away again.
type storeHealth struct {
	mu        sync.Mutex
	gen       uint64
	reachable bool
	lastOK    time.Time
}

// noteStoreRead records the outcome of the read with ticket gen, unless a
// later read's outcome is already recorded.
func (s *Service) noteStoreRead(gen uint64, err error) {
	h := &s.class.health
	h.mu.Lock()
	defer h.mu.Unlock()
	if gen < h.gen {
		return
	}
	h.gen = gen
	h.reachable = err == nil
	if err == nil {
		h.lastOK = time.Now().UTC()
	}
}

// StoreHealth reports whether the latest read of the store answered, and
// when a read last did in this process. A process started from the
// last-known-good file reports, until the store answers, the read that last
// changed the file: the file is written only on a change, so the store may
// have answered later. Zero when neither ever happened.
func (s *Service) StoreHealth() (reachable bool, lastOK time.Time) {
	if s == nil {
		return false, time.Time{}
	}
	h := &s.class.health
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reachable, h.lastOK
}

// Classes returns the snapshot in force, nil when nothing was ever read.
func (s *Service) Classes() *ClassSnapshot {
	if s == nil {
		return nil
	}
	return s.class.snap.Load()
}

// ClassSource reports where the class configuration in force came from, when
// the store answered with it, and how many refresh intervals have been
// served from the last-known-good file.
func (s *Service) ClassSource() (source string, readAt time.Time, lkgIntervals uint64) {
	snap := s.Classes()
	if snap == nil {
		return cmn.AIClassSourceNone, time.Time{}, 0
	}
	return snap.Source, snap.ReadAt, s.class.lkgTicks.Load()
}

// SetClassChangeHook installs a function called after every published
// snapshot, on the goroutine that published it.
func (s *Service) SetClassChangeHook(fn func(*ClassSnapshot)) {
	if fn == nil {
		s.class.onChange.Store(nil)
		return
	}
	s.class.onChange.Store(&fn)
}

// publishClasses publishes a snapshot of the store unless one of a newer
// read is already published, and reports whether it did. Once one is, the
// file's limit rows are no longer served.
func (s *Service) publishClasses(snap *ClassSnapshot) bool {
	s.class.pubMu.Lock()
	defer s.class.pubMu.Unlock()
	if cur := s.class.snap.Load(); cur != nil && cur.Source == cmn.AIClassSourceStore && cur.Gen >= snap.Gen {
		return false
	}
	s.class.snap.Store(snap)
	s.class.lkgLimits.Store(nil)
	if fn := s.class.onChange.Load(); fn != nil {
		(*fn)(snap)
	}
	return true
}

// RefreshClasses reads objectives and class rows from the store and
// publishes them. On any failure the snapshot in force stays.
//
// The read runs under the refresh budget, and under ctx: the four
// statements share one deadline, so a store that stalls while keeping its
// connections open fails the read inside the budget, the health is noted
// as not reachable, and the snapshot in force stays. Before the budget a
// stalled read held the refresher goroutine, and with it the health
// report, for as long as the stall lasted.
func (s *Service) RefreshClasses(ctx context.Context) error {
	// The ticket is taken before anything is asked: a read that starts
	// after a write committed has a higher one than any read that started
	// before it.
	gen := s.class.readGen.Add(1)
	err := s.refreshClasses(ctx, gen)
	s.noteStoreRead(gen, err)
	return err
}

func (s *Service) refreshClasses(ctx context.Context, gen uint64) error {
	db, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := pgstore.WithBudget(ctx, s.refreshBudget())
	defer cancel()
	objs, err := readObjectives(ctx, db)
	if err != nil {
		return fmt.Errorf("aikey: read objectives: %w", readErr(err))
	}
	tenants, err := readClassRows(ctx, db, sqlSelectTenantClasses)
	if err != nil {
		return fmt.Errorf("aikey: read tenant classes: %w", readErr(err))
	}
	keys, err := readClassRows(ctx, db, sqlSelectKeyClasses)
	if err != nil {
		return fmt.Errorf("aikey: read key classes: %w", readErr(err))
	}
	limits, err := readLimitRows(ctx, db)
	if err != nil {
		return fmt.Errorf("aikey: read limit rows: %w", readErr(err))
	}
	snap := &ClassSnapshot{Objectives: objs, Tenants: tenants, Keys: keys,
		ReadAt: time.Now().UTC(), Source: cmn.AIClassSourceStore, Gen: gen, limits: limits}
	prev := s.class.snap.Load()
	if !s.publishClasses(snap) {
		// A newer read is in force: this one is older than it, and is
		// neither published nor written.
		return nil
	}
	if prev != nil && prev.Source == cmn.AIClassSourceLKG {
		tk.LogIt(tk.LogInfo, "[AIKey] Objectives and classes read from the store again (%d objectives, %d tenants, %d keys); the last-known-good file is no longer served\n",
			len(objs), len(tenants), len(keys))
	}
	s.writeClassLKGIfCurrent(snap)
	return nil
}

// refreshClassesAfterWrite applies a local write at once. A failure is not
// the write's: the row is stored, and the next interval reads it.
//
// It takes its own budget rather than the write's context: the write has
// committed, and a client that hung up at that moment must not cancel the
// snapshot the next request on this node is decided with.
func (s *Service) refreshClassesAfterWrite() {
	if err := s.RefreshClasses(context.Background()); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Classes not refreshed after a write: %v\n", err)
	}
}

// refreshBudget is the refresh read's deadline: the configured budget, but
// never more than half the refresh interval, so one stalled read is over
// before the next tick starts and no two reads of the store overlap.
func (s *Service) refreshBudget() time.Duration {
	budget := pgstore.RefreshTimeout()
	if cap := ClassRefreshInterval() / 2; budget > cap {
		if s.class.budgetClamped.CompareAndSwap(false, true) {
			tk.LogIt(tk.LogWarning, "[AIKey] %s=%v exceeds half the refresh interval (%s): clamped to %v\n",
				pgstore.RefreshTimeoutEnv, budget, classRefreshEnv, cap)
		}
		budget = cap
	}
	return budget
}

func lkgContent(snap *ClassSnapshot) classLKGFile {
	f := classLKGFile{Version: classLKGVersion, Tenants: snap.Tenants, Keys: snap.Keys,
		Objectives: make([]cmn.AIObjectiveEntry, 0, len(snap.Objectives))}
	for _, o := range snap.Objectives {
		f.Objectives = append(f.Objectives, o)
	}
	// encoding/json sorts map keys; the list is sorted here, so equal
	// content is equal bytes.
	sortObjectives(f.Objectives)
	if f.Tenants == nil {
		f.Tenants = map[string]cmn.AIClassPolicy{}
	}
	if f.Keys == nil {
		f.Keys = map[string]cmn.AIClassPolicy{}
	}
	f.TenantLimits, f.TenantModelLimits, f.RateLimitDefaults =
		[]lkgTenantLimit{}, []lkgTenantModelLimit{}, []lkgDefaults{}
	if l := snap.limits; l != nil {
		f.TenantLimits = append(f.TenantLimits, l.Tenants...)
		f.TenantModelLimits = append(f.TenantModelLimits, l.TenantModels...)
		f.RateLimitDefaults = append(f.RateLimitDefaults, l.Defaults...)
	}
	return f
}

func sortObjectives(l []cmn.AIObjectiveEntry) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && l[j].Name < l[j-1].Name; j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

// writeClassLKGIfCurrent writes the file for snap when snap is still the
// snapshot in force: two refreshes publish in order but may reach the disk
// in the other order, and the older must not land last.
func (s *Service) writeClassLKGIfCurrent(snap *ClassSnapshot) {
	s.class.fileMu.Lock()
	defer s.class.fileMu.Unlock()
	if s.class.snap.Load() != snap {
		return
	}
	s.writeClassLKG(snap)
}

// writeClassLKG writes the file when the content differs from what it
// holds. A failure is logged and nothing else: the file is a convenience of
// the next start, never a condition of this one.
func (s *Service) writeClassLKG(snap *ClassSnapshot) {
	dirp := s.class.dir.Load()
	if dirp == nil || *dirp == "" {
		return
	}
	f := lkgContent(snap)
	body, err := json.Marshal(f)
	if err != nil {
		return
	}
	if last := s.class.written.Load(); last != nil && bytes.Equal(*last, body) {
		return
	}
	f.SourceTimestamp = snap.ReadAt
	data, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return
	}
	if err := writeFileAtomic(*dirp, ClassLKGFileName, append(data, '\n')); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Last-known-good file %s not written: %v\n",
			filepath.Join(*dirp, ClassLKGFileName), err)
		return
	}
	s.class.written.Store(&body)
}

// loadClassLKG publishes the file's content when nothing has been read yet,
// with its limit rows for the outage fallbacks. Reports whether it did.
func (s *Service) loadClassLKG() bool {
	s.class.pubMu.Lock()
	defer s.class.pubMu.Unlock()
	if s.class.snap.Load() != nil {
		return false
	}
	dirp := s.class.dir.Load()
	if dirp == nil || *dirp == "" {
		return false
	}
	path := filepath.Join(*dirp, ClassLKGFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			tk.LogIt(tk.LogError, "[AIKey] Last-known-good file %s not read: %v\n", path, err)
		}
		return false
	}
	var f classLKGFile
	if err := json.Unmarshal(data, &f); err != nil {
		tk.LogIt(tk.LogError, "[AIKey] Last-known-good file %s is not readable: %v\n", path, err)
		return false
	}
	if f.Version != classLKGVersion && f.Version != classLKGVersion1 {
		tk.LogIt(tk.LogError, "[AIKey] Last-known-good file %s has version %d, this gateway reads %d and %d: not used\n",
			path, f.Version, classLKGVersion1, classLKGVersion)
		return false
	}
	snap := &ClassSnapshot{Objectives: make(map[string]cmn.AIObjectiveEntry, len(f.Objectives)),
		Tenants: f.Tenants, Keys: f.Keys, ReadAt: f.SourceTimestamp, Source: cmn.AIClassSourceLKG}
	if f.Version >= classLKGVersion {
		snap.limits = &limitRows{Tenants: f.TenantLimits, TenantModels: f.TenantModelLimits,
			Defaults: f.RateLimitDefaults}
		snap.limits.sort()
	}
	for _, o := range f.Objectives {
		snap.Objectives[o.Name] = o
	}
	if snap.Tenants == nil {
		snap.Tenants = map[string]cmn.AIClassPolicy{}
	}
	if snap.Keys == nil {
		snap.Keys = map[string]cmn.AIClassPolicy{}
	}
	if snap.limits != nil {
		s.class.lkgLimits.Store(newLKGLimitSet(snap.limits))
	}
	s.class.health.mu.Lock()
	if s.class.health.lastOK.IsZero() {
		s.class.health.lastOK = f.SourceTimestamp
	}
	s.class.health.mu.Unlock()
	s.class.snap.Store(snap)
	if fn := s.class.onChange.Load(); fn != nil {
		(*fn)(snap)
	}
	// Only a file of the version this gateway writes is "already written":
	// an older one is rewritten at the first read, even of equal content.
	if f.Version == classLKGVersion {
		if body, err := json.Marshal(lkgContent(snap)); err == nil {
			s.class.written.Store(&body)
		}
	}
	nLimits := 0
	if snap.limits != nil {
		nLimits = len(snap.limits.Tenants) + len(snap.limits.TenantModels) + len(snap.limits.Defaults)
	}
	tk.LogIt(tk.LogWarning, "[AIKey] The key store has not answered: serving objectives, classes and limits from %s, as the store had them at %s (%d objectives, %d tenants, %d keys, %d limit rows); keyed requests are refused until it answers\n",
		path, f.SourceTimestamp.Format(time.RFC3339), len(snap.Objectives), len(snap.Tenants), len(snap.Keys), nLimits)
	return true
}

// AppliedObjectives lists the objectives of the snapshot in force, by name,
// with where it came from and when the store answered with it. ok is false
// when nothing was ever read.
func (s *Service) AppliedObjectives() (objs []cmn.AIObjectiveEntry, source string, at time.Time, ok bool) {
	snap := s.Classes()
	if snap == nil {
		return nil, cmn.AIClassSourceNone, time.Time{}, false
	}
	objs = make([]cmn.AIObjectiveEntry, 0, len(snap.Objectives))
	for _, o := range snap.Objectives {
		objs = append(objs, o)
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Name < objs[j].Name })
	return objs, snap.Source, snap.ReadAt, true
}

// classTick is one refresh interval.
func (s *Service) classTick() {
	if err := s.RefreshClasses(context.Background()); err != nil {
		s.loadClassLKG()
	}
	if snap := s.class.snap.Load(); snap != nil && snap.Source == cmn.AIClassSourceLKG {
		s.class.lkgTicks.Add(1)
	}
}

// ClassRefreshInterval is LLB_AI_OBJECTIVE_REFRESH_SEC: default 10 s, at
// least 1 s.
func ClassRefreshInterval() time.Duration {
	sec := classRefreshDefaultSec
	if v := os.Getenv(classRefreshEnv); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			sec = n
		}
	}
	if sec < 1 {
		sec = 1
	}
	return time.Duration(sec) * time.Second
}

// StartClassRefresher keeps the class snapshot current for the life of the
// process: one read at once, then one every ClassRefreshInterval. dir is
// the configuration directory for the last-known-good file ("" = no file).
// A second call does nothing.
func (s *Service) StartClassRefresher(dir string) {
	if s == nil || !s.class.started.CompareAndSwap(false, true) {
		return
	}
	s.class.dir.Store(&dir)
	go func() {
		t := time.NewTicker(ClassRefreshInterval())
		defer t.Stop()
		for {
			s.classTick()
			<-t.C
		}
	}()
}

// writeFileAtomic writes dir/name through a temporary file, fsync, rename
// and a directory fsync, mode 0600: a reader sees the previous complete file
// or the new one.
func writeFileAtomic(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
