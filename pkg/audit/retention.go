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
	"time"
)

// Retention is the local-tier policy. It is age and byte quota and disk
// reserve, never a backup count: a count limit binds long before any age
// at production rates and says nothing about how many days are kept.
//
// Pruning is announced by an audit_system record before the delete and is
// bounded to MaxPrunePerPass segments per pass, so lowering the policy
// never deletes history at once; the ledger shrinks one segment per pass
// with each deletion on record. A held segment is never pruned.
type Retention struct {
	// MaxAge prunes a sealed segment older than this. Zero keeps by age
	// forever.
	MaxAge time.Duration
	// MaxBytes prunes oldest first while the sealed segments exceed this
	// total. Zero disables the quota.
	MaxBytes int64
	// ReserveBytes is the free-space floor on the audit filesystem. Below
	// it, pruning proceeds regardless of age and quota, the breach is
	// recorded, and durable management writes are refused so a full disk
	// never produces an unrecorded change. Zero disables the check.
	ReserveBytes int64
	// MaxPrunePerPass bounds deletions per pass. Zero means one.
	MaxPrunePerPass int
}

func (r Retention) withDefaults() Retention {
	if r.MaxPrunePerPass <= 0 {
		r.MaxPrunePerPass = 1
	}
	return r
}

// prunePass applies the retention policy once. It runs on the writer
// goroutine so the announcing records are ordered with everything else.
func (w *Writer) prunePass() {
	pol := *w.retention.Load()
	segs, err := w.seg.listSealed()
	if err != nil {
		w.logf("audit: list segments: %v", err)
		return
	}
	var total int64
	for _, s := range segs {
		total += s.Bytes
	}
	w.sealedBytes.Store(total)

	breached := false
	if pol.ReserveBytes > 0 {
		if free := diskFree(w.cfg.Dir); free >= 0 {
			breached = free < pol.ReserveBytes
			if breached && !w.reserveBreached.Load() {
				w.stats.reserveBreaches.Add(1)
				w.logf("audit: disk reserve breached: free %d < reserved %d", free, pol.ReserveBytes)
				w.writeSystem(sysRecord("sys.disk.reserve_breached", "audit_dir", &SysDetail{
					FreeBytes: free, ReservedBytes: pol.ReserveBytes,
				}))
			}
			w.reserveBreached.Store(breached)
		}
	}

	now := w.now()
	pruned := 0
	for _, s := range segs {
		if pruned >= pol.MaxPrunePerPass {
			break
		}
		age := now.Sub(s.SealedAt)
		over := breached ||
			(pol.MaxAge > 0 && age > pol.MaxAge) ||
			(pol.MaxBytes > 0 && total > pol.MaxBytes)
		if !over {
			continue
		}
		uuid := w.seg.uuidOf(s.Path)
		if w.isHeld(uuid) {
			continue
		}
		// Announce first, durably; only then delete.
		if err := w.writeSystemDurable(sysRecord("sys.segment.prune", "audit_segment:"+uuid, &SysDetail{
			AgeDays: int(age.Hours() / 24), Bytes: s.Bytes, Hold: false,
		})); err != nil {
			w.logf("audit: prune of %s not announced, kept: %v", s.Name, err)
			return
		}
		if err := removeFile(s.Path); err != nil {
			w.logf("audit: prune %s: %v", s.Name, err)
			continue
		}
		total -= s.Bytes
		pruned++
		w.stats.pruned.Add(1)
	}
	w.sealedBytes.Store(total)
}

// Hold marks a sealed segment as under legal hold: it is never pruned
// regardless of age, quota or reserve until released.
func (w *Writer) Hold(segmentUUID, holdID string) {
	w.holdMu.Lock()
	defer w.holdMu.Unlock()
	w.holds[segmentUUID] = holdID
}

// ReleaseHold lifts a hold.
func (w *Writer) ReleaseHold(segmentUUID string) {
	w.holdMu.Lock()
	defer w.holdMu.Unlock()
	delete(w.holds, segmentUUID)
}

func (w *Writer) isHeld(segmentUUID string) bool {
	if segmentUUID == "" {
		return false
	}
	w.holdMu.Lock()
	defer w.holdMu.Unlock()
	_, ok := w.holds[segmentUUID]
	return ok
}

// SetRetention replaces the policy. It takes effect from the next pass and
// is bounded by MaxPrunePerPass like any other pass.
func (w *Writer) SetRetention(r Retention) {
	r = r.withDefaults()
	w.retention.Store(&r)
}

// RetentionPolicy returns the policy in force.
func (w *Writer) RetentionPolicy() Retention {
	return *w.retention.Load()
}
