/*
 * Copyright (c) 2026 LoxiLB Authors
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
package snapshot

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PreRestoreKeep is how many pre-restore-<ts>.json safety snapshots
// PruneArtifacts retains (newest first). Each successful commit writes one
// (§5.3 PRESERVE), so without pruning they accumulate forever — the G-8
// fix for legacy defect #6 (temp backup files piling up with no cleanup).
const PreRestoreKeep = 5

// staleTempAge is how old an orphaned writeAtomic temp file (".<name>-*.tmp",
// left behind only if the process died mid-write) must be before
// PruneArtifacts removes it. The age guard keeps a concurrent in-flight
// write's temp file safe.
const staleTempAge = time.Hour

// PruneArtifacts removes surplus snapshot artifacts from dir: pre-restore
// safety snapshots beyond the newest `keep` (the "pre-restore-<ts>.json"
// timestamp format is name-sortable), and orphaned writeAtomic temp files
// older than an hour. Best-effort by design — it returns the paths it
// removed and skips (never fails on) entries it cannot stat or delete, so
// callers on the restore path can invoke it without risking the restore.
func PruneArtifacts(dir string, keep int, now time.Time) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var removed []string
	var preRestores []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, "pre-restore-") && strings.HasSuffix(name, ".json"):
			preRestores = append(preRestores, name)
		case strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp"):
			info, ierr := entry.Info()
			if ierr != nil || now.Sub(info.ModTime()) < staleTempAge {
				continue
			}
			path := filepath.Join(dir, name)
			if os.Remove(path) == nil {
				removed = append(removed, path)
			}
		}
	}

	if keep < 0 {
		keep = 0
	}
	if len(preRestores) > keep {
		sort.Strings(preRestores) // timestamped names sort oldest-first
		for _, name := range preRestores[:len(preRestores)-keep] {
			path := filepath.Join(dir, name)
			if os.Remove(path) == nil {
				removed = append(removed, path)
			}
		}
	}
	return removed
}
