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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PersistFileName is the basename of the write-through snapshot (§6):
// {ConfigPath}/snapshot.json.
const PersistFileName = "snapshot.json"

// fileSync and dirSync are the durability syscalls behind writeAtomic and
// QuarantinePersisted, held in vars so unit tests can fail them
// deterministically; production code never overrides them.
var (
	fileSync = func(f *os.File) error { return f.Sync() }
	dirSync  = syncDir
)

// syncDir fsyncs the directory itself so a rename recorded in it survives
// a crash (a plain rename is only in the page cache until the directory
// inode is flushed).
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// writeAtomic writes data to dir/name via temp-file + fsync + rename +
// directory fsync, 0600, returning the final path. Shared by the PRESERVE
// stage (restore.go) and the §6 write-through persist.
//
// Crash-consistency claim (kept honest): at any interruption point a
// reader of dir/name observes either the previous complete file or the new
// complete file, never a torn mix; once writeAtomic returns nil the new
// content and the rename have both been fsynced, so they survive a crash
// or power loss to the extent the storage stack honors fsync (a volatile
// write cache that lies about flushes is outside what software can
// guarantee, and power-loss behavior is only tested where the testbed
// allows). A dir-fsync failure is returned as an error even though the
// rename is already visible in the namespace: durability is unconfirmed,
// so callers must treat the persist as failed rather than report success.
func writeAtomic(dir, name string, data []byte) (string, error) {
	finalPath := filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, "."+name+"-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if anything below fails; no-op after a
	// successful rename (the path no longer exists).
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write temp file: %w", err)
	}
	faultCrashPoint("persist-after-temp-write")
	// Flush file content to stable storage BEFORE the rename publishes it:
	// otherwise a crash after rename can leave a durable name pointing at
	// zero-length or partial content.
	if err := fileSync(tmp); err != nil {
		tmp.Close()
		return "", fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return "", fmt.Errorf("chmod temp file: %w", err)
	}
	faultCrashPoint("persist-before-rename")
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", fmt.Errorf("rename temp file: %w", err)
	}
	if err := dirSync(dir); err != nil {
		return "", fmt.Errorf("sync directory after rename: %w", err)
	}
	return finalPath, nil
}

// persistedGeneration loosely reads just the generation field out of one
// on-disk snapshot document. Corrupt or unreadable files report 0 -- a
// quarantined snapshot may be quarantined precisely because it is
// truncated, and the lineage scan must not fail on it.
func persistedGeneration(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var probe struct {
		Generation uint64 `json:"generation"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return 0
	}
	return probe.Generation
}

// nextGeneration returns the generation the next persisted snapshot in dir
// must carry: one past the highest generation the lineage has already
// spent, across the live snapshot.json AND the quarantined
// snapshot.json.failed-* files -- without the quarantines a post-quarantine
// persist would restart at 1 and make an older quarantined document look
// newer than the current state. Monotonicity is best-effort by design:
// callers serialize persists (the REST snapshotGate / the single-threaded
// boot), and if every lineage file is deleted the counter honestly
// restarts.
func nextGeneration(dir string) uint64 {
	highest := persistedGeneration(filepath.Join(dir, PersistFileName))
	quarantines, err := filepath.Glob(filepath.Join(dir, PersistFileName+".failed-*"))
	if err == nil {
		for _, q := range quarantines {
			if g := persistedGeneration(q); g > highest {
				highest = g
			}
		}
	}
	return highest + 1
}

// LineageGeneration reports the lineage generation carried by
// dir/snapshot.json: zero when the file is absent, unreadable, corrupt or
// predates generations (schema <1.5). The boot arbitration uses it --
// a positive generation proves the file was written by a gateway's
// persisted lineage rather than hand-dropped, so it outranks mtime
// comparisons against legacy artifacts.
func LineageGeneration(dir string) uint64 {
	return persistedGeneration(filepath.Join(dir, PersistFileName))
}

// Persist atomically writes doc's canonical encoding to dir/snapshot.json
// (§6 write-through target), returning the final path, the document
// checksum Encode computed, and the lineage generation stamped into the
// document (all reported by POST /config/persist, task G-9). Persist owns
// generation assignment: it stamps the next monotonic value BEFORE
// encoding, so the persisted bytes (and their checksum) carry the lineage
// position they claim.
func Persist(doc *Document, dir string) (string, string, uint64, error) {
	doc.Generation = nextGeneration(dir)
	data, err := Encode(doc)
	if err != nil {
		return "", "", 0, err
	}
	path, err := writeAtomic(dir, PersistFileName, data)
	if err != nil {
		return "", "", 0, err
	}
	recordPersistSuccess(doc.Generation, doc.Checksum, doc.Trigger)
	return path, doc.Checksum, doc.Generation, nil
}

// WriteThrough captures the full live configuration and persists it to
// dir/snapshot.json (§6: on successful restore commit, on explicit
// POST /config/persist, on debounced auto-persist, and after a successful
// legacy-txt boot). The capture runs against the post-commit live state so
// server-assigned fields are recorded as they now exist. Every caller
// holds the REST snapshotGate (or runs in the pre-API boot window), so the
// capture reads one frozen configuration point and the stamped generation
// labels exactly that point. The returned Document is the persisted one
// (generation and checksum stamped) -- the §9 response contract reports
// its metadata, so callers get the whole document rather than loose
// fields.
func WriteThrough(hooks Hooks, gatewayVersion, hostname, dir string) (string, *Document, error) {
	doc, err := Capture(hooks, gatewayVersion, hostname, TriggerWriteThrough, nil)
	if err != nil {
		return "", nil, err
	}
	path, _, _, err := Persist(doc, dir)
	if err != nil {
		return "", nil, err
	}
	return path, doc, nil
}

// QuarantinePersisted renames dir/snapshot.json to
// snapshot.json.failed-<ts> after a failed boot restore. Two reasons: the
// failing document is preserved for diagnosis instead of being overwritten
// by the next write-through persist (which, after a rolled-back boot
// restore, would capture a state missing everything the snapshot carried
// and make the loss durable), and the next boot no longer retries a
// snapshot that is already known not to apply. Returns the quarantine path.
// The rename is followed by a directory fsync for the same reason as
// writeAtomic: if the quarantine is not durable, a crash right after it
// resurrects snapshot.json and the next boot retries a snapshot already
// known not to apply.
func QuarantinePersisted(dir string, now time.Time) (string, error) {
	src := filepath.Join(dir, PersistFileName)
	dst := filepath.Join(dir, fmt.Sprintf("%s.failed-%s", PersistFileName,
		now.UTC().Format("20060102-150405.000000000")))
	if err := os.Rename(src, dst); err != nil {
		return "", err
	}
	if err := dirSync(dir); err != nil {
		return "", fmt.Errorf("sync directory after quarantine rename: %w", err)
	}
	snapshotQuarantineTotal.Inc()
	return dst, nil
}

// LoadPersisted reads dir/snapshot.json, returning (nil, nil) when the file
// does not exist (a fresh install / legacy-only node) and an error only for
// real I/O failures.
func LoadPersisted(dir string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(dir, PersistFileName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}
