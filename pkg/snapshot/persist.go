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
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PersistFileName is the basename of the write-through snapshot (§6):
// {ConfigPath}/snapshot.json.
const PersistFileName = "snapshot.json"

// writeAtomic writes data to dir/name via temp-file + rename, 0600,
// returning the final path. Shared by the PRESERVE stage (restore.go) and
// the §6 write-through persist.
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
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return "", fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", fmt.Errorf("rename temp file: %w", err)
	}
	return finalPath, nil
}

// Persist atomically writes doc's canonical encoding to dir/snapshot.json
// (§6 write-through target), returning the final path and the document
// checksum Encode computed (reported by POST /config/persist, task G-9).
func Persist(doc *Document, dir string) (string, string, error) {
	data, err := Encode(doc)
	if err != nil {
		return "", "", err
	}
	path, err := writeAtomic(dir, PersistFileName, data)
	if err != nil {
		return "", "", err
	}
	return path, doc.Checksum, nil
}

// WriteThrough captures the full live configuration and persists it to
// dir/snapshot.json (§6: on successful restore commit, on explicit
// POST /config/persist, on debounced auto-persist, and after a successful
// legacy-txt boot). The capture runs against the post-commit live state so
// server-assigned fields are recorded as they now exist.
func WriteThrough(hooks Hooks, gatewayVersion, hostname, dir string) (string, string, error) {
	doc, err := Capture(hooks, gatewayVersion, hostname, TriggerWriteThrough, nil)
	if err != nil {
		return "", "", err
	}
	return Persist(doc, dir)
}

// QuarantinePersisted renames dir/snapshot.json to
// snapshot.json.failed-<ts> after a failed boot restore. Two reasons: the
// failing document is preserved for diagnosis instead of being overwritten
// by the next write-through persist (which, after a rolled-back boot
// restore, would capture a state missing everything the snapshot carried
// and make the loss durable), and the next boot no longer retries a
// snapshot that is already known not to apply. Returns the quarantine path.
func QuarantinePersisted(dir string, now time.Time) (string, error) {
	src := filepath.Join(dir, PersistFileName)
	dst := filepath.Join(dir, fmt.Sprintf("%s.failed-%s", PersistFileName,
		now.UTC().Format("20060102-150405.000000000")))
	if err := os.Rename(src, dst); err != nil {
		return "", err
	}
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
