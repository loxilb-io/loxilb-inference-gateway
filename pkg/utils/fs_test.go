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

package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FileExists answers true for a regular file and false for a directory or a
// missing path, the three cases the original implementation handled.
func TestFileExistsRegularDirectoryMissing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !FileExists(file) {
		t.Errorf("regular file %s: want true", file)
	}
	if FileExists(dir) {
		t.Errorf("directory %s: want false", dir)
	}
	if FileExists(filepath.Join(dir, "missing")) {
		t.Error("missing path: want false")
	}
}

// A regular file used as a path component makes stat fail with ENOTDIR,
// which is neither success nor "not found": FileExists answers false and
// does not dereference the nil FileInfo.
func TestFileExistsNotADirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(file, "ca.crt")
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("precondition: stat %s should fail", path)
	}
	for i := 0; i < 3; i++ { // repeated probes must not panic either
		if FileExists(path) {
			t.Errorf("probe %d of %s: want false", i, path)
		}
	}
}

// A path under a directory without search permission makes stat fail with
// EACCES: FileExists answers false and does not panic. Root bypasses the
// permission check, so the case is skipped there.
func TestFileExistsPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("EACCES cannot be provoked as root")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(locked, "ca.crt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if _, err := os.Stat(path); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("precondition: stat %s should fail with EACCES, got %v", path, err)
	}
	if FileExists(path) {
		t.Errorf("%s: want false", path)
	}
}

// A path component longer than NAME_MAX makes stat fail with ENAMETOOLONG;
// FileExists answers false and does not panic.
func TestFileExistsNameTooLong(t *testing.T) {
	path := filepath.Join(t.TempDir(), strings.Repeat("a", 300))
	if FileExists(path) {
		t.Errorf("%s: want false", path)
	}
}
