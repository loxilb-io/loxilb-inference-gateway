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
package handler

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/api/restapi/operations"
	"github.com/loxilb-io/loxilb/pkg/audit"
)

// auditFileNames returns the names a real writer gives its files: the
// active segment, a sealed segment and its compressed form. They come from
// the writer rather than from constants so a renamed family is caught.
func auditFileNames(t *testing.T) []string {
	t.Helper()
	f := newGateFixture(t)
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"name":"x"}`); rec.Code != http.StatusOK {
		t.Fatalf("mutation answered %d", rec.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.w.SealNow(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"name":"y"}`); rec.Code != http.StatusOK {
		t.Fatalf("mutation answered %d", rec.Code)
	}
	// records closes the writer, which seals the active segment and waits
	// for the compression worker, so the listing below is stable.
	f.records()
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{audit.ActiveSegmentName}
	for _, e := range entries {
		if e.Name() != audit.ActiveSegmentName {
			names = append(names, e.Name())
		}
	}
	var sealed, gz bool
	for _, n := range names {
		sealed = sealed || strings.HasSuffix(n, ".jsonl")
		gz = gz || strings.HasSuffix(n, ".jsonl.gz")
	}
	if !sealed || !gz {
		t.Fatalf("the writer left no sealed and compressed segment to test against: %v", names)
	}
	return names
}

// The debug-log API filters on the file name, so the audit trail is
// invisible to it only because of how its files are named. Every name the
// writer produces is put where the operational logs live, and none of the
// three surfaces — the archive listing, the download, the tail's file
// selection — may return it. The listing still serves the operational
// file next to them, so the check is of the filter, not of an empty
// directory.
func TestLogArchivesNeverServeAuditFiles(t *testing.T) {
	names := auditFileNames(t)
	dir := stageLogDirIn(t)
	writeSparseLogFile(t, dir, "loxilbhost1.log", 100, 50, "ERROR")
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(`{"kind":"segment_header"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, "/netlox/v1/log-archives", nil)
	res := ConfigGetLogArchives(operations.GetLogArchivesParams{HTTPRequest: req}, nil)
	ok, isOK := res.(*operations.GetLogArchivesOK)
	if !isOK {
		t.Fatalf("listing: expected 200, got %T", res)
	}
	listed := map[string]bool{}
	for _, a := range ok.Payload.Archives {
		listed[a] = true
	}
	if !listed["loxilbhost1.log"] {
		t.Fatalf("the operational log is not listed: %v", ok.Payload.Archives)
	}
	for _, n := range names {
		if listed[n] {
			t.Errorf("audit file %q listed by /log-archives", n)
		}
	}

	res = ConfigGetLogFiles(operations.GetLogArchivesParams{HTTPRequest: req}, nil)
	if ok, isOK := res.(*operations.GetLogArchivesOK); isOK {
		for _, a := range ok.Payload.Archives {
			for _, n := range names {
				if a == n {
					t.Errorf("audit file %q listed as an active log file", n)
				}
			}
		}
	}

	for _, n := range names {
		res := ConfigGetLogArchivesFilename(operations.GetLogArchivesFilenameParams{HTTPRequest: req, Filename: n}, nil)
		if _, refused := res.(*operations.GetLogsBadRequest); !refused {
			t.Errorf("download of audit file %q answered %T, want a refusal", n, res)
		}
		if _, err := resolveLogFile(n); !errors.Is(err, errInvalidLogFilename) {
			t.Errorf("tail of audit file %q resolved with %v, want a refusal", n, err)
		}
		// The guarantee itself: the family never wears the operational
		// prefix, whatever the suffix.
		if strings.HasPrefix(n, logFileKey) {
			t.Errorf("audit file %q carries the operational log prefix", n)
		}
	}
}
