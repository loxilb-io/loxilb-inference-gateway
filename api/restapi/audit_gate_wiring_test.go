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

package restapi

// audit_gate_wiring_test.go — the gate as registered, not as a unit. The
// raw dispatches in setupGlobalMiddleware run outside the generated chain,
// so the only thing that puts them behind the audit gate is the order of
// the wrappers in that function. These tests drive setupGlobalMiddleware
// itself: a raw route with no writer is refused before its handler runs,
// preflight is still answered ahead of the gate, and with a writer the raw
// route leaves an intent and a result marked raw.

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/api/restapi/handler"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/audit"
)

type wiringProbe struct {
	rawReached  int
	nextReached int
	h           http.Handler
}

func newWiringProbe(t *testing.T) *wiringProbe {
	t.Helper()
	p := &wiringProbe{}
	prevOPA := opaWatcherHandler
	opaWatcherHandler = func(w http.ResponseWriter, r *http.Request) {
		p.rawReached++
		w.WriteHeader(http.StatusOK)
	}
	prevAuth := opts.Opts.UserServiceEnable
	opts.Opts.UserServiceEnable = false
	t.Cleanup(func() {
		opaWatcherHandler = prevOPA
		opts.Opts.UserServiceEnable = prevAuth
		handler.SetAuditWriter(nil)
	})
	handler.SetAuditRouteLookup("/netlox/v1", nil)
	p.h = setupGlobalMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.nextReached++
		w.WriteHeader(http.StatusOK)
	}))
	return p
}

func (p *wiringProbe) do(method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(`{"url":"http://opa"}`))
	req.Header.Set("Origin", "http://ui.example")
	p.h.ServeHTTP(rec, req)
	return rec
}

func TestGlobalMiddlewareRefusesRawRouteWithoutAudit(t *testing.T) {
	p := newWiringProbe(t)
	handler.SetAuditWriter(nil)

	rec := p.do(http.MethodPost, "/netlox/v1/config/opa/watcher")
	if rec.Code != http.StatusServiceUnavailable || p.rawReached != 0 {
		t.Fatalf("raw route: status %d, handler reached %d times", rec.Code, p.rawReached)
	}
	if !strings.Contains(rec.Body.String(), handler.AuditRefusalReason) {
		t.Fatalf("refusal body does not name the audit gate: %s", rec.Body.String())
	}
	rec = p.do(http.MethodPost, "/netlox/v1/config/loadbalancer")
	if rec.Code != http.StatusServiceUnavailable || p.nextReached != 0 {
		t.Fatalf("generated chain: status %d, reached %d times", rec.Code, p.nextReached)
	}
	// Reads and preflight are not the gate's business.
	if rec = p.do(http.MethodGet, "/netlox/v1/config/opa/watcher"); rec.Code != http.StatusOK || p.rawReached != 1 {
		t.Fatalf("raw GET: status %d reached %d", rec.Code, p.rawReached)
	}
	if rec = p.do(http.MethodOptions, "/netlox/v1/config/opa/watcher"); rec.Code != http.StatusOK || p.rawReached != 1 {
		t.Fatalf("preflight: status %d reached %d", rec.Code, p.rawReached)
	}
}

func TestGlobalMiddlewareRecordsRawRouteAsRaw(t *testing.T) {
	p := newWiringProbe(t)
	dir := filepath.Join(t.TempDir(), "audit")
	w, err := audit.New(audit.Config{Dir: dir, CreateDir: true, InstanceID: "gw-test"})
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	for deadline := time.Now().Add(5 * time.Second); !w.Running(); {
		if time.Now().After(deadline) {
			t.Fatal("writer did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	handler.SetAuditWriter(w)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t.Cleanup(func() { _ = w.Close(ctx) })

	if rec := p.do(http.MethodPost, "/netlox/v1/config/opa/watcher"); rec.Code != http.StatusOK || p.rawReached != 1 {
		t.Fatalf("status %d reached %d", rec.Code, p.rawReached)
	}
	if err := w.SealNow(ctx); err != nil {
		t.Fatal(err)
	}
	var mgmt []map[string]any
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.Contains(e.Name(), ".jsonl") {
			continue
		}
		fh, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var rd io.Reader = fh
		if strings.HasSuffix(e.Name(), ".gz") {
			zr, err := gzip.NewReader(fh)
			if err != nil {
				t.Fatal(err)
			}
			rd = zr
		}
		sc := bufio.NewScanner(rd)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil && m["stream"] == "mgmt" {
				mgmt = append(mgmt, m)
			}
		}
		fh.Close()
	}
	if len(mgmt) != 2 {
		t.Fatalf("got %d mgmt records, want the pair", len(mgmt))
	}
	d, _ := mgmt[0]["detail"].(map[string]any)
	if d["raw"] != true || d["route_class"] != "raw" || d["path"] != "/netlox/v1/config/opa/watcher" || d["method"] != "POST" {
		t.Fatalf("intent detail %v", d)
	}
	if mgmt[1]["phase"] != "result" || mgmt[1]["event_id"] != mgmt[0]["event_id"] {
		t.Fatalf("result %v", mgmt[1])
	}
}
