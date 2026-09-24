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

	"github.com/go-openapi/runtime"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations/auth"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/audit"
)

// The oracle for the gate is the state, not the status: a refused request
// must leave the handler uncalled, and an admitted one must leave an
// intent and a result sharing one event_id on disk.

type gateFixture struct {
	t       *testing.T
	dir     string
	w       *audit.Writer
	h       http.Handler
	reached int
	status  int
	body    []byte
	remote  string
	inside  func(r *http.Request)
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	// The writer insists on a 0700 directory; a fresh subdirectory gets that
	// mode from CreateDir, where the test harness's own directory does not.
	f := &gateFixture{t: t, dir: filepath.Join(t.TempDir(), "audit"), status: http.StatusOK, remote: "10.1.2.3:4444"}
	w, err := audit.New(audit.Config{Dir: f.dir, CreateDir: true, InstanceID: "gw-test"})
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	for deadline := time.Now().Add(5 * time.Second); !w.Running(); {
		if time.Now().After(deadline) {
			t.Fatal("audit writer did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.w = w
	SetAuditWriter(w)
	SetAuditRouteLookup("/netlox/v1", func(r *http.Request) (string, bool) {
		rel := strings.TrimPrefix(r.URL.Path, "/netlox/v1")
		switch {
		case strings.HasPrefix(rel, "/oauth/") && strings.HasSuffix(rel, "/callback"):
			return "/netlox/v1/oauth/{provider}/callback", true
		case strings.HasPrefix(rel, "/oauth/") && strings.HasSuffix(rel, "/token"):
			return "/netlox/v1/oauth/{provider}/token", true
		case strings.HasPrefix(rel, "/oauth/"):
			return "/netlox/v1/oauth/{provider}", true
		case strings.HasPrefix(rel, "/auth/users/"):
			return "/netlox/v1/auth/users/{id}", true
		case strings.HasPrefix(rel, "/log-archives/"):
			return "/netlox/v1/log-archives/{filename}", true
		case strings.HasPrefix(rel, "/config/ai/apikey/"):
			return "/netlox/v1/config/ai/apikey/{key_id}", true
		}
		return r.URL.Path, true
	})
	t.Cleanup(func() {
		SetAuditWriter(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Close(ctx)
	})
	f.h = AuditGateMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		f.reached++
		f.body, _ = io.ReadAll(r.Body)
		if f.inside != nil {
			f.inside(r)
		}
		rw.WriteHeader(f.status)
	}))
	return f
}

func (f *gateFixture) do(method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = f.remote
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// records returns every management record on disk, in write order. It
// closes the writer first: Close seals the active segment and waits for
// the compression worker, so the directory is stable while it is read.
// Nothing may be requested through the fixture afterwards.
func (f *gateFixture) records() []map[string]any {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.w.Close(ctx); err != nil {
		f.t.Fatal(err)
	}
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []map[string]any
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".jsonl") && !strings.HasSuffix(e.Name(), ".jsonl.gz") {
			continue
		}
		fh, err := os.Open(filepath.Join(f.dir, e.Name()))
		if err != nil {
			f.t.Fatal(err)
		}
		var rd io.Reader = fh
		if strings.HasSuffix(e.Name(), ".gz") {
			zr, err := gzip.NewReader(fh)
			if err != nil {
				f.t.Fatal(err)
			}
			defer zr.Close()
			rd = zr
		}
		sc := bufio.NewScanner(rd)
		sc.Buffer(make([]byte, 64*1024), 4<<20)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			if m["stream"] == "mgmt" {
				out = append(out, m)
			}
		}
		fh.Close()
	}
	return out
}

// auditPair is one gated request as it appears on disk.
type auditPair struct{ intent, result map[string]any }

// pairs groups the management records into intent/result pairs by
// event_id, in intent order. An intent is written durably before its
// handler runs, but the result is appended asynchronously, so on disk a
// result may follow the next request's intent; the pair, not the line
// position, is what a test across several requests reasons about.
func (f *gateFixture) pairs() []auditPair {
	f.t.Helper()
	idx := map[string]int{}
	var out []auditPair
	for _, r := range f.records() {
		id, _ := r["event_id"].(string)
		switch r["phase"] {
		case "intent":
			idx[id] = len(out)
			out = append(out, auditPair{intent: r})
		case "result":
			if i, ok := idx[id]; ok {
				out[i].result = r
				continue
			}
			idx[id] = len(out)
			out = append(out, auditPair{result: r})
		}
	}
	return out
}

func detailOf(m map[string]any) map[string]any {
	d, _ := m["detail"].(map[string]any)
	return d
}

func actorOf(m map[string]any) map[string]any {
	a, _ := m["actor"].(map[string]any)
	return a
}

func withAuthMode(t *testing.T, userService bool) {
	t.Helper()
	prev := opts.Opts.UserServiceEnable
	opts.Opts.UserServiceEnable = userService
	t.Cleanup(func() { opts.Opts.UserServiceEnable = prev })
}

func TestAuditGateRefusesWhenNoWriter(t *testing.T) {
	f := newGateFixture(t)
	SetAuditWriter(nil)
	rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"a":1}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	if f.reached != 0 {
		t.Fatal("handler ran behind a refused intent")
	}
	if !strings.Contains(rec.Body.String(), AuditRefusalReason) || !strings.Contains(rec.Body.String(), "audit") {
		t.Fatalf("body does not name the audit subsystem: %s", rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After on the refusal")
	}
	// Reads are never gated by a missing writer.
	if rec := f.do(http.MethodGet, "/netlox/v1/config/loadbalancer/all", ""); rec.Code != http.StatusOK || f.reached != 1 {
		t.Fatalf("GET refused: %d reached=%d", rec.Code, f.reached)
	}
}

func TestAuditGateRefusesWhenWriterDown(t *testing.T) {
	f := newGateFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.w.Close(ctx); err != nil {
		t.Fatal(err)
	}
	rec := f.do(http.MethodDelete, "/netlox/v1/config/loadbalancer/all", "")
	if rec.Code != http.StatusServiceUnavailable || f.reached != 0 {
		t.Fatalf("status %d reached=%d", rec.Code, f.reached)
	}
}

func TestAuditGateWritesIntentAndResultPair(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	f.inside = func(r *http.Request) { RecordAuditPrincipal(r, "alice|admin") }
	body := `{"serviceArguments":{"externalIP":"1.2.3.4"},"endpoints":[]}`
	rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer?x=secret", body, "Authorization", "Bearer tok")
	if rec.Code != http.StatusOK || f.reached != 1 {
		t.Fatalf("status %d reached=%d", rec.Code, f.reached)
	}
	if string(f.body) != body {
		t.Fatalf("handler saw body %q", f.body)
	}
	recs := f.records()
	if len(recs) != 2 {
		t.Fatalf("got %d mgmt records, want intent+result", len(recs))
	}
	intent, result := recs[0], recs[1]
	if intent["phase"] != "intent" || result["phase"] != "result" {
		t.Fatalf("phases %v / %v", intent["phase"], result["phase"])
	}
	if intent["event_id"] == "" || intent["event_id"] != result["event_id"] {
		t.Fatalf("event ids differ: %v / %v", intent["event_id"], result["event_id"])
	}
	if intent["event_type"] != "mgmt.config.mutate" || result["event_type"] != "mgmt.config.mutate" {
		t.Fatalf("event types %v / %v", intent["event_type"], result["event_type"])
	}
	d := detailOf(intent)
	if d["path"] != "/netlox/v1/config/loadbalancer" || d["method"] != "POST" || d["resource"] != "loadbalancer" || d["action"] != "create" || d["route_class"] != "generated" {
		t.Fatalf("intent detail %v", d)
	}
	if got := d["changed_fields"]; got == nil || len(got.([]any)) != 2 || got.([]any)[0] != "endpoints" || got.([]any)[1] != "serviceArguments" {
		t.Fatalf("changed_fields %v", got)
	}
	if a := actorOf(intent); a["provisional"] != true || a["auth"] != "none" || a["remote"] != "10.1.2.3:4444" || a["mechanism"] != "token" {
		t.Fatalf("intent actor %v", a)
	}
	if a := actorOf(result); a["user"] != "alice" || a["role"] != "admin" || a["auth"] != "session" || a["provisional"] != nil {
		t.Fatalf("result actor %v", a)
	}
	if o := result["outcome"].(map[string]any); o["status"] != float64(200) || o["ok"] != true || o["reason"] != "ok" {
		t.Fatalf("result outcome %v", o)
	}
	if _, ok := detailOf(result)["config_generation"]; !ok {
		t.Log("config_generation omitted at zero; the field is present once a mutation is counted")
	}
	for _, r := range recs {
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "1.2.3.4") {
			t.Fatalf("record carries a query or body value: %s", raw)
		}
	}
}

func TestAuditGateLoginCarriesClaimedNameNeverPassword(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	f.status = http.StatusUnauthorized
	rec := f.do(http.MethodPost, "/netlox/v1/auth/login", `{"username":"bob","password":"hunter2-canary"}`)
	if rec.Code != http.StatusUnauthorized || f.reached != 1 {
		t.Fatalf("status %d reached=%d", rec.Code, f.reached)
	}
	recs := f.records()
	if len(recs) != 2 {
		t.Fatalf("got %d records", len(recs))
	}
	intent, result := recs[0], recs[1]
	if intent["event_type"] != "mgmt.auth.login" || actorOf(intent)["username_claimed"] != "bob" || actorOf(intent)["mechanism"] != "password" {
		t.Fatalf("intent %v", intent)
	}
	if result["event_type"] != "sec.mgmt.authn_failed" || result["class"] != "security" || result["result_of"] != "mgmt.auth.login" {
		t.Fatalf("result %v", result)
	}
	if o := result["outcome"].(map[string]any); o["reason"] != "login_failed" {
		t.Fatalf("result reason %v", o["reason"])
	}
	if d := detailOf(intent); d["changed_fields"] != nil {
		t.Fatalf("login intent lists body fields: %v", d["changed_fields"])
	}
	for _, r := range recs {
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "hunter2") {
			t.Fatalf("password reached the record: %s", raw)
		}
	}
}

func TestAuditGateLoginSuccessCarriesTheActorTheHandlerSet(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	f.inside = func(r *http.Request) {
		RecordAuditActor(r, audit.Actor{Auth: audit.AuthSession, User: "bob", Role: "viewer"})
	}
	if rec := f.do(http.MethodPost, "/netlox/v1/auth/login", `{"username":"bob","password":"x"}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	recs := f.records()
	if a := actorOf(recs[1]); a["user"] != "bob" || a["role"] != "viewer" || a["remote"] != "10.1.2.3:4444" {
		t.Fatalf("result actor %v", a)
	}
}

func TestAuditGateAuthzDenialIsASecurityRecord(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	f.status = http.StatusForbidden
	f.inside = func(r *http.Request) { RecordAuditPrincipal(r, "carol|viewer") }
	if rec := f.do(http.MethodPost, "/netlox/v1/config/policy", `{"x":1}`, "Authorization", "Bearer t"); rec.Code != http.StatusForbidden {
		t.Fatal(rec.Code)
	}
	recs := f.records()
	result := recs[1]
	if result["event_type"] != "sec.mgmt.authz_denied" || result["class"] != "security" || result["result_of"] != "mgmt.config.mutate" {
		t.Fatalf("result %v", result)
	}
	if o := result["outcome"].(map[string]any); o["reason"] != "authz" {
		t.Fatalf("reason %v", o["reason"])
	}
	if detailOf(result)["role"] != "viewer" || actorOf(result)["role"] != "viewer" {
		t.Fatalf("role missing: %v", result)
	}
}

func TestAuditGateSideEffectingGETsAreGated(t *testing.T) {
	f := newGateFixture(t)
	if rec := f.do(http.MethodGet, "/netlox/v1/oauth/google", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if rec := f.do(http.MethodGet, "/netlox/v1/config/loadbalancer/all", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if rec := f.do(http.MethodOptions, "/netlox/v1/config/loadbalancer", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if rec := f.do(http.MethodHead, "/netlox/v1/config/loadbalancer", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	recs := f.records()
	if len(recs) != 2 {
		t.Fatalf("got %d records, want one pair for the OAuth start only", len(recs))
	}
	if recs[0]["event_type"] != "mgmt.auth.oauth_start" || detailOf(recs[0])["provider"] != "google" || detailOf(recs[0])["path"] != "/netlox/v1/oauth/{provider}" {
		t.Fatalf("intent %v", recs[0])
	}
}

func TestAuditGateExportReadsAreTwoPhase(t *testing.T) {
	f := newGateFixture(t)
	if rec := f.do(http.MethodGet, "/netlox/v1/log-archives/loxilb.log.gz", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if rec := f.do(http.MethodGet, "/netlox/v1/config/export", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	ps := f.pairs()
	if len(ps) != 2 || ps[0].result == nil || ps[1].result == nil {
		t.Fatalf("got %v, want two complete pairs", ps)
	}
	archive := ps[0].intent
	if archive["event_type"] != "read.log_archive.download" || archive["class"] != "read" || detailOf(archive)["filename"] != "loxilb.log.gz" || detailOf(archive)["resource"] != "log_archive:loxilb.log.gz" {
		t.Fatalf("archive intent %v", archive)
	}
	if ps[1].intent["event_type"] != "read.config.export" || ps[1].intent["class"] != "read" || ps[1].result["phase"] != "result" {
		t.Fatalf("export pair %v", ps[1])
	}
}

func TestAuditGateRawRoutesAreMarkedRaw(t *testing.T) {
	f := newGateFixture(t)
	if rec := f.do(http.MethodPatch, "/netlox/v1/config/ai/apikey/k-17", `{"rate_limit":1}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if rec := f.do(http.MethodPost, "/netlox/v1/config/opa/watcher", `{"url":"x"}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	ps := f.pairs()
	if len(ps) != 2 || ps[0].result == nil || ps[1].result == nil {
		t.Fatalf("got %v, want two complete pairs", ps)
	}
	if d := detailOf(ps[0].intent); d["raw"] != true || d["route_class"] != "raw" || d["path"] != "/netlox/v1/config/ai/apikey/{key_id}" || d["resource"] != "ai" {
		t.Fatalf("apikey intent %v", d)
	}
	if d := detailOf(ps[1].intent); d["raw"] != true || d["path"] != "/netlox/v1/config/opa/watcher" {
		t.Fatalf("opa intent %v", d)
	}
}

func TestAuditGateNamedRoutes(t *testing.T) {
	f := newGateFixture(t)
	cases := []struct{ method, path, event, resource string }{
		{http.MethodPut, "/netlox/v1/auth/users/42", "mgmt.user.update", "user:42"},
		{http.MethodDelete, "/netlox/v1/auth/users/42", "mgmt.user.delete", "user:42"},
		{http.MethodPost, "/netlox/v1/auth/users", "mgmt.user.create", "user"},
		{http.MethodPost, "/netlox/v1/auth/logout", "mgmt.auth.logout", "session"},
		{http.MethodPost, "/netlox/v1/auth/token/upgrade", "mgmt.auth.token_upgrade", "manual_token"},
		{http.MethodPut, "/netlox/v1/maintenance", "mgmt.maintenance", "maintenance"},
		{http.MethodPost, "/netlox/v1/config/persist", "mgmt.snapshot.persist", "snapshot"},
		{http.MethodPost, "/netlox/v1/config/restore", "mgmt.snapshot.restore", "snapshot"},
	}
	for _, c := range cases {
		if rec := f.do(c.method, c.path, ""); rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d", c.method, c.path, rec.Code)
		}
	}
	ps := f.pairs()
	if len(ps) != len(cases) {
		t.Fatalf("got %d pairs, want %d", len(ps), len(cases))
	}
	for i, c := range cases {
		in := ps[i].intent
		if in["event_type"] != c.event || detailOf(in)["resource"] != c.resource || ps[i].result == nil {
			t.Errorf("%s %s: got %v/%v, want %s/%s", c.method, c.path, in["event_type"], detailOf(in)["resource"], c.event, c.resource)
		}
	}
}

func TestAuditGateOversizedBodyPassesThroughUnread(t *testing.T) {
	f := newGateFixture(t)
	big := `{"k":"` + strings.Repeat("v", auditFieldBodyLimit) + `"}`
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", big); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if string(f.body) != big {
		t.Fatal("handler did not receive the whole body")
	}
	if d := detailOf(f.records()[0]); d["changed_fields"] != nil {
		t.Fatalf("fields recorded from an oversized body: %v", d["changed_fields"])
	}
}

func TestAuditGateResultLossIsCounted(t *testing.T) {
	f := newGateFixture(t)
	before := AuditResultDrops()
	f.inside = func(r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.w.Close(ctx)
	}
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"a":1}`); rec.Code != http.StatusOK {
		t.Fatalf("the response was held for a result the writer could not take: %d", rec.Code)
	}
	if AuditResultDrops() != before+1 {
		t.Fatalf("result loss not counted: %d -> %d", before, AuditResultDrops())
	}
}

func TestAuditGatedPredicate(t *testing.T) {
	for _, c := range []struct {
		method, template string
		gated            bool
		class            audit.Class
	}{
		{http.MethodPost, "/anything", true, ""},
		{http.MethodDelete, "/config/loadbalancer/all", true, ""},
		{http.MethodGet, "/config/loadbalancer/all", false, ""},
		{http.MethodGet, "/oauth/{provider}/token", true, ""},
		{http.MethodGet, "/config/snapshot", true, audit.ClassRead},
		{http.MethodHead, "/config/export", false, ""},
		{http.MethodOptions, "/config/loadbalancer", false, ""},
	} {
		gated, class := AuditGated(c.method, c.template)
		if gated != c.gated || class != c.class {
			t.Errorf("%s %s: got %v/%q, want %v/%q", c.method, c.template, gated, class, c.gated, c.class)
		}
	}
}

// loginStubHook answers the login hook with a fixed verdict so the real
// handler can be driven through the gate.
type loginStubHook struct {
	cmn.NetHookInterface
	valid bool
}

func (s *loginStubHook) NetUserLogin(um *cmn.User) (string, bool, error) {
	if !s.valid {
		return "", false, nil
	}
	return "issued-token-canary", true, nil
}

// The real login handler, behind the real gate: a rejected credential is a
// login_failed security result, an accepted one a result carrying the
// user the session was issued to, and neither the password nor the token
// reaches a record.
func TestAuditGateWithRealLoginHandler(t *testing.T) {
	withAuthMode(t, true)
	prev := ApiHooks
	t.Cleanup(func() { ApiHooks = prev })
	f := newGateFixture(t)
	username, password := "bob", "hunter2-canary"
	f.inside = func(r *http.Request) {
		resp := AuthPostLogin(auth.PostAuthLoginParams{
			HTTPRequest: r,
			User:        &models.User{Username: &username, Password: &password},
		})
		rec := httptest.NewRecorder()
		resp.WriteResponse(rec, runtime.JSONProducer())
		f.status = rec.Code
	}

	ApiHooks = &loginStubHook{valid: false}
	if rec := f.do(http.MethodPost, "/netlox/v1/auth/login", `{"username":"bob","password":"hunter2-canary"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("rejected login answered %d", rec.Code)
	}
	ApiHooks = &loginStubHook{valid: true}
	if rec := f.do(http.MethodPost, "/netlox/v1/auth/login", `{"username":"bob","password":"hunter2-canary"}`); rec.Code != http.StatusOK {
		t.Fatalf("accepted login answered %d", rec.Code)
	}

	ps := f.pairs()
	if len(ps) != 2 || ps[0].result == nil || ps[1].result == nil {
		t.Fatalf("got %v, want two complete pairs", ps)
	}
	failed, ok := ps[0].result, ps[1].result
	if failed["event_type"] != "sec.mgmt.authn_failed" || failed["outcome"].(map[string]any)["reason"] != "login_failed" {
		t.Fatalf("rejected login result %v", failed)
	}
	if a := actorOf(ok); a["user"] != "bob" || a["auth"] != "session" || a["provisional"] != nil {
		t.Fatalf("accepted login result actor %v", a)
	}
	if a := actorOf(ps[1].intent); a["username_claimed"] != "bob" || a["provisional"] != true {
		t.Fatalf("accepted login intent actor %v", a)
	}
	recs := []map[string]any{ps[0].intent, ps[0].result, ps[1].intent, ps[1].result}
	for _, r := range recs {
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "issued-token") {
			t.Fatalf("a secret reached a record: %s", raw)
		}
	}
}
