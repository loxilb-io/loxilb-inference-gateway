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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	aiops "github.com/loxilb-io/loxilb/api/restapi/operations/ai"
	"github.com/loxilb-io/loxilb/api/restapi/operations/auth"
	"github.com/loxilb-io/loxilb/api/restapi/operations/users"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
)

// The emitters are exercised through the real handlers behind the real
// gate wherever a handler can run without the datapath or the network.
// The record on disk is the oracle; a secret handed to a handler must not
// appear in any record.

type emitStubHook struct {
	cmn.NetHookInterface
	users     []cmn.User
	bootstrap error
	principal interface{}
	keys      []cmn.ApiKeySummary
}

func (s *emitStubHook) NetUserBootstrap(u *cmn.User) (int, error) {
	if s.bootstrap != nil {
		return 0, s.bootstrap
	}
	return 1, nil
}

func (s *emitStubHook) NetUserAdd(u *cmn.User) (int, error) { return 2, nil }
func (s *emitStubHook) NetUserGet() ([]cmn.User, error)     { return s.users, nil }
func (s *emitStubHook) NetUserUpdate(u *cmn.User) error     { return nil }
func (s *emitStubHook) NetAiInFlightStreamsGet() int64      { return 0 }
func (s *emitStubHook) NetAPIKeyList(string) ([]cmn.ApiKeySummary, error) {
	return s.keys, nil
}

func (s *emitStubHook) NetUserValidate(token string) (interface{}, error) {
	if s.principal == nil {
		return nil, errors.New("invalid token")
	}
	return s.principal, nil
}

func (s *emitStubHook) NetAPIKeyGet(id string) (*cmn.ApiKeySummary, error) {
	for i := range s.keys {
		if s.keys[i].KeyID == id {
			return &s.keys[i], nil
		}
	}
	return nil, errors.New("not found")
}

func withEmitHook(t *testing.T, h *emitStubHook) {
	t.Helper()
	prev := ApiHooks
	ApiHooks = h
	t.Cleanup(func() { ApiHooks = prev })
}

// serve runs a generated responder and hands its status to the fixture's
// inner handler, so the gate sees what the real handler answered.
func (f *gateFixture) serve(resp middleware.Responder) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	resp.WriteResponse(rec, runtime.JSONProducer())
	f.status = rec.Code
	return rec
}

func outcomeOf(m map[string]any) map[string]any {
	o, _ := m["outcome"].(map[string]any)
	return o
}

func assertNoSecret(t *testing.T, recs []map[string]any, canaries ...string) {
	t.Helper()
	for _, r := range recs {
		raw, _ := json.Marshal(r)
		for _, c := range canaries {
			if strings.Contains(string(raw), c) {
				t.Fatalf("a secret reached a record: %s", raw)
			}
		}
	}
}

func TestAuditEmitUserCreateBootstrap(t *testing.T) {
	withAuthMode(t, true)
	hook := &emitStubHook{}
	withEmitHook(t, hook)
	f := newGateFixture(t)
	username, password, role := "root", "hunter2-canary", "admin"
	body := `{"username":"root","password":"hunter2-canary","role":"admin"}`
	f.inside = func(r *http.Request) {
		f.serve(UsersPostUsers(users.PostAuthUsersParams{
			HTTPRequest: r,
			User:        &models.User{Username: &username, Password: &password, Role: role},
		}))
	}

	f.remote = "127.0.0.1:5555"
	if rec := f.do(http.MethodPost, "/netlox/v1/auth/users", body); rec.Code != http.StatusOK {
		t.Fatalf("loopback bootstrap answered %d", rec.Code)
	}
	f.remote = "10.9.8.7:5555"
	if rec := f.do(http.MethodPost, "/netlox/v1/auth/users", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-loopback bootstrap answered %d", rec.Code)
	}
	hook.bootstrap = cmn.ErrBootstrapClosed
	f.remote = "127.0.0.1:5555"
	if rec := f.do(http.MethodPost, "/netlox/v1/auth/users", body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("closed bootstrap answered %d", rec.Code)
	}

	ps := f.pairs()
	if len(ps) != 3 || ps[0].result == nil || ps[1].result == nil || ps[2].result == nil {
		t.Fatalf("got %v, want three complete pairs", ps)
	}
	recs := []map[string]any{ps[0].intent, ps[0].result, ps[1].intent, ps[1].result, ps[2].intent, ps[2].result}
	accepted := ps[0].result
	if accepted["event_type"] != "mgmt.user.create" || outcomeOf(accepted)["reason"] != "ok" {
		t.Fatalf("accepted bootstrap result %v", accepted)
	}
	if a := actorOf(accepted); a["auth"] != "none" || a["bootstrap"] != true || a["user"] != nil || a["provisional"] != nil {
		t.Fatalf("accepted bootstrap actor %v", a)
	}
	if d := detailOf(accepted); d["username"] != "root" || d["role"] != "admin" || d["bootstrap"] != true || d["resource"] != "user" {
		t.Fatalf("accepted bootstrap detail %v", d)
	}
	for _, refused := range []map[string]any{ps[1].result, ps[2].result} {
		if refused["event_type"] != "sec.mgmt.authn_failed" || refused["result_of"] != "mgmt.user.create" || outcomeOf(refused)["reason"] != "auth" {
			t.Fatalf("refused bootstrap result %v", refused)
		}
		if a := actorOf(refused); a["bootstrap"] != true || a["auth"] != "none" {
			t.Fatalf("refused bootstrap actor %v", a)
		}
		if detailOf(refused)["bootstrap"] != true {
			t.Fatalf("refused bootstrap detail %v", detailOf(refused))
		}
	}
	assertNoSecret(t, recs, "hunter2")
}

func TestAuditEmitUserCreateWithCredential(t *testing.T) {
	withAuthMode(t, true)
	withEmitHook(t, &emitStubHook{principal: "alice|admin"})
	f := newGateFixture(t)
	username, password := "bob", "hunter2-canary"
	f.inside = func(r *http.Request) {
		f.serve(UsersPostUsers(users.PostAuthUsersParams{
			HTTPRequest: r,
			User:        &models.User{Username: &username, Password: &password, Role: "viewer"},
		}))
	}
	rec := f.do(http.MethodPost, "/netlox/v1/auth/users", `{"username":"bob","password":"hunter2-canary","role":"viewer"}`, "Authorization", "Bearer tok-canary")
	if rec.Code != http.StatusOK {
		t.Fatalf("create answered %d", rec.Code)
	}
	recs := f.records()
	if len(recs) != 2 {
		t.Fatalf("got %d records", len(recs))
	}
	result := recs[1]
	if a := actorOf(result); a["user"] != "alice" || a["role"] != "admin" || a["auth"] != "session" || a["bootstrap"] != nil {
		t.Fatalf("result actor %v", a)
	}
	if d := detailOf(result); d["username"] != "bob" || d["role"] != "viewer" || d["bootstrap"] != nil {
		t.Fatalf("result detail %v", d)
	}
	assertNoSecret(t, recs, "hunter2", "tok-canary")
}

func TestAuditEmitUserUpdateNamesTheAccount(t *testing.T) {
	withAuthMode(t, true)
	withEmitHook(t, &emitStubHook{users: []cmn.User{{ID: 7, Username: "bob", Role: "viewer"}}})
	f := newGateFixture(t)
	username, password := "bob", "hunter2-canary"
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		f.serve(UsersPutUsers(users.PutAuthUsersIDParams{
			HTTPRequest: r, ID: 7,
			User: &models.User{Username: &username, Password: &password},
		}, "alice|admin"))
	}
	if rec := f.do(http.MethodPut, "/netlox/v1/auth/users/7", `{"username":"bob","password":"hunter2-canary"}`); rec.Code != http.StatusOK {
		t.Fatalf("update answered %d", rec.Code)
	}
	recs := f.records()
	d := detailOf(recs[1])
	if recs[1]["event_type"] != "mgmt.user.update" || d["resource"] != "user:7" || d["username"] != "bob" {
		t.Fatalf("result %v", recs[1])
	}
	if got := d["changed_fields"]; got == nil || len(got.([]any)) != 2 || got.([]any)[0] != "password" || got.([]any)[1] != "username" {
		t.Fatalf("changed_fields %v", got)
	}
	if d["role_from"] != nil || d["role_to"] != nil {
		t.Fatalf("role fields present although no role was applied: %v", d)
	}
	assertNoSecret(t, recs, "hunter2")

	// The stored role is what a role change would be recorded against.
	if got := currentUserRole(7); got != "viewer" {
		t.Fatalf("currentUserRole(7) = %q", got)
	}
	if got := currentUserRole(8); got != "" {
		t.Fatalf("currentUserRole(8) = %q", got)
	}
}

func TestAuditEmitManualTokenFingerprint(t *testing.T) {
	withAuthMode(t, true)
	prevPath := opts.Opts.ManualTokenPath
	opts.Opts.ManualTokenPath = filepath.Join(t.TempDir(), "manual_token")
	t.Cleanup(func() { opts.Opts.ManualTokenPath = prevPath })
	f := newGateFixture(t)
	key := "license-canary-9f"
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		f.serve(AuthPostManualTokenUpdate(auth.PostAuthTokenUpgradeParams{
			HTTPRequest: r,
			Token:       &models.UpdateLicenseRequest{LicenseKey: &key},
		}, "alice|admin"))
	}
	if rec := f.do(http.MethodPost, "/netlox/v1/auth/token/upgrade", `{"license_key":"license-canary-9f"}`); rec.Code != http.StatusOK {
		t.Fatalf("upgrade answered %d", rec.Code)
	}
	if stored, err := os.ReadFile(opts.Opts.ManualTokenPath); err != nil || string(stored) != key {
		t.Fatalf("token file %q, %v", stored, err)
	}
	recs := f.records()
	d := detailOf(recs[1])
	if recs[1]["event_type"] != "mgmt.auth.token_upgrade" || d["resource"] != "manual_token" {
		t.Fatalf("result %v", recs[1])
	}
	if d["token_fingerprint_sha256"] != auditFingerprint(key) {
		t.Fatalf("fingerprint %v, want %s", d["token_fingerprint_sha256"], auditFingerprint(key))
	}
	assertNoSecret(t, recs, "license-canary")
}

func TestAuditEmitMaintenanceTransition(t *testing.T) {
	withAuthMode(t, true)
	withMaintenanceFixture(t, 0)
	f := newGateFixture(t)
	enabled := true
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		f.serve(ConfigPutMaintenance(operations.PutMaintenanceParams{
			HTTPRequest: r,
			Attr:        &models.MaintenanceRequest{Enabled: &enabled},
		}, "alice|admin"))
	}
	if rec := f.do(http.MethodPut, "/netlox/v1/maintenance", `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("enter answered %d", rec.Code)
	}
	if rec := f.do(http.MethodPut, "/netlox/v1/maintenance", `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("repeat enter answered %d", rec.Code)
	}
	enabled = false
	if rec := f.do(http.MethodPut, "/netlox/v1/maintenance", `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("leave answered %d", rec.Code)
	}
	ps := f.pairs()
	if len(ps) != 3 {
		t.Fatalf("got %d pairs, want three", len(ps))
	}
	for i, want := range [][2]string{{"active", "maintenance"}, {"maintenance", "maintenance"}, {"maintenance", "active"}} {
		if ps[i].result == nil {
			t.Fatalf("transition %d has no result", i)
		}
		d := detailOf(ps[i].result)
		if ps[i].result["event_type"] != "mgmt.maintenance" || d["active_from"] != want[0] || d["active_to"] != want[1] {
			t.Fatalf("transition %d: %v", i, d)
		}
	}
}

func TestAuditEmitOAuthStartFingerprint(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	var location string
	f.inside = func(r *http.Request) {
		rec := f.serve(AuthGetOauthProvider(auth.GetOauthProviderParams{HTTPRequest: r, Provider: "google"}))
		location = rec.Header().Get("Location")
	}
	if rec := f.do(http.MethodGet, "/netlox/v1/oauth/google", ""); rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("start answered %d", rec.Code)
	}
	u, err := url.Parse(location)
	if err != nil || u.Query().Get("state") == "" {
		t.Fatalf("redirect %q carries no state", location)
	}
	state := u.Query().Get("state")
	t.Cleanup(func() { ValidateStateToken(state) })
	recs := f.records()
	if len(recs) != 2 {
		t.Fatalf("got %d records", len(recs))
	}
	d := detailOf(recs[1])
	if recs[1]["event_type"] != "mgmt.auth.oauth_start" || d["provider"] != "google" || d["action"] != "start" {
		t.Fatalf("result %v", recs[1])
	}
	if d["state_token_fingerprint"] != auditFingerprint(state) {
		t.Fatalf("state fingerprint %v", d["state_token_fingerprint"])
	}
	assertNoSecret(t, recs, state)
}

func TestAuditEmitOAuthActionsNameTheStep(t *testing.T) {
	f := newGateFixture(t)
	for _, c := range []struct{ path, event, action string }{
		{"/netlox/v1/oauth/github", "mgmt.auth.oauth_start", "start"},
		{"/netlox/v1/oauth/github/callback", "mgmt.auth.oauth_callback", "login"},
		{"/netlox/v1/oauth/github/token", "mgmt.auth.oauth_token_refresh", "refresh"},
	} {
		if rec := f.do(http.MethodGet, c.path, ""); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", c.path, rec.Code)
		}
	}
	ps := f.pairs()
	if len(ps) != 3 {
		t.Fatalf("got %d pairs, want three", len(ps))
	}
	for i, c := range []struct{ event, action string }{
		{"mgmt.auth.oauth_start", "start"}, {"mgmt.auth.oauth_callback", "login"}, {"mgmt.auth.oauth_token_refresh", "refresh"},
	} {
		in := ps[i].intent
		if in["event_type"] != c.event || detailOf(in)["action"] != c.action || detailOf(in)["provider"] != "github" || ps[i].result == nil {
			t.Errorf("%s: got %v/%v", c.event, in["event_type"], detailOf(in)["action"])
		}
	}
}

func TestAuditEmitListReadIsResultOnly(t *testing.T) {
	withAuthMode(t, true)
	withEmitHook(t, &emitStubHook{
		users: []cmn.User{{ID: 1, Username: "alice", Role: "admin"}, {ID: 2, Username: "bob", Role: "viewer"}},
		keys:  []cmn.ApiKeySummary{{KeyID: "k-1", TenantID: "acme"}},
	})
	f := newGateFixture(t)
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		switch {
		case strings.HasSuffix(r.URL.Path, "/auth/users"):
			f.serve(UsersGetUsers(users.GetAuthUsersParams{HTTPRequest: r}, "alice|admin"))
		case strings.HasSuffix(r.URL.Path, "/k-1"):
			f.serve(ConfigGetAIApikeyByID(aiops.GetConfigAiApikeyKeyIDParams{HTTPRequest: r, KeyID: "k-1"}, "alice|admin"))
		default:
			f.serve(ConfigGetAIApikeys(aiops.GetConfigAiApikeyParams{HTTPRequest: r}, "alice|admin"))
		}
	}
	for _, p := range []string{"/netlox/v1/auth/users", "/netlox/v1/config/ai/apikey", "/netlox/v1/config/ai/apikey/k-1"} {
		if rec := f.do(http.MethodGet, p, ""); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
	recs := f.records()
	if len(recs) != 3 {
		t.Fatalf("got %d records, want one result per listing and no intent", len(recs))
	}
	for _, r := range recs {
		if r["phase"] != "result" || r["class"] != "read" || r["event_type"] != "read.credential.list" {
			t.Fatalf("listing record %v", r)
		}
		if a := actorOf(r); a["user"] != "alice" || a["provisional"] != nil {
			t.Fatalf("listing actor %v", a)
		}
	}
	if d := detailOf(recs[0]); d["resource"] != "user" || d["action"] != "list" || d["count"] != float64(2) {
		t.Fatalf("user listing detail %v", d)
	}
	if d := detailOf(recs[1]); d["resource"] != "apikey" || d["action"] != "list" || d["count"] != float64(1) || d["tenant"] != nil {
		t.Fatalf("key listing detail %v", d)
	}
	if d := detailOf(recs[2]); d["resource"] != "apikey:k-1" || d["action"] != "get" || d["count"] != float64(1) || d["tenant"] != "acme" || d["path"] != "/netlox/v1/config/ai/apikey/{key_id}" {
		t.Fatalf("key get detail %v", d)
	}
}

func TestAuditEmitListReadServedWithoutWriter(t *testing.T) {
	withAuthMode(t, true)
	withEmitHook(t, &emitStubHook{users: []cmn.User{{ID: 1, Username: "alice", Role: "admin"}}})
	f := newGateFixture(t)
	f.inside = func(r *http.Request) {
		f.serve(UsersGetUsers(users.GetAuthUsersParams{HTTPRequest: r}, "alice|admin"))
	}
	SetAuditWriter(nil)
	before := AuditResultDrops()
	if rec := f.do(http.MethodGet, "/netlox/v1/auth/users", ""); rec.Code != http.StatusOK || f.reached != 1 {
		t.Fatalf("listing without a writer answered %d reached=%d", rec.Code, f.reached)
	}
	if AuditResultDrops() != before+1 {
		t.Fatalf("listing loss not counted: %d -> %d", before, AuditResultDrops())
	}
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"a":1}`); rec.Code != http.StatusServiceUnavailable || f.reached != 1 {
		t.Fatalf("mutation without a writer answered %d reached=%d", rec.Code, f.reached)
	}
}

func TestAuditEmitArchiveDownloadBytes(t *testing.T) {
	withAuthMode(t, true)
	prev := archivePath
	archivePath = t.TempDir()
	t.Cleanup(func() { archivePath = prev })
	content := []byte("seventeen bytes!!")
	if err := os.WriteFile(filepath.Join(archivePath, "loxilb-2.log"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	f := newGateFixture(t)
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		f.serve(ConfigGetLogArchivesFilename(operations.GetLogArchivesFilenameParams{HTTPRequest: r, Filename: "loxilb-2.log"}, "alice|admin"))
	}
	if rec := f.do(http.MethodGet, "/netlox/v1/log-archives/loxilb-2.log", ""); rec.Code != http.StatusOK {
		t.Fatalf("download answered %d", rec.Code)
	}
	recs := f.records()
	if len(recs) != 2 {
		t.Fatalf("got %d records", len(recs))
	}
	d := detailOf(recs[1])
	if recs[1]["event_type"] != "read.log_archive.download" || recs[1]["class"] != "read" || d["bytes"] != float64(len(content)) || d["filename"] != "loxilb-2.log" || d["content_disposition"] != "loxilb-2.log" {
		t.Fatalf("download result %v", recs[1])
	}
}

func TestAuditEmitExportDetail(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	f.inside = func(r *http.Request) {
		RecordAuditPrincipal(r, "alice|admin")
		auditExportServed(r, &snapshot.Document{Checksum: "sha256:abc"}, []byte(`{"doc":1}`), "loxilb-config-x.json")
	}
	if rec := f.do(http.MethodGet, "/netlox/v1/config/export", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	recs := f.records()
	d := detailOf(recs[1])
	if d["bytes"] != float64(9) || d["checksum"] != "sha256:abc" || d["format"] != "json" || d["content_disposition"] != "loxilb-config-x.json" {
		t.Fatalf("export detail %v", d)
	}
	if v, ok := d["secrets_included"]; !ok || v != false {
		t.Fatalf("secrets_included must be stated false, got %v (present=%v)", v, ok)
	}
	if _, ok := detailOf(recs[0])["secrets_included"]; ok {
		t.Fatalf("intent claims a document was served: %v", detailOf(recs[0]))
	}
}

func TestAuditEmitRestorePhases(t *testing.T) {
	withAuthMode(t, true)
	f := newGateFixture(t)
	cases := []struct {
		mode    snapshot.RestoreMode
		result  *snapshot.Result
		phase   string
		applied float64
		failed  float64
	}{
		{snapshot.ModeDryRun, &snapshot.Result{Result: snapshot.ResultOK, Plan: []snapshot.PlanItem{{ToApply: 3}}}, "plan", 0, 0},
		{snapshot.ModeCommit, &snapshot.Result{Result: snapshot.ResultOK, Plan: []snapshot.PlanItem{{ToApply: 3}, {ToApply: 2}}}, "commit", 5, 0},
		{snapshot.ModeCommit, &snapshot.Result{Result: snapshot.ResultRolledBack, Errors: []string{"a", "b"}}, "rollback", 0, 2},
		{snapshot.ModeCommit, &snapshot.Result{Result: snapshot.ResultRollbackFailed, Errors: []string{"a"}}, "rollback_failed", 0, 1},
		{snapshot.ModeCommit, &snapshot.Result{Errors: []string{"bad document"}}, "rejected", 0, 1},
	}
	i := 0
	f.inside = func(r *http.Request) { auditRestoreEnded(r, cases[i].mode, cases[i].result) }
	for i = range cases {
		if rec := f.do(http.MethodPost, "/netlox/v1/config/restore", `{"schema_version":"1"}`); rec.Code != http.StatusOK {
			t.Fatal(rec.Code)
		}
	}
	ps := f.pairs()
	if len(ps) != len(cases) {
		t.Fatalf("got %d pairs, want %d", len(ps), len(cases))
	}
	for i, c := range cases {
		if d := detailOf(ps[i].intent); d["restore_phase"] != "begin" {
			t.Errorf("case %d intent phase %v", i, d["restore_phase"])
		}
		if ps[i].result == nil {
			t.Fatalf("case %d has no result", i)
		}
		d := detailOf(ps[i].result)
		if d["restore_phase"] != c.phase {
			t.Errorf("case %d result phase %v, want %s", i, d["restore_phase"], c.phase)
		}
		applied, _ := d["entries_applied"].(float64)
		failed, _ := d["entries_failed"].(float64)
		if applied != c.applied || failed != c.failed {
			t.Errorf("case %d applied/failed %v/%v, want %v/%v", i, applied, failed, c.applied, c.failed)
		}
	}
}

func TestAuditEmitServiceUnavailableIsAdmission(t *testing.T) {
	f := newGateFixture(t)
	f.status = http.StatusServiceUnavailable
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"a":1}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatal(rec.Code)
	}
	o := outcomeOf(f.records()[1])
	if o["reason"] != "admission" || o["ok"] != false || o["status"] != float64(503) {
		t.Fatalf("outcome %v", o)
	}
}

// With no authentication service configured the management API is open,
// and the record says so: the actor is none in both fields and not
// provisional, because there was never anything to establish.
func TestAuditEmitNoAuthModeActorIsNone(t *testing.T) {
	withAuthMode(t, false)
	prevOauth, prevManual := opts.Opts.Oauth2Enable, opts.Opts.ManualTokenEnable
	opts.Opts.Oauth2Enable, opts.Opts.ManualTokenEnable = false, false
	t.Cleanup(func() { opts.Opts.Oauth2Enable, opts.Opts.ManualTokenEnable = prevOauth, prevManual })
	f := newGateFixture(t)
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"a":1}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	recs := f.records()
	if a := actorOf(recs[0]); a["provisional"] != true || a["auth"] != "none" {
		t.Fatalf("intent actor %v", a)
	}
	if a := actorOf(recs[1]); a["auth"] != "none" || a["mechanism"] != "none" || a["provisional"] != nil || a["user"] != nil {
		t.Fatalf("result actor %v", a)
	}
}
