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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/pkg/audit"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
)

// The management audit gate is the two-phase middleware that makes a
// configuration change impossible without a record of it.
//
// Ahead of the handler it builds a mgmt record with phase=intent from the
// request alone and writes it durably; if that write fails or times out
// the request is answered 503 and the handler is never called, so the
// authoritative state is unchanged. After the handler returns it appends
// phase=result with the status and the actor the handler established. The
// two share one event_id. An intent with no result is the signature of a
// crash between the phases and is reported at the next start rather than
// hidden.
//
// The gate runs before authentication: the intent carries the view the
// request presents (peer address, the mechanism offered, the claimed login
// name) and is labelled provisional; the result carries the authoritative
// actor, which the generated chain's authorizer and the raw routes'
// RequireManagementAuth hand to the gate through the request context.
//
// Scope is every request whose method is not GET, HEAD or OPTIONS, on every
// path, plus the named GET routes that create or replace state, plus the
// export-class reads. There is no exclusion list. The listing-class reads
// of credential metadata are the one lighter contract: they are served
// whatever the writer's state and leave a single result record behind
// them, with a loss counted rather than refused.

const (
	// auditIntentTimeout bounds how long a gated request waits for its
	// intent to become durable before it is refused.
	auditIntentTimeout = 2 * time.Second
	// auditLoginBodyLimit bounds the buffered copy of a login body from
	// which the claimed username is read.
	auditLoginBodyLimit = 4096
	// auditFieldBodyLimit bounds the body a gated request may carry for
	// its top-level field names to be recorded. A larger body passes
	// through unread and the record carries no field names.
	auditFieldBodyLimit = 64 << 10

	auditRouteGenerated = "generated"
	auditRouteRaw       = "raw"
)

// AuditRefusalReason is the token the 503 body carries so a client and a
// test can tell the audit gate's refusal from any other 503.
const AuditRefusalReason = string(audit.ReasonAuditUnavailable)

var (
	auditWriter      atomic.Pointer[audit.Writer]
	auditResultDrops atomic.Uint64
	auditRoutes      atomic.Pointer[auditRouteLookup]

	auditOriginatorDropped atomic.Uint64
	auditDelegationLookups atomic.Uint64
)

// The originator header lets a caller that acts for someone else — the
// MCP bridge for its client, a CLI run under a service account — name
// that someone. The name is recorded verbatim as actor.delegated and is
// never the actor: whether it is trusted is a separate flag decided by
// the authenticated account's own delegation permission, so a caller
// cannot launder an identity through the header. The value is a closed
// scheme followed by an identifier; anything else is dropped and counted.
const (
	AuditOriginatorHeader   = "X-Loxilb-Originator"
	auditOriginatorMaxBytes = 256
)

var auditOriginatorSchemes = []string{"mcp:", "mcp-stdio:", "cli:"}

// AuditOriginatorDropped counts originator headers that did not parse.
func AuditOriginatorDropped() uint64 { return auditOriginatorDropped.Load() }

// AuditDelegationLookups counts the account lookups made to decide
// whether an originator is trusted; a request without the header makes
// none.
func AuditDelegationLookups() uint64 { return auditDelegationLookups.Load() }

// auditOriginatorOf reads the header once and validates it: bounded,
// printable ASCII, a known scheme with a non-empty identifier. A header
// that fails is dropped and counted, never stored in part.
func auditOriginatorOf(r *http.Request) string {
	v := r.Header.Get(AuditOriginatorHeader)
	if v == "" {
		return ""
	}
	if auditOriginatorValid(v) {
		return v
	}
	auditOriginatorDropped.Add(1)
	return ""
}

func auditOriginatorValid(v string) bool {
	if len(v) > auditOriginatorMaxBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	for _, scheme := range auditOriginatorSchemes {
		if strings.HasPrefix(v, scheme) {
			return len(v) > len(scheme)
		}
	}
	return false
}

type auditRouteLookup struct {
	basePath string
	lookup   func(*http.Request) (string, bool)
}

// SetAuditWriter installs the writer the gate records through. A nil
// writer means every gated request is refused: a gateway that cannot
// audit does not change configuration.
//
// The same writer is published package-wide in pkg/audit so the datapath
// bridge can reach it without importing this package. The two handles are
// set and cleared together so a caller can never find one alive and the
// other empty.
func SetAuditWriter(w *audit.Writer) {
	auditWriter.Store(w)
	audit.SetGlobal(w)
}

// AuditWriter returns the installed writer, or nil.
func AuditWriter() *audit.Writer { return auditWriter.Load() }

// CloseAuditWriter stops the installed writer, draining what is queued.
func CloseAuditWriter(ctx context.Context) error {
	w := auditWriter.Swap(nil)
	audit.SetGlobal(nil)
	if w == nil {
		return nil
	}
	return w.Close(ctx)
}

// SetAuditRouteLookup hands the gate the served base path and a resolver
// from a request to the route template it will be dispatched to, so a
// record stores the template and never the URL as received.
func SetAuditRouteLookup(basePath string, lookup func(*http.Request) (string, bool)) {
	auditRoutes.Store(&auditRouteLookup{basePath: basePath, lookup: lookup})
}

// AuditResultDrops counts result records the writer could not accept.
// The mutation has happened by then, so the response is not held for the
// record, but the loss is counted and alarmed.
func AuditResultDrops() uint64 { return auditResultDrops.Load() }

// auditGETAllowlist is the named table of GET routes that create or
// replace state. A GET handler that calls a state-writing hook must be
// listed here; the route enumeration test enforces it. The action names
// the step of the OAuth flow the route performs.
var auditGETAllowlist = map[string]struct{ event, action string }{
	"/oauth/{provider}":          {"mgmt.auth.oauth_start", "start"},
	"/oauth/{provider}/callback": {"mgmt.auth.oauth_callback", "login"},
	"/oauth/{provider}/token":    {"mgmt.auth.oauth_token_refresh", "refresh"},
}

// auditListReads are the reads that list credential or account metadata:
// served whatever the writer's state, recorded as one result-only record
// after the handler. A GET handler that reaches a listing hook must be
// listed here; the route enumeration test enforces it.
var auditListReads = map[string]struct{ event, resource string }{
	"/auth/users":                {"read.credential.list", "user"},
	"/config/ai/apikey":          {"read.credential.list", "apikey"},
	"/config/ai/apikey/{key_id}": {"read.credential.list", "apikey"},
}

// auditExportReads are the reads that serve the configuration or an
// archive: two-phase like a mutation, with "nothing served" as the
// negative oracle.
var auditExportReads = map[string]string{
	"/config/export":           "read.config.export",
	"/config/snapshot":         "read.config.export",
	"/log-archives/{filename}": "read.log_archive.download",
}

// auditRawRoutes are the routes setupGlobalMiddleware dispatches itself,
// ahead of the generated chain. The enumeration test keeps this table
// equal to the dispatch sites.
var auditRawRoutes = map[string]bool{
	"/config/opa/watcher":        true,
	"/config/dpu/hwcounters":     true,
	"/config/dpu/debug":          true,
	"/config/ai/kv/inventory":    true,
	"/config/ai/apikey/{key_id}": true,
}

// auditNamedMutations gives the routes with their own contract their own
// event type and resource. Everything else is mgmt.config.mutate.
var auditNamedMutations = map[string]struct{ event, resource string }{
	"POST /auth/login":         {"mgmt.auth.login", "session"},
	"POST /auth/logout":        {"mgmt.auth.logout", "session"},
	"POST /auth/token/upgrade": {"mgmt.auth.token_upgrade", "manual_token"},
	"POST /auth/users":         {"mgmt.user.create", "user"},
	"PUT /auth/users/{id}":     {"mgmt.user.update", "user"},
	"DELETE /auth/users/{id}":  {"mgmt.user.delete", "user"},
	"PUT /maintenance":         {"mgmt.maintenance", "maintenance"},
	"POST /config/persist":     {"mgmt.snapshot.persist", "snapshot"},
	"POST /config/restore":     {"mgmt.snapshot.restore", "snapshot"},
}

// AuditGETAllowlist lists the side-effecting GET templates the gate covers.
func AuditGETAllowlist() []string { return auditSortedKeys(auditGETAllowlist) }

// AuditExportReads lists the export-class read templates the gate covers.
func AuditExportReads() []string { return auditSortedKeys(auditExportReads) }

// AuditListReads lists the listing-class read templates the gate covers.
func AuditListReads() []string { return auditSortedKeys(auditListReads) }

// AuditRawRoutes lists the raw-dispatched templates the gate knows.
func AuditRawRoutes() []string { return auditSortedKeys(auditRawRoutes) }

func auditSortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AuditGated reports whether a request for the route template (without
// the base path) is gated, and with which class. It is the predicate the
// enumeration test checks every declared operation against.
func AuditGated(method, template string) (gated bool, class audit.Class) {
	switch method {
	case http.MethodGet:
		if _, ok := auditGETAllowlist[template]; ok {
			return true, ""
		}
		if _, ok := auditExportReads[template]; ok {
			return true, audit.ClassRead
		}
		if _, ok := auditListReads[template]; ok {
			return true, audit.ClassRead
		}
		return false, ""
	case http.MethodHead, http.MethodOptions:
		return false, ""
	}
	return true, ""
}

// auditRoute is what the gate decided about one request.
type auditRoute struct {
	template  string // route template without the base path
	path      string // template with the base path, as stored
	event     string
	class     audit.Class
	resource  string
	action    string
	raw       bool
	provider  string
	filename  string
	login     bool
	list      bool // listing-class read: one result record, never refused
	mechanism string
}

// auditRawTemplate mirrors the dispatch conditions of setupGlobalMiddleware.
func auditRawTemplate(method, rel string) (string, bool) {
	switch rel {
	case "/config/opa/watcher", "/config/dpu/hwcounters", "/config/dpu/debug", "/config/ai/kv/inventory":
		return rel, true
	}
	if method == http.MethodPatch && strings.HasPrefix(rel, "/config/ai/apikey/") {
		return "/config/ai/apikey/{key_id}", true
	}
	return "", false
}

func auditRouteFor(r *http.Request) (auditRoute, bool) {
	rt := auditRoutes.Load()
	base := ""
	if rt != nil {
		base = strings.TrimSuffix(rt.basePath, "/")
	}
	rel := r.URL.Path
	if base != "" && strings.HasPrefix(rel, base+"/") {
		rel = strings.TrimPrefix(rel, base)
	}
	route := auditRoute{template: rel}
	if t, ok := auditRawTemplate(r.Method, rel); ok {
		route.template, route.raw = t, true
	} else if rt != nil && rt.lookup != nil {
		if t, ok := rt.lookup(r); ok {
			route.template = strings.TrimPrefix(t, base)
		}
	}
	gated, class := AuditGated(r.Method, route.template)
	if !gated {
		return route, false
	}
	route.class = class
	route.path = base + route.template
	params := auditPathParams(route.template, rel)
	switch {
	case r.Method == http.MethodGet && class == audit.ClassRead:
		if listed, ok := auditListReads[route.template]; ok {
			route.list = true
			route.event, route.resource = listed.event, listed.resource
			route.action = "list"
			if id := params["key_id"]; id != "" {
				route.resource += ":" + id
				route.action = "get"
			}
			break
		}
		route.event = auditExportReads[route.template]
		route.resource = "config"
		route.action = "export"
		if fn := params["filename"]; fn != "" {
			route.filename = fn
			route.resource = "log_archive:" + fn
			route.action = "download"
		}
	case r.Method == http.MethodGet:
		named := auditGETAllowlist[route.template]
		route.event = named.event
		route.action = named.action
		route.resource = "session"
		route.provider = params["provider"]
	default:
		if named, ok := auditNamedMutations[r.Method+" "+route.template]; ok {
			route.event, route.resource = named.event, named.resource
			if id := params["id"]; id != "" {
				route.resource += ":" + id
			}
			route.login = route.event == "mgmt.auth.login"
		} else {
			route.event = "mgmt.config.mutate"
			route.resource = auditResourceOf(route.template)
		}
		route.action = auditActionOf(r.Method)
	}
	switch {
	case route.login:
		route.mechanism = "password"
	case r.Header.Get("Authorization") != "":
		route.mechanism = "token"
	default:
		route.mechanism = "none"
	}
	return route, true
}

// auditPathParams pairs the template's {name} segments with the request
// path's segments.
func auditPathParams(template, path string) map[string]string {
	ts := strings.Split(template, "/")
	ps := strings.Split(path, "/")
	out := map[string]string{}
	if len(ts) != len(ps) {
		return out
	}
	for i, t := range ts {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			out[t[1:len(t)-1]] = ps[i]
		}
	}
	return out
}

// auditResourceOf derives the resource type from the template: the
// segment after /config/, or the first segment for anything else.
func auditResourceOf(template string) string {
	segs := strings.Split(strings.Trim(template, "/"), "/")
	if len(segs) >= 2 && segs[0] == "config" {
		return segs[1]
	}
	if len(segs) >= 1 && segs[0] != "" {
		return segs[0]
	}
	return "unknown"
}

func auditActionOf(method string) string {
	switch method {
	case http.MethodPost:
		return "create"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	}
	return strings.ToLower(method)
}

// auditTrail is the request-scoped state the gate and the handlers share:
// the principal the chain established, an actor a handler established
// itself, and detail a handler adds to the result.
type auditTrail struct {
	mu        sync.Mutex
	principal any
	hasPrinc  bool
	actor     *audit.Actor
	enrich    []func(*audit.MgmtDetail)
	// originator is the validated header value, copied onto every record
	// of the request; trusted caches the one lookup that decides it.
	originator string
	trusted    *bool
	// claimed is the login name the request asserted, carried from the
	// intent to a result that never got a principal: a refused login is
	// recorded against the name that was tried.
	claimed string
}

// newAuditTrail starts the request-scoped state, reading the originator
// header exactly once.
func newAuditTrail(r *http.Request) *auditTrail {
	return &auditTrail{originator: auditOriginatorOf(r)}
}

// delegationTrusted decides, once per request and only when an originator
// was named, whether the authenticated account may delegate. The lookup
// asks the store for that account; any failure, including a store that is
// down, answers no rather than refusing the request — the flag narrows
// what the record claims, it never blocks what the record records. Called
// with the trail locked.
func (t *auditTrail) delegationTrusted(username string) bool {
	if t.originator == "" || username == "" {
		return false
	}
	if t.trusted != nil {
		return *t.trusted
	}
	auditDelegationLookups.Add(1)
	allowed := false
	if ApiHooks != nil {
		if ok, err := ApiHooks.NetUserDelegationAllowed(username); err == nil {
			allowed = ok
		}
	}
	t.trusted = &allowed
	return allowed
}

type auditTrailKey struct{}

func auditTrailFrom(ctx context.Context) *auditTrail {
	t, _ := ctx.Value(auditTrailKey{}).(*auditTrail)
	return t
}

// RecordAuditPrincipal hands the gate the principal the request
// authenticated as. Both dispatch paths call it, so the result phase
// carries the same actor whichever chain served the request.
func RecordAuditPrincipal(r *http.Request, principal any) {
	t := auditTrailFrom(r.Context())
	if t == nil {
		return
	}
	t.mu.Lock()
	t.principal, t.hasPrinc = principal, true
	t.mu.Unlock()
}

// RecordAuditActor hands the gate an actor a handler established itself,
// as a login does. It overrides the principal-derived actor.
func RecordAuditActor(r *http.Request, a audit.Actor) {
	t := auditTrailFrom(r.Context())
	if t == nil {
		return
	}
	t.mu.Lock()
	t.actor = &a
	t.mu.Unlock()
}

// AuditDetail lets a handler add detail fields to the result record of
// the request it is serving. Field names only; never values that are
// secrets.
func AuditDetail(r *http.Request, fn func(*audit.MgmtDetail)) {
	t := auditTrailFrom(r.Context())
	if t == nil || fn == nil {
		return
	}
	t.mu.Lock()
	t.enrich = append(t.enrich, fn)
	t.mu.Unlock()
}

// AuditGateMiddleware is the two-phase gate. It is registered ahead of the
// raw dispatches and the generated chain.
func AuditGateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, gated := auditRouteFor(r)
		if !gated {
			next.ServeHTTP(w, r)
			return
		}
		if route.list {
			auditListRead(w, r, next, route)
			return
		}
		wr := AuditWriter()
		if wr == nil {
			auditRefuse(w, audit.ErrUnavailable)
			return
		}
		trail := newAuditTrail(r)
		r = r.WithContext(context.WithValue(r.Context(), auditTrailKey{}, trail))

		fields, claimed := auditReadBody(r, route)
		trail.claimed = claimed
		eventID := audit.NewEventID()
		intent := wr.AcquireRecord()
		intent.EventID = eventID
		intent.Stream = audit.StreamMgmt
		intent.EventType = route.event
		intent.Class = route.class
		intent.Phase = audit.PhaseIntent
		// The intent is the pre-authentication view: the originator is
		// named, but no principal exists yet to decide whether it is
		// trusted, so the claim stands untrusted until the result.
		intent.Actor = audit.Actor{
			Auth: audit.AuthNone, Remote: r.RemoteAddr, Provisional: true,
			UsernameClaimed: claimed, Mechanism: route.mechanism,
			Delegated: trail.originator,
		}
		intent.Outcome = audit.Outcome{Reason: audit.ReasonOK}
		intent.Mgmt = auditDetailFor(r, route, fields)
		if route.event == "mgmt.snapshot.restore" {
			// The intent is the restore's begin; the handler names the
			// phase the pipeline ended in on the result.
			intent.Mgmt.RestorePhase = auditRestoreBegin
		}

		ctx, cancel := context.WithTimeout(r.Context(), auditIntentTimeout)
		err := wr.Write(ctx, intent)
		cancel()
		if err != nil {
			auditRefuse(w, err)
			return
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		if !wr.Append(auditResultRecord(wr, r, trail, route, eventID, rec.status, fields)) {
			auditResultDrops.Add(1)
		}
	})
}

// auditListRead is the listing-read contract: the handler runs whatever
// the writer's state and one result record follows it, best-effort. The
// listing is metadata the caller was already authorized to see, so a
// record the writer cannot take is counted, never a reason to refuse.
func auditListRead(w http.ResponseWriter, r *http.Request, next http.Handler, route auditRoute) {
	trail := newAuditTrail(r)
	r = r.WithContext(context.WithValue(r.Context(), auditTrailKey{}, trail))
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	next.ServeHTTP(rec, r)
	wr := AuditWriter()
	if wr == nil {
		auditResultDrops.Add(1)
		return
	}
	if !wr.Append(auditResultRecord(wr, r, trail, route, audit.NewEventID(), rec.status, nil)) {
		auditResultDrops.Add(1)
	}
}

// auditResultRecord builds the result phase: the outcome the handler
// answered with, the authoritative actor, the security re-typing of a
// refusal, and the detail the handler added through AuditDetail.
func auditResultRecord(wr *audit.Writer, r *http.Request, trail *auditTrail, route auditRoute, eventID string, status int, fields []string) *audit.Record {
	result := wr.AcquireRecord()
	result.EventID = eventID
	result.Stream = audit.StreamMgmt
	result.Phase = audit.PhaseResult
	result.EventType = route.event
	result.Class = route.class
	result.Outcome = auditOutcomeOf(status, route)
	result.Actor = auditResultActor(r, trail, route)
	switch status {
	case http.StatusUnauthorized:
		result.EventType, result.Class, result.ResultOf = "sec.mgmt.authn_failed", audit.ClassSecurity, route.event
	case http.StatusForbidden:
		result.EventType, result.Class, result.ResultOf = "sec.mgmt.authz_denied", audit.ClassSecurity, route.event
	}
	d := auditDetailFor(r, route, fields)
	d.ConfigGeneration = snapshot.ConfigGeneration()
	if status == http.StatusForbidden {
		d.Role = result.Actor.Role
	}
	trail.mu.Lock()
	for _, fn := range trail.enrich {
		fn(d)
	}
	trail.mu.Unlock()
	result.Mgmt = d
	return result
}

// Restore phases a record can name. The intent carries the begin; the
// result carries where the pipeline stopped.
const (
	auditRestoreBegin          = "begin"
	auditRestorePlan           = "plan"
	auditRestoreCommit         = "commit"
	auditRestoreRollback       = "rollback"
	auditRestoreRollbackFailed = "rollback_failed"
	auditRestoreRejected       = "rejected"
)

// auditFingerprint identifies a token or state value without carrying it:
// the hex SHA-256 of the value. A record stores the fingerprint only.
func auditFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func auditDetailFor(r *http.Request, route auditRoute, fields []string) *audit.MgmtDetail {
	d := &audit.MgmtDetail{
		Method:        r.Method,
		Path:          route.path,
		RouteClass:    auditRouteGenerated,
		Raw:           route.raw,
		Resource:      route.resource,
		Action:        route.action,
		ChangedFields: fields,
		Provider:      route.provider,
		Filename:      route.filename,
		Mechanism:     route.mechanism,
	}
	if route.raw {
		d.RouteClass = auditRouteRaw
	}
	return d
}

// auditOutcomeOf maps the status the handler answered with to the closed
// reason vocabulary. A 503 is the gateway declining to perform the request
// (the boot and restore freezes, operator maintenance, a store that is not
// up) and so is an admission decision, not an upstream failure.
func auditOutcomeOf(status int, route auditRoute) audit.Outcome {
	o := audit.Outcome{Status: status}
	switch {
	case status < http.StatusBadRequest:
		o.OK, o.Reason = true, audit.ReasonOK
	case status == http.StatusUnauthorized && route.login:
		o.Reason = audit.ReasonLoginFailed
	case status == http.StatusUnauthorized:
		o.Reason = audit.ReasonAuth
	case status == http.StatusForbidden:
		o.Reason = audit.ReasonAuthz
	case status == http.StatusGatewayTimeout:
		o.Reason = audit.ReasonTimeout
	case status == http.StatusServiceUnavailable:
		o.Reason = audit.ReasonAdmission
	case status >= http.StatusInternalServerError:
		o.Reason = audit.ReasonUpstreamError
	default:
		o.Reason = audit.ReasonAdmission
	}
	return o
}

// auditResultActor is the authoritative actor: what a handler established
// itself, else the principal the chain authenticated, else the
// pre-authentication view carried over from the intent.
func auditResultActor(r *http.Request, t *auditTrail, route auditRoute) audit.Actor {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := auditPrincipalActor(r, t, route)
	// The originator rides on every record of the request, refusals
	// included; trust is decided from the account the request actually
	// authenticated as, so a claim from no account is never trusted.
	a.Delegated = t.originator
	a.DelegationTrusted = t.delegationTrusted(a.User)
	return a
}

// auditPrincipalActor is the actor before delegation is applied: what a
// handler established itself, else the principal the chain authenticated,
// else the pre-authentication view carried over from the intent.
func auditPrincipalActor(r *http.Request, t *auditTrail, route auditRoute) audit.Actor {
	if t.actor != nil {
		a := *t.actor
		if a.Remote == "" {
			a.Remote = r.RemoteAddr
		}
		return a
	}
	a := audit.Actor{Auth: audit.AuthNone, Remote: r.RemoteAddr, Mechanism: route.mechanism}
	if !managementAuthConfigured() {
		a.Mechanism = "none"
		return a
	}
	if !t.hasPrinc {
		a.Provisional = true
		a.UsernameClaimed = t.claimed
		return a
	}
	switch p := t.principal.(type) {
	case string:
		fields := strings.Split(p, "|")
		a.Auth = audit.AuthSession
		a.User = fields[0]
		if len(fields) > 1 {
			a.Role = fields[1]
		}
	case bool:
		if p {
			a.Auth = audit.AuthSession
			a.Mechanism = "manual_token"
		}
	}
	return a
}

// auditRefuse answers the D4 refusal: the audit subsystem did not record
// the request, so the request was not performed.
func auditRefuse(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusServiceUnavailable)
	msg := AuditRefusalReason + ": the audit subsystem did not record the request (" +
		auditErrClass(err) + "); the request was not performed"
	body, _ := json.Marshal(&models.Error{
		Code:    http.StatusServiceUnavailable,
		Message: "Audit unavailable",
		Result:  msg,
		Fields:  []string{},
	})
	_, _ = w.Write(body)
}

func auditErrClass(err error) string {
	switch {
	case errors.Is(err, audit.ErrDiskReserve):
		return "disk reserve breached"
	case errors.Is(err, audit.ErrWriteFailed):
		return "durable write failed"
	case errors.Is(err, audit.ErrInvalid):
		return "record rejected"
	case errors.Is(err, context.DeadlineExceeded):
		return "writer timeout"
	default:
		return "writer unavailable"
	}
}

// bodyWithPrefix hands the bytes the gate read back to the handler ahead
// of the rest of the body.
type bodyWithPrefix struct {
	io.Reader
	io.Closer
}

// auditReadBody reads a bounded prefix of the body, restores the body for
// the handler, and returns the top-level field names of a JSON object
// body and, for a login, the claimed username. Values are never kept: the
// buffer is released with the request and only names leave it.
func auditReadBody(r *http.Request, route auditRoute) (fields []string, claimed string) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, ""
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return nil, ""
	}
	limit := int64(auditFieldBodyLimit)
	if route.login {
		limit = auditLoginBodyLimit
	}
	buf, _ := io.ReadAll(io.LimitReader(r.Body, limit+1))
	r.Body = &bodyWithPrefix{Reader: io.MultiReader(bytes.NewReader(buf), r.Body), Closer: r.Body}
	if int64(len(buf)) > limit {
		return nil, ""
	}
	if route.login {
		var login struct {
			Username string `json:"username"`
		}
		if json.Unmarshal(buf, &login) == nil {
			return nil, login.Username
		}
		return nil, ""
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(buf, &obj) != nil || len(obj) == 0 {
		return nil, ""
	}
	return auditSortedKeys(obj), ""
}
