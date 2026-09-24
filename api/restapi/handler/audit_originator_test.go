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
	"net/http"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// originatorHook answers delegation lookups from a fixed account table:
// alice may delegate, bob may not.
func originatorHook(t *testing.T) *emitStubHook {
	t.Helper()
	h := &emitStubHook{users: []cmn.User{
		{ID: 1, Username: "alice", Role: "admin", DelegationAllowed: boolp(true)},
		{ID: 2, Username: "bob", Role: "admin", DelegationAllowed: boolp(false)},
	}}
	withEmitHook(t, h)
	return h
}

// A named originator rides on both records of the request, verbatim,
// beside the account that authenticated — never in its place. The intent
// carries the claim untrusted because no principal exists yet; the result
// carries the trust decision, which is the account's own flag.
func TestAuditOriginatorTrustedByTheAccountsFlag(t *testing.T) {
	withAuthMode(t, true)
	hook := originatorHook(t)
	f := newGateFixture(t)
	f.inside = func(r *http.Request) { RecordAuditPrincipal(r, "alice|admin") }
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"x":1}`,
		AuditOriginatorHeader, "mcp:claude"); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if hook.lookups != 1 {
		t.Fatalf("lookups = %d, want exactly one per request", hook.lookups)
	}
	pairs := f.pairs()
	if len(pairs) != 1 {
		t.Fatalf("pairs %d", len(pairs))
	}
	in, out := actorOf(pairs[0].intent), actorOf(pairs[0].result)
	if in["delegated"] != "mcp:claude" || in["delegation_trusted"] != false || in["provisional"] != true || in["user"] != nil {
		t.Fatalf("intent actor %v", in)
	}
	if out["delegated"] != "mcp:claude" || out["delegation_trusted"] != true || out["user"] != "alice" {
		t.Fatalf("result actor %v", out)
	}
}

// From an account without the flag the claim is still recorded — it is
// evidence of an attempt — and flagged untrusted.
func TestAuditOriginatorUntrustedWithoutTheFlag(t *testing.T) {
	withAuthMode(t, true)
	originatorHook(t)
	f := newGateFixture(t)
	f.inside = func(r *http.Request) { RecordAuditPrincipal(r, "bob|admin") }
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"x":1}`,
		AuditOriginatorHeader, "cli:svc@build-7"); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	out := actorOf(f.pairs()[0].result)
	if out["delegated"] != "cli:svc@build-7" || out["delegation_trusted"] != false || out["user"] != "bob" {
		t.Fatalf("result actor %v", out)
	}
}

// A refusal is attributable to the same originator as a success: the
// security record the denial becomes carries the claim and the decision.
func TestAuditOriginatorOnARefusal(t *testing.T) {
	withAuthMode(t, true)
	originatorHook(t)
	f := newGateFixture(t)
	f.status = http.StatusForbidden
	f.inside = func(r *http.Request) { RecordAuditPrincipal(r, "alice|admin") }
	if rec := f.do(http.MethodPost, "/netlox/v1/config/policy", `{"x":1}`,
		AuditOriginatorHeader, "mcp-stdio:kong@host-1:4242"); rec.Code != http.StatusForbidden {
		t.Fatal(rec.Code)
	}
	result := f.pairs()[0].result
	if result["event_type"] != "sec.mgmt.authz_denied" {
		t.Fatalf("result %v", result)
	}
	if a := actorOf(result); a["delegated"] != "mcp-stdio:kong@host-1:4242" || a["delegation_trusted"] != true || a["user"] != "alice" {
		t.Fatalf("refusal actor %v", a)
	}
}

// A refusal before any principal exists — the chain never authenticated —
// still names the originator, untrusted, and makes no lookup: there is no
// account to ask about.
func TestAuditOriginatorOnAnUnauthenticatedRefusal(t *testing.T) {
	withAuthMode(t, true)
	hook := originatorHook(t)
	f := newGateFixture(t)
	f.status = http.StatusUnauthorized
	if rec := f.do(http.MethodPost, "/netlox/v1/config/policy", `{"x":1}`,
		AuditOriginatorHeader, "mcp:claude"); rec.Code != http.StatusUnauthorized {
		t.Fatal(rec.Code)
	}
	result := f.pairs()[0].result
	if result["event_type"] != "sec.mgmt.authn_failed" {
		t.Fatalf("result %v", result)
	}
	if a := actorOf(result); a["delegated"] != "mcp:claude" || a["delegation_trusted"] != false || a["user"] != nil {
		t.Fatalf("refusal actor %v", a)
	}
	if hook.lookups != 0 {
		t.Fatalf("lookups = %d without a principal", hook.lookups)
	}
}

// A listing read is a class-R record; it carries the originator too.
func TestAuditOriginatorOnAListingRead(t *testing.T) {
	withAuthMode(t, true)
	originatorHook(t)
	f := newGateFixture(t)
	f.inside = func(r *http.Request) { RecordAuditPrincipal(r, "alice|admin") }
	if rec := f.do(http.MethodGet, "/netlox/v1/auth/users", "", AuditOriginatorHeader, "mcp:claude"); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	recs := f.records()
	if len(recs) != 1 || recs[0]["class"] != "read" {
		t.Fatalf("records %v", recs)
	}
	if a := actorOf(recs[0]); a["delegated"] != "mcp:claude" || a["delegation_trusted"] != true {
		t.Fatalf("listing actor %v", a)
	}
}

// Without the header nothing is looked up and no delegation field is
// written: the trust flag exists only beside a claim.
func TestAuditOriginatorAbsentMakesNoLookup(t *testing.T) {
	withAuthMode(t, true)
	hook := originatorHook(t)
	f := newGateFixture(t)
	f.inside = func(r *http.Request) { RecordAuditPrincipal(r, "alice|admin") }
	before := AuditDelegationLookups()
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"x":1}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if hook.lookups != 0 || AuditDelegationLookups() != before {
		t.Fatalf("a lookup happened without the header: hook %d, counter %d→%d", hook.lookups, before, AuditDelegationLookups())
	}
	for _, r := range f.records() {
		a := actorOf(r)
		if _, ok := a["delegated"]; ok {
			t.Fatalf("delegated present without a header: %v", a)
		}
		if _, ok := a["delegation_trusted"]; ok {
			t.Fatalf("delegation_trusted present without a claim: %v", a)
		}
	}
}

// A store that cannot answer, or a principal that is not an account,
// leaves the claim untrusted and the request served.
func TestAuditOriginatorUntrustedWhenTheStoreCannotAnswer(t *testing.T) {
	withAuthMode(t, true)
	hook := originatorHook(t)
	hook.lookupErr = cmn.ErrDBUnavailable
	f := newGateFixture(t)
	f.inside = func(r *http.Request) { RecordAuditPrincipal(r, "alice|admin") }
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"x":1}`,
		AuditOriginatorHeader, "mcp:claude"); rec.Code != http.StatusOK {
		t.Fatalf("a failed lookup refused the request: %d", rec.Code)
	}
	if a := actorOf(f.pairs()[0].result); a["delegated"] != "mcp:claude" || a["delegation_trusted"] != false {
		t.Fatalf("result actor %v", a)
	}
}

func TestAuditOriginatorManualTokenIsNeverTrusted(t *testing.T) {
	withAuthMode(t, true)
	hook := originatorHook(t)
	f := newGateFixture(t)
	f.inside = func(r *http.Request) { RecordAuditPrincipal(r, true) }
	if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"x":1}`,
		AuditOriginatorHeader, "mcp:claude"); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if a := actorOf(f.pairs()[0].result); a["delegated"] != "mcp:claude" || a["delegation_trusted"] != false || a["mechanism"] != "manual_token" {
		t.Fatalf("result actor %v", a)
	}
	if hook.lookups != 0 {
		t.Fatalf("a shared credential was looked up as an account: %d", hook.lookups)
	}
}

// A header that does not parse is dropped whole and counted; no record
// carries any part of it.
func TestAuditOriginatorMalformedIsDroppedAndCounted(t *testing.T) {
	withAuthMode(t, true)
	hook := originatorHook(t)
	for _, bad := range []string{
		"claude",                          // no scheme
		"foo:claude",                      // unknown scheme
		"mcp:",                            // empty identifier
		"mcp:cl\x01aude",                  // control byte
		"mcp:clé",                         // outside ASCII
		"mcp:" + strings.Repeat("a", 260), // over the bound
	} {
		f := newGateFixture(t)
		f.inside = func(r *http.Request) { RecordAuditPrincipal(r, "alice|admin") }
		before := AuditOriginatorDropped()
		if rec := f.do(http.MethodPost, "/netlox/v1/config/loadbalancer", `{"x":1}`,
			AuditOriginatorHeader, bad); rec.Code != http.StatusOK {
			t.Fatalf("%q: %d", bad, rec.Code)
		}
		if AuditOriginatorDropped() != before+1 {
			t.Fatalf("%q: not counted as dropped", bad)
		}
		for _, r := range f.records() {
			if _, ok := actorOf(r)["delegated"]; ok {
				t.Fatalf("%q: a malformed originator was recorded: %v", bad, actorOf(r))
			}
		}
	}
	if hook.lookups != 0 {
		t.Fatalf("a dropped header still caused %d lookups", hook.lookups)
	}
}

func TestAuditOriginatorValid(t *testing.T) {
	for v, want := range map[string]bool{
		"mcp:claude":                 true,
		"mcp-stdio:kong@host-1:4242": true,
		"cli:svc@build-7":            true,
		"mcp:with space":             true,
		"MCP:claude":                 false,
		"mcp":                        false,
		"":                           false,
	} {
		if got := auditOriginatorValid(v); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}
