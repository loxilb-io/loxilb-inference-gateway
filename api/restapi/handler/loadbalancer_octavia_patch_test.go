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

// loadbalancer_octavia_patch_test.go — unit tests for the
// net-new RFC 7386 merge-patch presence-detection logic. The 200/404/400 responder glue
// in ConfigPatchLoadbalancer is thin and is validated on the remote gate via go test +
// behavioral curl; the genuinely new logic — distinguishing an ABSENT key from a ZERO
// value and explicit-null clearing — is exercised here.

package handler

import (
	"context"
	"encoding/json"
	"testing"
)

// TestPatchPresenceDistinguishesAbsentFromZero: a body that sets only name must report
// name present and every other serviceArguments key absent — the core guard that
// stops the merge from zero-resetting untouched fields.
func TestPatchPresenceDistinguishesAbsentFromZero(t *testing.T) {
	raw := []byte(`{"serviceArguments":{"name":"new-name"}}`)
	p, err := parsePatchPresence(raw)
	if err != nil {
		t.Fatalf("parsePatchPresence: %v", err)
	}
	if !p.svcPresent("name") {
		t.Fatalf("expected name present")
	}
	for _, absent := range []string{"sel", "inactiveTimeOut", "security", "egress", "mode", "monitor"} {
		if p.svcPresent(absent) {
			t.Fatalf("expected %q absent in a name-only patch", absent)
		}
	}
}

// TestPatchPresenceExplicitNullClears: an explicit JSON null on a clearable field is
// reported as present AND null (RFC 7386 clear semantics), distinct from absent.
func TestPatchPresenceExplicitNullClears(t *testing.T) {
	raw := []byte(`{"serviceArguments":{"name":null}}`)
	p, err := parsePatchPresence(raw)
	if err != nil {
		t.Fatalf("parsePatchPresence: %v", err)
	}
	if !p.svcPresent("name") {
		t.Fatalf("explicit null must count as present")
	}
	if !p.svcIsNull("name") {
		t.Fatalf("explicit null must be detected as null")
	}
}

// TestPatchPresenceImmutableKeysDetected: presenting an immutable key (security/egress/
// mode/protocol/externalIP/port) is detected so the handler can 400 it.
func TestPatchPresenceImmutableKeysDetected(t *testing.T) {
	raw := []byte(`{"serviceArguments":{"security":2,"mode":4,"protocol":"udp","externalIP":"9.9.9.9","port":1,"egress":true}}`)
	p, err := parsePatchPresence(raw)
	if err != nil {
		t.Fatalf("parsePatchPresence: %v", err)
	}
	for _, k := range []string{"security", "mode", "protocol", "externalIP", "port", "egress"} {
		if !p.svcPresent(k) {
			t.Fatalf("expected immutable key %q to be detected as present", k)
		}
	}
}

// TestPatchPresenceTopLevelCollections: endpoints/allowedSources presence at top level is
// detected so absent collections are left untouched (declarative replace only when sent).
func TestPatchPresenceTopLevelCollections(t *testing.T) {
	raw := []byte(`{"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080}]}`)
	p, err := parsePatchPresence(raw)
	if err != nil {
		t.Fatalf("parsePatchPresence: %v", err)
	}
	if !p.topPresent("endpoints") {
		t.Fatalf("expected endpoints present")
	}
	if p.topPresent("allowedSources") {
		t.Fatalf("expected allowedSources absent")
	}
	if p.svcPresent("name") {
		t.Fatalf("expected no serviceArguments keys present")
	}
}

// TestPatchPresenceEmptyBody: an empty/absent body yields an all-absent presence map (a
// no-op patch leaves the rule untouched), not an error.
func TestPatchPresenceEmptyBody(t *testing.T) {
	p, err := parsePatchPresence(nil)
	if err != nil {
		t.Fatalf("empty body must not error: %v", err)
	}
	if p.svcPresent("name") || p.topPresent("endpoints") {
		t.Fatalf("empty body must report all keys absent")
	}
}

// TestPatchPresenceMalformedBody: malformed JSON surfaces an error so the handler returns 400.
func TestPatchPresenceMalformedBody(t *testing.T) {
	if _, err := parsePatchPresence([]byte(`{not json`)); err == nil {
		t.Fatalf("malformed body must error")
	}
}

// TestRawPatchBodyContextRoundTrip: the middleware-stashed raw body round-trips through
// the request context so the handler can re-read it after go-swagger drains r.Body.
func TestRawPatchBodyContextRoundTrip(t *testing.T) {
	raw := []byte(`{"serviceArguments":{"name":"x"}}`)
	ctx := WithRawPatchBody(context.Background(), raw)
	got := rawPatchBodyFromContext(ctx)
	if string(got) != string(raw) {
		t.Fatalf("raw body did not round-trip; got %q", string(got))
	}
	if rawPatchBodyFromContext(context.Background()) != nil {
		t.Fatalf("absent context value must return nil")
	}
}

// TestRuleNotExistsErrCodeStable: the mirrored control-plane sentinel value must stay the
// 5th entry of the rules.go error iota (RuleErrBase=-7000): -7000+4 = -6996. If the
// control plane reorders that iota, this guard fails and the 404 mapping must be updated.
func TestRuleNotExistsErrCodeStable(t *testing.T) {
	if ruleNotExistsErrCode != -6996 {
		t.Fatalf("ruleNotExistsErrCode drifted from the control-plane sentinel: got %d, want -6996", ruleNotExistsErrCode)
	}
}

// --- declarative endpoints[] pass-through ---
//
// These tests pin the three declarative member-set semantics at the presence
// layer that drives ConfigPatchLoadbalancer's `if pres.topPresent("endpoints")` branch:
// a present non-empty array REPLACES the set, an ABSENT key leaves members untouched
// (presence-aware: absent != empty), and an explicit empty array CLEARS all
// members. The presence map is the gate the handler uses to decide whether to rebuild
// merged.Eps from params.Attr.Endpoints (replace/clear) or carry the current rule's
// members (no-op); the 200/404 responder glue + the atomic CT-preserving reconcile are
// validated on the remote gate.

// TestPatchEndpointsPresentNonEmptyReplaces: a body with a non-empty endpoints[] array is
// reported present, so the handler rebuilds the desired member set (declarative replace).
func TestPatchEndpointsPresentNonEmptyReplaces(t *testing.T) {
	raw := []byte(`{"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080},{"endpointIP":"32.32.32.1","targetPort":8080}]}`)
	p, err := parsePatchPresence(raw)
	if err != nil {
		t.Fatalf("parsePatchPresence: %v", err)
	}
	if !p.topPresent("endpoints") {
		t.Fatalf("a non-empty endpoints[] must be detected present (declarative replace)")
	}
}

// TestPatchEndpointsAbsentLeavesMembersUntouched: a body WITHOUT an endpoints key must
// report endpoints absent — the handler then skips the rebuild and carries the current
// rule's members, so the reconcile is a member no-op (: absent != empty array).
func TestPatchEndpointsAbsentLeavesMembersUntouched(t *testing.T) {
	raw := []byte(`{"serviceArguments":{"name":"only-name-changed"}}`)
	p, err := parsePatchPresence(raw)
	if err != nil {
		t.Fatalf("parsePatchPresence: %v", err)
	}
	if p.topPresent("endpoints") {
		t.Fatalf("an absent endpoints key must NOT be reported present (members untouched)")
	}
	// And the name change that WAS sent must still be seen — absent endpoints does not
	// suppress unrelated present fields.
	if !p.svcPresent("name") {
		t.Fatalf("the present name field must still be detected alongside absent endpoints")
	}
}

// TestPatchEndpointsExplicitEmptyArrayRejected: WR-01 contract. An explicit empty
// endpoints[] array is still reported PRESENT (distinct from absent), but a PATCH must
// NEVER tear down the rule — an empty desired set reaching AddLbRule would hit the
// `len(retEps)==0 => DeleteLbRule` branch and destroy the rule + orphan the opaque id.
// The handler therefore REJECTS a present-but-empty endpoints array with HTTP 400; a
// client removes the rule via DELETE, not via an empty-array PATCH. We assert (a) the
// presence detection (empty != absent) and (b) the len==0 guard predicate the handler
// uses to trigger the 400, keeping the test in lockstep with the handler gate. The full
// handler 400 round-trip is validated on the remote gate (operations pkg + cicd).
func TestPatchEndpointsExplicitEmptyArrayRejected(t *testing.T) {
	raw := []byte(`{"endpoints":[]}`)
	p, err := parsePatchPresence(raw)
	if err != nil {
		t.Fatalf("parsePatchPresence: %v", err)
	}
	if !p.topPresent("endpoints") {
		t.Fatalf("an explicit empty endpoints[] must be detected present (so the handler can reject it, not treat it as untouched)")
	}

	// The handler rejects when the present endpoints key carries zero members. Decode the
	// array the handler would build from and assert the reject predicate fires.
	var eps []json.RawMessage
	if err := json.Unmarshal(p.top["endpoints"], &eps); err != nil {
		t.Fatalf("decode endpoints array: %v", err)
	}
	if len(eps) != 0 {
		t.Fatalf("explicit empty array must decode to zero members (handler reject trigger)")
	}
	// Sanity: a NON-empty array must NOT trip the reject predicate.
	rawNonEmpty := []byte(`{"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080}]}`)
	pn, err := parsePatchPresence(rawNonEmpty)
	if err != nil {
		t.Fatalf("parsePatchPresence(non-empty): %v", err)
	}
	var epsN []json.RawMessage
	if err := json.Unmarshal(pn.top["endpoints"], &epsN); err != nil {
		t.Fatalf("decode non-empty endpoints array: %v", err)
	}
	if len(epsN) == 0 {
		t.Fatalf("a non-empty endpoints[] must NOT trip the empty-array reject (declarative replace)")
	}
}
