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

// Unit tests for the l7policy snapshot domain (schema 1.3): registry
// Get/Apply/Delete plumbing, boot-retry idempotency semantics, and the
// coverage rule that keeps pre-1.3 documents from wiping live policies.

package snapshot

import (
	"errors"
	"reflect"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func l7TestPolicy(id, lbID string) cmn.L7PolicyArg {
	return cmn.L7PolicyArg{
		Id:   id,
		Name: "pol-" + id,
		LbId: lbID,
		Rules: []cmn.L7RuleArg{{
			Position: 1,
			MatchSets: []cmn.L7MatchSetArg{{
				Conditions: []cmn.L7ConditionArg{{Field: "PATH", Op: "STARTS_WITH", Value: "/v1/"}},
			}},
			Action: cmn.L7ActionArg{Kind: "REJECT", Reject: &cmn.L7RejectArg{StatusCode: 403}},
		}},
	}
}

// TestL7PolicyDomainHooks exercises the domain's Get/Apply/Delete against
// the mock backend.
func TestL7PolicyDomainHooks(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.L7Policy = []cmn.L7PolicyArg{
		l7TestPolicy("pol-a", "lb-1"), l7TestPolicy("pol-b", "lb-2"),
	}

	applied, skipped, err := applyL7Policy(hooks, doc, false)
	if err != nil || applied != 2 || skipped != 0 {
		t.Fatalf("apply = (%d,%d,%v), want (2,0,nil)", applied, skipped, err)
	}

	out := NewDocument("v0.9.9", "gw-test", TriggerManual)
	if err := getL7Policy(hooks, out); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(out.Domains.L7Policy, doc.Domains.L7Policy) {
		t.Fatalf("get after apply drifted: %+v", out.Domains.L7Policy)
	}

	deleted, err := deleteL7Policy(hooks)
	if err != nil || deleted != 2 {
		t.Fatalf("delete = (%d,%v), want (2,nil)", deleted, err)
	}
	if got, _ := hooks.NetL7PolicyGet(); len(got) != 0 {
		t.Fatalf("policies survive delete: %+v", got)
	}
}

// TestL7PolicyApplyIdempotency: with tolerateExists (boot replay, rollback
// re-apply), re-adding an identical policy is skipped as a no-op; without
// it (post-wipe commit apply) the same error is fatal. A same-id
// DIFFERENT-content conflict is fatal in BOTH modes -- tolerating it would
// silently keep the wrong policy live.
func TestL7PolicyApplyIdempotency(t *testing.T) {
	hooks := newMockHooks()
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.L7Policy = []cmn.L7PolicyArg{l7TestPolicy("pol-a", "lb-1")}

	if _, _, err := applyL7Policy(hooks, doc, false); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	applied, skipped, err := applyL7Policy(hooks, doc, true)
	if err != nil || applied != 0 || skipped != 1 {
		t.Fatalf("tolerant re-apply = (%d,%d,%v), want (0,1,nil)", applied, skipped, err)
	}

	if _, _, err := applyL7Policy(hooks, doc, false); err == nil {
		t.Fatalf("intolerant re-apply must surface the exists error (post-wipe 'exists' means the wipe failed)")
	}

	conflict := NewDocument("v0.9.9", "gw-test", TriggerManual)
	changed := l7TestPolicy("pol-a", "lb-1")
	changed.Rules[0].Action = cmn.L7ActionArg{Kind: "REDIRECT", Redirect: &cmn.L7RedirectArg{StatusCode: 302}}
	conflict.Domains.L7Policy = []cmn.L7PolicyArg{changed}
	if _, _, err := applyL7Policy(hooks, conflict, true); err == nil {
		t.Fatalf("same-id different-content conflict must be fatal even with tolerateExists")
	}
}

// TestL7PolicyApplyFailureAborts: a failing Add aborts the domain with the
// failing policy named -- a policy that cannot be attached must fail the
// restore (allow-all after reboot is the exact defect this domain closes),
// never be skipped.
func TestL7PolicyApplyFailureAborts(t *testing.T) {
	hooks := newMockHooks()
	hooks.failNext("NetL7PolicyAdd", errors.New("l7policy: load-balancer \"lb-1\" not found"))
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.L7Policy = []cmn.L7PolicyArg{l7TestPolicy("pol-a", "lb-1")}

	applied, _, err := applyL7Policy(hooks, doc, true)
	if err == nil || applied != 0 {
		t.Fatalf("apply with missing LB = (%d,%v), want abort", applied, err)
	}
}

// TestL7PolicyCaptureSubsystemUnavailable: bgp-peer-mode gateways report
// the L7 registry unavailable; capture treats the domain as empty instead
// of failing the whole snapshot (matching bfd/bgp/ipsec).
func TestL7PolicyCaptureSubsystemUnavailable(t *testing.T) {
	hooks := newMockHooks()
	hooks.failNext("NetL7PolicyGet", errors.New("running in bgp only mode"))
	doc := NewDocument("v0.9.9", "gw-test", TriggerManual)
	doc.Domains.L7Policy = []cmn.L7PolicyArg{l7TestPolicy("stale", "lb-9")}
	if err := getL7Policy(hooks, doc); err != nil {
		t.Fatalf("get with unavailable subsystem: %v", err)
	}
	if doc.Domains.L7Policy != nil {
		t.Fatalf("unavailable subsystem must capture as empty, got %+v", doc.Domains.L7Policy)
	}
}
