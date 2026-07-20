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

// qos_assoc_test.go — unit tests for the vip_qos_policy_id →
// LB-rule association via policer plane (PolAssociateLbRule). These exercise
// the trust-boundary invariants THIS plan owns WITHOUT touching the dataplane: an
// unresolvable ident must surface an error (no silent-drop), and an
// empty ident must be a no-op (round-trips byte-identical). The full
// resolve+attach+DP success path is exercised on the remote/AWS gate (assert (d) lineage).

package loxinet

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestPolAssociateLbRuleUnresolvableErrors: associating a vip_qos_policy_id that does NOT
// reference an existing policer ident surfaces PolNoExistErr — never a silent-drop
// . loxilb only associates an EXISTING ident.
func TestPolAssociateLbRuleUnresolvableErrors(t *testing.T) {
	P := &PolH{PolMap: make(map[PolKey]*PolEntry)}
	rc, err := P.PolAssociateLbRule("does-not-exist", "20.20.20.1:443:tcp")
	if err == nil || rc != PolNoExistErr {
		t.Fatalf("unresolvable vip_qos_policy_id must error (no silent-drop), got rc=%d err=%v", rc, err)
	}
}

// TestPolAssociateLbRuleEmptyIsNoop: an empty vip_qos_policy_id is a no-op success so an
// LB-create without QoS round-trips byte-identical.
func TestPolAssociateLbRuleEmptyIsNoop(t *testing.T) {
	P := &PolH{PolMap: make(map[PolKey]*PolEntry)}
	rc, err := P.PolAssociateLbRule("", "20.20.20.1:443:tcp")
	if err != nil || rc != 0 {
		t.Fatalf("empty vip_qos_policy_id must be a no-op success, got rc=%d err=%v", rc, err)
	}
	if len(P.PolMap) != 0 {
		t.Fatalf("empty vip_qos_policy_id must not create any policer attachment")
	}
}

// TestPolAssociateLbRuleIdempotentAttach: associating an ident that is ALREADY attached to
// the same lbKey is a no-op (the attachment is set, not appended twice) — re-running an
// LB-create must not duplicate the policer↔rule edge. This path does not touch the
// dataplane (the duplicate is detected before any DP call).
func TestPolAssociateLbRuleIdempotentAttach(t *testing.T) {
	lbKey := "20.20.20.1:443:tcp"
	p := &PolEntry{}
	p.Key.PolName = "qos-1"
	p.PObjs = []PolObjInfo{
		{Args: cmn.PolObj{PolObjName: lbKey, AttachMent: cmn.PolAttachLbRule}, Parent: p},
	}
	P := &PolH{PolMap: map[PolKey]*PolEntry{{"qos-1"}: p}}

	rc, err := P.PolAssociateLbRule("qos-1", lbKey)
	if err != nil || rc != 0 {
		t.Fatalf("re-associating an existing ident→rule edge must be a no-op success, got rc=%d err=%v", rc, err)
	}
	if got := len(P.PolMap[PolKey{"qos-1"}].PObjs); got != 1 {
		t.Fatalf("idempotent associate must not duplicate the attachment, got %d PObjs", got)
	}
}
