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

// qos_assoc_test.go — unit tests for the vip_qos_policy_id
// additive-model contract at the handler trust boundary: the field round-trips verbatim
// through the cmn.LbServiceArg JSON surface, and — critically — is OMITTED
// from the wire when empty so today's Octavia driver + kube-loxilb flows are byte-identical.
//
// The full /config/loadbalancer association behaviour (resolve-or-error) is exercised in
// pkg/loxinet (TestPolAssociateLbRule*); this handler-package test pins the model-field
// contract THIS plan owns. The swagger/handler wiring + regen is owned.
//
// darwin cannot compile this package (Linux cgo / regen-dependent), same deferral as every
// /73 handler test — the assertion runs on the remote/AWS gate.

package handler

import (
	"encoding/json"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestQoSVipPolicyIdRoundTrip: a non-empty vip_qos_policy_id round-trips verbatim through
// the cmn.LbServiceArg JSON surface (— loxilb stores the reference as given).
func TestQoSVipPolicyIdRoundTrip(t *testing.T) {
	in := cmn.LbServiceArg{
		ServIP:         "20.20.20.9",
		ServPort:       443,
		Proto:          "tcp",
		VipQosPolicyId: "qos-policy-7",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"vip_qos_policy_id":"qos-policy-7"`) {
		t.Fatalf("vip_qos_policy_id must serialize under its JSON tag, got: %s", b)
	}
	var out cmn.LbServiceArg
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.VipQosPolicyId != "qos-policy-7" {
		t.Fatalf("vip_qos_policy_id must round-trip verbatim, got %q", out.VipQosPolicyId)
	}
}

// TestQoSVipPolicyIdOmittedWhenEmpty: an empty vip_qos_policy_id is OMITTED from the wire
// (omitempty) so an LB-create without QoS round-trips byte-identical. This is
// the additive/default-off invariant every field must satisfy.
func TestQoSVipPolicyIdOmittedWhenEmpty(t *testing.T) {
	in := cmn.LbServiceArg{
		ServIP:   "20.20.20.9",
		ServPort: 443,
		Proto:    "tcp",
		// VipQosPolicyId intentionally left empty
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "vip_qos_policy_id") {
		t.Fatalf("empty vip_qos_policy_id must be omitted from the wire (omitempty), got: %s", b)
	}
}
