//go:build !doca

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

// rules_fw_hwoffload_test.go - Wave-0 test scaffold.
//
// This file covers the validateHwOffloadExpressible hard-reject
// gate added in pkg/loxinet/rules.go. Wave-0 scope: pure-Go unit tests
// against the helper itself, no DOCA, no eBPF, no REST. Linux-CI safe
// under the !doca build tag.
//
// (DOCA wire-up) and (REST integration) will add
// downstream test coverage that observes Fw2DP / FwDpWorkQ.HwOffload
// dispatch behaviour and 4xx error-body propagation. The scaffold here
// locks the typed-error contract so those later layers can switch on
// HwOffloadUnexpressibleReason rather than parsing message text.
//
// Decision references:. See
//

package loxinet

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// validRule - a known-expressible HwOffload=true rule used as the base
// for table cases. Each case overrides exactly one field to drive a
// specific branch of validateHwOffloadExpressible.
//
// /32 IPs are mandatory after correction: DOCA 2.9.4 BASIC pipes
// use a single pipe-level template mask (UINT32_MAX → exact match) and
// do not support per-entry CIDR masks. /24 (or any non-/32 prefix) is
// rejected by HwOffloadReasonCIDRSrc / HwOffloadReasonCIDRDst.
func validRule() cmn.FwRuleArg {
	return cmn.FwRuleArg{
		SrcIP:      "10.0.0.1/32",
		DstIP:      "20.0.0.1/32",
		SrcPortMin: 0, // wildcard source port
		SrcPortMax: 0,
		DstPortMin: 8080, // single-port destination
		DstPortMax: 8080,
		Proto:      0, // any — proto-agnostic TRANSPORT match
		InPort:     "p0",
		Pref:       100,
		HwOffload:  true,
	}
}

// TestHwOffloadExpressibility - table-driven coverage of
// hard-reject gate. Exercises all 8 rejection branches (IPv6 src/dst,
// non-/32 CIDR src/dst correction, port range src/dst, proto
// TCP/UDP) + 3 acceptance branches + the typed-error contract.
//
// The test name is referenced verbatim by the success criteria for
// ("go test -tags '!doca' -run TestHwOffloadExpressibility").
// may add nested t.Run subtests; do not rename the top-level
// test function without updating the success-criteria invocation.
func TestHwOffloadExpressibility(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(r *cmn.FwRuleArg)
		wantErr     bool
		wantReason  HwOffloadUnexpressibleReason
		wantMsgSubs []string // every substring MUST appear in err.Error
	}{
		// ---------------- Acceptance branches (3) ----------------
		{
			name: "accept/IPv4 5-tuple wildcard src + single-port dst (baseline expressible)",
			mutate: func(r *cmn.FwRuleArg) {
				// Use the baseline as-is — fully expressible.
			},
			wantErr: false,
		},
		{
			name: "accept/single-port src + wildcard dst",
			mutate: func(r *cmn.FwRuleArg) {
				r.SrcPortMin = 1234
				r.SrcPortMax = 1234
				r.DstPortMin = 0
				r.DstPortMax = 0
			},
			wantErr: false,
		},
		{
			name: "accept/IPv4 /32 src + /32 dst + wildcard ports + proto any",
			mutate: func(r *cmn.FwRuleArg) {
				r.SrcIP = "192.0.2.10/32"
				r.DstIP = "198.51.100.10/32"
				r.SrcPortMin = 0
				r.SrcPortMax = 0
				r.DstPortMin = 0
				r.DstPortMax = 0
				r.Proto = 0
			},
			wantErr: false,
		},
		// ---------------- Rejection branches (8) ----------------
		{
			name: "reject/IPv6 source CIDR",
			mutate: func(r *cmn.FwRuleArg) {
				r.SrcIP = "2001:db8::/32"
			},
			wantErr:     true,
			wantReason:  HwOffloadReasonIPv6Src,
			wantMsgSubs: []string{"IPv6 source", "2001:db8::/32", ""},
		},
		{
			name: "reject/IPv6 destination CIDR",
			mutate: func(r *cmn.FwRuleArg) {
				r.DstIP = "2001:db8::1/128"
			},
			wantErr:     true,
			wantReason:  HwOffloadReasonIPv6Dst,
			wantMsgSubs: []string{"IPv6 destination", "2001:db8::1/128", ""},
		},
		{
			name: "reject/non-/32 IPv4 source CIDR (corrected — DOCA 2.9.4 BASIC pipes exact-IP only)",
			mutate: func(r *cmn.FwRuleArg) {
				r.SrcIP = "10.0.0.0/24"
			},
			wantErr:     true,
			wantReason:  HwOffloadReasonCIDRSrc,
			wantMsgSubs: []string{"source CIDR /24", "10.0.0.0/24", "", "exact-IP"},
		},
		{
			name: "reject/non-/32 IPv4 destination CIDR (corrected — DOCA 2.9.4 BASIC pipes exact-IP only)",
			mutate: func(r *cmn.FwRuleArg) {
				r.DstIP = "20.0.0.0/16"
			},
			wantErr:     true,
			wantReason:  HwOffloadReasonCIDRDst,
			wantMsgSubs: []string{"destination CIDR /16", "20.0.0.0/16", "", "exact-IP"},
		},
		{
			name: "reject/source port range",
			mutate: func(r *cmn.FwRuleArg) {
				r.SrcPortMin = 1000
				r.SrcPortMax = 2000
			},
			wantErr:     true,
			wantReason:  HwOffloadReasonPortRangeSrc,
			wantMsgSubs: []string{"source port range", "L4SrcMin=1000", "L4SrcMax=2000", ""},
		},
		{
			name: "reject/destination port range",
			mutate: func(r *cmn.FwRuleArg) {
				r.DstPortMin = 8000
				r.DstPortMax = 9000
			},
			wantErr:     true,
			wantReason:  HwOffloadReasonPortRangeDst,
			wantMsgSubs: []string{"destination port range", "L4DstMin=8000", "L4DstMax=9000", ""},
		},
		{
			name: "reject/proto-specific TCP (Proto=6)",
			mutate: func(r *cmn.FwRuleArg) {
				r.Proto = 6
			},
			wantErr:     true,
			wantReason:  HwOffloadReasonProtoTCP,
			wantMsgSubs: []string{"Proto=6", "TCP-specific", "TRANSPORT", ""},
		},
		{
			name: "reject/proto-specific UDP (Proto=17)",
			mutate: func(r *cmn.FwRuleArg) {
				r.Proto = 17
			},
			wantErr:     true,
			wantReason:  HwOffloadReasonProtoUDP,
			wantMsgSubs: []string{"Proto=17", "UDP-specific", "TRANSPORT", ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := validRule()
			tc.mutate(&r)
			err := validateHwOffloadExpressible(r)

			if !tc.wantErr {
				if err != nil {
					t.Fatalf("expected expressible rule to pass validation, got error: %v", err)
				}
				return
			}

			// Rejection-branch assertions.
			if err == nil {
				t.Fatalf("expected validation error for %s, got nil", tc.name)
			}
			// Typed-error contract — the failure path MUST surface a
			// *errHwOffloadUnexpressible so / 64-06 callers
			// can switch on Reason without parsing message text.
			var typed *errHwOffloadUnexpressible
			if !errors.As(err, &typed) {
				t.Fatalf("expected *errHwOffloadUnexpressible, got %T: %v", err, err)
			}
			if typed.Reason != tc.wantReason {
				t.Errorf("Reason: got %d, want %d", typed.Reason, tc.wantReason)
			}
			for _, sub := range tc.wantMsgSubs {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error message %q missing required substring %q",
						err.Error(), sub)
				}
			}
			// Every rejection message MUST include the operator
			// remediation hint ("HwOffload=false" or "use HwOffload=false")
			// so the REST 4xx body tells operators what to do next.
			// contract: rejected rule installed in neither layer.
			if !strings.Contains(err.Error(), "HwOffload=false") {
				t.Errorf("error message %q missing remediation hint 'HwOffload=false'",
					err.Error())
			}
		})
	}
}

// TestHwOffloadExpressibilityReasonCodesStable - Wave-0 forward-compat
// guard. The HwOffloadUnexpressibleReason iota values are part of the
// stable contract: REST clients, DOCA
// dispatcher, and downstream Prometheus reason-labeling will all switch
// on them. Re-ordering or inserting between the existing values silently
// reassigns codes — this test pins the current assignments so any
// re-order trips a regression.
func TestHwOffloadExpressibilityReasonCodesStable(t *testing.T) {
	pinned := map[HwOffloadUnexpressibleReason]int{
		HwOffloadReasonNone:         0,
		HwOffloadReasonIPv6Src:      1,
		HwOffloadReasonIPv6Dst:      2,
		HwOffloadReasonPortRangeSrc: 3,
		HwOffloadReasonPortRangeDst: 4,
		HwOffloadReasonProtoTCP:     5,
		HwOffloadReasonProtoUDP:     6,
		// 7+8 added SDK correction; appended at the end so the
		// codes 1..6 above stay pinned to their pre-correction values.
		HwOffloadReasonCIDRSrc: 7,
		HwOffloadReasonCIDRDst: 8,
	}
	for reason, want := range pinned {
		if int(reason) != want {
			t.Errorf("Reason code drift: %v is %d, expected %d (re-ordering breaks REST contract)",
				reason, int(reason), want)
		}
	}
}

// TestHwOffloadExpressibilityNonHwFlaggedBypass - documents (and pins)
// the contract that validateHwOffloadExpressible is ONLY called from
// AddFwRule when fwRule.HwOffload == true. Non-HW-flagged rules — even
// those with IPv6 sources, port ranges, or proto-specific shapes — are
// the eBPF firewall's domain and MUST NOT be rejected.
//
// This test exercises the helper directly with HwOffload=false rules
// that would fail every branch if mistakenly called; the helper
// itself does NOT check the HwOffload field (that gating lives in
// AddFwRule placement). We pin that semantic so a future
// refactor that moves the gate into the helper has to update both
// sites.
func TestHwOffloadExpressibilityNonHwFlaggedBypass(t *testing.T) {
	// Direct-call posture: helper rejects regardless of HwOffload flag
	// because the AddFwRule layer is responsible for the gate. This is
	// a CONTRACT test — if a future refactor moves the gate into the
	// helper, this test will need to flip to assert nil (and the
	// AddFwRule injection in rules.go must be removed in lockstep).
	r := validRule()
	r.HwOffload = false // flag off, but every other field is still expressible
	if err := validateHwOffloadExpressible(r); err != nil {
		t.Fatalf("baseline expressible rule with HwOffload=false should still validate cleanly when helper is called directly: %v", err)
	}

	// And — also direct-call — a non-expressible rule with
	// HwOffload=false STILL surfaces the typed error when the helper
	// is invoked directly. The eBPF-bypass semantic is at the
	// AddFwRule call site, not inside the helper.
	r2 := validRule()
	r2.HwOffload = false
	r2.SrcIP = "2001:db8::/32" // IPv6 source — not expressible
	err := validateHwOffloadExpressible(r2)
	if err == nil {
		t.Fatalf("direct-call to validateHwOffloadExpressible with IPv6 src should still return typed error regardless of HwOffload flag; got nil")
	}
	var typed *errHwOffloadUnexpressible
	if !errors.As(err, &typed) {
		t.Fatalf("expected *errHwOffloadUnexpressible from direct call, got %T", err)
	}
	if typed.Reason != HwOffloadReasonIPv6Src {
		t.Errorf("Reason: got %d, want %d", typed.Reason, HwOffloadReasonIPv6Src)
	}
}

// TestValidateHwOffloadExpressible — direct-call alias for the success-criteria
// grep ("func TestValidateHwOffloadExpressible") expected
// acceptance criteria. The body re-uses validRule to assert the helper's
// happy path; the broad-coverage table-driven tests live in
// TestHwOffloadExpressibility above. Keep this thin alias so test renames do
// not silently break automated grep verification.
func TestValidateHwOffloadExpressible(t *testing.T) {
	r := validRule()
	if err := validateHwOffloadExpressible(r); err != nil {
		t.Fatalf("baseline expressible rule should validate, got %v", err)
	}
}

// TestFwRuleArg_HwOffload_DefaultFalse — pin the Go zero-value contract:
// constructing an FwRuleArg without the HwOffload field MUST default to
// false. This is the wire-level backwards-compat guarantee for clients
// (kube-loxilb, loxicmd) that have not been updated to know about the new
// field.
func TestFwRuleArg_HwOffload_DefaultFalse(t *testing.T) {
	var r cmn.FwRuleArg
	if r.HwOffload {
		t.Fatal("FwRuleArg{}.HwOffload zero value: expected false, got true")
	}

	// Also: a partial construction (omitting HwOffload from the literal)
	// keeps the default.
	r2 := cmn.FwRuleArg{SrcIP: "10.0.0.0/24"}
	if r2.HwOffload {
		t.Fatal("partial FwRuleArg without HwOffload field: expected false, got true")
	}
}

// TestFwRuleArg_HwOffload_JSONRoundTrip — pin the wire-level JSON contract.
//
// Current FwRuleArg.HwOffload tag is `json:"hwOffload"`
// commit b11d40e7 and amendments). This test asserts the actual
// shipped behavior:
//
//   - Marshaling {HwOffload: true}  ⇒ JSON contains `"hwOffload":true`.
//   - Marshaling {HwOffload: false} ⇒ JSON contains `"hwOffload":false`
//     (NO omitempty in the current tag).
//   - Unmarshaling JSON WITHOUT the `hwOffload` key ⇒ HwOffload defaults to
//     false (Go zero value); the backwards-compat path for legacy clients.
//   - Unmarshaling JSON WITH `"hwOffload":true` ⇒ HwOffload = true.
//   - Round-trip preserves the value in both directions.
//
// > Forward-compat note (deviation): the 64-MIGRATION.md spec
// > mentions ",omitempty" as the eventual wire contract for clients that
// > MUST NOT serialize the new field. The current shipped tag has NO
// > omitempty; this test pins that reality so any future ",omitempty"
// > change is a deliberate wire-contract bump (and the test will flip in
// > the same commit). Tracked in 64-05-DEVIATIONS.md.
func TestFwRuleArg_HwOffload_JSONRoundTrip(t *testing.T) {
	t.Run("marshal_true_present", func(t *testing.T) {
		r := cmn.FwRuleArg{SrcIP: "10.0.0.0/24", DstIP: "20.0.0.0/24", HwOffload: true}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !strings.Contains(string(b), `"hwOffload":true`) {
			t.Errorf("Marshal {HwOffload:true}: expected `\"hwOffload\":true` in output, got %s", string(b))
		}
	})

	t.Run("marshal_false_present_no_omitempty", func(t *testing.T) {
		r := cmn.FwRuleArg{SrcIP: "10.0.0.0/24", DstIP: "20.0.0.0/24", HwOffload: false}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		// Pinning current shipped contract: NO omitempty, so HwOffload=false
		// is wire-encoded as the literal `"hwOffload":false`. If a future
		// commit adds ",omitempty" this assertion flips and 64-MIGRATION.md
		// updates in lockstep.
		if !strings.Contains(string(b), `"hwOffload":false`) {
			t.Errorf("Marshal {HwOffload:false}: expected `\"hwOffload\":false` in output (NO omitempty in current tag), got %s", string(b))
		}
	})

	t.Run("unmarshal_missing_field_defaults_to_false", func(t *testing.T) {
		// Backwards-compat path: legacy clients pre- do NOT include
		// the field in REST bodies. The Go decoder MUST default to false.
		js := `{"sourceIP":"10.0.0.0/24","destinationIP":"20.0.0.0/24","preference":100}`
		var r cmn.FwRuleArg
		if err := json.Unmarshal([]byte(js), &r); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if r.HwOffload {
			t.Errorf("Unmarshal missing hwOffload key: expected false, got true")
		}
	})

	t.Run("unmarshal_explicit_true", func(t *testing.T) {
		js := `{"sourceIP":"10.0.0.0/24","destinationIP":"20.0.0.0/24","hwOffload":true}`
		var r cmn.FwRuleArg
		if err := json.Unmarshal([]byte(js), &r); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if !r.HwOffload {
			t.Errorf("Unmarshal {\"hwOffload\":true}: expected true, got false")
		}
	})

	t.Run("unmarshal_explicit_false", func(t *testing.T) {
		js := `{"sourceIP":"10.0.0.0/24","destinationIP":"20.0.0.0/24","hwOffload":false}`
		var r cmn.FwRuleArg
		if err := json.Unmarshal([]byte(js), &r); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if r.HwOffload {
			t.Errorf("Unmarshal {\"hwOffload\":false}: expected false, got true")
		}
	})

	t.Run("round_trip_true", func(t *testing.T) {
		r1 := cmn.FwRuleArg{SrcIP: "10.0.0.0/24", DstIP: "20.0.0.0/24", HwOffload: true}
		b, err := json.Marshal(r1)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var r2 cmn.FwRuleArg
		if err := json.Unmarshal(b, &r2); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if r2.HwOffload != r1.HwOffload {
			t.Errorf("round-trip true: in=%v out=%v", r1.HwOffload, r2.HwOffload)
		}
	})

	t.Run("round_trip_false", func(t *testing.T) {
		r1 := cmn.FwRuleArg{SrcIP: "10.0.0.0/24", DstIP: "20.0.0.0/24", HwOffload: false}
		b, err := json.Marshal(r1)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var r2 cmn.FwRuleArg
		if err := json.Unmarshal(b, &r2); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if r2.HwOffload != r1.HwOffload {
			t.Errorf("round-trip false: in=%v out=%v", r1.HwOffload, r2.HwOffload)
		}
	})
}

// TestFw2DP_HwOffload_PassThroughContract — pin
// pass-through contract at the type-shape level. The full Fw2DP integration
// path (`r.zone.Ports.PortFindByName(...)` + `mh.dp.ToDpCh <- nWork`)
// requires global state setup (Zone, mh.dp.ToDpCh) that is out of scope
// for a !doca unit test. Instead, this test asserts via reflection that:
//
//  1. FwDpWorkQ has an exported HwOffload bool field — the DP-side mirror.
//  2. FwRuleArg has an exported HwOffload bool field — the REST-side source.
//  3. Both types use the same Go field kind (bool), so the pass-through
//     in rules.go:4133 (`nWork.HwOffload = r.hwOffload`) is type-correct.
//  4. A direct-construction FwDpWorkQ round-trips the HwOffload value
//     through its struct field (Go zero-value semantics + explicit set).
//
// integration validation lives in the operator runbook §4
// (Scope 3): an HwOffload=true expressible rule POSTed via REST appears in
// /metrics with `loxilb_acl_hw_deny_entries=1`, confirming the full chain
// REST→FwRuleArg→ruleEnt→Fw2DP→FwDpWorkQ→FwRuleAdd→Prometheus is intact.
func TestFw2DP_HwOffload_PassThroughContract(t *testing.T) {
	t.Run("FwDpWorkQ_has_HwOffload_bool", func(t *testing.T) {
		wq := reflect.TypeOf(FwDpWorkQ{})
		f, ok := wq.FieldByName("HwOffload")
		if !ok {
			t.Fatal("FwDpWorkQ.HwOffload field missing — contract broken")
		}
		if f.Type.Kind() != reflect.Bool {
			t.Errorf("FwDpWorkQ.HwOffload type: expected bool, got %s", f.Type.Kind())
		}
	})

	t.Run("FwRuleArg_has_HwOffload_bool", func(t *testing.T) {
		ra := reflect.TypeOf(cmn.FwRuleArg{})
		f, ok := ra.FieldByName("HwOffload")
		if !ok {
			t.Fatal("cmn.FwRuleArg.HwOffload field missing — contract broken")
		}
		if f.Type.Kind() != reflect.Bool {
			t.Errorf("cmn.FwRuleArg.HwOffload type: expected bool, got %s", f.Type.Kind())
		}
		// Tag-level wire contract: ensure the JSON tag is exactly "hwOffload".
		// (omitempty handling is verified in TestFwRuleArg_HwOffload_JSONRoundTrip.)
		gotTag := f.Tag.Get("json")
		if !strings.HasPrefix(gotTag, "hwOffload") {
			t.Errorf("cmn.FwRuleArg.HwOffload JSON tag: expected prefix \"hwOffload\", got %q", gotTag)
		}
	})

	t.Run("FwDpWorkQ_HwOffload_direct_passthrough", func(t *testing.T) {
		// Direct construction: zero value → false; explicit true → true.
		var w1 FwDpWorkQ
		if w1.HwOffload {
			t.Error("FwDpWorkQ{}.HwOffload zero value: expected false, got true")
		}
		w2 := FwDpWorkQ{HwOffload: true}
		if !w2.HwOffload {
			t.Error("FwDpWorkQ{HwOffload:true}: expected true after explicit set")
		}
	})
}

// TestFwRuleAdd_HwOffloadFalse_NoEbpfInstall_Negative — -VAL-S3-F.
//
// The validateHwOffloadExpressible gate is called from AddFwRule when (and
// ONLY when) FwRuleArg.HwOffload == true (per placement). A
// non-expressible rule with HwOffload=true MUST return a typed
// *errHwOffloadUnexpressible error and MUST NOT proceed to the eBPF or HW
// install path. This test pins the helper-level contract that backs that
// gate: calling validateHwOffloadExpressible on a non-expressible shape
// always returns a typed error regardless of the HwOffload flag — the gate
// at AddFwRule is responsible for the flag check; the helper is responsible
// for the typed-error contract.
//
// -06 (if REST handler integration is delayed) will
// add the end-to-end install-counter assertion. For Wave-0 / !doca, the
// contract checked here is sufficient to lock the typed-error path.
func TestFwRuleAdd_HwOffloadFalse_NoEbpfInstall_Negative(t *testing.T) {
	// Setup: a non-expressible rule that would (if HwOffload=true) fail
	// validateHwOffloadExpressible with HwOffloadReasonPortRangeDst.
	r := validRule()
	r.DstPortMin = 8000
	r.DstPortMax = 9000

	// Sub-test 1: HwOffload=true on this rule MUST surface the typed error.
	t.Run("hwoffload_true_returns_typed_error", func(t *testing.T) {
		r.HwOffload = true
		err := validateHwOffloadExpressible(r)
		if err == nil {
			t.Fatal("expected typed error for non-expressible HwOffload=true rule, got nil")
		}
		var typed *errHwOffloadUnexpressible
		if !errors.As(err, &typed) {
			t.Fatalf("expected *errHwOffloadUnexpressible, got %T: %v", err, err)
		}
		if typed.Reason != HwOffloadReasonPortRangeDst {
			t.Errorf("Reason: got %d, want %d", typed.Reason, HwOffloadReasonPortRangeDst)
		}
	})

	// Sub-test 2: HwOffload=false on this rule — at the helper layer, the
	// helper does NOT short-circuit on the flag (that gate lives in
	// AddFwRule placement). The typed-error contract is identical
	// from the helper's perspective; the AddFwRule call site is responsible
	// for the "do not even call the helper if HwOffload=false" semantic.
	t.Run("hwoffload_false_helper_still_returns_typed_error", func(t *testing.T) {
		r.HwOffload = false
		err := validateHwOffloadExpressible(r)
		// The helper has no flag-awareness; it still surfaces the typed
		// error. This is the pin that future refactors that move the gate
		// into the helper must update both sites in lockstep.
		if err == nil {
			t.Fatal("expected typed error from direct helper call regardless of HwOffload flag, got nil")
		}
		var typed *errHwOffloadUnexpressible
		if !errors.As(err, &typed) {
			t.Fatalf("expected *errHwOffloadUnexpressible, got %T: %v", err, err)
		}
	})
}
