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

// ipv6_brackets_test.go — unit tests for the server-side IPv6
// bracket-strip. stripV6Brackets (DEFINED in) is now applied across all 6
// composite-key LB paths; these tests pin (1) the strip normalization (bracketed IPv6 -> bare,
// IPv4/bare unchanged), (2) bracketed-IPv6 lookup resolution through findLBRuleByKey (the
// central site every GET/status caller routes through), and (3) malformed-param rejection
// (a non-IP path param resolves to no rule rather than silently mis-matching).
//
// These tests run on the remote/AWS gate: the handler package compiles only against the
// go-swagger-regenerated operations/models and the Linux cgo/loxinet backing — darwin cannot
// compile this package (the same deferral as every/73 handler test). The
// stubLbGetHook one-method NetLbRuleGet stub is shared from
// loadbalancer_octavia_datamodel_test.go (same package).

package handler

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// mkV6Rule builds an LB rule whose ServIP is stored UNBRACKETED (net.IP.String form), the
// way the data path stores it, so a bracketed path param only resolves via the strip.
func mkV6Rule(ip string, port uint16, proto string) cmn.LbRuleMod {
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = ip
	lb.Serv.ServPort = port
	lb.Serv.Proto = proto
	return lb
}

// TestStripV6BracketsNormalizes: the strip removes RFC brackets from an IPv6 literal and is a
// no-op for bare IPv6 and for IPv4 (idempotent), which is what keeps IPv4 lookups byte-identical.
func TestStripV6BracketsNormalizes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"[2001:db8::1]", "2001:db8::1"}, // bracketed IPv6 -> bare
		{"2001:db8::1", "2001:db8::1"},   // bare IPv6 unchanged
		{"[fe80::1]", "fe80::1"},         // link-local bracketed -> bare
		{"10.0.0.1", "10.0.0.1"},         // IPv4 unchanged (Trim is a no-op)
		{"192.168.1.254", "192.168.1.254"},
	}
	for _, c := range cases {
		if got := stripV6Brackets(c.in); got != c.want {
			t.Errorf("stripV6Brackets(%q): want %q, got %q", c.in, c.want, got)
		}
	}
}

// TestFindLBRuleByKeyResolvesBracketedIPv6: a rule whose ServIP is stored bare ("2001:db8::1")
// is resolved by findLBRuleByKey when addressed with the RFC-bracketed form ("[2001:db8::1]").
// findLBRuleByKey strips the brackets BEFORE the raw == ServIP compare, so the rule resolves
// (non-nil) instead of 404ing — covering every GET/status caller routed through it.
func TestFindLBRuleByKeyResolvesBracketedIPv6(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	ApiHooks = &stubLbGetHook{rules: []cmn.LbRuleMod{
		mkV6Rule("2001:db8::1", 80, "tcp"),
	}}

	lb, err := findLBRuleByKey("[2001:db8::1]", 80, "tcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lb == nil {
		t.Fatalf("bracketed IPv6 key must resolve the bare-stored rule (no 404), got nil")
	}
	if lb.Serv.ServIP != "2001:db8::1" {
		t.Errorf("resolved the wrong rule: ServIP=%q", lb.Serv.ServIP)
	}
}

// TestFindLBRuleByKeyBareIPv6StillResolves: the strip must not regress the already-working
// bare-IPv6 path — a bare path param resolves the bare-stored rule.
func TestFindLBRuleByKeyBareIPv6StillResolves(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	ApiHooks = &stubLbGetHook{rules: []cmn.LbRuleMod{
		mkV6Rule("2001:db8::1", 80, "tcp"),
	}}

	lb, err := findLBRuleByKey("2001:db8::1", 80, "tcp")
	if err != nil || lb == nil {
		t.Fatalf("bare IPv6 key must still resolve (err=%v, lb=%v)", err, lb)
	}
}

// TestFindLBRuleByKeyRejectsMalformed: a malformed/non-IP path param does NOT silently
// mis-match a stored rule — it resolves to no rule (nil), the 404 path. Even after
// bracket-strip the garbage value cannot equal a stored bare ServIP.
func TestFindLBRuleByKeyRejectsMalformed(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	ApiHooks = &stubLbGetHook{rules: []cmn.LbRuleMod{
		mkV6Rule("2001:db8::1", 80, "tcp"),
	}}

	for _, bad := range []string{"[not-an-ip]", "2001:db8::zzzz", "]["} {
		lb, err := findLBRuleByKey(bad, 80, "tcp")
		if err != nil {
			t.Fatalf("malformed param %q: unexpected error %v", bad, err)
		}
		if lb != nil {
			t.Errorf("malformed param %q must not mis-match a stored rule, got ServIP=%q", bad, lb.Serv.ServIP)
		}
	}
}

// TestFindLBRuleByKeyIPv4Unaffected: IPv4 lookups are byte-identical after the strip (Trim is
// a no-op for bare IPv4), so the existing IPv4 composite-key resolution is unchanged.
func TestFindLBRuleByKeyIPv4Unaffected(t *testing.T) {
	prev := ApiHooks
	defer func() { ApiHooks = prev }()

	ApiHooks = &stubLbGetHook{rules: []cmn.LbRuleMod{
		mkV6Rule("20.20.20.10", 80, "tcp"),
	}}

	lb, err := findLBRuleByKey("20.20.20.10", 80, "tcp")
	if err != nil || lb == nil {
		t.Fatalf("IPv4 key must resolve unchanged (err=%v, lb=%v)", err, lb)
	}
}
