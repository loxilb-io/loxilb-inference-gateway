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

package loxinet

import (
	"errors"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func sockMapServ(mode string) cmn.LbServiceArg {
	return cmn.LbServiceArg{
		ServIP:      "10.10.10.254",
		ServPort:    2020,
		Proto:       "tcp",
		Mode:        cmn.LBModeFullProxy,
		Security:    cmn.LBServPlain,
		SockMapMode: mode,
	}
}

func TestLbSockMapCodeModes(t *testing.T) {
	want := map[string]uint8{"": 0, "off": 0, "both": 1, "request": 2, "response": 3}
	for mode, code := range want {
		serv := sockMapServ(mode)
		got, err := lbSockMapCode(&serv, true)
		if err != nil || got != code {
			t.Fatalf("mode %q: want code %d, got %d err %v", mode, code, got, err)
		}
	}

	serv := sockMapServ("sideways")
	if _, err := lbSockMapCode(&serv, true); err == nil {
		t.Fatal("an unknown sockMapMode must be rejected")
	}
}

// Without --sockmapsupport no sockmap BPF assets are loaded, so a request for
// acceleration must be refused instead of being stored and silently ignored.
func TestLbSockMapCodeRequiresDaemonSupport(t *testing.T) {
	for _, mode := range []string{"both", "request", "response"} {
		serv := sockMapServ(mode)
		_, err := lbSockMapCode(&serv, false)
		if err == nil || !strings.Contains(err.Error(), "--sockmapsupport") {
			t.Fatalf("mode %q without daemon support: want a --sockmapsupport error, got %v", mode, err)
		}
	}

	// "off" asks for nothing, so it stays valid on any daemon.
	serv := sockMapServ("off")
	if code, err := lbSockMapCode(&serv, false); err != nil || code != 0 {
		t.Fatalf("mode off without daemon support: want code 0, got %d err %v", code, err)
	}
}

// A snapshot restore on a daemon restarted without the flag must not fail: an error
// there aborts the whole loadbalancer domain. The mode is kept, and the dataplane
// ignores it because the assets are absent.
func TestLbSockMapCodeRestoreReplayWithoutSupport(t *testing.T) {
	serv := sockMapServ("both")
	serv.RestoreReplay = true
	code, err := lbSockMapCode(&serv, false)
	if err != nil || code != 1 {
		t.Fatalf("restore replay without daemon support: want code 1, got %d err %v", code, err)
	}
}

// Eligibility is checked before daemon support, so an ineligible service reports
// what is wrong with the service itself.
func TestLbSockMapCodeEligibility(t *testing.T) {
	cases := map[string]func(*cmn.LbServiceArg){
		"not fullproxy": func(s *cmn.LbServiceArg) { s.Mode = cmn.LBModeFullNAT },
		"udp":           func(s *cmn.LbServiceArg) { s.Proto = "udp" },
		"tls":           func(s *cmn.LbServiceArg) { s.Security = cmn.LBServHTTPS },
		"ipv6 vip":      func(s *cmn.LbServiceArg) { s.ServIP = "2001:db8::1" },
	}
	for name, mutate := range cases {
		for _, support := range []bool{true, false} {
			serv := sockMapServ("both")
			mutate(&serv)
			_, err := lbSockMapCode(&serv, support)
			if err == nil || !strings.Contains(err.Error(), "plaintext tcp fullproxy ipv4") {
				t.Fatalf("%s (support=%v): want eligibility error, got %v", name, support, err)
			}
		}
	}
}

// Every declaration that puts per-request work on the relay path refuses every
// non-off mode. sse_mode and pd_disagg_mode re-run admission at each keep-alive
// request and record requests from their responses; any non-empty api_key_auth
// makes the gateway own the X-Api-Key header and strip it on every request; an
// attached L7 policy rewrites request headers on every request.
func TestLbSockMapL7CodeRefused(t *testing.T) {
	// name -> (mutate serv, api_key_auth, l7Attached)
	perRequest := map[string]struct {
		mutate     func(*cmn.LbServiceArg)
		apiKeyAuth string
		l7Attached bool
	}{
		"sse_mode":                   {mutate: func(s *cmn.LbServiceArg) { s.SSEMode = true }},
		"pd_disagg_mode":             {mutate: func(s *cmn.LbServiceArg) { s.PDDisaggMode = true }},
		"api_key_auth=required":      {apiKeyAuth: cmn.ApiKeyAuthRequired},
		"api_key_auth=jwt":           {apiKeyAuth: cmn.ApiKeyAuthJWT},
		"api_key_auth=apikey-or-jwt": {apiKeyAuth: cmn.ApiKeyAuthApiKeyOrJWT},
		// The case the AI-gateway test could not express: an EXPLICIT "disabled"
		// enforces no credential, so aiGwModeFor reads it as "not an AI gateway",
		// but it still claims the X-Api-Key namespace and the data plane strips
		// the header on every request. An accelerated request direction would
		// carry the tenant's key upstream from the second keep-alive request on.
		"api_key_auth=disabled (explicit)": {apiKeyAuth: cmn.ApiKeyAuthDisabled},
		"l7 policy attached":               {l7Attached: true},
	}
	for name, tc := range perRequest {
		for mode, code := range map[string]uint8{"both": 1, "request": 2, "response": 3} {
			serv := sockMapServ(mode)
			if tc.mutate != nil {
				tc.mutate(&serv)
			}
			got, err := lbSockMapL7Code(&serv, code, tc.apiKeyAuth, tc.l7Attached)
			if !errors.Is(err, errSockMapPerRequestL7) || got != 0 {
				t.Fatalf("%s, mode %s: want errSockMapPerRequestL7 and code 0, got %d err %v",
					name, mode, got, err)
			}
		}
	}
}

// The mirror image: a service that declares nothing keeps its mode. Without this
// the refusal could widen into a blanket ban and nothing would fail.
func TestLbSockMapL7CodeAllowed(t *testing.T) {
	// An OMITTED api_key_auth declares nothing: the data plane touches no header
	// and a backend-owned X-Api-Key passes through untouched, so the rule stays
	// accelerable. This is the one api_key_auth value that does.
	serv := sockMapServ("request")
	if got, err := lbSockMapL7Code(&serv, 2, "", false); err != nil || got != 2 {
		t.Fatalf("api_key_auth omitted: want code 2, got %d err %v", got, err)
	}

	// off asks for nothing, so it is valid on any service.
	serv = sockMapServ("off")
	serv.SSEMode = true
	if got, err := lbSockMapL7Code(&serv, 0, cmn.ApiKeyAuthRequired, true); err != nil || got != 0 {
		t.Fatalf("off on a per-request service: want code 0, got %d err %v", got, err)
	}
}

// sockMapPerRequestL7 must not be confused with aiGwModeFor: they answer
// different questions and disagree on exactly one input. aiGwModeFor arms
// accounting and streaming state; this one decides who owns the header bytes.
func TestSockMapPerRequestL7DivergesFromAiGwMode(t *testing.T) {
	serv := sockMapServ("both")
	if aiGwModeFor(serv.SSEMode, serv.PDDisaggMode, cmn.ApiKeyAuthDisabled) {
		t.Fatal("an explicit api_key_auth=disabled is not an AI gateway service")
	}
	if !sockMapPerRequestL7(&serv, cmn.ApiKeyAuthDisabled, false) {
		t.Fatal("an explicit api_key_auth=disabled still owns X-Api-Key, so it must refuse acceleration")
	}
	// And they agree on an omitted declaration.
	if aiGwModeFor(serv.SSEMode, serv.PDDisaggMode, "") ||
		sockMapPerRequestL7(&serv, "", false) {
		t.Fatal("an omitted api_key_auth declares nothing on either axis")
	}

	// The streaming/disaggregation arm is delegated to aiGwModeFor rather than
	// re-spelled, so it must still answer for those two inputs on their own.
	for name, mutate := range map[string]func(*cmn.LbServiceArg){
		"sse_mode":       func(s *cmn.LbServiceArg) { s.SSEMode = true },
		"pd_disagg_mode": func(s *cmn.LbServiceArg) { s.PDDisaggMode = true },
	} {
		s := sockMapServ("both")
		mutate(&s)
		if !sockMapPerRequestL7(&s, "", false) {
			t.Fatalf("%s alone must refuse acceleration", name)
		}
	}
}

// The check follows the api_key_auth the rule will carry, not the incoming field. A
// replace that omits api_key_auth keeps enforcement on (apiKeyAuthOnReplace), so an
// empty incoming value must not let acceleration through on a protected service.
func TestLbSockMapL7CodeUsesResolvedApiKeyAuth(t *testing.T) {
	serv := sockMapServ("both") // incoming api_key_auth omitted
	resolved := apiKeyAuthOnReplace(cmn.ApiKeyAuthRequired, serv.ApiKeyAuth)
	if _, err := lbSockMapL7Code(&serv, 1, resolved, false); !errors.Is(err, errSockMapPerRequestL7) {
		t.Fatalf("replace omitting api_key_auth on a protected service: want errSockMapPerRequestL7, got %v", err)
	}
}

// A snapshot restore must not fail, since an error aborts the whole loadbalancer
// domain. The rule is restored with acceleration off. This holds for an attached
// L7 policy as well, which is the one input the rule document does not carry.
func TestLbSockMapL7CodeRestoreReplay(t *testing.T) {
	for name, tc := range map[string]struct {
		apiKeyAuth string
		l7Attached bool
		sse        bool
	}{
		"sse_mode":           {sse: true},
		"explicit disabled":  {apiKeyAuth: cmn.ApiKeyAuthDisabled},
		"l7 policy attached": {l7Attached: true},
	} {
		serv := sockMapServ("request")
		serv.SSEMode = tc.sse
		serv.RestoreReplay = true
		if got, err := lbSockMapL7Code(&serv, 2, tc.apiKeyAuth, tc.l7Attached); err != nil || got != 0 {
			t.Fatalf("restore replay (%s): want code 0 and no error, got %d err %v", name, got, err)
		}
	}
}

// The attachment index is what the rule path reads, so its three maintenance
// points must agree: an attach marks, a detach clears, and a deleted rule clears.
func TestL7AttachmentIndex(t *testing.T) {
	vip, port, proto := "10.10.10.254", uint16(2062), "tcp"
	l7ClearAttached(vip, port, proto)
	if l7RuleHasPolicy(vip, port, proto) {
		t.Fatal("a listener with no policy must not be marked attached")
	}
	l7MarkAttached(vip, port, proto)
	if !l7RuleHasPolicy(vip, port, proto) {
		t.Fatal("an attached policy must be visible to the rule path")
	}
	// The key is the attach key: protocol case must not split an entry.
	if !l7RuleHasPolicy(vip, port, "TCP") {
		t.Fatal("the protocol is matched case-insensitively")
	}
	// A different listener is unaffected.
	if l7RuleHasPolicy(vip, port+1, proto) {
		t.Fatal("the index must be per listener")
	}
	l7ClearAttached(vip, port, proto)
	if l7RuleHasPolicy(vip, port, proto) {
		t.Fatal("a detached policy must clear the index")
	}
}

// Which mode changes drop the connections already being accelerated. Adding a
// direction must NOT: an existing connection is never accelerated retroactively,
// so dropping it would cost a client its connection for no gain.
func TestSockMapModeReduces(t *testing.T) {
	const (
		off  = uint8(0)
		both = uint8(1)
		req  = uint8(2)
		resp = uint8(3)
	)
	name := map[uint8]string{off: "off", both: "both", req: "request", resp: "response"}

	reduces := map[[2]uint8]bool{
		// taking a direction away
		{both, off}: true, {both, req}: true, {both, resp}: true,
		{req, off}: true, {req, resp}: true,
		{resp, off}: true, {resp, req}: true,
		// adding one, or no change
		{off, off}: false, {off, both}: false, {off, req}: false, {off, resp}: false,
		{both, both}: false,
		{req, req}:   false, {req, both}: false,
		{resp, resp}: false, {resp, both}: false,
	}
	for pair, want := range reduces {
		if got := sockMapModeReduces(pair[0], pair[1]); got != want {
			t.Fatalf("%s -> %s: want reduces=%v, got %v", name[pair[0]], name[pair[1]], want, got)
		}
	}

	// The direction decomposition the rule above is built from.
	for code, want := range map[uint8][2]bool{
		off: {false, false}, both: {true, true}, req: {true, false}, resp: {false, true},
	} {
		gotReq, gotResp := sockMapDirs(code)
		if gotReq != want[0] || gotResp != want[1] {
			t.Fatalf("%s: want req=%v resp=%v, got req=%v resp=%v",
				name[code], want[0], want[1], gotReq, gotResp)
		}
	}
}
