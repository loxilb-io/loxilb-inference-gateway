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

// An AI gateway service re-runs admission at every keep-alive request and records
// requests from their responses, so an accelerated direction would let later
// requests through unchecked and leave responses unrecorded. Every non-off mode is
// refused, whichever of the three inputs makes the service an AI gateway.
func TestLbSockMapAiGwCodeRefused(t *testing.T) {
	aiGw := map[string]func(*cmn.LbServiceArg) string{
		"sse_mode":                   func(s *cmn.LbServiceArg) string { s.SSEMode = true; return "" },
		"pd_disagg_mode":             func(s *cmn.LbServiceArg) string { s.PDDisaggMode = true; return "" },
		"api_key_auth=required":      func(s *cmn.LbServiceArg) string { return cmn.ApiKeyAuthRequired },
		"api_key_auth=jwt":           func(s *cmn.LbServiceArg) string { return cmn.ApiKeyAuthJWT },
		"api_key_auth=apikey-or-jwt": func(s *cmn.LbServiceArg) string { return cmn.ApiKeyAuthApiKeyOrJWT },
	}
	for name, mutate := range aiGw {
		for mode, code := range map[string]uint8{"both": 1, "request": 2, "response": 3} {
			serv := sockMapServ(mode)
			apiKeyAuth := mutate(&serv)
			got, err := lbSockMapAiGwCode(&serv, code, apiKeyAuth)
			if !errors.Is(err, errSockMapAiGateway) || got != 0 {
				t.Fatalf("%s, mode %s: want errSockMapAiGateway and code 0, got %d err %v", name, mode, got, err)
			}
		}
	}
}

// A service that is not an AI gateway keeps its mode, and off is valid on any service.
func TestLbSockMapAiGwCodeAllowed(t *testing.T) {
	for _, apiKeyAuth := range []string{"", cmn.ApiKeyAuthDisabled} {
		serv := sockMapServ("request")
		if got, err := lbSockMapAiGwCode(&serv, 2, apiKeyAuth); err != nil || got != 2 {
			t.Fatalf("api_key_auth %q: want code 2, got %d err %v", apiKeyAuth, got, err)
		}
	}

	serv := sockMapServ("off")
	serv.SSEMode = true
	if got, err := lbSockMapAiGwCode(&serv, 0, cmn.ApiKeyAuthRequired); err != nil || got != 0 {
		t.Fatalf("off on an AI gateway service: want code 0, got %d err %v", got, err)
	}
}

// The check follows the api_key_auth the rule will carry, not the incoming field. A
// replace that omits api_key_auth keeps enforcement on (apiKeyAuthOnReplace), so an
// empty incoming value must not let acceleration through on a protected service.
func TestLbSockMapAiGwCodeUsesResolvedApiKeyAuth(t *testing.T) {
	serv := sockMapServ("both") // incoming api_key_auth omitted
	resolved := apiKeyAuthOnReplace(cmn.ApiKeyAuthRequired, serv.ApiKeyAuth)
	if _, err := lbSockMapAiGwCode(&serv, 1, resolved); !errors.Is(err, errSockMapAiGateway) {
		t.Fatalf("replace omitting api_key_auth on a protected service: want errSockMapAiGateway, got %v", err)
	}
}

// A snapshot restore must not fail, since an error aborts the whole loadbalancer
// domain. The rule is restored with acceleration off.
func TestLbSockMapAiGwCodeRestoreReplay(t *testing.T) {
	serv := sockMapServ("request")
	serv.SSEMode = true
	serv.RestoreReplay = true
	if got, err := lbSockMapAiGwCode(&serv, 2, ""); err != nil || got != 0 {
		t.Fatalf("restore replay of an AI gateway service: want code 0 and no error, got %d err %v", got, err)
	}
}
