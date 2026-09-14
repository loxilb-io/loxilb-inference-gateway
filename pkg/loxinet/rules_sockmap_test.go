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
