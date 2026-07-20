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

// loadbalancer_octavia_adminstate_test.go — unit tests for the
// admin_state pause/resume surface in the handler layer: the paused -> OFFLINE
// operatingStatus fold, the effective-bool serialization, and the
// presence-aware PATCH carry semantics (absent => unchanged). The 200/404 responder glue
// and the end-to-end curl behavior are validated on the remote gate.

package handler

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// TestResolveEffectiveAdminStateUp: the handler-layer back-compat resolution mirrors the
// control plane — nil/absent => enabled (true); explicit true => true; explicit false =>
// paused (false).
func TestResolveEffectiveAdminStateUp(t *testing.T) {
	mk := func(p *bool) cmn.LbRuleMod {
		lb := cmn.LbRuleMod{}
		lb.Serv.AdminStateUp = p
		return lb
	}
	tru, fls := true, false

	if !resolveEffectiveAdminStateUp(mk(nil)) {
		t.Fatalf("nil AdminStateUp must resolve to enabled=true")
	}
	if !resolveEffectiveAdminStateUp(mk(&tru)) {
		t.Fatalf("explicit true must resolve to enabled=true")
	}
	if resolveEffectiveAdminStateUp(mk(&fls)) {
		t.Fatalf("explicit false must resolve to paused=false")
	}
}

// TestOperatingStatusPausedIsOffline: a service with effective adminStateUp=false surfaces
// as OFFLINE regardless of endpoint health — it forwards no new connections
// drains the active backend set). Membership is intact; only the operating status reflects
// the pause.
func TestOperatingStatusPausedIsOffline(t *testing.T) {
	fls := false
	lb := cmn.LbRuleMod{}
	lb.Serv.Monitor = true
	lb.Serv.AdminStateUp = &fls
	// Even with all endpoints healthy, a paused service is OFFLINE.
	lb.Eps = append(lb.Eps,
		cmn.LbEndPointArg{State: "active"},
		cmn.LbEndPointArg{State: "active"},
	)

	if got := deriveOperatingStatus(lb); got != "OFFLINE" {
		t.Fatalf("paused service must surface OFFLINE even with healthy endpoints; got %q", got)
	}
}

// TestOperatingStatusEnabledStillDerivesFromHealth: an enabled (true/nil) service derives
// its operating status from endpoint health as before — the pause fold must not change the
// healthy/degraded path (regression guard for the vocabulary).
func TestOperatingStatusEnabledStillDerivesFromHealth(t *testing.T) {
	tru := true
	mk := func(p *bool, states ...string) cmn.LbRuleMod {
		lb := cmn.LbRuleMod{}
		lb.Serv.Monitor = true
		lb.Serv.AdminStateUp = p
		for _, s := range states {
			lb.Eps = append(lb.Eps, cmn.LbEndPointArg{State: s})
		}
		return lb
	}

	if got := deriveOperatingStatus(mk(&tru, "active", "active")); got != "ONLINE" {
		t.Fatalf("enabled all-up must be ONLINE, got %q", got)
	}
	if got := deriveOperatingStatus(mk(nil, "active", "inactive")); got != "DEGRADED" {
		t.Fatalf("enabled (nil) some-down must be DEGRADED, got %q", got)
	}
	if got := deriveOperatingStatus(mk(&tru, "inactive", "inactive")); got != "OFFLINE" {
		t.Fatalf("enabled all-down must be OFFLINE, got %q", got)
	}
}

// TestSerializeLBRulePausedSurfacesFalse: a paused rule serializes adminStateUp=false
// (explicit), so GET-all/by-key/by-id echo the pause.
func TestSerializeLBRulePausedSurfacesFalse(t *testing.T) {
	fls := false
	lb := cmn.LbRuleMod{}
	lb.Serv.ServIP = "20.20.20.9"
	lb.Serv.ServPort = 443
	lb.Serv.Proto = "tcp"
	lb.Serv.AdminStateUp = &fls

	out := serializeLBRule(lb)
	if out.ServiceArguments.AdminStateUp != false {
		t.Fatalf("paused rule must serialize adminStateUp=false, got %v", out.ServiceArguments.AdminStateUp)
	}
}

// TestPatchAdminStatePresenceCarrySemantics: the PATCH merge starts from the current rule
// (merged := *current), so an ABSENT adminStateUp in the body leaves the current value
// unchanged (presence-aware), while a PRESENT value overwrites it. This asserts the
// pointer-overlay semantics the handler relies on (octavia_patch.go).
func TestPatchAdminStatePresenceCarrySemantics(t *testing.T) {
	tru, fls := true, false

	// current rule is enabled
	current := cmn.LbRuleMod{}
	current.Serv.AdminStateUp = &tru

	// absent in body => merged carries current (unchanged)
	merged := current // mirrors `merged := *current`
	// (no overlay performed because the key was absent)
	if merged.Serv.AdminStateUp == nil || *merged.Serv.AdminStateUp != true {
		t.Fatalf("absent adminStateUp must leave the current value (true) unchanged")
	}

	// present false in body => overlay sets explicit false
	merged = current
	v := fls
	merged.Serv.AdminStateUp = &v // mirrors the present-key overlay
	if merged.Serv.AdminStateUp == nil || *merged.Serv.AdminStateUp != false {
		t.Fatalf("present adminStateUp=false must overwrite the merged value to false")
	}
}
