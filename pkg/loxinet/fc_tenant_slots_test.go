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

package loxinet

import (
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

func TestFcTenantSlotsFromEnv(t *testing.T) {
	for _, c := range []struct {
		env  string
		want int
	}{
		{"", cmn.FcTenantSlotsDefault},
		{"many", cmn.FcTenantSlotsDefault},
		{"-5", cmn.FcTenantSlotsDefault},
		{"0", cmn.FcTenantSlotsMin},
		{"1", cmn.FcTenantSlotsMin},
		{"300", 300},
		{"1024", 1024},
		{"999999", cmn.FcTenantSlotsMax},
	} {
		t.Setenv("LLB_FC_TENANT_SLOTS", c.env)
		if got := fcTenantSlotsFromEnv(); got != c.want {
			t.Errorf("LLB_FC_TENANT_SLOTS=%q: got %d, want %d", c.env, got, c.want)
		}
	}
}

func TestFcTenantSlotsWarning(t *testing.T) {
	t.Setenv("LLB_FC_TENANT_MAX_SHARE_PCT", "")
	share := &cmn.LbServiceArg{FcTenantMaxSharePct: 25}
	none := &cmn.LbServiceArg{}
	full := &cmn.LbServiceArg{FcTenantMaxSharePct: 100}

	if msg := fcTenantSlotsWarning(share, 256, 256); msg != "" {
		t.Errorf("as many tenants as slots: got %q, want no warning", msg)
	}
	msg := fcTenantSlotsWarning(share, 300, 256)
	for _, want := range []string{"fc_tenant_max_share_pct", "300 tenants", "tracks 256", "LLB_FC_TENANT_SLOTS"} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning %q does not name %q", msg, want)
		}
	}
	// No share, no table: nothing to warn about, whatever the count.
	for _, serv := range []*cmn.LbServiceArg{none, full} {
		if msg := fcTenantSlotsWarning(serv, 100000, 64); msg != "" {
			t.Errorf("share %d: got %q, want no warning", serv.FcTenantMaxSharePct, msg)
		}
	}
	// A rule that leaves the share to the environment is warned on its value.
	t.Setenv("LLB_FC_TENANT_MAX_SHARE_PCT", "10")
	if msg := fcTenantSlotsWarning(none, 300, 256); msg == "" {
		t.Error("share from the environment: got no warning")
	}
}

func TestFcTenantSlotsWarningNeedsAStore(t *testing.T) {
	saved := mh.AIKeyService.Load()
	defer func() { mh.AIKeyService.Store(saved) }()
	mh.AIKeyService.Store(nil)
	na := &NetAPIStruct{}
	lm := &cmn.LbRuleMod{Serv: cmn.LbServiceArg{FcTenantMaxSharePct: 25}}
	if msg := na.NetFcTenantSlotsWarning(lm); msg != "" {
		t.Errorf("no key store: got %q, want no warning", msg)
	}
	if msg := na.NetFcTenantSlotsWarning(nil); msg != "" {
		t.Errorf("nil rule: got %q, want no warning", msg)
	}
}

// An environment share past 32 bits reads as no share, like any value over
// 100; it must not be narrowed to its low bits and come back as a share.
func TestFcTenantShareWantedBoundsTheEnvironment(t *testing.T) {
	serv := &cmn.LbServiceArg{}
	for _, tc := range []struct {
		env  string
		want uint32
	}{
		{"10", 10},
		{"99", 99},
		{"100", 0},
		{"101", 0},
		{"4294967306", 0}, // 2^32 + 10
		{"-5", 0},
		{"x", 0},
	} {
		t.Setenv("LLB_FC_TENANT_MAX_SHARE_PCT", tc.env)
		if got := fcTenantShareWanted(serv); got != tc.want {
			t.Errorf("LLB_FC_TENANT_MAX_SHARE_PCT=%s: share %d, want %d", tc.env, got, tc.want)
		}
	}
}
