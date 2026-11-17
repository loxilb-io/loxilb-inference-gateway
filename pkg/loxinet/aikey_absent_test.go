/*
 * Copyright (c) 2025 LoxiLB Authors
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
	"context"
	"errors"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
)

// A nil key store is two different situations, and the API renders them
// differently on purpose: no store was configured, or a configured store has
// not been reached yet. Telling an operator the first when the second is true
// sends them to look for a missing flag instead of at a database that is down.
//
// The pointer cannot make that distinction. loxiNetInit builds the store
// partway through a much longer initialisation and the REST listener is already
// answering before it gets there, so early in every boot the pointer is nil on
// a gateway that is configured. These legs pin the decision to the option,
// which is what the operator actually set.
func TestAbsentKeyStoreDistinguishesUnconfiguredFromUnreachable(t *testing.T) {
	if mh.AIKeyService.Load() != nil {
		t.Fatal("a key store is constructed in this test process; these legs are about the window in which none is")
	}
	saved := opts.Opts.AIKeyDBHost
	t.Cleanup(func() { opts.Opts.AIKeyDBHost = saved })

	var na NetAPIStruct
	enabled := false
	classStd := cmn.AIClassStandard

	// Every hook that can be reached before the store exists. Naming them
	// individually rather than testing one is the point: a hook added later
	// that returns the bare sentinel would pass a single-hook test.
	calls := map[string]func() error{
		"NetAPIKeyCreate": func() error {
			_, err := na.NetAPIKeyCreate(context.Background(), cmn.ApiKeyEntry{TenantID: "t"})
			return err
		},
		"NetAPIKeyList":         func() error { _, err := na.NetAPIKeyList(context.Background(), ""); return err },
		"NetAPIKeyGet":          func() error { _, err := na.NetAPIKeyGet(context.Background(), "k"); return err },
		"NetAPIKeyRevoke":       func() error { return na.NetAPIKeyRevoke(context.Background(), "k") },
		"NetAPIKeyDelete":       func() error { return na.NetAPIKeyDelete(context.Background(), "k") },
		"NetAPIKeyPatch":        func() error { return na.NetAPIKeyPatch(context.Background(), "k", cmn.ApiKeyPatch{Enabled: &enabled}) },
		"NetTenantRateLimitSet": func() error { return na.NetTenantRateLimitSet(context.Background(), "t", 1, 1, 1, nil) },
		"NetTenantRateLimitGet": func() error { _, err := na.NetTenantRateLimitGet(context.Background(), "t"); return err },
		"NetAPIKeyRateLimitPatch": func() error {
			one := 1
			return na.NetAPIKeyPatch(context.Background(), "k", cmn.ApiKeyPatch{RateLimitRPS: &one})
		},
		"NetUserRateLimitSet": func() error {
			return na.NetUserRateLimitSet(context.Background(), cmn.UserRateLimitEntry{TenantID: "t", UserID: "u", RPS: 1})
		},
		"NetUserRateLimitGet":    func() error { _, err := na.NetUserRateLimitGet(context.Background(), "t", "u"); return err },
		"NetUserRateLimitList":   func() error { _, err := na.NetUserRateLimitList(context.Background(), "t"); return err },
		"NetUserRateLimitDelete": func() error { return na.NetUserRateLimitDelete(context.Background(), "t", "u") },
		"NetRateLimitDefaultsSet": func() error {
			return na.NetRateLimitDefaultsSet(context.Background(), cmn.RateLimitDefaultsEntry{Scope: cmn.RateLimitScopeGlobal, DefaultUserRPS: 1})
		},
		"NetRateLimitDefaultsGet": func() error {
			_, err := na.NetRateLimitDefaultsGet(context.Background(), cmn.RateLimitScopeGlobal, "")
			return err
		},
		"NetRateLimitDefaultsDelete": func() error { return na.NetRateLimitDefaultsDelete(context.Background(), cmn.RateLimitScopeGlobal, "") },
		"NetAIObjectiveGet":          func() error { _, err := na.NetAIObjectiveGet(context.Background()); return err },
		"NetAIObjectiveAdd": func() error {
			_, err := na.NetAIObjectiveAdd(context.Background(), &cmn.AIObjectiveEntry{Name: "o", Priority: 1})
			return err
		},
		"NetAIObjectiveDel": func() error { _, err := na.NetAIObjectiveDel(context.Background(), "o"); return err },
		"NetTenantClassPatch": func() error {
			return na.NetTenantClassPatch(context.Background(), "t", cmn.AIClassPatch{PriorityClass: &classStd})
		},
		"NetAPIKeyClassPatch": func() error {
			return na.NetAPIKeyPatch(context.Background(), "k", cmn.ApiKeyPatch{Class: cmn.AIClassPatch{PriorityClass: &classStd}})
		},
	}

	opts.Opts.AIKeyDBHost = ""
	for name, call := range calls {
		if err := call(); !errors.Is(err, cmn.ErrKeyStoreUnconfigured) {
			t.Errorf("%s with no store configured = %v, want ErrKeyStoreUnconfigured", name, err)
		}
	}

	opts.Opts.AIKeyDBHost = "store.invalid"
	for name, call := range calls {
		err := call()
		if !errors.Is(err, cmn.ErrDBUnavailable) {
			t.Errorf("%s with a configured store not yet reachable = %v, want ErrDBUnavailable", name, err)
		}
		if errors.Is(err, cmn.ErrKeyStoreUnconfigured) {
			t.Errorf("%s told the caller no store was configured when --aikey-db-host is set", name)
		}
	}
}
