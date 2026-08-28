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
	if mh.AIKeyService != nil {
		t.Fatal("a key store is constructed in this test process; these legs are about the window in which none is")
	}
	saved := opts.Opts.AIKeyDBHost
	t.Cleanup(func() { opts.Opts.AIKeyDBHost = saved })

	var na NetAPIStruct
	enabled := false

	// Every hook that can be reached before the store exists. Naming them
	// individually rather than testing one is the point: a hook added later
	// that returns the bare sentinel would pass a single-hook test.
	calls := map[string]func() error{
		"NetAPIKeyCreate":       func() error { _, _, err := na.NetAPIKeyCreate(cmn.ApiKeyEntry{TenantID: "t"}); return err },
		"NetAPIKeyList":         func() error { _, err := na.NetAPIKeyList(""); return err },
		"NetAPIKeyGet":          func() error { _, err := na.NetAPIKeyGet("k"); return err },
		"NetAPIKeyRevoke":       func() error { return na.NetAPIKeyRevoke("k") },
		"NetAPIKeyDelete":       func() error { return na.NetAPIKeyDelete("k") },
		"NetAPIKeyPatch":        func() error { return na.NetAPIKeyPatch("k", nil, &enabled) },
		"NetTenantRateLimitSet": func() error { return na.NetTenantRateLimitSet("t", 1, 1, 1, nil) },
		"NetTenantRateLimitGet": func() error { _, err := na.NetTenantRateLimitGet("t"); return err },
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
