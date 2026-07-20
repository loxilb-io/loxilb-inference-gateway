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

// This file (wipe.go) covers task G-6: a registry-driven full-config wipe,
// replacing the per-domain delete logic of the legacy
// api/restapi/handler/backup.go:302 DeleteAllConfiguration. It is used both
// standalone (a future deprecation-alias wiring, task G-4) and by the
// restore engine (restore.go, task G-2) for the pre-apply wipe and the
// rollback path (§5.3).
package snapshot

import (
	"errors"
	"fmt"
)

// WipeItem is the per-domain outcome of one Wipe call: how many items were
// deleted for that domain and the first error encountered deleting it (nil
// on full success). Domains are reported in delete order (DeleteOrder,
// §4.1: the exact reverse of ApplyOrder).
type WipeItem struct {
	Domain  string
	Deleted int
	Err     error
}

// Wipe deletes every live item in the domains selected by components (nil
// or empty selects every v1 domain -- see Select) via each DomainEntry's
// Delete function, in delete order (reverse of ApplyOrder: e.g. loadbalancer
// before endpoint, since LB rules reference endpoints).
//
// Cluster/HA state is never touched: it is not part of Registry at all
// (§4.1 "Deliberately excluded"), so no components value can cause Wipe to
// reach it -- this mirrors and makes symmetric the legacy
// DeleteAllConfiguration's implicit cluster-skip (backup.go:344, "Note :
// Cluster configurations are not deleted").
//
// Firewall's SrcChk-mark (0x40000000) exclusion is preserved because Wipe
// delegates to the registry's deleteFirewall (registry.go), which already
// filters those rules out before deleting (mirroring backup.go:228's
// GetFirewallConfig behavior) -- Wipe does not need, and does not
// duplicate, that filtering itself.
//
// A wipe must attempt everything: per-item/per-domain delete errors are
// collected, not fatal mid-wipe. Wipe always calls every selected domain's
// Delete function, even after an earlier domain failed, and returns the
// full per-domain breakdown (results) alongside a combined error (via
// errors.Join; nil if every domain deleted cleanly) so callers can either
// inspect results in detail or treat the call as pass/fail via the error.
//
// The restore engine (restore.go) treats ANY non-nil error returned here
// (during its pre-apply wipe) as fatal to the APPLY stage and transitions
// straight to ROLLBACK -- that is a decision made by the caller, not by
// Wipe itself, which always finishes the full pass regardless.
func Wipe(hooks Hooks, components []string) ([]WipeItem, error) {
	entries, err := Select(components)
	if err != nil {
		return nil, fmt.Errorf("snapshot: wipe: %w", err)
	}

	ordered := reverse(entries)
	results := make([]WipeItem, 0, len(ordered))
	var errs []error
	for _, e := range ordered {
		n, derr := e.Delete(hooks)
		results = append(results, WipeItem{Domain: e.Name, Deleted: n, Err: derr})
		if derr != nil {
			errs = append(errs, fmt.Errorf("wipe %s: %w", e.Name, derr))
		}
	}
	return results, errors.Join(errs...)
}

// reverse returns a new slice with entries in the opposite order. Used to
// turn Select's apply-order result into delete order without re-deriving it
// from the full Registry (equivalent to filtering DeleteOrder() by the same
// components, since reversing preserves the relative order of a filtered
// subsequence either way).
func reverse(entries []DomainEntry) []DomainEntry {
	out := make([]DomainEntry, len(entries))
	for i, e := range entries {
		out[len(entries)-1-i] = e
	}
	return out
}
