/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package snapshot

import "testing"

// TestApplyLoadBalancerMarksRestoreReplay: every rule replayed by the
// loadbalancer domain must carry the RestoreReplay flag. A strict KV-exact
// rule keys binding allocation off it — a replay that looked like a fresh
// POST would allocate a new binding generation and collide with the
// authoritative kvexactbinding domain applied right after (losing the
// allocation high-water mark that prevents generation reuse).
func TestApplyLoadBalancerMarksRestoreReplay(t *testing.T) {
	hooks := newMockHooks()
	doc := restoreDoc("0.9.8.6-beta")

	e := &Engine{Hooks: hooks}
	errs, _ := e.stageApply(doc, ApplyOrder(), false)
	if len(errs) != 0 {
		t.Fatalf("stageApply: %v", errs)
	}

	found := false
	for _, r := range hooks.lbRules {
		found = true
		if !r.Serv.RestoreReplay {
			t.Fatalf("replayed rule %s:%d reached NetLbRuleAdd without RestoreReplay", r.Serv.ServIP, r.Serv.ServPort)
		}
	}
	if !found {
		t.Fatal("restore doc replayed no loadbalancer rules — the assertion never ran")
	}
}
