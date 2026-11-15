/*
 * Copyright (c) 2026 LoxiLB Authors
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

package loxinet

import (
	"sync"
	"testing"
)

// attached() is the datapath truth behind both the policy GET's "attached"
// field and the loxilb_policer_attached gauge: a policer counts as attached
// only when the policer object and every attachment point are in sync. Any
// pending re-drive means it currently shapes nothing.
func TestPolEntryAttachedTruthTable(t *testing.T) {
	tests := []struct {
		name     string
		entry    PolEntry
		attached bool
	}{
		{
			name:     "no attachment object shapes nothing",
			entry:    PolEntry{},
			attached: false,
		},
		{
			name: "policer object itself pending",
			entry: PolEntry{
				Sync:  1,
				PObjs: []PolObjInfo{{}},
			},
			attached: false,
		},
		{
			name: "attachment pending re-drive (target absent)",
			entry: PolEntry{
				PObjs: []PolObjInfo{{Sync: 1}},
			},
			attached: false,
		},
		{
			name: "one of several attachments pending",
			entry: PolEntry{
				PObjs: []PolObjInfo{{Sync: 0}, {Sync: 1}},
			},
			attached: false,
		},
		{
			name: "policer and every attachment programmed",
			entry: PolEntry{
				PObjs: []PolObjInfo{{Sync: 0}, {Sync: 0}},
			},
			attached: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.entry.attached(); got != tc.attached {
				t.Fatalf("attached() = %v, want %v", got, tc.attached)
			}
		})
	}
}

// The datapath worker completes independently of the routine lock. Its status
// publication must be safe while GET/metrics evaluate attachment truth.
func TestPolicerConcurrentDatapathCompletion(t *testing.T) {
	entry := &PolEntry{Sync: 1, PObjs: []PolObjInfo{{}}}
	work := &PolDpWorkQ{Status: &entry.Sync}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			work.setStatus(DpCreateErr)
			work.setStatus(0)
		}
	}()
	for i := 0; i < 10000; i++ {
		entry.attached()
	}
	wg.Wait()
	work.setStatus(DpCreateErr)
	if entry.attached() {
		t.Fatal("failed policer was reported attached")
	}
	work.setStatus(0)
	if !entry.attached() {
		t.Fatal("completed policer attachment was not published")
	}
}
