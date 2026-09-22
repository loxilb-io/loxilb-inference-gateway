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
package utils

import "testing"

// PeekMarker names the marker GetMarker hands out next, follows the
// allocator's free-list order (freed markers first), and fails when the
// allocator is exhausted.
func TestPeekMarkerFollowsGetMarker(t *testing.T) {
	m := NewMarker(10, 3)
	for i := 0; i < 3; i++ {
		peek, err := m.PeekMarker()
		if err != nil {
			t.Fatalf("peek %d: %v", i, err)
		}
		got, err := m.GetMarker()
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if got != peek {
			t.Fatalf("peek said %d, get gave %d", peek, got)
		}
	}
	if _, err := m.PeekMarker(); err == nil {
		t.Fatal("peek on an exhausted marker must fail")
	}
	if err := m.ReleaseMarker(11); err != nil {
		t.Fatal(err)
	}
	peek, err := m.PeekMarker()
	if err != nil || peek != 11 {
		t.Fatalf("after release peek = %d, %v; want the freed marker 11", peek, err)
	}
	if got, _ := m.GetMarker(); got != 11 {
		t.Fatalf("get after release = %d, want 11", got)
	}
}
