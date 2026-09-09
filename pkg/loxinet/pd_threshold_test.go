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
package loxinet

import "testing"

func TestPDThresholdOnReplace(t *testing.T) {
	cases := []struct {
		name              string
		current, incoming uint8
		present           bool
		want              uint8
	}{
		{name: "omission retains positive", current: 55, want: 55},
		{name: "omission retains zero", current: 0, want: 0},
		{name: "explicit zero resets", current: 55, present: true, want: 0},
		{name: "explicit positive replaces", current: 55, incoming: 40, present: true, want: 40},
		{name: "legacy positive remains update", current: 55, incoming: 40, want: 40},
		{name: "legacy zero remains omission", current: 55, want: 55},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pdThresholdOnReplace(tc.current, tc.incoming, tc.present); got != tc.want {
				t.Fatalf("pdThresholdOnReplace(%d,%d,%v)=%d, want %d", tc.current, tc.incoming, tc.present, got, tc.want)
			}
		})
	}
}

func TestPDThresholdEffectiveValues(t *testing.T) {
	if got := pdCacheThresholdEffective(0); got != 20 {
		t.Fatalf("cache declared zero effective=%d, want 20", got)
	}
	if got := pdBalanceAbsThresholdEffective(0); got != 3 {
		t.Fatalf("balance declared zero effective=%d, want 3", got)
	}
	for _, value := range []uint8{1, 20, 47, 100} {
		if got := pdCacheThresholdEffective(value); got != value {
			t.Fatalf("cache declared %d effective=%d", value, got)
		}
	}
	for _, value := range []uint8{1, 3, 9, 255} {
		if got := pdBalanceAbsThresholdEffective(value); got != value {
			t.Fatalf("balance declared %d effective=%d", value, got)
		}
	}
}
