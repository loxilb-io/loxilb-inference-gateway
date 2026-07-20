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
package prometheus

import "testing"

// The data plane formats firewall rule counters as "packets:bytes"
// (pkg/loxinet/rules.go). The old exporter parsed the whole string as one
// number, failed on every rule, and reported 0 drops forever.
func TestParseFwCounterPackets(t *testing.T) {
	cases := []struct {
		in      string
		want    uint64
		wantOk  bool
		comment string
	}{
		{"0:0", 0, true, "idle rule"},
		{"1234:56789", 1234, true, "active rule"},
		{"18446744073709551615:1", 18446744073709551615, true, "max uint64"},
		{"42", 42, true, "packets-only form"},
		{"", 0, false, "empty"},
		{":123", 0, false, "missing packets field"},
		{"abc:def", 0, false, "garbage"},
		{"-5:0", 0, false, "negative"},
		{" 7:8", 7, true, "leading space tolerated"},
	}
	for _, c := range cases {
		got, ok := parseFwCounterPackets(c.in)
		if ok != c.wantOk || got != c.want {
			t.Errorf("parseFwCounterPackets(%q) = (%d, %v), want (%d, %v) [%s]",
				c.in, got, ok, c.want, c.wantOk, c.comment)
		}
	}
}

// generateLabelsKey must be deterministic regardless of map iteration order,
// otherwise one logical series splits across multiple shared-metric entries.
func TestGenerateLabelsKeyDeterministic(t *testing.T) {
	labels := map[string]string{"service": "svc1", "sip": "10.0.0.1", "dip": "10.0.0.2"}
	want := "m|dip=10.0.0.2|service=svc1|sip=10.0.0.1"
	for i := 0; i < 100; i++ {
		if got := generateLabelsKey("m", labels); got != want {
			t.Fatalf("generateLabelsKey not deterministic: got %q, want %q", got, want)
		}
	}
}

// Shared-metric helpers: Set overwrites, Add accumulates, Delete removes.
func TestSharedLabeledMetricHelpers(t *testing.T) {
	name := "test_labeled_metric_helpers"
	labels := map[string]string{"fw_rule": "42"}

	AddLabeledMetric(name, labels, 5)
	AddLabeledMetric(name, labels, 7)
	if got := findLabeledValue(name, labels); got != 12 {
		t.Fatalf("AddLabeledMetric accumulate: got %v, want 12", got)
	}

	SetLabeledMetric(name, labels, 3)
	if got := findLabeledValue(name, labels); got != 3 {
		t.Fatalf("SetLabeledMetric overwrite: got %v, want 3", got)
	}

	DeleteLabeledMetric(name, labels)
	if got := findLabeledValue(name, labels); got != -1 {
		t.Fatalf("DeleteLabeledMetric: entry still present with value %v", got)
	}
}

// findLabeledValue returns the value of a labeled shared metric, or -1 if absent.
func findLabeledValue(name string, labels map[string]string) float64 {
	sharedMetrics.RLock()
	defer sharedMetrics.RUnlock()
	if m, ok := sharedMetrics.data[generateLabelsKey(name, labels)]; ok {
		return m.Value
	}
	return -1
}
