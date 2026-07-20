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

package prometheus

// Tests for the loxilb_proxy_http_ttfb_seconds ConstHistogram pipeline
// (sanitizeTtfbSnapshot / mergeTtfbSnapshot / ttfbCollector). The functions
// under test are pure Go; the package itself carries CGO files, so these run
// on the Linux build gate (linked against proxy_metrics_stub.c).

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// mkTtfbSnapshot builds a snapshot from a short bucket prefix; remaining
// buckets repeat the last given value so the sequence stays cumulative.
func mkTtfbSnapshot(prefix []uint64, count uint64, sumSecs float64) ttfbSnapshot {
	var s ttfbSnapshot
	last := uint64(0)
	for i := range s.buckets {
		if i < len(prefix) {
			last = prefix[i]
		}
		s.buckets[i] = last
	}
	s.count = count
	s.sumSecs = sumSecs
	return s
}

// TestSanitizeTtfbSnapshotTornRead verifies the exact underflow trigger from
// the audited defect: a torn read makes bucket[i+1] < bucket[i]. The old code
// computed deltaBuckets[i+1]-prevCum on uint64 and underflowed to ~2^64,
// livelocking the metrics goroutine. Sanitize must clamp the sequence
// non-decreasing instead.
func TestSanitizeTtfbSnapshotTornRead(t *testing.T) {
	raw := mkTtfbSnapshot([]uint64{10, 8, 12}, 15, 1.5) // 8 < 10: torn read
	s := sanitizeTtfbSnapshot(raw)
	for i := 1; i < len(s.buckets); i++ {
		if s.buckets[i] < s.buckets[i-1] {
			t.Fatalf("bucket[%d]=%d < bucket[%d]=%d after sanitize",
				i, s.buckets[i], i-1, s.buckets[i-1])
		}
	}
	if s.buckets[1] != 10 {
		t.Errorf("torn bucket[1] = %d, want clamped to 10", s.buckets[1])
	}
	if s.buckets[2] != 12 {
		t.Errorf("bucket[2] = %d, want 12 (untouched)", s.buckets[2])
	}
}

// TestSanitizeTtfbSnapshotCountClamp verifies count is raised to at least the
// highest cumulative bucket (a torn read between latency_count and the
// buckets could otherwise expose count < buckets["10.0"]).
func TestSanitizeTtfbSnapshotCountClamp(t *testing.T) {
	raw := mkTtfbSnapshot([]uint64{5, 20}, 7, 0.5) // count 7 < top bucket 20
	s := sanitizeTtfbSnapshot(raw)
	if s.count != 20 {
		t.Errorf("count = %d, want clamped to 20", s.count)
	}

	// count > top bucket (samples above 10s) must be preserved.
	raw = mkTtfbSnapshot([]uint64{5, 20}, 25, 0.5)
	s = sanitizeTtfbSnapshot(raw)
	if s.count != 25 {
		t.Errorf("count = %d, want 25 (overflow samples preserved)", s.count)
	}
}

// TestMergeTtfbSnapshotMonotonic verifies the exposed state never goes
// backwards across snapshots: element-wise max on buckets, count and sum.
func TestMergeTtfbSnapshotMonotonic(t *testing.T) {
	prev := mkTtfbSnapshot([]uint64{10, 20, 30}, 35, 3.5)
	// New snapshot with one torn-low bucket and slightly lower sum.
	next := mkTtfbSnapshot([]uint64{12, 18, 31}, 36, 3.4)
	m := mergeTtfbSnapshot(prev, next)

	want := mkTtfbSnapshot([]uint64{12, 20, 31}, 36, 3.5)
	if m != want {
		t.Errorf("merge = %+v, want %+v", m, want)
	}
	for i := 1; i < len(m.buckets); i++ {
		if m.buckets[i] < m.buckets[i-1] {
			t.Fatalf("merged bucket[%d]=%d < bucket[%d]=%d",
				i, m.buckets[i], i-1, m.buckets[i-1])
		}
	}
}

// TestMergeTtfbSnapshotReset verifies a drastically lower count (< half of
// previous) is treated as a genuine C-side reset and replaces the state.
func TestMergeTtfbSnapshotReset(t *testing.T) {
	prev := mkTtfbSnapshot([]uint64{100, 200}, 250, 25.0)
	next := mkTtfbSnapshot([]uint64{1, 2}, 3, 0.1)
	m := mergeTtfbSnapshot(prev, next)
	if m != next {
		t.Errorf("merge after reset = %+v, want new state %+v", m, next)
	}

	// A small dip (>= half of previous) is NOT a reset: max wins.
	next = mkTtfbSnapshot([]uint64{90, 190}, 240, 24.0)
	m = mergeTtfbSnapshot(prev, next)
	if m != prev {
		t.Errorf("merge on small dip = %+v, want previous state %+v", m, prev)
	}
}

// TestTtfbCollectorEmitsConstHistogram verifies the collector emits
// loxilb_proxy_http_ttfb_seconds with cumulative le buckets keyed by the bounds in
// seconds, plus exact count and sum, straight from ttfbStore.
func TestTtfbCollectorEmitsConstHistogram(t *testing.T) {
	ttfbStoreMutex.Lock()
	saved := ttfbStore
	ttfbStore = mkTtfbSnapshot([]uint64{1, 2, 3}, 4, 0.25)
	ttfbStoreMutex.Unlock()
	defer func() {
		ttfbStoreMutex.Lock()
		ttfbStore = saved
		ttfbStoreMutex.Unlock()
	}()

	ch := make(chan prometheus.Metric, 1)
	ttfbCollector{}.Collect(ch)
	close(ch)

	metric, ok := <-ch
	if !ok {
		t.Fatal("collector emitted no metric")
	}
	m := &dto.Metric{}
	if err := metric.Write(m); err != nil {
		t.Fatalf("metric.Write failed: %v", err)
	}
	h := m.GetHistogram()
	if h == nil {
		t.Fatal("emitted metric is not a histogram")
	}
	if h.GetSampleCount() != 4 {
		t.Errorf("sample count = %d, want 4", h.GetSampleCount())
	}
	if h.GetSampleSum() != 0.25 {
		t.Errorf("sample sum = %v, want 0.25", h.GetSampleSum())
	}
	if len(h.Bucket) != len(ttfbBucketBounds) {
		t.Fatalf("bucket count = %d, want %d", len(h.Bucket), len(ttfbBucketBounds))
	}
	wantCum := []uint64{1, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	for i, b := range h.Bucket {
		if b.GetUpperBound() != ttfbBucketBounds[i] {
			t.Errorf("bucket[%d] le = %v, want %v", i, b.GetUpperBound(), ttfbBucketBounds[i])
		}
		if b.GetCumulativeCount() != wantCum[i] {
			t.Errorf("bucket[%d] cumulative = %d, want %d", i, b.GetCumulativeCount(), wantCum[i])
		}
	}
}

// TestTtfbBucketBoundsMatchC pins the Go bounds (seconds) to the C-side
// latency_bucket_bounds_us table (microseconds) so drift between the twin
// declarations is caught at test time.
func TestTtfbBucketBoundsMatchC(t *testing.T) {
	cBoundsUs := []uint64{
		1000, 5000, 10000, 25000, 50000, 100000,
		250000, 500000, 1000000, 2500000, 5000000, 10000000,
	}
	if len(cBoundsUs) != len(ttfbBucketBounds) {
		t.Fatalf("bound count mismatch: C=%d Go=%d", len(cBoundsUs), len(ttfbBucketBounds))
	}
	for i, us := range cBoundsUs {
		if got := ttfbBucketBounds[i]; got != float64(us)/1e6 {
			t.Errorf("bound[%d] = %v s, want %v us / 1e6", i, got, us)
		}
	}
}
