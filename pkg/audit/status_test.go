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
package audit

import (
	"context"
	"math"
	"path/filepath"
	"testing"
	"time"
)

func TestProjectedRetentionDays(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name    string
		s       Stats
		elapsed time.Duration
		want    float64
	}{
		{"unlimited", Stats{}, time.Hour, 0},
		{"age only", Stats{Retention: Retention{MaxAge: 36 * time.Hour}}, time.Hour, 1.5},
		{"quota, rate not yet measurable", Stats{Retention: Retention{MaxBytes: 1 << 20}, BytesWritten: 1024}, 10 * time.Second, 0},
		{"quota, nothing written", Stats{Retention: Retention{MaxBytes: 1 << 20}}, time.Hour, 0},
		// 1 MiB/day written against a 10 MiB quota keeps ten days.
		{"quota from rate", Stats{Retention: Retention{MaxBytes: 10 << 20}, BytesWritten: 1 << 20}, 24 * time.Hour, 10},
		// The age bound is shorter than the quota's projection.
		{"age shorter", Stats{Retention: Retention{MaxAge: 48 * time.Hour, MaxBytes: 10 << 20}, BytesWritten: 1 << 20}, 24 * time.Hour, 2},
		// The quota's projection is shorter than the age bound.
		{"quota shorter", Stats{Retention: Retention{MaxAge: 30 * 24 * time.Hour, MaxBytes: 10 << 20}, BytesWritten: 1 << 20}, 24 * time.Hour, 10},
	} {
		c.s.StartedUnix = start.Unix()
		got := c.s.ProjectedRetentionDays(start.Add(c.elapsed))
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// The status snapshot describes the active segment and the bytes this
// process appended, so a poller can see the segment fill and the write
// rate without reading any record.
func TestStatsDescribesTheActiveSegment(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	w, err := New(Config{Dir: dir, CreateDir: true, InstanceID: "gw-test",
		Retention: Retention{MaxAge: 48 * time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Close(ctx)
	})
	waitFor(t, "writer running", w.Running)

	// A fresh writer has already written its own start records, so the
	// segment is described from the first moment and everything below is
	// measured as growth.
	st0 := w.Stats()
	if st0.SegmentUUID == "" || st0.SegmentOpenedUnix == 0 || st0.SegmentBytes == 0 {
		t.Fatalf("fresh segment not described: %+v", st0)
	}
	if st0.SegmentRecords != st0.Accepted[StreamSystem] || st0.BytesWritten == 0 {
		t.Fatalf("the start records are not reflected: %+v", st0)
	}
	if st0.Retention.MaxAge != 48*time.Hour {
		t.Fatalf("retention not reported: %+v", st0.Retention)
	}

	if err := w.Write(context.Background(), mgmtIntent("/x")); err != nil {
		t.Fatal(err)
	}
	st := w.Stats()
	if st.SegmentRecords != st0.SegmentRecords+1 || st.SegmentBytes <= st0.SegmentBytes {
		t.Fatalf("the record is not reflected: before %+v after %+v", st0, st)
	}
	if grew, counted := st.SegmentBytes-st0.SegmentBytes, st.BytesWritten-st0.BytesWritten; grew != counted {
		t.Fatalf("segment grew by %d but %d bytes were counted as written", grew, counted)
	}
	if st.StartedUnix == 0 || st.StartedUnix > time.Now().Unix() {
		t.Fatalf("start time %d", st.StartedUnix)
	}
}
