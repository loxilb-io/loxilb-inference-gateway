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
	"path/filepath"
	"testing"
	"time"
)

func mgmtPair(w *Writer, id string) (*Record, *Record) {
	in := w.AcquireRecord()
	in.EventID, in.Stream, in.EventType, in.Phase = id, StreamMgmt, "mgmt.config.mutate", PhaseIntent
	in.Outcome.Reason = ReasonOK
	in.Mgmt = &MgmtDetail{Method: "POST", Path: "/netlox/v1/config/policy"}
	out := w.AcquireRecord()
	out.EventID, out.Stream, out.EventType, out.Phase = id, StreamMgmt, "mgmt.config.mutate", PhaseResult
	out.Outcome = Outcome{Status: 200, OK: true, Reason: ReasonOK}
	out.Mgmt = &MgmtDetail{Method: "POST", Path: "/netlox/v1/config/policy"}
	return in, out
}

// An intent whose result never became durable is reported at the next
// start with its event_id and the generation observed at that boot; a
// completed pair is not.
func TestOrphanedIntentIsReportedAtNextStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	w1, err := New(Config{Dir: dir, CreateDir: true, InstanceID: "i"})
	if err != nil {
		t.Fatal(err)
	}
	w1.Start()
	waitFor(t, "writer running", w1.Running)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pairedIn, pairedOut := mgmtPair(w1, "paired-1")
	if err := w1.Write(ctx, pairedIn); err != nil {
		t.Fatal(err)
	}
	if !w1.Append(pairedOut) {
		t.Fatal("append")
	}
	orphanIn, _ := mgmtPair(w1, "orphan-1")
	if err := w1.Write(ctx, orphanIn); err != nil {
		t.Fatal(err)
	}
	// Rotate so the orphan's intent sits in a sealed segment and the pair
	// straddles nothing: both placements must be scanned.
	if err := w1.SealNow(ctx); err != nil {
		t.Fatal(err)
	}
	straddleIn, straddleOut := mgmtPair(w1, "straddle-1")
	if err := w1.Write(ctx, straddleIn); err != nil {
		t.Fatal(err)
	}
	if err := w1.SealNow(ctx); err != nil {
		t.Fatal(err)
	}
	if !w1.Append(straddleOut) {
		t.Fatal("append")
	}
	if err := w1.Close(ctx); err != nil {
		t.Fatal(err)
	}

	gen := uint64(0)
	w2, err := New(Config{Dir: dir, InstanceID: "i", ConfigGeneration: func() uint64 { gen++; return 41 + gen }})
	if err != nil {
		t.Fatal(err)
	}
	w2.Start()
	waitFor(t, "writer running", w2.Running)
	if err := w2.SealNow(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var orphans []line
	for _, l := range readDir(t, dir) {
		if l.str("event_type") == "sys.intent.orphaned" {
			orphans = append(orphans, l)
		}
	}
	if len(orphans) != 1 {
		t.Fatalf("got %d orphan records, want 1", len(orphans))
	}
	d := orphans[0].detail()
	if d["intent_event_id"] != "orphan-1" {
		t.Fatalf("orphan names %v", d["intent_event_id"])
	}
	if d["config_generation_at_boot"] != float64(42) {
		t.Fatalf("generation %v", d["config_generation_at_boot"])
	}
	if s := w2.Stats(); s.OrphanedIntents != 1 || s.LastOrphanEventID != "orphan-1" {
		t.Fatalf("stats %+v", s)
	}
}

// A writer's own restart never reports the pairs it has in flight, and a
// boot with nothing before it reports nothing.
func TestOrphanScanIgnoresOwnBootAndEmptyDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	w, err := New(Config{Dir: dir, CreateDir: true, InstanceID: "i"})
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	waitFor(t, "writer running", w.Running)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in, _ := mgmtPair(w, "inflight")
	if err := w.Write(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err := w.SealNow(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for _, l := range readDir(t, dir) {
		if l.str("event_type") == "sys.intent.orphaned" {
			t.Fatal("a writer reported an orphan from its own boot")
		}
	}
	if s := w.Stats(); s.OrphanedIntents != 0 {
		t.Fatalf("stats %+v", s)
	}
}
