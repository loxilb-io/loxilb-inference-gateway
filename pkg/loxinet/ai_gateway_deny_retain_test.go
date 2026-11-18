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

package loxinet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/audit"
)

// The refusal path keeps no Go heap per refusal.
//
// Every refusal the data plane makes is recorded once through the export
// llb_ai_record_deny: the request counter, the network-identity counter and
// the data.ai.deny record. At steady state none of that keeps anything per
// call: the counters are existing series, the record goes back to the
// writer's pool once written, and the queue drains. A leak there was seen by
// nothing before this test: ai-jwtauth's H2-LIFE-003 scores the process's
// mapped memory, and the Go heap grows in bursts as the collector raises its
// goal, so a build keeping 16 KiB of Go heap per refusal completed its
// window in a quiet stretch and passed.
//
// This reads what a leak is, not what the heap has mapped: the live heap
// after forced collections, before and after a number of refusals driven
// through the export with C arguments, with a real audit writer running and
// drained before every reading.
//
// What it does not see: the verdict exports that run before the record (the
// bearer and key checks among them); retention under the ceiling (a bare
// set of request IDs may be under it); leaks
// keyed on what this test holds fixed (tenant, model, identity); growth that
// stops at a cap; memory outside the Go heap (C, stacks beyond a goroutine
// count, runtime metadata).
const (
	retainChildEnv = "LOXILB_TEST_REFUSAL_RETAIN_CHILD"
	retainTestName = "TestRefusalPathKeepsNoGoHeap"

	retainWarmup  = 2000 // counter series, producer, pool and writer buffers; not scored
	retainBatch   = 2000 // below the writer's queue (8192), drained between batches
	retainBatches = 10   // 20,000 measured refusals

	// The ceiling: 64 bytes per measured refusal, 1,280,000 bytes of live
	// heap growth, applied after every batch. What the path should keep is
	// zero; this is the noise budget of a process holding only this test,
	// read after two forced collections. A request ID kept with its tenant
	// in a map (about 107 B per refusal) was shown to cross it, at batch 6;
	// a bare set of request IDs (about 51-71 B per refusal) may not. It was
	// fixed before the test was first run, and is not to be raised to make a
	// red go away.
	retainCeilingPerRefusal = 64
	retainCeiling           = retainCeilingPerRefusal * retainBatch * retainBatches

	retainDrainLimit = 10 * time.Second
)

func TestRefusalPathKeepsNoGoHeap(t *testing.T) {
	if os.Getenv(retainChildEnv) == "1" {
		refusalRetainChild(t)
		return
	}
	// The package's other tests leave goroutines and state behind that
	// would move the live heap under the measurement. The measurement runs
	// in a fresh process holding only this test.
	cmd := exec.Command(os.Args[0], "-test.run=^"+retainTestName+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), retainChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("child process:\n%s", out)
	if err != nil {
		t.Fatalf("child process failed: %v", err)
	}
	// A child that matched no test exits 0; it must have run this one.
	if !strings.Contains(string(out), "--- PASS: "+retainTestName) {
		t.Fatalf("child process did not run %s", retainTestName)
	}
}

func refusalRetainChild(t *testing.T) {
	startTrail(t)
	w := audit.Global()
	if w == nil {
		t.Fatal("test fault: no audit writer")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), retainDrainLimit)
		defer cancel()
		_ = w.Close(ctx)
	})

	// One refusal as H2-LIFE-003 makes them: a bearer refused 401 at the
	// auth stage, with attribution and correlation. Only the request ID
	// changes from call to call, as it does in life.
	d := aiDenyRecord{
		TenantID: "tenant-retain", UserID: "user-retain", SvcIdent: "10.0.0.1:2040", ModelName: "llama-3",
		Stage: aiStageAuth, HTTPStatus: 401, ErrorCode: "invalid_token", WorkerID: 1,
		ClientIP: "192.0.2.10", AuthSrc: aiAuthSrcBearer, NetIdentity: "netid-retain",
		TraceID: corrTrace, ParentSpanID: corrParent, SessionID: corrSess,
	}
	base := w.Stats().Accepted[audit.StreamData]
	sent := 0
	refuse := func(n int) {
		for i := 0; i < n; i++ {
			d.RequestID = fmt.Sprintf("refusal-%024d", sent)
			aiRecordDenyC(d)
			sent++
		}
	}
	// drain waits until the writer has written every record sent. A record
	// the producer did not accept means the path was not exercised as
	// written: that is the test's fault, and is never read as a leak.
	drain := func() {
		deadline := time.Now().Add(retainDrainLimit)
		for {
			st := w.Stats()
			var accepted, dropped uint64
			for _, p := range st.Producers {
				if p.Stream != audit.StreamData {
					continue
				}
				accepted += p.Accepted
				for _, n := range p.Dropped {
					dropped += n
				}
			}
			if dropped != 0 || accepted > uint64(sent) {
				t.Fatalf("test fault: %d records sent, the producer accepted %d and dropped %d", sent, accepted, dropped)
			}
			idle := true
			for _, n := range st.QueueDepth {
				idle = idle && n == 0
			}
			if accepted == uint64(sent) && st.Accepted[audit.StreamData]-base >= uint64(sent) && idle {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("test fault: writer not drained within %v: %d sent, %d accepted, %d written",
					retainDrainLimit, sent, accepted, st.Accepted[audit.StreamData]-base)
			}
			time.Sleep(time.Millisecond)
		}
	}
	// live is the heap the collector found reachable: two forced
	// collections, the second emptying the record pool's victim cache.
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	live := func() int64 {
		runtime.GC()
		runtime.GC()
		metrics.Read(sample)
		if sample[0].Value.Kind() != metrics.KindUint64 {
			t.Fatalf("test fault: %s not supported", sample[0].Name)
		}
		return int64(sample[0].Value.Uint64())
	}

	refuse(retainWarmup)
	drain()
	heap0, gor0 := live(), runtime.NumGoroutine()
	t.Logf("baseline after %d warm-up refusals: live heap %d B, goroutines %d; ceiling %d B (%d B per refusal over %d)",
		retainWarmup, heap0, gor0, retainCeiling, retainCeilingPerRefusal, retainBatch*retainBatches)

	var growth int64
	for b := 1; b <= retainBatches; b++ {
		refuse(retainBatch)
		drain()
		growth = live() - heap0
		n := b * retainBatch
		t.Logf("batch %2d: %6d refusals, live heap %+d B (%.1f B per refusal), goroutines %d",
			b, n, growth, float64(growth)/float64(n), runtime.NumGoroutine())
		// Stopping at the first batch over the ceiling keeps a leaking
		// build from holding more than one batch of what it leaks.
		if growth > retainCeiling {
			t.Fatalf("the refusal path kept Go heap: live heap +%d B after %d refusals (%.1f B per refusal); ceiling %d B (%d B per refusal over %d)",
				growth, n, float64(growth)/float64(n), retainCeiling, retainCeilingPerRefusal, retainBatch*retainBatches)
		}
	}
	if g := runtime.NumGoroutine(); g > gor0+2 {
		t.Fatalf("the refusal path kept goroutines: %d after %d refusals, %d before", g, retainBatch*retainBatches, gor0)
	}
	t.Logf("verdict: live heap %+d B over %d refusals (%.1f B per refusal); ceiling %d B",
		growth, retainBatch*retainBatches, float64(growth)/float64(retainBatch*retainBatches), retainCeiling)
}
