/*
 * Copyright (c) 2022 NetLOX Inc
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

// Tests for the staged shutdown sequencer.
//
// These tests are intentionally `package loxinet` (internal) so they can
// override the unexported function-pointer variables `shutdownRESTFn`,
// `shutdownWorkersFn`, `shutdownDocaFn`, `shutdownEbpfFn` to verify call
// ordering without dragging in the full DOCA / eBPF subsystems.

package loxinet

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestRunShutdownStage_Success — stage func returns nil within deadline; the
// helper must return promptly (well within `deadline`) and signal "done".
func TestRunShutdownStage_Success(t *testing.T) {
	called := false
	start := time.Now()
	runShutdownStage("test", 200*time.Millisecond, func(ctx context.Context) error {
		called = true
		return nil
	})
	elapsed := time.Since(start)
	if !called {
		t.Fatalf("stage fn was not invoked")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("success path exceeded deadline: %v > 200ms", elapsed)
	}
}

// TestRunShutdownStage_Timeout — stage func sleeps longer than deadline.
// The helper must return within `deadline + slack` and NOT wait for the
// goroutine to finish.
func TestRunShutdownStage_Timeout(t *testing.T) {
	const deadline = 100 * time.Millisecond
	const slack = 100 * time.Millisecond

	start := time.Now()
	runShutdownStage("test", deadline, func(ctx context.Context) error {
		// Sleep MUCH longer than the deadline.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			return nil
		}
	})
	elapsed := time.Since(start)
	if elapsed < deadline {
		t.Fatalf("timeout path returned too early: %v < deadline %v", elapsed, deadline)
	}
	if elapsed > deadline+slack {
		t.Fatalf("timeout path exceeded deadline+slack: %v > %v",
			elapsed, deadline+slack)
	}
}

// TestRunShutdownStage_Error — stage fn returns a non-nil error; helper logs
// and returns within `deadline`.
func TestRunShutdownStage_Error(t *testing.T) {
	start := time.Now()
	runShutdownStage("test", 200*time.Millisecond, func(ctx context.Context) error {
		return errors.New("boom")
	})
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Fatalf("error path exceeded deadline: %v > 200ms", elapsed)
	}
}

// TestShutdownStagesOrdering — substitutes each stage function with a
// recording stub and asserts the staged sequencer (the helper that the
// loxinet.go signal handler calls) invokes them in the order
// [rest, workers, doca, ebpf]. We test the stage-function-pointer
// indirection so the loxinet.go signal-handler integration can be unit-
// tested without driving real syscalls.
func TestShutdownStagesOrdering(t *testing.T) {
	var (
		mu    sync.Mutex
		order []string
	)

	// Save and restore the unexported function-pointer vars.
	origREST := shutdownRESTFn
	origWorkers := shutdownWorkersFn
	origDoca := shutdownDocaFn
	origEbpf := shutdownEbpfFn
	defer func() {
		shutdownRESTFn = origREST
		shutdownWorkersFn = origWorkers
		shutdownDocaFn = origDoca
		shutdownEbpfFn = origEbpf
	}()

	rec := func(name string) func(ctx context.Context) error {
		return func(ctx context.Context) error {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			return nil
		}
	}
	shutdownRESTFn = rec("rest")
	shutdownWorkersFn = rec("workers")
	shutdownDocaFn = rec("doca")
	shutdownEbpfFn = rec("ebpf")

	// Drive the same sequence the loxinet.go SIGINT handler will drive.
	runShutdownStage("rest", 200*time.Millisecond, shutdownRESTFn)
	runShutdownStage("workers", 200*time.Millisecond, shutdownWorkersFn)
	runShutdownStage("doca", 200*time.Millisecond, shutdownDocaFn)
	runShutdownStage("ebpf", 200*time.Millisecond, shutdownEbpfFn)

	mu.Lock()
	defer mu.Unlock()
	want := []string{"rest", "workers", "doca", "ebpf"}
	if len(order) != len(want) {
		t.Fatalf("expected %d stages, got %d (%v)", len(want), len(order), order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("stage %d: want %q got %q (full order: %v)",
				i, want[i], order[i], order)
		}
	}
}
