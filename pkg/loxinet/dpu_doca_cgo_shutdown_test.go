//go:build doca

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

// contract tests for DocaBridge.Shutdown(ctx).
//
// These tests construct a minimal DocaBridge by hand (without driving
// CGO / DPDK) and start a synthetic worker goroutine that mimics the
// real worker's `case <-d.shutdownCh: defer close(d.workerDone); return`
// shape. We exercise the close-and-wait contract directly; the CGO
// path is exercised by the manual SIGINT validation.

package loxinet

import (
	"context"
	"errors"
	"testing"
	"time"
)

// newTestDocaBridge constructs a DocaBridge wired for unit tests:
// initDone=true so Shutdown(ctx) takes the post-init branch, and a
// caller-supplied `cooperative` flag controls whether the synthetic
// worker reads d.shutdownCh (cooperative=true → drains within 1ms) or
// ignores it (cooperative=false → blocks until t.Cleanup forces exit).
func newTestDocaBridge(t *testing.T, cooperative bool) *DocaBridge {
	t.Helper()
	d := &DocaBridge{
		workCh:     make(chan docaWorkItem, 1),
		shutdownCh: make(chan struct{}),
		workerDone: make(chan struct{}),
		initDone:   true,
		pciAddr:    "test:0000",
		numRepr:    0,
	}
	// Synthetic worker — does NOT call runtime.LockOSThread; we only
	// care about the shutdownCh→workerDone rendezvous shape.
	stopForce := make(chan struct{})
	go func() {
		defer close(d.workerDone)
		if cooperative {
			<-d.shutdownCh
			return
		}
		// Non-cooperative: ignore shutdownCh until the test forces exit.
		<-stopForce
	}()
	t.Cleanup(func() {
		// Always release the synthetic worker so the test doesn't leak
		// goroutines, regardless of whether Shutdown(ctx) returned.
		select {
		case <-d.workerDone:
			// already exited
		default:
			close(stopForce)
			<-d.workerDone
		}
	})
	return d
}

// TestDocaBridgeShutdown_Bounded — cooperative worker exits promptly on
// shutdownCh close; Shutdown(ctx) returns nil within the deadline.
func TestDocaBridgeShutdown_Bounded(t *testing.T) {
	d := newTestDocaBridge(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := d.Shutdown(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Shutdown returned error on cooperative worker: %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("Shutdown returned too slowly: %v > 200ms", elapsed)
	}
	// workerDone must be closed.
	select {
	case <-d.workerDone:
	default:
		t.Fatalf("workerDone is not closed after Shutdown returned nil")
	}
}

// TestDocaBridgeShutdown_Timeout — non-cooperative worker; Shutdown(ctx)
// returns the wrapped ctx.Err within the deadline.
func TestDocaBridgeShutdown_Timeout(t *testing.T) {
	d := newTestDocaBridge(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := d.Shutdown(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Shutdown returned nil on non-cooperative worker (expected timeout)")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error did not wrap DeadlineExceeded: %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("Shutdown returned too slowly: %v > 200ms", elapsed)
	}
	// workerDone must NOT be closed (worker still alive).
	select {
	case <-d.workerDone:
		t.Fatalf("workerDone is closed but worker is non-cooperative")
	default:
	}
}
