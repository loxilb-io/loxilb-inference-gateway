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
package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/loxilb-io/loxilb/pkg/snapshot"
)

// The two ways a mutating config call can meet a snapshot-family operation,
// and the two different things the contract promises for them: a capture
// (snapshot, export, persist, auto-persist write-through) HOLDS the call
// for the milliseconds the capture takes and then admits it; a restore or
// import REFUSES it with 503 and Retry-After for the seconds the pipeline
// runs. The distinction is the point of these tests. Before it existed, a
// write-through held the same gate a restore did, and every accepted write
// was followed one quiet period later by a window in which the next write
// was refused as "restore in progress" -- a refusal the client could not
// anticipate, for an operation it never requested.

type freezeProbe struct {
	h       http.Handler
	reached chan struct{}
	block   chan struct{}
}

func newFreezeProbe(t *testing.T) *freezeProbe {
	t.Helper()
	withMaintenanceFixture(t, 0)
	snapshot.MarkBootConfigSettled()
	p := &freezeProbe{reached: make(chan struct{}, 16), block: nil}
	p.h = SnapshotFreezeMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.reached <- struct{}{}
		if p.block != nil {
			<-p.block
		}
		w.WriteHeader(http.StatusOK)
	}))
	return p
}

func (p *freezeProbe) do(method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	p.h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// A mutating call that arrives while a capture holds the config waits for
// the capture and is then served -- it is never answered 503.
func TestCaptureHoldsWritesInsteadOfRefusingThem(t *testing.T) {
	p := newFreezeProbe(t)

	captureStarted := make(chan struct{})
	releaseCapture := make(chan struct{})
	captureDone := make(chan struct{})
	go func() {
		defer close(captureDone)
		_, _ = captureWithConfigWritesHeld(func() (struct{}, error) {
			close(captureStarted)
			<-releaseCapture
			return struct{}{}, nil
		})
	}()
	<-captureStarted

	type answer struct {
		code int
		body string
	}
	answered := make(chan answer, 1)
	go func() {
		rec := p.do(http.MethodPost, "/netlox/v1/config/loadbalancer")
		answered <- answer{rec.Code, rec.Body.String()}
	}()

	// Held, not refused: while the capture runs the write neither reaches
	// the handler nor gets an answer.
	select {
	case a := <-answered:
		t.Fatalf("write answered %d %q while a capture was running; want it held until the capture ends", a.code, a.body)
	case <-p.reached:
		t.Fatal("write reached the handler while a capture was running")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseCapture)
	<-captureDone
	select {
	case a := <-answered:
		if a.code != http.StatusOK {
			t.Fatalf("write after the capture answered %d %q, want 200", a.code, a.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write still held after the capture finished")
	}
	select {
	case <-p.reached:
	default:
		t.Fatal("write answered 200 without reaching the handler")
	}

	// A read is never held, even mid-capture.
	go func() {
		_, _ = captureWithConfigWritesHeld(func() (struct{}, error) {
			time.Sleep(150 * time.Millisecond)
			return struct{}{}, nil
		})
	}()
	time.Sleep(10 * time.Millisecond)
	start := time.Now()
	if rec := p.do(http.MethodGet, "/netlox/v1/config/loadbalancer/all"); rec.Code != http.StatusOK {
		t.Fatalf("GET during a capture answered %d, want 200", rec.Code)
	}
	if waited := time.Since(start); waited > 100*time.Millisecond {
		t.Fatalf("GET during a capture waited %v; reads must not be held", waited)
	}
}

// A mutating call that arrives while a restore runs is refused with the
// restore body and a Retry-After, the lifecycle endpoints stay exempt, and
// the refusal ends with the pipeline.
func TestRestoreRefusesWritesWithRetryAfter(t *testing.T) {
	p := newFreezeProbe(t)

	if rec := p.do(http.MethodPost, "/netlox/v1/config/loadbalancer"); rec.Code != http.StatusOK {
		t.Fatalf("POST with no restore running answered %d, want 200", rec.Code)
	}
	<-p.reached

	release := beginRestoreFreeze()
	rec := p.do(http.MethodPost, "/netlox/v1/config/loadbalancer")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST during a restore answered %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "snapshot restore is in progress") {
		t.Fatalf("503 body %q does not name the restore", rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("503 during a restore carries no Retry-After")
	}
	select {
	case <-p.reached:
		t.Fatal("refused write reached the handler")
	default:
	}
	for _, exempt := range []struct{ method, path string }{
		{http.MethodGet, "/netlox/v1/config/loadbalancer/all"},
		{http.MethodPost, "/netlox/v1/config/persist"},
		{http.MethodPost, "/netlox/v1/config/snapshot"},
		{http.MethodPost, "/netlox/v1/config/restore"},
	} {
		if rec := p.do(exempt.method, exempt.path); rec.Code != http.StatusOK {
			t.Fatalf("%s %s answered %d during a restore, want exempted", exempt.method, exempt.path, rec.Code)
		}
		<-p.reached
	}
	// The legacy import is deliberately not exempt.
	if rec := p.do(http.MethodPost, "/netlox/v1/config/import"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /config/import during a restore answered %d, want 503", rec.Code)
	}

	release()
	if rec := p.do(http.MethodPost, "/netlox/v1/config/loadbalancer"); rec.Code != http.StatusOK {
		t.Fatalf("POST after the restore answered %d, want 200", rec.Code)
	}
}

// Raising the restore freeze waits for the mutating calls already inside a
// handler, and a call that arrives after the flag is up is refused rather
// than admitted behind the barrier.
func TestRestoreFreezeDrainsInFlightWrites(t *testing.T) {
	p := newFreezeProbe(t)
	p.block = make(chan struct{})

	inFlightDone := make(chan int, 1)
	go func() {
		inFlightDone <- p.do(http.MethodPost, "/netlox/v1/config/loadbalancer").Code
	}()
	<-p.reached // the write is inside the handler, holding the shared lock

	frozen := make(chan func(), 1)
	go func() { frozen <- beginRestoreFreeze() }()
	select {
	case <-frozen:
		t.Fatal("restore freeze raised while a write was still inside its handler")
	case <-time.After(100 * time.Millisecond):
	}

	// The barrier is waiting on the in-flight write; a new write must
	// already be refused, not queued behind the barrier into the restore.
	lateAnswered := make(chan int, 1)
	go func() { lateAnswered <- p.do(http.MethodPost, "/netlox/v1/config/loadbalancer").Code }()

	close(p.block)
	if code := <-inFlightDone; code != http.StatusOK {
		t.Fatalf("in-flight write answered %d, want 200", code)
	}
	var release func()
	select {
	case release = <-frozen:
	case <-time.After(2 * time.Second):
		t.Fatal("restore freeze did not rise after the in-flight write finished")
	}
	select {
	case code := <-lateAnswered:
		if code != http.StatusServiceUnavailable {
			t.Fatalf("write that arrived during the barrier answered %d, want 503", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write that arrived during the barrier never answered")
	}
	select {
	case <-p.reached:
		t.Fatal("write that arrived during the barrier reached the handler")
	default:
	}
	release()
}
