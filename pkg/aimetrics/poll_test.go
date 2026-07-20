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

// poll_test.go — proves the extracted poll-loop semantics survived the move:
// per-EP in-flight dedup (LoadOrStore), LastUpdate stamping per scrape, the
// "no recognized metrics ⇒ no sink call" condition, and Run/Stop lifecycle.

package aimetrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordSink collects samples and signals each delivery.
type recordSink struct {
	mu      sync.Mutex
	samples []WorkerSample
	epIdxs  []int
	ch      chan struct{}
}

func newRecordSink() *recordSink {
	return &recordSink{ch: make(chan struct{}, 64)}
}

func (r *recordSink) OnSample(epIdx int, s WorkerSample) {
	r.mu.Lock()
	r.samples = append(r.samples, s)
	r.epIdxs = append(r.epIdxs, epIdx)
	r.mu.Unlock()
	r.ch <- struct{}{}
}

func (r *recordSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.samples)
}

func (r *recordSink) sample(i int) WorkerSample {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.samples[i]
}

func waitSignal(t *testing.T, ch chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sink delivery")
	}
}

func healthyFixtureHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	body, err := os.ReadFile("testdata/vllm_metrics_healthy.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}
}

// TestPollerScrapeDeliversSample: one scrape ⇒ one sink delivery carrying
// the parsed fixture values, epIdx preserved, LastUpdate stamped.
func TestPollerScrapeDeliversSample(t *testing.T) {
	srv := httptest.NewServer(healthyFixtureHandler(t))
	defer srv.Close()

	sink := newRecordSink()
	p := NewPoller([]string{srv.Listener.Addr().String()}, time.Hour, sink)

	before := time.Now()
	p.scrapeAll(context.Background())
	waitSignal(t, sink.ch)

	s := sink.sample(0)
	if sink.epIdxs[0] != 0 {
		t.Errorf("epIdx = %d, want 0", sink.epIdxs[0])
	}
	if s.NumRequestsWaiting != 3 || s.NumGPUBlocks != 7408 || s.GPUCacheUsagePerc != 0.42 {
		t.Errorf("sample = %+v, want waiting=3 blocks=7408 kv=0.42", s)
	}
	if s.LastUpdate.Before(before) {
		t.Errorf("LastUpdate %v not stamped at scrape time (before %v)", s.LastUpdate, before)
	}
}

// TestPollerLastUpdateAdvances: LastUpdate advances per scrape.
func TestPollerLastUpdateAdvances(t *testing.T) {
	srv := httptest.NewServer(healthyFixtureHandler(t))
	defer srv.Close()

	sink := newRecordSink()
	p := NewPoller([]string{srv.Listener.Addr().String()}, time.Hour, sink)

	p.scrapeAll(context.Background())
	waitSignal(t, sink.ch)
	time.Sleep(10 * time.Millisecond)
	p.scrapeAll(context.Background())
	waitSignal(t, sink.ch)

	first, second := sink.sample(0), sink.sample(1)
	if !second.LastUpdate.After(first.LastUpdate) {
		t.Errorf("LastUpdate did not advance: first=%v second=%v", first.LastUpdate, second.LastUpdate)
	}
}

// TestPollerInFlightDedup proves the LoadOrStore semantics survived the
// move: while a scrape for an EP is in flight (slow fake server), a second
// tick must NOT launch a second scrape for that EP; after the first
// completes, the next tick scrapes again.
func TestPollerInFlightDedup(t *testing.T) {
	var reqCount int32
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	fixture, err := os.ReadFile("testdata/vllm_metrics_healthy.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&reqCount, 1)
		started <- struct{}{}
		if n == 1 {
			<-release // First scrape stalls until released.
		}
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	sink := newRecordSink()
	p := NewPoller([]string{srv.Listener.Addr().String()}, time.Hour, sink)
	ctx := context.Background()

	p.scrapeAll(ctx) // Tick 1: scrape starts, stalls in the handler.
	<-started

	p.scrapeAll(ctx) // Tick 2 while in flight: MUST be deduped.
	time.Sleep(50 * time.Millisecond)
	if n := atomic.LoadInt32(&reqCount); n != 1 {
		t.Fatalf("in-flight dedup broken: %d requests while first scrape stalled, want 1", n)
	}

	close(release) // First scrape completes and delivers.
	waitSignal(t, sink.ch)

	// inFlight.Delete runs AFTER scrapeOne returns (defer) — poll briefly
	// until the slot is free, then the next tick must scrape again.
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.scrapeAll(ctx)
		if atomic.LoadInt32(&reqCount) >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := atomic.LoadInt32(&reqCount); n < 2 {
		t.Fatalf("EP never scraped again after in-flight slot freed: reqCount=%d", n)
	}
	waitSignal(t, sink.ch)
}

// TestPollerNoRecognizedMetricsNoSink: a body with none of the 3 series
// must NOT reach the sink (original early-return preserved).
func TestPollerNoRecognizedMetricsNoSink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("go_goroutines 42\n"))
	}))
	defer srv.Close()

	sink := newRecordSink()
	p := NewPoller([]string{srv.Listener.Addr().String()}, time.Hour, sink)
	p.scrapeOne(context.Background(), 0, srv.Listener.Addr().String())

	if sink.count() != 0 {
		t.Errorf("sink called %d times for unrecognized body, want 0", sink.count())
	}
}

// TestPollerSkipsEmptyEndpointSlots: sparse EP-index slots (empty strings
// from the map-shaped loxinet caller) are skipped without panic.
func TestPollerSkipsEmptyEndpointSlots(t *testing.T) {
	srv := httptest.NewServer(healthyFixtureHandler(t))
	defer srv.Close()

	sink := newRecordSink()
	p := NewPoller([]string{"", srv.Listener.Addr().String(), ""}, time.Hour, sink)
	p.scrapeAll(context.Background())
	waitSignal(t, sink.ch)

	if sink.count() != 1 || sink.epIdxs[0] != 1 {
		t.Errorf("got %d samples (epIdx %v), want exactly 1 from index 1", sink.count(), sink.epIdxs)
	}
}

// TestPollerLMCachePiggybackOffByDefault: without EnableLMCachePiggyback the
// delivered sample carries the narrow vLLM 3-series and NO lmcache:* keys — the
// loxilb hot-path contract (byte-identical scrape) is preserved even when the
// body also carries lmcache families.
func TestPollerLMCachePiggybackOffByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(lmcacheGoldenBody))
	}))
	defer srv.Close()

	sink := newRecordSink()
	p := NewPoller([]string{srv.Listener.Addr().String()}, time.Hour, sink)
	p.scrapeOne(context.Background(), 0, srv.Listener.Addr().String())
	waitSignal(t, sink.ch)

	s := sink.sample(0)
	if s.NumRequestsWaiting != 3 {
		t.Errorf("narrow vLLM parse lost: waiting=%d, want 3", s.NumRequestsWaiting)
	}
	for k := range s.Raw {
		if len(k) >= len(LMCacheFamilyPrefix) && k[:len(LMCacheFamilyPrefix)] == LMCacheFamilyPrefix {
			t.Errorf("piggyback OFF but lmcache key %q leaked into Raw", k)
		}
	}
}

// TestPollerLMCachePiggybackMergesFamilies: with EnableLMCachePiggyback the
// SAME /metrics body yields a sample carrying BOTH the narrow vLLM series AND
// the lmcache:* families merged into Raw — no second scrape target (LMC-02).
func TestPollerLMCachePiggybackMergesFamilies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(lmcacheGoldenBody))
	}))
	defer srv.Close()

	sink := newRecordSink()
	p := NewPoller([]string{srv.Listener.Addr().String()}, time.Hour, sink)
	p.EnableLMCachePiggyback()
	p.scrapeOne(context.Background(), 0, srv.Listener.Addr().String())
	waitSignal(t, sink.ch)

	s := sink.sample(0)
	if s.NumRequestsWaiting != 3 {
		t.Errorf("narrow vLLM parse lost under piggyback: waiting=%d, want 3", s.NumRequestsWaiting)
	}
	if got := s.Raw[FamilyLMCacheRetrieveHitRate]; got != 0.75 {
		t.Errorf("lmcache retrieve_hit_rate = %v, want 0.75 (not merged)", got)
	}
	if _, ok := s.Raw[FamilyLMCacheLocalCacheUsage]; !ok {
		t.Errorf("lmcache local_cache_usage missing from merged Raw: %v", s.Raw)
	}
	if s.LastUpdate.IsZero() {
		t.Errorf("LastUpdate not stamped on piggyback sample")
	}
}

// TestPollerRunStop: Run performs the immediate first scrape plus ticker
// scrapes, and Stop terminates the loop.
func TestPollerRunStop(t *testing.T) {
	srv := httptest.NewServer(healthyFixtureHandler(t))
	defer srv.Close()

	sink := newRecordSink()
	p := NewPoller([]string{srv.Listener.Addr().String()}, 20*time.Millisecond, sink)

	done := make(chan struct{})
	go func() {
		p.Run(context.Background())
		close(done)
	}()

	waitSignal(t, sink.ch) // Immediate first scrape.
	waitSignal(t, sink.ch) // At least one ticker scrape.

	p.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Stop")
	}
}
