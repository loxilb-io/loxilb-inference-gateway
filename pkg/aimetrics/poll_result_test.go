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

// poll_result_test.go — the ResultSink contract.
//
// The reason this hook exists is that OnSample is reached ONLY by a scrape
// that parsed, so on its own it leaves every failure state invisible: when an
// endpoint stops answering /metrics the pushes simply stop. Downstream that is
// handled, but silently, and "routing on live load" and "routing on a fill-in
// because every scrape has failed for ten minutes" need opposite responses.
//
// So these tests hold the contract that makes the state reportable at all:
// EVERY scrape reports EXACTLY ONCE, including the successful ones, and the
// outcome it reports names the actual failure rather than a catch-all.

package aimetrics

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// resultSink is a Sink that ALSO implements ResultSink.
type resultSink struct {
	recordSink
	mu      sync.Mutex
	results []string
	eps     []string
	idxs    []int
}

func newResultSink() *resultSink {
	return &resultSink{recordSink: recordSink{ch: make(chan struct{}, 64)}}
}

func (r *resultSink) OnScrapeResult(epIdx int, endpoint string, result string) {
	r.mu.Lock()
	r.results = append(r.results, result)
	r.eps = append(r.eps, endpoint)
	r.idxs = append(r.idxs, epIdx)
	r.mu.Unlock()
}

func (r *resultSink) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.results))
	copy(out, r.results)
	return out
}

// scrapeAndCollect runs ONE scrape against handler and returns the reported
// outcomes. A nil handler means "nothing is listening", which is the
// unreachable case and cannot be produced by an httptest server.
func scrapeAndCollect(t *testing.T, handler http.Handler) ([]string, string) {
	t.Helper()
	var addr string
	if handler == nil {
		// Bind and immediately release, so the address is routable and closed.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr = l.Addr().String()
		_ = l.Close()
	} else {
		srv := httptest.NewServer(handler)
		defer srv.Close()
		addr = srv.Listener.Addr().String()
	}
	sink := newResultSink()
	p := NewPoller([]string{addr}, time.Hour, sink)
	p.scrapeOne(context.Background(), 0, addr)
	return sink.got(), addr
}

// TestScrapeReportsOK: the success path reports, and reports exactly once.
//
// The success arm is not symmetry for its own sake. A counter that moves only
// on failure cannot distinguish "nothing is failing" from "the scraper is not
// running at all", which is the same false reassurance an eager zero gives.
func TestScrapeReportsOK(t *testing.T) {
	got, _ := scrapeAndCollect(t, healthyFixtureHandler(t))
	if len(got) != 1 || got[0] != ScrapeOK {
		t.Fatalf("results = %v, want exactly one %q", got, ScrapeOK)
	}
}

// TestScrapeReportsUnreachable: a closed port is the state this whole hook
// exists for — the transport failure that produces no sample and, before the
// hook, no signal of any kind (it is logged at Debug, below the shipped level).
func TestScrapeReportsUnreachable(t *testing.T) {
	got, _ := scrapeAndCollect(t, nil)
	if len(got) != 1 || got[0] != ScrapeUnreachable {
		t.Fatalf("results = %v, want exactly one %q", got, ScrapeUnreachable)
	}
}

// TestScrapeReportsHTTPError: answered, but not 200. Distinct from unreachable
// because the two need different responses — one is a dead endpoint, the other
// is a reachable endpoint whose exporter is refusing.
func TestScrapeReportsHTTPError(t *testing.T) {
	got, _ := scrapeAndCollect(t, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
	if len(got) != 1 || got[0] != ScrapeHTTPError {
		t.Fatalf("results = %v, want exactly one %q", got, ScrapeHTTPError)
	}
}

// TestScrapeReportsUnparseable: 200 and readable, but carrying none of the
// series the scorer needs. Reported separately because it is the one failure
// an operator can mistake for success — the endpoint is healthy, the HTTP
// exchange completed, and the routing signal is still missing.
func TestScrapeReportsUnparseable(t *testing.T) {
	got, _ := scrapeAndCollect(t, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("# nothing the narrow parser recognises\n"))
		}))
	if len(got) != 1 || got[0] != ScrapeUnparseable {
		t.Fatalf("results = %v, want exactly one %q", got, ScrapeUnparseable)
	}
}

// TestScrapeReportsCarryEndpointAndIndex: the report identifies WHICH endpoint
// it is about. The exported counter deliberately does not label by endpoint,
// but the hook must still carry it so a different sink can.
func TestScrapeReportsCarryEndpointAndIndex(t *testing.T) {
	srv := httptest.NewServer(healthyFixtureHandler(t))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	// Sparse EP-index space: only slot 7 is populated, so a report that
	// carried a positional index rather than the real one would show up.
	eps := make([]string, 8)
	eps[7] = addr
	sink := newResultSink()
	p := NewPoller(eps, time.Hour, sink)
	p.scrapeOne(context.Background(), 7, addr)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.idxs) != 1 || sink.idxs[0] != 7 || sink.eps[0] != addr {
		t.Fatalf("report = idx %v ep %v, want idx 7 ep %q", sink.idxs, sink.eps, addr)
	}
}

// TestScrapeResultOptionalForPlainSink: a Sink that does NOT implement
// ResultSink is unaffected. The extension is optional by interface assertion
// precisely so the controller's own sink needs no change.
func TestScrapeResultOptionalForPlainSink(t *testing.T) {
	srv := httptest.NewServer(healthyFixtureHandler(t))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	plain := newRecordSink() // implements Sink only
	p := NewPoller([]string{addr}, time.Hour, plain)
	p.scrapeOne(context.Background(), 0, addr) // must not panic
	if plain.count() != 1 {
		t.Fatalf("sample count = %d, want 1", plain.count())
	}
}

// TestEveryScrapeReportsExactlyOnce is the property that makes the counter's
// result set exhaustive rather than merely plausible: across a mix of
// outcomes, the number of reports equals the number of scrapes. A future early
// return that forgets to report fails HERE rather than showing up later as a
// total that quietly undercounts.
func TestEveryScrapeReportsExactlyOnce(t *testing.T) {
	ok := httptest.NewServer(healthyFixtureHandler(t))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	defer bad.Close()
	junk := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("junk\n")) }))
	defer junk.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := l.Addr().String()
	_ = l.Close()

	eps := []string{ok.Listener.Addr().String(), bad.Listener.Addr().String(),
		junk.Listener.Addr().String(), dead}
	sink := newResultSink()
	p := NewPoller(eps, time.Hour, sink)
	for i, ep := range eps {
		p.scrapeOne(context.Background(), i, ep)
	}
	got := sink.got()
	if len(got) != len(eps) {
		t.Fatalf("%d reports for %d scrapes: %v", len(got), len(eps), got)
	}
	want := map[string]bool{ScrapeOK: true, ScrapeHTTPError: true,
		ScrapeUnparseable: true, ScrapeUnreachable: true}
	for _, r := range got {
		if !want[r] {
			t.Errorf("unexpected outcome %q in %v", r, got)
		}
		delete(want, r)
	}
	if len(want) != 0 {
		t.Errorf("outcomes never reported: %v (got %v)", want, got)
	}
}
