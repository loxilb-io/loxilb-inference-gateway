/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

// eppMetric reads one labelled counter of the EPP metric families (M8)
// from the default registry; 0 when the series does not exist yet.
func eppMetric(t *testing.T, name, label, value string) float64 {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == label && l.GetValue() == value {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func eppHistogramCount(t *testing.T, name string) uint64 {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == name && f.GetType() == dto.MetricType_HISTOGRAM && len(f.GetMetric()) > 0 {
			return f.GetMetric()[0].GetHistogram().GetSampleCount()
		}
	}
	return 0
}

// completion checks, end to end through the in-process data
// plane (the loxinet harness runs the sockproxy workers): an EPP rule's
// request is handed to Go, the client parks without blocking its worker,
// the decision resumes it, and a deadline, a client that leaves or a
// recycled slot leaks nothing. Needs TestMain -> loxiNetInit (root).

const eppTestVIP = "127.0.0.1"

// eppTestSeen is what a test backend saw of its last request.
type eppTestSeen struct {
	mu      sync.Mutex
	hits    int
	body    string
	headers http.Header
}

func eppTestBackend(t *testing.T) (*httptest.Server, cmn.LbEndPointArg) {
	_, ep, _ := eppTestBackendSeen(t, "a")
	return nil, ep
}

// eppTestBackendSeen starts a backend named `name` that answers
// {"served":"<name>"} and records the request it received.
func eppTestBackendSeen(t *testing.T, name string) (*httptest.Server, cmn.LbEndPointArg, *eppTestSeen) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return eppTestBackendOn(t, name, l)
}

// eppTestBackendOn serves the `name` backend on an existing listener (one
// bound elsewhere than loopback, say).
func eppTestBackendOn(t *testing.T, name string, l net.Listener) (*httptest.Server, cmn.LbEndPointArg, *eppTestSeen) {
	t.Helper()
	seen := &eppTestSeen{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen.mu.Lock()
		seen.hits++
		seen.body = string(body)
		seen.headers = r.Header.Clone()
		seen.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"served":"%s","bytes":%d}`, name, len(body))
	}))
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(l.Addr().String())
	var p int
	fmt.Sscanf(port, "%d", &p)
	return srv, cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), Weight: 1}, seen
}

func eppAddr(ep cmn.LbEndPointArg) string { return fmt.Sprintf("%s:%d", ep.EpIP, ep.EpPort) }

// eppTestAddRule/eppTestDeleteRule follow the management API's caller-lock
// contract while the native harness's zone ticker is running.
func eppTestAddRule(serv cmn.LbServiceArg, eps []cmn.LbEndPointArg) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()
	return mh.zr.Rules.AddLbRule(serv, nil, nil, nil, eps)
}

func eppTestDeleteRule(serv cmn.LbServiceArg) (int, error) {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()
	return mh.zr.Rules.DeleteLbRule(serv)
}

func eppTestRuleMark(key string) int {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()
	return mh.zr.Rules.GetLBRuleMarkByKey(key)
}

func eppTestRule(t *testing.T, port uint16, eppAddr, failureMode string, timeoutMs uint32, eps ...cmn.LbEndPointArg) cmn.LbServiceArg {
	t.Helper()
	serv := cmn.LbServiceArg{
		ServIP: eppTestVIP, ServPort: port, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelRr,
		EppEndpoint: eppAddr, EppFailureMode: failureMode, EppTimeoutMs: timeoutMs, EppPlaintext: true,
	}
	if _, err := eppTestAddRule(serv, eps); err != nil {
		t.Fatalf("add rule on :%d: %v", port, err)
	}
	t.Cleanup(func() { eppTestDeleteRule(serv) })
	return serv
}

// eppTestRequest sends one JSON POST through the VIP and returns the
// status code and body, or an error (a cut connection).
func eppTestRequest(port uint16, body string, timeout time.Duration) (int, string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(eppTestVIP, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		eppTestVIP, port, len(body), body)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// eppTestResponsePhase waits for the fake EPP's stream to end and checks
// what the response phase told it (M6): the status under the plain "status"
// key, the served endpoint, and the end of stream.
func eppTestResponsePhase(t *testing.T, f *epptest.Fake, wantStatus string, wantServed string) {
	t.Helper()
	select {
	case <-f.StreamClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("the EPP stream did not end after the response")
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.RespStatus["status"] != wantStatus || f.RespStatus[":status"] != wantStatus {
		t.Fatalf("EPP saw response status %v, want %s", f.RespStatus, wantStatus)
	}
	if f.Served != wantServed {
		t.Fatalf("EPP saw served=%q, want %q", f.Served, wantServed)
	}
	if !f.RespEOS {
		t.Fatal("EPP did not get the end of stream")
	}
}

func eppTestSettled(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if EppInflight() == 0 && EppPendingDecisions() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("EPP state did not settle: inflight=%d pending=%d", EppInflight(), EppPendingDecisions())
}

func TestEppParkResumeThroughDataPlane(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	_, ep := eppTestBackend(t)
	body := `{"model":"alias","prompt":"hello"}`

	t.Run("decision resumes the request", func(t *testing.T) {
		f := epptest.New("ok")
		f.Dest = eppAddr(ep) // M5 pins the decision: name the rule's endpoint
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28100, addr, cmn.EppFailureModeFailClose, 3000, ep)
		code, resp, err := eppTestRequest(28100, body, 5*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"a"`) {
			t.Fatalf("code=%d resp=%q err=%v", code, resp, err)
		}
		f.Mu.Lock()
		defer f.Mu.Unlock()
		if f.ReqHeaders[":method"] != "POST" || f.ReqHeaders[":path"] != "/v1/completions" || string(f.Body) != body {
			t.Fatalf("EPP saw headers=%v body=%q", f.ReqHeaders, f.Body)
		}
		if len(f.Subset) != 1 || f.Subset[0] != fmt.Sprintf("%s:%d", ep.EpIP, ep.EpPort) {
			t.Fatalf("EPP saw subset %v, want the rule's healthy endpoint", f.Subset)
		}
		f.Mu.Unlock()
		eppTestResponsePhase(t, f, "200", eppAddr(ep))
		f.Mu.Lock()
		eppTestSettled(t)
	})

	t.Run("deadline: FailOpen falls back, FailClose answers 503", func(t *testing.T) {
		f := epptest.New("hang")
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28102, addr, cmn.EppFailureModeFailOpen, 300, ep)
		eppTestRule(t, 28104, addr, cmn.EppFailureModeFailClose, 300, ep)
		start := time.Now()
		code, _, err := eppTestRequest(28102, body, 5*time.Second)
		if err != nil || code != 200 {
			t.Fatalf("FailOpen after the deadline: code=%d err=%v", code, err)
		}
		if el := time.Since(start); el < 250*time.Millisecond || el > 3*time.Second {
			t.Fatalf("FailOpen took %s, want about the 300 ms deadline", el)
		}
		code, resp, err := eppTestRequest(28104, body, 5*time.Second)
		if err != nil || code != 503 || !strings.Contains(resp, "epp_unavailable") {
			t.Fatalf("FailClose after the deadline: code=%d resp=%q err=%v", code, resp, err)
		}
		eppTestSettled(t)
	})

	t.Run("immediate response is relayed", func(t *testing.T) {
		f := epptest.New("immediate")
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28106, addr, cmn.EppFailureModeFailClose, 3000, ep)
		code, resp, err := eppTestRequest(28106, body, 5*time.Second)
		if err != nil || code != 429 || !strings.Contains(resp, "shed") {
			t.Fatalf("immediate: code=%d resp=%q err=%v", code, resp, err)
		}
		eppTestSettled(t)
	})

	t.Run("a parked request does not block other connections", func(t *testing.T) {
		f := epptest.New("hang")
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28108, addr, cmn.EppFailureModeFailOpen, 2000, ep)
		plain := cmn.LbServiceArg{ServIP: eppTestVIP, ServPort: 28110, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelRr}
		if _, err := eppTestAddRule(plain, []cmn.LbEndPointArg{ep}); err != nil {
			t.Fatal(err)
		}
		defer eppTestDeleteRule(plain)

		// Park several requests on every worker, then push plain traffic
		// through: it must complete long before the parked ones resume.
		const parked = 16
		var wg sync.WaitGroup
		for i := 0; i < parked; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				eppTestRequest(28108, body, 10*time.Second)
			}()
		}
		time.Sleep(200 * time.Millisecond)
		if EppInflight() != parked {
			t.Fatalf("%d requests parked, want %d", EppInflight(), parked)
		}
		start := time.Now()
		for i := 0; i < 8; i++ {
			code, _, err := eppTestRequest(28110, body, 5*time.Second)
			if err != nil || code != 200 {
				t.Fatalf("plain request %d while %d are parked: code=%d err=%v", i, parked, code, err)
			}
		}
		if el := time.Since(start); el > time.Second {
			t.Fatalf("plain requests took %s while EPP requests were parked", el)
		}
		wg.Wait()
		eppTestSettled(t)
	})

	t.Run("a client that leaves while parked aborts the stream", func(t *testing.T) {
		f := epptest.New("hang")
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28112, addr, cmn.EppFailureModeFailOpen, 5000, ep)
		conn, err := net.Dial("tcp", net.JoinHostPort(eppTestVIP, "28112"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "POST /v1/completions HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		time.Sleep(200 * time.Millisecond)
		if EppInflight() != 1 {
			t.Fatalf("inflight=%d, want the parked request", EppInflight())
		}
		conn.Close()
		select {
		case <-f.StreamClosed:
		case <-time.After(3 * time.Second):
			t.Fatal("the EPP did not see the stream end after the client left")
		}
		eppTestSettled(t)
	})
}

// the EPP's decision is applied — its first usable candidate
// gets the request, with the header and body mutations; unusable
// candidates (unknown to the rule, down) are skipped in order; with none
// usable the failure mode decides.
func TestEppDecisionPinsEndpoint(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	_, epA, seenA := eppTestBackendSeen(t, "a")
	_, epB, seenB := eppTestBackendSeen(t, "b")
	body := `{"model":"alias","prompt":"hello"}`
	dead := func() cmn.LbEndPointArg {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		_, port, _ := net.SplitHostPort(l.Addr().String())
		l.Close()
		var p int
		fmt.Sscanf(port, "%d", &p)
		return cmn.LbEndPointArg{EpIP: "127.0.0.1", EpPort: uint16(p), Weight: 1}
	}()
	hits := func(s *eppTestSeen) int { s.mu.Lock(); defer s.mu.Unlock(); return s.hits }

	t.Run("second endpoint named first wins, mutations reach it", func(t *testing.T) {
		f := epptest.New("ok")
		f.Dest = eppAddr(epB) + "," + eppAddr(epA)
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28120, addr, cmn.EppFailureModeFailClose, 3000, epA, epB)
		a0, b0 := hits(seenA), hits(seenB)
		reqBody := body
		code, resp, err := eppTestRequest(28120, reqBody, 5*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"b"`) {
			t.Fatalf("code=%d resp=%q err=%v (want backend b)", code, resp, err)
		}
		if hits(seenA) != a0 || hits(seenB) != b0+1 {
			t.Fatalf("hits a=%d->%d b=%d->%d", a0, hits(seenA), b0, hits(seenB))
		}
		seenB.mu.Lock()
		defer seenB.mu.Unlock()
		if seenB.headers.Get("X-Prefiller-Host-Port") != "10.0.0.9:8000" {
			t.Fatalf("prefill hint did not reach the backend: %v", seenB.headers)
		}
		if seenB.headers.Get("X-Drop") != "" {
			t.Fatalf("removed header reached the backend: %v", seenB.headers)
		}
		if !strings.Contains(seenB.body, `"model":"served-model"`) || seenB.headers.Get("Content-Length") != fmt.Sprint(len(seenB.body)) {
			t.Fatalf("rewritten body or its length wrong: body=%q cl=%q", seenB.body, seenB.headers.Get("Content-Length"))
		}
		seenB.mu.Unlock()
		eppTestResponsePhase(t, f, "200", eppAddr(epB))
		seenB.mu.Lock()
		eppTestSettled(t)
	})

	t.Run("dead and unknown candidates are skipped in order", func(t *testing.T) {
		f := epptest.New("echo")
		f.Dest = "10.9.9.9:1," + eppAddr(dead) + "," + eppAddr(epA)
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28122, addr, cmn.EppFailureModeFailClose, 3000, epA, epB, dead)
		code, resp, err := eppTestRequest(28122, body, 8*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"a"`) {
			t.Fatalf("code=%d resp=%q err=%v (want backend a after the dead one)", code, resp, err)
		}
		eppTestResponsePhase(t, f, "200", eppAddr(epA))
		eppTestSettled(t)
	})

	t.Run("no usable candidate: FailClose 503, FailOpen falls back", func(t *testing.T) {
		f := epptest.New("echo")
		f.Dest = "10.9.9.9:1," + eppAddr(dead)
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28124, addr, cmn.EppFailureModeFailClose, 3000, epA, dead)
		eppTestRule(t, 28126, addr, cmn.EppFailureModeFailOpen, 3000, epA, dead)
		code, resp, err := eppTestRequest(28124, body, 8*time.Second)
		if err != nil || code != 503 || !strings.Contains(resp, "epp_no_endpoint") {
			t.Fatalf("FailClose: code=%d resp=%q err=%v", code, resp, err)
		}
		code, resp, err = eppTestRequest(28126, body, 8*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"a"`) {
			t.Fatalf("FailOpen: code=%d resp=%q err=%v", code, resp, err)
		}
		eppTestSettled(t)
	})
}

// failure handling the data plane decides after the decision —
// an EPP that is down (connection refused, the shape of NOT_SERVING and of
// a restart gap) takes the failure mode, and a request the EPP evicts
// during its response is cut. M8: the counters explain each run.
func TestEppFailureHandlingAndMetrics(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	_, ep, _ := eppTestBackendSeen(t, "a")
	body := `{"model":"alias","prompt":"hello"}`

	t.Run("EPP down: FailOpen falls back, FailClose answers 503", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := l.Addr().String()
		l.Close()
		eppTestRule(t, 28130, addr, cmn.EppFailureModeFailOpen, 2000, ep)
		eppTestRule(t, 28132, addr, cmn.EppFailureModeFailClose, 2000, ep)
		errors0 := eppMetric(t, "loxilb_ai_epp_requests_total", "outcome", "error")
		code, resp, err := eppTestRequest(28130, body, 5*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"a"`) {
			t.Fatalf("FailOpen with the EPP down: code=%d resp=%q err=%v", code, resp, err)
		}
		code, resp, err = eppTestRequest(28132, body, 5*time.Second)
		if err != nil || code != 503 || !strings.Contains(resp, "epp_unavailable") {
			t.Fatalf("FailClose with the EPP down: code=%d resp=%q err=%v", code, resp, err)
		}
		if got := eppMetric(t, "loxilb_ai_epp_requests_total", "outcome", "error"); got != errors0+2 {
			t.Fatalf("error outcomes %v -> %v, want +2", errors0, got)
		}
		eppTestSettled(t)
	})

	t.Run("eviction during a streaming response cuts the relay", func(t *testing.T) {
		slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			for i := 0; i < 40; i++ {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
				fmt.Fprintf(w, "data: {\"i\":%d}\n\n", i)
				w.(http.Flusher).Flush()
			}
		}))
		defer slow.Close()
		host, port, _ := net.SplitHostPort(strings.TrimPrefix(slow.URL, "http://"))
		var p int
		fmt.Sscanf(port, "%d", &p)
		slowEp := cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), Weight: 1}
		f := epptest.New("evict")
		f.Dest = eppAddr(slowEp)
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28134, addr, cmn.EppFailureModeFailClose, 3000, slowEp)
		evicted0 := eppMetric(t, "loxilb_ai_epp_requests_total", "outcome", "evicted")

		conn, err := net.Dial("tcp", net.JoinHostPort(eppTestVIP, "28134"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "POST /v1/completions HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		start := time.Now()
		got, _ := io.ReadAll(conn) // ends when the relay is cut
		took := time.Since(start)
		if !strings.HasPrefix(string(got), "HTTP/1.1 200") {
			t.Fatalf("response head %q", got)
		}
		if took > 2*time.Second {
			t.Fatalf("the stream ran %s after the eviction; want it cut", took)
		}
		if got := eppMetric(t, "loxilb_ai_epp_requests_total", "outcome", "evicted"); got != evicted0+1 {
			t.Fatalf("evicted outcomes %v -> %v, want +1", evicted0, got)
		}
		eppTestSettled(t)
	})

	t.Run("counters explain a routed request", func(t *testing.T) {
		_, epB, _ := eppTestBackendSeen(t, "b")
		f := epptest.New("echo")
		f.Dest = "10.9.9.9:1," + eppAddr(epB)
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppTestRule(t, 28136, addr, cmn.EppFailureModeFailClose, 3000, ep, epB)
		ok0 := eppMetric(t, "loxilb_ai_epp_requests_total", "outcome", "ok")
		unknown0 := eppMetric(t, "loxilb_ai_epp_candidates_rejected_total", "reason", "unknown")
		dur0 := eppHistogramCount(t, "loxilb_ai_epp_duration_seconds")
		code, resp, err := eppTestRequest(28136, body, 5*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"b"`) {
			t.Fatalf("code=%d resp=%q err=%v", code, resp, err)
		}
		if got := eppMetric(t, "loxilb_ai_epp_requests_total", "outcome", "ok"); got != ok0+1 {
			t.Fatalf("ok outcomes %v -> %v", ok0, got)
		}
		if got := eppMetric(t, "loxilb_ai_epp_candidates_rejected_total", "reason", "unknown"); got != unknown0+1 {
			t.Fatalf("unknown rejections %v -> %v", unknown0, got)
		}
		if got := eppHistogramCount(t, "loxilb_ai_epp_duration_seconds"); got != dur0+1 {
			t.Fatalf("duration samples %v -> %v", dur0, got)
		}
		eppTestResponsePhase(t, f, "200", eppAddr(epB))
		eppTestSettled(t)
	})
}

// Two requests on one keep-alive connection are two EPP decisions: the
// second must not ride the first one's state (it would skip the EPP and
// take the rule's selector).
func TestEppKeepAliveRequestsEachAskTheEPP(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	_, epA, _ := eppTestBackendSeen(t, "a")
	_, epB, _ := eppTestBackendSeen(t, "b")
	f := epptest.New("echo")
	f.Dest = eppAddr(epB)
	addr, stop := epptest.Start(t, f, false)
	defer stop()
	eppTestRule(t, 28140, addr, cmn.EppFailureModeFailClose, 3000, epA, epB)
	body := `{"model":"alias","prompt":"hello"}`

	conn, err := net.Dial("tcp", net.JoinHostPort(eppTestVIP, "28140"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	rd := bufio.NewReader(conn)
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(conn, "POST /v1/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		resp, err := http.ReadResponse(rd, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), `"served":"b"`) {
			t.Fatalf("request %d on the kept connection: code=%d body=%q (want the EPP's pod b)", i, resp.StatusCode, b)
		}
		select {
		case <-f.StreamClosed:
		case <-time.After(3 * time.Second):
			t.Fatalf("request %d: the EPP stream did not end", i)
		}
	}
	f.Mu.Lock()
	streams := f.Streams
	f.Mu.Unlock()
	if streams != 3 {
		t.Fatalf("the EPP saw %d streams for 3 keep-alive requests", streams)
	}
	eppTestSettled(t)
}
