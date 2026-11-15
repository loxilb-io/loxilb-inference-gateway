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

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

// eppTestSSEBackend streams a short SSE completion, the shape of a vLLM
// `stream: true` answer, after reading the whole request body.
func eppTestSSEBackend(t *testing.T, name string, chunks int, every time.Duration) cmn.LbEndPointArg {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		for i := 0; i < chunks; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(every):
			}
			fmt.Fprintf(w, "data: {\"choices\":[{\"text\":\"%s%d \"}]}\n\n", name, i)
			w.(http.Flusher).Flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var p int
	fmt.Sscanf(port, "%d", &p)
	return cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), Weight: 1}
}

// eppTestStreamRequest is one kvbench-shaped request: a fresh connection,
// a large JSON body with stream:true, the SSE response read to its end.
func eppTestStreamRequest(port uint16, body string, timeout time.Duration) (int, string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(eppTestVIP, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: %s:%d\r\nAccept-Encoding: identity\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
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

// TestEppFailOpenStreamingKeepsChwblLoadBalanced: a CHWBL rule with the
// EPP in FailOpen, driven the way the 2026-10-13 cluster benchmark drove
// it (12 sessions, 4 concurrent, one connection per request, ~25 KB JSON
// bodies, streamed answers). Every request is answered, and once the
// clients are gone every endpoint's bounded-load count is back to zero:
// no unit leaked (a selection never given back) and none stolen (a release
// of a unit never taken, the "underflow protection" line).
func TestEppFailOpenStreamingKeepsChwblLoadBalanced(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	eps := []cmn.LbEndPointArg{
		eppTestSSEBackend(t, "a", 5, 20*time.Millisecond),
		eppTestSSEBackend(t, "b", 5, 20*time.Millisecond),
		eppTestSSEBackend(t, "c", 5, 20*time.Millisecond),
	}
	f := epptest.New("echo")
	for i := 0; i < 200; i++ {
		f.Dests = append(f.Dests, eppAddr(eps[i%len(eps)]))
	}
	addr, stop := epptest.Start(t, f, false)
	defer stop()
	serv := eppTestRuleSel(t, 28180, addr, cmn.EppFailureModeFailOpen, 3000, cmn.LbSelCHWBL, eps...)
	ruleNum := eppTestRuleMark(fmt.Sprintf("%s:%d:%s", serv.ServIP, serv.ServPort, serv.Proto))
	if ruleNum == 0 {
		t.Fatal("rule number not found")
	}

	const sessions, turns, concurrency = 12, 3, 4
	prefix := make([]string, sessions)
	for s := range prefix {
		prefix[s] = strings.Repeat(fmt.Sprintf("session%02d word ", s), 1500) // ~24 KB
	}
	type job struct{ s, k int }
	jobs := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	ok := 0
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				body := fmt.Sprintf(`{"model":"alias","prompt":"%sQ%d","max_tokens":8,"stream":true}`, prefix[j.s], j.k)
				code, resp, err := eppTestStreamRequest(28180, body, 10*time.Second)
				mu.Lock()
				if err != nil || code != 200 || !strings.Contains(resp, "[DONE]") {
					failures = append(failures, fmt.Sprintf("s%d/t%d: code=%d err=%v resp=%.80q", j.s, j.k, code, err, resp))
				} else {
					ok++
				}
				mu.Unlock()
			}
		}()
	}
	for k := 0; k < turns; k++ {
		for s := 0; s < sessions; s++ {
			jobs <- job{s, k}
		}
	}
	close(jobs)
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("%d of %d requests failed: %v", len(failures), sessions*turns, failures)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		loads := []int{DpChwblEpLoad(uint32(ruleNum), 0), DpChwblEpLoad(uint32(ruleNum), 1), DpChwblEpLoad(uint32(ruleNum), 2)}
		if loads[0] == 0 && loads[1] == 0 && loads[2] == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %d answered requests the endpoints still hold %v bounded-load units, want all 0", ok, loads)
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.Mu.Lock()
	streams := f.Streams
	f.Mu.Unlock()
	t.Logf("%d requests answered, %d EPP streams", ok, streams)
}
