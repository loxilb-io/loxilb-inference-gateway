/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 */
package loxinet

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

func pdBodyTestLimit() int {
	limit, err := strconv.Atoi(os.Getenv("LLB_PD_MAX_BODY_BYTES"))
	if err != nil || limit <= 0 || limit > 768*1024 {
		return 768 * 1024
	}
	return limit
}

func pdBodyTestJSON(size int) string {
	const format = `{"model":"alias","prompt":"%s","max_tokens":16}`
	return fmt.Sprintf(format, strings.Repeat("x", size-(len(format)-2)))
}

func pdBodyTestRequest(t *testing.T, port uint16, request string) (int, http.Header, string) {
	t.Helper()
	k := eppPdDial(t, port)
	k.conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, writeErr := io.WriteString(k.conn, request)
	response, err := http.ReadResponse(k.rd, nil)
	if err != nil {
		t.Fatalf("response read: %v (request write: %v)", err, writeErr)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header, string(body)
}

func TestEppPdBodyPolicy(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	for _, withEpp := range []bool{false, true} {
		t.Run(fmt.Sprintf("EPP=%t", withEpp), func(t *testing.T) {
			prefill, seenP := eppPdTestEngine(t, "prefill", 1, true)
			decode, seenD := eppPdTestEngine(t, "decode", 2, false)
			sidecar, seenS := eppPdTestEngine(t, "sidecar", 0, false)
			port := uint16(28260)
			addr := ""
			if withEpp {
				port++
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr = l.Addr().String()
				l.Close()
			}
			eppPdTestRule(t, port, addr, prefill, decode, sidecar)
			// Wait for the asynchronous rule update using an ordinary inference.
			body := `{"model":"alias","prompt":"ready","max_tokens":16}`
			if code, resp, err := eppTestRequest(port, body, 10*time.Second); err != nil || code != 200 {
				t.Fatalf("initial inference: code=%d resp=%q err=%v", code, resp, err)
			}
			hits := func(s *eppTestSeen) int { s.mu.Lock(); defer s.mu.Unlock(); return s.hits }
			if rc := mh.dpEbpf.DpLBEndpointHealthUpdateByAddr(net.ParseIP(eppTestVIP), port, 6,
				net.ParseIP(prefill.EpIP), prefill.EpPort, true); rc != 0 {
				t.Fatal("mark prefill inactive")
			}
			t.Run("bodyless reaches decode while prefill is down", func(t *testing.T) {
				for _, method := range []string{"GET", "HEAD", "POST"} {
					request := fmt.Sprintf("%s /v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", method, port)
					// HEAD needs a response reader that knows there is no body.
					if method == "HEAD" {
						client := &http.Client{Timeout: 10 * time.Second}
						req, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d/v1/models", port), nil)
						req.Close = true
						resp, err := client.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						resp.Body.Close()
						if resp.StatusCode != 200 || resp.Header.Get("X-Test-Engine") != "decode" {
							t.Errorf("HEAD status=%d engine=%q", resp.StatusCode, resp.Header.Get("X-Test-Engine"))
						}
						continue
					}
					code, headers, response := pdBodyTestRequest(t, port, request)
					if code != 200 || headers.Get("X-Test-Engine") != "decode" {
						t.Errorf("%s code=%d engine=%q response=%s", method, code, headers.Get("X-Test-Engine"), response)
					}
				}
			})
			if rc := mh.dpEbpf.DpLBEndpointHealthUpdateByAddr(net.ParseIP(eppTestVIP), port, 6,
				net.ParseIP(prefill.EpIP), prefill.EpPort, false); rc != 0 {
				t.Fatal("restore prefill")
			}
			t.Run("metadata then inference on a kept connection", func(t *testing.T) {
				k := eppPdDial(t, port)
				k.conn.SetDeadline(time.Now().Add(10 * time.Second))
				fmt.Fprintf(k.conn, "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port)
				response, err := http.ReadResponse(k.rd, nil)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != 200 || response.Header.Get("X-Test-Engine") != "decode" {
					t.Errorf("metadata code=%d engine=%q", response.StatusCode, response.Header.Get("X-Test-Engine"))
				}
				code, answer, err := k.send(body, 10*time.Second)
				if err != nil || code != 200 || !strings.Contains(answer, `"served":"decode"`) {
					t.Errorf("inference code=%d answer=%q err=%v", code, answer, err)
				}
			})
			t.Run("body at the byte limit runs both roles", func(t *testing.T) {
				p0, d0, s0 := hits(seenP), hits(seenD), hits(seenS)
				code, response, err := eppTestRequest(port, pdBodyTestJSON(pdBodyTestLimit()), 15*time.Second)
				if err != nil || code != 200 || !strings.Contains(response, `"served":"decode"`) {
					t.Fatalf("code=%d response=%q err=%v", code, response, err)
				}
				if hits(seenP) != p0+1 || hits(seenD) != d0+1 || hits(seenS) != s0 {
					t.Fatal("bounded inference did not run exactly one prefill and decode")
				}
			})
			streamError := "pd_body_unbufferable"
			if pdBodyTestLimit() < 65*1024 {
				streamError = "pd_body_too_large"
			}
			for _, tc := range []struct {
				name, request, errorCode string
			}{
				{"limit plus one", fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
					port, pdBodyTestLimit()+1, pdBodyTestJSON(pdBodyTestLimit()+1)), "pd_body_too_large"},
				{"oversized upload prefix", fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\nContent-Length: 1049600\r\nConnection: close\r\n\r\n{\"model\":\"alias\",\"prompt\":\"",
					port), "pd_body_too_large"},
				{"chunked inference", fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n%s\r\n0\r\n\r\n",
					port, len(body), body), "pd_body_unbufferable"},
				{"streamed non-JSON body", fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
					port, 65*1024, pdBodyTestJSON(65*1024)), streamError},
			} {
				t.Run(tc.name, func(t *testing.T) {
					p0, d0, s0 := hits(seenP), hits(seenD), hits(seenS)
					code, _, response := pdBodyTestRequest(t, port, tc.request)
					if code != http.StatusRequestEntityTooLarge || !strings.Contains(response, `"error":"`+tc.errorCode+`"`) {
						t.Errorf("code=%d response=%q", code, response)
					}
					if hits(seenP) != p0 || hits(seenD) != d0 || hits(seenS) != s0 {
						t.Error("refused request reached a backend")
					}
				})
			}
			t.Run("unavailable decode has no role fallback", func(t *testing.T) {
				if rc := mh.dpEbpf.DpLBEndpointHealthUpdateByAddr(net.ParseIP(eppTestVIP), port, 6,
					net.ParseIP(decode.EpIP), decode.EpPort, true); rc != 0 {
					t.Fatal("mark decode inactive")
				}
				code, _, response := pdBodyTestRequest(t, port, fmt.Sprintf("GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", port))
				if code != 503 || !strings.Contains(response, "pd_pool_unavailable") {
					t.Errorf("code=%d response=%q", code, response)
				}
			})
		})
	}
}

func TestEppPdBodyPolicyHonorsExplicitPick(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	prefill, _ := eppPdTestEngine(t, "prefill", 1, true)
	decode, _ := eppPdTestEngine(t, "decode", 2, false)
	sidecar, seen := eppPdTestEngine(t, "sidecar", 0, false)
	fake := epptest.New("echo")
	fake.Dest = eppAddr(sidecar)
	addr, stop := epptest.Start(t, fake, false)
	defer stop()
	eppPdTestRule(t, 28263, addr, prefill, decode, sidecar)
	code, response, err := eppTestRequest(28263, pdBodyTestJSON(65*1024), 10*time.Second)
	if err != nil || code != 200 || !strings.Contains(response, `"served":"sidecar"`) {
		t.Fatalf("explicit EPP pick: code=%d response=%q err=%v", code, response, err)
	}
	seen.mu.Lock()
	defer seen.mu.Unlock()
	if seen.hits != 1 {
		t.Errorf("sidecar hits=%d, want 1", seen.hits)
	}
}

func TestEppPdBodylessDecodeOrder(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	prefill, _ := eppPdTestEngine(t, "prefill", 1, true)
	first, _ := eppPdTestEngine(t, "decode-first", 2, false)
	second, _ := eppPdTestEngine(t, "decode-second", 2, false)
	sidecar, _ := eppPdTestEngine(t, "sidecar", 0, false)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	unreachable := cmn.LbEndPointArg{EpIP: "127.0.0.1", EpPort: uint16(p), EpRole: 2, Weight: 1, NixlPort: 5600}
	listener.Close()
	eppPdTestRule(t, 28264, "", prefill, unreachable, first, second, sidecar)
	for attempt := 0; attempt < 3; attempt++ {
		code, headers, response := pdBodyTestRequest(t, 28264, "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:28264\r\nConnection: close\r\n\r\n")
		if code != 200 || headers.Get("X-Test-Engine") != "decode-first" {
			t.Fatalf("attempt %d code=%d engine=%q response=%q", attempt, code, headers.Get("X-Test-Engine"), response)
		}
	}
	if rc := mh.dpEbpf.DpLBEndpointHealthUpdateByAddr(net.ParseIP(eppTestVIP), 28264, 6,
		net.ParseIP(first.EpIP), first.EpPort, true); rc != 0 {
		t.Fatal("mark first decode inactive")
	}
	code, headers, response := pdBodyTestRequest(t, 28264, "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:28264\r\nConnection: close\r\n\r\n")
	if code != 200 || headers.Get("X-Test-Engine") != "decode-second" {
		t.Fatalf("code=%d engine=%q response=%q", code, headers.Get("X-Test-Engine"), response)
	}
}

func TestEppPdBodylessDoesNotHoldRoleCapacity(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	prefill, _ := eppPdTestEngine(t, "prefill", 1, true)
	hit, release := make(chan struct{}, 1), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/metadata-check" {
			hit <- struct{}{}
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"served":"decode","choices":[{"text":"answer"}]}`)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	p, _ := strconv.Atoi(port)
	decode := cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), EpRole: 2, Weight: 1, NixlPort: 5600}
	serv := cmn.LbServiceArg{ServIP: eppTestVIP, ServPort: 28262, Proto: "tcp", Mode: cmn.LBModeFullProxy,
		Sel: cmn.LbSelCHWBL, PDDisaggMode: true, FcMode: "enforce",
		FcPrefillMaxInflight: 1, FcDecodeMaxInflight: 1}
	if _, err := mh.zr.Rules.AddLbRule(serv, nil, nil, nil, []cmn.LbEndPointArg{prefill, decode}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mh.zr.Rules.DeleteLbRule(serv) })
	k := eppPdDial(t, 28262)
	k.conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprint(k.conn, "GET /metadata-check HTTP/1.1\r\nHost: 127.0.0.1:28262\r\nConnection: close\r\n\r\n")
	select {
	case <-hit:
	case <-time.After(3 * time.Second):
		t.Fatal("metadata request did not reach decode")
	}
	code, response, err := eppTestRequest(28262, `{"model":"alias","prompt":"inference while GET waits","max_tokens":16}`, 5*time.Second)
	if err != nil || code != 200 || !strings.Contains(response, `"served":"decode"`) {
		t.Fatalf("bodyless request occupied P/D capacity: code=%d response=%q err=%v", code, response, err)
	}
}
