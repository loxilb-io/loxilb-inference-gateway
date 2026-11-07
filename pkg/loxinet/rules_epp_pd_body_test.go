/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 */
package loxinet

import (
	"crypto/sha256"
	"fmt"
	"github.com/loxilb-io/loxilb/pkg/aikey"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
				p0, d0 := hits(seenP), hits(seenD)
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
				if hits(seenP) != p0+1 || hits(seenD) != d0+1 {
					t.Error("inference after GET did not take the full P/D legs")
				}
				fmt.Fprintf(k.conn, "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", port)
				response, err = http.ReadResponse(k.rd, nil)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != 200 || response.Header.Get("X-Test-Engine") != "decode" {
					t.Errorf("GET after POST code=%d engine=%q", response.StatusCode, response.Header.Get("X-Test-Engine"))
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
			t.Run("reject non-JSON and malformed JSON without backend traffic", func(t *testing.T) {
				for _, tc := range []struct {
					name, media, accept, body string
					status                    int
					code                      string
				}{
					{"octet", "application/octet-stream", "", strings.Repeat("x", 1024), 415, "pd_body_unsupported_media"},
					{"octet Accept decoy", "application/octet-stream", "Accept: application/json\r\n", strings.Repeat("x", 1024), 415, "pd_body_unsupported_media"},
					{"multipart", "multipart/form-data; boundary=x", "", strings.Repeat("x", 1024), 415, "pd_body_unsupported_media"},
					{"binary closing brace", "application/octet-stream", "", strings.Repeat("x", 1023) + "}", 415, "pd_body_unsupported_media"},
					{"JSON array", "application/json", "", `[{"model":"alias"}]`, 400, "invalid_json_body"},
					{"truncated object", "application/json", "", `{"model":"alias","prompt":`, 400, "invalid_json_body"},
				} {
					t.Run(tc.name, func(t *testing.T) {
						p0, d0, s0 := hits(seenP), hits(seenD), hits(seenS)
						request := fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s", port, tc.media, tc.accept, len(tc.body), tc.body)
						code, _, response := pdBodyTestRequest(t, port, request)
						if code != tc.status || !strings.Contains(response, tc.code) {
							t.Errorf("code=%d response=%q", code, response)
						}
						if hits(seenP) != p0 || hits(seenD) != d0 || hits(seenS) != s0 {
							t.Error("refused request reached a backend")
						}
					})
				}
			})
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
					port, 65*1024, pdBodyTestJSON(65*1024)), "pd_body_unsupported_media"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					p0, d0, s0 := hits(seenP), hits(seenD), hits(seenS)
					code, _, response := pdBodyTestRequest(t, port, tc.request)
					want := http.StatusRequestEntityTooLarge
					if tc.errorCode == "pd_body_unsupported_media" {
						want = http.StatusUnsupportedMediaType
					}
					if code != want || !strings.Contains(response, `"error":"`+tc.errorCode+`"`) {
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
	code, _, response = pdBodyTestRequest(t, 28263,
		"POST /v1/completions HTTP/1.1\r\nHost: 127.0.0.1:28263\r\n"+
			"Content-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata")
	if code != 200 || !strings.Contains(response, `"served":"sidecar"`) {
		t.Errorf("explicit EPP non-JSON pick: code=%d response=%q", code, response)
	}
	seen.mu.Lock()
	defer seen.mu.Unlock()
	if seen.hits != 2 {
		t.Errorf("sidecar hits=%d, want 2", seen.hits)
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

func TestEppPdLargeUploadCurl(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	prefill, seenP := eppPdTestEngine(t, "prefill", 1, true)
	decode, seenD := eppPdTestEngine(t, "decode", 2, false)
	sidecar, seenS := eppPdTestEngine(t, "sidecar", 0, false)
	eppPdTestRule(t, 28265, "", prefill, decode, sidecar)
	dir := t.TempDir()
	upload, answer := filepath.Join(dir, "upload.json"), filepath.Join(dir, "answer.json")
	if err := os.WriteFile(upload, []byte(pdBodyTestJSON(2*1024*1024)), 0600); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 4; attempt++ {
		output, err := exec.Command("curl", "--http1.1", "--noproxy", "*", "--max-time", "15",
			"-sS", "-H", "Expect:", "-H", "Content-Type: application/json",
			"--data-binary", "@"+upload, "-o", answer, "-w", "%{http_code}",
			"http://127.0.0.1:28265/v1/completions").CombinedOutput()
		if err != nil || strings.TrimSpace(string(output)) != "413" {
			t.Fatalf("attempt=%d curl exit=%v output=%q", attempt, err, output)
		}
		body, err := os.ReadFile(answer)
		if err != nil || !strings.Contains(string(body), "pd_body_too_large") {
			t.Fatalf("response=%q err=%v", body, err)
		}
	}
	for _, seen := range []*eppTestSeen{seenP, seenD, seenS} {
		seen.mu.Lock()
		hits := seen.hits
		seen.mu.Unlock()
		if hits != 0 {
			t.Errorf("rejected upload reached a backend (%d hits)", hits)
		}
	}
}

// Send a bounded final body fragment and request 2 together. Sending the
// entire near-limit upload in one Write does not guarantee one proxy read.
func pdBodyTestPipeline(t *testing.T, port uint16, body, second string, split bool) *eppPdKeepAlive {
	t.Helper()
	k := eppPdDial(t, port)
	k.conn.SetDeadline(time.Now().Add(5 * time.Second))
	head := fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", eppTestVIP, port, len(body))
	if split {
		if _, err := io.WriteString(k.conn, head+body[:len(body)-64]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond) // first read remains an incomplete message
		head = ""
		body = body[len(body)-64:]
	}
	if _, err := io.WriteString(k.conn, head+body+second); err != nil {
		t.Fatal(err)
	}
	return k
}

func pdBodyTestRead(t *testing.T, k *eppPdKeepAlive, want int) string {
	t.Helper()
	r, err := http.ReadResponse(k.rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != want {
		t.Fatalf("status=%d want=%d body=%s", r.StatusCode, want, b)
	}
	return string(b)
}

func pdBodyTestPlainRule(t *testing.T, port uint16, auth string, ep cmn.LbEndPointArg) {
	t.Helper()
	serv := cmn.LbServiceArg{ServIP: eppTestVIP, ServPort: port, Proto: "tcp", Mode: cmn.LBModeFullProxy, SSEMode: true, ApiKeyAuth: auth}
	ep.EpRole = 0
	if _, err := mh.zr.Rules.AddLbRule(serv, nil, nil, nil, []cmn.LbEndPointArg{ep}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mh.zr.Rules.DeleteLbRule(serv) })
}

func TestEppPdPipelinedBodyBound(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized")
	}
	prefill, p := eppPdTestEngine(t, "prefill", 1, true)
	decode, d := eppPdTestEngine(t, "decode", 2, false)
	sidecar, s := eppPdTestEngine(t, "sidecar", 0, false)
	eppPdTestRule(t, 28266, "", prefill, decode, sidecar)
	second := fmt.Sprintf("GET /v1/models HTTP/1.1\r\nHost: %s:28266\r\nContent-Type: text/plain\r\nX-Padding: %s\r\nConnection: close\r\n\r\n", eppTestVIP, strings.Repeat("x", 256))
	k := pdBodyTestPipeline(t, 28266, pdBodyTestJSON(pdBodyTestLimit()-64), second, true)
	if b := pdBodyTestRead(t, k, 400); !strings.Contains(b, "pd_pipelining_unsupported") {
		t.Fatal(b)
	}
	for _, seen := range []*eppTestSeen{p, d, s} {
		seen.mu.Lock()
		hits := seen.hits
		seen.mu.Unlock()
		if hits != 0 {
			t.Fatalf("pipelined P/D request reached backend: %d hits", hits)
		}
	}
}

func TestEppPdNonPdPipeline(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized")
	}
	ep, _ := eppPdTestEngine(t, "plain", 0, false)
	pdBodyTestPlainRule(t, 28267, cmn.ApiKeyAuthDisabled, ep)
	second := fmt.Sprintf("GET /v1/models HTTP/1.1\r\nHost: %s:28267\r\nContent-Type: text/plain\r\nX-Padding: %s\r\nConnection: close\r\n\r\n", eppTestVIP, strings.Repeat("x", 256))
	for _, nearLimit := range []bool{false, true} {
		t.Run(fmt.Sprintf("near-limit=%t", nearLimit), func(t *testing.T) {
			body := `{"model":"alias","prompt":"hello"}`
			if nearLimit {
				body = pdBodyTestJSON(pdBodyTestLimit() - 64)
			}
			k := pdBodyTestPipeline(t, 28267, body, second, nearLimit)
			pdBodyTestRead(t, k, 200)
			pdBodyTestRead(t, k, 200)
		})
	}
}

func pdBodyTestRequestWithKey(t *testing.T, port uint16, body, key string) int {
	t.Helper()
	request := fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\nX-Api-Key: %s\r\nConnection: close\r\n\r\n%s", eppTestVIP, port, len(body), key, body)
	code, _, _ := pdBodyTestRequest(t, port, request)
	return code
}

func TestEppPdNonPdPipelineCredentials(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized")
	}
	// Cached entries keep this datapath regression independent of a database.
	// Key B is valid but cannot access alias. A second keyless request must
	// likewise fail instead of inheriting key A's captured credential.
	svc := aikey.New()
	for raw, models := range map[string][]string{"review-key-A": nil, "review-key-B": {"other-model"}} {
		sum := sha256.Sum256([]byte(raw))
		svc.Cache.Set(fmt.Sprintf("ak:%x", sum), &cmn.ApiKeyEntry{Enabled: true, AllowedModels: models}, time.Minute)
	}
	saved := mh.AIKeyService
	mh.AIKeyService = svc
	t.Cleanup(func() { mh.AIKeyService = saved })
	ep, seen := eppPdTestEngine(t, "plain-auth", 0, false)
	pdBodyTestPlainRule(t, 28268, cmn.ApiKeyAuthRequired, ep)
	body := `{"model":"alias","prompt":"hello"}`
	control := pdBodyTestRequestWithKey(t, 28268, body, "review-key-A")
	if control != 200 {
		t.Fatalf("first credential control: status=%d", control)
	}
	seen.mu.Lock()
	before := seen.hits
	seen.mu.Unlock()
	for _, key := range []string{"review-key-B", ""} {
		t.Run(key, func(t *testing.T) {
			k := eppPdDial(t, 28268)
			k.conn.SetDeadline(time.Now().Add(5 * time.Second))
			first := fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: %s:28268\r\nContent-Type: application/json\r\nContent-Length: %d\r\nX-Api-Key: review-key-A\r\n\r\n%s", eppTestVIP, len(body), body)
			nextHeader := ""
			if key != "" {
				nextHeader = "X-Api-Key: " + key + "\r\n"
			}
			second := fmt.Sprintf("GET /v1/models HTTP/1.1\r\nHost: %s:28268\r\nX-Model: alias\r\n%sConnection: close\r\n\r\n", eppTestVIP, nextHeader)
			if _, err := io.WriteString(k.conn, first+second); err != nil {
				t.Fatal(err)
			}
			// Both messages are checked before this buffered pair is dispatched.
			// The forbidden request must not reach the backend.
			want := 403
			if key == "" {
				want = 401
			}
			pdBodyTestRead(t, k, want)
			seen.mu.Lock()
			hits := seen.hits
			seen.mu.Unlock()
			if hits != before {
				t.Fatalf("refused pipeline reached backend: %d->%d", before, hits)
			}
		})
	}
	// A later valid key must never authorize an earlier missing/restricted key.
	for _, tc := range []struct {
		name, first string
		want        int
	}{
		{"missing first key cannot borrow later valid key", "", 401},
		{"restricted first key cannot borrow later valid key", "review-key-B", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := eppPdDial(t, 28268)
			k.conn.SetDeadline(time.Now().Add(5 * time.Second))
			firstKey := ""
			if tc.first != "" {
				firstKey = "X-Api-Key: " + tc.first + "\r\n"
			}
			first := fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: %s:28268\r\nContent-Type: application/json\r\nContent-Length: %d\r\n%s\r\n%s", eppTestVIP, len(body), firstKey, body)
			second := fmt.Sprintf("GET /v1/models HTTP/1.1\r\nHost: %s:28268\r\nX-Model: alias\r\nX-Api-Key: review-key-A\r\nConnection: close\r\n\r\n", eppTestVIP)
			if _, err := io.WriteString(k.conn, first+second); err != nil {
				t.Fatal(err)
			}
			pdBodyTestRead(t, k, tc.want)
			seen.mu.Lock()
			hits := seen.hits
			seen.mu.Unlock()
			if hits != before {
				t.Fatalf("earlier unauthorized request reached backend: %d->%d", before, hits)
			}
		})
	}

}

func TestEppPdRefusalWorkerLatency(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized")
	}
	if os.Getenv("LLB_PROXY_WORKERS") != "1" {
		t.Skip("requires one worker to prove same-worker latency")
	}
	prefill, _ := eppPdTestEngine(t, "prefill", 1, true)
	decode, _ := eppPdTestEngine(t, "decode", 2, false)
	eppPdTestRule(t, 28269, "", prefill, decode)
	request := fmt.Sprintf("GET /v1/models HTTP/1.1\r\nHost: %s:28269\r\nConnection: close\r\n\r\n", eppTestVIP)
	start := time.Now()
	pdBodyTestRequest(t, 28269, request)
	baseline := time.Since(start)
	for trial := 0; trial < 5; trial++ {
		upload := eppPdDial(t, 28269)
		upload.conn.SetDeadline(time.Now().Add(3 * time.Second))
		// A declared 2 MiB upload, initially only 1 KiB, then 1 KiB/s.
		fmt.Fprintf(upload.conn, "POST /v1/completions HTTP/1.1\r\nHost: %s:28269\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", eppTestVIP, 2*1024*1024, `{"model":"alias","prompt":"`+strings.Repeat(" ", 1000))
		done := make(chan struct{})
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if _, err := io.WriteString(upload.conn, strings.Repeat(" ", 1024)); err != nil {
						return
					}
				}
			}
		}()
		time.Sleep(10 * time.Millisecond)
		start = time.Now()
		code, _, _ := pdBodyTestRequest(t, 28269, request)
		elapsed := time.Since(start)
		close(done)
		pdBodyTestRead(t, upload, 413)
		upload.conn.Close()
		t.Logf("one worker baseline=%s concurrent=%s trial=%d", baseline, elapsed, trial)
		if code != 200 || elapsed > baseline+100*time.Millisecond {
			t.Fatalf("normal request stalled: status=%d elapsed=%s baseline=%s", code, elapsed, baseline)
		}
	}
}
