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
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/epp/epptest"
)

// eppPdTestEngine is a prefill or decode engine stand-in for the EPP-primary
// P/D tests. A prefill engine answers the gateway's probe with vLLM-shaped
// kv_transfer_params; a decode (or sidecar) engine answers a plain
// completion. Both record what they were sent.
func eppPdTestEngine(t *testing.T, name string, role int, prefill bool) (cmn.LbEndPointArg, *eppTestSeen) {
	t.Helper()
	seen := &eppTestSeen{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost {
			// The gateway's own GET probes of a pd_disagg rule's engines
			// (model/role discovery) are not legs of the request under test.
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"object":"list","data":[{"id":"alias"}]}`)
			return
		}
		seen.mu.Lock()
		seen.hits++
		seen.body = string(body)
		seen.headers = r.Header.Clone()
		seen.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if prefill {
			fmt.Fprintf(w, `{"id":"cmpl-p","object":"text_completion","model":"alias","choices":[{"index":0,"text":"","finish_reason":"length"}],`+
				`"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5},`+
				`"kv_transfer_params":{"do_remote_prefill":true,"do_remote_decode":false,"remote_block_ids":[[1,2,3]],"remote_host":"127.0.0.1","remote_port":5600,"remote_engine_id":"prefill-%s","remote_request_id":"rr-1","tp_size":1}}`, name)
			return
		}
		fmt.Fprintf(w, `{"id":"cmpl-d","object":"text_completion","model":"alias","served":"%s","choices":[{"index":0,"text":"answer","finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`, name)
	}))
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(l.Addr().String())
	var p int
	fmt.Sscanf(port, "%d", &p)
	ep := cmn.LbEndPointArg{EpIP: host, EpPort: uint16(p), Weight: 1, EpRole: role}
	if role != 0 {
		ep.NixlPort = 5600
	}
	return ep, seen
}

func eppPdTestRule(t *testing.T, port uint16, eppAddr string, eps ...cmn.LbEndPointArg) cmn.LbServiceArg {
	t.Helper()
	serv := cmn.LbServiceArg{
		ServIP: eppTestVIP, ServPort: port, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelCHWBL,
		PDDisaggMode: true,
		EppEndpoint:  eppAddr, EppFailureMode: cmn.EppFailureModeFailOpen, EppTimeoutMs: 2000, EppPlaintext: true,
	}
	if _, err := mh.zr.Rules.AddLbRule(serv, nil, nil, nil, eps); err != nil {
		t.Fatalf("add rule on :%d: %v", port, err)
	}
	t.Cleanup(func() { mh.zr.Rules.DeleteLbRule(serv) })
	return serv
}

// eppPdKeepAlive is one client connection that sends several requests in a
// row (HTTP/1.1 keep-alive), the way most clients talk to the gateway.
type eppPdKeepAlive struct {
	conn net.Conn
	rd   *bufio.Reader
	port uint16
}

func eppPdDial(t *testing.T, port uint16) *eppPdKeepAlive {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(eppTestVIP, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &eppPdKeepAlive{conn: conn, rd: bufio.NewReader(conn), port: port}
}

func (k *eppPdKeepAlive) send(body string, timeout time.Duration) (int, string, error) {
	k.conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("POST /v1/completions HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		eppTestVIP, k.port, len(body), body)
	if _, err := k.conn.Write([]byte(req)); err != nil {
		return 0, "", err
	}
	resp, err := http.ReadResponse(k.rd, nil)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// EPP-primary P/D: a rule that names an EPP and runs pd_disagg_mode. While
// the EPP answers, its candidate (the decode pod's routing sidecar, ep_role 0)
// is served plainly - the gateway's own prefill/decode machine stays out of
// the request. When the EPP is down, FailOpen hands the request to the rule's
// own ladder, which on a pd_disagg rule runs the two legs itself: a probe to
// a prefill engine (ep_role 1) and the original request, carrying the
// prefill's kv_transfer_params, to a decode engine (ep_role 2).
func TestEppOnPdDisaggRule(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	prefill, seenP := eppPdTestEngine(t, "prefill", 1, true)
	decode, seenD := eppPdTestEngine(t, "decode", 2, false)
	sidecar, seenS := eppPdTestEngine(t, "sidecar", 0, false)
	hits := func(s *eppTestSeen) int { s.mu.Lock(); defer s.mu.Unlock(); return s.hits }
	bodyOf := func(s *eppTestSeen) string { s.mu.Lock(); defer s.mu.Unlock(); return s.body }
	body := `{"model":"alias","prompt":"hello pd","max_tokens":16}`

	t.Run("EPP names the sidecar: served plainly, no P/D legs", func(t *testing.T) {
		f := epptest.New("echo")
		f.Dest = eppAddr(sidecar)
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppPdTestRule(t, 28210, addr, prefill, decode, sidecar)
		p0, d0, s0 := hits(seenP), hits(seenD), hits(seenS)
		code, resp, err := eppTestRequest(28210, body, 8*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"sidecar"`) {
			t.Fatalf("code=%d resp=%q err=%v (want the sidecar's answer)", code, resp, err)
		}
		if hits(seenS) != s0+1 || hits(seenP) != p0 || hits(seenD) != d0 {
			t.Fatalf("hits sidecar %d->%d prefill %d->%d decode %d->%d: the gateway ran a P/D leg on an EPP-pinned request",
				s0, hits(seenS), p0, hits(seenP), d0, hits(seenD))
		}
		got := bodyOf(seenS)
		if !strings.Contains(got, `"max_tokens":16`) || strings.Contains(got, "kv_transfer_params") {
			t.Fatalf("the EPP-pinned request was rewritten as a prefill probe: %q", got)
		}
		seenS.mu.Lock()
		hint := seenS.headers.Get("X-Prefiller-Host-Port")
		seenS.mu.Unlock()
		if hint != "10.0.0.9:8000" {
			t.Fatalf("the EPP's prefill hint did not reach the sidecar: %q", hint)
		}
		eppTestResponsePhase(t, f, "200", eppAddr(sidecar))
		eppTestSettled(t)
	})

	t.Run("EPP down: FailOpen runs the rule's own prefill and decode legs", func(t *testing.T) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := l.Addr().String()
		l.Close()
		eppPdTestRule(t, 28212, addr, prefill, decode, sidecar)
		p0, d0, s0 := hits(seenP), hits(seenD), hits(seenS)
		code, resp, err := eppTestRequest(28212, body, 10*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"decode"`) {
			t.Fatalf("code=%d resp=%q err=%v (want the decode engine's answer)", code, resp, err)
		}
		if hits(seenP) != p0+1 || hits(seenD) != d0+1 || hits(seenS) != s0 {
			t.Fatalf("hits prefill %d->%d decode %d->%d sidecar %d->%d: want one prefill leg, one decode leg, no sidecar",
				p0, hits(seenP), d0, hits(seenD), s0, hits(seenS))
		}
		probe := bodyOf(seenP)
		if !strings.Contains(probe, `"max_tokens":1`) || strings.Contains(probe, `"max_tokens":16`) || !strings.Contains(probe, "kv_transfer_params") {
			t.Fatalf("prefill leg is not the one-token probe: %q", probe)
		}
		dec := bodyOf(seenD)
		if !strings.Contains(dec, `"max_tokens":16`) || !strings.Contains(dec, `"remote_block_ids"`) {
			t.Fatalf("decode leg lacks the original request or the relayed kv_transfer_params: %q", dec)
		}
		eppTestSettled(t)
	})

	for _, tc := range []struct {
		name string
		port uint16
		down cmn.LbEndPointArg
	}{
		{"prefill unavailable", 28216, prefill},
		{"decode unavailable", 28218, decode},
	} {
		t.Run("EPP down: FailOpen refuses "+tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := l.Addr().String()
			l.Close()
			eppPdTestRule(t, tc.port, addr, prefill, decode, sidecar)

			// Confirm the rule is live before toggling a single role in the datapath.
			if code, resp, err := eppTestRequest(tc.port, body, 10*time.Second); err != nil ||
				code != http.StatusOK || !strings.Contains(resp, `"served":"decode"`) {
				t.Fatalf("healthy P/D rule: code=%d resp=%q err=%v", code, resp, err)
			}
			if rc := mh.dpEbpf.DpLBEndpointHealthUpdateByAddr(net.ParseIP(eppTestVIP), tc.port, 6,
				net.ParseIP(tc.down.EpIP), tc.down.EpPort, true); rc != 0 {
				t.Fatalf("mark %s inactive: rc=%d", eppAddr(tc.down), rc)
			}
			p0, d0, s0 := hits(seenP), hits(seenD), hits(seenS)
			code, resp, err := eppTestRequest(tc.port, body, 10*time.Second)
			if err != nil || code != http.StatusServiceUnavailable ||
				!strings.Contains(resp, `"error":"pd_pool_unavailable"`) {
				t.Errorf("code=%d resp=%q err=%v (want 503 pd_pool_unavailable)", code, resp, err)
			}
			if hits(seenP) != p0 || hits(seenD) != d0 || hits(seenS) != s0 {
				t.Errorf("refused request reached a backend: prefill %d->%d decode %d->%d sidecar %d->%d",
					p0, hits(seenP), d0, hits(seenD), s0, hits(seenS))
			}
			eppTestSettled(t)
		})
	}

	t.Run("kept connection: a refused submit after a pinned request still runs the P/D legs", func(t *testing.T) {
		f := epptest.New("echo")
		f.Dest = eppAddr(sidecar)
		addr, stop := epptest.Start(t, f, false)
		defer stop()
		eppPdTestRule(t, 28214, addr, prefill, decode, sidecar)
		k := eppPdDial(t, 28214)
		p0, d0, s0 := hits(seenP), hits(seenD), hits(seenS)
		code, resp, err := k.send(body, 8*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"sidecar"`) {
			t.Fatalf("request 1: code=%d resp=%q err=%v (want the sidecar's answer)", code, resp, err)
		}
		eppTestResponsePhase(t, f, "200", eppAddr(sidecar))
		// The EPP's in-flight cap is full: the next submit is refused before a
		// stream id exists, the earliest FailOpen there is.
		saved := eppMaxInflight
		eppMaxInflight = 0
		defer func() { eppMaxInflight = saved }()
		code, resp, err = k.send(body, 10*time.Second)
		if err != nil || code != 200 || !strings.Contains(resp, `"served":"decode"`) {
			t.Fatalf("request 2: code=%d resp=%q err=%v (want the decode engine's answer)", code, resp, err)
		}
		if hits(seenP) != p0+1 || hits(seenD) != d0+1 || hits(seenS) != s0+1 {
			t.Fatalf("hits prefill %d->%d decode %d->%d sidecar %d->%d: want the first request on the sidecar and the second as one prefill leg + one decode leg",
				p0, hits(seenP), d0, hits(seenD), s0, hits(seenS))
		}
		if probe := bodyOf(seenP); !strings.Contains(probe, `"max_tokens":1`) || !strings.Contains(probe, "kv_transfer_params") {
			t.Fatalf("the pin of request 1 leaked into request 2: prefill leg is not the probe: %q", probe)
		}
		eppMaxInflight = saved
		eppTestSettled(t)
	})
}
