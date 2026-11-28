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
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// A replace of a CHWBL or WRR_HASH rule, end to end through the in-process
// data plane (the loxinet harness, run as root): what the rule declares is
// what is stored, what GET reports and what the installed pool enforces,
// including when the data plane refuses the push.
//
// The data plane refuses a WRR_HASH pool in which no endpoint can take a
// request: a paused rule (every endpoint inactive) is such a pool.

// replLiveReq sends one keyless request on a new connection and returns the
// status and the gateway's refusal stage ("" for an answer of the backend).
func replLiveReq(port uint16) (int, string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(eppTestVIP, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	body := `{"model":"m","prompt":"p"}`
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
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get("X-Loxilb-Refusal-Stage"), nil
}

func replLiveServ(port uint16, sel cmn.EpSelect, auth string, up bool) cmn.LbServiceArg {
	return cmn.LbServiceArg{ServIP: eppTestVIP, ServPort: port, Proto: "tcp", Mode: cmn.LBModeFullProxy,
		Sel: sel, SSEMode: true, FcMode: "observe", ApiKeyAuth: auth, AdminStateUp: &up}
}

func replLiveRead(t *testing.T, port uint16) cmn.LbServiceArg {
	t.Helper()
	mh.mtx.Lock()
	rules, err := mh.zr.Rules.GetLBRule()
	mh.mtx.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Serv.ServPort == port && r.Serv.ServIP == eppTestVIP {
			return r.Serv
		}
	}
	t.Fatalf("rule :%d not read back", port)
	return cmn.LbServiceArg{}
}

// replLiveExpect: a keyless request is refused by the gateway's credential
// check (wantStage "auth"), or answered by the backend (wantStage "").
func replLiveExpect(t *testing.T, what string, port uint16, wantStage string) {
	t.Helper()
	var code int
	var stage string
	var err error
	for i := 0; i < 20; i++ { // the push is asynchronous: give it a moment
		code, stage, err = replLiveReq(port)
		if err == nil && stage == wantStage && (wantStage != "" || code == 200) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("%s: keyless request on :%d: status %d, refusal stage %q, err %v; want stage %q", what, port, code, stage, err, wantStage)
}

func replLiveAdd(serv cmn.LbServiceArg, eps []cmn.LbEndPointArg) (int, error) {
	return eppTestAddRule(serv, eps)
}

// A rule-level pause and resume (an AddLbRule replace with admin_state
// false, then true; REST POST does not carry admin_state and PATCH refuses a
// full-proxy rule, so in-process callers are the way to it) with a request
// in flight: the request in flight is answered by the backend, a new request
// while paused is not, and after the resume the rule serves again. On round
// robin and on CHWBL; WRR_HASH refuses the pause (TestLbReplaceHashedPoolLive).
func TestLbReplacePauseInFlightLive(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	slow := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.Header.Get("X-Hold") != "" {
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"served":"slow"}`)
	})}
	go slow.Serve(l)
	t.Cleanup(func() { slow.Close() })
	host, p, _ := net.SplitHostPort(l.Addr().String())
	var pn int
	fmt.Sscanf(p, "%d", &pn)
	eps := []cmn.LbEndPointArg{{EpIP: host, EpPort: uint16(pn), Weight: 1}}

	for i, sel := range []cmn.EpSelect{cmn.LbSelRr, cmn.LbSelCHWBL} {
		port := uint16(28650 + i)
		name := fmt.Sprintf("sel %d", sel)
		if _, err := replLiveAdd(replLiveServ(port, sel, "", true), eps); err != nil {
			t.Fatalf("%s: create: %v", name, err)
		}
		t.Cleanup(func() { eppTestDeleteRule(replLiveServ(port, sel, "", true)) })
		replLiveExpect(t, name+", created", port, "")

		// a request held at the backend
		held := make(chan [2]interface{}, 1)
		go func() {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(eppTestVIP, fmt.Sprint(port)), 2*time.Second)
			if err != nil {
				held <- [2]interface{}{0, err}
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(20 * time.Second))
			body := `{"model":"m","prompt":"p"}`
			fmt.Fprintf(conn, "POST /v1/completions HTTP/1.1\r\nHost: %s:%d\r\nX-Hold: 1\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				eppTestVIP, port, len(body), body)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				held <- [2]interface{}{0, err}
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			held <- [2]interface{}{resp.StatusCode, resp.Header.Get("X-Loxilb-Refusal-Stage")}
		}()
		time.Sleep(500 * time.Millisecond)

		if _, err := replLiveAdd(replLiveServ(port, sel, "", false), eps); err != nil {
			t.Errorf("%s: pause: %v", name, err)
		}
		if got := replLiveRead(t, port); got.AdminStateUp == nil || *got.AdminStateUp {
			t.Errorf("%s: GET after the pause: admin_state_up %v, want false", name, got.AdminStateUp)
		}
		var code int
		var stage string
		for j := 0; j < 20; j++ {
			code, stage, err = replLiveReq(port)
			if err != nil || code != 200 || stage != "" {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err == nil && code == 200 && stage == "" {
			t.Errorf("%s: paused: a new request was answered by the backend", name)
		}
		close(release)
		select {
		case r := <-held:
			if r[0] != 200 || r[1] != "" {
				t.Errorf("%s: the request in flight at the pause ended %v %v, want 200 from the backend", name, r[0], r[1])
			}
		case <-time.After(15 * time.Second):
			t.Errorf("%s: the request in flight at the pause did not end", name)
		}
		release = make(chan struct{})

		if _, err := replLiveAdd(replLiveServ(port, sel, "", true), eps); err != nil {
			t.Errorf("%s: resume: %v", name, err)
		}
		replLiveExpect(t, name+", resumed", port, "")
	}
}

func TestLbReplaceHashedPoolLive(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	_, ep, _ := eppTestBackendSeen(t, "replace-class")
	eps := []cmn.LbEndPointArg{ep}

	for i, sel := range []cmn.EpSelect{cmn.LbSelCHWBL, cmn.LbSelWRRHash} {
		port := uint16(28640 + i)
		name := fmt.Sprintf("sel %d", sel)
		if _, err := replLiveAdd(replLiveServ(port, sel, "", true), eps); err != nil {
			t.Fatalf("%s: create: %v", name, err)
		}
		t.Cleanup(func() { eppTestDeleteRule(replLiveServ(port, sel, "", true)) })
		replLiveExpect(t, name+", created without a credential policy", port, "")

		// A re-create-class change the data plane takes: in force at once.
		if _, err := replLiveAdd(replLiveServ(port, sel, "required", true), eps); err != nil {
			t.Fatalf("%s: replace with api_key_auth required: %v", name, err)
		}
		if got := replLiveRead(t, port); got.ApiKeyAuth != "required" {
			t.Errorf("%s: GET after the replace: api_key_auth %q, want required", name, got.ApiKeyAuth)
		}
		replLiveExpect(t, name+", replaced with api_key_auth required", port, "auth")
	}

	// A re-create-class change the data plane refuses (WRR_HASH, the
	// credential check dropped and the rule paused in one replace): the
	// replace is refused, and the rule, GET and the installed pool are the
	// rule as it was - the credential check still in force.
	port := uint16(28641)
	_, err := replLiveAdd(replLiveServ(port, cmn.LbSelWRRHash, "disabled", false), eps)
	if err == nil {
		t.Errorf("WRR_HASH, api_key_auth disabled + paused: the replace was accepted, want refused (no endpoint can take a request)")
	}
	got := replLiveRead(t, port)
	if got.ApiKeyAuth != "required" || got.AdminStateUp == nil || !*got.AdminStateUp {
		t.Errorf("WRR_HASH, refused replace: GET api_key_auth %q admin_state_up %v; want the rule as it was (required, up)",
			got.ApiKeyAuth, got.AdminStateUp)
	}
	replLiveExpect(t, "WRR_HASH, after the refused replace", port, "auth")

	// A refresh-class change the data plane refuses (WRR_HASH paused, no
	// credential policy): the replace is refused, the pool stays and serves.
	port = 28642
	if _, err := replLiveAdd(replLiveServ(port, cmn.LbSelWRRHash, "", true), eps); err != nil {
		t.Fatalf("WRR_HASH :%d create: %v", port, err)
	}
	t.Cleanup(func() { eppTestDeleteRule(replLiveServ(port, cmn.LbSelWRRHash, "", true)) })
	replLiveExpect(t, "WRR_HASH, created", port, "")
	if _, err := replLiveAdd(replLiveServ(port, cmn.LbSelWRRHash, "", false), eps); err == nil {
		t.Errorf("WRR_HASH, paused: the replace was accepted, want refused (no endpoint can take a request)")
	}
	if got := replLiveRead(t, port); got.AdminStateUp == nil || !*got.AdminStateUp {
		t.Errorf("WRR_HASH, refused pause: GET admin_state_up %v, want up (the rule as it was)", got.AdminStateUp)
	}
	replLiveExpect(t, "WRR_HASH, after the refused pause", port, "")
}

// The endpoint-count reset of a hashed rule together with a re-create-class
// value: the declared authorization mode is the installed one. A request
// above MaxLBEndPoints is refused before any pool decision (the rule as it
// was is declared and installed); a request at MaxLBEndPoints that replaces
// the endpoint set and requires a key is installed with the key required.
func TestLbReplaceOverflowLive(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	_, ep, _ := eppTestBackendSeen(t, "overflow")
	port := uint16(28660)
	serv := replLiveServ(port, cmn.LbSelCHWBL, "", true)
	if _, err := replLiveAdd(serv, []cmn.LbEndPointArg{ep}); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { eppTestDeleteRule(serv) })
	replLiveExpect(t, "created", port, "")
	many := func(n int) []cmn.LbEndPointArg {
		eps := []cmn.LbEndPointArg{ep}
		for i := 0; len(eps) < n; i++ {
			eps = append(eps, cmn.LbEndPointArg{EpIP: "127.0.0.1", EpPort: uint16(10001 + i), Weight: 1})
		}
		return eps
	}
	if _, err := replLiveAdd(replLiveServ(port, cmn.LbSelCHWBL, "required", true), many(MaxLBEndPoints+1)); err == nil {
		t.Errorf("%d endpoints with api_key_auth required: accepted, want refused at the endpoint cap", MaxLBEndPoints+1)
	}
	if got := replLiveRead(t, port); got.ApiKeyAuth == "required" {
		t.Errorf("after the refused overflow: GET api_key_auth %q, want the rule as it was", got.ApiKeyAuth)
	}
	replLiveExpect(t, "after the refused overflow (declared and installed: no key required)", port, "")

	if _, err := replLiveAdd(replLiveServ(port, cmn.LbSelCHWBL, "required", true), many(MaxLBEndPoints)); err != nil {
		t.Fatalf("%d endpoints with api_key_auth required: %v", MaxLBEndPoints, err)
	}
	if got := replLiveRead(t, port); got.ApiKeyAuth != "required" {
		t.Errorf("after the %d-endpoint replace: GET api_key_auth %q, want required", MaxLBEndPoints, got.ApiKeyAuth)
	}
	replLiveExpect(t, fmt.Sprintf("after the %d-endpoint replace with api_key_auth required", MaxLBEndPoints), port, "auth")
}
