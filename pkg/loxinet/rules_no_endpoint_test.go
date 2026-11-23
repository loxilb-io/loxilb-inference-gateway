/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// noEpServ - a host|path fullproxy rule on the loopback VIP.
func noEpServ(port uint16, path string) cmn.LbServiceArg {
	return cmn.LbServiceArg{
		ServIP: eppTestVIP, ServPort: port, Proto: "tcp", Mode: cmn.LBModeFullProxy, Sel: cmn.LbSelRr,
		HostUrl: "shop.example.com", PathPrefix: path, PathMatchMode: "prefix",
	}
}

func TestLbZeroEndpointsRefusal(t *testing.T) {
	ok := func(mod func(*cmn.LbServiceArg)) cmn.LbServiceArg {
		s := noEpServ(80, "/down")
		if mod != nil {
			mod(&s)
		}
		return s
	}
	may := map[string]cmn.LbServiceArg{
		"host and path":  ok(nil),
		"host alone":     ok(func(s *cmn.LbServiceArg) { s.PathPrefix = "" }),
		"path alone":     ok(func(s *cmn.LbServiceArg) { s.HostUrl = "" }),
		"weighted":       ok(func(s *cmn.LbServiceArg) { s.Sel = cmn.LbSelPrio }),
		"rr persist":     ok(func(s *cmn.LbServiceArg) { s.Sel = cmn.LbSelRrPersist }),
		"session header": ok(func(s *cmn.LbServiceArg) { s.SessionHeaderName = "X-Session" }),
		"https":          ok(func(s *cmn.LbServiceArg) { s.Security = 1 }),
	}
	for name, s := range may {
		if err := lbZeroEndpointsRefusal(&s); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	mayNot := map[string]cmn.LbServiceArg{
		"l4":            ok(func(s *cmn.LbServiceArg) { s.Mode = cmn.LBModeFullNAT }),
		"no host, path": ok(func(s *cmn.LbServiceArg) { s.HostUrl, s.PathPrefix = "", "" }),
		"udp":           ok(func(s *cmn.LbServiceArg) { s.Proto = "udp" }),
		"ipv6":          ok(func(s *cmn.LbServiceArg) { s.ServIP = "2001:db8::1" }),
		"model":         ok(func(s *cmn.LbServiceArg) { s.ModelName = "llama" }),
		"pd":            ok(func(s *cmn.LbServiceArg) { s.PDDisaggMode = true }),
		"kv exact":      ok(func(s *cmn.LbServiceArg) { s.KvExactMode = 3 }),
		"epp":           ok(func(s *cmn.LbServiceArg) { s.EppEndpoint = "10.0.0.9:9002" }),
		"mcp":           ok(func(s *cmn.LbServiceArg) { s.MCPProtocolVersion = "2025-06-18" }),
		"n2":            ok(func(s *cmn.LbServiceArg) { s.Sel = cmn.LbSelN2 }),
		"chwbl":         ok(func(s *cmn.LbServiceArg) { s.Sel = cmn.LbSelCHWBL }),
		"wrr hash":      ok(func(s *cmn.LbServiceArg) { s.Sel = cmn.LbSelWRRHash }),
	}
	for name, s := range mayNot {
		if err := lbZeroEndpointsRefusal(&s); err == nil {
			t.Errorf("%s: may have no endpoints", name)
		}
	}
}

func TestLbNoEndpointStatus(t *testing.T) {
	cases := []struct {
		in   int
		l4   bool
		want int
		err  bool
	}{
		{0, false, 503, false},
		{503, false, 503, false},
		{500, false, 500, false},
		{0, true, 503, false},
		{503, true, 503, false},
		{500, true, 0, true}, // never answered on a rule that may not be empty
		{404, false, 0, true},
		{502, false, 0, true},
	}
	for _, c := range cases {
		s := noEpServ(80, "/down")
		if c.l4 {
			s.Mode = cmn.LBModeFullNAT
		}
		s.NoEndpointStatus = c.in
		got, err := lbNoEndpointStatus(&s)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("status %d (l4 %v): got %d, %v; want %d, error %v", c.in, c.l4, got, err, c.want, c.err)
		}
	}
	if lbNoEndpointDpStatus(500) != 1 || lbNoEndpointDpStatus(503) != 0 || lbNoEndpointDpStatus(0) != 0 {
		t.Fatal("data-plane codes are SP_NO_EP_STATUS_503 (0) and SP_NO_EP_STATUS_500 (1)")
	}
}

func TestLbZeroEndpointEdge(t *testing.T) {
	one := []ruleLBEp{{xPort: 1}}
	two := []ruleLBEp{{xPort: 1}, {xPort: 2}}
	for _, c := range []struct {
		old, new []ruleLBEp
		want     bool
	}{
		{nil, one, true}, {one, nil, true}, {two, nil, true},
		{nil, nil, false}, {one, two, false}, {two, one, false},
	} {
		if got := lbZeroEndpointEdge(c.old, c.new); got != c.want {
			t.Errorf("%d -> %d endpoints: edge %v, want %v", len(c.old), len(c.new), got, c.want)
		}
	}
}

// A rule with no endpoints reaches the data plane with none and with its
// status, whatever its selector: the weighted one fills its slots from the
// endpoints, and with none it used to divide by zero.
func TestLB2DPNoEndpoints(t *testing.T) {
	saved := mh.dp
	queue := make(chan interface{}, 8)
	mh.dp = &DpH{ToDpCh: queue}
	t.Cleanup(func() { mh.dp = saved })
	for _, sel := range []cmn.EpSelect{cmn.LbSelRr, cmn.LbSelPrio} {
		r := fenceRule(t, "10.10.10.254", 8080, cmn.LBModeFullProxy)
		r.act.actType = RtActFullProxy
		r.zone = &Zone{}
		r.act.action.(*ruleLBActs).sel = sel
		r.noEndpointStatus = cmn.NoEndpointStatusInternal
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("sel %d: LB2DP with no endpoints panicked: %v\n%s", sel, p, debug.Stack())
				}
			}()
			if rc := r.LB2DP(DpCreate); rc != 0 {
				t.Fatalf("sel %d: LB2DP returned %d", sel, rc)
			}
		}()
		w, ok := (<-queue).(*LBDpWorkQ)
		if !ok {
			t.Fatalf("sel %d: no load-balancer work queued", sel)
		}
		if len(w.endPoints) != 0 || w.NoEndpointStatus != 1 {
			t.Fatalf("sel %d: %d endpoints, no-endpoint code %d; want none and 1 (500)",
				sel, len(w.endPoints), w.NoEndpointStatus)
		}
	}
}

// An empty endpoint list on a rule that may not have none is refused as it
// always was, with the reason, and before any rule state is touched.
func TestAddLbRuleZeroEndpointsRefused(t *testing.T) {
	R := &RuleH{}
	for name, mod := range map[string]func(*cmn.LbServiceArg){
		"l4":       func(s *cmn.LbServiceArg) { s.Mode = cmn.LBModeFullNAT; s.HostUrl, s.PathPrefix = "", "" },
		"no route": func(s *cmn.LbServiceArg) { s.HostUrl, s.PathPrefix = "", "" },
		"chwbl":    func(s *cmn.LbServiceArg) { s.Sel = cmn.LbSelCHWBL },
	} {
		s := noEpServ(28499, "/down")
		mod(&s)
		code, err := R.AddLbRule(s, nil, nil, nil, nil)
		if code != RuleEpCountErr || err == nil || !strings.HasPrefix(err.Error(), "endpoints-range error") {
			t.Errorf("%s: got %d, %v; want RuleEpCountErr, endpoints-range error", name, code, err)
		}
	}
	s := noEpServ(28499, "/down")
	s.Mode, s.HostUrl, s.PathPrefix = cmn.LBModeFullNAT, "", ""
	s.NoEndpointStatus = 500
	_, err := R.AddLbRule(s, nil, nil, nil, []cmn.LbEndPointArg{{EpIP: "127.0.0.1", EpPort: 1, Weight: 1}})
	var ruleArg *cmn.RuleArgumentError
	if err == nil || !errors.As(err, &ruleArg) {
		t.Fatalf("500 on an L4 rule: got %v, want a RuleArgumentError (HTTP 400)", err)
	}
}

// noEpRequest sends one GET for path through the VIP with the rule's host.
func noEpRequest(port uint16, path string) (int, string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(eppTestVIP, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: shop.example.com\r\nConnection: close\r\n\r\n", path)
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

func noEpExpect(t *testing.T, port uint16, path string, wantCode int, want string) {
	t.Helper()
	code, body, err := noEpRequest(port, path)
	if err != nil || code != wantCode || !strings.Contains(body, want) {
		t.Fatalf("GET %s on :%d: code=%d body=%q err=%v; want %d with %s", path, port, code, body, err, wantCode, want)
	}
}

func noEpRuleRead(t *testing.T, serv cmn.LbServiceArg) cmn.LbRuleMod {
	t.Helper()
	mh.mtx.Lock()
	rules, err := mh.zr.Rules.GetLBRule()
	mh.mtx.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Serv.ServPort == serv.ServPort && r.Serv.HostUrl == serv.HostUrl && r.Serv.PathPrefix == serv.PathPrefix {
			return r
		}
	}
	t.Fatalf("rule :%d %s%s not read back", serv.ServPort, serv.HostUrl, serv.PathPrefix)
	return cmn.LbRuleMod{}
}

// TestNoEndpointRuleAnswers: a host|path rule with no endpoints answers the
// requests it takes and hands none to the shorter prefix beside it, through
// emptying and refilling, on a listener of its own, and by the status it
// asks for (the kube-loxilb HTTPRoute direct-route conditions).
func TestNoEndpointRuleAnswers(t *testing.T) {
	if mh.zr == nil || mh.dpEbpf == nil {
		t.Skip("loxinet harness not initialized (run the whole package as root)")
	}
	_, root, _ := eppTestBackendSeen(t, "web-b")
	_, down, _ := eppTestBackendSeen(t, "web-down")

	// Beside a "/" rule with an endpoint.
	rootServ := noEpServ(28400, "/")
	downServ := noEpServ(28400, "/down")
	if _, err := eppTestAddRule(rootServ, []cmn.LbEndPointArg{root}); err != nil {
		t.Fatalf("add /: %v", err)
	}
	t.Cleanup(func() { eppTestDeleteRule(rootServ) })
	if _, err := eppTestAddRule(downServ, nil); err != nil {
		t.Fatalf("add /down with no endpoints: %v", err)
	}
	t.Cleanup(func() { eppTestDeleteRule(downServ) })
	noEpExpect(t, 28400, "/down", 503, `"error":"no_healthy_backend"`)
	noEpExpect(t, 28400, "/down/x", 503, `"detail":"the rule has no endpoints"`)
	noEpExpect(t, 28400, "/", 200, `"served":"web-b"`)
	if got := noEpRuleRead(t, downServ); len(got.Eps) != 0 || got.Serv.NoEndpointStatus != 503 {
		t.Fatalf("read back: %d endpoints, no_endpoint_status %d; want none and 503", len(got.Eps), got.Serv.NoEndpointStatus)
	}
	if got := noEpRuleRead(t, rootServ); got.Serv.NoEndpointStatus != 503 {
		t.Fatalf("the / rule reads back no_endpoint_status %d, want 503", got.Serv.NoEndpointStatus)
	}

	// Refilled and emptied again, with requests running all along: none of
	// them reaches the "/" rule's backend.
	var stop atomic.Bool
	var wrong, seen atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_, body, err := noEpRequest(28400, "/down")
			if err == nil {
				seen.Add(1)
				if strings.Contains(body, `"served":"web-b"`) {
					wrong.Add(1)
				}
			}
		}
	}()
	for i := 0; i < 10; i++ {
		if _, err := eppTestAddRule(downServ, []cmn.LbEndPointArg{down}); err != nil {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("refill /down (%d): %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
		if _, err := eppTestAddRule(downServ, nil); err != nil {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("empty /down (%d): %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	if wrong.Load() != 0 || seen.Load() == 0 {
		t.Fatalf("%d of %d /down requests reached the / rule's backend while /down was emptied and refilled",
			wrong.Load(), seen.Load())
	}
	if _, err := eppTestAddRule(downServ, []cmn.LbEndPointArg{down}); err != nil {
		t.Fatalf("refill /down: %v", err)
	}
	noEpExpect(t, 28400, "/down", 200, `"served":"web-down"`)
	if _, err := eppTestAddRule(downServ, nil); err != nil {
		t.Fatalf("empty /down: %v", err)
	}
	noEpExpect(t, 28400, "/down", 503, `"error":"no_healthy_backend"`)

	// A rule with no endpoints alone on its address still gets a listener.
	alone := noEpServ(28402, "/down")
	if _, err := eppTestAddRule(alone, nil); err != nil {
		t.Fatalf("add a lone rule with no endpoints: %v", err)
	}
	t.Cleanup(func() { eppTestDeleteRule(alone) })
	noEpExpect(t, 28402, "/down", 503, `"error":"no_healthy_backend"`)

	// The status is the rule's own: 500 and 503 side by side, and a change
	// of it alone applies.
	a, b := noEpServ(28404, "/a"), noEpServ(28404, "/b")
	a.NoEndpointStatus = 500
	if _, err := eppTestAddRule(a, nil); err != nil {
		t.Fatalf("add /a (500): %v", err)
	}
	t.Cleanup(func() { eppTestDeleteRule(a) })
	if _, err := eppTestAddRule(b, nil); err != nil {
		t.Fatalf("add /b: %v", err)
	}
	t.Cleanup(func() { eppTestDeleteRule(b) })
	noEpExpect(t, 28404, "/a", 500, `"error":"no_backend"`)
	noEpExpect(t, 28404, "/b", 503, `"error":"no_healthy_backend"`)
	if got := noEpRuleRead(t, a); got.Serv.NoEndpointStatus != 500 {
		t.Fatalf("/a reads back no_endpoint_status %d, want 500", got.Serv.NoEndpointStatus)
	}
	b.NoEndpointStatus = 500
	if _, err := eppTestAddRule(b, nil); err != nil {
		t.Fatalf("/b to 500: %v", err)
	}
	noEpExpect(t, 28404, "/b", 500, `"error":"no_backend"`)

	// An L4 rule keeps refusing an empty list.
	l4 := cmn.LbServiceArg{ServIP: eppTestVIP, ServPort: 28406, Proto: "tcp", Mode: cmn.LBModeFullNAT, Sel: cmn.LbSelRr}
	if code, err := eppTestAddRule(l4, nil); code != RuleEpCountErr || err == nil {
		t.Fatalf("an L4 rule with no endpoints: got %d, %v; want endpoints-range error", code, err)
	}
}
