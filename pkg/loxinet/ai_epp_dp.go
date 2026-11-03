/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

// The Go half of the Endpoint Picker (EPP) boundary.
//
// The data plane hands a buffered request over (llb_epp_submit, on a worker
// thread, returns at once with a stream id) and parks the client. A
// goroutine runs the ext_proc exchange through pkg/epp and hands the
// decision back from its own thread (proxy_epp_complete), which the C side
// copies into its side table before waking the fd's owner worker. The
// stream stays open until the data plane reports the response phase
// (llb_epp_resp_event: headers, end of stream, or abort), exactly once per
// stream id.
//
// Rules are resolved by their number (dp_proxy_tacts.ca.cidx, the pool's
// epp_svc_id): the rule layer registers each EPP rule's address, failure
// mode, deadline and TLS choice here when it stores the rule.

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sockproxy_epp.h"
*/
import "C"

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	tk "github.com/loxilb-io/loxilib"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/epp"
)

// eppMaxInflight bounds the requests waiting on EPPs at once; a submit
// past it is refused (sid 0) and the rule's failure mode applies.
var eppMaxInflight int64 = 65536 // var so a test can force the "already waiting" refusal

var (
	eppClient   = epp.NewClient()
	eppRulesMu  sync.RWMutex
	eppRules    = make(map[uint32]epp.RuleCfg) // rule number -> EPP config
	eppNextSid  atomic.Uint64
	eppFlights  sync.Map // sid (uint64) -> *eppFlight
	eppInflight atomic.Int64
)

func init() {
	prom.SetEppStateProvider(func() (int, int) { return EppInflight(), EppPendingDecisions() })
}

// eppFlight is one request between its submit and its last response event.
type eppFlight struct {
	sid    uint64
	fd     int
	gen    uint64
	ns     unsafe.Pointer
	ctx    context.Context    // bounds the request phase; cancelled by end()
	cancel context.CancelFunc // so an abort while the EPP is still deciding ends the stream now
	mu     sync.Mutex
	stream *epp.Stream // nil until the decision is OK; nil again once ended
	ended  bool
	// resp carries the response-phase events in the order the data plane
	// reported them to the one goroutine that sends them (respLoop):
	// headers before end of stream, never blocking the worker thread.
	resp chan eppRespEvent
}

type eppRespEvent struct {
	kind   int
	status int
	hdrs   []epp.Header
	served string
}

// eppRespQueue bounds the response events waiting per flight; a request
// reports at most headers and an end, so a full queue is a bug, not load.
const eppRespQueue = 4

// eppRuleRegister records (or clears) the EPP configuration of a rule by
// its number. Called by the rule layer whenever a rule is stored.
func eppRuleRegister(ruleNum uint64, serv *cmn.LbServiceArg) {
	eppRulesMu.Lock()
	defer eppRulesMu.Unlock()
	if serv == nil || serv.EppEndpoint == "" {
		delete(eppRules, uint32(ruleNum))
		return
	}
	eppRules[uint32(ruleNum)] = epp.RuleCfg{
		Endpoint:    serv.EppEndpoint,
		FailureMode: serv.EppFailureMode,
		TimeoutMs:   serv.EppTimeoutMs,
		Plaintext:   serv.EppPlaintext,
	}
}

func eppRuleUnregister(ruleNum uint64) {
	eppRulesMu.Lock()
	delete(eppRules, uint32(ruleNum))
	eppRulesMu.Unlock()
}

// eppHealthReport is the read-only EPP view a rule GET carries: connection
// state, when it changed (RFC3339) and the last request-phase error. The
// connection is opened on first ask, so a rule that never sent a request
// still learns whether its EPP is reachable.
func eppHealthReport(r *ruleEnt) (state, since, lastErr string) {
	cfg, ok := eppRuleLookup(uint32(r.ruleNum))
	if !ok {
		cfg = epp.RuleCfg{Endpoint: r.eppEndpoint, FailureMode: r.eppFailureMode, TimeoutMs: r.eppTimeoutMs, Plaintext: r.eppPlaintext}
	}
	h := eppClient.Health(cfg)
	if !h.Since.IsZero() {
		since = h.Since.UTC().Format(time.RFC3339)
	}
	return h.State, since, h.LastError
}

func eppRuleLookup(svcID uint32) (epp.RuleCfg, bool) {
	eppRulesMu.RLock()
	cfg, ok := eppRules[svcID]
	eppRulesMu.RUnlock()
	return cfg, ok
}

// EppInflight reports the requests currently between submit and their last
// response event (diagnostic).
func EppInflight() int { return int(eppInflight.Load()) }

// EppPendingDecisions reports the decisions the C side table still holds
// (diagnostic).
func EppPendingDecisions() int { return int(C.epp_pending_count()) }

//export llb_epp_submit
func llb_epp_submit(svcID C.uint32_t, ns unsafe.Pointer, fd C.int, gen C.uint64_t,
	reqHdrs *C.char, reqHdrsLen C.int, body *C.char, bodyLen C.int,
	subset *C.char, subsetLen C.int) C.uint64_t {
	defer cgoRecover("llb_epp_submit")

	cfg, ok := eppRuleLookup(uint32(svcID))
	if !ok {
		tk.LogIt(tk.LogDebug, "[EPP] submit fd=%d: rule %d has no EPP configuration\n", int(fd), uint32(svcID))
		return 0
	}
	if eppInflight.Load() >= eppMaxInflight {
		tk.LogIt(tk.LogWarning, "[EPP] submit fd=%d: %d requests already waiting on EPPs; refused\n", int(fd), eppMaxInflight)
		return 0
	}
	head := C.GoBytes(unsafe.Pointer(reqHdrs), reqHdrsLen)
	req, err := epp.ParseHTTP1Request(head, "http")
	if err != nil {
		tk.LogIt(tk.LogWarning, "[EPP] submit fd=%d: %v\n", int(fd), err)
		return 0
	}
	if bodyLen > 0 {
		req.Body = C.GoBytes(unsafe.Pointer(body), bodyLen)
	}
	if subsetLen > 0 {
		for _, s := range strings.Split(C.GoStringN(subset, subsetLen), ",") {
			if s = strings.TrimSpace(s); s != "" {
				req.Subset = append(req.Subset, s)
			}
		}
	}
	sid := eppNextSid.Add(1)
	fl := &eppFlight{sid: sid, fd: int(fd), gen: uint64(gen), ns: ns, resp: make(chan eppRespEvent, eppRespQueue)}
	fl.ctx, fl.cancel = context.WithCancel(context.Background())
	eppFlights.Store(sid, fl)
	eppInflight.Add(1)
	go fl.run(cfg, req)
	return C.uint64_t(sid)
}

// run is the request phase on its own goroutine: the ext_proc exchange,
// then the decision handed to C from this thread.
func (fl *eppFlight) run(cfg epp.RuleCfg, req *epp.Request) {
	defer cgoRecover("eppFlight.run")
	start := time.Now()
	dec, stream := eppClient.Submit(fl.ctx, cfg, req)
	took := time.Since(start).Seconds()
	switch dec.Status {
	case epp.StatusImmediate:
		prom.RecordEppOutcome("immediate", took)
	case epp.StatusError:
		if fl.ctx.Err() == nil {
			tk.LogIt(tk.LogInfo, "[EPP] sid=%d fd=%d: %v\n", fl.sid, fl.fd, dec.Err)
			prom.RecordEppOutcome("error", took)
		}
	default:
		// The final outcome of an OK decision (ok / no_endpoint /
		// body_too_large) is decided and counted in the data plane; only
		// the duration is observed here.
		prom.RecordEppOutcome("", took)
	}
	fl.mu.Lock()
	fl.stream = stream
	fl.mu.Unlock()
	if stream != nil {
		stream.OnEvict(func(code int) {
			defer cgoRecover("eppFlight.evict")
			prom.RecordEppOutcome("evicted", 0)
			rc := int(C.proxy_epp_evict(fl.ns, C.int(fl.fd), C.uint64_t(fl.gen), C.uint64_t(fl.sid), C.int(code)))
			if rc != 0 {
				tk.LogIt(tk.LogDebug, "[EPP] sid=%d fd=%d: eviction not delivered (%d)\n", fl.sid, fl.fd, rc)
			}
			fl.end()
		})
	}

	rc := eppComplete(fl, dec)
	if rc != 0 || stream == nil {
		// Nobody will route on this decision (slot gone) or nothing stays
		// open for a response phase: the flight is over now.
		if rc != 0 && stream != nil {
			stream.Abort()
		}
		fl.end()
		return
	}
	go fl.respLoop(stream)
}

// respLoop sends the response-phase events of one flight in order on the
// stream the request keeps open, and ends the flight after the end of
// stream. It exits when end() closes the queue.
func (fl *eppFlight) respLoop(s *epp.Stream) {
	defer cgoRecover("eppFlight.respLoop")
	for ev := range fl.resp {
		switch ev.kind {
		case C.EPP_EV_RESP_HEADERS:
			if err := s.ReportResponseHeaders(ev.status, ev.hdrs, ev.served); err != nil {
				tk.LogIt(tk.LogDebug, "[EPP] sid=%d: response headers report: %v\n", fl.sid, err)
			}
		case C.EPP_EV_RESP_EOS:
			if err := s.ReportResponseEnd(); err != nil {
				tk.LogIt(tk.LogDebug, "[EPP] sid=%d: end-of-stream report: %v\n", fl.sid, err)
			}
			fl.end()
			return
		}
	}
}

// eppComplete marshals the decision into struct epp_result and hands it to
// C, which copies what it keeps before returning.
func eppComplete(fl *eppFlight, dec *epp.Decision) int {
	var r C.struct_epp_result
	C.memset(unsafe.Pointer(&r), 0, C.sizeof_struct_epp_result)
	var keep []unsafe.Pointer
	cbuf := func(b []byte) (*C.char, C.int) {
		if len(b) == 0 {
			return nil, 0
		}
		p := C.CBytes(b)
		keep = append(keep, p)
		return (*C.char)(p), C.int(len(b))
	}
	defer func() {
		for _, p := range keep {
			C.free(p)
		}
	}()

	switch dec.Status {
	case epp.StatusOK:
		r.status = C.EPP_RES_OK
		n := 0
		for _, c := range dec.Candidates {
			if n == C.EPP_MAX_CANDS || len(c) >= C.EPP_CAND_LEN {
				break
			}
			cs := C.CString(c)
			C.strncpy(&r.cands[n][0], cs, C.EPP_CAND_LEN-1)
			C.free(unsafe.Pointer(cs))
			n++
		}
		r.ncands = C.int(n)
		r.hdr_set, r.hdr_set_len = cbuf([]byte(eppHeaderLines(dec.HdrSet)))
		var del strings.Builder
		for _, k := range dec.HdrDel {
			del.WriteString(k)
			del.WriteString("\r\n")
		}
		r.hdr_del, r.hdr_del_len = cbuf([]byte(del.String()))
		if dec.BodyChanged {
			r.new_body, r.new_body_len = cbuf(dec.NewBody)
		}
	case epp.StatusImmediate:
		r.status = C.EPP_RES_IMMEDIATE
		r.imm_code = C.int(dec.ImmCode)
		r.imm_body, r.imm_body_len = cbuf(dec.ImmBody)
		r.hdr_set, r.hdr_set_len = cbuf([]byte(eppHeaderLines(dec.ImmHeaders)))
	default:
		r.status = C.EPP_RES_ERROR
	}
	rc := int(C.proxy_epp_complete(fl.ns, C.int(fl.fd), C.uint64_t(fl.gen), C.uint64_t(fl.sid), &r))
	if rc != 0 {
		tk.LogIt(tk.LogDebug, "[EPP] sid=%d fd=%d: decision not delivered (%d)\n", fl.sid, fl.fd, rc)
	}
	return rc
}

// eppHeaderLines renders headers as the "k: v\r\n" lines the C ABI takes.
func eppHeaderLines(hdrs []epp.Header) string {
	var b strings.Builder
	for _, h := range hdrs {
		b.WriteString(h.Key)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteString("\r\n")
	}
	return b.String()
}

// end closes the flight once: the stream is aborted if still open.
func (fl *eppFlight) end() {
	fl.mu.Lock()
	if fl.ended {
		fl.mu.Unlock()
		return
	}
	fl.ended = true
	s := fl.stream
	fl.stream = nil
	close(fl.resp) // every enqueue checks ended under fl.mu first
	fl.mu.Unlock()
	fl.cancel() // a Submit still waiting returns now and aborts its stream
	if s != nil {
		s.Abort()
	}
	eppFlights.Delete(fl.sid)
	eppInflight.Add(-1)
}

//export llb_epp_resp_event
func llb_epp_resp_event(sid C.uint64_t, kind C.int, httpStatus C.int,
	respHdrs *C.char, respHdrsLen C.int, served *C.char, servedLen C.int) {
	defer cgoRecover("llb_epp_resp_event")
	v, ok := eppFlights.Load(uint64(sid))
	if !ok {
		return
	}
	fl := v.(*eppFlight)
	if int(kind) == C.EPP_EV_ABORT {
		fl.end()
		return
	}
	ev := eppRespEvent{kind: int(kind), status: int(httpStatus)}
	if respHdrsLen > 0 {
		ev.hdrs = eppParseHeaderLines(C.GoStringN(respHdrs, respHdrsLen))
	}
	if servedLen > 0 {
		ev.served = C.GoStringN(served, servedLen)
	}
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if fl.ended {
		return
	}
	select {
	case fl.resp <- ev:
	default:
		tk.LogIt(tk.LogWarning, "[EPP] sid=%d: response event %d dropped (queue full)\n", fl.sid, int(kind))
	}
}

// eppParseHeaderLines reads "k: v\r\n" lines back into headers.
func eppParseHeaderLines(raw string) []epp.Header {
	var out []epp.Header
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out = append(out, epp.Header{Key: strings.ToLower(strings.TrimSpace(k)), Value: strings.TrimSpace(v)})
	}
	return out
}

//export llb_epp_metric_outcome
func llb_epp_metric_outcome(outcome *C.char) {
	defer cgoRecover("llb_epp_metric_outcome")
	prom.RecordEppOutcome(C.GoString(outcome), 0)
}

//export llb_epp_metric_rejected
func llb_epp_metric_rejected(reason *C.char) {
	defer cgoRecover("llb_epp_metric_rejected")
	prom.RecordEppCandidateRejected(C.GoString(reason))
}
