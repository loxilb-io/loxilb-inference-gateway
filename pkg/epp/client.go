/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package epp

// Package epp is the Endpoint Picker (EPP) client. Pure Go, no
// cgo: the data plane (pkg/loxinet) and the cmd/epp-probe diagnostic share it.
//
// An EPP is a Gateway API Inference Extension endpoint picker (llm-d-router,
// GIE). It speaks Envoy's ext_proc protocol: for every HTTP request the
// proxy opens one ExternalProcessor.Process stream, sends the request
// headers and body, and receives the destination (a comma-separated list
// of ip:port in the x-gateway-destination-endpoint header), header
// mutations (for example x-prefiller-host-port) and, when the EPP rewrites
// the model, the new body. The stream stays open until the proxy has
// reported the response headers and the end of the response, which is how
// the EPP keeps its in-flight accounting and runs its response plugins.
//
// Nothing here knows C or rules. The request comes in already
// parsed (Request), the decision goes out as an Decision that mirrors
// struct epp_result of the C ABI (interface spec 4.3), and the open stream
// is handed back for the response phase. The EPP address, failure mode,
// deadline and TLS choice arrive as RuleCfg, resolved by the rule layer.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	tk "github.com/loxilb-io/loxilib"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	cmn "github.com/loxilb-io/loxilb/common"
)

const (
	// MaxCandidates is the most destinations taken from the EPP's list,
	// in its order (decision D6).
	MaxCandidates = 4
	// The GIE Endpoint Picker Protocol names (llm-d-router
	// pkg/epp/metadata/consts.go).
	HeaderDestination       = "x-gateway-destination-endpoint"
	HeaderServed            = "x-gateway-destination-endpoint-served"
	HeaderSubset            = "x-gateway-destination-endpoint-subset"
	MetadataNamespace       = "envoy.lb"
	MetadataSubsetNamespace = "envoy.lb.subset_hint"
	// BodyChunk bounds one RequestBody message; the EPP reassembles.
	BodyChunk = 64 * 1024
	// responseDrain bounds how long the end-of-stream report waits for
	// the EPP to close its side before the stream is torn down anyway.
	responseDrain = 2 * time.Second
)

// Status is the outcome of the request phase, numbered as
// epp_result.status in the C ABI.
type Status int

const (
	// StatusOK — the EPP answered; Candidates (possibly empty) and the
	// mutations apply.
	StatusOK Status = 0
	// StatusImmediate — the EPP answered the client itself (429/503
	// shedding, validation): ImmCode / ImmBody / ImmHeaders go back as is.
	StatusImmediate Status = 1
	// StatusError — no usable answer (submission refused, deadline,
	// gRPC error, NOT_SERVING): the rule's eppFailureMode decides.
	StatusError Status = 2
)

// Header is one header line, key already lower-cased.
type Header struct {
	Key   string
	Value string
}

// Request is one HTTP/1.1 request as the EPP wants to see it: the
// request line split into the ext_proc pseudo headers, the headers (host
// removed — it travels as :authority), the whole body, and the local
// subset hint (ip:port the proxy would accept) when the rule has one.
type Request struct {
	Method    string
	Path      string
	Authority string
	Scheme    string
	Headers   []Header
	Body      []byte
	Subset    []string
}

// Decision mirrors struct epp_result (interface spec 4.3).
type Decision struct {
	Status Status
	// Candidates are "ip:port" in the EPP's order, at most MaxCandidates.
	Candidates []string
	// ImmediateResponse: status code, body and headers to return.
	ImmCode    int
	ImmBody    []byte
	ImmHeaders []Header
	// Request header mutations to apply before forwarding. content-length
	// is never included: the data plane recomputes it from the body.
	HdrSet []Header
	HdrDel []string
	// NewBody replaces the request body when BodyChanged (model rewrite).
	NewBody     []byte
	BodyChanged bool
	// Err explains StatusError.
	Err error
}

// RuleCfg is what the rule layer resolved for the rule's EPP.
type RuleCfg struct {
	Endpoint    string // host:port
	FailureMode string // cmn.EppFailureModeFailOpen | FailClose
	TimeoutMs   uint32 // request-phase deadline, dial included (0 ⇒ cmn.EppDefaultTimeoutMs)
	Plaintext   bool   // true: no TLS; false: TLS without verification (D3)
}

func (c RuleCfg) timeout() time.Duration {
	if c.TimeoutMs == 0 {
		return time.Duration(cmn.EppDefaultTimeoutMs) * time.Millisecond
	}
	return time.Duration(c.TimeoutMs) * time.Millisecond
}

// Dead-peer detection. An EPP pod that is killed outright (OOM, node
// loss, a forced delete) sends no FIN or RST: the TCP connection stays
// half-open, gRPC keeps the channel READY, every new stream's frames go
// out unacknowledged and the decision deadline is the only thing that
// fails. Two things end that:
//
//   - DeadPeerTimeout is set as TCP_USER_TIMEOUT on the dial socket, so
//     the kernel errors the connection once sent data has gone that long
//     without an ACK; gRPC then reconnects with the backoff below.
//   - SilentTimeoutsBeforeReset consecutive request phases that hit the
//     deadline without a single frame from the EPP make the client drop the
//     cached connection and dial afresh on the next request, which covers
//     a transport the kernel still considers fine (nothing in flight, or a
//     middlebox that ACKs for a dead peer).
//
// Neither relies on gRPC keepalive pings, whose cadence the EPP server's
// enforcement policy (default: one per 5 min) would have to permit.
const (
	DeadPeerTimeout           = 10 * time.Second
	SilentTimeoutsBeforeReset = 2
)

// Client keeps one gRPC connection per EPP address and opens one
// ext_proc stream per request on it.
type Client struct {
	mu    sync.Mutex
	conns map[string]*connEntry
	// Resets counts the cached connections dropped by dead-peer detection.
	Resets atomic.Int64
	done   chan struct{} // closed by Close; stops the health probe loop
}

type connEntry struct {
	cc *grpc.ClientConn
	// silent counts consecutive request phases on this connection that
	// timed out without any frame from the EPP; any received frame zeroes it.
	silent atomic.Int32
	// health, sampled by the probe loop and by Health() (see health.go).
	hmu       sync.Mutex
	state     string
	since     time.Time
	lastErr   string
	lastErrAt time.Time
	lastOKAt  time.Time
}

// NewClient makes an empty connection pool and starts its health probe.
func NewClient() *Client {
	c := &Client{conns: make(map[string]*connEntry), done: make(chan struct{})}
	go c.probeLoop()
	return c
}

// Close drops every connection and stops the health probe.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	for k, e := range c.conns {
		e.cc.Close()
		delete(c.conns, k)
	}
}

func connKey(cfg RuleCfg) string {
	if cfg.Plaintext {
		return cfg.Endpoint + "|plaintext"
	}
	return cfg.Endpoint
}

// silentTimeout records a request phase that saw nothing from the EPP on
// e; after SilentTimeoutsBeforeReset in a row the connection is dropped.
func (c *Client) silentTimeout(key string, e *connEntry) {
	if e.silent.Add(1) < SilentTimeoutsBeforeReset {
		return
	}
	c.mu.Lock()
	cur, ok := c.conns[key]
	if ok && cur == e {
		delete(c.conns, key)
	}
	c.mu.Unlock()
	if ok && cur == e {
		c.Resets.Add(1)
		tk.LogIt(tk.LogWarning, "[EPP] %s: no frame from the EPP in %d consecutive request phases, dropping the connection\n", key, SilentTimeoutsBeforeReset)
		e.cc.Close()
	}
}

// dialTCP connects with TCP_USER_TIMEOUT so a half-open connection errors
// out instead of retransmitting for minutes (see DeadPeerTimeout).
func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Control: func(network, address string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(DeadPeerTimeout/time.Millisecond))
		}); err != nil {
			return err
		}
		return serr
	}}
	return d.DialContext(ctx, "tcp", addr)
}

func (c *Client) conn(cfg RuleCfg) (*connEntry, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("epp: rule has no eppEndpoint")
	}
	key := connKey(cfg)
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.conns[key]; ok {
		return e, nil
	}
	var creds credentials.TransportCredentials
	if cfg.Plaintext {
		creds = insecure.NewCredentials()
	} else {
		// The llm-d EPP serves a self-signed certificate; the charts'
		// DestinationRule skips verification the same way (decision D3).
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}) // #nosec G402
	}
	// Reconnect quickly after the EPP goes away and comes back (a restart
	// gap): gRPC's default backoff climbs to 120 s, during which every
	// stream fails fast and the rule stays on its failure mode.
	conn, err := grpc.NewClient(cfg.Endpoint, grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(dialTCP),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: 100 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: 2 * time.Second},
			MinConnectTimeout: 2 * time.Second,
		}))
	if err != nil {
		return nil, fmt.Errorf("epp: dial %s: %w", cfg.Endpoint, err)
	}
	e := &connEntry{cc: conn}
	c.conns[key] = e
	return e, nil
}

// Stream is the ext_proc stream of one request, open from the request
// decision until the response phase ends (ReportResponseEnd) or the
// request is abandoned (Abort). Exactly one of those must be called for
// every stream Submit hands back, or the EPP's in-flight count never
// drops.
type Stream struct {
	stream extprocv3.ExternalProcessor_ProcessClient
	cancel context.CancelFunc
	recv   chan recvMsg
	mu     sync.Mutex
	done   bool
	// decided is set once the request phase is over; from then on an
	// ImmediateResponse from the EPP is an eviction (the EPP sheds a request
	// it already admitted, llm-d-router flow control) and goes to onEvict.
	decided atomic.Bool
	evicted atomic.Bool
	onEvict atomic.Pointer[func(code int)]
	// received is set by the first frame the EPP sends on this stream.
	received atomic.Bool
}

// OnEvict installs the handler called, once, from the stream's receiver
// when the EPP answers the response phase with an ImmediateResponse: the
// request must be cut (the backend leg ended) with that status.
func (s *Stream) OnEvict(fn func(code int)) {
	s.onEvict.Store(&fn)
}

// Evicted reports whether the EPP evicted the request during its response.
func (s *Stream) Evicted() bool { return s.evicted.Load() }

type recvMsg struct {
	msg *extprocv3.ProcessingResponse
	err error
}

// openedStream is the result of opening the ext_proc stream, delivered to
// Submit so the open can be abandoned at the deadline.
type openedStream struct {
	stream extprocv3.ExternalProcessor_ProcessClient
	err    error
}

// Submit runs the request phase: it opens the stream, sends the headers
// and body, and waits at most the rule's deadline for the EPP's decision.
// The caller's ctx bounds the whole call as well. With StatusOK the
// returned stream is open for the response phase; otherwise it is already
// closed and nil.
func (c *Client) Submit(ctx context.Context, cfg RuleCfg, req *Request) (*Decision, *Stream) {
	e, err := c.conn(cfg)
	if err != nil {
		return &Decision{Status: StatusError, Err: err}, nil
	}
	// One deadline covers opening the stream, sending and the wait for the
	// decision. Opening includes the dial when the connection is down:
	// gRPC blocks a new stream while the channel is CONNECTING (up to
	// MinConnectTimeout, a dial a packet filter blackholes takes all of it),
	// so the open runs apart from this goroutine and the timer decides.
	// On a dead or wedged connection Send itself can block too (HTTP/2
	// flow-control window never replenished); neither outlives the rule's
	// timeout.
	deadline := cfg.timeout()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	sctx, cancel := context.WithCancel(context.Background())
	opened := make(chan openedStream, 1)
	go func() {
		st, err := extprocv3.NewExternalProcessorClient(e.cc).Process(sctx)
		opened <- openedStream{stream: st, err: err}
	}()
	var stream extprocv3.ExternalProcessor_ProcessClient
	select {
	case o := <-opened:
		if o.err != nil {
			cancel()
			err := fmt.Errorf("epp: open stream: %w", o.err)
			e.noteErr(err)
			return &Decision{Status: StatusError, Err: err}, nil
		}
		stream = o.stream
	case <-timer.C:
		// The cancel ends the pending open; its result is discarded. The
		// connection is left to gRPC: its own connect timeout and backoff
		// turn a dial that never answers into a channel in transient
		// failure, on which the requests that follow fail at once instead
		// of each waiting the deadline (dead-peer detection is for a
		// connection that is up and silent, not for one that never came up).
		cancel()
		err := fmt.Errorf("epp: no connection within %s: %w", deadline, context.DeadlineExceeded)
		e.noteErr(err)
		return &Decision{Status: StatusError, Err: err}, nil
	case <-ctx.Done():
		cancel()
		return &Decision{Status: StatusError, Err: fmt.Errorf("epp: request abandoned: %w", ctx.Err())}, nil
	}
	s := &Stream{stream: stream, cancel: cancel, recv: make(chan recvMsg, 8)}
	go s.receiver()

	sent := make(chan error, 1)
	go func() { sent <- s.sendRequest(req) }()
	var dec *Decision
	select {
	case err := <-sent:
		if err != nil {
			dec = &Decision{Status: StatusError, Err: err}
		} else {
			dec = s.awaitDecision(ctx, timer.C, deadline, req)
		}
	case <-timer.C:
		dec = &Decision{Status: StatusError, Err: fmt.Errorf("epp: no decision within %s: %w", deadline, context.DeadlineExceeded)}
	case <-ctx.Done():
		dec = &Decision{Status: StatusError, Err: fmt.Errorf("epp: request abandoned: %w", ctx.Err())}
	}
	if s.received.Load() {
		e.silent.Store(0)
	} else if dec.Status != StatusOK && errors.Is(dec.Err, context.DeadlineExceeded) {
		c.silentTimeout(connKey(cfg), e)
	}
	if dec.Status == StatusError {
		e.noteErr(dec.Err)
	} else {
		e.noteOK()
	}
	if dec.Status != StatusOK {
		s.Abort()
		return dec, nil
	}
	s.decided.Store(true)
	return dec, s
}

// receiver is the stream's only reader; it ends on any error (EOF, cancel).
// Once the request phase is decided it also watches for an eviction.
func (s *Stream) receiver() {
	for {
		msg, err := s.stream.Recv()
		if err == nil {
			s.received.Store(true)
		}
		if err == nil && s.decided.Load() {
			if im, ok := msg.Response.(*extprocv3.ProcessingResponse_ImmediateResponse); ok && s.evicted.CompareAndSwap(false, true) {
				code := immediateDecision(im.ImmediateResponse).ImmCode
				tk.LogIt(tk.LogInfo, "[EPP] request evicted by the EPP during its response (%d)\n", code)
				if fn := s.onEvict.Load(); fn != nil {
					(*fn)(code)
				}
			}
		}
		s.recv <- recvMsg{msg: msg, err: err}
		if err != nil {
			return
		}
	}
}

func (s *Stream) sendRequest(req *Request) error {
	hdrs := &corev3.HeaderMap{Headers: make([]*corev3.HeaderValue, 0, len(req.Headers)+4)}
	add := func(k, v string) {
		hdrs.Headers = append(hdrs.Headers, &corev3.HeaderValue{Key: k, RawValue: []byte(v)})
	}
	add(":method", req.Method)
	add(":path", req.Path)
	add(":authority", req.Authority)
	add(":scheme", req.Scheme)
	for _, h := range req.Headers {
		add(h.Key, h.Value)
	}
	first := &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{Headers: hdrs, EndOfStream: len(req.Body) == 0},
		},
	}
	if len(req.Subset) > 0 {
		st, err := structpb.NewStruct(map[string]any{HeaderSubset: stringsToAny(req.Subset)})
		if err != nil {
			return fmt.Errorf("epp: subset metadata: %w", err)
		}
		first.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{MetadataSubsetNamespace: st}}
	}
	if err := s.stream.Send(first); err != nil {
		return fmt.Errorf("epp: send headers: %w", err)
	}
	for off := 0; off < len(req.Body); off += BodyChunk {
		end := off + BodyChunk
		if end > len(req.Body) {
			end = len(req.Body)
		}
		msg := &extprocv3.ProcessingRequest{
			Request: &extprocv3.ProcessingRequest_RequestBody{
				RequestBody: &extprocv3.HttpBody{Body: req.Body[off:end], EndOfStream: end == len(req.Body)},
			},
		}
		if err := s.stream.Send(msg); err != nil {
			return fmt.Errorf("epp: send body: %w", err)
		}
	}
	return nil
}

func stringsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// awaitDecision consumes responses until the request phase is decided.
func (s *Stream) awaitDecision(ctx context.Context, expired <-chan time.Time, deadline time.Duration, req *Request) *Decision {
	dec := &Decision{Status: StatusOK}
	var body []byte
	bodyExpected := len(req.Body) > 0
	gotHeaders := false
	for {
		select {
		case <-ctx.Done():
			return &Decision{Status: StatusError, Err: fmt.Errorf("epp: request abandoned: %w", ctx.Err())}
		case <-expired:
			return &Decision{Status: StatusError, Err: fmt.Errorf("epp: no decision within %s: %w", deadline, context.DeadlineExceeded)}
		case r := <-s.recv:
			if r.err != nil {
				return &Decision{Status: StatusError, Err: fmt.Errorf("epp: stream: %w", r.err)}
			}
			switch m := r.msg.Response.(type) {
			case *extprocv3.ProcessingResponse_ImmediateResponse:
				return immediateDecision(m.ImmediateResponse)
			case *extprocv3.ProcessingResponse_RequestHeaders:
				gotHeaders = true
				cr := m.RequestHeaders.GetResponse()
				dec.applyHeaderMutation(cr.GetHeaderMutation(), r.msg.GetDynamicMetadata())
				if done, nb := bodyMutation(cr.GetBodyMutation(), body); done || !bodyExpected {
					body = nb
					return dec.finish(req.Body, body, gotHeaders)
				} else {
					body = nb
				}
			case *extprocv3.ProcessingResponse_RequestBody:
				cr := m.RequestBody.GetResponse()
				dec.applyHeaderMutation(cr.GetHeaderMutation(), r.msg.GetDynamicMetadata())
				bm := cr.GetBodyMutation()
				done, nb := bodyMutation(bm, body)
				body = nb
				if done || bm == nil || bm.GetStreamedResponse() == nil {
					return dec.finish(req.Body, body, gotHeaders)
				}
			default:
				// Response-phase replies cannot arrive yet; anything else is
				// ignored, as Envoy does.
			}
		}
	}
}

// finish settles the body: a streamed echo that equals the request body is
// not a change, and a request the EPP never streamed back keeps its body.
func (d *Decision) finish(orig, streamed []byte, gotHeaders bool) *Decision {
	if streamed != nil && !bytes.Equal(streamed, orig) {
		d.NewBody = streamed
		d.BodyChanged = true
	}
	if !gotHeaders && len(d.Candidates) == 0 {
		tk.LogIt(tk.LogDebug, "[EPP] decision without a headers response: no destination\n")
	}
	return d
}

// bodyMutation folds one body mutation into the body being rebuilt.
// It reports whether the mutation completed the body: a whole-body
// replacement, a streamed chunk with end_of_stream, or (nil → false) no
// mutation at all, which the caller decides on by message type.
func bodyMutation(bm *extprocv3.BodyMutation, acc []byte) (bool, []byte) {
	if bm == nil {
		return false, acc
	}
	switch mut := bm.Mutation.(type) {
	case *extprocv3.BodyMutation_Body:
		return true, append([]byte(nil), mut.Body...)
	case *extprocv3.BodyMutation_StreamedResponse:
		if acc == nil {
			acc = []byte{}
		}
		acc = append(acc, mut.StreamedResponse.GetBody()...)
		return mut.StreamedResponse.GetEndOfStream(), acc
	case *extprocv3.BodyMutation_ClearBody:
		if mut.ClearBody {
			return true, []byte{}
		}
	}
	return false, acc
}

// applyHeaderMutation collects the destination list and the header
// changes. A destination also carried in dynamic_metadata["envoy.lb"] must
// agree with the header; the header wins and a disagreement is logged.
func (d *Decision) applyHeaderMutation(hm *extprocv3.HeaderMutation, dyn *structpb.Struct) {
	var hdrDest string
	for _, opt := range hm.GetSetHeaders() {
		h := opt.GetHeader()
		if h == nil {
			continue
		}
		key := strings.ToLower(h.GetKey())
		val := string(h.GetRawValue())
		if val == "" {
			val = h.GetValue()
		}
		switch {
		case key == HeaderDestination:
			hdrDest = val
			d.Candidates = parseCandidates(val)
		case key == "content-length":
			// The data plane sets it from the body it forwards (risk R4).
		case strings.HasPrefix(key, ":"):
			// The llm-d EPP echoes the pseudo headers (:method, :path,
			// :authority, :scheme) in its mutation; they are the request
			// line, not header lines of an HTTP/1.1 request.
		default:
			d.HdrSet = append(d.HdrSet, Header{Key: key, Value: val})
		}
	}
	for _, k := range hm.GetRemoveHeaders() {
		d.HdrDel = append(d.HdrDel, strings.ToLower(k))
	}
	if lb := dyn.GetFields()[MetadataNamespace]; lb != nil {
		if v := lb.GetStructValue().GetFields()[HeaderDestination]; v != nil {
			md := v.GetStringValue()
			if hdrDest == "" {
				d.Candidates = parseCandidates(md)
			} else if md != hdrDest {
				tk.LogIt(tk.LogWarning, "[EPP] destination header %q and metadata %q differ; using the header\n", hdrDest, md)
			}
		}
	}
}

// parseCandidates turns "ip:port, ip:port" into at most
// MaxCandidates well-formed, de-duplicated entries in order.
func parseCandidates(list string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, raw := range strings.Split(list, ",") {
		c := strings.TrimSpace(raw)
		if c == "" {
			continue
		}
		host, port, err := net.SplitHostPort(c)
		if err != nil || host == "" || port == "" {
			tk.LogIt(tk.LogWarning, "[EPP] ignoring malformed destination %q\n", c)
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
		if len(out) == MaxCandidates {
			break
		}
	}
	return out
}

func immediateDecision(im *extprocv3.ImmediateResponse) *Decision {
	dec := &Decision{Status: StatusImmediate, ImmCode: 500, ImmBody: im.GetBody()}
	if st := im.GetStatus(); st != nil && st.GetCode() != 0 {
		dec.ImmCode = int(st.GetCode())
	}
	for _, opt := range im.GetHeaders().GetSetHeaders() {
		h := opt.GetHeader()
		if h == nil {
			continue
		}
		val := string(h.GetRawValue())
		if val == "" {
			val = h.GetValue()
		}
		key := strings.ToLower(h.GetKey())
		if strings.HasPrefix(key, ":") || key == "content-length" {
			continue // the status line and the length are the data plane's
		}
		dec.ImmHeaders = append(dec.ImmHeaders, Header{Key: key, Value: val})
	}
	return dec
}

// ReportResponseHeaders sends the backend's response headers, the status
// code and the endpoint that actually served the request. The code goes
// as the :status pseudo header Envoy sends and, because the EPP reads it
// under the plain key (risk R2), as "status" too.
func (s *Stream) ReportResponseHeaders(status int, hdrs []Header, served string) error {
	hm := &corev3.HeaderMap{Headers: make([]*corev3.HeaderValue, 0, len(hdrs)+2)}
	code := strconv.Itoa(status)
	hm.Headers = append(hm.Headers,
		&corev3.HeaderValue{Key: ":status", RawValue: []byte(code)},
		&corev3.HeaderValue{Key: "status", RawValue: []byte(code)})
	for _, h := range hdrs {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: h.Key, RawValue: []byte(h.Value)})
	}
	msg := &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extprocv3.HttpHeaders{Headers: hm},
		},
	}
	if served != "" {
		st, err := structpb.NewStruct(map[string]any{HeaderServed: served})
		if err != nil {
			return fmt.Errorf("epp: served metadata: %w", err)
		}
		msg.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{MetadataNamespace: st}}
	}
	return s.send(msg)
}

// ReportResponseEnd tells the EPP the response is over (one empty
// ResponseBody with end_of_stream, decision: no response body relay), then
// waits briefly for the EPP to finish and closes the stream.
func (s *Stream) ReportResponseEnd() error {
	msg := &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{EndOfStream: true},
		},
	}
	err := s.send(msg)
	if err == nil {
		err = s.stream.CloseSend()
	}
	s.drain(responseDrain)
	s.Abort()
	return err
}

// drain waits for the EPP to answer the end of stream or close, bounded.
func (s *Stream) drain(wait time.Duration) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case r := <-s.recv:
			if r.err != nil {
				return
			}
		case <-timer.C:
			return
		}
	}
}

// Abort cancels the stream: the EPP sees the cancel and releases the
// request. Safe to call more than once and after ReportResponseEnd.
func (s *Stream) Abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	s.done = true
	s.cancel()
}

func (s *Stream) send(msg *extprocv3.ProcessingRequest) error {
	s.mu.Lock()
	closed := s.done
	s.mu.Unlock()
	if closed {
		return errors.New("epp: stream already closed")
	}
	if err := s.stream.Send(msg); err != nil {
		if errors.Is(err, io.EOF) {
			// The EPP closed first; its status is in the receiver.
			return fmt.Errorf("epp: stream closed by the EPP: %w", err)
		}
		return fmt.Errorf("epp: send: %w", err)
	}
	return nil
}

// ParseHTTP1Request turns the raw request line + headers the data plane
// buffered (through the blank line, or the whole buffer) into the pseudo
// headers and header list the EPP expects. host becomes :authority; keys
// are lower-cased; the body is NOT part of raw.
func ParseHTTP1Request(raw []byte, scheme string) (*Request, error) {
	head := raw
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		head = raw[:i]
	} else if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		head = raw[:i]
	}
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, errors.New("epp: empty request head")
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, fmt.Errorf("epp: malformed request line %q", lines[0])
	}
	req := &Request{Method: parts[0], Path: parts[1], Scheme: scheme}
	if req.Scheme == "" {
		req.Scheme = "http"
	}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("epp: malformed header line %q", line)
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		if key == "host" {
			req.Authority = val
			continue
		}
		req.Headers = append(req.Headers, Header{Key: key, Value: val})
	}
	return req, nil
}
