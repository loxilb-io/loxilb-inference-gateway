/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

// Package epptest is a fake Endpoint Picker (ExternalProcessor) for tests of
// the ext_proc client and of the data plane's EPP stage. It behaves like the
// llm-d EPP: it waits for the whole request body, answers with a headers
// response and streamed body chunks, then expects the response-phase
// reports. Mode selects the behaviour: ok, echo, immediate, hang,
// metadata-only, disagree, evict (an ImmediateResponse in the response
// phase).
package epptest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/loxilb-io/loxilb/pkg/epp"
)

// Fake is an ExternalProcessor that behaves like the llm-d EPP: it
// waits for the whole request body, answers with a headers response and
// streamed body chunks, then expects the response-phase reports.
type Fake struct {
	extprocv3.UnimplementedExternalProcessorServer
	Mode string // "ok", "echo", "immediate", "hang", "metadata-only", "disagree"
	// Dest, when set, replaces the default destination list in the headers
	// response (comma-separated ip:port, as the EPP sends it).
	Dest string
	// Dests, when set, names one entry per stream in turn (the first stream
	// gets Dests[0], the second Dests[1], ...): an EPP that spreads its
	// decisions over the pool, as the llm-d scheduler does with equal
	// scores. Takes precedence over Dest.
	Dests []string

	Mu           sync.Mutex
	Streams      int // ext_proc streams opened so far
	ReqHeaders   map[string]string
	Subset       []string
	Body         []byte
	RespStatus   map[string]string
	Served       string
	RespEOS      bool
	StreamClosed chan struct{}
}

func New(mode string) *Fake {
	return &Fake{Mode: mode, StreamClosed: make(chan struct{}, 1)}
}

func hv(k, v string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: k, RawValue: []byte(v)}}
}

func (f *Fake) Process(st extprocv3.ExternalProcessor_ProcessServer) error {
	f.Mu.Lock()
	f.Streams++
	f.Mu.Unlock()
	defer func() { f.StreamClosed <- struct{}{} }()
	var body []byte
	headersEOS := false
	// Request phase.
	for {
		msg, err := st.Recv()
		if err != nil {
			return err
		}
		switch r := msg.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			f.Mu.Lock()
			f.ReqHeaders = make(map[string]string)
			for _, h := range r.RequestHeaders.GetHeaders().GetHeaders() {
				f.ReqHeaders[h.Key] = string(h.RawValue)
			}
			if hint := msg.GetMetadataContext().GetFilterMetadata()[epp.MetadataSubsetNamespace]; hint != nil {
				for _, v := range hint.GetFields()[epp.HeaderSubset].GetListValue().GetValues() {
					f.Subset = append(f.Subset, v.GetStringValue())
				}
			}
			f.Mu.Unlock()
			headersEOS = r.RequestHeaders.GetEndOfStream()
		case *extprocv3.ProcessingRequest_RequestBody:
			body = append(body, r.RequestBody.GetBody()...)
			headersEOS = r.RequestBody.GetEndOfStream()
		}
		if headersEOS {
			break
		}
	}
	f.Mu.Lock()
	f.Body = body
	f.Mu.Unlock()

	switch f.Mode {
	case "hang":
		<-st.Context().Done()
		return st.Context().Err()
	case "immediate":
		return st.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extprocv3.ImmediateResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_TooManyRequests},
				Body:    []byte(`{"error":"shed"}`),
				Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{hv("Retry-After", "1")}},
			}}})
	}

	// Headers response: destination (five entries, the client keeps four),
	// a prefill hint, a content-length the client must drop, a removal.
	hm := &extprocv3.HeaderMutation{RemoveHeaders: []string{"X-Drop"}}
	dest := "10.0.0.1:8000,10.0.0.2:8000, 10.0.0.3:8000,10.0.0.1:8000,bogus,10.0.0.4:8000,10.0.0.5:8000"
	if f.Dest != "" {
		dest = f.Dest
	}
	f.Mu.Lock()
	if len(f.Dests) > 0 {
		dest = f.Dests[(f.Streams-1)%len(f.Dests)]
	}
	f.Mu.Unlock()
	dyn, _ := structpb.NewStruct(map[string]any{epp.MetadataNamespace: map[string]any{epp.HeaderDestination: dest}})
	switch f.Mode {
	case "metadata-only":
		hm.SetHeaders = []*corev3.HeaderValueOption{hv("x-prefiller-host-port", "10.0.0.9:8000")}
	case "disagree":
		hm.SetHeaders = []*corev3.HeaderValueOption{hv(epp.HeaderDestination, "10.0.0.7:8000")}
	default:
		// The llm-d EPP echoes the pseudo headers in its mutation too.
		hm.SetHeaders = []*corev3.HeaderValueOption{
			hv(epp.HeaderDestination, dest), hv("x-prefiller-host-port", "10.0.0.9:8000"), hv("Content-Length", "5"),
			hv(":method", "POST"), hv(":path", "/v1/completions"), hv(":authority", "vip:8080"), hv(":scheme", "http"),
		}
	}
	if err := st.Send(&extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{
			Response: &extprocv3.CommonResponse{HeaderMutation: hm, ClearRouteCache: true}}},
		DynamicMetadata: dyn,
	}); err != nil {
		return err
	}
	if len(body) > 0 {
		out := body
		if f.Mode == "ok" {
			out = bytes.Replace(body, []byte(`"model":"alias"`), []byte(`"model":"served-model"`), 1)
		}
		half := len(out) / 2
		for i, chunk := range [][]byte{out[:half], out[half:]} {
			if err := st.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
				RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{BodyMutation: &extprocv3.BodyMutation{
					Mutation: &extprocv3.BodyMutation_StreamedResponse{StreamedResponse: &extprocv3.StreamedBodyResponse{Body: chunk, EndOfStream: i == 1}}}}}}}); err != nil {
				return err
			}
		}
	}

	// Response phase.
	for {
		msg, err := st.Recv()
		if err != nil {
			return err
		}
		switch r := msg.Request.(type) {
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			if f.Mode == "evict" {
				// Flow-control eviction: the EPP sheds a request it admitted.
				return st.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &extprocv3.ImmediateResponse{
						Status: &typev3.HttpStatus{Code: typev3.StatusCode_TooManyRequests},
						Body:   []byte(`{"error":"evicted"}`),
					}}})
			}
			f.Mu.Lock()
			f.RespStatus = make(map[string]string)
			for _, h := range r.ResponseHeaders.GetHeaders().GetHeaders() {
				f.RespStatus[h.Key] = string(h.RawValue)
			}
			if lb := msg.GetMetadataContext().GetFilterMetadata()[epp.MetadataNamespace]; lb != nil {
				f.Served = lb.GetFields()[epp.HeaderServed].GetStringValue()
			}
			f.Mu.Unlock()
			if err := st.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{}}}}); err != nil {
				return err
			}
		case *extprocv3.ProcessingRequest_ResponseBody:
			if r.ResponseBody.GetEndOfStream() {
				f.Mu.Lock()
				f.RespEOS = true
				f.Mu.Unlock()
				return st.Send(&extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{}}}})
			}
		}
	}
}

func Start(t *testing.T, f *Fake, serverTLS bool) (addr string, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return startOn(t, f, lis, serverTLS)
}

// StartOn serves the fake, plaintext, on an existing listener (to bring an
// EPP back on the address a rule already names).
func StartOn(t *testing.T, f *Fake, lis net.Listener) (addr string, stop func()) {
	t.Helper()
	return startOn(t, f, lis, false)
}

func startOn(t *testing.T, f *Fake, lis net.Listener, serverTLS bool) (addr string, stop func()) {
	t.Helper()
	var opts []grpc.ServerOption
	if serverTLS {
		opts = append(opts, grpc.Creds(credentials.NewServerTLSFromCert(SelfSignedCert(t))))
	}
	srv := grpc.NewServer(opts...)
	extprocv3.RegisterExternalProcessorServer(srv, f)
	go srv.Serve(lis)
	return lis.Addr().String(), srv.Stop
}

func SelfSignedCert(t testing.TB) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "epp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
