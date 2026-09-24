/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package audit

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var goldenStamp = stamp{
	instanceID:  "igw-test-01",
	bootID:      "0192b7a0-0000-7000-8000-000000000001",
	segmentUUID: "0192b7a0-0000-7000-8000-000000000002",
	seq:         42,
}

var goldenTS = time.Date(2026, 9, 24, 7, 0, 1, 481_000_000, time.UTC)

func goldenData() *Record {
	return &Record{
		EventID:    "0192b7a0-0000-7000-8000-00000000000a",
		TS:         goldenTS,
		Stream:     StreamData,
		EventType:  "data.ai.complete",
		RequestID:  "req-1",
		Actor:      Actor{Auth: AuthAPIKey, KeyID: "k-17", Tenant: "t1", User: "alice", Remote: "10.0.0.9:51234"},
		Outcome:    Outcome{Status: 200, OK: true, Reason: ReasonOK},
		Data:       &DataDetail{Service: "chat", Rule: "r1", Model: "llama-3", Endpoint: "10.0.0.11:8000", TokensIn: 12, TokensOut: 40, LatencyMs: 812, FinishReason: "stop", Stream: true},
		producerID: "w3",
		pseq:       7,
	}
}

func goldenMgmt() *Record {
	return &Record{
		EventID:   "0192b7a0-0000-7000-8000-00000000000b",
		TS:        goldenTS,
		Stream:    StreamMgmt,
		EventType: "mgmt.config.mutate",
		Phase:     PhaseIntent,
		Actor:     Actor{Auth: AuthSession, User: "admin", Role: "admin", Remote: "127.0.0.1:40000", Delegated: "mcp:claude", DelegationTrusted: false},
		Outcome:   Outcome{Status: 0, OK: false, Reason: ReasonOK},
		Mgmt:      &MgmtDetail{Method: "POST", Path: "/netlox/v1/config/loadbalancer", RouteClass: "generated", Resource: "loadbalancer", Action: "create", ChangedFields: []string{"serviceArguments.externalIP", "endpoints"}},
	}
}

const goldenDataLine = `{"schema_version":1,"event_id":"0192b7a0-0000-7000-8000-00000000000a","ts":"2026-09-24T07:00:01.481Z","instance_id":"igw-test-01","boot_id":"0192b7a0-0000-7000-8000-000000000001","segment_uuid":"0192b7a0-0000-7000-8000-000000000002","seq":42,"producer_id":"w3","pseq":7,"stream":"data","event_type":"data.ai.complete","request_id":"req-1","actor":{"auth":"apikey","key_id":"k-17","user":"alice","tenant":"t1","remote":"10.0.0.9:51234"},"outcome":{"status":200,"ok":true,"reason":"ok"},"detail":{"service":"chat","rule":"r1","model":"llama-3","endpoint":"10.0.0.11:8000","tokens_in":12,"tokens_out":40,"latency_ms":812,"finish_reason":"stop","retried":false,"stream":true,"prompt_captured":false}}` + "\n"

const goldenMgmtLine = `{"schema_version":1,"event_id":"0192b7a0-0000-7000-8000-00000000000b","ts":"2026-09-24T07:00:01.481Z","instance_id":"igw-test-01","boot_id":"0192b7a0-0000-7000-8000-000000000001","segment_uuid":"0192b7a0-0000-7000-8000-000000000002","seq":42,"stream":"mgmt","event_type":"mgmt.config.mutate","phase":"intent","actor":{"auth":"session","user":"admin","role":"admin","remote":"127.0.0.1:40000","delegated":"mcp:claude","delegation_trusted":false},"outcome":{"status":0,"ok":false,"reason":"ok"},"detail":{"method":"POST","path":"/netlox/v1/config/loadbalancer","route_class":"generated","resource":"loadbalancer","action":"create","changed_fields":["serviceArguments.externalIP","endpoints"]}}` + "\n"

// TestEncodeGolden pins the wire format. A change here is a schema change
// and must be add-only.
func TestEncodeGolden(t *testing.T) {
	e := newEncoder()
	got, err := e.encode(goldenData(), goldenStamp)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenDataLine {
		t.Errorf("data record:\n got %s\nwant %s", got, goldenDataLine)
	}
	got, err = e.encode(goldenMgmt(), goldenStamp)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenMgmtLine {
		t.Errorf("mgmt record:\n got %s\nwant %s", got, goldenMgmtLine)
	}
	for _, line := range []string{goldenDataLine, goldenMgmtLine} {
		if !json.Valid([]byte(line)) {
			t.Errorf("not valid JSON: %s", line)
		}
	}
}

// envelopeKeys is the complete top-level allowlist of schema version 1.
var envelopeKeys = map[string]bool{
	"schema_version": true, "event_id": true, "ts": true, "instance_id": true, "boot_id": true,
	"segment_uuid": true, "seq": true, "producer_id": true, "pseq": true, "stream": true,
	"event_type": true, "class": true, "phase": true, "result_of": true, "request_id": true,
	"trace_id": true, "span_id": true, "actor": true, "outcome": true, "detail": true,
}

// forbiddenKeyParts are the names no key at any depth may contain.
var forbiddenKeyParts = []string{"body", "password", "passwd", "secret", "authorization",
	"cookie", "raw_query", "request_uri", "rawquery", "requesturi", "headers", "prompt_text", "response_text"}

// TestEncodeKeysAreTheAllowlist decodes encoded records and asserts every
// top-level key is in the envelope allowlist and no key anywhere carries a
// forbidden name.
func TestEncodeKeysAreTheAllowlist(t *testing.T) {
	e := newEncoder()
	sys := sysRecord("sys.heartbeat", "writer", &SysDetail{Heartbeat: &Heartbeat{
		Accepted: map[Stream]uint64{StreamData: 1}, QueueDepth: map[string]uint64{"data": 0}, QueueHWM: map[string]uint64{},
	}})
	sys.EventID, sys.TS = "x", goldenTS
	for _, r := range []*Record{goldenData(), goldenMgmt(), sys} {
		line, err := e.encode(r, goldenStamp)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("%s: %v", r.Stream, err)
		}
		for k := range m {
			if !envelopeKeys[k] {
				t.Errorf("%s: top-level key %q is not in the envelope allowlist", r.Stream, k)
			}
		}
		walkKeys(t, string(r.Stream), m)
	}
}

func walkKeys(t *testing.T, where string, v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			lk := strings.ToLower(k)
			for _, bad := range forbiddenKeyParts {
				if strings.Contains(lk, bad) {
					t.Errorf("%s: key %q contains forbidden name %q", where, k, bad)
				}
			}
			walkKeys(t, where+"."+k, val)
		}
	case []any:
		for _, val := range x {
			walkKeys(t, where+"[]", val)
		}
	}
}

// TestRecordTypesHaveNoBodyField makes the "no body field" invariant
// structural: the typed structs are the schema, so a forbidden field name
// cannot appear without changing a type here.
func TestRecordTypesHaveNoBodyField(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(Record{}), reflect.TypeOf(Actor{}), reflect.TypeOf(Outcome{}),
		reflect.TypeOf(MgmtDetail{}), reflect.TypeOf(DataDetail{}), reflect.TypeOf(SysDetail{}),
		reflect.TypeOf(mgmtJSON{}), reflect.TypeOf(Heartbeat{}),
	}
	for _, typ := range types {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !canCarryContent(f.Type) {
				// A bool or a number cannot carry a body or a credential;
				// flags such as prompt_captured are allowed.
				continue
			}
			name := strings.ToLower(f.Name)
			for _, bad := range []string{"body", "password", "secret", "header", "query", "requesturi", "cookie", "prompt", "response"} {
				if strings.Contains(name, bad) {
					t.Errorf("%s.%s: content-carrying field name contains %q", typ.Name(), f.Name, bad)
				}
			}
			if strings.Contains(name, "token") && !strings.Contains(name, "fingerprint") {
				t.Errorf("%s.%s: a token field must be a fingerprint", typ.Name(), f.Name)
			}
		}
	}
}

// canCarryContent reports whether a field of this type could hold text or
// bytes: strings, byte slices, slices of such, maps, interfaces, pointers
// to structs (checked recursively by listing them in the type table).
func canCarryContent(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.String, reflect.Interface, reflect.Map:
		return true
	case reflect.Slice, reflect.Array:
		return canCarryContent(t.Elem())
	case reflect.Ptr:
		return t.Elem().Kind() != reflect.Struct && canCarryContent(t.Elem())
	}
	return false
}

// TestPathIsSanitized is the T15 arm for the route that carries credentials
// in its query string: the canary must never reach the line.
func TestPathIsSanitized(t *testing.T) {
	const canary = "CANARY-ACCESS-TOKEN-7f3a"
	r := goldenMgmt()
	r.Mgmt.Path = "/netlox/v1/oauth/github/token?access_token=" + canary + "&refresh_token=" + canary
	if !r.sanitize() {
		t.Fatal("sanitize reported nothing to do")
	}
	line, err := newEncoder().encode(r, goldenStamp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(line), canary) {
		t.Fatalf("canary leaked: %s", line)
	}
	if !strings.Contains(string(line), `"path":"/netlox/v1/oauth/github/token"`) {
		t.Fatalf("route template lost: %s", line)
	}
	if r.sanitize() {
		t.Fatal("sanitize is not idempotent")
	}
}

func TestValidate(t *testing.T) {
	ok := goldenData()
	if err := ok.Validate(); err != nil {
		t.Fatalf("golden data record invalid: %v", err)
	}
	cases := map[string]func(*Record){
		"no stream":      func(r *Record) { r.Stream = "" },
		"unknown stream": func(r *Record) { r.Stream = "other" },
		"no event type":  func(r *Record) { r.EventType = "" },
		"reason not in vocabulary": func(r *Record) {
			r.Outcome.Reason = "because"
		},
		"empty reason":    func(r *Record) { r.Outcome.Reason = "" },
		"detail mismatch": func(r *Record) { r.Mgmt = &MgmtDetail{} },
		"missing detail":  func(r *Record) { r.Data = nil },
		"phase on data":   func(r *Record) { r.Phase = PhaseIntent },
		"unknown phase":   func(r *Record) { r.Stream = StreamMgmt; r.Data = nil; r.Mgmt = &MgmtDetail{}; r.Phase = "maybe" },
		"two details":     func(r *Record) { r.Sys = &SysDetail{} },
		"phase on system": func(r *Record) { r.Stream = StreamSystem; r.Data = nil; r.Sys = &SysDetail{}; r.Phase = PhaseResult },
	}
	for name, mutate := range cases {
		r := goldenData()
		mutate(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestAppendStringMatchesJSON(t *testing.T) {
	inputs := []string{
		"", "plain", `quote " and backslash \`, "tab\tnewline\ncr\r", "ctl\x01\x1f",
		"unicode 한글 ✓", "invalid \xff\xfe utf8", "  line sep", "</script>",
	}
	for _, in := range inputs {
		got := appendString(nil, in)
		var back string
		if err := json.Unmarshal(got, &back); err != nil {
			t.Errorf("%q: output %s does not parse: %v", in, got, err)
			continue
		}
		// The oracle is encoding/json itself: one replacement rune per
		// invalid byte, the same escapes, the same parse.
		ref, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("%q: reference marshal: %v", in, err)
		}
		var want string
		if err := json.Unmarshal(ref, &want); err != nil {
			t.Fatalf("%q: reference parse: %v", in, err)
		}
		if back != want {
			t.Errorf("%q: round trip %q, want %q", in, back, want)
		}
	}
}

// TestEncodeDataZeroAlloc is the producer-cost gate's unit form: the hot
// path must not allocate once the encoder's buffer is warm.
func TestEncodeDataZeroAlloc(t *testing.T) {
	e := newEncoder()
	r := goldenData()
	if _, err := e.encode(r, goldenStamp); err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := e.encode(r, goldenStamp); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("data record encode allocates %.1f times per record, want 0", allocs)
	}
}

func BenchmarkEncodeData(b *testing.B) {
	e := newEncoder()
	r := goldenData()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := e.encode(r, goldenStamp); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeMgmt(b *testing.B) {
	e := newEncoder()
	r := goldenMgmt()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := e.encode(r, goldenStamp); err != nil {
			b.Fatal(err)
		}
	}
}
