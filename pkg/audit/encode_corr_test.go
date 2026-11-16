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
	"strings"
	"testing"
)

// A request's traceparent gives trace_id and the client's span as
// parent_span_id on the envelope; its X-Client-Session-Id gives
// detail.session_id. span_id stays for a span of the gateway's own.
// All three are add-only: a record without them is byte for byte what it was.
func TestEncodeCorrelationFieldsAreAddOnly(t *testing.T) {
	e := newEncoder()

	got, err := e.encode(goldenData(), goldenStamp)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenDataLine {
		t.Errorf("a record with no correlation changed:\n got %s\nwant %s", got, goldenDataLine)
	}
	for _, key := range []string{"trace_id", "parent_span_id", "span_id", "session_id"} {
		if strings.Contains(string(got), `"`+key+`"`) {
			t.Errorf("record with no correlation carries %q", key)
		}
	}

	r := goldenData()
	r.TraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	r.ParentSpanID = "00f067aa0ba902b7"
	r.Data.SessionID = "loxigpt.app:sess_01-A"
	got, err = e.encode(r, goldenStamp)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(got) {
		t.Fatalf("not valid JSON: %s", got)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if m["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace_id = %v", m["trace_id"])
	}
	if m["parent_span_id"] != "00f067aa0ba902b7" {
		t.Errorf("parent_span_id = %v", m["parent_span_id"])
	}
	if _, ok := m["span_id"]; ok {
		t.Errorf("span_id written from the client's span: %v (it is the gateway's own)", m["span_id"])
	}
	d, _ := m["detail"].(map[string]any)
	if d["session_id"] != "loxigpt.app:sess_01-A" {
		t.Errorf("detail.session_id = %v", d["session_id"])
	}
}
