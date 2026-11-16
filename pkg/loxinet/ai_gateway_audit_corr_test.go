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

package loxinet

import (
	"reflect"
	"testing"
)

// The deny, complete and settle records carry the correlation the
// datapath captured -- trace_id and parent_span_id from a valid traceparent,
// detail.session_id from a valid X-Client-Session-Id -- and nothing when it
// captured nothing. Neither is identity: the actor is the same with or
// without them.

const (
	corrTrace  = "4bf92f3577b34da6a3ce929d0e0e4736"
	corrParent = "00f067aa0ba902b7"
	corrSess   = "loxigpt.app:sess_01-A"
)

type corrCase struct {
	event string
	emit  func(trace, parent, sess string) bool
}

func corrCases() []corrCase {
	return []corrCase{
		{eventAIComplete, func(tr, pa, se string) bool {
			return emitAIComplete(aiCompleteRecord{
				RequestID: "req-c", TenantID: "acme", UserID: "u-1", KeyID: "k-1",
				SvcIdent: "10.0.0.1:8080", ModelName: "llama-3", StatusCode: 200, WorkerID: 1,
				TraceID: tr, ParentSpanID: pa, SessionID: se,
			})
		}},
		{eventAISettle, func(tr, pa, se string) bool {
			return emitAISettle(aiSettleRecord{
				RequestID: "req-s", TenantID: "acme", UserID: "u-1", KeyID: "k-1",
				SvcIdent: "10.0.0.1:8080", ModelName: "llama-3", TokensIn: 3, TokensOut: 4,
				Allowed: true, WorkerID: 1,
				TraceID: tr, ParentSpanID: pa, SessionID: se,
			})
		}},
		{eventAIDeny, func(tr, pa, se string) bool {
			return emitAIDeny(aiDenyRecord{
				RequestID: "req-d", TenantID: "acme", KeyID: "k-1", SvcIdent: "10.0.0.1:8080",
				ModelName: "llama-3", Stage: aiStageAuth, HTTPStatus: 403,
				ErrorCode: "model_not_allowed", WorkerID: 1,
				TraceID: tr, ParentSpanID: pa, SessionID: se,
			})
		}},
	}
}

func TestAIRecordsCarryTheCorrelation(t *testing.T) {
	for _, c := range corrCases() {
		t.Run(c.event, func(t *testing.T) {
			_, drain := startTrail(t)
			if !c.emit(corrTrace, corrParent, corrSess) {
				t.Fatal("emit refused")
			}
			r := only(t, drain(), c.event)
			if got := r.str("trace_id"); got != corrTrace {
				t.Errorf("trace_id = %q, want %q", got, corrTrace)
			}
			if got := r.str("parent_span_id"); got != corrParent {
				t.Errorf("parent_span_id = %q, want %q", got, corrParent)
			}
			if _, ok := r["span_id"]; ok {
				t.Errorf("span_id = %v: the client's span goes to parent_span_id", r["span_id"])
			}
			if got := r.detail().str("session_id"); got != corrSess {
				t.Errorf("detail.session_id = %q, want %q", got, corrSess)
			}
		})
	}
}

func TestAIRecordsInventNoCorrelation(t *testing.T) {
	for _, c := range corrCases() {
		t.Run(c.event, func(t *testing.T) {
			_, drain := startTrail(t)
			if !c.emit("", "", "") {
				t.Fatal("emit refused")
			}
			r := only(t, drain(), c.event)
			for _, k := range []string{"trace_id", "parent_span_id", "span_id"} {
				if _, ok := r[k]; ok {
					t.Errorf("%s = %v on a request that sent none", k, r[k])
				}
			}
			if _, ok := r.detail()["session_id"]; ok {
				t.Errorf("detail.session_id = %v on a request that sent none", r.detail()["session_id"])
			}
		})
	}
}

// One header voided never voids the other: the emitters write each field
// on its own.
func TestAIRecordsWriteEachCorrelationFieldAlone(t *testing.T) {
	for _, c := range corrCases() {
		t.Run(c.event, func(t *testing.T) {
			_, drain := startTrail(t)
			if !c.emit("", "", corrSess) || !c.emit(corrTrace, corrParent, "") {
				t.Fatal("emit refused")
			}
			ls := ofEvent(drain(), c.event)
			if len(ls) != 2 {
				t.Fatalf("%d records, want 2", len(ls))
			}
			if _, ok := ls[0]["trace_id"]; ok || ls[0].detail().str("session_id") != corrSess {
				t.Errorf("session only: %v", ls[0])
			}
			if ls[1].str("trace_id") != corrTrace || ls[1].str("parent_span_id") != corrParent {
				t.Errorf("trace only: %v", ls[1])
			}
			if _, ok := ls[1].detail()["session_id"]; ok {
				t.Errorf("trace only, yet a session: %v", ls[1])
			}
		})
	}
}

func TestAICorrelationIsNotIdentity(t *testing.T) {
	for _, c := range corrCases() {
		t.Run(c.event, func(t *testing.T) {
			_, drain := startTrail(t)
			if !c.emit("", "", "") || !c.emit(corrTrace, corrParent, corrSess) {
				t.Fatal("emit refused")
			}
			ls := ofEvent(drain(), c.event)
			if len(ls) != 2 {
				t.Fatalf("%d records, want 2", len(ls))
			}
			if !reflect.DeepEqual(ls[0].actor(), ls[1].actor()) {
				t.Errorf("actor changed with the correlation:\n without %v\n    with %v", ls[0].actor(), ls[1].actor())
			}
		})
	}
}

// Through the export itself: the record the data plane writes for a refusal
// reads each field of the ai_corr_t it is handed, up to its NUL, and a NULL
// pointer gives none of them. (The complete and settle exports read the
// same struct through the same helper, aiCorrStrings.)
func TestDenyExportReadsTheCorrelation(t *testing.T) {
	_, drain := startTrail(t)
	base := aiDenyRecord{
		RequestID: "req-x", SvcIdent: "10.0.0.1:2040", ModelName: "llama-3",
		Stage: aiStageAuth, HTTPStatus: 401, ErrorCode: "invalid_api_key", WorkerID: 1,
	}
	with := base
	with.TraceID, with.ParentSpanID, with.SessionID = corrTrace, corrParent, corrSess
	aiRecordDenyC(with)
	sessOnly := base
	sessOnly.SessionID = corrSess
	aiRecordDenyC(sessOnly)
	aiRecordDenyC(base) // NULL

	ls := ofEvent(drain(), eventAIDeny)
	if len(ls) != 3 {
		t.Fatalf("%d deny records, want 3", len(ls))
	}
	if ls[0].str("trace_id") != corrTrace || ls[0].str("parent_span_id") != corrParent ||
		ls[0].detail().str("session_id") != corrSess {
		t.Errorf("all three through the export: %v", ls[0])
	}
	if _, ok := ls[1]["trace_id"]; ok || ls[1].detail().str("session_id") != corrSess {
		t.Errorf("session alone through the export: %v", ls[1])
	}
	for _, k := range []string{"trace_id", "parent_span_id", "span_id"} {
		if _, ok := ls[2][k]; ok {
			t.Errorf("NULL correlation, yet %s = %v", k, ls[2][k])
		}
	}
	if _, ok := ls[2].detail()["session_id"]; ok {
		t.Errorf("NULL correlation, yet a session: %v", ls[2])
	}
}
