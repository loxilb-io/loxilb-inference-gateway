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
package handler

// worker_metrics_get_test.go — GET /config/worker/metrics must report whether
// monitoring is on.
//
// The read is deliberately not gated on monitoring-enabled, unlike the POST
// and the cleanup, so with monitoring off it answers 200 with an empty worker
// list. That is byte-identical to "enabled, nothing has reported yet" unless
// monitoring_enabled is on the wire, which is why consumers had to fall back
// to a second endpoint to tell the two apart.
//
// Serialization is asserted on the rendered JSON rather than the struct: the
// field is only useful if it survives the encoder, and an omitempty bool drops
// exactly the false case that carries the information.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"

	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
)

// stubWorkerMetricsHook answers only what the GET consults.
type stubWorkerMetricsHook struct {
	cmn.NetHookInterface
	enabled bool
	workers []interface{}
}

func (s *stubWorkerMetricsHook) NetDpEbpfIsGPUMonitoringEnabled() bool { return s.enabled }
func (s *stubWorkerMetricsHook) NetDpEbpfGetAllWorkerMetrics() []interface{} {
	return s.workers
}

func getWorkerMetrics(t *testing.T, hook *stubWorkerMetricsHook) (int, map[string]any, string) {
	t.Helper()
	prev := ApiHooks
	defer func() { ApiHooks = prev }()
	ApiHooks = hook

	resp := ConfigGetConfigWorkerMetrics(operations.GetConfigWorkerMetricsParams{}, nil)
	rec := httptest.NewRecorder()
	resp.WriteResponse(rec, runtime.JSONProducer())

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON (%v): %s", err, rec.Body.String())
	}
	return rec.Code, body, rec.Body.String()
}

// TestGetWorkerMetricsReportsMonitoringDisabled is the case the field exists
// for: monitoring off, so the empty list means "nothing is being collected".
func TestGetWorkerMetricsReportsMonitoringDisabled(t *testing.T) {
	code, body, raw := getWorkerMetrics(t, &stubWorkerMetricsHook{enabled: false})
	if code != http.StatusOK {
		t.Fatalf("answered %d, want 200", code)
	}
	v, present := body["monitoring_enabled"]
	if !present {
		t.Fatalf("monitoring_enabled absent from %s — false and \"not populated\" are "+
			"the same bytes, which is the defect; mark the field required so "+
			"omitempty is dropped", raw)
	}
	if v != false {
		t.Errorf("monitoring_enabled = %v, want false", v)
	}
}

// TestGetWorkerMetricsReportsMonitoringEnabled is the state it must be
// distinguishable from: monitoring on, but no worker has reported yet.
func TestGetWorkerMetricsReportsMonitoringEnabled(t *testing.T) {
	code, body, raw := getWorkerMetrics(t, &stubWorkerMetricsHook{enabled: true})
	if code != http.StatusOK {
		t.Fatalf("answered %d, want 200", code)
	}
	if v, present := body["monitoring_enabled"]; !present || v != true {
		t.Fatalf("monitoring_enabled = %v (present=%v), want true: %s", v, present, raw)
	}
}

// TestGetWorkerMetricsDistinguishesDisabledFromIdle states the property
// directly: the two responses must not be identical. Without it the earlier
// two tests could both pass against a constant.
func TestGetWorkerMetricsDistinguishesDisabledFromIdle(t *testing.T) {
	_, _, off := getWorkerMetrics(t, &stubWorkerMetricsHook{enabled: false})
	_, _, on := getWorkerMetrics(t, &stubWorkerMetricsHook{enabled: true})
	if off == on {
		t.Fatalf("monitoring disabled and monitoring enabled with no workers "+
			"produce identical responses (%s); a consumer cannot tell a disabled "+
			"subsystem from an idle one", off)
	}
}

// TestGetWorkerMetricsSerializesEmptyWorkersAsList guards the other field on
// the response: an empty list must be [] rather than null, or a consumer has
// to special-case a state that is not special.
func TestGetWorkerMetricsSerializesEmptyWorkersAsList(t *testing.T) {
	_, body, raw := getWorkerMetrics(t, &stubWorkerMetricsHook{enabled: true})
	w, present := body["workers"]
	if !present {
		t.Fatalf("workers absent from %s", raw)
	}
	list, ok := w.([]any)
	if !ok {
		t.Fatalf("workers is %T, want a list: %s", w, raw)
	}
	if len(list) != 0 {
		t.Errorf("workers = %v, want empty", list)
	}
}
