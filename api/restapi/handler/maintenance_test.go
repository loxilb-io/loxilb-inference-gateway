/*
 * Copyright (c) 2026 LoxiLB Authors
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

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/maintenance"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
)

// stubMaintenanceHook is the standard embed-and-override stub for the wide
// hook interface: only the in-flight counter the maintenance surface reads
// is implemented; any other call panics loudly on the nil embed.
type stubMaintenanceHook struct {
	cmn.NetHookInterface
	inFlight int64
}

func (s *stubMaintenanceHook) NetAiInFlightStreamsGet() int64 { return s.inFlight }

func withMaintenanceFixture(t *testing.T, inFlight int64) {
	t.Helper()
	prev := ApiHooks
	ApiHooks = &stubMaintenanceHook{inFlight: inFlight}
	t.Cleanup(func() {
		ApiHooks = prev
		maintenance.Leave() // never leak operator state into another test
	})
}

func putMaintenance(t *testing.T, enabled bool, drainTimeoutSeconds uint32) *models.MaintenanceStatus {
	t.Helper()
	params := operations.PutMaintenanceParams{
		HTTPRequest: httptest.NewRequest(http.MethodPut, "/netlox/v1/maintenance", nil),
		Attr:        &models.MaintenanceRequest{Enabled: &enabled, DrainTimeoutSeconds: drainTimeoutSeconds},
	}
	resp := ConfigPutMaintenance(params, nil)
	ok, isOK := resp.(*operations.PutMaintenanceOK)
	if !isOK {
		t.Fatalf("PUT maintenance returned %T, want *PutMaintenanceOK", resp)
	}
	return ok.Payload
}

func getMaintenance(t *testing.T) *models.MaintenanceStatus {
	t.Helper()
	params := operations.GetMaintenanceParams{
		HTTPRequest: httptest.NewRequest(http.MethodGet, "/netlox/v1/maintenance", nil),
	}
	resp := ConfigGetMaintenance(params, nil)
	ok, isOK := resp.(*operations.GetMaintenanceOK)
	if !isOK {
		t.Fatalf("GET maintenance returned %T, want *GetMaintenanceOK", resp)
	}
	return ok.Payload
}

func TestMaintenanceEnterReportsTruthfully(t *testing.T) {
	withMaintenanceFixture(t, 7)
	st := putMaintenance(t, true, 300)
	if *st.State != "maintenance" {
		t.Fatalf("state = %q, want maintenance", *st.State)
	}
	if st.OperationID == "" {
		t.Fatal("enter returned empty operation_id")
	}
	if !*st.RefusingNewConfig {
		t.Fatal("refusing_new_config = false while in maintenance")
	}
	// The management-plane state must never claim a data-path drain.
	if *st.RefusingNewInference {
		t.Fatal("refusing_new_inference = true; data-path refusal is not implemented by this state")
	}
	if *st.InFlightStreams != 7 {
		t.Fatalf("in_flight_streams = %d, want the hook's 7", *st.InFlightStreams)
	}
	if st.DrainTimeoutSeconds != 300 {
		t.Fatalf("drain_timeout_seconds = %d, want 300", st.DrainTimeoutSeconds)
	}
	if !*st.Cancellable {
		t.Fatal("cancellable = false; leave must always be possible")
	}
}

func TestMaintenancePutIsIdempotentAndLeaveCarriesReceipt(t *testing.T) {
	withMaintenanceFixture(t, 0)
	first := putMaintenance(t, true, 60)
	repeat := putMaintenance(t, true, 999) // different window must be ignored
	if repeat.OperationID != first.OperationID {
		t.Fatalf("repeat enter changed operation_id: %q -> %q", first.OperationID, repeat.OperationID)
	}
	if repeat.DrainTimeoutSeconds != 60 {
		t.Fatalf("repeat enter rewrote drain window to %d, want original 60", repeat.DrainTimeoutSeconds)
	}
	left := putMaintenance(t, false, 0)
	if *left.State != "active" {
		t.Fatalf("state after leave = %q, want active", *left.State)
	}
	if left.OperationID != first.OperationID {
		t.Fatalf("leave receipt = %q, want ended episode %q", left.OperationID, first.OperationID)
	}
	again := putMaintenance(t, false, 0)
	if again.OperationID != "" {
		t.Fatalf("no-op leave carried operation_id %q, want empty", again.OperationID)
	}
	if st := getMaintenance(t); *st.State != "active" || st.OperationID != "" {
		t.Fatalf("GET after leave = state %q op %q, want active/empty", *st.State, st.OperationID)
	}
}

// The middleware's operator gate: mutating config calls are refused while
// maintenance holds, with the exact exemptions the contract promises --
// reads, the maintenance endpoint itself, and the configuration-lifecycle
// operations maintenance exists to make safe.
func TestMaintenanceFreezeMiddlewareGate(t *testing.T) {
	withMaintenanceFixture(t, 0)
	snapshot.MarkBootConfigSettled() // get past the boot gate (one-way, harmless to other tests)

	reached := false
	h := SnapshotFreezeMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	probe := func(method, path string) (int, string, bool) {
		reached = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code, rec.Body.String(), reached
	}

	// Red twin first: without maintenance the mutating call passes.
	if code, _, ok := probe(http.MethodPost, "/netlox/v1/config/loadbalancer"); code != 200 || !ok {
		t.Fatalf("pre-maintenance POST blocked (code %d, reached %v) - gate misfires when inactive", code, ok)
	}

	maintenance.Enter(0)

	code, body, ok := probe(http.MethodPost, "/netlox/v1/config/loadbalancer")
	if code != http.StatusServiceUnavailable || ok {
		t.Fatalf("POST during maintenance: code %d reached %v, want 503/blocked", code, ok)
	}
	if !strings.Contains(body, "operator maintenance is active") {
		t.Fatalf("503 body %q does not name the operator gate", body)
	}
	for _, exempt := range []struct{ method, path string }{
		{http.MethodGet, "/netlox/v1/config/loadbalancer/all"},
		{http.MethodPut, "/netlox/v1/maintenance"},
		{http.MethodPost, "/netlox/v1/config/persist"},
		{http.MethodPost, "/netlox/v1/config/snapshot"},
		{http.MethodPost, "/netlox/v1/config/restore"},
	} {
		if code, _, ok := probe(exempt.method, exempt.path); code != 200 || !ok {
			t.Fatalf("%s %s blocked during maintenance (code %d), want exempted", exempt.method, exempt.path, code)
		}
	}

	maintenance.Leave()
	if code, _, ok := probe(http.MethodPost, "/netlox/v1/config/loadbalancer"); code != 200 || !ok {
		t.Fatalf("POST after leave still blocked (code %d, reached %v)", code, ok)
	}
}
