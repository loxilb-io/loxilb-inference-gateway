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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/maintenance"
)

// sensitiveDSN is planted into the stub's dependency identity fields; the
// diagnostics wire must never carry it.
const sensitiveDSN = "postgres://svc:hunter2@10.0.0.9:5432/keys"

type stubDiagnosticsHook struct {
	cmn.NetHookInterface
	deps        []cmn.RecoveryDependency
	failDep     string
	attachments []cmn.EbpfAttachmentDump
}

func (s *stubDiagnosticsHook) NetRecoveryDepsGet() ([]cmn.RecoveryDependency, error) {
	return s.deps, nil
}

func (s *stubDiagnosticsHook) NetRecoveryDepReady(depType string) error {
	if depType == s.failDep {
		return errors.New("connection refused")
	}
	return nil
}

func (s *stubDiagnosticsHook) NetEbpfAttachmentGet() ([]cmn.EbpfAttachmentDump, error) {
	return s.attachments, nil
}

func (s *stubDiagnosticsHook) NetAiInFlightStreamsGet() int64 { return 0 }

func getDiagnostics(t *testing.T) *models.DiagnosticsStatus {
	t.Helper()
	params := operations.GetDiagnosticsParams{
		HTTPRequest: httptest.NewRequest(http.MethodGet, "/netlox/v1/diagnostics", nil),
	}
	resp := ConfigGetDiagnostics(params, nil)
	ok, isOK := resp.(*operations.GetDiagnosticsOK)
	if !isOK {
		t.Fatalf("GET diagnostics returned %T, want *GetDiagnosticsOK", resp)
	}
	return ok.Payload
}

func withDiagnosticsFixture(t *testing.T, hook *stubDiagnosticsHook) {
	t.Helper()
	prev := ApiHooks
	ApiHooks = hook
	t.Cleanup(func() {
		ApiHooks = prev
		maintenance.Leave()
	})
}

func TestDiagnosticsAssemblesAllowlist(t *testing.T) {
	withDiagnosticsFixture(t, &stubDiagnosticsHook{
		deps: []cmn.RecoveryDependency{
			{Type: "keystore", ID: sensitiveDSN, Digest: "sha256:aabb", Required: true},
			{Type: "certstore", ID: sensitiveDSN, Required: false},
		},
		failDep: "certstore",
		attachments: []cmn.EbpfAttachmentDump{
			{Name: "eno1", Mode: "tc", Attached: true},
			{Name: "eno2", Mode: "tc", Attached: false},
		},
	})
	st := getDiagnostics(t)

	if *st.Version == "" && st.BuildInfo == "" {
		t.Fatal("diagnostics carries no build identity at all")
	}
	if *st.UptimeSeconds < 0 {
		t.Fatalf("uptime_seconds = %d, want >= 0", *st.UptimeSeconds)
	}
	if *st.MaintenanceState != "active" {
		t.Fatalf("maintenance_state = %q, want active", *st.MaintenanceState)
	}
	if len(st.EbpfAttachments) != 2 {
		t.Fatalf("ebpf_attachments has %d entries, want the stub's 2", len(st.EbpfAttachments))
	}
	if *st.EbpfAttachments[1].Attached {
		t.Fatal("the detached interface reads attached=true")
	}
	if len(st.ExternalDependencies) != 2 {
		t.Fatalf("external_dependencies has %d entries, want 2", len(st.ExternalDependencies))
	}
	for _, d := range st.ExternalDependencies {
		switch *d.Type {
		case "keystore":
			if *d.Status != "ready" || *d.LatencyClass == "failed" {
				t.Fatalf("healthy dependency reported %s/%s", *d.Status, *d.LatencyClass)
			}
		case "certstore":
			if *d.Status != "failed" || *d.LatencyClass != "failed" {
				t.Fatalf("failing dependency reported %s/%s, want failed/failed", *d.Status, *d.LatencyClass)
			}
		}
	}
}

// The secret-safety property is the point of the endpoint: identity beyond
// the type name - IDs, digests, connection strings - must never appear on
// the diagnostics wire, even though the hook hands them to the handler.
func TestDiagnosticsNeverLeaksDependencyIdentity(t *testing.T) {
	withDiagnosticsFixture(t, &stubDiagnosticsHook{
		deps: []cmn.RecoveryDependency{
			{Type: "keystore", ID: sensitiveDSN, Digest: "sha256:deadbeef", Required: true},
		},
	})
	st := getDiagnostics(t)
	wire, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("payload does not marshal: %v", err)
	}
	for _, secret := range []string{sensitiveDSN, "hunter2", "sha256:deadbeef"} {
		if strings.Contains(string(wire), secret) {
			t.Fatalf("diagnostics wire leaks %q:\n%s", secret, wire)
		}
	}
}

func TestDiagnosticsReflectsMaintenanceAndReadiness(t *testing.T) {
	withDiagnosticsFixture(t, &stubDiagnosticsHook{
		deps:    []cmn.RecoveryDependency{{Type: "keystore", Required: true}},
		failDep: "keystore",
	})
	maintenance.Enter(0)
	st := getDiagnostics(t)
	if *st.MaintenanceState != "maintenance" {
		t.Fatalf("maintenance_state = %q, want maintenance", *st.MaintenanceState)
	}
	// A failing REQUIRED dependency must surface in the readiness verdict
	// exactly as /status/ready would report it.
	if *st.Ready {
		t.Fatal("ready = true while a required dependency is down")
	}
	found := false
	for _, r := range st.ReadyReasons {
		if strings.Contains(r, "keystore") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ready_reasons %v does not name the failing dependency", st.ReadyReasons)
	}
}

// The formalized status bodies must keep the exact wire shape the inline
// schemas produced - the field name is the compatibility contract.
func TestFormalizedStatusBodiesKeepWireShape(t *testing.T) {
	pb, err := json.Marshal(&models.ProcessStatus{ProcessAttr: []*models.ProcessInfoEntry{}})
	if err != nil || !strings.Contains(string(pb), `"processAttr"`) {
		t.Fatalf("ProcessStatus wire = %s (err %v), want a processAttr key", pb, err)
	}
	fb, err := json.Marshal(&models.FilesystemStatus{FilesystemAttr: []*models.FileSystemInfoEntry{}})
	if err != nil || !strings.Contains(string(fb), `"filesystemAttr"`) {
		t.Fatalf("FilesystemStatus wire = %s (err %v), want a filesystemAttr key", fb, err)
	}
}
