/*
 * Copyright (c) 2025 LoxiLB Authors
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

// Deprecated /config/export and /config/import aliases (task G-4, design
// docs/SNAPSHOT-DESIGN.md §5.1/§5.2): both remain for one release, emit
// Deprecation + Link headers pointing at their successors, and run on the
// snapshot engine — the legacy hand-rolled dump/delete/add pipeline
// (DumpConfiguration / DeleteAllConfiguration / AddImportConfiguration) is
// gone, replaced by snapshot.Capture and the staged restore engine.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
	tk "github.com/loxilb-io/loxilib"
)

// DumpFile is the legacy /config/export document shape, kept only so
// /config/import can keep accepting old files during the deprecation
// window (converted via legacyDumpToSnapshot).
type DumpFile struct {
	Lbrule    []cmn.LbRuleMod   `json:"loadbalancer,omitempty"`
	Cluster   []cmn.HASMod      `json:"cluster,omitempty"`
	Endpoint  []cmn.EndPointMod `json:"endpoint,omitempty"`
	Firewall  []cmn.FwRuleMod   `json:"firewall,omitempty"`
	Mirror    []cmn.MirrMod     `json:"mirror,omitempty"`
	Policy    []cmn.PolMod      `json:"policy,omitempty"`
	Timestamp string            `json:"timestamp"`
	Version   string            `json:"version"`
}

// legacyDumpDomains is the components selection matching what a legacy
// DumpFile can carry (cluster is deliberately absent: it was never deleted
// by import and is an excluded snapshot domain).
var legacyDumpDomains = []string{
	snapshot.DomainEndpoint,
	snapshot.DomainLoadBalancer,
	snapshot.DomainFirewall,
	snapshot.DomainPolicy,
	snapshot.DomainMirror,
}

func setDeprecationHeaders(w http.ResponseWriter, successor string) {
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"successor-version\"", successor))
}

// ConfigGetExport - deprecated alias for GET /config/snapshot (§5.1). Emits
// the new snapshot document (the legacy hand-rolled dump shape is gone) plus
// Deprecation headers. Honors `components`, which the legacy handler
// silently ignored; the legacy-only "cluster" component is dropped from the
// selection (never capturable) rather than rejected.
func ConfigGetExport(params operations.GetConfigExportParams, principal any) middleware.Responder {
	var components []string
	for _, c := range parseComponents(params.Components) {
		if c == "cluster" {
			tk.LogIt(tk.LogWarning, "config/export: legacy component %q is not part of snapshots, skipping\n", c)
			continue
		}
		components = append(components, c)
	}
	if _, err := snapshot.Select(components); err != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    400,
			Message: "Invalid parameters",
			Result:  err.Error(),
		}}
	}

	if !snapshotGate.CompareAndSwap(false, true) {
		return snapshotBusyError()
	}
	defer snapshotGate.Store(false)

	doc, err := snapshot.Capture(ApiHooks, cmn.Version, snapshotHostname(), snapshot.TriggerManual, components)
	if err != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    500,
			Message: "Internal service error",
			Result:  "snapshot capture failed: " + err.Error(),
		}}
	}
	data, err := snapshot.Encode(doc)
	if err != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    500,
			Message: "Internal service error",
			Result:  "snapshot encode failed: " + err.Error(),
		}}
	}

	filename := fmt.Sprintf("loxilb-config-%s.json", time.Now().UTC().Format("20060102-150405"))
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		setDeprecationHeaders(w, "/netlox/v1/config/snapshot")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("X-Snapshot-Checksum", doc.Checksum)
		w.WriteHeader(http.StatusOK)
		if _, werr := w.Write(data); werr != nil {
			tk.LogIt(tk.LogError, "config/export: failed to write response: %v\n", werr)
		}
	})
}

// legacyDumpToSnapshot converts a legacy DumpFile into an encoded snapshot
// document (checksum computed) restorable by the engine. Cluster entries
// are ignored with a warning: the legacy import applied them, but cluster
// state is deliberately outside snapshot scope (§4.1).
func legacyDumpToSnapshot(legacy *DumpFile) ([]byte, error) {
	if len(legacy.Cluster) > 0 {
		tk.LogIt(tk.LogWarning, "config/import: ignoring %d legacy cluster entrie(s): cluster state is not restorable via snapshots\n", len(legacy.Cluster))
	}
	doc := snapshot.NewDocument(cmn.Version, snapshotHostname(), snapshot.TriggerManual)
	// The legacy dump format can only express these five domains, so the
	// converted document declares exactly that coverage: importing it must
	// not wipe domains (sessions, bgp, ipsec, ...) the legacy file could
	// never have carried.
	doc.IncludedDomains = []string{
		snapshot.DomainEndpoint,
		snapshot.DomainLoadBalancer,
		snapshot.DomainFirewall,
		snapshot.DomainPolicy,
		snapshot.DomainMirror,
	}
	doc.Domains.Endpoint = legacy.Endpoint
	doc.Domains.LoadBalancer = legacy.Lbrule
	doc.Domains.Firewall = legacy.Firewall
	doc.Domains.Policy = legacy.Policy
	for _, m := range legacy.Mirror {
		doc.Domains.Mirror = append(doc.Domains.Mirror, cmn.MirrGetMod{
			Ident:  m.Ident,
			Info:   m.Info,
			Target: m.Target,
		})
	}
	return snapshot.Encode(doc)
}

// ConfigPostImport - deprecated alias for POST /config/restore?mode=commit
// (§5.2). Accepts either a new snapshot document or the legacy DumpFile
// shape (converted internally); either way the staged restore engine runs a
// full commit (preserve, wipe, apply, verify, rollback-on-failure) — the
// legacy delete-then-add pipeline that could stop halfway is gone. The
// response is the engine result (§5.2), not the legacy {"result":"Success"}.
func ConfigPostImport(params operations.PostConfigImportParams, principal any) middleware.Responder {
	if params.Configuration == nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    400,
			Message: "Invalid parameters",
			Result:  "no configuration file provided",
		}}
	}
	fileData, err := io.ReadAll(params.Configuration)
	if err != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    400,
			Message: "Invalid parameters",
			Result:  "failed to read configuration file: " + err.Error(),
		}}
	}

	// New-format documents pass through untouched; anything else is
	// treated as a legacy DumpFile and converted.
	var probe struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(fileData, &probe)
	raw := fileData
	components := []string(nil) // new-format: full restore, all domains
	if probe.Kind != snapshot.DocKind {
		var legacy DumpFile
		if err := json.Unmarshal(fileData, &legacy); err != nil {
			return &ErrorResponse{Payload: &models.Error{
				Code:    400,
				Message: "Invalid parameters",
				Result:  "invalid JSON format: " + err.Error(),
			}}
		}
		raw, err = legacyDumpToSnapshot(&legacy)
		if err != nil {
			return &ErrorResponse{Payload: &models.Error{
				Code:    500,
				Message: "Internal service error",
				Result:  "legacy conversion failed: " + err.Error(),
			}}
		}
		// Restrict the restore to the domains a legacy dump can carry so
		// the pre-apply wipe does not touch bgp/ipsec/etc. state the old
		// import never managed.
		components = append([]string(nil), legacyDumpDomains...)
	}

	if !snapshotGate.CompareAndSwap(false, true) {
		return snapshotBusyError()
	}
	defer snapshotGate.Store(false)

	engine := snapshot.NewEngine(ApiHooks, cmn.Version, snapshotHostname(), opts.Opts.ConfigPath)
	result, err := engine.Restore(raw, snapshot.RestoreOptions{Mode: snapshot.ModeCommit, Components: components})
	if err != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    500,
			Message: "Internal service error",
			Result:  "restore engine: " + err.Error(),
		}}
	}

	// §6 write-through, same as POST /config/restore.
	if result.Result == snapshot.ResultOK {
		if path, _, _, werr := snapshot.WriteThrough(ApiHooks, cmn.Version, snapshotHostname(), opts.Opts.ConfigPath); werr != nil {
			tk.LogIt(tk.LogError, "config/import: write-through persist failed after commit: %v\n", werr)
			result.Errors = append(result.Errors, "warning: write-through persist failed (import applied but will not survive restart): "+werr.Error())
		} else {
			tk.LogIt(tk.LogInfo, "config/import: write-through persisted to %s\n", path)
		}
	}

	status := http.StatusOK
	switch result.Result {
	case snapshot.ResultRolledBack, snapshot.ResultRollbackFailed:
		status = http.StatusInternalServerError
	case snapshot.ResultOK:
		status = http.StatusOK
	default:
		status = http.StatusBadRequest
	}
	if result.Result == snapshot.ResultRollbackFailed {
		tk.LogIt(tk.LogCritical, "config/import: restore ROLLBACK-FAILED; pre-restore snapshot: %s errors: %v\n",
			result.PreRestoreSnapshotPersisted, result.Errors)
	}

	payload, err := json.Marshal(result)
	if err != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    500,
			Message: "Internal service error",
			Result:  "marshal restore result: " + err.Error(),
		}}
	}
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		setDeprecationHeaders(w, "/netlox/v1/config/restore?mode=commit")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, werr := w.Write(payload); werr != nil {
			tk.LogIt(tk.LogError, "config/import: failed to write response: %v\n", werr)
		}
	})
}
