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
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
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

// snapshotGate serializes snapshot/restore operations against each other,
// and — via SnapshotRestoreActive and the mutation-freeze middleware in
// configure_loxilb_rest_api.go — rejects (503) concurrent mutating API
// calls while a restore holds it. This is the §5.3 "global config write
// lock" at the REST layer: the engine's per-hook calls still take the
// loxinet-internal mh.mtx individually; the gate is what keeps another
// client's POST /config/loadbalancer from interleaving between restore
// stages 4-7. Mutating requests already in flight when the gate is taken
// are not interrupted (they hold mh.mtx per call); the freeze window
// starts with the next routed request.
var snapshotGate atomic.Bool

// SnapshotRestoreActive reports whether a snapshot capture or restore is in
// progress (read by the mutation-freeze middleware).
func SnapshotRestoreActive() bool {
	return snapshotGate.Load()
}

// SnapshotFreezeMiddleware rejects mutating API calls with 503 (+Retry-After)
// while a snapshot/restore holds the gate, so restore stages 4-7 run against
// a frozen config (§5.3). Reads pass through; the snapshot/restore endpoints
// themselves pass through to get the gate's own 409 instead.
//
// It also holds mutating calls until the BOOT config replay has settled:
// the API server starts serving before the boot restore runs, and a write
// landing mid-restore both races the restore (it can fail on state it did
// not create and roll back the whole boot config) and, via auto-persist,
// can overwrite snapshot.json with that half-applied state. No path is
// exempt during the boot window -- a restore/persist racing boot is
// exactly the interleaving being prevented. Boot replay is seconds-scale
// (worst case ~30s when optional subsystems are slow to start); clients
// retry per Retry-After.
func SnapshotFreezeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !snapshot.BootConfigSettled() {
			w.Header().Set("Retry-After", "5")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":503,"message":"Maintenance mode","result":"configuration writes are rejected until the boot config replay settles"}`))
			return
		}
		if SnapshotRestoreActive() &&
			!strings.HasSuffix(r.URL.Path, "/config/restore") &&
			!strings.HasSuffix(r.URL.Path, "/config/snapshot") &&
			!strings.HasSuffix(r.URL.Path, "/config/persist") {
			w.Header().Set("Retry-After", "5")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":503,"message":"Maintenance mode","result":"configuration is frozen while a snapshot restore is in progress"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func snapshotBusyError() *ErrorResponse {
	return &ErrorResponse{Payload: &models.Error{
		Code:    409,
		Message: "Resource conflict",
		Result:  "another snapshot or restore operation is in progress",
	}}
}

// parseComponents splits a `components` query value ("lb,firewall") into
// the registry's selection slice; nil (all domains) for empty/absent.
func parseComponents(raw *string) []string {
	if raw == nil {
		return nil
	}
	var out []string
	for _, c := range strings.Split(*raw, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

func snapshotHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// ConfigGetSnapshot implements GET /config/snapshot (§5.1): a consistent,
// checksummed, versioned snapshot document of the selected (default: all)
// v1 domains, honoring `components` — unlike the deprecated /config/export
// which ignored it.
func ConfigGetSnapshot(params operations.GetConfigSnapshotParams, principal any) middleware.Responder {
	components := parseComponents(params.Components)
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

	filename := fmt.Sprintf("loxilb-snapshot-%s.json", time.Now().UTC().Format("20060102-150405"))
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("X-Snapshot-Checksum", doc.Checksum)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(data); err != nil {
			tk.LogIt(tk.LogError, "snapshot: failed to write response: %v\n", err)
		}
	})
}

// ConfigPostRestore implements POST /config/restore (§5.2): the staged
// restore pipeline over the posted snapshot document. mode=dry-run (the
// default) stops after PLAN and mutates nothing; mode=commit applies with
// automatic rollback. The engine Result is returned verbatim as the
// response body in every case that reaches the pipeline.
func ConfigPostRestore(params operations.PostConfigRestoreParams, principal any) middleware.Responder {
	mode := snapshot.ModeDryRun
	if params.Mode != nil {
		switch *params.Mode {
		case string(snapshot.ModeDryRun), "":
			mode = snapshot.ModeDryRun
		case string(snapshot.ModeCommit):
			mode = snapshot.ModeCommit
		default:
			return &ErrorResponse{Payload: &models.Error{
				Code:    400,
				Message: "Invalid parameters",
				Result:  fmt.Sprintf("mode must be %q or %q, got %q", snapshot.ModeDryRun, snapshot.ModeCommit, *params.Mode),
			}}
		}
	}
	if params.Snapshot == nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    400,
			Message: "Invalid parameters",
			Result:  "request body must be a snapshot document",
		}}
	}
	// The generated body param is an untyped JSON value; re-marshal it to
	// raw bytes for the engine's strict decode (DisallowUnknownFields +
	// checksum verify happen there, on the Document type itself).
	raw, err := json.Marshal(params.Snapshot)
	if err != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    400,
			Message: "Invalid parameters",
			Result:  "unparseable snapshot document: " + err.Error(),
		}}
	}

	if !snapshotGate.CompareAndSwap(false, true) {
		return snapshotBusyError()
	}
	defer snapshotGate.Store(false)

	engine := snapshot.NewEngine(ApiHooks, cmn.Version, snapshotHostname(), opts.Opts.ConfigPath)
	result, err := engine.Restore(raw, snapshot.RestoreOptions{Mode: mode})
	if err != nil {
		// Engine-level precondition failure (not a document/apply problem).
		return &ErrorResponse{Payload: &models.Error{
			Code:    500,
			Message: "Internal service error",
			Result:  "restore engine: " + err.Error(),
		}}
	}

	// §6 write-through: a committed restore must survive a daemon restart,
	// so persist the (post-commit) live config to {ConfigPath}/snapshot.json.
	// A persist failure does not undo the applied restore -- report it in
	// the errors array (result stays "ok") so the caller knows restart
	// survival is NOT guaranteed until a later persist succeeds.
	if mode == snapshot.ModeCommit && result.Result == snapshot.ResultOK {
		if path, _, werr := snapshot.WriteThrough(ApiHooks, cmn.Version, snapshotHostname(), opts.Opts.ConfigPath); werr != nil {
			tk.LogIt(tk.LogError, "snapshot: write-through persist failed after commit: %v\n", werr)
			result.Errors = append(result.Errors, "warning: write-through persist failed (restore applied but will not survive restart): "+werr.Error())
		} else {
			tk.LogIt(tk.LogInfo, "snapshot: write-through persisted to %s\n", path)
		}
	}

	status := http.StatusOK
	switch result.Result {
	case snapshot.ResultRolledBack, snapshot.ResultRollbackFailed:
		// Commit failed; live config was rolled back (or worse). §5.3.
		status = http.StatusInternalServerError
	case snapshot.ResultOK:
		status = http.StatusOK
	default:
		// Pipeline stopped before APPLY (parse/validate/plan/preserve
		// failure): nothing was mutated, the document is at fault.
		status = http.StatusBadRequest
	}
	if result.Result == snapshot.ResultRollbackFailed {
		tk.LogIt(tk.LogCritical, "snapshot restore ROLLBACK-FAILED; pre-restore snapshot: %s errors: %v\n",
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, werr := w.Write(payload); werr != nil {
			tk.LogIt(tk.LogError, "restore: failed to write response: %v\n", werr)
		}
	})
}

// ConfigPostPersist implements POST /config/persist (§6.1 rule 1): the
// gateway dumps its own running config to {ConfigPath}/snapshot.json --
// "save" as an API, available to every channel (UI, OAM, loxicmd --api).
// The gateway is the single writer of canonical persisted config.
func ConfigPostPersist(params operations.PostConfigPersistParams, principal any) middleware.Responder {
	if !snapshotGate.CompareAndSwap(false, true) {
		return snapshotBusyError()
	}
	defer snapshotGate.Store(false)

	path, sum, err := snapshot.WriteThrough(ApiHooks, cmn.Version, snapshotHostname(), opts.Opts.ConfigPath)
	if err != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    500,
			Message: "Internal service error",
			Result:  "persist failed: " + err.Error(),
		}}
	}
	tk.LogIt(tk.LogInfo, "config/persist: running config persisted to %s\n", path)

	payload, merr := json.Marshal(map[string]string{"result": "ok", "path": path, "checksum": sum})
	if merr != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    500,
			Message: "Internal service error",
			Result:  "marshal persist result: " + merr.Error(),
		}}
	}
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, werr := w.Write(payload); werr != nil {
			tk.LogIt(tk.LogError, "persist: failed to write response: %v\n", werr)
		}
	})
}

// ---------------------------------------------------------------------
// §6.1 rule 2: debounced auto-persist. Every successful mutating config
// API call kicks a debouncer; one quiet period after the last call in a
// burst, the running config is written through to snapshot.json. This
// closes the pre-existing hole where UI/OAM-made config silently died on
// daemon restart unless someone remembered to run loxicmd save.
// ---------------------------------------------------------------------

var autoPersist *snapshot.AutoPersister

// InitAutoPersist starts the auto-persist debouncer unless
// --config-auto-persist=off. Called once from configureAPI.
func InitAutoPersist() {
	if strings.EqualFold(opts.Opts.ConfigAutoPersist, "off") {
		tk.LogIt(tk.LogInfo, "auto-persist: disabled (--config-auto-persist=off)\n")
		return
	}
	autoPersist = snapshot.NewAutoPersister(snapshot.AutoPersistQuiet, autoPersistFire)
	tk.LogIt(tk.LogInfo, "auto-persist: enabled (quiet period %s, target %s/%s)\n",
		snapshot.AutoPersistQuiet, opts.Opts.ConfigPath, snapshot.PersistFileName)
}

// autoPersistFire is the debouncer callback: write through unless a
// snapshot/restore holds the gate, in which case retry a quiet period
// later (a restore commit does its own write-through anyway). It also
// refuses to write before the boot config replay settles -- a persist in
// that window would capture a partially-replayed (or, after a failed boot
// restore, empty) state over snapshot.json, turning a transient boot
// problem into durable config loss. The freeze middleware already rejects
// the mutating calls that kick the debouncer during boot, so this is a
// second, independent layer.
func autoPersistFire() {
	if !snapshot.BootConfigSettled() {
		autoPersist.Kick()
		return
	}
	if !snapshotGate.CompareAndSwap(false, true) {
		autoPersist.Kick()
		return
	}
	defer snapshotGate.Store(false)
	if path, _, err := snapshot.WriteThrough(ApiHooks, cmn.Version, snapshotHostname(), opts.Opts.ConfigPath); err != nil {
		tk.LogIt(tk.LogError, "auto-persist: write-through failed: %v\n", err)
	} else {
		tk.LogIt(tk.LogDebug, "auto-persist: running config persisted to %s\n", path)
	}
}

// autoPersistEligible reports whether a request is a mutating config call
// whose success should kick the debouncer. Snapshot-family endpoints are
// excluded: persist IS the write, and restore/import write through on
// commit themselves.
func autoPersistEligible(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	p := r.URL.Path
	if !strings.Contains(p, "/config/") {
		return false
	}
	for _, skip := range []string{"/config/persist", "/config/restore", "/config/import", "/config/snapshot", "/config/export"} {
		if strings.HasSuffix(p, skip) {
			return false
		}
	}
	return true
}

// statusRecorder captures the response status so the middleware only kicks
// on 2xx (a rejected mutation changed nothing worth persisting).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// AutoPersistMiddleware kicks the auto-persist debouncer after every
// successful mutating config API call (wired in setupMiddlewares next to
// the snapshot freeze). It also records the mutation for the config-dirty
// gauge — including when auto-persist is disabled, where the gauge staying
// 1 until a manual persist is exactly the operational signal.
func AutoPersistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !autoPersistEligible(r) {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status >= 200 && rec.status < 300 {
			snapshot.MarkConfigMutated()
			if autoPersist != nil {
				autoPersist.Kick()
			}
		}
	})
}
