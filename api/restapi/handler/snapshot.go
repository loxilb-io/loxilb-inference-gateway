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
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	"github.com/loxilb-io/loxilb/pkg/maintenance"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
	tk "github.com/loxilb-io/loxilib"
)

// snapshotGate serializes the snapshot-family operations (capture, export,
// persist, auto-persist, restore, import) against each other: a second one
// arriving while the first runs is answered 409 rather than interleaved.
// It says nothing about ordinary mutating config calls; those are governed
// by the two mechanisms below, which differ in how long they hold writers
// and therefore in what a writer sees.
var snapshotGate atomic.Bool

// restoreFreeze is set for the duration of a restore or import pipeline.
// While it is set the mutation-freeze middleware in
// configure_loxilb_rest_api.go answers mutating config calls with 503 and
// Retry-After. This is the §5.3 "global config write lock" at the REST
// layer: the engine's per-hook calls still take the loxinet-internal
// mh.mtx individually; the freeze is what keeps another client's POST
// /config/loadbalancer from interleaving between restore stages 4-7. A
// restore takes seconds, so refusing with a retry hint is the right
// contract for it: a write that waited the pipeline out could fail on
// state it did not create and roll the whole restore back.
var restoreFreeze atomic.Bool

// configWrites keeps a config capture and the mutating config calls from
// running at the same time. Mutating requests hold it shared for the
// handler's duration (taken in the middleware); a capture -- snapshot,
// export, persist, and the auto-persist write-through -- holds it
// exclusively around the capture itself. A capture is milliseconds, so a
// writer that arrives during one simply waits for it instead of being
// refused: the auto-persist write-through fires one quiet period after
// every accepted write, and a client that refused-on-503 there would see
// its own earlier write turn its next write into a spurious "restore in
// progress" at a fixed offset it never asked for. Exclusive hold also
// gives the capture what the serialization alone did not: the running
// config it encodes is one no write is changing under it.
var configWrites sync.RWMutex

// SnapshotRestoreActive reports whether a restore or import pipeline is in
// progress (read by the mutation-freeze middleware).
func SnapshotRestoreActive() bool {
	return restoreFreeze.Load()
}

// beginRestoreFreeze raises the restore freeze and waits for the mutating
// calls already past the middleware to finish, so the pipeline starts from
// a config no write is still changing. New mutating calls are refused from
// the moment the flag is set, and the middleware re-checks the flag after
// it acquires its shared hold, so a writer that slipped past the check
// before the flag went up is refused rather than admitted behind the
// barrier. The returned func lowers the freeze; the caller defers it.
func beginRestoreFreeze() func() {
	restoreFreeze.Store(true)
	configWrites.Lock()
	configWrites.Unlock()
	return func() { restoreFreeze.Store(false) }
}

// captureWithConfigWritesHeld runs one capture with mutating config calls
// held off for its duration. Keep the function short: everything a writer
// waits on is inside it, so encoding, dependency probes and the response
// belong outside.
func captureWithConfigWritesHeld[T any](capture func() (T, error)) (T, error) {
	configWrites.Lock()
	defer configWrites.Unlock()
	return capture()
}

// writeThroughWithConfigWritesHeld is the write-through persist under the
// same hold: the capture and the file publish together, so the document on
// disk is the running config as of one instant with no write in between.
func writeThroughWithConfigWritesHeld() (string, *snapshot.Document, error) {
	configWrites.Lock()
	defer configWrites.Unlock()
	return snapshot.WriteThrough(ApiHooks, cmn.Version, snapshotHostname(), opts.Opts.ConfigPath)
}

// SnapshotFreezeMiddleware rejects mutating API calls with 503 (+Retry-After)
// while a restore or import pipeline runs, so restore stages 4-7 run against
// a frozen config (§5.3). Reads pass through; the snapshot/restore endpoints
// themselves pass through to get the gate's own 409 instead. Every other
// mutating call holds configWrites shared for its duration, which is what
// lets a capture wait for in-flight writes and hold new ones -- for the
// milliseconds a capture takes -- rather than refuse them. The
// snapshot-family endpoints take that lock themselves and are excluded
// from the shared hold so they cannot deadlock against their own request.
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
		exemptFromRestoreFreeze := strings.HasSuffix(r.URL.Path, "/config/restore") ||
			strings.HasSuffix(r.URL.Path, "/config/snapshot") ||
			strings.HasSuffix(r.URL.Path, "/config/persist")
		if !exemptFromRestoreFreeze &&
			!strings.HasSuffix(r.URL.Path, "/config/import") &&
			!strings.HasSuffix(r.URL.Path, "/config/export") {
			configWrites.RLock()
			defer configWrites.RUnlock()
		}
		// Checked after the shared hold is taken: a restore raises its flag
		// first and then waits for the shared holders to drain, so a call
		// that reaches this line has either finished before the barrier or
		// sees the flag.
		if !exemptFromRestoreFreeze && SnapshotRestoreActive() {
			w.Header().Set("Retry-After", "5")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":503,"message":"Maintenance mode","result":"configuration is frozen while a snapshot restore is in progress"}`))
			return
		}
		// Third, operator-owned gate (PUT /maintenance) -- distinct from
		// the two self-clearing internal freezes above. The exemptions
		// are the configuration-lifecycle operations maintenance exists
		// to make safe, plus the maintenance endpoint itself so the
		// operator can always leave.
		if maintenance.Active() &&
			!strings.HasSuffix(r.URL.Path, "/maintenance") &&
			!strings.HasSuffix(r.URL.Path, "/config/restore") &&
			!strings.HasSuffix(r.URL.Path, "/config/snapshot") &&
			!strings.HasSuffix(r.URL.Path, "/config/persist") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":503,"message":"Maintenance mode","result":"configuration writes are rejected while operator maintenance is active"}`))
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

	doc, err := captureWithConfigWritesHeld(func() (*snapshot.Document, error) {
		return snapshot.Capture(ApiHooks, cmn.Version, snapshotHostname(), snapshot.TriggerManual, components)
	})
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
	defer beginRestoreFreeze()()

	engine := snapshot.NewEngine(ApiHooks, cmn.Version, snapshotHostname(), opts.Opts.ConfigPath)
	restoreOpts := snapshot.RestoreOptions{
		Mode: mode,
		// Selection semantics live in the engine: components intersects
		// the document's included_domains, an uncovered component is
		// refused, and empty means "everything the document covers".
		Components: parseComponents(params.Components),
	}
	result, err := engine.Restore(raw, restoreOpts)
	// The optional subsystems a restore may apply to (IPsec, BGP) finish
	// initializing AFTER the API starts serving and after the boot config
	// replay settles -- so there is a window, measured at 3-4s on the
	// testbed, in which /status/ready answers READY while a commit restore
	// of a document covering those domains fails with "IPsec not
	// initialized". An operator (or an orchestrator gating recovery on
	// readiness) restoring a node right after boot lands in it. The boot
	// replay already rides this window out by retrying; the REST path
	// retries on the same shared rule, for a bounded time, and then fails
	// loudly exactly as before -- a subsystem this gateway genuinely does
	// not run must still refuse the document, just a few seconds later.
	// Retrying is safe because a failed commit rolled the live config back
	// to its pre-restore state; a ROLLBACK-FAILED result is NOT retried,
	// since the node is no longer in a known state.
	const restoreStartupRetries = 8
	for attempt := 1; err == nil && attempt < restoreStartupRetries &&
		mode == snapshot.ModeCommit &&
		result.Result == snapshot.ResultRolledBack &&
		snapshot.SubsystemStartupErrors(result.Errors); attempt++ {
		tk.LogIt(tk.LogWarning, "snapshot: restore attempt %d hit subsystem startup ordering (%v); retrying\n",
			attempt, result.Errors)
		time.Sleep(time.Second)
		result, err = engine.Restore(raw, restoreOpts)
	}
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
	// A persist failure does not undo the applied restore -- the response
	// carries an EXPLICIT degraded marker (persisted=false) plus the
	// failure in the errors array, never a bare "ok": the caller must know
	// restart survival is NOT guaranteed until a later persist succeeds.
	if mode == snapshot.ModeCommit && result.Result == snapshot.ResultOK {
		persisted := false
		if path, pdoc, werr := snapshot.WriteThrough(ApiHooks, cmn.Version, snapshotHostname(), opts.Opts.ConfigPath); werr != nil {
			tk.LogIt(tk.LogError, "snapshot: write-through persist failed after commit: %v\n", werr)
			result.Errors = append(result.Errors, "warning: write-through persist failed (restore applied but will not survive restart): "+werr.Error())
		} else {
			persisted = true
			result.PersistedGeneration = pdoc.Generation
			tk.LogIt(tk.LogInfo, "snapshot: write-through persisted to %s (generation %d)\n", path, pdoc.Generation)
		}
		result.Persisted = &persisted
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

	path, doc, err := writeThroughWithConfigWritesHeld()
	if err != nil {
		return &ErrorResponse{Payload: &models.Error{
			Code:    500,
			Message: "Internal service error",
			Result:  "persist failed: " + err.Error(),
		}}
	}
	tk.LogIt(tk.LogInfo, "config/persist: running config persisted to %s (generation %d)\n", path, doc.Generation)

	// §9 response contract, through the swagger model: the persisted
	// document's identity and coverage, so automation can verify what was
	// saved without re-reading the file.
	return operations.NewPostConfigPersistOK().WithPayload(&models.PersistResult{
		Result:               "ok",
		Path:                 path,
		Checksum:             doc.Checksum,
		SchemaVersion:        doc.SchemaVersion,
		Generation:           doc.Generation,
		IncludedDomains:      doc.IncludedDomains,
		ExcludedDomains:      doc.ExcludedDomains,
		ExternalDependencies: depStatusModels(snapshot.CaptureDependencyStatuses(doc.RecoveryDependencies)),
		Warnings:             []string{},
	})
}

// ConfigGetStatusReady implements GET /status/ready: the configuration
// readiness verdict with its evidence -- the boot replay outcome, LIVE
// external-dependency probes (unlike the restore engine's deliberately
// configured-only checks), and the most recent successful persist/restore
// identities. A not-ready gateway answers 503 with the same body so
// probes and operators read the reasons from either status; a failed boot
// restore is never silently READY.
func ConfigGetStatusReady(params operations.GetStatusReadyParams, principal any) middleware.Responder {
	boot := snapshot.BootRestoreStateGet()

	var depStatuses []*models.ExternalDependencyStatus
	var depFailures []string
	if deps, err := ApiHooks.NetRecoveryDepsGet(); err != nil {
		depFailures = append(depFailures, "dependency identities unavailable: "+err.Error())
	} else {
		for _, d := range deps {
			st := &models.ExternalDependencyStatus{
				Type:       d.Type,
				ID:         d.ID,
				Generation: d.Generation,
				Digest:     d.Digest,
				Required:   d.Required,
				Status:     snapshot.DepStatusReady,
			}
			if perr := ApiHooks.NetRecoveryDepReady(d.Type); perr != nil {
				st.Status = snapshot.DepStatusFailed
				if d.Required {
					depFailures = append(depFailures, fmt.Sprintf("dependency %s: %v", d.Type, perr))
				}
			}
			depStatuses = append(depStatuses, st)
		}
	}

	lastRestore := snapshot.LastRestore()
	autoPersistState := snapshot.AutoPersistStateGet()
	reasons := snapshot.ReadinessReasons(snapshot.BootConfigSettled(), boot, lastRestore, autoPersistState, depFailures)

	ready := len(reasons) == 0
	bootFound, bootSucceeded := boot.SnapshotFound, boot.Succeeded
	bootLegacy, bootDegraded := boot.LegacyFallback, boot.Degraded
	payload := &models.ReadyStatus{
		// Required in the contract (pointer in the generated model): the
		// 503 body must carry an explicit ready=false, never omit it.
		Ready:   &ready,
		Reasons: reasons,
		// Required in the contract (pointers in the generated model) for
		// the same reason `ready` is: a plain bool is omitempty, so the
		// FALSE cases -- no snapshot found, boot did not succeed -- would
		// vanish from the payload, and a missing volume would read
		// exactly like a healthy replay. The empty-boot classification is
		// precisely what an operator needs off this surface.
		Boot: &models.BootStatus{
			Profile:        boot.Profile,
			SnapshotFound:  &bootFound,
			Succeeded:      &bootSucceeded,
			Generation:     boot.Generation,
			QuarantinePath: boot.QuarantinePath,
			LegacyFallback: &bootLegacy,
			Degraded:       &bootDegraded,
			Reasons:        boot.Reasons,
		},
		ExternalDependencies: depStatuses,
		LastPersist:          opRecordModel(snapshot.LastPersist()),
		LastRestore:          opRecordModel(lastRestore),
	}
	// Additive, informational: per-interface eBPF attachment verified
	// against the kernel. Never a readiness reason -- the contract adds
	// evidence to the surface without changing the verdict; a walk
	// failure is logged and the field simply stays absent.
	if atts, aerr := ApiHooks.NetEbpfAttachmentGet(); aerr != nil {
		tk.LogIt(tk.LogWarning, "status/ready: ebpf attachment walk failed: %v\n", aerr)
	} else {
		for _, a := range atts {
			name, mode, attached := a.Name, a.Mode, a.Attached
			payload.EbpfAttachments = append(payload.EbpfAttachments, &models.EbpfAttachmentStatus{
				Name:     &name,
				Mode:     &mode,
				Attached: &attached,
			})
		}
	}
	if autoPersistState.ConsecutiveFailures > 0 {
		payload.AutoPersist = &models.AutoPersistStatus{
			ConsecutiveFailures: int64(autoPersistState.ConsecutiveFailures),
			LastError:           autoPersistState.LastError,
			LastAttempt:         strfmt.DateTime(autoPersistState.LastAttempt),
		}
	}
	if ready {
		return operations.NewGetStatusReadyOK().WithPayload(payload)
	}
	return operations.NewGetStatusReadyServiceUnavailable().WithPayload(payload)
}

// opRecordModel converts a snapshot.OpRecord to its swagger model; nil in,
// nil out (the field is simply absent until the first success).
func opRecordModel(rec *snapshot.OpRecord) *models.ConfigOpRecord {
	if rec == nil {
		return nil
	}
	return &models.ConfigOpRecord{
		Generation: rec.Generation,
		Checksum:   rec.Checksum,
		Mode:       rec.Mode,
		At:         strfmt.DateTime(rec.At),
	}
}

// depStatusModels converts the engine's dependency statuses to the
// generated swagger model entries.
func depStatusModels(statuses []snapshot.DependencyStatus) []*models.ExternalDependencyStatus {
	if len(statuses) == 0 {
		return nil
	}
	out := make([]*models.ExternalDependencyStatus, 0, len(statuses))
	for _, s := range statuses {
		out = append(out, &models.ExternalDependencyStatus{
			Type:       s.Type,
			ID:         s.ID,
			Generation: s.Generation,
			Digest:     s.Digest,
			Required:   s.Required,
			Status:     s.Status,
		})
	}
	return out
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

// autoPersistFire is the debouncer callback: write through unless another
// snapshot-family operation holds the gate, in which case retry a quiet
// period later (a restore commit does its own write-through anyway).
// Mutating calls that arrive during the write-through wait for it rather
// than being refused; see configWrites. It also
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
	if path, _, err := writeThroughWithConfigWritesHeld(); err != nil {
		// Loud, bounded, surfaced: the failure streak feeds the metrics
		// and the readiness surface (config changes not reaching disk
		// must never be a log-line-only signal), and the debouncer
		// re-kicks itself only within the retry budget -- after that it
		// waits for the next config mutation instead of burning a retry
		// every quiet period against a permanently failing capture.
		tk.LogIt(tk.LogError, "auto-persist: write-through failed: %v\n", err)
		if snapshot.RecordAutoPersistFailure(err) {
			autoPersist.Kick()
		} else {
			tk.LogIt(tk.LogError, "auto-persist: retry budget exhausted; surfaced as not-ready, next config change retries\n")
		}
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
