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
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/loxilb-io/loxilb/api/models"
	prom "github.com/loxilb-io/loxilb/api/prometheus"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/maintenance"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
	tk "github.com/loxilb-io/loxilib"
)

// processStart approximates the process start: this package initializes
// while the gateway boots, before the API listener accepts anything, so
// uptime measured from here is the API layer's honest lifetime.
var processStart = time.Now()

// apiSpecIdentity is the served contract's identity (base path plus spec
// version), pushed by the restapi wiring from the embedded spec at
// configure time - never hand-maintained here, so it cannot drift from
// what is actually served.
var apiSpecIdentity string

// SetAPISpecIdentity records the served API contract identity. Called
// once from the restapi configuration with values read out of the
// embedded spec.
func SetAPISpecIdentity(basePath, specVersion string) {
	apiSpecIdentity = basePath + " " + specVersion
}

// depLatencyClassSlow is the fast/slow boundary for dependency probes.
const depLatencyClassSlow = 250 * time.Millisecond

// probeDependencies runs the live recovery-dependency probes with timing
// and returns the diagnostics entries plus the failure strings the
// readiness computation wants. Identity beyond the type name (IDs,
// digests) is deliberately not copied onto this surface - reachability
// and latency class only.
func probeDependencies() ([]*models.DependencyDiagnostic, []string) {
	deps, err := ApiHooks.NetRecoveryDepsGet()
	if err != nil {
		return nil, []string{"dependency identities unavailable: " + err.Error()}
	}
	var out []*models.DependencyDiagnostic
	var failures []string
	for _, d := range deps {
		start := time.Now()
		perr := ApiHooks.NetRecoveryDepReady(d.Type)
		elapsed := time.Since(start)

		depType, required := d.Type, d.Required
		status, latency := snapshot.DepStatusReady, "fast"
		if perr != nil {
			status, latency = snapshot.DepStatusFailed, "failed"
			if required {
				failures = append(failures, "dependency "+d.Type+": "+perr.Error())
			}
		} else if elapsed >= depLatencyClassSlow {
			latency = "slow"
		}
		out = append(out, &models.DependencyDiagnostic{
			Type:         &depType,
			Required:     &required,
			Status:       &status,
			LatencyClass: &latency,
		})
	}
	return out, failures
}

// ConfigGetDiagnostics implements GET /diagnostics: the secret-safe,
// allowlist-only diagnostic assembly. Every field is drawn from state the
// gateway already maintains for another purpose (version identity, the
// readiness sources, the maintenance state machine, the metrics
// collector's conntrack snapshot, netlink attachment truth) - this
// handler assembles, it never collects anything new or unbounded.
func ConfigGetDiagnostics(params operations.GetDiagnosticsParams, principal any) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api called. url : %s\n", params.HTTPRequest.URL)

	boot := snapshot.BootRestoreStateGet()
	lastRestore := snapshot.LastRestore()
	autoPersistState := snapshot.AutoPersistStateGet()
	depDiags, depFailures := probeDependencies()
	reasons := snapshot.ReadinessReasons(snapshot.BootConfigSettled(), boot, lastRestore, autoPersistState, depFailures)

	ready := len(reasons) == 0
	uptime := int64(time.Since(processStart) / time.Second)
	maintState := string(maintenance.Get().State)
	version := cmn.Version
	bootFound, bootSucceeded := boot.SnapshotFound, boot.Succeeded
	bootLegacy, bootDegraded := boot.LegacyFallback, boot.Degraded

	payload := &models.DiagnosticsStatus{
		Version:          &version,
		BuildInfo:        cmn.BuildInfo,
		Product:          cmn.Product,
		APIVersion:       apiSpecIdentity,
		UptimeSeconds:    &uptime,
		Ready:            &ready,
		ReadyReasons:     reasons,
		MaintenanceState: &maintState,
		ExternalDependencies: depDiags,
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
		LastPersist: opRecordModel(snapshot.LastPersist()),
		LastRestore: opRecordModel(lastRestore),
	}
	if autoPersistState.ConsecutiveFailures > 0 {
		payload.AutoPersist = &models.AutoPersistStatus{
			ConsecutiveFailures: int64(autoPersistState.ConsecutiveFailures),
			LastError:           autoPersistState.LastError,
			LastAttempt:         strfmt.DateTime(autoPersistState.LastAttempt),
		}
	}
	if atts, aerr := ApiHooks.NetEbpfAttachmentGet(); aerr != nil {
		tk.LogIt(tk.LogWarning, "diagnostics: ebpf attachment walk failed: %v\n", aerr)
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
	// Conntrack is the one datapath table with both a cached count and a
	// recorded capacity today; a capacity of 0 means this build carries
	// no datapath table and the entry would be noise.
	if capacity := prom.ConntrackCapacity(); capacity > 0 {
		name, count := "conntrack", prom.ConntrackCachedCount()
		payload.Maps = append(payload.Maps, &models.MapUtilization{
			Name:     &name,
			Count:    &count,
			Capacity: &capacity,
		})
	}
	return operations.NewGetDiagnosticsOK().WithPayload(payload)
}
