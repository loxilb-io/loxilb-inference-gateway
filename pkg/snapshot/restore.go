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

// This file (restore.go) covers task G-2: the 7-stage restore engine
// described in docs/SNAPSHOT-DESIGN.md §5.3, built on top of G-1's document
// types/codec (doc.go, codec.go, migrate.go) and the domain registry
// (registry.go), and G-6's wipe primitive (wipe.go).
package snapshot

import (
	"bytes"
	"fmt"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// ---------------------------------------------------------------------
// Public types (§5.2 response shape, §5.3 options)
// ---------------------------------------------------------------------

// RestoreMode selects dry-run (validate + plan only) vs commit (actually
// mutate) behavior, per §5.1's `mode=dry-run|commit` query parameter. The
// zero value behaves as ModeDryRun -- §5.2: "default dry-run -- commit must
// be explicit".
type RestoreMode string

const (
	ModeDryRun RestoreMode = "dry-run"
	ModeCommit RestoreMode = "commit"
)

// Result.Result values, spelled exactly as §5.2 specifies.
const (
	ResultOK             = "ok"
	ResultRolledBack     = "rolled-back"
	ResultRollbackFailed = "ROLLBACK-FAILED"
)

// RestoreOptions configures one Restore call.
type RestoreOptions struct {
	// Mode selects dry-run vs commit (ignored, see Boot, when Boot is set).
	Mode RestoreMode
	// Components filters which domains participate, exactly like the
	// `components` REST query parameter (task G-3) and Select (registry.go).
	// Nil/empty selects every v1 domain.
	Components []string
	// Boot selects the §6.2 boot-time variant: applies doc with NO
	// pre-restore capture and NO pre-apply wipe, because the datapath is
	// empty at boot (there is nothing live to preserve or delete). Mode is
	// ignored when Boot is set -- a boot restore always runs the
	// apply/verify/commit-or-rollback stages. Used by the future G-5 boot
	// loader (nlp.go); wired here now per task G-2's instructions so G-5
	// needs no engine changes later.
	Boot bool
}

func (o RestoreOptions) modeString() string {
	if o.Boot {
		return "boot"
	}
	if o.Mode == ModeCommit {
		return string(ModeCommit)
	}
	return string(ModeDryRun)
}

func (o RestoreOptions) isDryRun() bool {
	return !o.Boot && o.Mode != ModeCommit
}

// PlanItem is one row of the §5.2 `plan` array: how many live items this
// domain currently has (to be deleted) and how many the incoming document
// carries (to be applied).
type PlanItem struct {
	Domain   string `json:"domain"`
	ToDelete int    `json:"to_delete"`
	ToApply  int    `json:"to_apply"`
}

// Result is the §5.2 restore response shape, returned for both dry-run and
// commit calls (and, internally, for the §6.2 boot variant).
type Result struct {
	Mode                   string     `json:"mode"`
	Compatible             bool       `json:"compatible"`
	SchemaVersion          string     `json:"schema_version"`
	SnapshotGatewayVersion string     `json:"snapshot_gateway_version"`
	CurrentGatewayVersion  string     `json:"current_gateway_version"`
	Plan                   []PlanItem `json:"plan"`
	// Errors holds validation errors (dry-run/VALIDATE failures) or apply
	///verify/rollback errors (commit), as human-readable strings -- this is
	// a REST response payload (§5.2), not a Go error chain.
	Errors []string `json:"errors"`
	// Result is one of ResultOK/ResultRolledBack/ResultRollbackFailed, or
	// "" if the pipeline never reached APPLY (e.g. PARSE/VALIDATE failure,
	// or a successful dry-run/PLAN-only call -- see stage gating below: a
	// dry-run that passes VALIDATE+PLAN reports ResultOK since nothing was
	// left inconsistent; a dry-run that fails VALIDATE reports "" with
	// Errors populated).
	Result string `json:"result,omitempty"`
	// SnapshotGeneration is the restored document's lineage generation
	// (schema 1.5+; zero/absent for older documents and bare captures).
	// The boot loader records it as the applied boot generation.
	SnapshotGeneration uint64 `json:"snapshot_generation,omitempty"`
	// Warnings reports non-fatal anomalies the pipeline tolerated -- today,
	// document items skipped during a boot apply because a byte-identical
	// item already existed (a duplicate entry inside the document). Kept
	// separate from Errors: warnings never change Result or trigger
	// rollback, and callers that pattern-match Errors (e.g. the boot
	// loader's subsystem-startup retry check) must not see them.
	Warnings []string `json:"warnings,omitempty"`
	// PreRestoreSnapshotPersisted is the on-disk path of the PRESERVE-stage
	// snapshot (§5.3 step 4), empty for dry-run, failed-before-PRESERVE, and
	// Boot (which never captures one) cases.
	PreRestoreSnapshotPersisted string `json:"pre_restore_snapshot_persisted,omitempty"`
	// ExternalDependencies reports the document's recovery_dependencies
	// manifest with this restore's per-entry disposition (verified /
	// warning / failed / declared -- see depstatus.go). Populated by the
	// VERIFY-DEPENDENCIES stage; empty for documents without a manifest
	// and for pipelines that stop before VALIDATE completes.
	ExternalDependencies []DependencyStatus `json:"external_dependencies,omitempty"`
	// Persisted is the §6 write-through disposition, set by the REST
	// layer (the engine does not persist): true when the committed state
	// reached snapshot.json, false when the restore applied but the
	// write-through FAILED -- the applied state will not survive a restart
	// until a later persist succeeds, so a result carrying persisted=false
	// is explicitly degraded, never a bare "ok" (the failure detail is
	// appended to Errors). nil (absent) for dry-run and for pipelines that
	// never reached a successful commit.
	Persisted *bool `json:"persisted,omitempty"`
	// PersistedGeneration is the lineage generation the write-through
	// stamped (set with Persisted=true only).
	PersistedGeneration uint64 `json:"persisted_generation,omitempty"`
}

// Clock lets tests control "now" (used for the pre-restore file's
// timestamp); defaults to time.Now.
type Clock func() time.Time

// Engine is the restore pipeline's dependency-injected entrypoint. Every
// external dependency (hooks, clock, disk paths, version strings) is a
// field so the whole pipeline is unit-testable against mockHooks without
// touching pkg/loxinet or the filesystem's real clock.
type Engine struct {
	// Hooks is the same Hooks interface the domain registry (registry.go)
	// runs against; production callers (task G-3) pass their existing
	// cmn.NetHookInterface implementation straight through.
	Hooks Hooks
	// GatewayVersion is recorded into pre-restore documents and reported as
	// Result.CurrentGatewayVersion. Production callers pass cmn.Version
	// (common/common.go) -- this package does not import it directly to
	// keep the dependency explicit and the engine testable with fixture
	// version strings.
	GatewayVersion string
	// Hostname is recorded into pre-restore documents (§4's "hostname"
	// field).
	Hostname string
	// PreRestoreDir is the directory PRESERVE (§5.3 step 4) atomically
	// writes "pre-restore-<ts>.json" into, 0600, temp-file-then-rename.
	// Required for any non-Boot commit; dry-run and Boot never use it.
	PreRestoreDir string
	// Now defaults to time.Now; overridable for deterministic tests.
	Now Clock
}

// NewEngine builds an Engine with Now defaulted to time.Now.
func NewEngine(hooks Hooks, gatewayVersion, hostname, preRestoreDir string) *Engine {
	return &Engine{
		Hooks:          hooks,
		GatewayVersion: gatewayVersion,
		Hostname:       hostname,
		PreRestoreDir:  preRestoreDir,
		Now:            time.Now,
	}
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// ---------------------------------------------------------------------
// Restore: the §5.3 7-stage pipeline entrypoint.
//
// LOCKING CONTRACT (§5.3 implementer note): Restore does NOT take the
// gateway's global config lock itself. Stages 1-3 (PARSE/VALIDATE/PLAN) are
// read-only (decode + Get calls) and safe to run unlocked. The CALLER (the
// REST layer, task G-3) MUST hold the global config write lock for the
// duration of stages 4-7 (PRESERVE/APPLY/VERIFY/COMMIT-or-ROLLBACK) so that
// concurrent mutating API calls are rejected (409/503) for the duration of
// a restore, exactly as §5.3 specifies. Restore has no way to enforce this
// itself; a caller that invokes it without holding that lock risks
// interleaving a restore with concurrent config mutations.
// ---------------------------------------------------------------------

// Restore runs the §5.3 pipeline against raw (a snapshot document's raw
// JSON bytes, as produced by Encode/GET /config/snapshot). It always
// returns a non-nil *Result describing what happened, even on failure --
// the returned Go error is reserved for engine-level precondition failures
// (e.g. an unconfigured PreRestoreDir on a commit call), not for
// document/validation/apply problems, which are reported via
// Result.Errors/Result.Result so callers can render the §5.2 response
// regardless of where the pipeline stopped.
func (e *Engine) Restore(raw []byte, opts RestoreOptions) (*Result, error) {
	start := e.now()
	result, err := e.restore(raw, opts)
	end := e.now()
	committed := err == nil && result != nil && result.Result == ResultOK && !opts.isDryRun()
	observeRestore(opts.modeString(), result, err, end.Sub(start), committed, end)
	return result, err
}

// restore is the uninstrumented pipeline body (Restore wraps it with the §7
// metrics so every return path is observed exactly once).
func (e *Engine) restore(raw []byte, opts RestoreOptions) (*Result, error) {
	result := &Result{
		Mode:                  opts.modeString(),
		SchemaVersion:         SchemaVersion,
		CurrentGatewayVersion: e.GatewayVersion,
	}

	// 1. PARSE -- strict decode + checksum verify.
	doc, err := stageParse(raw)
	if err != nil {
		result.Errors = []string{err.Error()}
		return result, nil
	}
	result.SchemaVersion = doc.SchemaVersion
	result.SnapshotGatewayVersion = doc.GatewayVersion
	result.SnapshotGeneration = doc.Generation

	// 2. VALIDATE -- schema-version gate + migrations + coverage checks.
	// Stage gating: a VALIDATE failure returns here and never reaches
	// PLAN/PRESERVE/APPLY (no Get/Add/Del call has happened yet beyond the
	// pure in-memory decode).
	compatible, verrs := stageValidate(doc)
	result.Compatible = compatible
	if len(verrs) > 0 {
		result.Errors = verrs
		return result, nil
	}

	// 2b. VERIFY DEPENDENCIES -- every REQUIRED recovery_dependencies
	// entry is checked against this node's actual stores (hooks) while
	// nothing has been planned, wiped, or applied: a restore whose
	// declared-load-bearing external store is missing must stop HERE, not
	// mid-apply after the wipe. Optional entries are informational and
	// never verified. Runs in dry-run too -- preflighting exactly this is
	// what dry-run is for.
	depStatuses, depWarns, depErrs := e.stageVerifyDeps(doc)
	result.ExternalDependencies = depStatuses
	result.Warnings = append(result.Warnings, depWarns...)
	if len(depErrs) > 0 {
		result.Errors = depErrs
		return result, nil
	}

	// Selection runs AFTER validate so migrations have stamped
	// included_domains onto pre-1.2 documents: what a restore may wipe and
	// apply is included_domains ∩ the caller's components -- a partial
	// document must never wipe domains it does not cover.
	selected, err := selectForRestore(doc, opts.Components)
	if err != nil {
		result.Errors = []string{err.Error()}
		return result, nil
	}

	// 3. PLAN -- ordered per-domain {to_delete (live), to_apply (doc)}.
	// Read-only (Get calls only); dry-run stops here.
	plan, err := e.stagePlan(doc, selected, opts.Boot)
	if err != nil {
		result.Errors = []string{err.Error()}
		return result, nil
	}
	result.Plan = plan

	if opts.isDryRun() {
		result.Result = ResultOK
		return result, nil
	}

	// 4. PRESERVE -- capture + persist live config before touching
	// anything, UNLESS this is the Boot variant (§6.2: datapath is empty at
	// boot, nothing to preserve).
	var preDoc *Document
	if !opts.Boot {
		preDoc, err = e.stagePreserve(selected)
		if err != nil {
			result.Errors = []string{fmt.Sprintf("preserve: %v", err)}
			return result, nil // nothing mutated yet -- safe to stop here
		}
		path, perr := e.persistPreRestore(preDoc)
		if perr != nil {
			result.Errors = []string{fmt.Sprintf("preserve: persist: %v", perr)}
			return result, nil // still nothing mutated
		}
		result.PreRestoreSnapshotPersisted = path
	} else {
		// Implicit rollback target for Boot: "nothing existed before".
		preDoc = NewDocument(e.GatewayVersion, e.Hostname, TriggerPreRestore)
	}

	// 5. APPLY -- wipe (unless Boot) then apply forward-order; any error
	// aborts remaining domains and falls through to ROLLBACK. A Boot apply
	// tolerates idempotent already-exists items (skip, don't roll back):
	// the datapath starts empty at boot, so an "exists" there is a
	// duplicate entry within the document itself -- a no-op, not a reason
	// to throw away the whole boot config. Non-boot commits stay strict:
	// they run after a wipe, so "exists" means the wipe failed.
	applyErrs, skipped := e.stageApply(doc, selected, opts.Boot)
	for domain, count := range skipped {
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"apply %s: skipped %d already-existing identical item(s) (duplicate document entries)", domain, count))
	}

	// 6. VERIFY -- only meaningful if APPLY fully succeeded. Counts and
	// digests compare DISTINCT normalized items on both sides, so
	// tolerated idempotent duplicates (in-document or pre-existing from a
	// boot retry) need no special arithmetic.
	if len(applyErrs) == 0 {
		applyErrs = append(applyErrs, e.stageVerify(doc, selected)...)
	}

	if len(applyErrs) == 0 {
		// 7. COMMIT.
		result.Result = ResultOK
		return result, nil
	}

	for _, ae := range applyErrs {
		result.Errors = append(result.Errors, ae.Error())
	}

	// A BOOT apply that failed only on still-starting subsystems does not
	// roll back: the boot loader retries, boot applies tolerate
	// idempotent duplicates, and the next attempt converges over the
	// partial state. Rolling back between attempts made the replayed
	// config flap in and out for the whole retry window, and let the
	// rollback's own wipe fail against the same still-starting subsystem,
	// escalating a transient startup race into ROLLBACK-FAILED plus a
	// quarantined snapshot (observed live on a BGP-enabled gateway).
	// Any OTHER boot failure (a real conflict, a bad document) still
	// rolls back -- a permanent failure must not leave partial state for
	// the legacy fallback to collide with.
	if opts.Boot && allSubsystemStartup(applyErrs) {
		return result, nil
	}

	// ROLLBACK: wipe again + re-apply the step-4 pre-restore document.
	// "already exists" apply errors are tolerated (item-level
	// idempotency, §5.3) -- see rollback().
	rollbackErrs := e.rollback(preDoc, selected)
	if len(rollbackErrs) == 0 {
		result.Result = ResultRolledBack
		return result, nil
	}
	for _, re := range rollbackErrs {
		result.Errors = append(result.Errors, re.Error())
	}
	result.Result = ResultRollbackFailed
	return result, nil
}

// ---------------------------------------------------------------------
// Stage 1: PARSE
// ---------------------------------------------------------------------

func stageParse(raw []byte) (*Document, error) {
	doc, err := Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if err := VerifyChecksum(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// ---------------------------------------------------------------------
// Stage 2b: VERIFY DEPENDENCIES
// ---------------------------------------------------------------------

// stageVerifyDeps checks each REQUIRED recovery_dependencies entry against
// this node's actual external stores, via the hooks. It runs after
// VALIDATE (the manifest's shape and type vocabulary are already good) and
// before PLAN, so a missing load-bearing store fails the restore closed
// with zero mutations -- the wipe-then-fail-mid-apply alternative costs a
// rollback and, at boot, the whole replay. Warnings (a store that is
// wired but degraded, an older-generation registry the per-item apply
// will re-verify) surface in the result without blocking. The returned
// statuses mirror the whole manifest (optional entries included, as
// declared) for the response's external_dependencies surface.
func (e *Engine) stageVerifyDeps(doc *Document) (statuses []DependencyStatus, warns, errs []string) {
	for _, dep := range doc.RecoveryDependencies {
		status := DependencyStatus{
			Type:       dep.Type,
			ID:         dep.ID,
			Generation: dep.Generation,
			Digest:     dep.Digest,
			Required:   dep.Required,
			Status:     DepStatusDeclared,
		}
		if dep.Required {
			warn, err := e.Hooks.NetRecoveryDepVerify(dep)
			switch {
			case err != nil:
				status.Status = DepStatusFailed
				errs = append(errs, fmt.Sprintf("dependency %s: %v", dep.Type, err))
			case warn != "":
				status.Status = DepStatusWarning
				warns = append(warns, fmt.Sprintf("dependency %s: %s", dep.Type, warn))
			default:
				status.Status = DepStatusVerified
			}
		}
		statuses = append(statuses, status)
	}
	return statuses, warns, errs
}

// ---------------------------------------------------------------------
// Stage 2: VALIDATE
// ---------------------------------------------------------------------

// stageValidate implements §5.3 step 2: the schema-version gate (§4.2),
// then ApplyMigrations (migrate.go's stable call site), then per-domain
// semantic checks. compatible reflects the schema-version gate
// specifically (true even if semantic checks below it fail -- those are a
// different failure mode from cross-version incompatibility).
func stageValidate(doc *Document) (compatible bool, errs []string) {
	if err := CheckSchemaVersion(doc.SchemaVersion); err != nil {
		return false, []string{err.Error()}
	}
	if err := ApplyMigrations(doc); err != nil {
		return true, []string{err.Error()}
	}

	// Coverage declaration checks (schema 1.2+; migrations stamped full
	// coverage onto older documents just above). All fail closed: restore
	// selection is derived from included_domains, so an absent, unknown,
	// duplicated, or contradicted declaration must stop the pipeline
	// before anything is planned, wiped, or applied.
	if len(doc.IncludedDomains) == 0 {
		return true, []string{"snapshot: document declares no included_domains (required in schema 1.2+); refusing to guess restore coverage"}
	}
	included := make(map[string]bool, len(doc.IncludedDomains))
	for _, name := range doc.IncludedDomains {
		if included[name] {
			errs = append(errs, fmt.Sprintf("snapshot: included_domains lists %q more than once", name))
		}
		included[name] = true
	}
	if _, err := Select(doc.IncludedDomains); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return true, errs
	}
	// A domain carrying content but not declared as included is a torn or
	// hand-edited document: applying it would be guesswork, skipping it
	// would silently drop configuration.
	for _, name := range DomainNames() {
		if !included[name] && countDomain(name, &doc.Domains) > 0 {
			errs = append(errs, fmt.Sprintf("snapshot: domain %q carries content but is not listed in included_domains", name))
		}
	}
	if len(errs) > 0 {
		return true, errs
	}

	// recovery_dependencies manifest checks (schema 1.4+; nil = none
	// declared, valid). A REQUIRED entry of a type this build does not
	// know cannot be verified -- proceeding would be guessing about a
	// dependency the capturing gateway declared load-bearing, so it fails
	// closed here, before anything is planned or wiped. Unknown OPTIONAL
	// types pass (forward compatibility: informational entries from a
	// newer producer must not brick an otherwise-compatible restore).
	seenDep := make(map[string]bool, len(doc.RecoveryDependencies))
	for _, d := range doc.RecoveryDependencies {
		if d.Type == "" {
			errs = append(errs, "snapshot: recovery_dependencies entry with empty type")
			continue
		}
		key := d.Type + "\x00" + d.ID
		if seenDep[key] {
			errs = append(errs, fmt.Sprintf("snapshot: recovery_dependencies lists %s %q more than once", d.Type, d.ID))
		}
		seenDep[key] = true
		if d.Required && !cmn.KnownRecoveryDepTypes[d.Type] {
			errs = append(errs, fmt.Sprintf("snapshot: required recovery dependency of unknown type %q cannot be verified by this build; refusing to restore", d.Type))
		}
	}
	if len(errs) > 0 {
		return true, errs
	}

	// NOTE (G-8/G-9 E2E finding, 2026-07-20): the §5.3 example semantic
	// check "every LB endpoint reference resolvable within the doc" was
	// implemented here and then REMOVED. It contradicts the capture-side
	// RuleManaged filter: snapshots deliberately carry only standalone
	// (non-rule-managed) endpoints, while NetLbRuleAdd auto-creates the
	// endpoints named in each rule's Eps list -- so an LB endpoint absent
	// from the endpoint domain is the NORMAL shape of a captured document,
	// not a dangling reference. With the check in place, every
	// write-through/auto-persisted snapshot containing an LB whose
	// endpoints are all rule-managed failed VALIDATE on boot restore.
	return true, nil
}

// selectForRestore derives the effective restore selection: the document's
// included_domains intersected with the caller's `components`. With no
// components given, the document's own coverage is the selection -- so a
// partial document wipes and applies exactly what it covers, nothing more.
// An explicitly requested component the document does not cover is an
// error, not a silent no-op: the caller asked to restore state this
// document cannot provide.
func selectForRestore(doc *Document, components []string) ([]DomainEntry, error) {
	if len(components) == 0 {
		return Select(doc.IncludedDomains)
	}
	included := make(map[string]bool, len(doc.IncludedDomains))
	for _, name := range doc.IncludedDomains {
		included[name] = true
	}
	for _, name := range components {
		if !included[name] {
			return nil, fmt.Errorf("snapshot: component %q is not covered by this document (included_domains: %v)", name, doc.IncludedDomains)
		}
	}
	return Select(components)
}

// ---------------------------------------------------------------------
// Stage 3: PLAN
// ---------------------------------------------------------------------

// stagePlan builds the ordered per-domain plan. The Boot variant never
// calls Get: the datapath is empty at boot BY THE SAME PREMISE that lets
// Boot skip PRESERVE and the pre-apply wipe, so to_delete is 0 by
// definition -- and, critically, a boot-time Get can race an optional
// subsystem (gobgpd, ipsec) that has not finished starting, turning a
// startup-ordering hiccup into a failed (and quarantined) boot restore.
// Discovered live: a BGP-enabled gateway quarantined its snapshot on
// EVERY boot because PLAN's bgp Get hit the not-yet-listening gobgpd.
func (e *Engine) stagePlan(doc *Document, selected []DomainEntry, boot bool) ([]PlanItem, error) {
	plan := make([]PlanItem, 0, len(selected))
	for _, entry := range selected {
		toDelete := 0
		if !boot {
			scratch := &Document{}
			if err := entry.Get(e.Hooks, scratch); err != nil {
				return nil, fmt.Errorf("plan: get %s: %w", entry.Name, err)
			}
			toDelete = countDomain(entry.Name, &scratch.Domains)
		}
		plan = append(plan, PlanItem{
			Domain:   entry.Name,
			ToDelete: toDelete,
			ToApply:  countDomain(entry.Name, &doc.Domains),
		})
	}
	return plan, nil
}

// countDomain returns how many items a Domains struct carries for the
// named domain -- the same shape Apply functions (registry.go) build up
// and PLAN/VERIFY compare against.
func countDomain(name string, d *Domains) int {
	switch name {
	case DomainEndpoint:
		return len(d.Endpoint)
	case DomainLoadBalancer:
		return len(d.LoadBalancer)
	case DomainFirewall:
		return len(d.Firewall)
	case DomainPolicy:
		return len(d.Policy)
	case DomainMirror:
		return len(d.Mirror)
	case DomainSession:
		return len(d.Session)
	case DomainSessionUlCl:
		return len(d.SessionUlCl)
	case DomainKvExactBinding:
		return len(d.KvExactBinding)
	case DomainL7Policy:
		return len(d.L7Policy)
	case DomainIPFilter:
		return len(d.IPFilter)
	case DomainSecurityRate:
		if d.SecurityRate != nil {
			return 1
		}
		return 0
	case DomainBFD:
		return len(d.BFD)
	case DomainBGP:
		n := len(d.BGP.Neighbors) + len(d.BGP.DefinedSets) + len(d.BGP.PolicyDefinitions)
		if d.BGP.GlobalConfig != nil {
			n++
		}
		return n
	case DomainCORS:
		if d.CORS != nil {
			return 1
		}
		return 0
	case DomainTracing:
		if d.Tracing != nil {
			return 1
		}
		return 0
	case DomainCert:
		return len(d.Cert)
	case DomainIPsec:
		// The Config singleton is deliberately NOT counted: it cannot be
		// wiped (deleteIPsec's documented no-op) and it materializes on its
		// own once the IPsec subsystem initializes, so counting it makes
		// VERIFY fail whenever doc-vs-live config presence differs (e.g.
		// restoring a doc captured while IPsec was still starting up --
		// found live in testbed E2E, 2026-07-20). Config apply still runs
		// and still fails loudly on error; it is only the count-based
		// plan/verify arithmetic that ignores it.
		return len(d.IPsec.Tunnels) + len(d.IPsec.Certificates) + len(d.IPsec.CACertificates)
	default:
		return 0
	}
}

// ---------------------------------------------------------------------
// Stage 4: PRESERVE
// ---------------------------------------------------------------------

func (e *Engine) stagePreserve(selected []DomainEntry) (*Document, error) {
	preDoc := NewDocument(e.GatewayVersion, e.Hostname, TriggerPreRestore)
	// The pre-restore capture covers exactly the restore's selection: its
	// own included_domains must say so, or restoring it later (manually,
	// after a rollback) would wipe domains it never captured.
	preDoc.IncludedDomains = entryNames(selected)
	for _, entry := range selected {
		if err := entry.Get(e.Hooks, preDoc); err != nil {
			return nil, fmt.Errorf("get %s: %w", entry.Name, err)
		}
	}
	// Same canonicalization as Capture: the pre-restore document is a
	// persisted artifact too.
	if err := NormalizeDomains(&preDoc.Domains); err != nil {
		return nil, fmt.Errorf("normalize: %w", err)
	}
	snapshotTotal.WithLabelValues(string(TriggerPreRestore)).Inc()
	return preDoc, nil
}

// persistPreRestore atomically (temp file + rename, 0600) writes doc to
// PreRestoreDir/pre-restore-<ts>.json (§5.3 step 4 / §6 style path),
// returning the final path.
func (e *Engine) persistPreRestore(doc *Document) (string, error) {
	if e.PreRestoreDir == "" {
		return "", fmt.Errorf("PreRestoreDir not configured, cannot persist pre-restore snapshot")
	}
	data, err := Encode(doc)
	if err != nil {
		return "", fmt.Errorf("encode: %w", err)
	}

	ts := e.now().UTC().Format("20060102-150405.000000000")
	path, err := writeAtomic(e.PreRestoreDir, fmt.Sprintf("pre-restore-%s.json", ts), data)
	if err == nil {
		// G-8 (legacy defect #6): bound the pre-restore backlog now that a
		// new one landed. Best-effort — never fails the restore.
		PruneArtifacts(e.PreRestoreDir, PreRestoreKeep, e.now())
	}
	return path, err
}

// ---------------------------------------------------------------------
// Stage 5: APPLY
// ---------------------------------------------------------------------

// stageApply implements §5.3 step 5: delete existing (reverse domain
// order, via Wipe/G-6) then apply the document (forward order). Per-item
// apply errors (returned by DomainEntry.Apply, which itself already stops
// at the first fatally-failing item within a domain) abort remaining
// DOMAINS too -- stageApply returns immediately on the first domain-level
// error rather than continuing to apply further domains onto a
// known-inconsistent state. skipWipe is true for the Boot variant (§6.2:
// nothing live to wipe); the Boot variant also tolerates idempotent
// already-exists items (see DomainEntry.Apply), reporting them in the
// returned per-domain skip counts instead of failing the domain.
//
// Wipe's own contract (wipe.go) is "attempt every domain, collect errors,
// never abort mid-wipe" -- that contract is unchanged and still honored
// here (Wipe runs to completion internally). What stageApply decides is
// what to do with a non-empty Wipe error: treat it as fatal to the APPLY
// stage as a whole and skip the forward-apply phase entirely, since
// applying the new document on top of a partially-wiped, unknown state
// would compound the inconsistency rather than resolve it.
func (e *Engine) stageApply(doc *Document, selected []DomainEntry, boot bool) ([]error, map[string]int) {
	if !boot {
		_, wipeErr := Wipe(e.Hooks, entryNames(selected))
		if wipeErr != nil {
			return []error{fmt.Errorf("wipe: %w", wipeErr)}, nil
		}
	}

	var errs []error
	var skipped map[string]int
	for _, entry := range selected {
		_, nskip, err := entry.Apply(e.Hooks, doc, boot)
		if nskip > 0 {
			if skipped == nil {
				skipped = make(map[string]int)
			}
			skipped[entry.Name] = nskip
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("apply %s: %w", entry.Name, err))
			break // abort remaining domains (§5.3: "abort remaining items")
		}
	}
	return errs, skipped
}

// ---------------------------------------------------------------------
// Stage 6: VERIFY
// ---------------------------------------------------------------------

// stageVerify re-Gets each selected domain and checks, per §5.3 step 6:
// first the cheap count pre-check (live count vs the plan's to_apply,
// minus items the apply stage skipped as idempotent duplicates -- a
// duplicate document entry materializes once, not twice), then the content
// digest (DomainDigest, digest.go): the normalized desired-state content
// the backend now reports must equal the normalized content of the
// document that was just applied. The count alone lets a backend that
// silently dropped a field -- or replaced one item with another -- pass;
// the digest does not. stageVerify is only reached when stageApply
// reported zero errors, so any mismatch here means the backend didn't
// persist what it acknowledged.
func (e *Engine) stageVerify(doc *Document, selected []DomainEntry) []error {
	var errs []error
	for _, entry := range selected {
		scratch := &Document{}
		if err := entry.Get(e.Hooks, scratch); err != nil {
			errs = append(errs, fmt.Errorf("verify: get %s: %w", entry.Name, err))
			continue
		}
		wantCount, wantDigest, err := DomainContent(entry.Name, &doc.Domains)
		if err != nil {
			errs = append(errs, fmt.Errorf("verify: %s: %w", entry.Name, err))
			continue
		}
		gotCount, gotDigest, err := DomainContent(entry.Name, &scratch.Domains)
		if err != nil {
			errs = append(errs, fmt.Errorf("verify: %s: %w", entry.Name, err))
			continue
		}
		if gotCount != wantCount {
			errs = append(errs, fmt.Errorf("verify: %s: expected %d item(s) after apply, found %d", entry.Name, wantCount, gotCount))
			continue
		}
		if wantDigest != gotDigest {
			errs = append(errs, fmt.Errorf("verify: %s: content mismatch after apply: live state digests to %s, document to %s", entry.Name, gotDigest, wantDigest))
		}
	}
	return errs
}

// ---------------------------------------------------------------------
// ROLLBACK
// ---------------------------------------------------------------------

// rollback implements §5.3's ROLLBACK path: wipe again, then re-apply
// preDoc (the step-4 capture, or the implicit empty document for Boot).
//
// Unlike the forward APPLY loop (which aborts remaining domains on the
// first error), rollback attempts EVERY selected domain regardless of
// earlier failures in this pass -- rollback is the last line of defense
// against silently leaving partial state (§5.3: "Never silently leave
// partial state"), so it maximizes how much of the pre-restore state it
// manages to restore before reporting ROLLBACK-FAILED, rather than
// stopping at the first domain that won't cooperate. Idempotent "already
// exists" apply errors are tolerated per ITEM (tolerateExists inside
// DomainEntry.Apply, §5.3's item-level idempotency note), so one
// still-live duplicate no longer aborts the rest of its domain's
// re-apply -- previously tolerance acted at domain level and silently
// dropped every item after the duplicate.
func (e *Engine) rollback(preDoc *Document, selected []DomainEntry) []error {
	var errs []error

	if _, wipeErr := Wipe(e.Hooks, entryNames(selected)); wipeErr != nil {
		errs = append(errs, fmt.Errorf("rollback wipe: %w", wipeErr))
	}

	for _, entry := range selected {
		if _, _, err := entry.Apply(e.Hooks, preDoc, true); err != nil {
			errs = append(errs, fmt.Errorf("rollback apply %s: %w", entry.Name, err))
		}
	}
	return errs
}

// allSubsystemStartup reports whether every error is a still-starting
// subsystem condition (isSubsystemUnavailable, registry.go) -- the
// boot-retryable class.
func allSubsystemStartup(errs []error) bool {
	if len(errs) == 0 {
		return false
	}
	for _, err := range errs {
		if !isSubsystemUnavailable(err) {
			return false
		}
	}
	return true
}

// entryNames extracts DomainEntry.Name in order, for passing a selected
// subset back into Wipe/Select as a `components` list.
func entryNames(entries []DomainEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Name
	}
	return out
}
