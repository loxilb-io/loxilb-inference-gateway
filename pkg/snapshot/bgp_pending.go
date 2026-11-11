/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	cmn "github.com/loxilb-io/loxilb/common"
	"sync"
	"time"
)

// BGP recovery is serialized with a full interactive replacement. The disk
// snapshot is the sole durable intent; this cache is discarded at process exit.
// There is no second intent file, persisted epoch, or independent lineage.
var bgpRecovery struct {
	op       sync.Mutex
	mu       sync.RWMutex
	pending  *pendingBGP
	parent   context.Context
	intent   *Document
	tracking bool
}

type pendingBGP struct {
	doc        *Document
	raw        []byte
	components []string
	cancel     context.CancelFunc
	done       chan struct{}
	begin      chan struct{}
	replace    bool
}

func isBGPDomain(name string) bool {
	return name == DomainBGP || name == DomainBGPPolicyAssignment
}

// LockBGPRecovery excludes the boot retry from an interactive transaction,
// including its write-through. Lock order: REST snapshot gate, config writes,
// recovery, then the subsystem locks. Crash retries never take the REST gates.
func LockBGPRecovery() func() {
	bgpRecovery.op.Lock()
	return bgpRecovery.op.Unlock
}

func SetBGPRecoveryContext(ctx context.Context) {
	bgpRecovery.mu.Lock()
	defer bgpRecovery.mu.Unlock()
	bgpRecovery.parent = ctx
}

func BGPPending() bool {
	bgpRecovery.mu.RLock()
	defer bgpRecovery.mu.RUnlock()
	return bgpRecovery.pending != nil
}

// ResolvePendingBGP is called with LockBGPRecovery held after a successful full
// replacement. A failed transaction leaves the original retry and intent intact.
func ResolvePendingBGP() {
	bgpRecovery.mu.Lock()
	defer bgpRecovery.mu.Unlock()
	if p := bgpRecovery.pending; p != nil {
		p.cancel()
		bgpRecovery.pending = nil
		bgpPendingGauge.Set(0)
	}
}

func pendingBGPDocument() *Document {
	bgpRecovery.mu.RLock()
	defer bgpRecovery.mu.RUnlock()
	if bgpRecovery.pending == nil {
		return nil
	}
	// Do not give captures aliases into the immutable desired-state cache.
	data, _ := json.Marshal(bgpRecovery.pending.doc)
	var doc Document
	_ = json.Unmarshal(data, &doc)
	doc.pendingBGPRaw = cloneBGPRaw(bgpRecovery.pending.doc.pendingBGPRaw)
	return &doc
}

// FullBGPReplacement requires the full snapshot, rather than a component
// restore that could accidentally abandon outstanding intent.
func FullBGPReplacement(raw []byte, components []string) bool {
	if len(components) != 0 {
		return false
	}
	doc, err := stageParse(raw)
	if err != nil {
		return false
	}
	if _, errs := stageValidate(doc); len(errs) != 0 {
		return false
	}
	covered := make(map[string]bool)
	for _, n := range doc.IncludedDomains {
		covered[n] = true
	}
	entries, _ := Select(nil)
	for _, entry := range entries {
		if !covered[entry.Name] {
			return false
		}
	}
	return true
}

// BootDomainGroups verifies the complete document before any independent
// domain is applied, including security and external recovery dependencies.
func (e *Engine) BootDomainGroups(raw []byte) (independent, bgp []string, result *Result, err error) {
	result, err = e.Restore(raw, RestoreOptions{Boot: true, PlanOnly: true})
	if err != nil || result.Result != ResultOK {
		return
	}
	doc, err := stageParse(raw)
	if err != nil {
		return nil, nil, result, err
	}
	if _, errs := stageValidate(doc); len(errs) != 0 {
		return nil, nil, result, fmt.Errorf("validate boot domains: %v", errs)
	}
	// Empty BGP domains on a non-BGP node need no deferred recovery.
	needsBGP := countDomain(DomainBGP, &doc.Domains) != 0 || countDomain(DomainBGPPolicyAssignment, &doc.Domains) != 0
	for _, name := range doc.IncludedDomains {
		if needsBGP && isBGPDomain(name) {
			bgp = append(bgp, name)
		} else {
			independent = append(independent, name)
		}
	}
	return
}

// StartPendingBGP publishes pending state before the boot write gate opens.
// The retry only ever applies the BGP group. Non-BGP mutations and persists can
// proceed; BGP API writes are refused until this group or a full restore wins.
func (e *Engine) StartPendingBGP(raw []byte, components []string) error {
	start, err := e.PreparePendingBGP(raw, components)
	if err != nil {
		return err
	}
	start()
	return nil
}

// PreparePendingBGP gates advertisements before independent LB apply. The
// returned callback starts BGP work only after independent verification.
func (e *Engine) PreparePendingBGP(raw []byte, components []string) (func(), error) {
	doc, err := stageParse(raw)
	if err != nil {
		return nil, err
	}
	if _, errs := stageValidate(doc); len(errs) != 0 {
		return nil, fmt.Errorf("validate pending BGP: %v", errs)
	}
	doc.pendingBGPRaw, err = extractBGPRaw(raw)
	if err != nil {
		return nil, err
	}
	bgpRecovery.mu.Lock()
	defer bgpRecovery.mu.Unlock()
	if bgpRecovery.pending != nil {
		return nil, fmt.Errorf("BGP recovery already pending")
	}
	parent := bgpRecovery.parent
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	// A retry must not revalidate or apply obsolete non-BGP dependencies
	// after safe management writes. The complete source was validated at
	// boot; this checksummed in-memory projection contains only its BGP group.
	group := *doc
	group.Domains = Domains{BGP: doc.Domains.BGP, BGPPolicyAssignment: doc.Domains.BGPPolicyAssignment}
	group.IncludedDomains = append([]string(nil), components...)
	group.RecoveryDependencies = nil // BGP has no external secret/store dependencies
	groupRaw, err := Encode(&group)
	if err != nil {
		cancel()
		return nil, err
	}
	p := &pendingBGP{doc: doc, raw: groupRaw, components: append([]string(nil), components...), cancel: cancel, done: make(chan struct{}), begin: make(chan struct{})}
	bgpRecovery.pending = p
	bgpPendingGauge.Set(1)
	go e.retryPendingBGP(ctx, p)
	var once sync.Once
	return func() { once.Do(func() { close(p.begin) }) }, nil
}

func (e *Engine) retryPendingBGP(ctx context.Context, p *pendingBGP) {
	defer close(p.done)
	select {
	case <-ctx.Done():
		return
	case <-p.begin:
	}
	delay := 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		bgpRecovery.op.Lock()
		bgpRecovery.mu.RLock()
		current := bgpRecovery.pending == p
		bgpRecovery.mu.RUnlock()
		if !current || ctx.Err() != nil {
			bgpRecovery.op.Unlock()
			return
		}
		// A YAML-backed replacement may contain settings deleted through the
		// API. Once API/snapshot intent owns the group, remove that static
		// baseline before replay, rather than merely tolerating duplicates.
		var result *Result
		var err error
		if p.replace {
			var global cmn.GoBGPGlobalConfig
			global, err = e.Hooks.NetGoBGPGCGet()
			if err == nil && global.LocalAs != 0 {
				_, err = Wipe(e.Hooks, p.components)
			}
		}
		if err == nil {
			result, err = e.Restore(p.raw, RestoreOptions{Boot: true, Components: p.components})
		}
		if ctx.Err() != nil {
			bgpRecovery.op.Unlock()
			return
		}
		state := BootRestoreStateGet()
		state.Degraded, state.Succeeded = true, false
		state.Reasons = []string{"bgp_domain_pending: independent domains restored; retrying the BGP group"}
		if err != nil {
			state.Reasons = append(state.Reasons, err.Error())
		} else if result.Result != ResultOK {
			state.Reasons = append(state.Reasons, result.Errors...)
		}
		if err == nil && result.Result == ResultOK {
			RememberBGPIntent(p.doc)
			if notifier, ok := e.Hooks.(interface{ NetBGPRecoveryComplete() }); ok {
				notifier.NetBGPRecoveryComplete()
			}
			state.Degraded, state.Succeeded, state.Reasons = false, true, nil
			bgpRecovery.mu.Lock()
			bgpRecovery.pending = nil
			bgpPendingGauge.Set(0)
			bgpRecovery.mu.Unlock()
		}
		RecordBootRestoreState(state)
		bgpRecovery.op.Unlock()
		if state.Succeeded {
			return
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func StopBGPRecovery(ctx context.Context) error {
	bgpRecovery.mu.RLock()
	p := bgpRecovery.pending
	if p != nil {
		p.cancel()
	}
	bgpRecovery.mu.RUnlock()
	if p == nil {
		return nil
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
