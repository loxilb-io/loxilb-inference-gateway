/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"

	cmn "github.com/loxilb-io/loxilb/common"
)

var bgpComponents = []string{DomainBGP, DomainBGPPolicyAssignment}

func EnableBGPIntentRecovery() {
	bgpRecovery.mu.Lock()
	bgpRecovery.tracking = true
	bgpRecovery.mu.Unlock()
}

// Retention is not adoption: auto-persist and old boot snapshots may retain
// the supported projection of YAML without taking ownership of that speaker.
func BGPIntentAdopted() bool {
	bgpRecovery.mu.RLock()
	defer bgpRecovery.mu.RUnlock()
	return bgpRecovery.adopted
}

func AdoptBGPIntent() {
	bgpRecovery.mu.Lock()
	bgpRecovery.adopted = true
	bgpRecovery.mu.Unlock()
}

func BGPIntentOwnsSpeaker(dir string, staticFile bool) bool {
	if !staticFile || BGPIntentAdopted() {
		return true
	}
	raw, err := LoadPersisted(dir)
	if err != nil || raw == nil {
		return false
	}
	d, err := stageParse(raw)
	if err != nil {
		return false
	}
	if _, errs := stageValidate(d); len(errs) != 0 {
		return false
	}
	return d.BGPAPIAdopted && slices.Contains(d.IncludedDomains, DomainBGP)
}

func cloneBGPDocument(d *Document) *Document {
	if d == nil {
		return nil
	}
	raw, _ := json.Marshal(d)
	var copy Document
	_ = json.Unmarshal(raw, &copy)
	copy.pendingBGPRaw = cloneBGPRaw(d.pendingBGPRaw)
	return &copy
}

// RememberBGPIntent retains the completed configuration too. snapshot.json
// remains the only durable store; this process-local copy also includes API
// writes in the auto-persist quiet period. Callers serialize through recovery.op
// or the REST config-write gate. No live speaker reads occur on crash recovery.
func RememberBGPIntent(d *Document) {
	if d == nil || !slices.Contains(d.IncludedDomains, DomainBGP) || !slices.Contains(d.IncludedDomains, DomainBGPPolicyAssignment) {
		return
	}
	copy := cloneBGPDocument(d)
	copy.Domains = Domains{BGP: copy.Domains.BGP, BGPPolicyAssignment: copy.Domains.BGPPolicyAssignment}
	copy.IncludedDomains = append([]string(nil), bgpComponents...)
	copy.RecoveryDependencies = nil
	copy.BGPAPIAdopted = BGPIntentAdopted()
	bgpRecovery.mu.Lock()
	if !bgpRecovery.tracking {
		bgpRecovery.mu.Unlock()
		return
	}
	bgpRecovery.intent = copy
	bgpRecovery.mu.Unlock()
}

func (e *Engine) rememberBGPSelection(d *Document, selected []DomainEntry, interactive bool) {
	bgp, assignments := false, false
	for _, entry := range selected {
		bgp = bgp || entry.Name == DomainBGP
		assignments = assignments || entry.Name == DomainBGPPolicyAssignment
	}
	if !bgp && !assignments {
		return
	}
	if interactive || d.BGPAPIAdopted {
		AdoptBGPIntent()
	}
	bgpRecovery.mu.RLock()
	tracking := bgpRecovery.tracking
	base := cloneBGPDocument(bgpRecovery.intent)
	bgpRecovery.mu.RUnlock()
	if !tracking {
		return
	}
	if bgp && assignments {
		RememberBGPIntent(d)
		return
	}
	if base == nil {
		base = NewDocument(e.GatewayVersion, e.Hostname, TriggerManual)
		base.IncludedDomains = append([]string(nil), bgpComponents...)
		// Only read the unselected part. The selected target already passed
		// verification; a daemon dying now must not erase that replacement.
		if !bgp {
			if err := getBGP(e.Hooks, base); err != nil {
				return
			}
		}
		if !assignments {
			if err := getBGPPolicyAssignment(e.Hooks, base); err != nil {
				return
			}
		}
	}
	if bgp {
		base.Domains.BGP = d.Domains.BGP
	}
	if assignments {
		base.Domains.BGPPolicyAssignment = d.Domains.BGPPolicyAssignment
	}
	base.pendingBGPRaw = nil
	RememberBGPIntent(base)
}

// ChangeBGPIntent publishes the exact acknowledged mutation before returning
// success. In particular, it does not depend on a post-delete read of a daemon
// which may already have died. Recovery and interactive replacement use the
// same operation lock, so a queued retry cannot replay an earlier generation.
// The REST write gate must already be held; see the lock order in bgp_pending.go.
func ChangeBGPIntent(h Hooks, value any, add bool, apply func() (int, error)) (int, error) {
	// Startup waiting belongs before the recovery op lock. After the first
	// transport readiness in this process, the hook is a no-op, including crashes.
	if startup, ok := h.(interface{ NetBGPWaitForStartup() error }); ok {
		if err := startup.NetBGPWaitForStartup(); err != nil {
			return 0, err
		}
	}
	defer LockBGPRecovery()()
	EnableBGPIntentRecovery()
	bgpRecovery.mu.RLock()
	pending := bgpRecovery.pending != nil
	d := cloneBGPDocument(bgpRecovery.intent)
	bgpRecovery.mu.RUnlock()
	if pending {
		return 0, cmn.NewConflictError("bgp_domain_pending: retry is active; use a full snapshot replacement")
	}
	if d == nil {
		var err error
		d, err = captureBGPGroup(h)
		if err != nil {
			return 0, err
		}
	}
	if err := editBGPIntent(d, value, add); err != nil {
		return 0, err
	}
	n, err := apply()
	if err == nil {
		AdoptBGPIntent()
		RememberBGPIntent(d)
		// Preserve the acknowledgement first, then enrich it with GoBGP's
		// effective representation (defaults, canonical prefix ranges, etc.).
		// A crash during this read cannot replace intent with an empty daemon.
		observed := NewDocument(cmn.Version, "", TriggerManual)
		observed.IncludedDomains = append([]string(nil), bgpComponents...)
		if getBGP(h, observed) == nil && getBGPPolicyAssignment(h, observed) == nil {
			global, readErr := h.NetGoBGPGCGet()
			if readErr == nil && observed.Domains.BGP.GlobalConfig != nil && d.Domains.BGP.GlobalConfig != nil &&
				global == *observed.Domains.BGP.GlobalConfig && global == *d.Domains.BGP.GlobalConfig {
				RememberBGPIntent(observed)
			}
		}
	}
	return n, err
}

// captureBGPGroup uses a stable healthy live read, retaining the last complete
// projection if the daemon fails or changes generation during capture.
func captureBGPGroup(h Hooks) (*Document, error) {
	if p := pendingBGPDocument(); p != nil {
		return p, nil
	}
	bgpRecovery.mu.RLock()
	fallback := cloneBGPDocument(bgpRecovery.intent)
	bgpRecovery.mu.RUnlock()
	health, hasHealth := h.(interface {
		NetBGPRecoveryHealthy() bool
		NetBGPRecoveryGeneration() uint64
	})
	var generation uint64
	healthyAtStart := !hasHealth || health.NetBGPRecoveryHealthy()
	if hasHealth {
		generation = health.NetBGPRecoveryGeneration()
		if fallback != nil && !health.NetBGPRecoveryHealthy() {
			return fallback, nil
		}
	}
	live := NewDocument(cmn.Version, "", TriggerManual)
	live.IncludedDomains = append([]string(nil), bgpComponents...)
	err := getBGP(h, live)
	if err == nil {
		err = getBGPPolicyAssignment(h, live)
	}
	if err == nil && fallback != nil && fallback.Domains.BGP.GlobalConfig != nil && live.Domains.BGP.GlobalConfig == nil {
		err = fmt.Errorf("BGP speaker became unconfigured during capture")
	}
	if err == nil && hasHealth && fallback != nil && (!health.NetBGPRecoveryHealthy() || generation != health.NetBGPRecoveryGeneration()) {
		err = fmt.Errorf("BGP speaker changed during capture")
	}
	if err != nil {
		if fallback != nil {
			return fallback, nil
		}
		return nil, err
	}
	if err = NormalizeDomains(&live.Domains); err != nil {
		return nil, err
	}
	// A first capture during startup may be useful to its caller, but cannot
	// seed recovery intent from a partial/unconfigured speaker.
	if live.Domains.BGP.GlobalConfig != nil && (!hasHealth || (healthyAtStart && health.NetBGPRecoveryHealthy() && generation == health.NetBGPRecoveryGeneration())) {
		RememberBGPIntent(live)
	}
	return live, nil
}

func canonicalBGPSetType(s string) string {
	switch strings.ToLower(s) {
	case "neighbor", "nei", "neigh":
		return "neigh"
	case "extcommunity":
		return "extCommunity"
	case "largecommunity":
		return "largeCommunity"
	case "aspath":
		return "asPath"
	default:
		return strings.ToLower(s)
	}
}

func editBGPIntent(d *Document, value any, add bool) error {
	b := &d.Domains.BGP
	// The edited projection owns its encoding; never retain the old raw BGP
	// bytes used to preserve an unapplied boot snapshot.
	d.pendingBGPRaw = nil
	switch v := value.(type) {
	case *cmn.GoBGPGlobalConfig:
		copy := *v
		b.GlobalConfig = &copy
	case *cmn.GoBGPNeighMod:
		addr := v.Addr.String()
		b.Neighbors = slices.DeleteFunc(b.Neighbors, func(n cmn.GoBGPNeighGetMod) bool { return net.ParseIP(n.Addr).Equal(v.Addr) })
		if !add {
			d.Domains.BGPPolicyAssignment = slices.DeleteFunc(d.Domains.BGPPolicyAssignment, func(a cmn.GoBGPPolicyApply) bool { return a.NeighIPAddress == addr })
		} else {
			port := v.RemotePort
			if port == 179 {
				port = 0
			}
			b.Neighbors = append(b.Neighbors, cmn.GoBGPNeighGetMod{Addr: addr, RemoteAS: v.RemoteAS, RemotePort: port, MultiHop: v.MultiHop})
		}
	case *cmn.GoBGPPolicyDefinedSetMod:
		copy := *v
		copy.DefinedTypeString = canonicalBGPSetType(copy.DefinedTypeString)
		for i, existing := range b.DefinedSets {
			if existing.Name != copy.Name || canonicalBGPSetType(existing.DefinedTypeString) != copy.DefinedTypeString {
				continue
			}
			if add {
				for _, s := range copy.List {
					if !slices.Contains(existing.List, s) {
						existing.List = append(existing.List, s)
					}
				}
				for _, p := range copy.PrefixList {
					if !slices.Contains(existing.PrefixList, p) {
						existing.PrefixList = append(existing.PrefixList, p)
					}
				}
				b.DefinedSets[i] = existing
			} else {
				b.DefinedSets = slices.Delete(b.DefinedSets, i, i+1)
			}
			return nil
		}
		if add {
			b.DefinedSets = append(b.DefinedSets, copy)
		}
	case *cmn.GoBGPPolicyDefinitionsMod:
		b.PolicyDefinitions = slices.DeleteFunc(b.PolicyDefinitions, func(p cmn.GoBGPPolicyDefinitionsMod) bool { return p.Name == v.Name })
		if add {
			b.PolicyDefinitions = append(b.PolicyDefinitions, *v)
		}
	case *cmn.GoBGPPolicyApply:
		copy := *v
		copy.PolicyType = strings.ToLower(copy.PolicyType)
		unique := make([]string, 0, len(copy.Polices))
		for _, name := range copy.Polices {
			if !slices.Contains(unique, name) {
				unique = append(unique, name)
			}
		}
		copy.Polices = unique
		for i, existing := range d.Domains.BGPPolicyAssignment {
			if existing.NeighIPAddress != copy.NeighIPAddress || existing.PolicyType != copy.PolicyType {
				continue
			}
			if add {
				for _, name := range copy.Polices {
					if !slices.Contains(existing.Polices, name) {
						existing.Polices = append(existing.Polices, name)
					}
				}
				if copy.RouteAction == "accept" || copy.RouteAction == "reject" {
					existing.RouteAction = copy.RouteAction
				}
			} else if len(copy.Polices) == 0 {
				d.Domains.BGPPolicyAssignment = slices.Delete(d.Domains.BGPPolicyAssignment, i, i+1)
				return nil
			} else {
				existing.Polices = slices.DeleteFunc(existing.Polices, func(p string) bool { return slices.Contains(copy.Polices, p) })
			}
			d.Domains.BGPPolicyAssignment[i] = existing
			return nil
		}
		if add {
			if copy.RouteAction == "" {
				copy.RouteAction = "accept"
			}
			d.Domains.BGPPolicyAssignment = append(d.Domains.BGPPolicyAssignment, copy)
		}
	default:
		return fmt.Errorf("unsupported BGP intent mutation %T", value)
	}
	return nil
}

// RecoverBGPAfterRestart runs in the daemon supervisor, outside the GoBGP
// mutex, BEFORE launching the replacement or waiting for its ASN. A pending
// boot retry already owns its target; a completed group starts a fresh retry
// from the latest acknowledged intent. Pointer identity invalidates stale work.
func (e *Engine) RecoverBGPAfterRestart(ctx context.Context, staticFile bool) (bool, error) {
	defer LockBGPRecovery()()
	if err := ctx.Err(); err != nil {
		return true, err
	}
	if !BGPIntentOwnsSpeaker(e.PreRestoreDir, staticFile) {
		e.skipPendingBGPForYAML()
		return false, nil
	}
	bgpRecovery.mu.Lock()
	pending := bgpRecovery.pending != nil
	d := cloneBGPDocument(bgpRecovery.intent)
	bgpRecovery.mu.Unlock()
	if pending {
		return true, nil
	}
	if d == nil {
		return false, nil
	} // static-only configuration belongs to YAML
	raw, err := Encode(d)
	if err != nil {
		return true, err
	}
	start, err := e.PreparePendingBGP(raw, bgpComponents)
	if err != nil {
		return true, err
	}
	bgpRecovery.mu.Lock()
	bgpRecovery.pending.replace = true
	bgpRecovery.mu.Unlock()
	start()
	return true, nil
}

// ResultSelectsBGP reports successful selection, not whether boot happened to
// have an active retry. Interactive recovery also clears prepare-error gates.
func ResultSelectsBGP(r *Result) bool {
	if r == nil || r.Result != ResultOK {
		return false
	}
	for _, p := range r.Plan {
		if isBGPDomain(p.Domain) {
			return true
		}
	}
	return false
}
