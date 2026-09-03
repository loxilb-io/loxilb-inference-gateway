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

// Per-domain content digests for the restore engine's VERIFY stage
// (restore.go): a canonical, order-insensitive fingerprint of one domain's
// DESIRED state, with server-assigned runtime fields (probe delays,
// endpoint states, traffic counters, session uptimes) normalized away so
// that a live re-Get after apply can be compared field-by-field against
// the document that was just applied. Counting items (the previous VERIFY)
// only proves the backend kept the right number of things; the digest
// proves it kept the right things.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	cmn "github.com/loxilb-io/loxilb/common"
)

// DomainDigest computes "sha256:<hex>" over the named domain's normalized
// desired-state content in d. Items are individually canonicalized
// (volatile fields zeroed, nested endpoint/IP lists sorted), then sorted
// and de-duplicated, so the digest is insensitive to backend enumeration
// order and to duplicate document entries (which materialize at most once
// live), but sensitive to every desired-state field.
func DomainDigest(name string, d *Domains) (string, error) {
	items, err := domainItemJSONs(name, d)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, it := range items {
		h.Write([]byte(it))
		h.Write([]byte{'\n'})
	}
	return checksumPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// domainItemJSONs renders the domain's normalized items as sorted, unique
// canonical-JSON strings.
func domainItemJSONs(name string, d *Domains) ([]string, error) {
	switch name {
	case DomainEndpoint:
		eps := make([]cmn.EndPointMod, len(d.Endpoint))
		for i, ep := range d.Endpoint {
			// Probe measurements and current health are runtime state.
			ep.MinDelay, ep.AvgDelay, ep.MaxDelay, ep.CurrState = "", "", "", ""
			eps[i] = ep
		}
		return itemJSONs(eps)
	case DomainLoadBalancer:
		rules := make([]cmn.LbRuleMod, len(d.LoadBalancer))
		for i, r := range d.LoadBalancer {
			r.Serv.Oper = 0 // transient attach/detach opcode, not state
			r.SecIPs = append([]cmn.LbSecIPArg(nil), r.SecIPs...)
			r.SecVIPs = append([]cmn.LbSecVIPArg(nil), r.SecVIPs...)
			r.SrcIPs = append([]cmn.LbAllowedSrcIPArg(nil), r.SrcIPs...)
			eps := make([]cmn.LbEndPointArg, len(r.Eps))
			for j, ep := range r.Eps {
				ep.State, ep.Counters = "", "" // runtime health + traffic
				eps[j] = ep
			}
			r.Eps = eps
			// Nested lists have no order semantics; sort them so backend
			// enumeration order cannot flip the digest.
			if err := sortByJSON(r.SecIPs); err != nil {
				return nil, err
			}
			if err := sortByJSON(r.SecVIPs); err != nil {
				return nil, err
			}
			if err := sortByJSON(r.SrcIPs); err != nil {
				return nil, err
			}
			if err := sortByJSON(r.Eps); err != nil {
				return nil, err
			}
			rules[i] = r
		}
		return itemJSONs(rules)
	case DomainKvExactBinding:
		return itemJSONs(d.KvExactBinding)
	case DomainFirewall:
		fws := make([]cmn.FwRuleMod, len(d.Firewall))
		for i, f := range d.Firewall {
			f.Opts.Counter = "" // traffic counter
			fws[i] = f
		}
		return itemJSONs(fws)
	case DomainPolicy:
		return itemJSONs(d.Policy)
	case DomainMirror:
		ms := make([]cmn.MirrGetMod, len(d.Mirror))
		for i, m := range d.Mirror {
			m.Sync = 0 // datapath sync status
			ms[i] = m
		}
		return itemJSONs(ms)
	case DomainSession:
		return itemJSONs(d.Session)
	case DomainSessionUlCl:
		return itemJSONs(d.SessionUlCl)
	case DomainIPFilter:
		fs := make([]cmn.IPFilterEntry, len(d.IPFilter))
		for i, f := range d.IPFilter {
			f.Packets, f.Bytes = 0, 0 // match counters
			fs[i] = f
		}
		return itemJSONs(fs)
	case DomainSecurityRate:
		// Singleton, Config-only: Stats is runtime counters, and a nil
		// domain equals an all-disabled config (the wipe primitive resets
		// by Setting the zero config, so "absent" and "zeroed" are the
		// same live state).
		cfg := cmn.SecurityRateConfig{}
		if d.SecurityRate != nil {
			cfg = d.SecurityRate.Config
		}
		return itemJSONs([]cmn.SecurityRateConfig{cfg})
	case DomainBFD:
		return itemJSONs(d.BFD)
	case DomainBGP:
		neighs := make([]cmn.GoBGPNeighGetMod, len(d.BGP.Neighbors))
		for i, n := range d.BGP.Neighbors {
			n.State, n.Uptime = "", "" // session state, not config
			neighs[i] = n
		}
		nj, err := itemJSONs(neighs)
		if err != nil {
			return nil, err
		}
		dj, err := itemJSONs(d.BGP.DefinedSets)
		if err != nil {
			return nil, err
		}
		pj, err := itemJSONs(d.BGP.PolicyDefinitions)
		if err != nil {
			return nil, err
		}
		// GlobalConfig is excluded: there is no Get hook for it (capture
		// always leaves it nil), so including it would make every verify
		// of a global-config-bearing document fail against a live re-Get
		// that structurally cannot report it.
		out := make([]string, 0, len(nj)+len(dj)+len(pj))
		for _, s := range nj {
			out = append(out, "neighbor:"+s)
		}
		for _, s := range dj {
			out = append(out, "defined_set:"+s)
		}
		for _, s := range pj {
			out = append(out, "policy_definition:"+s)
		}
		return out, nil
	case DomainIPsec:
		// Config is excluded for the same reason countDomain excludes it:
		// it materializes on its own as the subsystem initializes, so
		// doc-vs-live presence legitimately differs. Tunnels are compared
		// by their Mod (desired) half only; State/traffic/rekey fields are
		// runtime.
		tuns := make([]cmn.IPsecTunnelMod, 0, len(d.IPsec.Tunnels))
		for _, t := range d.IPsec.Tunnels {
			if t != nil {
				tuns = append(tuns, t.IPsecTunnelMod)
			}
		}
		tj, err := itemJSONs(tuns)
		if err != nil {
			return nil, err
		}
		cj, err := itemJSONs(d.IPsec.Certificates)
		if err != nil {
			return nil, err
		}
		caj, err := itemJSONs(d.IPsec.CACertificates)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(tj)+len(cj)+len(caj))
		for _, s := range tj {
			out = append(out, "tunnel:"+s)
		}
		for _, s := range cj {
			out = append(out, "certificate:"+s)
		}
		for _, s := range caj {
			out = append(out, "ca_certificate:"+s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("snapshot: digest: unknown domain %q", name)
	}
}

// itemJSONs marshals every item, sorts the encodings, and drops exact
// duplicates (a duplicate document entry materializes once live).
func itemJSONs[T any](items []T) ([]string, error) {
	out := make([]string, 0, len(items))
	for i := range items {
		b, err := json.Marshal(items[i])
		if err != nil {
			return nil, fmt.Errorf("snapshot: digest: marshal: %w", err)
		}
		out = append(out, string(b))
	}
	sort.Strings(out)
	uniq := out[:0]
	var prev string
	for i, s := range out {
		if i > 0 && s == prev {
			continue
		}
		uniq = append(uniq, s)
		prev = s
	}
	return uniq, nil
}

// sortByJSON sorts items in place by their canonical JSON encoding --
// a stable, type-agnostic order for nested lists that have no inherent
// order semantics.
func sortByJSON[T any](items []T) error {
	keys := make([]string, len(items))
	for i := range items {
		b, err := json.Marshal(items[i])
		if err != nil {
			return fmt.Errorf("snapshot: digest: marshal: %w", err)
		}
		keys[i] = string(b)
	}
	sort.Sort(&byKey[T]{items: items, keys: keys})
	return nil
}

type byKey[T any] struct {
	items []T
	keys  []string
}

func (b *byKey[T]) Len() int           { return len(b.items) }
func (b *byKey[T]) Less(i, j int) bool { return b.keys[i] < b.keys[j] }
func (b *byKey[T]) Swap(i, j int) {
	b.items[i], b.items[j] = b.items[j], b.items[i]
	b.keys[i], b.keys[j] = b.keys[j], b.keys[i]
}
