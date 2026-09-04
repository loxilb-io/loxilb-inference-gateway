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

// Canonicalization of captured domain content, shared by two consumers:
//
//   - Capture and the restore engine's PRESERVE stage call
//     NormalizeDomains so persisted documents carry DESIRED state only,
//     deterministically ordered. Both properties were violated live:
//     endpoint probe delays (runtime measurements) landed in
//     snapshot.json, and the backend's map-ordered rule enumeration made
//     two captures of an unchanged gateway differ byte-wise -- so
//     checksums churned on idle gateways and byte-golden comparisons
//     were impossible.
//   - The VERIFY stage's DomainDigest compares normalized content:
//     a live re-Get after apply must digest-equal the applied document,
//     field-for-field, regardless of enumeration order, duplicate
//     document entries, or runtime fields the backend fills in.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// NormalizeDomains canonicalizes d IN PLACE: volatile runtime fields are
// zeroed (they are measurements, not desired configuration) and every
// unordered list is sorted by its canonical JSON encoding, so an
// unchanged gateway always produces the identical domains payload.
func NormalizeDomains(d *Domains) error {
	for i := range d.Endpoint {
		ep := &d.Endpoint[i]
		// Probe measurements and current health are runtime state.
		ep.MinDelay, ep.AvgDelay, ep.MaxDelay, ep.CurrState = "", "", "", ""
	}
	if err := sortByJSON(d.Endpoint); err != nil {
		return err
	}

	for i := range d.LoadBalancer {
		r := &d.LoadBalancer[i]
		r.Serv.Oper = 0 // transient attach/detach opcode, not state
		// Rebuild nested lists before mutating/sorting them: a Get hook
		// may hand back slices whose backing arrays alias live rule
		// state, and normalization must never write through such an
		// alias.
		r.SecIPs = append([]cmn.LbSecIPArg(nil), r.SecIPs...)
		r.SecVIPs = append([]cmn.LbSecVIPArg(nil), r.SecVIPs...)
		r.SrcIPs = append([]cmn.LbAllowedSrcIPArg(nil), r.SrcIPs...)
		r.Eps = append([]cmn.LbEndPointArg(nil), r.Eps...)
		for j := range r.Eps {
			r.Eps[j].State, r.Eps[j].Counters = "", "" // runtime health + traffic
		}
		// Nested lists have no order semantics; sort them so backend
		// enumeration order cannot flip the payload.
		for _, err := range []error{
			sortByJSON(r.SecIPs), sortByJSON(r.SecVIPs),
			sortByJSON(r.SrcIPs), sortByJSON(r.Eps),
		} {
			if err != nil {
				return err
			}
		}
	}
	if err := sortByJSON(d.LoadBalancer); err != nil {
		return err
	}

	if err := sortByJSON(d.KvExactBinding); err != nil {
		return err
	}

	// L7 policies carry no runtime measurement fields; sorting by canonical
	// JSON (id leads the encoding) keeps captures byte-stable.
	if err := sortByJSON(d.L7Policy); err != nil {
		return err
	}

	for i := range d.Firewall {
		d.Firewall[i].Opts.Counter = "" // traffic counter
	}
	if err := sortByJSON(d.Firewall); err != nil {
		return err
	}

	if err := sortByJSON(d.Policy); err != nil {
		return err
	}

	for i := range d.Mirror {
		d.Mirror[i].Sync = 0 // datapath sync status
	}
	if err := sortByJSON(d.Mirror); err != nil {
		return err
	}

	if err := sortByJSON(d.Session); err != nil {
		return err
	}
	if err := sortByJSON(d.SessionUlCl); err != nil {
		return err
	}

	for i := range d.IPFilter {
		d.IPFilter[i].Packets, d.IPFilter[i].Bytes = 0, 0 // match counters
	}
	if err := sortByJSON(d.IPFilter); err != nil {
		return err
	}

	if d.SecurityRate != nil {
		d.SecurityRate.Stats = cmn.SecurityRateStats{} // runtime counters
	}

	if err := sortByJSON(d.BFD); err != nil {
		return err
	}

	for i := range d.BGP.Neighbors {
		n := &d.BGP.Neighbors[i]
		n.State, n.Uptime = "", "" // session state, not config
	}
	for _, err := range []error{
		sortByJSON(d.BGP.Neighbors), sortByJSON(d.BGP.DefinedSets),
		sortByJSON(d.BGP.PolicyDefinitions),
	} {
		if err != nil {
			return err
		}
	}

	for i, t := range d.IPsec.Tunnels {
		if t == nil {
			continue
		}
		// Copy before zeroing: the Get hook may return pointers into
		// live tunnel state. Only the Mod half is desired state; the
		// rest is live SA status.
		c := *t
		c.State = ""
		c.InstalledAt = time.Time{}
		c.BytesIn, c.BytesOut, c.PacketsIn, c.PacketsOut = 0, 0, 0, 0
		c.LastRekeyAt = time.Time{}
		c.SAsInstalled = 0
		d.IPsec.Tunnels[i] = &c
	}
	for _, err := range []error{
		sortByJSON(d.IPsec.Tunnels), sortByJSON(d.IPsec.Certificates),
		sortByJSON(d.IPsec.CACertificates),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

// cloneDomains deep-copies via the JSON codec (Domains is JSON-complete
// by construction -- it IS the wire format).
func cloneDomains(d *Domains) (*Domains, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("snapshot: digest: clone: %w", err)
	}
	var c Domains
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("snapshot: digest: clone: %w", err)
	}
	return &c, nil
}

// DomainContent computes the number of DISTINCT desired-state items the
// named domain carries in d, plus their "sha256:<hex>" content digest
// (d itself is never mutated). Items are individually canonicalized,
// sorted and de-duplicated, so both values are insensitive to backend
// enumeration order and to duplicate document entries (which materialize
// at most once live), but the digest is sensitive to every desired-state
// field. Distinct-count is the right VERIFY arithmetic on both sides:
// a document item that already existed live (a tolerated idempotent
// duplicate) and a document that lists an item twice both materialize
// exactly one live item.
func DomainContent(name string, d *Domains) (int, string, error) {
	c, err := cloneDomains(d)
	if err != nil {
		return 0, "", err
	}
	if err := NormalizeDomains(c); err != nil {
		return 0, "", err
	}
	items, err := domainItemJSONs(name, c)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	for _, it := range items {
		h.Write([]byte(it))
		h.Write([]byte{'\n'})
	}
	return len(items), checksumPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// DomainDigest is DomainContent's digest half.
func DomainDigest(name string, d *Domains) (string, error) {
	_, sum, err := DomainContent(name, d)
	return sum, err
}

// domainItemJSONs renders one NORMALIZED domain's items as sorted, unique
// canonical-JSON strings. Digest-only exclusions live here (not in
// NormalizeDomains, because captured documents still carry these fields):
// BGP GlobalConfig is verified indirectly (the speaker only starts when
// it applies -- every neighbor apply after it proves it took effect) and
// older documents never carried it, so digest inclusion would flip
// verify verdicts by document age; the IPsec Config singleton
// materializes on its own as the subsystem initializes, so doc-vs-live
// presence legitimately differs -- exactly like countDomain's matching
// exclusion.
func domainItemJSONs(name string, d *Domains) ([]string, error) {
	switch name {
	case DomainEndpoint:
		return itemJSONs(d.Endpoint)
	case DomainLoadBalancer:
		return itemJSONs(d.LoadBalancer)
	case DomainKvExactBinding:
		return itemJSONs(d.KvExactBinding)
	case DomainL7Policy:
		return itemJSONs(d.L7Policy)
	case DomainFirewall:
		return itemJSONs(d.Firewall)
	case DomainPolicy:
		return itemJSONs(d.Policy)
	case DomainMirror:
		return itemJSONs(d.Mirror)
	case DomainSession:
		return itemJSONs(d.Session)
	case DomainSessionUlCl:
		return itemJSONs(d.SessionUlCl)
	case DomainIPFilter:
		return itemJSONs(d.IPFilter)
	case DomainSecurityRate:
		// Singleton, Config-only: a nil domain equals an all-disabled
		// config (the wipe primitive resets by Setting the zero config,
		// so "absent" and "zeroed" are the same live state).
		cfg := cmn.SecurityRateConfig{}
		if d.SecurityRate != nil {
			cfg = d.SecurityRate.Config
		}
		return itemJSONs([]cmn.SecurityRateConfig{cfg})
	case DomainCORS:
		// Singleton: nil (unconfigured factory default) digests as no
		// items -- absent-vs-configured is exactly the difference VERIFY
		// must see, unlike securityrate where nil and zeroed coincide.
		if d.CORS == nil {
			return nil, nil
		}
		return itemJSONs([]cmn.CORSConfig{*d.CORS})
	case DomainTracing:
		// Same nil-vs-configured distinction as cors.
		if d.Tracing == nil {
			return nil, nil
		}
		return itemJSONs([]cmn.TracingConfig{*d.Tracing})
	case DomainCert:
		return itemJSONs(d.Cert)
	case DomainBFD:
		return itemJSONs(d.BFD)
	case DomainBGP:
		nj, err := itemJSONs(d.BGP.Neighbors)
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
// a stable, type-agnostic order for lists that have no inherent order
// semantics.
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
