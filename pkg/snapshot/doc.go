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

// Package snapshot implements the loxilb instance snapshot/restore
// document primitive described in docs/SNAPSHOT-DESIGN.md. This file
// (doc.go) covers task G-1: the canonical document types (§4).
//
// The package deliberately owns no I/O and no side effects on the running
// gateway -- see registry.go for the domain Get/Apply/Delete function table
// (dependency-injected on a Hooks interface so callers, including the future
// restore engine of task G-2, decide when and how to touch live state.
package snapshot

import (
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

// SchemaVersion is the current document format version emitted by Encode.
// Bumped per §4.2: major on breaking changes, minor on additive changes.
//
// 1.1: added the kvexactbinding domain (KV-exact model-profile/engine-
// contract bindings). Profile-aware documents must not restore onto builds
// that do not understand binding state, so this is a minor bump (the
// version gate in CheckSchemaVersion refuses newer-minor documents) rather
// than a silently-added field.
const SchemaVersion = "1.1"

// DocKind identifies the document type, matching §4's "kind" field.
const DocKind = "loxilb-snapshot"

// Trigger enumerates why a snapshot was taken (§4).
type Trigger string

// Recognized Trigger values. Decode does not reject unrecognized values --
// the field is informational/audit metadata, not a protocol gate.
const (
	TriggerManual       Trigger = "manual"
	TriggerPreRestore   Trigger = "pre-restore"
	TriggerScheduled    Trigger = "scheduled"
	TriggerPreUpgrade   Trigger = "pre-upgrade"
	TriggerWriteThrough Trigger = "write-through"
)

// Domain name constants -- these are exactly the domains.* JSON keys (§4)
// and the DomainEntry.Name values in the registry (registry.go). They are
// also the valid values for the REST `components` query parameter (task
// G-3) and for Select (registry.go).
const (
	DomainEndpoint       = "endpoint"
	DomainLoadBalancer   = "loadbalancer"
	DomainKvExactBinding = "kvexactbinding"
	DomainFirewall       = "firewall"
	DomainPolicy         = "policy"
	DomainMirror         = "mirror"
	DomainSession        = "session"
	DomainSessionUlCl    = "sessionulcl"
	DomainIPFilter       = "ipfilter"
	DomainSecurityRate   = "securityrate"
	DomainBFD            = "bfd"
	DomainBGP            = "bgp"
	DomainIPsec          = "ipsec"
)

// DefaultExcludedDomains lists the domains deliberately never captured by a
// v1 snapshot (§4.1 "Deliberately excluded" table). Recorded verbatim into
// Document.ExcludedDomains as an honesty marker -- it is not a filter over
// the Domains struct (which simply never has fields for these).
var DefaultExcludedDomains = []string{"cluster", "conntrack", "ai_keys", "interface"}

// BGPDomain is the composite "bgp" domain document (§4, row 11 of §4.1).
//
// GlobalConfig (G-7) is nil when BGP global config was never set on the
// snapshotted gateway; `omitempty` keeps old documents (without the field)
// decoding cleanly under DisallowUnknownFields, with no schema_version bump
// (§4.2).
type BGPDomain struct {
	Neighbors         []cmn.GoBGPNeighGetMod          `json:"neighbors"`
	DefinedSets       []cmn.GoBGPPolicyDefinedSetMod  `json:"defined_sets"`
	PolicyDefinitions []cmn.GoBGPPolicyDefinitionsMod `json:"policy_definitions"`
	GlobalConfig      *cmn.GoBGPGlobalConfig          `json:"global_config,omitempty"`
}

// IPsecDomain is the composite "ipsec" domain document (§4, row 12 of §4.1).
//
// Certificates round-trip with FULL PEM material (G-3a, user decision
// 2026-07-20): capture uses the PEM-bearing NetIPsecCertificateExportAll /
// NetIPsecCACertificateExportAll hooks, which return the exact Mod shapes
// the Add hooks accept -- certificate PEM, private-key PEM (certs), name and
// description. This makes the snapshot document itself carry private keys,
// squarely under §8's "snapshots contain secrets" posture (0600 on disk,
// authenticated API only, at-rest encryption is OAM's job).
//
// Known limitation: a private key uploaded WITH a passphrase is stored (and
// therefore exported) as encrypted PEM, but the passphrase itself is never
// persisted, so restore's NetIPsecCertificateAdd validation fails loudly on
// it -- such certs need manual re-upload. Tunnel PSKs round-trip verbatim
// via IPsecTunnelMod.
type IPsecDomain struct {
	Config         *cmn.IPsecConfig            `json:"config,omitempty"`
	Tunnels        []*cmn.IPsecTunnel          `json:"tunnels,omitempty"`
	Certificates   []cmn.IPsecCertificateMod   `json:"certificates,omitempty"`
	CACertificates []cmn.IPsecCACertificateMod `json:"ca_certificates,omitempty"`
}

// Domains holds the per-domain payloads, one field per v1 domain, in
// exactly the §4.1 table order (apply order; DeleteOrder in registry.go is
// the reverse).
type Domains struct {
	Endpoint     []cmn.EndPointMod `json:"endpoint"`
	LoadBalancer []cmn.LbRuleMod   `json:"loadbalancer"`
	// KvExactBinding carries each rule's KV-exact composed-binding identity
	// (model-profile ref, engine-contract ref, binding generation + digest,
	// allocation high-water mark). Applied after loadbalancer (bindings
	// belong to rules). Added in schema 1.1; absent in 1.0 documents.
	KvExactBinding []cmn.KvExactBindingMod `json:"kvexactbinding,omitempty"`
	Firewall       []cmn.FwRuleMod         `json:"firewall"`
	Policy         []cmn.PolMod            `json:"policy"`
	Mirror         []cmn.MirrGetMod        `json:"mirror"`
	Session        []cmn.SessionMod        `json:"session"`
	SessionUlCl    []cmn.SessionUlClMod    `json:"sessionulcl"`
	IPFilter       []cmn.IPFilterEntry     `json:"ipfilter"`
	// SecurityRate is a singleton (Set semantics on apply); nil means "not
	// captured" (e.g. excluded via `components`).
	SecurityRate *cmn.SecurityRateState `json:"securityrate,omitempty"`
	BFD          []cmn.BFDMod           `json:"bfd"`
	BGP          BGPDomain              `json:"bgp"`
	IPsec        IPsecDomain            `json:"ipsec"`
}

// Document is the canonical, versioned snapshot document (§4). It is the
// single artifact exchanged over the wire (GET /config/snapshot, POST
// /config/restore -- task G-3) and persisted to disk (snapshot.json --
// task G-5/G-9).
type Document struct {
	SchemaVersion  string    `json:"schema_version"`
	Kind           string    `json:"kind"`
	CreatedAt      time.Time `json:"created_at"`
	GatewayVersion string    `json:"gateway_version"`
	Hostname       string    `json:"hostname"`
	Trigger        Trigger   `json:"trigger"`
	Domains        Domains   `json:"domains"`
	// ExcludedDomains is an honesty marker (§4): the domains this document
	// never captures, regardless of `components` filtering. See
	// DefaultExcludedDomains.
	ExcludedDomains []string `json:"excluded_domains"`
	// Checksum is "sha256:<hex>" over the canonical JSON of this document
	// with this field set to "" (see codec.go ComputeChecksum). Populated by
	// Encode; validated by VerifyChecksum.
	Checksum string `json:"checksum"`
}

// NewDocument builds an empty Document with the required constant/metadata
// fields populated (SchemaVersion, Kind, CreatedAt, GatewayVersion,
// Hostname, Trigger, ExcludedDomains) and all Domains fields left at their
// zero value, ready for the registry's Get functions (registry.go) to fill
// in. Domains selection (via `components`) is the caller's responsibility;
// see Select in registry.go.
func NewDocument(gatewayVersion, hostname string, trigger Trigger) *Document {
	return &Document{
		SchemaVersion:   SchemaVersion,
		Kind:            DocKind,
		CreatedAt:       time.Now().UTC(),
		GatewayVersion:  gatewayVersion,
		Hostname:        hostname,
		Trigger:         trigger,
		ExcludedDomains: append([]string(nil), DefaultExcludedDomains...),
	}
}
