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

// Configuration-lifecycle registry: every mutating REST route of the
// gateway API (api/swagger.yml) is classified into exactly one lifecycle
// class, so that "is this configuration recovered after a reboot, and
// from where?" has a single, code-level answer instead of folklore.
//
// The registry is enforced by lifecycle_test.go, which parses
// api/swagger.yml and fails when a mutating route is missing here (or when
// an entry here no longer exists in the API). Adding a mutating route to
// the API therefore forces an explicit persistence decision at review
// time.
//
// It is also the source of truth for Document.ExcludedDomains (doc.go):
// the honesty marker listing configuration areas that have a mutating API
// but are NOT captured by the snapshot document.
package snapshot

import "sort"

// LifecycleClass says how the state behind a mutating route survives (or
// deliberately does not survive) a gateway restart.
type LifecycleClass string

const (
	// ClassSnapshot: desired state captured into the snapshot document
	// (Domains, doc.go) and replayed at boot.
	ClassSnapshot LifecycleClass = "snapshot"
	// ClassExternalStore: desired state owned by a store outside the
	// snapshot document (the auth/key database, the on-disk certificate
	// store) and recovered from that store at boot. The snapshot may
	// reference such stores but never embeds them.
	ClassExternalStore LifecycleClass = "external-store"
	// ClassRuntimeRebuilt: state that lives only at runtime. Either the
	// gateway rebuilds it after boot from an authoritative source (kernel
	// networking state via netlink, health probing), or it is by design
	// ephemeral (sessions, diagnostics, operational overrides) and must be
	// re-established by the operator if wanted again.
	ClassRuntimeRebuilt LifecycleClass = "runtime-rebuilt"
	// ClassLifecycleOperation: the configuration-lifecycle mechanism
	// itself (persist, restore, legacy import). These routes move or apply
	// configuration owned by other classes and carry no desired state of
	// their own.
	ClassLifecycleOperation LifecycleClass = "lifecycle-operation"
	// ClassOutOfScope: features explicitly excluded from the persistence
	// contract by product decision. Their configuration is not persisted
	// and they must not become snapshot domains without separate approval;
	// classifying them here keeps the exclusion loud instead of silent.
	ClassOutOfScope LifecycleClass = "out-of-scope"
)

// RouteLifecycle classifies one mutating route of api/swagger.yml.
type RouteLifecycle struct {
	// Method is the lower-case HTTP method exactly as it appears in
	// api/swagger.yml (post, put, patch, delete).
	Method string
	// Path is the swagger path template, without the basePath prefix.
	Path string
	// Class is the lifecycle class of the state this route mutates.
	Class LifecycleClass
	// Area names the configuration area the route belongs to. For
	// ClassSnapshot routes it is exactly the snapshot domain name (the
	// Domain* constants in doc.go); for the other classes it is a stable
	// grouping label used for the excluded_domains honesty list.
	Area string
	// DesiredState is true when the route creates, updates or deletes
	// durable desired configuration -- the kind an operator expects back
	// after a reboot. It is false for ephemeral actions: logins, stat
	// resets, validation probes, cleanups, operational overrides and
	// diagnostics toggles. Only desired-state routes participate in the
	// excluded_domains derivation.
	DesiredState bool
}

// Area labels for non-snapshot classes. Snapshot-classed routes use the
// Domain* constants from doc.go instead.
const (
	AreaAuthSessions = "auth_sessions"
	AreaAuthUsers    = "auth_users"
	AreaAIKeys       = "ai_keys"
	AreaAIRateLimit  = "ai_ratelimit"
	AreaCert         = "cert"
	AreaCluster      = "cluster"
	AreaGPU          = "gpu"
	AreaGPUMode      = "gpu_mode"
	AreaInterface    = "interface"
	AreaL4Trace      = "l4trace"
	AreaLifecycle    = "config_lifecycle"
	AreaLlamaFW      = "llamafirewall"
	AreaMetrics      = "metrics"
	AreaOPA          = "opa"
	AreaParams       = "params"
	AreaPII          = "pii"
	AreaTracing      = "tracing"
)

// RouteLifecycles is the classification table. One entry per mutating
// route in api/swagger.yml; lifecycle_test.go enforces the bijection in
// both directions.
var RouteLifecycles = []RouteLifecycle{
	// --- Authentication plane. Sessions/tokens are runtime state; user
	// accounts live in the management database (external store).
	{Method: "post", Path: "/auth/login", Class: ClassRuntimeRebuilt, Area: AreaAuthSessions},
	{Method: "post", Path: "/auth/logout", Class: ClassRuntimeRebuilt, Area: AreaAuthSessions},
	{Method: "post", Path: "/auth/token/upgrade", Class: ClassRuntimeRebuilt, Area: AreaAuthSessions},
	{Method: "post", Path: "/auth/users", Class: ClassExternalStore, Area: AreaAuthUsers, DesiredState: true},
	{Method: "put", Path: "/auth/users/{id}", Class: ClassExternalStore, Area: AreaAuthUsers, DesiredState: true},
	{Method: "delete", Path: "/auth/users/{id}", Class: ClassExternalStore, Area: AreaAuthUsers, DesiredState: true},

	// --- AI key/quota plane: key-store database.
	{Method: "post", Path: "/config/ai/apikey", Class: ClassExternalStore, Area: AreaAIKeys, DesiredState: true},
	{Method: "delete", Path: "/config/ai/apikey/{key_id}", Class: ClassExternalStore, Area: AreaAIKeys, DesiredState: true},
	{Method: "post", Path: "/config/ai/tenant/ratelimit", Class: ClassExternalStore, Area: AreaAIRateLimit, DesiredState: true},

	// --- Snapshot domains (doc.go Domains struct).
	{Method: "post", Path: "/config/endpoint", Class: ClassSnapshot, Area: DomainEndpoint, DesiredState: true},
	{Method: "delete", Path: "/config/endpoint/epipaddress/{ip_address}", Class: ClassSnapshot, Area: DomainEndpoint, DesiredState: true},
	// Operational probe-state override; endpoint health is rebuilt by
	// probing after boot, never replayed.
	{Method: "post", Path: "/config/endpointhoststate", Class: ClassRuntimeRebuilt, Area: DomainEndpoint},

	{Method: "post", Path: "/config/loadbalancer", Class: ClassSnapshot, Area: DomainLoadBalancer, DesiredState: true},
	{Method: "patch", Path: "/config/loadbalancer/externalipaddress/{ip_address}/port/{port}/protocol/{proto}", Class: ClassSnapshot, Area: DomainLoadBalancer, DesiredState: true},
	{Method: "delete", Path: "/config/loadbalancer/all", Class: ClassSnapshot, Area: DomainLoadBalancer, DesiredState: true},
	{Method: "delete", Path: "/config/loadbalancer/externalipaddress/{ip_address}/port/{port}/protocol/{proto}", Class: ClassSnapshot, Area: DomainLoadBalancer, DesiredState: true},
	{Method: "delete", Path: "/config/loadbalancer/externalipaddress/{ip_address}/port/{port}/portmax/{portmax}/protocol/{proto}", Class: ClassSnapshot, Area: DomainLoadBalancer, DesiredState: true},
	{Method: "delete", Path: "/config/loadbalancer/hosturl/{hosturl}/externalipaddress/{ip_address}/port/{port}/protocol/{proto}", Class: ClassSnapshot, Area: DomainLoadBalancer, DesiredState: true},
	{Method: "delete", Path: "/config/loadbalancer/hosturl/{hosturl}/externalipaddress/{ip_address}/port/{port}/portmax/{portmax}/protocol/{proto}", Class: ClassSnapshot, Area: DomainLoadBalancer, DesiredState: true},
	{Method: "delete", Path: "/config/loadbalancer/name/{lb_name}", Class: ClassSnapshot, Area: DomainLoadBalancer, DesiredState: true},

	{Method: "post", Path: "/config/firewall", Class: ClassSnapshot, Area: DomainFirewall, DesiredState: true},
	{Method: "delete", Path: "/config/firewall", Class: ClassSnapshot, Area: DomainFirewall, DesiredState: true},

	{Method: "post", Path: "/config/policy", Class: ClassSnapshot, Area: DomainPolicy, DesiredState: true},
	{Method: "delete", Path: "/config/policy/ident/{ident}", Class: ClassSnapshot, Area: DomainPolicy, DesiredState: true},

	{Method: "post", Path: "/config/mirror", Class: ClassSnapshot, Area: DomainMirror, DesiredState: true},
	{Method: "delete", Path: "/config/mirror/ident/{ident}", Class: ClassSnapshot, Area: DomainMirror, DesiredState: true},

	{Method: "post", Path: "/config/session", Class: ClassSnapshot, Area: DomainSession, DesiredState: true},
	{Method: "delete", Path: "/config/session/ident/{ident}", Class: ClassSnapshot, Area: DomainSession, DesiredState: true},

	{Method: "post", Path: "/config/sessionulcl", Class: ClassSnapshot, Area: DomainSessionUlCl, DesiredState: true},
	{Method: "delete", Path: "/config/sessionulcl/ident/{ident}/ulclAddress/{ip_address}", Class: ClassSnapshot, Area: DomainSessionUlCl, DesiredState: true},

	{Method: "post", Path: "/config/ipfilter", Class: ClassSnapshot, Area: DomainIPFilter, DesiredState: true},
	{Method: "delete", Path: "/config/ipfilter", Class: ClassSnapshot, Area: DomainIPFilter, DesiredState: true},

	{Method: "post", Path: "/config/securityrate", Class: ClassSnapshot, Area: DomainSecurityRate, DesiredState: true},
	{Method: "delete", Path: "/config/securityrate", Class: ClassSnapshot, Area: DomainSecurityRate, DesiredState: true},
	// Counter/state reset on the captured domain, not desired state.
	{Method: "put", Path: "/config/securityrate/reset", Class: ClassRuntimeRebuilt, Area: DomainSecurityRate},

	{Method: "post", Path: "/config/bfd", Class: ClassSnapshot, Area: DomainBFD, DesiredState: true},
	{Method: "delete", Path: "/config/bfd/remoteIP/{remote_ip}", Class: ClassSnapshot, Area: DomainBFD, DesiredState: true},

	{Method: "post", Path: "/config/bgp/global", Class: ClassSnapshot, Area: DomainBGP, DesiredState: true},
	{Method: "post", Path: "/config/bgp/neigh", Class: ClassSnapshot, Area: DomainBGP, DesiredState: true},
	{Method: "delete", Path: "/config/bgp/neigh/{ip_address}", Class: ClassSnapshot, Area: DomainBGP, DesiredState: true},
	{Method: "post", Path: "/config/bgp/policy/apply", Class: ClassSnapshot, Area: DomainBGP, DesiredState: true},
	{Method: "delete", Path: "/config/bgp/policy/apply", Class: ClassSnapshot, Area: DomainBGP, DesiredState: true},
	{Method: "post", Path: "/config/bgp/policy/definedsets/{defineset_type}", Class: ClassSnapshot, Area: DomainBGP, DesiredState: true},
	{Method: "delete", Path: "/config/bgp/policy/definedsets/{defineset_type}/{type_name}", Class: ClassSnapshot, Area: DomainBGP, DesiredState: true},
	{Method: "post", Path: "/config/bgp/policy/definitions", Class: ClassSnapshot, Area: DomainBGP, DesiredState: true},
	{Method: "delete", Path: "/config/bgp/policy/definitions/{policy_name}", Class: ClassSnapshot, Area: DomainBGP, DesiredState: true},

	{Method: "post", Path: "/config/ipsec", Class: ClassSnapshot, Area: DomainIPsec, DesiredState: true},
	{Method: "post", Path: "/config/ipsec/tunnels", Class: ClassSnapshot, Area: DomainIPsec, DesiredState: true},
	{Method: "put", Path: "/config/ipsec/tunnels/{name}", Class: ClassSnapshot, Area: DomainIPsec, DesiredState: true},
	{Method: "delete", Path: "/config/ipsec/tunnels/{name}", Class: ClassSnapshot, Area: DomainIPsec, DesiredState: true},
	{Method: "post", Path: "/config/ipsec/certificates", Class: ClassSnapshot, Area: DomainIPsec, DesiredState: true},
	{Method: "delete", Path: "/config/ipsec/certificates/{name}", Class: ClassSnapshot, Area: DomainIPsec, DesiredState: true},
	{Method: "post", Path: "/config/ipsec/ca-certificates", Class: ClassSnapshot, Area: DomainIPsec, DesiredState: true},
	{Method: "delete", Path: "/config/ipsec/ca-certificates/{name}", Class: ClassSnapshot, Area: DomainIPsec, DesiredState: true},
	// Actions/diagnostics on the ipsec domain, not desired state.
	{Method: "post", Path: "/config/ipsec/certificates/validate", Class: ClassRuntimeRebuilt, Area: DomainIPsec},
	{Method: "post", Path: "/config/ipsec/tunnels/{name}/action", Class: ClassRuntimeRebuilt, Area: DomainIPsec},
	{Method: "delete", Path: "/config/ipsec/stats", Class: ClassRuntimeRebuilt, Area: DomainIPsec},

	// --- L7 policies: snapshot domain since schema 1.3 (the desired-state
	// registry lives control-plane side and round-trips through capture/
	// restore).
	{Method: "post", Path: "/config/l7policy", Class: ClassSnapshot, Area: DomainL7Policy, DesiredState: true},
	{Method: "delete", Path: "/config/l7policy/id/{id}", Class: ClassSnapshot, Area: DomainL7Policy, DesiredState: true},

	// --- CORS: snapshot domain since schema 1.3 (explicit allowlist +
	// wildcard opt-in round-trip; the unconfigured factory default is not
	// captured).
	{Method: "post", Path: "/config/cors", Class: ClassSnapshot, Area: DomainCORS, DesiredState: true},
	{Method: "delete", Path: "/config/cors/{cors_url}", Class: ClassSnapshot, Area: DomainCORS, DesiredState: true},

	// --- TLS certificate store: PEM material lives on disk under the
	// certificate directory (external store), not in the snapshot.
	{Method: "post", Path: "/config/cert", Class: ClassExternalStore, Area: AreaCert, DesiredState: true},
	{Method: "put", Path: "/config/cert/{certId}", Class: ClassExternalStore, Area: AreaCert, DesiredState: true},
	{Method: "delete", Path: "/config/cert/{certId}", Class: ClassExternalStore, Area: AreaCert, DesiredState: true},
	{Method: "post", Path: "/sni/certificates", Class: ClassExternalStore, Area: AreaCert, DesiredState: true},
	{Method: "delete", Path: "/sni/certificates", Class: ClassExternalStore, Area: AreaCert, DesiredState: true},

	// --- Tracing/observability. The OTLP collector endpoint is product
	// configuration (desired state, runtime-only today); trace toggles,
	// catalog parsers and L4 trace sampling are diagnostics.
	// OTLP export product config: snapshot domain since schema 1.3
	// (header values stay node-local; only names ride the document). The
	// remaining trace routes are runtime toggles/diagnostics.
	{Method: "post", Path: "/config/trace/otlp", Class: ClassSnapshot, Area: DomainTracing, DesiredState: true},
	{Method: "post", Path: "/config/trace/enable", Class: ClassRuntimeRebuilt, Area: AreaTracing},
	{Method: "post", Path: "/config/trace/disable", Class: ClassRuntimeRebuilt, Area: AreaTracing},
	{Method: "put", Path: "/config/trace/catalog/{catalog_id}/parser", Class: ClassRuntimeRebuilt, Area: AreaTracing},
	{Method: "delete", Path: "/config/trace/catalog/{catalog_id}/parser", Class: ClassRuntimeRebuilt, Area: AreaTracing},
	{Method: "post", Path: "/config/l4trace/enable", Class: ClassRuntimeRebuilt, Area: AreaL4Trace},
	{Method: "post", Path: "/config/l4trace/disable", Class: ClassRuntimeRebuilt, Area: AreaL4Trace},
	{Method: "put", Path: "/config/l4trace/sampling", Class: ClassRuntimeRebuilt, Area: AreaL4Trace},
	{Method: "post", Path: "/config/l4trace/stats/reset", Class: ClassRuntimeRebuilt, Area: AreaL4Trace},

	// --- Metrics exporter toggle: runtime-only configuration.
	{Method: "post", Path: "/config/metrics", Class: ClassRuntimeRebuilt, Area: AreaMetrics, DesiredState: true},
	{Method: "delete", Path: "/config/metrics", Class: ClassRuntimeRebuilt, Area: AreaMetrics, DesiredState: true},

	// --- Global runtime parameters (log level).
	{Method: "post", Path: "/config/params", Class: ClassRuntimeRebuilt, Area: AreaParams, DesiredState: true},

	// --- Cluster/HA instance state: driven by the HA manager, never
	// replayed from a snapshot.
	{Method: "post", Path: "/config/cistate", Class: ClassRuntimeRebuilt, Area: AreaCluster, DesiredState: true},

	// --- GPU/worker plane. Mode toggle is runtime-only desired state;
	// the rest are operational actions and telemetry ingestion.
	{Method: "post", Path: "/config/gpu/enable", Class: ClassRuntimeRebuilt, Area: AreaGPUMode, DesiredState: true},
	{Method: "post", Path: "/config/gpu/disable", Class: ClassRuntimeRebuilt, Area: AreaGPUMode, DesiredState: true},
	{Method: "post", Path: "/config/gpu/conversations/cleanup", Class: ClassRuntimeRebuilt, Area: AreaGPU},
	{Method: "post", Path: "/config/worker/metrics", Class: ClassRuntimeRebuilt, Area: AreaGPU},

	// --- Kernel networking plumbing: the kernel owns this state and the
	// gateway relearns it from netlink at boot.
	{Method: "post", Path: "/config/ipv4address", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "delete", Path: "/config/ipv4address/{ip_address}/{mask}/dev/{if_name}", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "post", Path: "/config/ipv6address", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "delete", Path: "/config/ipv6address/{ip_address}/{mask}/dev/{if_name}", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "post", Path: "/config/route", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "delete", Path: "/config/route/destinationIPNet/{ip_address}/{mask}", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "post", Path: "/config/neighbor", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "delete", Path: "/config/neighbor/{ip_address}/dev/{if_name}", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "post", Path: "/config/fdb", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "delete", Path: "/config/fdb/{mac_address}/dev/{if_name}", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "post", Path: "/config/vlan", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "delete", Path: "/config/vlan/{vlan_id}", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "post", Path: "/config/vlan/{vlan_id}/member", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "delete", Path: "/config/vlan/{vlan_id}/member/{if_name}/tagged/{tagged}", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "post", Path: "/config/tunnel/vxlan", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "delete", Path: "/config/tunnel/vxlan/{vxlanID}", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "post", Path: "/config/tunnel/vxlan/{vxlanID}/peer", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},
	{Method: "delete", Path: "/config/tunnel/vxlan/{vxlanID}/peer/{PeerIP}", Class: ClassRuntimeRebuilt, Area: AreaInterface, DesiredState: true},

	// --- Configuration-lifecycle mechanism.
	{Method: "post", Path: "/config/persist", Class: ClassLifecycleOperation, Area: AreaLifecycle},
	{Method: "post", Path: "/config/restore", Class: ClassLifecycleOperation, Area: AreaLifecycle},
	{Method: "post", Path: "/config/import", Class: ClassLifecycleOperation, Area: AreaLifecycle},

	// --- Explicitly out of the persistence contract by product decision
	// (documented as non-persistent; do not add as snapshot domains
	// without separate approval).
	{Method: "post", Path: "/config/pii/configure", Class: ClassOutOfScope, Area: AreaPII, DesiredState: true},
	{Method: "post", Path: "/config/pii/enable", Class: ClassOutOfScope, Area: AreaPII, DesiredState: true},
	{Method: "post", Path: "/config/pii/url-patterns", Class: ClassOutOfScope, Area: AreaPII, DesiredState: true},
	{Method: "post", Path: "/config/llamafirewall/configure", Class: ClassOutOfScope, Area: AreaLlamaFW, DesiredState: true},
	{Method: "post", Path: "/config/llamafirewall/enable", Class: ClassOutOfScope, Area: AreaLlamaFW, DesiredState: true},
	{Method: "post", Path: "/config/llamafirewall/scanners", Class: ClassOutOfScope, Area: AreaLlamaFW, DesiredState: true},
	{Method: "post", Path: "/config/llamafirewall/health", Class: ClassOutOfScope, Area: AreaLlamaFW},
	{Method: "post", Path: "/config/opa/watcher", Class: ClassOutOfScope, Area: AreaOPA, DesiredState: true},
	{Method: "delete", Path: "/config/opa/watcher", Class: ClassOutOfScope, Area: AreaOPA, DesiredState: true},
}

// RouteKey builds the lookup key for a route: "<method> <path>", method
// lower-case, path as in api/swagger.yml.
func RouteKey(method, path string) string {
	return method + " " + path
}

// RouteLifecycleIndex returns the classification table keyed by RouteKey.
// Duplicate entries are a programming error caught by lifecycle_test.go.
func RouteLifecycleIndex() map[string]RouteLifecycle {
	idx := make(map[string]RouteLifecycle, len(RouteLifecycles))
	for _, rl := range RouteLifecycles {
		idx[RouteKey(rl.Method, rl.Path)] = rl
	}
	return idx
}

// snapshotDomainSet is the set of Domains struct field names (doc.go).
var snapshotDomainSet = map[string]bool{
	DomainEndpoint:       true,
	DomainLoadBalancer:   true,
	DomainKvExactBinding: true,
	DomainL7Policy:       true,
	DomainFirewall:       true,
	DomainPolicy:         true,
	DomainMirror:         true,
	DomainSession:        true,
	DomainSessionUlCl:    true,
	DomainIPFilter:       true,
	DomainSecurityRate:   true,
	DomainBFD:            true,
	DomainBGP:            true,
	DomainIPsec:          true,
	DomainCORS:           true,
	DomainTracing:        true,
}

// ExcludedDomainsFromLifecycle derives the excluded_domains honesty list
// (Document.ExcludedDomains) from the lifecycle registry: every area that
// has at least one desired-state mutating route NOT captured by the
// snapshot document. Areas that are snapshot domains never appear (their
// runtime-action routes do not make a captured domain "excluded"), and
// purely ephemeral areas (sessions, diagnostics) do not either -- there is
// no desired state to miss. Sorted for deterministic documents.
func ExcludedDomainsFromLifecycle() []string {
	seen := map[string]bool{}
	for _, rl := range RouteLifecycles {
		if !rl.DesiredState || rl.Class == ClassSnapshot || snapshotDomainSet[rl.Area] {
			continue
		}
		seen[rl.Area] = true
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
