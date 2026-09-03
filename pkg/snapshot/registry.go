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

package snapshot

import (
	"errors"
	"fmt"
	"net"
	"strings"

	cmn "github.com/loxilb-io/loxilb/common"
)

// Hooks is the subset of cmn.NetHookInterface (pkg/loxinet/apiclient.go)
// that the snapshot domain registry needs. Any real cmn.NetHookInterface
// implementation -- notably loxinet.NetAPIStruct -- satisfies Hooks
// automatically (its method set is a strict superset), so production code
// passes its existing hooks value straight through with no adapter. Unit
// tests implement this much smaller interface directly instead of stubbing
// out all ~80 NetHookInterface methods.
type Hooks interface {
	// endpoint (§4.1 #1)
	NetEpHostGet() ([]cmn.EndPointMod, error)
	NetEpHostAdd(*cmn.EndPointMod) (int, error)
	NetEpHostDel(*cmn.EndPointMod) (int, error)

	// loadbalancer (§4.1 #2)
	NetLbRuleGet() ([]cmn.LbRuleMod, error)
	NetLbRuleAdd(*cmn.LbRuleMod) (int, error)
	NetLbRuleDel(*cmn.LbRuleMod) (int, error)

	// kvexactbinding (schema 1.1): per-rule KV-exact composed-binding
	// identity. Applied after loadbalancer (bindings belong to rules).
	NetKvExactBindingGet() ([]cmn.KvExactBindingMod, error)
	NetKvExactBindingAdd(*cmn.KvExactBindingMod) (int, error)
	NetKvExactBindingDel(*cmn.KvExactBindingMod) (int, error)

	// l7policy (schema 1.3): dedicated L7_POLICY resources. Applied after
	// loadbalancer (a policy attaches to a rule resolved by its stable
	// opaque id). Add validates, resolves the LB and attaches to the
	// dataplane; Del detaches and removes.
	NetL7PolicyGet() ([]cmn.L7PolicyArg, error)
	NetL7PolicyAdd(*cmn.L7PolicyArg) (int, error)
	NetL7PolicyDel(id string) (int, error)

	// firewall (§4.1 #3)
	NetFwRuleGet() ([]cmn.FwRuleMod, error)
	NetFwRuleAdd(*cmn.FwRuleMod) (int, error)
	NetFwRuleDel(*cmn.FwRuleMod) (int, error)

	// policy / QoS meter (§4.1 #4)
	NetPolicerGet() ([]cmn.PolMod, error)
	NetPolicerAdd(*cmn.PolMod) (int, error)
	NetPolicerDel(*cmn.PolMod) (int, error)

	// mirror (§4.1 #5)
	NetMirrorGet() ([]cmn.MirrGetMod, error)
	NetMirrorAdd(*cmn.MirrMod) (int, error)
	NetMirrorDel(*cmn.MirrMod) (int, error)

	// session (§4.1 #6)
	NetSessionGet() ([]cmn.SessionMod, error)
	NetSessionAdd(*cmn.SessionMod) (int, error)
	NetSessionDel(*cmn.SessionMod) (int, error)

	// sessionulcl (§4.1 #7)
	NetSessionUlClGet() ([]cmn.SessionUlClMod, error)
	NetSessionUlClAdd(*cmn.SessionUlClMod) (int, error)
	NetSessionUlClDel(*cmn.SessionUlClMod) (int, error)

	// ipfilter (§4.1 #8)
	NetIPFilterGet() ([]cmn.IPFilterEntry, error)
	NetIPFilterAdd(*cmn.IPFilterMod) (int, error)
	NetIPFilterDel(*cmn.IPFilterMod) (int, error)

	// securityrate (§4.1 #9) -- singleton, Set semantics
	NetSecurityRateGet() (*cmn.SecurityRateState, error)
	NetSecurityRateSet(*cmn.SecurityRateConfig) (int, error)

	// bfd (§4.1 #10)
	NetBFDGet() ([]cmn.BFDMod, error)
	NetBFDAdd(*cmn.BFDMod) (int, error)
	NetBFDDel(*cmn.BFDMod) (int, error)

	// bgp (§4.1 #11)
	NetGoBGPNeighGet() ([]cmn.GoBGPNeighGetMod, error)
	NetGoBGPNeighAdd(*cmn.GoBGPNeighMod) (int, error)
	NetGoBGPNeighDel(*cmn.GoBGPNeighMod) (int, error)
	// NetGoBGPGCGet returns the zero value (LocalAs 0) when global config
	// has not been set; it errors only on real failures (G-7).
	NetGoBGPGCGet() (cmn.GoBGPGlobalConfig, error)
	NetGoBGPGCAdd(*cmn.GoBGPGlobalConfig) (int, error)
	NetGoBGPPolicyDefinedSetGet(name string, definedTypeString string) ([]cmn.GoBGPPolicyDefinedSetMod, error)
	NetGoBGPPolicyDefinedSetAdd(*cmn.GoBGPPolicyDefinedSetMod) (int, error)
	NetGoBGPPolicyDefinedSetDel(*cmn.GoBGPPolicyDefinedSetMod) (int, error)
	NetGoBGPPolicyDefinitionsGet() ([]cmn.GoBGPPolicyDefinitionsMod, error)
	NetGoBGPPolicyDefinitionAdd(*cmn.GoBGPPolicyDefinitionsMod) (int, error)
	NetGoBGPPolicyDefinitionDel(*cmn.GoBGPPolicyDefinitionsMod) (int, error)

	// ipsec (§4.1 #12)
	NetIPsecGetConfig() (*cmn.IPsecConfig, error)
	NetIPsecConfigSet(*cmn.IPsecConfigMod) (int, error)
	NetIPsecTunnelGetAll() ([]*cmn.IPsecTunnel, error)
	NetIPsecTunnelAdd(*cmn.IPsecTunnelMod) (int, error)
	NetIPsecTunnelDel(name string) (int, error)
	NetIPsecCertificateGetAll() ([]*cmn.IPsecCertificate, error)
	NetIPsecCertificateAdd(*cmn.IPsecCertificateMod) (int, error)
	NetIPsecCertificateDel(name string) (int, error)
	NetIPsecCACertificateGetAll() ([]*cmn.IPsecCACertificate, error)
	NetIPsecCACertificateAdd(*cmn.IPsecCACertificateMod) (int, error)
	NetIPsecCACertificateDel(name string) (int, error)
	// PEM-bearing exports (G-3a): capture certificates in the exact Mod
	// shapes NetIPsecCertificateAdd/NetIPsecCACertificateAdd accept, so
	// snapshots round-trip. SENSITIVE (§8).
	NetIPsecCertificateExportAll() ([]cmn.IPsecCertificateMod, error)
	NetIPsecCACertificateExportAll() ([]cmn.IPsecCACertificateMod, error)
}

// DomainEntry describes one v1 snapshot domain: how to fetch its live
// config into a Document, how to apply a Document's items via hooks, and
// how to delete every item currently live for the domain via hooks. All
// three are dependency-injected on Hooks so callers (and unit tests)
// control exactly which backend they run against.
type DomainEntry struct {
	// Name is the domains.<name> JSON key (§4) and the valid `components`
	// value (task G-3) for this domain.
	Name string
	// Get fetches the live config for this domain and writes it into the
	// corresponding Domains field of doc.
	Get func(hooks Hooks, doc *Document) error
	// Apply reads the corresponding Domains field of doc and adds each item
	// via hooks. Returns the count of items successfully applied, the count
	// of items skipped as idempotent duplicates, and the first fatal error
	// encountered; per §5.3 step 5 a fatal error aborts remaining items in
	// the domain (the caller decides whether/how to proceed with other
	// domains and whether to roll back). When tolerateExists is true, an
	// item whose Add fails with the backend's idempotent "already exists"
	// convention (isIdempotentExists) is counted in skipped and the loop
	// continues -- the item's config is already live, so treating it as
	// fatal would throw away an entire domain over a no-op. Boot restores
	// and rollback re-applies set it; a post-wipe commit apply does not
	// (after a wipe, "exists" means the wipe failed and must surface).
	Apply func(hooks Hooks, doc *Document, tolerateExists bool) (applied int, skipped int, err error)
	// Delete fetches every item currently live for this domain (via hooks)
	// and deletes it. Returns the count deleted and the per-item delete
	// errors joined (nil on full success). Every item is attempted even
	// after an earlier item fails -- aborting a domain's teardown at the
	// first failing item leaves every item after it live while its
	// dependents may already be gone, a partial state that then poisons
	// both re-applies (spurious "exists") and dependent-domain deletes
	// ("still referred"). Used for both the pre-restore wipe and rollback
	// (§5.3).
	Delete func(hooks Hooks) (deleted int, err error)
}

// Registry is the ordered v1 domain table. Its order is exactly the §4.1
// table order (apply order: dependencies first, endpoint before
// loadbalancer, session before sessionulcl, etc.). See ApplyOrder/DeleteOrder.
var Registry = []DomainEntry{
	{Name: DomainEndpoint, Get: getEndpoint, Apply: applyEndpoint, Delete: deleteEndpoint},
	{Name: DomainLoadBalancer, Get: getLoadBalancer, Apply: applyLoadBalancer, Delete: deleteLoadBalancer},
	{Name: DomainKvExactBinding, Get: getKvExactBinding, Apply: applyKvExactBinding, Delete: deleteKvExactBinding},
	{Name: DomainL7Policy, Get: getL7Policy, Apply: applyL7Policy, Delete: deleteL7Policy},
	{Name: DomainFirewall, Get: getFirewall, Apply: applyFirewall, Delete: deleteFirewall},
	{Name: DomainPolicy, Get: getPolicy, Apply: applyPolicy, Delete: deletePolicy},
	{Name: DomainMirror, Get: getMirror, Apply: applyMirror, Delete: deleteMirror},
	{Name: DomainSession, Get: getSession, Apply: applySession, Delete: deleteSession},
	{Name: DomainSessionUlCl, Get: getSessionUlCl, Apply: applySessionUlCl, Delete: deleteSessionUlCl},
	{Name: DomainIPFilter, Get: getIPFilter, Apply: applyIPFilter, Delete: deleteIPFilter},
	{Name: DomainSecurityRate, Get: getSecurityRate, Apply: applySecurityRate, Delete: deleteSecurityRate},
	{Name: DomainBFD, Get: getBFD, Apply: applyBFD, Delete: deleteBFD},
	{Name: DomainBGP, Get: getBGP, Apply: applyBGP, Delete: deleteBGP},
	{Name: DomainIPsec, Get: getIPsec, Apply: applyIPsec, Delete: deleteIPsec},
}

// ApplyOrder returns the registry in apply order (table order, dependencies
// first), as a fresh copy: a caller sorting/truncating/reordering the
// returned slice cannot corrupt the package-global apply-order contract
// every other caller depends on.
func ApplyOrder() []DomainEntry {
	out := make([]DomainEntry, len(Registry))
	copy(out, Registry)
	return out
}

// DomainNames returns every registry domain name in apply order.
func DomainNames() []string {
	out := make([]string, len(Registry))
	for i, e := range Registry {
		out[i] = e.Name
	}
	return out
}

// DeleteOrder returns the registry in delete order: the exact reverse of
// ApplyOrder, so items are torn down in the opposite order they were built
// up in (e.g. loadbalancer before endpoint, since LB rules reference
// endpoints).
func DeleteOrder() []DomainEntry {
	out := make([]DomainEntry, len(Registry))
	for i, e := range Registry {
		out[len(Registry)-1-i] = e
	}
	return out
}

// Select returns the subset of Registry (in registry/apply order) whose
// Name appears in components. An empty or nil components selects every
// domain (the "default: all v1 domains" behavior specified for the
// `components` query parameter, §5.1). An unknown name is an error, naming
// the offending value, so a typo in `components` fails loudly rather than
// silently capturing fewer domains than the caller asked for.
func Select(components []string) ([]DomainEntry, error) {
	if len(components) == 0 {
		return Registry, nil
	}
	wanted := make(map[string]bool, len(components))
	for _, name := range components {
		wanted[name] = true
	}
	// Validate every requested name exists before filtering, so a typo
	// fails loudly rather than silently selecting fewer domains than asked.
	for name := range wanted {
		found := false
		for _, e := range Registry {
			if e.Name == name {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("snapshot: unknown domain %q in components", name)
		}
	}
	// Filter in registry (apply) order, not request order: apply/delete
	// ordering guarantees (§4.1) must hold regardless of how the caller
	// listed `components`.
	out := make([]DomainEntry, 0, len(components))
	for _, e := range Registry {
		if wanted[e.Name] {
			out = append(out, e)
		}
	}
	return out, nil
}

// isIdempotentExists reports whether err is the backend saying "this exact
// item already exists" -- a no-op duplicate, not a conflict. Two loxinet
// conventions cover it: the generic "already exists" texts (ipsec tunnels/
// certificates, endpoint hosts) and the per-domain "<kind>-exists error"
// sentinels returned when an Add finds a byte-identical item and short-
// circuits (e.g. pkg/loxinet/rules.go AddLbRule's "lbrule-exists error"
// when nothing about the rule changed). Deliberately NOT matched: the
// "-exist error: cant modify ..." texts (same key but DIFFERENT config --
// a real conflict) and anything carrying "not-exists" (delete-side "no
// such item" errors).
func isIdempotentExists(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	if strings.Contains(m, "not-exists") {
		return false
	}
	if strings.Contains(m, "already exists") {
		return true
	}
	for _, sentinel := range []string{
		"lbrule-exists error",
		"fwrule-exists error",
		"mirr-exists error",
		"pol-exists error",
		"sess-exists error",
		"ulcl-exists error",
		"prop-exists error",
		"l7policy-exists error",
	} {
		if strings.Contains(m, sentinel) {
			return true
		}
	}
	return false
}

// isSubsystemUnavailable reports whether err is an optional subsystem
// (BFD, BGP, IPsec) telling us it is not running/enabled on this gateway
// (loxinet nil-guard convention: "bfd session not running", "loxilb BGP
// mode is disabled", "IPsec not initialized", "running in bgp only mode").
// Capture and wipe treat such a domain as EMPTY -- a subsystem that is not
// running has no configuration to snapshot or delete, and failing the whole
// snapshot for it would make snapshots unusable on every gateway that does
// not enable all optional daemons (found live in testbed E2E, 2026-07-20).
// Apply is deliberately NOT tolerant: restoring a document that carries
// e.g. BGP config onto a gateway with BGP disabled must fail loudly.
func isSubsystemUnavailable(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "not running") ||
		strings.Contains(m, "mode is disabled") ||
		strings.Contains(m, "not initialized") ||
		strings.Contains(m, "bgp only mode") ||
		// gRPC-backed subsystems (gobgpd) surface "not up yet" as a
		// transport error, not a domain message -- during startup the
		// daemon's socket simply is not listening. Discovered live: boot
		// capture/verify hit "rpc error: code = Unavailable ...
		// connection refused" while gobgpd was still starting.
		strings.Contains(m, "code = unavailable") ||
		strings.Contains(m, "connection refused") ||
		// gobgpd answers this until loxilb's global-config push runs
		// StartBgp -- same startup window, different message.
		strings.Contains(m, "hasn't started") ||
		// gobgpd's ListDefinedSet rejects even the valid PREFIX type with
		// this message until the speaker's policy table initializes --
		// one more shape of the same startup window (only gobgp emits it).
		strings.Contains(m, "invalid defined-set type")
}

// ---------------------------------------------------------------------
// 1. endpoint
// ---------------------------------------------------------------------

func getEndpoint(hooks Hooks, doc *Document) error {
	eps, err := hooks.NetEpHostGet()
	if err != nil {
		return fmt.Errorf("get endpoint: %w", err)
	}
	// Rule-managed end-points (EndPointMod.RuleManaged: entries that exist
	// only because an LB rule references them) are excluded: applying the
	// loadbalancer domain recreates them, so capturing them would
	// double-apply on restore and break VERIFY's per-domain counts (which
	// re-Get through this same filter). Found live in testbed E2E.
	kept := make([]cmn.EndPointMod, 0, len(eps))
	for _, ep := range eps {
		if ep.RuleManaged {
			continue
		}
		kept = append(kept, ep)
	}
	doc.Domains.Endpoint = kept
	return nil
}

func applyEndpoint(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.Endpoint {
		ep := &doc.Domains.Endpoint[i]
		if _, err := hooks.NetEpHostAdd(ep); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply endpoint %q: %w", ep.Name, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteEndpoint(hooks Hooks) (int, error) {
	eps, err := hooks.NetEpHostGet()
	if err != nil {
		return 0, fmt.Errorf("delete endpoint: get: %w", err)
	}
	n := 0
	var errs []error
	for i := range eps {
		ep := &eps[i]
		// Rule-managed end-points live and die with the LB rule that
		// references them (deleting that rule removes them); deleting them
		// here fails with "rule-referred" while the rule exists and is a
		// double-delete once it is gone. The capture side filters them for
		// the same reason (getEndpoint above).
		if ep.RuleManaged {
			continue
		}
		if _, err := hooks.NetEpHostDel(ep); err != nil {
			errs = append(errs, fmt.Errorf("delete endpoint %q: %w", ep.Name, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 2. loadbalancer
// ---------------------------------------------------------------------

func getLoadBalancer(hooks Hooks, doc *Document) error {
	rules, err := hooks.NetLbRuleGet()
	if err != nil {
		return fmt.Errorf("get loadbalancer: %w", err)
	}
	doc.Domains.LoadBalancer = rules
	return nil
}

func applyLoadBalancer(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.LoadBalancer {
		lb := &doc.Domains.LoadBalancer[i]
		// Restore replay, not a fresh POST: a strict KV-exact rule must not
		// allocate a new binding generation here — the kvexactbinding domain
		// applies right after this one and carries the authoritative binding,
		// including the allocation high-water mark that prevents a restarted
		// allocator from reissuing a generation that may still be in flight.
		lb.Serv.RestoreReplay = true
		if _, err := hooks.NetLbRuleAdd(lb); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply loadbalancer %q: %w", lb.Serv.ServIP, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteLoadBalancer(hooks Hooks) (int, error) {
	rules, err := hooks.NetLbRuleGet()
	if err != nil {
		return 0, fmt.Errorf("delete loadbalancer: get: %w", err)
	}
	n := 0
	var errs []error
	for i := range rules {
		lb := &rules[i]
		if _, err := hooks.NetLbRuleDel(lb); err != nil {
			errs = append(errs, fmt.Errorf("delete loadbalancer %q: %w", lb.Serv.ServIP, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 2b. kvexactbinding (schema 1.1)
//
// Bindings apply after loadbalancer (they reference rules by identity) and
// delete before it in DeleteOrder's reversal (binding state goes away
// before the rule it describes).
// ---------------------------------------------------------------------

func getKvExactBinding(hooks Hooks, doc *Document) error {
	binds, err := hooks.NetKvExactBindingGet()
	if err != nil {
		return fmt.Errorf("get kvexactbinding: %w", err)
	}
	doc.Domains.KvExactBinding = binds
	return nil
}

func applyKvExactBinding(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.KvExactBinding {
		b := &doc.Domains.KvExactBinding[i]
		if _, err := hooks.NetKvExactBindingAdd(b); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply kvexactbinding %q: %w", b.RuleIdent, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteKvExactBinding(hooks Hooks) (int, error) {
	binds, err := hooks.NetKvExactBindingGet()
	if err != nil {
		return 0, fmt.Errorf("delete kvexactbinding: get: %w", err)
	}
	n := 0
	var errs []error
	for i := range binds {
		b := &binds[i]
		if _, err := hooks.NetKvExactBindingDel(b); err != nil {
			errs = append(errs, fmt.Errorf("delete kvexactbinding %q: %w", b.RuleIdent, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 2c. l7policy (schema 1.3)
//
// Dedicated L7_POLICY resources: ordered content routes attached to an L4
// LB by its stable opaque id. Applied after loadbalancer (the referenced
// rule must be live for the attach to succeed) and deleted before it in
// DeleteOrder's reversal. Add validates server-side and fails loudly on a
// missing LB or a failed dataplane attach -- a policy that cannot be
// enforced must fail the domain (and with it a boot generation), never
// silently restore as allow-all.
// ---------------------------------------------------------------------

func getL7Policy(hooks Hooks, doc *Document) error {
	pols, err := hooks.NetL7PolicyGet()
	if isSubsystemUnavailable(err) {
		doc.Domains.L7Policy = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("get l7policy: %w", err)
	}
	doc.Domains.L7Policy = pols
	return nil
}

func applyL7Policy(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.L7Policy {
		p := &doc.Domains.L7Policy[i]
		if _, err := hooks.NetL7PolicyAdd(p); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply l7policy %q: %w", p.Id, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteL7Policy(hooks Hooks) (int, error) {
	pols, err := hooks.NetL7PolicyGet()
	if isSubsystemUnavailable(err) {
		return 0, nil // subsystem not running: nothing to delete
	}
	if err != nil {
		return 0, fmt.Errorf("delete l7policy: get: %w", err)
	}
	n := 0
	var errs []error
	for i := range pols {
		if _, err := hooks.NetL7PolicyDel(pols[i].Id); err != nil {
			errs = append(errs, fmt.Errorf("delete l7policy %q: %w", pols[i].Id, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 3. firewall
//
// SrcChk-mark (0x40000000) rules are auto-generated internal plumbing, not
// user config -- excluded from both capture and delete, mirroring
// api/restapi/handler/backup.go:228 (GetFirewallConfig). See §4.1 #3.
// ---------------------------------------------------------------------

// srcChkFwMark is the firewall option Mark value that identifies an
// auto-generated source-check rule (api/restapi/handler/backup.go:228).
const srcChkFwMark = 0x40000000

func filterSrcChkRules(rules []cmn.FwRuleMod) []cmn.FwRuleMod {
	var out []cmn.FwRuleMod
	for _, fw := range rules {
		if fw.Opts.Mark&srcChkFwMark != 0 {
			continue
		}
		out = append(out, fw)
	}
	return out
}

func getFirewall(hooks Hooks, doc *Document) error {
	rules, err := hooks.NetFwRuleGet()
	if err != nil {
		return fmt.Errorf("get firewall: %w", err)
	}
	doc.Domains.Firewall = filterSrcChkRules(rules)
	return nil
}

func applyFirewall(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.Firewall {
		fw := &doc.Domains.Firewall[i]
		if _, err := hooks.NetFwRuleAdd(fw); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply firewall rule: %w", err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteFirewall(hooks Hooks) (int, error) {
	rules, err := hooks.NetFwRuleGet()
	if err != nil {
		return 0, fmt.Errorf("delete firewall: get: %w", err)
	}
	rules = filterSrcChkRules(rules)
	n := 0
	var errs []error
	for i := range rules {
		fw := &rules[i]
		if _, err := hooks.NetFwRuleDel(fw); err != nil {
			errs = append(errs, fmt.Errorf("delete firewall rule: %w", err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 4. policy (QoS/meter)
// ---------------------------------------------------------------------

func getPolicy(hooks Hooks, doc *Document) error {
	pols, err := hooks.NetPolicerGet()
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}
	doc.Domains.Policy = pols
	return nil
}

func applyPolicy(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.Policy {
		p := &doc.Domains.Policy[i]
		if _, err := hooks.NetPolicerAdd(p); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply policy %q: %w", p.Ident, err)
		}
		n++
	}
	return n, skipped, nil
}

func deletePolicy(hooks Hooks) (int, error) {
	pols, err := hooks.NetPolicerGet()
	if err != nil {
		return 0, fmt.Errorf("delete policy: get: %w", err)
	}
	n := 0
	var errs []error
	for i := range pols {
		p := &pols[i]
		if _, err := hooks.NetPolicerDel(p); err != nil {
			errs = append(errs, fmt.Errorf("delete policy %q: %w", p.Ident, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 5. mirror
//
// Get returns cmn.MirrGetMod (adds a Sync status field); Add/Del take
// cmn.MirrMod. The two share Ident/Info/Target, so mirrGetToMod projects
// down to what Add/Del need.
// ---------------------------------------------------------------------

func mirrGetToMod(m cmn.MirrGetMod) *cmn.MirrMod {
	return &cmn.MirrMod{Ident: m.Ident, Info: m.Info, Target: m.Target}
}

func getMirror(hooks Hooks, doc *Document) error {
	mirrs, err := hooks.NetMirrorGet()
	if err != nil {
		return fmt.Errorf("get mirror: %w", err)
	}
	doc.Domains.Mirror = mirrs
	return nil
}

func applyMirror(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for _, m := range doc.Domains.Mirror {
		if _, err := hooks.NetMirrorAdd(mirrGetToMod(m)); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply mirror %q: %w", m.Ident, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteMirror(hooks Hooks) (int, error) {
	mirrs, err := hooks.NetMirrorGet()
	if err != nil {
		return 0, fmt.Errorf("delete mirror: get: %w", err)
	}
	n := 0
	var errs []error
	for _, m := range mirrs {
		if _, err := hooks.NetMirrorDel(mirrGetToMod(m)); err != nil {
			errs = append(errs, fmt.Errorf("delete mirror %q: %w", m.Ident, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 6. session
// ---------------------------------------------------------------------

func getSession(hooks Hooks, doc *Document) error {
	sess, err := hooks.NetSessionGet()
	if err != nil {
		return fmt.Errorf("get session: %w", err)
	}
	doc.Domains.Session = sess
	return nil
}

func applySession(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.Session {
		s := &doc.Domains.Session[i]
		if _, err := hooks.NetSessionAdd(s); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply session %q: %w", s.Ident, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteSession(hooks Hooks) (int, error) {
	sess, err := hooks.NetSessionGet()
	if err != nil {
		return 0, fmt.Errorf("delete session: get: %w", err)
	}
	n := 0
	var errs []error
	for i := range sess {
		s := &sess[i]
		if _, err := hooks.NetSessionDel(s); err != nil {
			errs = append(errs, fmt.Errorf("delete session %q: %w", s.Ident, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 7. sessionulcl (must apply/delete alongside session -- §4.1 #7 "after
// session"; enforced by registry table order / DeleteOrder, not here)
// ---------------------------------------------------------------------

func getSessionUlCl(hooks Hooks, doc *Document) error {
	ulcl, err := hooks.NetSessionUlClGet()
	if err != nil {
		return fmt.Errorf("get sessionulcl: %w", err)
	}
	doc.Domains.SessionUlCl = ulcl
	return nil
}

func applySessionUlCl(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.SessionUlCl {
		s := &doc.Domains.SessionUlCl[i]
		if _, err := hooks.NetSessionUlClAdd(s); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply sessionulcl %q: %w", s.Ident, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteSessionUlCl(hooks Hooks) (int, error) {
	ulcl, err := hooks.NetSessionUlClGet()
	if err != nil {
		return 0, fmt.Errorf("delete sessionulcl: get: %w", err)
	}
	n := 0
	var errs []error
	for i := range ulcl {
		s := &ulcl[i]
		if _, err := hooks.NetSessionUlClDel(s); err != nil {
			errs = append(errs, fmt.Errorf("delete sessionulcl %q: %w", s.Ident, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 8. ipfilter
//
// Get returns cmn.IPFilterEntry (embeds IPFilterMod + Packets/Bytes
// counters); Add/Del take cmn.IPFilterMod. IPFilterEntry.IPFilterMod is the
// exact projection needed.
// ---------------------------------------------------------------------

func getIPFilter(hooks Hooks, doc *Document) error {
	entries, err := hooks.NetIPFilterGet()
	if err != nil {
		return fmt.Errorf("get ipfilter: %w", err)
	}
	doc.Domains.IPFilter = entries
	return nil
}

func applyIPFilter(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.IPFilter {
		mod := doc.Domains.IPFilter[i].IPFilterMod
		if _, err := hooks.NetIPFilterAdd(&mod); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply ipfilter %s: %w", mod.CIDR, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteIPFilter(hooks Hooks) (int, error) {
	entries, err := hooks.NetIPFilterGet()
	if err != nil {
		return 0, fmt.Errorf("delete ipfilter: get: %w", err)
	}
	n := 0
	var errs []error
	for i := range entries {
		mod := entries[i].IPFilterMod
		if _, err := hooks.NetIPFilterDel(&mod); err != nil {
			errs = append(errs, fmt.Errorf("delete ipfilter %s: %w", mod.CIDR, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 9. securityrate -- singleton, Set semantics (§4.1 #9)
//
// Get returns config+stats combined; only Config is meaningful to
// apply/restore (Stats is live counters, not configuration). There is no
// per-item delete for a singleton: deleteSecurityRate resets Config to its
// zero value (all protections disabled) as the closest available
// approximation of "remove this domain's config" -- NetSecurityRateResetStats
// only clears counters, not the config, so it cannot be used here.
// ---------------------------------------------------------------------

func getSecurityRate(hooks Hooks, doc *Document) error {
	state, err := hooks.NetSecurityRateGet()
	if isSubsystemUnavailable(err) {
		doc.Domains.SecurityRate = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("get securityrate: %w", err)
	}
	if state == nil {
		doc.Domains.SecurityRate = nil
		return nil
	}
	// Deep-copy and keep Config only: the hook may return a pointer into
	// live state (a later live update must not silently rewrite an
	// already-captured document), and Stats is runtime counters, not
	// desired configuration -- persisting it made every idle persist churn
	// the document checksum and leaked meaningless numbers into restores.
	doc.Domains.SecurityRate = &cmn.SecurityRateState{Config: state.Config}
	return nil
}

func applySecurityRate(hooks Hooks, doc *Document, _ bool) (int, int, error) {
	// Singleton with Set (overwrite) semantics: there is no "exists"
	// failure mode to tolerate.
	if doc.Domains.SecurityRate == nil {
		return 0, 0, nil
	}
	cfg := doc.Domains.SecurityRate.Config
	if _, err := hooks.NetSecurityRateSet(&cfg); err != nil {
		return 0, 0, fmt.Errorf("apply securityrate: %w", err)
	}
	return 1, 0, nil
}

func deleteSecurityRate(hooks Hooks) (int, error) {
	// No per-item delete exists for this singleton; the nearest equivalent
	// available via Hooks is to Set the zero-value (all-disabled) config.
	if _, err := hooks.NetSecurityRateSet(&cmn.SecurityRateConfig{}); err != nil {
		return 0, fmt.Errorf("delete securityrate: %w", err)
	}
	return 1, nil
}

// ---------------------------------------------------------------------
// 10. bfd
// ---------------------------------------------------------------------

func getBFD(hooks Hooks, doc *Document) error {
	bfd, err := hooks.NetBFDGet()
	if isSubsystemUnavailable(err) {
		doc.Domains.BFD = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("get bfd: %w", err)
	}
	doc.Domains.BFD = bfd
	return nil
}

func applyBFD(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	for i := range doc.Domains.BFD {
		b := &doc.Domains.BFD[i]
		if _, err := hooks.NetBFDAdd(b); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply bfd %q: %w", b.Instance, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteBFD(hooks Hooks) (int, error) {
	bfd, err := hooks.NetBFDGet()
	if isSubsystemUnavailable(err) {
		return 0, nil // subsystem not running: nothing to delete
	}
	if err != nil {
		return 0, fmt.Errorf("delete bfd: get: %w", err)
	}
	n := 0
	var errs []error
	for i := range bfd {
		b := &bfd[i]
		if _, err := hooks.NetBFDDel(b); err != nil {
			errs = append(errs, fmt.Errorf("delete bfd %q: %w", b.Instance, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 11. bgp (composite: neighbors, defined_sets, policy_definitions,
// global_config) -- §4.1 #11
//
// bgpDefinedSetTypes enumerates every DefinedType GoBGP supports (mirroring
// pkg/loxinet/gobgpclient.go GetPolicyDefinedSet's switch). There is no
// "get every type" GoBGP call -- NetGoBGPPolicyDefinedSetGet(name, type)
// requires a type, and name="all" is the sentinel for "every set of that
// type" (see GetPolicyDefinedSet), so capturing the whole domain means
// looping over every known type with name="all".
// ---------------------------------------------------------------------

var bgpDefinedSetTypes = []string{"prefix", "neigh", "community", "extCommunity", "largeCommunity", "asPath"}

// bgpManagedPolicySuffix marks policy definitions the gateway creates and
// owns itself (pkg/loxinet/gobgpclient.go: set-next-hop-self-gpolicy,
// set-llb-export-gpolicy). They are excluded from capture and wipe: the
// speaker machinery recreates them, so they are not operator desired
// state, and deleting them would break the LB export/HA path.
const bgpManagedPolicySuffix = "-gpolicy"

// bgpNeighGetModToMod converts the Get-shaped cmn.GoBGPNeighGetMod back into
// the Add/Del-shaped cmn.GoBGPNeighMod. RemotePort and MultiHop round-trip
// through the Get shape (additive fields; a zero RemotePort means "default"
// and the Add path normalizes it to 179), so restored neighbors keep their
// transport configuration instead of silently reverting to defaults.
func bgpNeighGetModToMod(n cmn.GoBGPNeighGetMod) *cmn.GoBGPNeighMod {
	return &cmn.GoBGPNeighMod{
		Addr:       net.ParseIP(n.Addr),
		RemoteAS:   n.RemoteAS,
		RemotePort: n.RemotePort,
		MultiHop:   n.MultiHop,
	}
}

func getBGP(hooks Hooks, doc *Document) error {
	neighbors, err := hooks.NetGoBGPNeighGet()
	if isSubsystemUnavailable(err) {
		doc.Domains.BGP = BGPDomain{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get bgp neighbors: %w", err)
	}

	var definedSets []cmn.GoBGPPolicyDefinedSetMod
	for _, ts := range bgpDefinedSetTypes {
		sets, err := hooks.NetGoBGPPolicyDefinedSetGet("all", ts)
		if err != nil {
			return fmt.Errorf("get bgp defined_sets (%s): %w", ts, err)
		}
		definedSets = append(definedSets, sets...)
	}

	policyDefs, err := hooks.NetGoBGPPolicyDefinitionsGet()
	if err != nil {
		return fmt.Errorf("get bgp policy_definitions: %w", err)
	}
	// Gateway-managed policies (the "-gpolicy" convention: next-hop-self,
	// LB export MED/local-pref) are (re)created by the speaker machinery
	// itself -- capturing them double-applies on restore ("statement
	// already defined") exactly like rule-managed endpoints would. Same
	// filter discipline: operator config only.
	kept := make([]cmn.GoBGPPolicyDefinitionsMod, 0, len(policyDefs))
	for _, pd := range policyDefs {
		if strings.HasSuffix(pd.Name, bgpManagedPolicySuffix) {
			continue
		}
		kept = append(kept, pd)
	}

	doc.Domains.BGP = BGPDomain{
		Neighbors:         neighbors,
		DefinedSets:       definedSets,
		PolicyDefinitions: kept,
	}

	// G-7: capture global config; zero LocalAs means "not configured" and
	// keeps GlobalConfig nil (omitempty).
	gc, err := hooks.NetGoBGPGCGet()
	if isSubsystemUnavailable(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get bgp global_config: %w", err)
	}
	if gc.LocalAs != 0 {
		doc.Domains.BGP.GlobalConfig = &gc
	}
	return nil
}

func applyBGP(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	// Global config FIRST: pushing it is what STARTS the BGP speaker, and
	// every other item (AddPeer above all) is refused with "bgp server
	// hasn't started yet" until then. With global config applied last, a
	// boot replay of a neighbor-bearing snapshot deadlocked forever:
	// every retry failed on the first neighbor before ever reaching the
	// one item that would have started the speaker (observed live).
	if doc.Domains.BGP.GlobalConfig != nil {
		// Set-semantics singleton (overwrite): no "exists" to tolerate.
		if _, err := hooks.NetGoBGPGCAdd(doc.Domains.BGP.GlobalConfig); err != nil {
			return n, skipped, fmt.Errorf("apply bgp global_config: %w", err)
		}
		n++
	}
	for _, nb := range doc.Domains.BGP.Neighbors {
		if _, err := hooks.NetGoBGPNeighAdd(bgpNeighGetModToMod(nb)); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply bgp neighbor %s: %w", nb.Addr, err)
		}
		n++
	}
	for i := range doc.Domains.BGP.DefinedSets {
		ds := &doc.Domains.BGP.DefinedSets[i]
		if _, err := hooks.NetGoBGPPolicyDefinedSetAdd(ds); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply bgp defined_set %q: %w", ds.Name, err)
		}
		n++
	}
	for i := range doc.Domains.BGP.PolicyDefinitions {
		pd := &doc.Domains.BGP.PolicyDefinitions[i]
		if _, err := hooks.NetGoBGPPolicyDefinitionAdd(pd); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply bgp policy_definition %q: %w", pd.Name, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteBGP(hooks Hooks) (int, error) {
	n := 0
	var errs []error

	neighbors, err := hooks.NetGoBGPNeighGet()
	if isSubsystemUnavailable(err) {
		return 0, nil // subsystem not running: nothing to delete
	}
	if err != nil {
		return n, fmt.Errorf("delete bgp: get neighbors: %w", err)
	}
	for _, nb := range neighbors {
		if _, err := hooks.NetGoBGPNeighDel(bgpNeighGetModToMod(nb)); err != nil {
			errs = append(errs, fmt.Errorf("delete bgp neighbor %s: %w", nb.Addr, err))
			continue
		}
		n++
	}

	for _, ts := range bgpDefinedSetTypes {
		sets, err := hooks.NetGoBGPPolicyDefinedSetGet("all", ts)
		if isSubsystemUnavailable(err) {
			continue // speaker (still) not up for this call: nothing to delete
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("delete bgp: get defined_sets (%s): %w", ts, err))
			continue
		}
		for i := range sets {
			ds := &sets[i]
			if _, err := hooks.NetGoBGPPolicyDefinedSetDel(ds); err != nil {
				errs = append(errs, fmt.Errorf("delete bgp defined_set %q: %w", ds.Name, err))
				continue
			}
			n++
		}
	}

	policyDefs, err := hooks.NetGoBGPPolicyDefinitionsGet()
	if isSubsystemUnavailable(err) {
		return n, errors.Join(errs...)
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("delete bgp: get policy_definitions: %w", err))
		return n, errors.Join(errs...)
	}
	for i := range policyDefs {
		pd := &policyDefs[i]
		// Gateway-managed policies stay: the speaker machinery owns them
		// (see bgpManagedPolicySuffix) and the LB export path needs them.
		if strings.HasSuffix(pd.Name, bgpManagedPolicySuffix) {
			continue
		}
		if _, err := hooks.NetGoBGPPolicyDefinitionDel(pd); err != nil {
			errs = append(errs, fmt.Errorf("delete bgp policy_definition %q: %w", pd.Name, err))
			continue
		}
		n++
	}

	// No delete hook exists for BGP global config (NetGoBGPGCAdd has no
	// counterpart) -- nothing to do here even once TODO(G-7) lands, unless a
	// future hook adds one.
	return n, errors.Join(errs...)
}

// ---------------------------------------------------------------------
// 12. ipsec (composite: config, tunnels, certificates, ca_certificates)
// §4.1 #12 -- SENSITIVE, see §8 and IPsecDomain's doc comment for the
// certificate-PEM round-trip gap discovered while wiring this domain.
// ---------------------------------------------------------------------

// ipsecConfigToMod converts the full cmn.IPsecConfig (GET shape) into the
// pointer-optional cmn.IPsecConfigMod (SET shape), setting every field so a
// restore fully overwrites, rather than partially patches, the live config.
func ipsecConfigToMod(c cmn.IPsecConfig) *cmn.IPsecConfigMod {
	fastPath := c.FastPathEnabled
	hwOffload := c.HwOffloadEnabled
	hwOffloadType := c.HwOffloadType
	antiReplay := c.AntiReplayEnabled
	saWarn := c.SALifetimeWarnSeconds
	seqOverflow := c.SeqOverflowAction
	mtu := c.MTU
	return &cmn.IPsecConfigMod{
		FastPathEnabled:       &fastPath,
		HwOffloadEnabled:      &hwOffload,
		HwOffloadType:         &hwOffloadType,
		AntiReplayEnabled:     &antiReplay,
		SALifetimeWarnSeconds: &saWarn,
		SeqOverflowAction:     &seqOverflow,
		MTU:                   &mtu,
	}
}

func getIPsec(hooks Hooks, doc *Document) error {
	cfg, err := hooks.NetIPsecGetConfig()
	if isSubsystemUnavailable(err) {
		doc.Domains.IPsec = IPsecDomain{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get ipsec config: %w", err)
	}
	tunnels, err := hooks.NetIPsecTunnelGetAll()
	if err != nil {
		return fmt.Errorf("get ipsec tunnels: %w", err)
	}
	certs, err := hooks.NetIPsecCertificateExportAll()
	if err != nil {
		return fmt.Errorf("get ipsec certificates: %w", err)
	}
	caCerts, err := hooks.NetIPsecCACertificateExportAll()
	if err != nil {
		return fmt.Errorf("get ipsec ca_certificates: %w", err)
	}
	doc.Domains.IPsec = IPsecDomain{
		Config:         cfg,
		Tunnels:        tunnels,
		Certificates:   certs,
		CACertificates: caCerts,
	}
	return nil
}

func applyIPsec(hooks Hooks, doc *Document, tolerateExists bool) (int, int, error) {
	n, skipped := 0, 0
	if doc.Domains.IPsec.Config != nil {
		// Set-semantics singleton (overwrite): no "exists" to tolerate.
		if _, err := hooks.NetIPsecConfigSet(ipsecConfigToMod(*doc.Domains.IPsec.Config)); err != nil {
			return n, skipped, fmt.Errorf("apply ipsec config: %w", err)
		}
		n++
	}
	// Certificates before tunnels: tunnels in certificate auth mode
	// reference an installed certificate by CertName. A cert whose private
	// key was uploaded passphrase-encrypted fails Add validation here
	// (passphrase is never persisted -- see IPsecDomain doc comment).
	for _, ca := range doc.Domains.IPsec.CACertificates {
		if _, err := hooks.NetIPsecCACertificateAdd(&ca); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply ipsec ca_certificate %q: %w", ca.Name, err)
		}
		n++
	}
	for _, c := range doc.Domains.IPsec.Certificates {
		if _, err := hooks.NetIPsecCertificateAdd(&c); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply ipsec certificate %q: %w", c.Name, err)
		}
		n++
	}
	for _, t := range doc.Domains.IPsec.Tunnels {
		if t == nil {
			continue
		}
		mod := t.IPsecTunnelMod
		if _, err := hooks.NetIPsecTunnelAdd(&mod); err != nil {
			if tolerateExists && isIdempotentExists(err) {
				skipped++
				continue
			}
			return n, skipped, fmt.Errorf("apply ipsec tunnel %q: %w", t.Name, err)
		}
		n++
	}
	return n, skipped, nil
}

func deleteIPsec(hooks Hooks) (int, error) {
	n := 0
	var errs []error

	tunnels, err := hooks.NetIPsecTunnelGetAll()
	if isSubsystemUnavailable(err) {
		return 0, nil // subsystem not running: nothing to delete
	}
	if err != nil {
		return n, fmt.Errorf("delete ipsec: get tunnels: %w", err)
	}
	for _, t := range tunnels {
		if t == nil {
			continue
		}
		if _, err := hooks.NetIPsecTunnelDel(t.Name); err != nil {
			errs = append(errs, fmt.Errorf("delete ipsec tunnel %q: %w", t.Name, err))
			continue
		}
		n++
	}

	// Deleting certificates/CA-certificates by name works fine even though
	// re-applying them does not (delete only needs the name, not the PEM
	// data) -- see the Apply-side gap note above.
	certs, err := hooks.NetIPsecCertificateGetAll()
	if err != nil {
		errs = append(errs, fmt.Errorf("delete ipsec: get certificates: %w", err))
		return n, errors.Join(errs...)
	}
	for _, c := range certs {
		if c == nil {
			continue
		}
		if _, err := hooks.NetIPsecCertificateDel(c.Name); err != nil {
			errs = append(errs, fmt.Errorf("delete ipsec certificate %q: %w", c.Name, err))
			continue
		}
		n++
	}

	caCerts, err := hooks.NetIPsecCACertificateGetAll()
	if err != nil {
		errs = append(errs, fmt.Errorf("delete ipsec: get ca_certificates: %w", err))
		return n, errors.Join(errs...)
	}
	for _, c := range caCerts {
		if c == nil {
			continue
		}
		if _, err := hooks.NetIPsecCACertificateDel(c.Name); err != nil {
			errs = append(errs, fmt.Errorf("delete ipsec ca_certificate %q: %w", c.Name, err))
			continue
		}
		n++
	}

	// No delete for ipsec Config: it is a singleton, and there is no
	// "unset"/reset-to-default hook exposed beyond NetIPsecConfigSet, which
	// requires the caller to already know defaults -- left as a no-op,
	// mirroring securityrate's own singleton caveat but without even a
	// zero-value Set to fall back on (IPsecConfigMod's pointer fields would
	// need real default values, not just zero values, to be safe).
	return n, errors.Join(errs...)
}
