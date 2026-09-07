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
	"fmt"
	"reflect"

	cmn "github.com/loxilb-io/loxilb/common"
)

// mockHooks is a minimal, in-memory implementation of the Hooks interface
// (registry.go) for unit testing the domain registry, the restore engine
// (restore.go, task G-2) and the wipe primitive (wipe.go, task G-6) without
// touching pkg/loxinet. It records every call in Calls (in call order) so
// tests can assert both the data effects and the order/shape of hook
// invocations (e.g. that bgp defined_sets Get loops over every DefinedType).
//
// Extended for G-2/G-6 (originally G-1-only): every Add/Del now actually
// mutates the in-memory store (G-1's version only mutated a handful of
// domains -- fine for registry-level Get/Apply/Delete unit tests, but the
// restore engine's PLAN/VERIFY stages re-Get after Apply/Wipe and need to
// observe real effects). failOn/lenOverride give tests single-shot control
// over any hook call by name, for injecting mid-apply failures, "already
// exists" rollback-tolerance errors, and VERIFY-mismatch drift.
type mockHooks struct {
	Calls []string

	endpoints []cmn.EndPointMod
	lbRules   []cmn.LbRuleMod
	kvBinds   []cmn.KvExactBindingMod
	fwRules   []cmn.FwRuleMod
	policies  []cmn.PolMod
	mirrors   []cmn.MirrGetMod
	sessions  []cmn.SessionMod
	ulcl      []cmn.SessionUlClMod
	ipFilters []cmn.IPFilterEntry
	secRate   *cmn.SecurityRateState
	bfds      []cmn.BFDMod

	bgpNeighbors  []cmn.GoBGPNeighGetMod
	bgpDefined    map[string][]cmn.GoBGPPolicyDefinedSetMod // by DefinedTypeString
	bgpPolicyDefs []cmn.GoBGPPolicyDefinitionsMod
	bgpGC         *cmn.GoBGPGlobalConfig

	ipsecConfig  *cmn.IPsecConfig
	ipsecTunnels []*cmn.IPsecTunnel
	ipsecCerts   []*cmn.IPsecCertificate
	ipsecCAs     []*cmn.IPsecCACertificate
	// PEM-bearing mirrors of ipsecCerts/ipsecCAs (G-3a): Add appends to
	// both stores, Del filters both, so GetAll (metadata, wipe/delete) and
	// ExportAll (capture) stay consistent like the real IPsecH.
	ipsecCertMods []cmn.IPsecCertificateMod
	ipsecCAMods   []cmn.IPsecCACertificateMod

	// failOn, keyed by hook method name (e.g. "NetLbRuleAdd"), makes the
	// next call to that hook fail once with the given error, then clears
	// itself (single-shot) so subsequent calls (e.g. during rollback)
	// succeed normally.
	failOn map[string]error
	// failOnCall, keyed by "<op>#<call-number>" (1-indexed, e.g.
	// "NetEpHostAdd#2"), makes the Nth call to that hook fail with the
	// given error regardless of failOn -- for tests that need the FIRST
	// call to an op to succeed (e.g. the forward-apply phase) and a LATER
	// call to the same op to fail (e.g. the rollback re-apply phase), which
	// failOn's single-shot-on-next-call semantics can't express.
	failOnCall map[string]error

	// lenOverride, keyed by hook method name (e.g. "NetLbRuleGet"), makes
	// the next call to that Get hook return a slice resized (truncated or
	// zero-padded) to the given length instead of the real stored length --
	// single-shot, used to simulate VERIFY-stage drift (the backend
	// reports a different count than what was actually applied) without
	// otherwise corrupting the mock's state for later calls (e.g. rollback).
	lenOverride map[string]int
	// lenOverrideCall, keyed by "<op>#<call-number>", is the call-indexed
	// counterpart of lenOverride -- needed because a single restore pass
	// calls a domain's Get hook multiple times (PLAN, PRESERVE, the
	// pre-apply wipe's enumeration, VERIFY), and a VERIFY-mismatch test
	// must target VERIFY's call specifically, not whichever comes first.
	lenOverrideCall map[string]int

	// mutateAt, keyed by "<op>#<call-number>", runs the given function just
	// before the Nth call to the named Get hook builds its return value --
	// for simulating a backend whose stored content DRIFTED between apply
	// and a later re-Get (field corruption, runtime fields filled in),
	// which lenOverride's count-only resizing cannot express.
	mutateAt map[string]func()

	// callCounts tracks how many times each hook has been called (1-indexed
	// on first call), backing failOnCall, lenOverrideCall and mutateAt.
	callCounts map[string]int
}

func newMockHooks() *mockHooks {
	return &mockHooks{
		bgpDefined:      make(map[string][]cmn.GoBGPPolicyDefinedSetMod),
		failOn:          make(map[string]error),
		failOnCall:      make(map[string]error),
		lenOverride:     make(map[string]int),
		lenOverrideCall: make(map[string]int),
		mutateAt:        make(map[string]func()),
		callCounts:      make(map[string]int),
	}
}

func (m *mockHooks) log(format string, a ...interface{}) {
	m.Calls = append(m.Calls, fmt.Sprintf(format, a...))
}

// callSeq increments and returns the 1-indexed call count for op, shared by
// failIfConfigured and resizeOverride so a "which call number is this"
// question has one authoritative counter per op.
func (m *mockHooks) callSeq(op string) int {
	m.callCounts[op]++
	return m.callCounts[op]
}

func (m *mockHooks) failIfConfigured(op string) error {
	n := m.callSeq(op)
	if err, ok := m.failOn[op]; ok {
		delete(m.failOn, op)
		return err
	}
	if err, ok := m.failOnCall[fmt.Sprintf("%s#%d", op, n)]; ok {
		return err
	}
	return nil
}

// failNext arranges for the next call to the named hook to fail once with
// err (test convenience wrapper over failOn).
func (m *mockHooks) failNext(op string, err error) {
	m.failOn[op] = err
}

// failOnNthCall arranges for the call-th (1-indexed) call to the named hook
// to fail with err, independent of any other call to that hook (test
// convenience wrapper over failOnCall).
func (m *mockHooks) failOnNthCall(op string, call int, err error) {
	m.failOnCall[fmt.Sprintf("%s#%d", op, call)] = err
}

// overrideNextGetLen arranges for the next call to the named Get hook to
// return n items instead of the real count (test convenience wrapper over
// lenOverride).
func (m *mockHooks) overrideNextGetLen(op string, n int) {
	m.lenOverride[op] = n
}

// overrideGetLenAtCall arranges for the call-th (1-indexed) call to the
// named Get hook to return n items instead of the real count, independent
// of any other call to that hook (test convenience wrapper over
// lenOverrideCall).
func (m *mockHooks) overrideGetLenAtCall(op string, call int, n int) {
	m.lenOverrideCall[fmt.Sprintf("%s#%d", op, call)] = n
}

// resizeTo truncates or zero-pads items to exactly n elements.
func resizeTo[T any](items []T, n int) []T {
	if n <= len(items) {
		return items[:n]
	}
	out := make([]T, n)
	copy(out, items)
	return out
}

// mutateAtCall registers fn to run just before the call-th (1-indexed) call
// to the named Get hook copies out its return value, so the test can drift
// the stored content the way a corrupting backend would.
func (m *mockHooks) mutateAtCall(op string, call int, fn func()) {
	m.mutateAt[fmt.Sprintf("%s#%d", op, call)] = fn
}

// resizeOverride is the generic read path of every slice-returning Get
// method. snap builds the returned copy of the store LAZILY, so a mutateAt
// hook registered for this call number can drift the stored content first
// and the copy reflects it -- an eager copy taken at the call site would
// predate the mutation. After the (possibly drifted) snapshot is taken, a
// pending lenOverride (any call) or lenOverrideCall (this call number)
// resizes it; otherwise it is returned unchanged.
func resizeOverride[T any](m *mockHooks, op string, snap func() []T) []T {
	n := m.callSeq(op)
	if fn, ok := m.mutateAt[fmt.Sprintf("%s#%d", op, n)]; ok {
		fn()
	}
	items := snap()
	if v, ok := m.lenOverride[op]; ok {
		delete(m.lenOverride, op)
		return resizeTo(items, v)
	}
	if v, ok := m.lenOverrideCall[fmt.Sprintf("%s#%d", op, n)]; ok {
		return resizeTo(items, v)
	}
	return items
}

// --- endpoint ---

func (m *mockHooks) NetEpHostGet() ([]cmn.EndPointMod, error) {
	m.log("NetEpHostGet")
	return resizeOverride(m, "NetEpHostGet", func() []cmn.EndPointMod { return append([]cmn.EndPointMod(nil), m.endpoints...) }), nil
}
func (m *mockHooks) NetEpHostAdd(e *cmn.EndPointMod) (int, error) {
	m.log("NetEpHostAdd:%s", e.Name)
	if err := m.failIfConfigured("NetEpHostAdd"); err != nil {
		return -1, err
	}
	m.endpoints = append(m.endpoints, *e)
	return 0, nil
}
func (m *mockHooks) NetEpHostDel(e *cmn.EndPointMod) (int, error) {
	m.log("NetEpHostDel:%s", e.Name)
	if err := m.failIfConfigured("NetEpHostDel"); err != nil {
		return -1, err
	}
	out := m.endpoints[:0]
	for _, ep := range m.endpoints {
		if ep.Name != e.Name {
			out = append(out, ep)
		}
	}
	m.endpoints = out
	return 0, nil
}

// --- loadbalancer ---

func (m *mockHooks) NetLbRuleGet() ([]cmn.LbRuleMod, error) {
	m.log("NetLbRuleGet")
	return resizeOverride(m, "NetLbRuleGet", func() []cmn.LbRuleMod { return append([]cmn.LbRuleMod(nil), m.lbRules...) }), nil
}
func (m *mockHooks) NetLbRuleAdd(l *cmn.LbRuleMod) (int, error) {
	m.log("NetLbRuleAdd:%s", l.Serv.ServIP)
	if err := m.failIfConfigured("NetLbRuleAdd"); err != nil {
		return -1, err
	}
	m.lbRules = append(m.lbRules, *l)
	return 0, nil
}
func (m *mockHooks) NetLbRuleDel(l *cmn.LbRuleMod) (int, error) {
	m.log("NetLbRuleDel:%s", l.Serv.ServIP)
	if err := m.failIfConfigured("NetLbRuleDel"); err != nil {
		return -1, err
	}
	out := m.lbRules[:0]
	for _, r := range m.lbRules {
		if r.Serv.ServIP != l.Serv.ServIP || r.Serv.ServPort != l.Serv.ServPort {
			out = append(out, r)
		}
	}
	m.lbRules = out
	return 0, nil
}

// --- kvexactbinding ---

func (m *mockHooks) NetKvExactBindingGet() ([]cmn.KvExactBindingMod, error) {
	m.log("NetKvExactBindingGet")
	return resizeOverride(m, "NetKvExactBindingGet", func() []cmn.KvExactBindingMod { return append([]cmn.KvExactBindingMod(nil), m.kvBinds...) }), nil
}
func (m *mockHooks) NetKvExactBindingAdd(b *cmn.KvExactBindingMod) (int, error) {
	m.log("NetKvExactBindingAdd:%s", b.RuleIdent)
	if err := m.failIfConfigured("NetKvExactBindingAdd"); err != nil {
		return -1, err
	}
	m.kvBinds = append(m.kvBinds, *b)
	return 0, nil
}
func (m *mockHooks) NetKvExactBindingDel(b *cmn.KvExactBindingMod) (int, error) {
	m.log("NetKvExactBindingDel:%s", b.RuleIdent)
	if err := m.failIfConfigured("NetKvExactBindingDel"); err != nil {
		return -1, err
	}
	out := m.kvBinds[:0]
	for _, r := range m.kvBinds {
		if r.RuleIdent != b.RuleIdent {
			out = append(out, r)
		}
	}
	m.kvBinds = out
	return 0, nil
}

// --- firewall ---

func (m *mockHooks) NetFwRuleGet() ([]cmn.FwRuleMod, error) {
	m.log("NetFwRuleGet")
	return resizeOverride(m, "NetFwRuleGet", func() []cmn.FwRuleMod { return append([]cmn.FwRuleMod(nil), m.fwRules...) }), nil
}
func (m *mockHooks) NetFwRuleAdd(f *cmn.FwRuleMod) (int, error) {
	m.log("NetFwRuleAdd")
	if err := m.failIfConfigured("NetFwRuleAdd"); err != nil {
		return -1, err
	}
	m.fwRules = append(m.fwRules, *f)
	return 0, nil
}
func (m *mockHooks) NetFwRuleDel(f *cmn.FwRuleMod) (int, error) {
	m.log("NetFwRuleDel")
	if err := m.failIfConfigured("NetFwRuleDel"); err != nil {
		return -1, err
	}
	out := m.fwRules[:0]
	removed := false
	for _, r := range m.fwRules {
		if !removed && reflect.DeepEqual(r, *f) {
			removed = true
			continue
		}
		out = append(out, r)
	}
	m.fwRules = out
	return 0, nil
}

// --- policy ---

func (m *mockHooks) NetPolicerGet() ([]cmn.PolMod, error) {
	m.log("NetPolicerGet")
	return resizeOverride(m, "NetPolicerGet", func() []cmn.PolMod { return append([]cmn.PolMod(nil), m.policies...) }), nil
}
func (m *mockHooks) NetPolicerAdd(p *cmn.PolMod) (int, error) {
	m.log("NetPolicerAdd:%s", p.Ident)
	if err := m.failIfConfigured("NetPolicerAdd"); err != nil {
		return -1, err
	}
	m.policies = append(m.policies, *p)
	return 0, nil
}
func (m *mockHooks) NetPolicerDel(p *cmn.PolMod) (int, error) {
	m.log("NetPolicerDel:%s", p.Ident)
	if err := m.failIfConfigured("NetPolicerDel"); err != nil {
		return -1, err
	}
	out := m.policies[:0]
	for _, x := range m.policies {
		if x.Ident != p.Ident {
			out = append(out, x)
		}
	}
	m.policies = out
	return 0, nil
}

// --- mirror ---

func (m *mockHooks) NetMirrorGet() ([]cmn.MirrGetMod, error) {
	m.log("NetMirrorGet")
	return resizeOverride(m, "NetMirrorGet", func() []cmn.MirrGetMod { return append([]cmn.MirrGetMod(nil), m.mirrors...) }), nil
}
func (m *mockHooks) NetMirrorAdd(mm *cmn.MirrMod) (int, error) {
	m.log("NetMirrorAdd:%s", mm.Ident)
	if err := m.failIfConfigured("NetMirrorAdd"); err != nil {
		return -1, err
	}
	m.mirrors = append(m.mirrors, cmn.MirrGetMod{Ident: mm.Ident, Info: mm.Info, Target: mm.Target})
	return 0, nil
}
func (m *mockHooks) NetMirrorDel(mm *cmn.MirrMod) (int, error) {
	m.log("NetMirrorDel:%s", mm.Ident)
	if err := m.failIfConfigured("NetMirrorDel"); err != nil {
		return -1, err
	}
	out := m.mirrors[:0]
	for _, x := range m.mirrors {
		if x.Ident != mm.Ident {
			out = append(out, x)
		}
	}
	m.mirrors = out
	return 0, nil
}

// --- session ---

func (m *mockHooks) NetSessionGet() ([]cmn.SessionMod, error) {
	m.log("NetSessionGet")
	return resizeOverride(m, "NetSessionGet", func() []cmn.SessionMod { return append([]cmn.SessionMod(nil), m.sessions...) }), nil
}
func (m *mockHooks) NetSessionAdd(s *cmn.SessionMod) (int, error) {
	m.log("NetSessionAdd:%s", s.Ident)
	if err := m.failIfConfigured("NetSessionAdd"); err != nil {
		return -1, err
	}
	m.sessions = append(m.sessions, *s)
	return 0, nil
}
func (m *mockHooks) NetSessionDel(s *cmn.SessionMod) (int, error) {
	m.log("NetSessionDel:%s", s.Ident)
	if err := m.failIfConfigured("NetSessionDel"); err != nil {
		return -1, err
	}
	out := m.sessions[:0]
	for _, x := range m.sessions {
		if x.Ident != s.Ident {
			out = append(out, x)
		}
	}
	m.sessions = out
	return 0, nil
}

// --- sessionulcl ---

func (m *mockHooks) NetSessionUlClGet() ([]cmn.SessionUlClMod, error) {
	m.log("NetSessionUlClGet")
	return resizeOverride(m, "NetSessionUlClGet", func() []cmn.SessionUlClMod { return append([]cmn.SessionUlClMod(nil), m.ulcl...) }), nil
}
func (m *mockHooks) NetSessionUlClAdd(s *cmn.SessionUlClMod) (int, error) {
	m.log("NetSessionUlClAdd:%s", s.Ident)
	if err := m.failIfConfigured("NetSessionUlClAdd"); err != nil {
		return -1, err
	}
	m.ulcl = append(m.ulcl, *s)
	return 0, nil
}
func (m *mockHooks) NetSessionUlClDel(s *cmn.SessionUlClMod) (int, error) {
	m.log("NetSessionUlClDel:%s", s.Ident)
	if err := m.failIfConfigured("NetSessionUlClDel"); err != nil {
		return -1, err
	}
	out := m.ulcl[:0]
	for _, x := range m.ulcl {
		if x.Ident != s.Ident {
			out = append(out, x)
		}
	}
	m.ulcl = out
	return 0, nil
}

// --- ipfilter ---

func (m *mockHooks) NetIPFilterGet() ([]cmn.IPFilterEntry, error) {
	m.log("NetIPFilterGet")
	return resizeOverride(m, "NetIPFilterGet", func() []cmn.IPFilterEntry { return append([]cmn.IPFilterEntry(nil), m.ipFilters...) }), nil
}
func (m *mockHooks) NetIPFilterAdd(f *cmn.IPFilterMod) (int, error) {
	m.log("NetIPFilterAdd:%s", f.CIDR)
	if err := m.failIfConfigured("NetIPFilterAdd"); err != nil {
		return -1, err
	}
	m.ipFilters = append(m.ipFilters, cmn.IPFilterEntry{IPFilterMod: *f})
	return 0, nil
}
func (m *mockHooks) NetIPFilterDel(f *cmn.IPFilterMod) (int, error) {
	m.log("NetIPFilterDel:%s", f.CIDR)
	if err := m.failIfConfigured("NetIPFilterDel"); err != nil {
		return -1, err
	}
	out := m.ipFilters[:0]
	for _, x := range m.ipFilters {
		if x.CIDR != f.CIDR {
			out = append(out, x)
		}
	}
	m.ipFilters = out
	return 0, nil
}

// --- securityrate ---

func (m *mockHooks) NetSecurityRateGet() (*cmn.SecurityRateState, error) {
	m.log("NetSecurityRateGet")
	return m.secRate, nil
}
func (m *mockHooks) NetSecurityRateSet(c *cmn.SecurityRateConfig) (int, error) {
	m.log("NetSecurityRateSet:syn=%v", c.SYNEnabled)
	if err := m.failIfConfigured("NetSecurityRateSet"); err != nil {
		return -1, err
	}
	if m.secRate == nil {
		m.secRate = &cmn.SecurityRateState{}
	}
	m.secRate.Config = *c
	return 0, nil
}

// --- bfd ---

func (m *mockHooks) NetBFDGet() ([]cmn.BFDMod, error) {
	m.log("NetBFDGet")
	return resizeOverride(m, "NetBFDGet", func() []cmn.BFDMod { return append([]cmn.BFDMod(nil), m.bfds...) }), nil
}
func (m *mockHooks) NetBFDAdd(b *cmn.BFDMod) (int, error) {
	m.log("NetBFDAdd:%s", b.Instance)
	if err := m.failIfConfigured("NetBFDAdd"); err != nil {
		return -1, err
	}
	m.bfds = append(m.bfds, *b)
	return 0, nil
}
func (m *mockHooks) NetBFDDel(b *cmn.BFDMod) (int, error) {
	m.log("NetBFDDel:%s", b.Instance)
	if err := m.failIfConfigured("NetBFDDel"); err != nil {
		return -1, err
	}
	out := m.bfds[:0]
	for _, x := range m.bfds {
		if x.Instance != b.Instance {
			out = append(out, x)
		}
	}
	m.bfds = out
	return 0, nil
}

// --- bgp ---

func (m *mockHooks) NetGoBGPNeighGet() ([]cmn.GoBGPNeighGetMod, error) {
	m.log("NetGoBGPNeighGet")
	return resizeOverride(m, "NetGoBGPNeighGet", func() []cmn.GoBGPNeighGetMod { return append([]cmn.GoBGPNeighGetMod(nil), m.bgpNeighbors...) }), nil
}
func (m *mockHooks) NetGoBGPNeighAdd(n *cmn.GoBGPNeighMod) (int, error) {
	m.log("NetGoBGPNeighAdd:%s", n.Addr)
	if err := m.failIfConfigured("NetGoBGPNeighAdd"); err != nil {
		return -1, err
	}
	addr := ""
	if n.Addr != nil {
		addr = n.Addr.String()
	}
	m.bgpNeighbors = append(m.bgpNeighbors, cmn.GoBGPNeighGetMod{
		Addr: addr, RemoteAS: n.RemoteAS,
		RemotePort: n.RemotePort, MultiHop: n.MultiHop,
	})
	return 0, nil
}
func (m *mockHooks) NetGoBGPNeighDel(n *cmn.GoBGPNeighMod) (int, error) {
	m.log("NetGoBGPNeighDel:%s", n.Addr)
	if err := m.failIfConfigured("NetGoBGPNeighDel"); err != nil {
		return -1, err
	}
	addr := ""
	if n.Addr != nil {
		addr = n.Addr.String()
	}
	out := m.bgpNeighbors[:0]
	for _, x := range m.bgpNeighbors {
		if x.Addr != addr {
			out = append(out, x)
		}
	}
	m.bgpNeighbors = out
	return 0, nil
}
func (m *mockHooks) NetGoBGPGCGet() (cmn.GoBGPGlobalConfig, error) {
	m.log("NetGoBGPGCGet")
	if err := m.failIfConfigured("NetGoBGPGCGet"); err != nil {
		return cmn.GoBGPGlobalConfig{}, err
	}
	if m.bgpGC == nil {
		return cmn.GoBGPGlobalConfig{}, nil
	}
	return *m.bgpGC, nil
}
func (m *mockHooks) NetGoBGPGCAdd(gc *cmn.GoBGPGlobalConfig) (int, error) {
	m.log("NetGoBGPGCAdd")
	if err := m.failIfConfigured("NetGoBGPGCAdd"); err != nil {
		return -1, err
	}
	m.bgpGC = gc
	return 0, nil
}
func (m *mockHooks) NetGoBGPPolicyDefinedSetGet(name string, definedTypeString string) ([]cmn.GoBGPPolicyDefinedSetMod, error) {
	m.log("NetGoBGPPolicyDefinedSetGet:%s:%s", name, definedTypeString)
	return resizeOverride(m, "NetGoBGPPolicyDefinedSetGet:"+definedTypeString, func() []cmn.GoBGPPolicyDefinedSetMod {
		return append([]cmn.GoBGPPolicyDefinedSetMod(nil), m.bgpDefined[definedTypeString]...)
	}), nil
}
func (m *mockHooks) NetGoBGPPolicyDefinedSetAdd(d *cmn.GoBGPPolicyDefinedSetMod) (int, error) {
	m.log("NetGoBGPPolicyDefinedSetAdd:%s", d.Name)
	if err := m.failIfConfigured("NetGoBGPPolicyDefinedSetAdd"); err != nil {
		return -1, err
	}
	m.bgpDefined[d.DefinedTypeString] = append(m.bgpDefined[d.DefinedTypeString], *d)
	return 0, nil
}
func (m *mockHooks) NetGoBGPPolicyDefinedSetDel(d *cmn.GoBGPPolicyDefinedSetMod) (int, error) {
	m.log("NetGoBGPPolicyDefinedSetDel:%s", d.Name)
	if err := m.failIfConfigured("NetGoBGPPolicyDefinedSetDel"); err != nil {
		return -1, err
	}
	list := m.bgpDefined[d.DefinedTypeString]
	out := list[:0]
	for _, x := range list {
		if x.Name != d.Name {
			out = append(out, x)
		}
	}
	m.bgpDefined[d.DefinedTypeString] = out
	return 0, nil
}
func (m *mockHooks) NetGoBGPPolicyDefinitionsGet() ([]cmn.GoBGPPolicyDefinitionsMod, error) {
	m.log("NetGoBGPPolicyDefinitionsGet")
	return resizeOverride(m, "NetGoBGPPolicyDefinitionsGet", func() []cmn.GoBGPPolicyDefinitionsMod {
		return append([]cmn.GoBGPPolicyDefinitionsMod(nil), m.bgpPolicyDefs...)
	}), nil
}
func (m *mockHooks) NetGoBGPPolicyDefinitionAdd(d *cmn.GoBGPPolicyDefinitionsMod) (int, error) {
	m.log("NetGoBGPPolicyDefinitionAdd:%s", d.Name)
	if err := m.failIfConfigured("NetGoBGPPolicyDefinitionAdd"); err != nil {
		return -1, err
	}
	m.bgpPolicyDefs = append(m.bgpPolicyDefs, *d)
	return 0, nil
}
func (m *mockHooks) NetGoBGPPolicyDefinitionDel(d *cmn.GoBGPPolicyDefinitionsMod) (int, error) {
	m.log("NetGoBGPPolicyDefinitionDel:%s", d.Name)
	if err := m.failIfConfigured("NetGoBGPPolicyDefinitionDel"); err != nil {
		return -1, err
	}
	out := m.bgpPolicyDefs[:0]
	for _, x := range m.bgpPolicyDefs {
		if x.Name != d.Name {
			out = append(out, x)
		}
	}
	m.bgpPolicyDefs = out
	return 0, nil
}

// --- ipsec ---

func (m *mockHooks) NetIPsecGetConfig() (*cmn.IPsecConfig, error) {
	m.log("NetIPsecGetConfig")
	return m.ipsecConfig, nil
}
func (m *mockHooks) NetIPsecConfigSet(cfg *cmn.IPsecConfigMod) (int, error) {
	m.log("NetIPsecConfigSet")
	if err := m.failIfConfigured("NetIPsecConfigSet"); err != nil {
		return -1, err
	}
	if m.ipsecConfig == nil {
		m.ipsecConfig = &cmn.IPsecConfig{}
	}
	if cfg.FastPathEnabled != nil {
		m.ipsecConfig.FastPathEnabled = *cfg.FastPathEnabled
	}
	if cfg.HwOffloadEnabled != nil {
		m.ipsecConfig.HwOffloadEnabled = *cfg.HwOffloadEnabled
	}
	if cfg.HwOffloadType != nil {
		m.ipsecConfig.HwOffloadType = *cfg.HwOffloadType
	}
	if cfg.AntiReplayEnabled != nil {
		m.ipsecConfig.AntiReplayEnabled = *cfg.AntiReplayEnabled
	}
	if cfg.SALifetimeWarnSeconds != nil {
		m.ipsecConfig.SALifetimeWarnSeconds = *cfg.SALifetimeWarnSeconds
	}
	if cfg.SeqOverflowAction != nil {
		m.ipsecConfig.SeqOverflowAction = *cfg.SeqOverflowAction
	}
	if cfg.MTU != nil {
		m.ipsecConfig.MTU = *cfg.MTU
	}
	return 0, nil
}
func (m *mockHooks) NetIPsecTunnelGetAll() ([]*cmn.IPsecTunnel, error) {
	m.log("NetIPsecTunnelGetAll")
	return resizeOverride(m, "NetIPsecTunnelGetAll", func() []*cmn.IPsecTunnel { return append([]*cmn.IPsecTunnel(nil), m.ipsecTunnels...) }), nil
}
func (m *mockHooks) NetIPsecTunnelAdd(t *cmn.IPsecTunnelMod) (int, error) {
	m.log("NetIPsecTunnelAdd:%s", t.Name)
	if err := m.failIfConfigured("NetIPsecTunnelAdd"); err != nil {
		return -1, err
	}
	m.ipsecTunnels = append(m.ipsecTunnels, &cmn.IPsecTunnel{IPsecTunnelMod: *t})
	return 0, nil
}
func (m *mockHooks) NetIPsecTunnelDel(name string) (int, error) {
	m.log("NetIPsecTunnelDel:%s", name)
	if err := m.failIfConfigured("NetIPsecTunnelDel"); err != nil {
		return -1, err
	}
	out := m.ipsecTunnels[:0]
	for _, x := range m.ipsecTunnels {
		if x == nil || x.Name != name {
			out = append(out, x)
		}
	}
	m.ipsecTunnels = out
	return 0, nil
}
func (m *mockHooks) NetIPsecCertificateGetAll() ([]*cmn.IPsecCertificate, error) {
	m.log("NetIPsecCertificateGetAll")
	return resizeOverride(m, "NetIPsecCertificateGetAll", func() []*cmn.IPsecCertificate { return append([]*cmn.IPsecCertificate(nil), m.ipsecCerts...) }), nil
}
func (m *mockHooks) NetIPsecCertificateAdd(c *cmn.IPsecCertificateMod) (int, error) {
	m.log("NetIPsecCertificateAdd:%s", c.Name)
	if err := m.failIfConfigured("NetIPsecCertificateAdd"); err != nil {
		return -1, err
	}
	m.ipsecCerts = append(m.ipsecCerts, &cmn.IPsecCertificate{Name: c.Name, Description: c.Description})
	m.ipsecCertMods = append(m.ipsecCertMods, *c)
	return 0, nil
}
func (m *mockHooks) NetIPsecCertificateDel(name string) (int, error) {
	m.log("NetIPsecCertificateDel:%s", name)
	if err := m.failIfConfigured("NetIPsecCertificateDel"); err != nil {
		return -1, err
	}
	out := m.ipsecCerts[:0]
	for _, x := range m.ipsecCerts {
		if x == nil || x.Name != name {
			out = append(out, x)
		}
	}
	m.ipsecCerts = out
	outMods := m.ipsecCertMods[:0]
	for _, x := range m.ipsecCertMods {
		if x.Name != name {
			outMods = append(outMods, x)
		}
	}
	m.ipsecCertMods = outMods
	return 0, nil
}
func (m *mockHooks) NetIPsecCertificateExportAll() ([]cmn.IPsecCertificateMod, error) {
	m.log("NetIPsecCertificateExportAll")
	return resizeOverride(m, "NetIPsecCertificateExportAll", func() []cmn.IPsecCertificateMod { return append([]cmn.IPsecCertificateMod(nil), m.ipsecCertMods...) }), nil
}
func (m *mockHooks) NetIPsecCACertificateGetAll() ([]*cmn.IPsecCACertificate, error) {
	m.log("NetIPsecCACertificateGetAll")
	return resizeOverride(m, "NetIPsecCACertificateGetAll", func() []*cmn.IPsecCACertificate { return append([]*cmn.IPsecCACertificate(nil), m.ipsecCAs...) }), nil
}
func (m *mockHooks) NetIPsecCACertificateAdd(c *cmn.IPsecCACertificateMod) (int, error) {
	m.log("NetIPsecCACertificateAdd:%s", c.Name)
	if err := m.failIfConfigured("NetIPsecCACertificateAdd"); err != nil {
		return -1, err
	}
	m.ipsecCAs = append(m.ipsecCAs, &cmn.IPsecCACertificate{Name: c.Name, Description: c.Description})
	m.ipsecCAMods = append(m.ipsecCAMods, *c)
	return 0, nil
}
func (m *mockHooks) NetIPsecCACertificateDel(name string) (int, error) {
	m.log("NetIPsecCACertificateDel:%s", name)
	if err := m.failIfConfigured("NetIPsecCACertificateDel"); err != nil {
		return -1, err
	}
	out := m.ipsecCAs[:0]
	for _, x := range m.ipsecCAs {
		if x == nil || x.Name != name {
			out = append(out, x)
		}
	}
	m.ipsecCAs = out
	outMods := m.ipsecCAMods[:0]
	for _, x := range m.ipsecCAMods {
		if x.Name != name {
			outMods = append(outMods, x)
		}
	}
	m.ipsecCAMods = outMods
	return 0, nil
}
func (m *mockHooks) NetIPsecCACertificateExportAll() ([]cmn.IPsecCACertificateMod, error) {
	m.log("NetIPsecCACertificateExportAll")
	return resizeOverride(m, "NetIPsecCACertificateExportAll", func() []cmn.IPsecCACertificateMod { return append([]cmn.IPsecCACertificateMod(nil), m.ipsecCAMods...) }), nil
}

// compile-time assertion that mockHooks satisfies Hooks.
var _ Hooks = (*mockHooks)(nil)
