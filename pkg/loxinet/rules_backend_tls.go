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

package loxinet

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"syscall"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// backendVerifyOf reads the verification request of a rule; no object is the
// same request as an explicit false.
func backendVerifyOf(m *cmn.MTLSBackendConfig) bool {
	return m != nil && m.VerifyServerCert
}

// backendTLSFields is the backend TLS request as a rule stores it.
type backendTLSFields struct {
	caCertID     string
	clientCertID string
	serverName   string
	mtlsBackend  *cmn.MTLSBackendConfig
}

func backendTLSFieldsOf(r *ruleEnt) backendTLSFields {
	return backendTLSFields{
		caCertID:     r.backendCaCertId,
		clientCertID: r.backendClientCertId,
		serverName:   r.backendTLSServerName,
		mtlsBackend:  r.mtlsBackend,
	}
}

// restore puts a rule back to the backend TLS request it held.
func (f backendTLSFields) restore(r *ruleEnt) {
	r.backendCaCertId = f.caCertID
	r.backendClientCertId = f.clientCertID
	r.backendTLSServerName = f.serverName
	r.mtlsBackend = f.mtlsBackend
}

// backendTLSChanged reports whether a request asks for another backend TLS
// policy than the rule holds.
func backendTLSChanged(r *ruleEnt, serv *cmn.LbServiceArg) bool {
	return r.backendCaCertId != serv.BackendCaCertId ||
		r.backendClientCertId != serv.BackendClientCertId ||
		r.backendTLSServerName != serv.BackendTLSServerName ||
		backendVerifyOf(r.mtlsBackend) != backendVerifyOf(serv.MTLSBackend)
}

// lbPushRefusedText is the answer to a full-proxy rule the data plane did
// not install. The data plane keeps the reason in its own log; what is known
// here is that the listener or one of its TLS contexts could not be built.
func lbPushRefusedText(policyKept bool) string {
	if policyKept {
		return "the data plane could not build the backend TLS context for this policy; " +
			"the rule keeps its previous backend TLS policy, see the data plane log for the certificate that failed to load"
	}
	return "the data plane did not install the rule: its listener or a TLS context could not be built, " +
		"see the data plane log"
}

// lbVIPBindable reports whether a listener can be bound to a VIP on this
// host. Only "the address is not one of this host" counts as no: any other
// failure to bind says nothing about who holds the address. A variable so a
// test can stand in for the host.
var lbVIPBindable = func(vip net.IP) bool {
	if vip == nil || vip.IsUnspecified() {
		return true
	}
	l, err := net.Listen("tcp", net.JoinHostPort(vip.String(), "0"))
	if err != nil {
		return !errors.Is(err, syscall.EADDRNOTAVAIL)
	}
	l.Close()
	return true
}

// lbListenerAwaitsVIP reports whether a full-proxy rule the data plane did
// not install is one of a standby: its cluster instance is not the master,
// so the VIP is with the peer and the listener has nothing to bind to. Such a
// rule is kept and installed by the periodic sync once this gateway takes the
// VIP over. Refusing it would leave the gateway without the rule after a
// failover.
func lbListenerAwaitsVIP(ciState string, vip net.IP) bool {
	if ciState == cmn.CIMasterStateString || ciState == cmn.CIUnDefStateString {
		return false
	}
	return !lbVIPBindable(vip)
}

// lbStandbyKeeps reports whether a full-proxy rule the data plane did not
// install is kept for the periodic sync, see lbListenerAwaitsVIP.
func (R *RuleH) lbStandbyKeeps(r *ruleEnt) bool {
	ciState, _ := mh.has.CIStateGetInst(r.inst)
	if !lbListenerAwaitsVIP(ciState, r.tuples.l3Dst.addr.IP) {
		return false
	}
	tk.LogIt(tk.LogInfo, "lb-rule %s kept without a listener: cluster instance %s is %s and the VIP is not on this host\n",
		r.tuples.String(), r.inst, ciState)
	return true
}

// lbPushRefusedError classifies a full-proxy rule the data plane did not
// install. A VIP this gateway does not hold is the caller's to correct, and
// the answer names the field. Anything else is a condition of the gateway,
// which no other request body would change.
func lbPushRefusedError(vip net.IP, policyKept bool) error {
	if !policyKept && !lbVIPBindable(vip) {
		return &cmn.RuleArgumentError{Err: fmt.Errorf("externalIP %s is not an address of this gateway, so the rule's listener "+
			"could not be bound: use an address the host holds, or one in a subnet of the gateway that it holds as cluster master", vip)}
	}
	return &cmn.ServerPreconditionError{
		Reason: cmn.ReasonLbDataplaneInstallFailed,
		Err:    errors.New(lbPushRefusedText(policyKept)),
	}
}

// lbTLSCiphersErr refuses a cipher string that the TLS contexts of a rule
// could not be built with. The data plane passes the one string to both the
// TLS 1.3 ciphersuites and the TLS 1.2 cipher list of the listener and of the
// backend leg, and a rule whose context is not built is not installed. Only
// a full-proxy rule that terminates TLS builds a context; any other rule
// stores the value and does not use it.
func lbTLSCiphersErr(serv *cmn.LbServiceArg) error {
	if serv.TlsCiphers == "" || serv.Mode != cmn.LBModeFullProxy || serv.Security == cmn.LBServPlain {
		return nil
	}
	tls13, tls12, asked := tlsCiphersRefused(serv.TlsCiphers)
	if !asked || !tls13 && !tls12 {
		return nil
	}
	missing := "a TLS 1.3 ciphersuite and a TLS 1.2 cipher"
	if !tls12 {
		missing = "a TLS 1.3 ciphersuite"
	} else if !tls13 {
		missing = "a TLS 1.2 cipher"
	}
	return fmt.Errorf("tls_ciphers %q is not accepted by the gateway's TLS library: the one string is used as the "+
		"TLS 1.3 ciphersuites and as the TLS 1.2 cipher list, and it names no usable %s", serv.TlsCiphers, missing)
}

// lbReplaceUndo is a full-proxy rule as it stood before a replace wrote
// into it: the rule's own values, its endpoints and its allowed sources.
type lbReplaceUndo struct {
	ent  ruleEnt
	acts ruleLBActs
	srcs []string
}

func lbReplaceUndoOf(r *ruleEnt) *lbReplaceUndo {
	acts, ok := r.act.action.(*ruleLBActs)
	if !ok {
		return nil
	}
	u := &lbReplaceUndo{ent: *r, acts: *acts}
	u.acts.endPoints = snapshotLBEndpoints(acts.endPoints)
	for _, src := range r.srcList {
		u.srcs = append(u.srcs, src.srcPref.String())
	}
	return u
}

// apply writes the values back. What the rule has measured or been told by
// the data plane since is not part of what a request declares and stays.
func (u *lbReplaceUndo) apply(r *ruleEnt) {
	live := *r
	*r = u.ent
	r.sync = live.sync
	r.stat = live.stat
	r.activeConns, r.totalConns = live.activeConns, live.totalConns
	r.bytesIn, r.bytesOut = live.bytesIn, live.bytesOut
	r.vllmScraper = live.vllmScraper
	r.srcList = live.srcList

	acts := r.act.action.(*ruleLBActs)
	acts.mode, acts.sel = u.acts.mode, u.acts.sel
	acts.endPoints = snapshotLBEndpoints(u.acts.endPoints)
	for i := range acts.endPoints {
		// Every probe was detached before; the attach registers them anew.
		acts.endPoints[i].epCreated = false
	}
}

// lbReplaceUndo puts a rule back to what it was before a replace the data
// plane refused, and pushes it. The probes of the endpoints it has now are
// detached under the settings they were attached with, and the ones it had
// are attached again; the allowed sources it had are registered again.
func (R *RuleH) lbReplaceUndo(r *ruleEnt, u *lbReplaceUndo, activateProbe bool) {
	if u == nil {
		return
	}
	acts := r.act.action.(*ruleLBActs)
	R.modNatEpHost(r, acts.endPoints, false, activateProbe, r.egress)

	// The sources the rule had are registered before the ones it has now
	// are dropped, so a source in both sets is never without its entry.
	var srcs []*allowedSrcElem
	for _, pref := range u.srcs {
		src, err := R.addAllowedLbSrc(pref, uint32(r.ruleNum))
		if err != nil {
			tk.LogIt(tk.LogError, "lb-rule %s allowed source %s not registered again: %v\n", r.tuples.String(), pref, err)
			continue
		}
		srcs = append(srcs, src)
	}
	for _, src := range r.srcList {
		R.deleteAllowedLbSrc(src.srcPref.String(), uint32(r.ruleNum))
	}
	r.srcList = srcs
	if ferr := R.syncProxySrcFence(r); ferr != nil {
		tk.LogIt(tk.LogError, "lb-rule %s proxy src-fence not restored: %v\n", r.tuples.String(), ferr)
	}

	if r.id != u.ent.id {
		R.unregisterOpaqueID(r)
	}
	movedID := r.id != u.ent.id
	catalogID := r.tracingCatalogID
	u.apply(r)
	if movedID {
		R.registerOpaqueID(r)
	}
	if r.tracingCatalogID != 0 && r.tracingCatalogID != catalogID &&
		mh.dpEbpf != nil && mh.dpEbpf.catalogSyncManager != nil {
		_ = mh.dpEbpf.catalogSyncManager.AddServiceCatalogMapping(
			r.tuples.l3Dst.addr.IP, r.tuples.l4Dst.valMin, r.tuples.l4Prot.val, r.tracingCatalogID)
	}

	R.modNatEpHost(r, acts.endPoints, true, activateProbe, r.egress)
	R.electEPSrc(r)
	r.DP(DpCreate)
}

// lbRulesOfBackendCert returns the full-proxy rules whose backend leg refers
// to a certificate ID, in key order.
func (R *RuleH) lbRulesOfBackendCert(certID string) []*ruleEnt {
	var keys []string
	for key, r := range R.tables[RtLB].eMap {
		at, ok := r.act.action.(*ruleLBActs)
		if !ok || at.mode != cmn.LBModeFullProxy {
			continue
		}
		if r.backendCaCertId == certID || r.backendClientCertId == certID {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	rules := make([]*ruleEnt, 0, len(keys))
	for _, key := range keys {
		rules = append(rules, R.tables[RtLB].eMap[key])
	}
	return rules
}

// RefreshLbBackendCert pushes again every rule whose backend leg refers to a
// certificate ID, after the material under that ID was replaced, and waits
// for the data plane. A listener builds a new backend context when the files
// behind its IDs are not the ones its context was built from, and keeps the
// one it has when the new one cannot be built. It returns how many rules were
// pushed and names the ones whose listener kept its previous context. Those
// are not pushed again until the certificate or the rule is next written:
// the same files would be refused the same way.
func (R *RuleH) RefreshLbBackendCert(certID string) (int, []string) {
	rules := R.lbRulesOfBackendCert(certID)
	if len(rules) == 0 {
		return 0, nil
	}
	for _, r := range rules {
		r.DP(DpCreate)
	}
	DpBrokerSyncBarrier(mh.dp)
	var kept []string
	for _, r := range rules {
		if r.sync == 0 {
			r.backendTLSKept = false
			continue
		}
		r.sync = 0
		r.backendTLSKept = true
		name := fmt.Sprintf("%s:%d (%s)", r.tuples.l3Dst.addr.IP.String(), r.tuples.l4Dst.valMin, listenerRuleName(&r.tuples))
		kept = append(kept, name)
		tk.LogIt(tk.LogError, "lb-rule %s keeps its previous backend TLS context: the material now under certificate %q was not loaded\n",
			name, certID)
	}
	tk.LogIt(tk.LogInfo, "backend certificate %q replaced: %d rule(s) pushed, %d kept the previous context\n",
		certID, len(rules), len(kept))
	return len(rules), kept
}

// lbConfigReplay reports whether a rule add replays a saved configuration, a
// snapshot restore or the lbconfig.txt read at start, and not a request. A
// saved configuration is kept whole: what it holds ran before, and dropping
// one of its rules would lose it from the next save as well.
func lbConfigReplay(serv *cmn.LbServiceArg) bool {
	return serv.RestoreReplay || serv.BootReplay
}
