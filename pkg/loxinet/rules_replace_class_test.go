/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package loxinet

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// What a replace of a load-balancer rule does to its data-plane pool, and
// that every value the rule hands to the data plane belongs to a class that
// decides it.
//
// The classes of a replace, for a CHWBL or WRR_HASH (hashed) pool:
//
//	refresh   the native refresh of the pool applies it (the guard below
//	          names the copy line in the pinned native source): the pool and
//	          its loads are kept;
//	gateway   the Gateway applies it and the data plane does not hold it: the
//	          pool is kept;
//	recreate  everything else, and any value nobody classified: the pool is
//	          removed and created again, as for round robin.
//
// Round robin and the other selectors are unchanged: any change outside the
// in-place class and the zero-endpoint edge re-creates a full-proxy pool.

var allSelectors = []cmn.EpSelect{
	cmn.LbSelRr, cmn.LbSelHash, cmn.LbSelPrio, cmn.LbSelRrPersist, cmn.LbSelLeastConnections,
	cmn.LbSelN2, cmn.LbSelN3, cmn.LbSelCHWBL, cmn.LbSelGPUAware, cmn.LbSelWRRHash,
}

func hashedSel(s cmn.EpSelect) bool { return s == cmn.LbSelCHWBL || s == cmn.LbSelWRRHash }

// wantRemoves - the expected verdict, stated independently of the code.
func wantRemoves(oldSel, newSel cmn.EpSelect, mode cmn.LBMode, c lbReplaceChange) bool {
	hashed := hashedSel(oldSel) || hashedSel(newSel)
	if c.TooManyEps {
		// The endpoint-count reset: a non-hashed pool is removed and a
		// non-full-proxy rule keeps its behavior; a hashed full-proxy pool
		// is removed when a re-create-class value changes with it.
		if !hashed {
			return true
		}
		if mode != cmn.LBModeFullProxy {
			return false
		}
		return c.Recreate
	}
	if mode != cmn.LBModeFullProxy || c.InPlaceOnly || c.ZeroEpEdge {
		return false
	}
	if !hashed {
		return true // round robin and the other selectors: as today
	}
	return c.Recreate // a hashed pool: re-created only for the re-create class
}

// every combination of the seven flags
func allReplaceChanges() []lbReplaceChange {
	var out []lbReplaceChange
	for m := 0; m < 1<<7; m++ {
		out = append(out, lbReplaceChange{
			Recreate: m&1 != 0, Refresh: m&2 != 0, GatewayOnly: m&4 != 0, Endpoints: m&8 != 0,
			InPlaceOnly: m&16 != 0, ZeroEpEdge: m&32 != 0, TooManyEps: m&64 != 0,
		})
	}
	return out
}

func TestLbReplaceRemovesPool(t *testing.T) {
	var pairs [][2]cmn.EpSelect
	for _, a := range allSelectors {
		for _, b := range allSelectors {
			pairs = append(pairs, [2]cmn.EpSelect{a, b})
		}
	}
	n := 0
	for _, p := range pairs {
		for _, c := range allReplaceChanges() {
			for _, mode := range []cmn.LBMode{cmn.LBModeFullProxy, cmn.LBModeFullNAT, cmn.LBModeDefault} {
				got := lbReplaceRemovesPool(p[0], p[1], mode, c)
				if want := wantRemoves(p[0], p[1], mode, c); got != want {
					t.Errorf("sel %d -> %d, mode %d, %+v: removes=%v, want %v", p[0], p[1], mode, c, got, want)
				}
				n++
			}
		}
	}
	// The cases this change is about, by name.
	fp := cmn.LBModeFullProxy
	for _, sel := range []cmn.EpSelect{cmn.LbSelCHWBL, cmn.LbSelWRRHash} {
		for name, c := range map[string]lbReplaceChange{
			"re-create class":                     {Recreate: true},
			"re-create + refresh classes":         {Recreate: true, Refresh: true},
			"re-create class + endpoints":         {Recreate: true, Endpoints: true},
			"re-create + gateway classes":         {Recreate: true, GatewayOnly: true},
			"re-create class, too many endpoints": {Recreate: true, Endpoints: true, TooManyEps: true},
		} {
			if !lbReplaceRemovesPool(sel, sel, fp, c) {
				t.Errorf("sel %d, %s: the pool is kept", sel, name)
			}
		}
		for name, c := range map[string]lbReplaceChange{
			"refresh class":             {Refresh: true},
			"gateway class":             {GatewayOnly: true},
			"endpoints only":            {Endpoints: true},
			"refresh+gateway+endpoints": {Refresh: true, GatewayOnly: true, Endpoints: true},
			"in-place only":             {InPlaceOnly: true},
			"too many endpoints only":   {Endpoints: true, TooManyEps: true},
		} {
			if lbReplaceRemovesPool(sel, sel, fp, c) {
				t.Errorf("sel %d, %s: the pool is removed", sel, name)
			}
		}
	}
	if !lbReplaceRemovesPool(cmn.LbSelRr, cmn.LbSelRr, fp, lbReplaceChange{GatewayOnly: true}) {
		t.Error("round robin, gateway class: the pool is kept (round robin must stay as it is)")
	}
	t.Logf("%d verdicts checked", n)
}

// A selector change keeps a hashed pool only between the two hashed
// selectors: the refresh builds the new ring and loads through a validated
// candidate. Any other selector change re-creates.
func TestLbSelChangeRefreshes(t *testing.T) {
	for _, a := range allSelectors {
		for _, b := range allSelectors {
			if a == b {
				continue
			}
			want := hashedSel(a) && hashedSel(b)
			if got := lbSelChangeRefreshes(a, b); got != want {
				t.Errorf("sel %d -> %d: refresh=%v, want %v", a, b, got, want)
			}
		}
	}
}

// The CHWBL rollback (put the five values and the selector back, push the
// pool again) applies only to a pool that was refreshed. A pool that was
// removed is put back by the general undo, as for round robin.
func TestLbReplaceRollbackFollowsTheRemoval(t *testing.T) {
	for _, tc := range []struct {
		hashed, removed, refresh bool
	}{
		{false, false, false}, {false, true, false}, {true, false, true}, {true, true, false},
	} {
		if got := lbReplaceRefreshesHashedPool(tc.hashed, tc.removed); got != tc.refresh {
			t.Errorf("hashed=%v removed=%v: refresh-rollback=%v, want %v", tc.hashed, tc.removed, got, tc.refresh)
		}
	}
}

func addLbRuleBody(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "func (R *RuleH) AddLbRule(")
	if i < 0 {
		t.Fatal("AddLbRule not found")
	}
	j := strings.Index(src[i:], "\n}\n")
	return src[i : i+j]
}

// AddLbRule takes both decisions from the functions above: the removal,
// and every place that treated a hashed pool as refreshed (the rollbacks and
// the conntrack flush order) now asks whether it was refreshed.
func TestLbReplaceDecisionWired(t *testing.T) {
	add := addLbRuleBody(t)
	for _, f := range []string{"lbReplaceRemovesPool(", "lbReplaceRefreshesHashedPool(", "lbSelChangeRefreshes("} {
		if !strings.Contains(add, f) {
			t.Errorf("AddLbRule does not ask %s", strings.TrimSuffix(f, "("))
		}
	}
	if !regexp.MustCompile(`lbReplaceRemovesPool\([^\n]*replaceChg\)`).MatchString(add) {
		t.Error("AddLbRule does not hand the classified change (replaceChg) to lbReplaceRemovesPool")
	}
	// No decision is taken on the selector alone any more: chwblTxn may be
	// computed, but only the two functions read it.
	for _, m := range regexp.MustCompile(`[^\n]*\bchwblTxn\b[^\n]*`).FindAllString(add, -1) {
		if strings.Contains(m, "chwblTxn :=") || strings.Contains(m, "lbReplaceRemovesPool(") ||
			strings.Contains(m, "lbReplaceRefreshesHashedPool(") {
			continue
		}
		t.Errorf("a decision still reads chwblTxn: %s", strings.TrimSpace(m))
	}
	// Every pool removal of a replace goes through the decision.
	i := strings.Index(add, "chwblTxn :=")
	if i < 0 {
		t.Fatal("chwblTxn not found in AddLbRule")
	}
	for _, m := range regexp.MustCompile(`[^\n]*\n[^\n]*eRule\.DP\(DpRemove\)`).FindAllString(add[i:], -1) {
		if !strings.Contains(m, "lbReplaceRemovesPool(") && !strings.Contains(m, "removePool") {
			t.Errorf("a pool removal outside the decision: %s", strings.TrimSpace(m))
		}
	}
}

// ---- the guard: every value handed to the data plane has a class ----------

// lbDpClass - how a replace treats one LBDpWorkQ field:
//
//	recreate  compared in a re-create condition of AddLbRule's change chain
//	refresh   compared in a refresh condition; the native refresh copies it
//	selector  the selector: refresh between the hashed selectors, else recreate
//	inplace   compared in the in-place class (applied by the refresh)
//	tls       the backend TLS policy, staged in place (backendTLSChanged)
//	endpoint  endpoint data (compared by getLBConsolidatedEPs)
//	gateway   compared in a gateway-only condition; no data-plane pool value
//	          of a full-proxy rule holds it
//	key       part of the rule's key (a different value is another rule)
//	refused   a change is refused by AddLbRule, with this text
//	external  owned by another API or path; a replace does not set it
//	derived   computed from fields above, or from the gateway's own state
//	control   the work item itself
type lbDpClass struct {
	class  string
	attrs  []string   // the ruleEnt attributes compared; refused: the refusal text
	native []nativeAt // refresh/inplace/tls/endpoint/selector: where the native refresh copies it
	why    string
}

// nativeAt - a line the native refresh must contain, in one region of the
// pinned native source.
type nativeAt struct {
	region string // "refresh", "update" or "chwbl_prepare"
	line   string
}

func rf(line string) nativeAt { return nativeAt{"refresh", line} }

var chwblPrepare = rf("chwbl_prepare_runtime(&candidate, arg, tepval)")
var chwblSwap = rf("tepval->chwbl_config = candidate.chwbl_config;")

func cp(line string) nativeAt { return nativeAt{"chwbl_prepare", line} }

var fcApply = rf("sp_fc_apply_rule(tepval, arg, new_ent, 0);")

var lbDpFieldClasses = map[string]lbDpClass{
	"Work":               {class: "control", why: "the work type"},
	"Status":             {class: "control", why: "the sync status pointer"},
	"ZoneNum":            {class: "control", why: "zone of the rule"},
	"BlockNum":           {class: "control", why: "derived from the rule number"},
	"Mark":               {class: "control", why: "the rule number"},
	"CsumDis":            {class: "derived", why: "gateway-wide checksum setting"},
	"DsrMode":            {class: "derived", why: "from the rule mode, which cannot change"},
	"SrcCheck":           {class: "derived", why: "from the rule mode"},
	"NatType":            {class: "derived", why: "from the rule mode"},
	"SecMode":            {class: "refused", attrs: []string{"cant modify rule security mode"}},
	"HAListenerFreebind": {class: "derived", why: "from the HA forward guard and the session header and P/D fields, which are compared"},
	"ServiceIP":          {class: "key"},
	"L4Port":             {class: "key"},
	"Proto":              {class: "key"},
	"HostURL":            {class: "key"},
	"PathPrefix":         {class: "key"},
	"PathMatchMode":      {class: "key"},
	"ModelName":          {class: "key"},
	"endPoints": {class: "endpoint", native: []nativeAt{
		rf("memcpy(candidate.eps, arg->eps, sizeof(arg->eps));"),
		rf("memcpy(tepval->eps, candidate.eps, sizeof(candidate.eps));")}},
	"secIP":              {class: "refused", attrs: []string{"secIP modify error"}},
	"MCPProtocolVersion": {class: "refused", attrs: []string{"resolveMCPService("}},
	"PolId":              {class: "external", why: "owned by the policer attachment (RuleQosPolAttach)"},
	"CatalogID":          {class: "external", why: "the tracing catalog mapping, applied by its own call during a replace"},
	"EpSel": {class: "selector", attrs: []string{"SEL"}, native: []nativeAt{
		rf("candidate.select = arg->select;"), rf("tepval->select = candidate.select;"), chwblPrepare, chwblSwap}},
	"SockMapMode":                 {class: "refresh", attrs: []string{"sockMapMode"}, native: []nativeAt{rf("tepval->sockmap_en = arg->sockmap_en;")}},
	"Ppv2En":                      {class: "recreate", attrs: []string{"ppv2En"}},
	"BackendProtocol":             {class: "recreate", attrs: []string{"backendProtocol"}},
	"SessionHeaderName":           {class: "recreate", attrs: []string{"sessionHeaderName"}},
	"SSEMode":                     {class: "recreate", attrs: []string{"sseMode"}},
	"ApiKeyAuth":                  {class: "recreate", attrs: []string{"apiKeyAuth"}},
	"JwtAuthProfile":              {class: "recreate", attrs: []string{"jwtAuthProfile"}},
	"MaxStreamDurationSec":        {class: "recreate", attrs: []string{"maxStreamDurationSec"}},
	"BackendKeepaliveIntervalSec": {class: "recreate", attrs: []string{"backendKeepaliveIntervalSec"}},
	"TimeoutMemberConnect":        {class: "recreate", attrs: []string{"timeoutMemberConnectMs"}},
	"TimeoutMemberData":           {class: "recreate", attrs: []string{"timeoutMemberDataMs"}},
	"TimeoutTcpInspect":           {class: "recreate", attrs: []string{"timeoutTcpInspectMs"}},
	"PDDisaggMode":                {class: "recreate", attrs: []string{"pdDisaggMode"}},
	"PDCacheAwareMode":            {class: "recreate", attrs: []string{"pdCacheAwareMode"}},
	"PDSessionTTLSec":             {class: "recreate", attrs: []string{"pdSessionTTLSec"}},
	"PDPrefillTimeoutSec": {class: "refresh", attrs: []string{"pdPrefillTimeoutSec"},
		native: []nativeAt{rf("tepval->pd_prefill_timeout_sec = arg->pd_prefill_timeout_sec;")}},
	"PDCacheThreshold":      {class: "recreate", attrs: []string{"pdCacheThreshold"}},
	"PDBalanceAbsThreshold": {class: "recreate", attrs: []string{"pdBalanceAbsThreshold"}},
	"PDBootstrapPort":       {class: "recreate", attrs: []string{"pdBootstrapPort"}},
	"CbEnable":              {class: "recreate", attrs: []string{"cbEnable"}},
	"KvExactMode":           {class: "recreate", attrs: []string{"kvExactMode"}},
	"KvBlockSize":           {class: "recreate", attrs: []string{"kvBlockSize"}},
	"KvHashAlgo":            {class: "recreate", attrs: []string{"kvHashAlgo"}},
	"KvZmqPort":             {class: "recreate", attrs: []string{"kvZmqPort"}},
	"KvWarmupSec":           {class: "recreate", attrs: []string{"kvWarmupSec"}},
	"KvEngineType":          {class: "refused", attrs: []string{"kvEngineImmutabilityCheck("}},
	"KvDpRankCount":         {class: "recreate", attrs: []string{"kvDpRankCount"}},
	"EppMode":               {class: "recreate", attrs: []string{"eppEndpoint", "eppFailureMode"}},
	"EppTimeoutMs":          {class: "recreate", attrs: []string{"eppTimeoutMs"}},
	"MTLSFrontend":          {class: "recreate", attrs: []string{"mtlsFrontend"}},
	"AlpnProtocols":         {class: "recreate", attrs: []string{"alpnProtocols"}},
	"TlsCiphers":            {class: "recreate", attrs: []string{"tlsCiphers"}},
	"TlsVersions":           {class: "recreate", attrs: []string{"tlsVersions"}},
	"HstsMaxAge":            {class: "recreate", attrs: []string{"hstsMaxAge"}},
	"HstsIncludeSubdomains": {class: "recreate", attrs: []string{"hstsIncludeSubdomains"}},
	"HstsPreload":           {class: "recreate", attrs: []string{"hstsPreload"}},
	"CHWBLPrefixHashLevel": {class: "refresh", attrs: []string{"chwblPrefixHashLevel"},
		native: []nativeAt{chwblPrepare, chwblSwap, cp("config->prefix_hash_level = arg->chwbl_prefix_hash_level")}},
	"CHWBLMeanLoadFactor": {class: "refresh", attrs: []string{"chwblMeanLoadFactor"},
		native: []nativeAt{chwblPrepare, chwblSwap, cp("config->mean_load_factor = arg->chwbl_mean_load_factor")}},
	"CHWBLReplication": {class: "refresh", attrs: []string{"chwblReplication"},
		native: []nativeAt{chwblPrepare, chwblSwap, cp("config->replication = arg->chwbl_replication")}},
	"CHWBLPrefixHashFlags": {class: "refresh", attrs: []string{"chwblPrefixHashFlags"},
		native: []nativeAt{chwblPrepare, chwblSwap, cp("config->prefix_hash_flags = arg->chwbl_prefix_hash_flags;")}},
	"CHWBLEnableCacheSalt": {class: "refresh", attrs: []string{"chwblEnableCacheSalt"},
		native: []nativeAt{chwblPrepare, chwblSwap, cp("config->enable_cache_salt = arg->chwbl_enable_cache_salt")}},
	"InActTo":   {class: "recreate", attrs: []string{"iTO"}},
	"PersistTo": {class: "gateway", attrs: []string{"pTO"}, why: "not copied to the full-proxy arguments; the L4 path does not keep a pool"},
	"ConnLimit": {class: "recreate", attrs: []string{"connLimit"}},
	"BackendCaCertId": {class: "tls", attrs: []string{"backendCaCertId"},
		native: []nativeAt{{"update", "proxy_listener_epctx_refresh(ent, arg)"}}},
	"BackendClientCertId": {class: "tls", attrs: []string{"backendClientCertId"},
		native: []nativeAt{{"update", "proxy_listener_epctx_refresh(ent, arg)"}}},
	"BackendTLSServerName": {class: "tls", attrs: []string{"backendTLSServerName"},
		native: []nativeAt{{"update", "proxy_listener_epctx_refresh(ent, arg)"}}},
	"MTLSBackend": {class: "tls", attrs: []string{"mtlsBackend"},
		native: []nativeAt{{"update", "proxy_listener_epctx_refresh(ent, arg)"}}},
	"FcMaxQueueDepth":   {class: "inplace", attrs: []string{"fcMaxQueueDepth"}, native: []nativeAt{fcApply}},
	"FcMaxQueueWaitMs":  {class: "inplace", attrs: []string{"fcMaxQueueWaitMs"}, native: []nativeAt{fcApply}},
	"HalfCloseMode":     {class: "inplace", attrs: []string{"halfCloseMode"}, native: []nativeAt{rf("tepval->hold_mode = arg->half_close_mode;")}},
	"NoEndpointStatus":  {class: "inplace", attrs: []string{"noEndpointStatus"}, native: []nativeAt{rf("tepval->no_ep_status = arg->no_ep_status;")}},
	"AIDefaultTokens":   {class: "inplace", attrs: []string{"aiDefaultResv"}, native: []nativeAt{rf("tepval->ai_default_tokens = arg->ai_default_tokens;")}},
	"AIObjectiveStrict": {class: "inplace", attrs: []string{"aiObjectiveStrict"}, native: []nativeAt{rf("tepval->ai_objective_strict = arg->ai_objective_strict;")}},
}

// The flow-control fields are one compared struct (fcCfg).
func init() {
	for _, f := range []string{"FcMode", "FcMaxOutstanding", "FcEpMaxInflight", "FcPrefillMaxInflight",
		"FcDecodeMaxInflight", "FcTelemetryStaleMs", "FcAdaptive", "FcWarmupMs", "FcTtftTargetMs",
		"FcTenantSharePct", "FcExposeHeaders", "FcWakePolicy", "FcShedQueue", "FcTenantWake",
		"FcLlmdHeaders", "FcBandWeight", "FcBandMinSharePct", "FcCriticalReservePct", "FcBandQueuePct",
		"FcBandWaitMs"} {
		lbDpFieldClasses[f] = lbDpClass{class: "inplace", attrs: []string{"fcCfg"}, native: []nativeAt{fcApply}}
	}
}

// The terms of the change chain that are not data-plane values: each in a
// gateway-only condition (the admin state: an endpoints condition; the
// rule's admin state reaches the data plane as every endpoint inactive).
var lbGatewayTerms = map[string]struct {
	class string // "gateway" or "endpoint"
	attrs []string
}{
	"probe settings":   {"gateway", []string{"hChk.prbType", "hChk.prbPort", "hChk.prbReq", "hChk.prbResp", "hChk.prbTimeo", "hChk.prbRetries"}},
	"monitor":          {"gateway", []string{"hChk.actChk"}},
	"allowed sources":  {"gateway", []string{"srcList"}},
	"trace type":       {"gateway", []string{"traceType"}},
	"name":             {"gateway", []string{"name"}},
	"EPP plaintext":    {"gateway", []string{"eppPlaintext"}},
	"migration attach": {"gateway", []string{"KVMIGRATING"}},
	"admin state":      {"endpoint", []string{"adminStateUp"}},
}

var lineComment = regexp.MustCompile(`//[^\n]*`)

// chainConds returns, per class (Recreate, Refresh, GatewayOnly, Endpoints),
// the conditions of the change chain's "if <cond> { … replaceChg.<Class> = true }"
// statements, comments stripped, the selector and the migration flag named.
func chainConds(t *testing.T, add string) map[string][]string {
	t.Helper()
	a := strings.Index(add, "epChg := ruleChg")
	b := strings.Index(add, "fieldChg := ruleChg")
	if a < 0 || b < 0 || a > b {
		t.Fatal("AddLbRule landmarks moved: epChg, fieldChg")
	}
	chain := lineComment.ReplaceAllString(add[a:b], "")
	chain = strings.ReplaceAll(chain, "eRule.act.action.(*ruleLBActs).sel", "eRule.SEL")
	chain = regexp.MustCompile(`\bkvMigrating\b`).ReplaceAllString(chain, "eRule.KVMIGRATING")
	out := map[string][]string{}
	re := regexp.MustCompile(`\bif\s+([^{}]*?)\{([^{}]*)\}`)
	for _, m := range re.FindAllStringSubmatch(chain, -1) {
		for _, cl := range []string{"Recreate", "Refresh", "GatewayOnly", "Endpoints"} {
			if strings.Contains(m[2], "replaceChg."+cl+" = true") {
				out[cl] = append(out[cl], m[1])
			}
		}
	}
	return out
}

func condsHave(conds []string, attr string) bool {
	re := regexp.MustCompile(`\beRule\.` + regexp.QuoteMeta(attr) + `\b`)
	for _, c := range conds {
		if re.MatchString(c) {
			return true
		}
	}
	return false
}

var spaces = regexp.MustCompile(`\s+`)

func squash(s string) string { return spaces.ReplaceAllString(s, " ") }

// nativeRegions reads the pinned native source: the refresh of an existing
// pool in proxy_add_entry, the part of proxy_add_entry before it that runs
// on every update of a listener, and chwbl_prepare_runtime.
func nativeRegions(t *testing.T) map[string]string {
	t.Helper()
	read := func(f string) string {
		b, err := os.ReadFile("../../loxilb-ebpf/common/" + f)
		if err != nil {
			t.Fatalf("the pinned native source is needed (checkout with submodules): %v", err)
		}
		return string(b)
	}
	between := func(src, from, to, what string) string {
		i := strings.Index(src, from)
		if i < 0 {
			t.Fatalf("native %s: %q not found", what, from)
		}
		j := strings.Index(src[i:], to)
		if j < 0 {
			t.Fatalf("native %s: %q not found after %q", what, to, from)
		}
		return src[i : i+j]
	}
	http := read("sockproxy_http.c")
	add := between(http, "\nproxy_add_entry(proxy_ent_t *new_ent, proxy_arg_t *arg)", "\n}\n", "proxy_add_entry")
	update := between(add, "if (cmp_proxy_ent(&ent->key, new_ent)) {", "HASH_FIND_STR(ent->val.ephash, ephash_key, tepval);", "update")
	refresh := between(add, "HASH_FIND_STR(ent->val.ephash, ephash_key, tepval);", "tepval = sp_pool_alloc();", "refresh")
	lb := read("sockproxy_lb.c")
	prep := between(lb, "\nchwbl_prepare_runtime(", "\n}\n", "chwbl_prepare_runtime")
	return map[string]string{"refresh": squash(refresh), "update": squash(update), "chwbl_prepare": squash(prep)}
}

func TestLbDpWorkFieldsClassified(t *testing.T) {
	add := addLbRuleBody(t)
	conds := chainConds(t, add)
	for _, cl := range []string{"Recreate", "Refresh", "GatewayOnly", "Endpoints"} {
		if len(conds[cl]) == 0 {
			t.Errorf("the change chain has no %s condition (if … { replaceChg.%s = true })", cl, cl)
		}
	}
	c := strings.Index(add, "inPlaceOnlyChg := false")
	if c < 0 {
		t.Fatal("AddLbRule landmark moved: inPlaceOnlyChg")
	}
	inPlace := add[c:]
	inPlace = inPlace[:strings.Index(inPlace, "inPlaceOnlyChg = true")]
	tlsSrc, err := os.ReadFile("rules_backend_tls.go")
	if err != nil {
		t.Fatal(err)
	}
	tlsFn := string(tlsSrc)
	tlsFn = tlsFn[strings.Index(tlsFn, "func backendTLSChanged("):]
	tlsFn = tlsFn[:strings.Index(tlsFn, "\n}\n")]
	native := nativeRegions(t)

	// A class's attribute is compared in that class's conditions and in no
	// other class's (the selector: in both re-create and refresh, behind
	// lbSelChangeRefreshes).
	others := func(own ...string) []string {
		var out []string
		for _, cl := range []string{"Recreate", "Refresh", "GatewayOnly", "Endpoints"} {
			skip := false
			for _, o := range own {
				skip = skip || o == cl
			}
			if !skip {
				out = append(out, conds[cl]...)
			}
		}
		return out
	}
	placed := func(f, at string, own ...string) {
		var in []string
		for _, o := range own {
			in = append(in, conds[o]...)
		}
		if !condsHave(in, at) {
			t.Errorf("%s: eRule.%s is not compared in a %s condition", f, at, strings.Join(own, "/"))
		}
		if condsHave(others(own...), at) {
			t.Errorf("%s: eRule.%s is also compared in a condition of another class", f, at)
		}
	}

	var unclassified []string
	ty := reflect.TypeOf(LBDpWorkQ{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i).Name
		cl, ok := lbDpFieldClasses[f]
		if !ok {
			unclassified = append(unclassified, f)
			continue
		}
		switch cl.class {
		case "recreate":
			for _, at := range cl.attrs {
				placed(f, at, "Recreate")
			}
		case "refresh":
			for _, at := range cl.attrs {
				placed(f, at, "Refresh")
			}
		case "gateway":
			for _, at := range cl.attrs {
				placed(f, at, "GatewayOnly")
			}
		case "selector":
			for _, at := range cl.attrs {
				placed(f, at, "Recreate", "Refresh")
			}
			okR, okC := false, false
			for _, x := range conds["Refresh"] {
				okR = okR || strings.Contains(x, "eRule.SEL") && regexp.MustCompile(`[^!]lbSelChangeRefreshes\(`).MatchString(" "+x)
			}
			for _, x := range conds["Recreate"] {
				okC = okC || strings.Contains(x, "eRule.SEL") && strings.Contains(x, "!lbSelChangeRefreshes(")
			}
			if !okR || !okC {
				t.Errorf("%s: a selector change must be refresh only when lbSelChangeRefreshes, and re-create when not (refresh %v, re-create %v)", f, okR, okC)
			}
		case "inplace":
			for _, at := range cl.attrs {
				if !strings.Contains(inPlace, "eRule."+at) {
					t.Errorf("%s: class inplace, but eRule.%s is not in the in-place class", f, at)
				}
				if condsHave(others(), at) {
					t.Errorf("%s: class inplace, but eRule.%s is also in the change chain", f, at)
				}
			}
		case "tls":
			for _, at := range cl.attrs {
				if !strings.Contains(tlsFn, "r."+at) {
					t.Errorf("%s: class tls, but backendTLSChanged does not compare %s", f, at)
				}
			}
		case "refused":
			for _, text := range cl.attrs {
				if !strings.Contains(add, text) {
					t.Errorf("%s: class refused, but %q is not in AddLbRule", f, text)
				}
			}
		case "endpoint", "key", "external", "derived", "control":
		default:
			t.Errorf("%s: unknown class %q", f, cl.class)
		}
		// Every value a hashed pool keeps by the refresh has its copy in the
		// pinned native refresh.
		for _, n := range cl.native {
			if !strings.Contains(native[n.region], squash(n.line)) {
				t.Errorf("%s: class %s, but the native %s does not contain %q", f, cl.class, n.region, n.line)
			}
		}
		if (cl.class == "refresh" || cl.class == "selector" || cl.class == "inplace") && len(cl.native) == 0 {
			t.Errorf("%s: class %s names no native copy line", f, cl.class)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Fatalf("LBDpWorkQ fields with no class (add each to lbDpFieldClasses): %s",
			strings.Join(unclassified, ", "))
	}
	for f := range lbDpFieldClasses {
		if _, ok := ty.FieldByName(f); !ok {
			t.Errorf("lbDpFieldClasses names %s, which LBDpWorkQ does not have", f)
		}
	}

	// The terms of the chain that are not data-plane values.
	for name, g := range lbGatewayTerms {
		own := map[string]string{"gateway": "GatewayOnly", "endpoint": "Endpoints"}[g.class]
		for _, at := range g.attrs {
			placed(name, at, own)
		}
	}

	// Nothing sits in a keeping condition (refresh, gateway, endpoints) that
	// nobody classified there: an unclassified term is re-create.
	allowed := map[string]map[string]bool{"Refresh": {}, "GatewayOnly": {}, "Endpoints": {}}
	for _, cl := range lbDpFieldClasses {
		switch cl.class {
		case "refresh", "selector":
			for _, at := range cl.attrs {
				allowed["Refresh"][at] = true
			}
		case "gateway":
			for _, at := range cl.attrs {
				allowed["GatewayOnly"][at] = true
			}
		}
	}
	for _, g := range lbGatewayTerms {
		own := map[string]string{"gateway": "GatewayOnly", "endpoint": "Endpoints"}[g.class]
		for _, at := range g.attrs {
			allowed[own][at] = true
		}
	}
	attrRe := regexp.MustCompile(`\beRule\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)?)`)
	for cl, set := range allowed {
		for _, x := range conds[cl] {
			for _, m := range attrRe.FindAllStringSubmatch(x, -1) {
				at := m[1]
				if !set[at] && !set[strings.SplitN(at, ".", 2)[0]] {
					t.Errorf("eRule.%s is compared in a %s condition but is not classified there", at, cl)
				}
			}
		}
	}
	t.Logf("%d LBDpWorkQ fields classified, %d chain terms outside the data plane, conditions: %s",
		ty.NumField(), len(lbGatewayTerms), condCounts(conds))
}

func condCounts(conds map[string][]string) string {
	var parts []string
	for _, cl := range []string{"Recreate", "Refresh", "GatewayOnly", "Endpoints"} {
		parts = append(parts, fmt.Sprintf("%s=%d", cl, len(conds[cl])))
	}
	return strings.Join(parts, " ")
}
