/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 NetLOX Inc.
 */
package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func pendingFixture(t *testing.T) (*mockHooks, *Document, *Engine) {
	t.Helper()
	h := newMockHooks()
	d := restoreDoc("0.9.8.6-beta")
	d.Domains.BGP.GlobalConfig = &cmn.GoBGPGlobalConfig{LocalAs: 65122, RouterID: "192.0.2.22", ListenPort: 1179}
	e := newTestEngine(h, t.TempDir())
	return h, d, e
}

// Publish immutable intent without starting a retry: isolate persist/capture
// from the async retry in these tests. Runtime cases exercise the actual worker.
func holdPendingForTest(t *testing.T, doc *Document) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx
	done := make(chan struct{})
	close(done)
	bgpRecovery.mu.Lock()
	if bgpRecovery.pending != nil {
		bgpRecovery.mu.Unlock()
		t.Fatal("previous pending recovery leaked")
	}
	bgpRecovery.pending = &pendingBGP{doc: doc, cancel: cancel, done: done}
	bgpPendingGauge.Set(1)
	bgpRecovery.mu.Unlock()
	t.Cleanup(func() { defer LockBGPRecovery()(); ResolvePendingBGP(); RecordBootRestoreState(BootRestoreState{}) })
}

func TestBGPPendingPersistMerge(t *testing.T) {
	h, d, e := pendingFixture(t)
	d.Domains.BGP.DefinedSets = []cmn.GoBGPPolicyDefinedSetMod{{Name: "z", DefinedTypeString: "prefix"}, {Name: "a", DefinedTypeString: "prefix"}}
	d.Domains.BGPPolicyAssignment = []cmn.GoBGPPolicyApply{{NeighIPAddress: "global", PolicyType: "export", Polices: []string{"z-policy", "a-policy"}, RouteAction: "reject"}}
	raw := encodeDoc(t, d)
	independent, bgp, preflight, err := e.BootDomainGroups(raw)
	if err != nil || preflight.Result != ResultOK || len(bgp) != 2 {
		t.Fatalf("preflight: %+v %v %v", preflight, bgp, err)
	}
	for _, c := range h.Calls {
		if strings.Contains(c, "Add") || strings.Contains(c, "Replace") {
			t.Fatalf("preflight mutated: %s", c)
		}
	}
	holdPendingForTest(t, d)
	h.failOn["NetGoBGPGCGet"] = errors.New("rpc error: code = Unavailable desc = connection refused")
	r, err := e.Restore(raw, RestoreOptions{Boot: true, Components: independent})
	if err != nil || r.Result != ResultOK {
		t.Fatalf("independent restore: %+v %v", r, err)
	}
	// An unrelated rule arrives while BGP is unavailable.
	h.lbRules = append(h.lbRules, cmn.LbRuleMod{Serv: cmn.LbServiceArg{ServIP: "1.1.1.2", ServPort: 81, Proto: "tcp"}})
	want, _ := json.Marshal(d.Domains.BGP)
	_, saved, err := WriteThrough(h, e.GatewayVersion, e.Hostname, e.PreRestoreDir)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(saved.Domains.BGP)
	if !bytes.Equal(want, got) {
		t.Fatalf("pending BGP changed: %s != %s", want, got)
	}
	if len(saved.Domains.LoadBalancer) != 2 {
		t.Fatalf("unrelated live change lost: %+v", saved.Domains.LoadBalancer)
	}
	disk, err := LoadPersisted(e.PreRestoreDir)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Decode(bytes.NewReader(disk))
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyChecksum(next); err != nil {
		t.Fatal(err)
	}
	got, _ = json.Marshal(next.Domains.BGP)
	if !bytes.Equal(want, got) {
		t.Fatal("restart source lost BGP")
	}
	// A caller may edit its capture without changing the cached intent.
	saved.Domains.BGP.GlobalConfig.LocalAs = 1
	if pendingBGPDocument().Domains.BGP.GlobalConfig.LocalAs != 65122 {
		t.Fatal("capture aliases pending intent")
	}
}

func TestBGPPendingReadinessCannotBeClearedByOtherRestore(t *testing.T) {
	_, d, _ := pendingFixture(t)
	holdPendingForTest(t, d)
	reasons := ReadinessReasons(true, BootRestoreState{Degraded: true}, &OpRecord{Mode: string(ModeCommit)}, AutoPersistState{}, nil)
	if len(reasons) == 0 || !strings.Contains(reasons[0], "bgp_domain_pending") {
		t.Fatalf("pending reported READY: %v", reasons)
	}
}

func TestBGPRecoveryRejectsCorruptBeforeIndependentApply(t *testing.T) {
	h, d, e := pendingFixture(t)
	raw := encodeDoc(t, d)
	raw = bytes.Replace(raw, []byte("192.0.2.22"), []byte("192.0.2.23"), 1)
	_, _, r, err := e.BootDomainGroups(raw)
	if err == nil && r.Result == ResultOK {
		t.Fatal("corrupt boot accepted")
	}
	if len(h.Calls) != 0 {
		t.Fatalf("corrupt document touched hooks: %v", h.Calls)
	}
}

type coldSpeakerHooks struct {
	*mockHooks
	globalErr error
	lists     int
}

func (h *coldSpeakerHooks) NetGoBGPGCGet() (cmn.GoBGPGlobalConfig, error) {
	return cmn.GoBGPGlobalConfig{}, h.globalErr
}
func (h *coldSpeakerHooks) NetGoBGPPolicyDefinedSetGet(string, string) ([]cmn.GoBGPPolicyDefinedSetMod, error) {
	h.lists++
	return nil, errors.New("invalid defined-set type: 0")
}

func TestBGPCaptureBeforeGlobalConfig(t *testing.T) {
	h := &coldSpeakerHooks{mockHooks: newMockHooks()}
	d, err := Capture(h, "0.9.8.6-beta", "test", TriggerManual, []string{DomainBGP})
	if err != nil || d.Domains.BGP.GlobalConfig != nil || h.lists != 0 {
		t.Fatalf("cold capture: %+v %v lists=%d", d, err, h.lists)
	}
	h.globalErr = errors.New("rpc transport unavailable")
	if _, err = Capture(h, "0.9.8.6-beta", "test", TriggerManual, []string{DomainBGP}); err == nil {
		t.Fatal("transport failure hidden as empty BGP")
	}
}

func TestBGPPendingFullReplacementAndPersistFailure(t *testing.T) {
	h, d, e := pendingFixture(t)
	holdPendingForTest(t, d)
	raw := encodeDoc(t, d)
	if !FullBGPReplacement(raw, nil) || FullBGPReplacement(raw, []string{DomainBGP}) {
		t.Fatal("full replacement coverage wrong")
	}
	subset := *d
	subset.IncludedDomains = []string{DomainBGP}
	if FullBGPReplacement(encodeDoc(t, &subset), nil) {
		t.Fatal("component document treated as full replacement")
	}
	// Failed disk publish leaves the original source intact; no second file.
	if _, _, _, err := Persist(d, e.PreRestoreDir); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(e.PreRestoreDir, PersistFileName))
	swapSyncSeams(t, func(*os.File) error { return errors.New("injected fsync failure") }, nil)
	if _, _, err := WriteThrough(h, e.GatewayVersion, e.Hostname, e.PreRestoreDir); err == nil {
		t.Fatal("persist fault not surfaced")
	}
	after, _ := os.ReadFile(filepath.Join(e.PreRestoreDir, PersistFileName))
	if !bytes.Equal(before, after) {
		t.Fatal("failed persist damaged original intent")
	}
}

func TestBGPPendingStopDoesNotDiscardDiskIntent(t *testing.T) {
	_, d, e := pendingFixture(t)
	holdPendingForTest(t, d)
	if _, _, _, err := Persist(d, e.PreRestoreDir); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := StopBGPRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	if !BGPPending() {
		t.Fatal("shutdown discarded pending intent")
	}
	if _, err := LoadPersisted(e.PreRestoreDir); err != nil {
		t.Fatal(err)
	}
}

func TestBGPPendingReplacementStopsQueuedRetry(t *testing.T) {
	h, d, e := pendingFixture(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	SetBGPRecoveryContext(parent)
	unlock := LockBGPRecovery()
	if err := e.StartPendingBGP(encodeDoc(t, d), []string{DomainBGP, DomainBGPPolicyAssignment}); err != nil {
		unlock()
		t.Fatal(err)
	}
	bgpRecovery.mu.RLock()
	p := bgpRecovery.pending
	bgpRecovery.mu.RUnlock()
	if testutil.ToFloat64(bgpPendingGauge) != 1 {
		t.Fatal("pending gauge not set")
	}
	ResolvePendingBGP() // operator replaces pending before the queued retry can run
	if testutil.ToFloat64(bgpPendingGauge) != 0 {
		t.Fatal("replacement did not clear pending gauge")
	}
	unlock()
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("superseded retry leaked")
	}
	if BGPPending() || len(h.Calls) != 0 {
		t.Fatalf("stale retry changed config: %v", h.Calls)
	}
}

type notifyingBGP struct {
	*mockHooks
	notified chan struct{}
}

func (h *notifyingBGP) NetBGPRecoveryComplete() { close(h.notified) }
func TestBGPPendingRecoveryOnlyAppliesBGPAndNotifies(t *testing.T) {
	h, d, e := pendingFixture(t)
	notify := &notifyingBGP{mockHooks: h, notified: make(chan struct{})}
	e.Hooks = notify
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	SetBGPRecoveryContext(parent)
	unlock := LockBGPRecovery()
	if err := e.StartPendingBGP(encodeDoc(t, d), []string{DomainBGP, DomainBGPPolicyAssignment}); err != nil {
		unlock()
		t.Fatal(err)
	}
	bgpRecovery.mu.RLock()
	p := bgpRecovery.pending
	bgpRecovery.mu.RUnlock()
	unlock()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		t.Fatal("BGP recovery did not finish")
	}
	if BGPPending() || testutil.ToFloat64(bgpPendingGauge) != 0 {
		t.Fatal("successful group remains pending")
	}
	select {
	case <-notify.notified:
	default:
		t.Fatal("late advertisement reconciliation not requested")
	}
	for _, call := range h.Calls {
		if strings.HasPrefix(call, "NetLbRuleAdd") || strings.HasPrefix(call, "NetEndPointAdd") {
			t.Fatalf("BGP retry reapplied independent state: %v", h.Calls)
		}
	}
}

func TestBGPPendingPersistPreservesOriginalJSONBytes(t *testing.T) {
	h, d, e := pendingFixture(t)
	d.Domains.BGP.DefinedSets = []cmn.GoBGPPolicyDefinedSetMod{{Name: "z", DefinedTypeString: "prefix"}, {Name: "a", DefinedTypeString: "prefix"}}
	d.Domains.BGPPolicyAssignment = []cmn.GoBGPPolicyApply{{NeighIPAddress: "global", PolicyType: "export", Polices: []string{"z-policy", "a-policy"}, RouteAction: "reject"}}
	raw := encodeDoc(t, d)
	values, err := extractBGPRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	// JSON indentation, key order, and omitted default fields are independent
	// of the typed checksum. Preserve these original bytes across live writes.
	for name, value := range values {
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, value, " ", "  "); err != nil {
			t.Fatal(err)
		}
		values[name] = formatted.Bytes()
	}
	raw, err = preservePendingBGPRaw(raw, values)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.PreparePendingBGP(raw, []string{DomainBGP, DomainBGPPolicyAssignment})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := StopBGPRecovery(context.Background()); err != nil {
			t.Error(err)
		}
		defer LockBGPRecovery()()
		ResolvePendingBGP()
	})
	h.lbRules = append(h.lbRules, cmn.LbRuleMod{Serv: cmn.LbServiceArg{ServIP: "1.1.1.2", ServPort: 81, Proto: "tcp"}})
	_, captured, err := WriteThrough(h, e.GatewayVersion, e.Hostname, e.PreRestoreDir)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := LoadPersisted(e.PreRestoreDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := extractBGPRaw(disk)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range values {
		if !bytes.Equal(value, got[name]) {
			t.Fatalf("%s raw bytes changed: %s != %s", name, value, got[name])
		}
	}
	if _, err := stageParse(disk); err != nil {
		t.Fatal(err)
	}
	// Captures cannot corrupt shared raw cache or persist an inconsistent merge.
	captured.pendingBGPRaw[DomainBGP][0] = '['
	if bytes.Equal(captured.pendingBGPRaw[DomainBGP], pendingBGPDocument().pendingBGPRaw[DomainBGP]) {
		t.Fatal("raw cache aliases capture")
	}
	if _, _, _, err := Persist(captured, e.PreRestoreDir); err == nil {
		t.Fatal("invalid raw intent accepted")
	}
	captured.pendingBGPRaw = cloneBGPRaw(pendingBGPDocument().pendingBGPRaw)
	captured.Domains.BGP.GlobalConfig.LocalAs = 1
	if _, _, _, err := Persist(captured, e.PreRestoreDir); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("typed/raw mismatch was not refused: %v", err)
	}
	after, _ := LoadPersisted(e.PreRestoreDir)
	if !bytes.Equal(after, disk) {
		t.Fatal("failed persist changed durable intent")
	}
}

func TestBGPRawMemberReplacement(t *testing.T) {
	for _, object := range []string{`{}`, `{"nested":{"bgp":"wrong"},"text":"bgp"}`, `{"bgp":null,"nested":{"bgp":123}}`} {
		got, err := replaceJSONMember([]byte(object), "bgp", []byte("{\n \"value\": 1\n}"))
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(got, &decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded["bgp"], []byte("{\n \"value\": 1\n}")) {
			t.Fatalf("raw replacement changed: %s", got)
		}
	}
	if _, err := replaceJSONMember([]byte(`{}`), "bgp", []byte(`{`)); err == nil {
		t.Fatal("invalid value accepted")
	}
}
