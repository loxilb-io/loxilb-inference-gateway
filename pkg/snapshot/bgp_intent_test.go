package snapshot

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
)

func intentFixture(t *testing.T) (*mockHooks, *Document, *Engine) {
	t.Helper()
	h, d, e := pendingFixture(t)
	bgpRecovery.mu.Lock()
	bgpRecovery.adopted = false
	bgpRecovery.mu.Unlock()
	EnableBGPIntentRecovery()
	SetBGPRecoveryContext(context.Background())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = StopBGPRecovery(ctx)
		defer LockBGPRecovery()()
		ResolvePendingBGP()
		bgpRecovery.mu.Lock()
		bgpRecovery.intent = nil
		bgpRecovery.tracking = false
		bgpRecovery.adopted = false
		bgpRecovery.parent = nil
		bgpRecovery.mu.Unlock()
		RecordBootRestoreState(BootRestoreState{})
	})
	return h, d, e
}

func TestBGPCompletedIntentRepeatedDaemonRecovery(t *testing.T) {
	h, d, e := intentFixture(t)
	d.Domains.BGP.Neighbors = []cmn.GoBGPNeighGetMod{{Addr: "192.0.2.23", RemoteAS: 65123, RemotePort: 1179}}
	RememberBGPIntent(d)
	for i := 0; i < 3; i++ {
		// All real daemon state is gone. Recovery must use completed intent.
		h.bgpNeighbors = nil
		h.bgpGC = nil
		ok, err := e.RecoverBGPAfterRestart(context.Background(), false)
		if err != nil || !ok {
			t.Fatalf("restart %d: %v %v", i, ok, err)
		}
		waitIntentRecovery(t)
		if BGPPending() || len(h.bgpNeighbors) != 1 {
			t.Fatalf("restart %d lost intent: %+v", i, h.bgpNeighbors)
		}
	}
}

func TestBGPDeleteAcknowledgedBeforeSpeakerReadFailure(t *testing.T) {
	h, d, e := intentFixture(t)
	d.Domains.BGP.Neighbors = []cmn.GoBGPNeighGetMod{{Addr: "192.0.2.23", RemoteAS: 65123}}
	RememberBGPIntent(d)
	_, err := ChangeBGPIntent(h, &cmn.GoBGPNeighMod{Addr: net.ParseIP("192.0.2.23")}, false, func() (int, error) {
		h.failOn["NetGoBGPGCGet"] = errors.New("daemon died after delete acknowledgement")
		return 0, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A concurrent/unrelated persist must carry the acknowledged deletion,
	// even before the supervisor has published a pending group.
	_, saved, err := WriteThrough(h, e.GatewayVersion, e.Hostname, e.PreRestoreDir)
	if err != nil || len(saved.Domains.BGP.Neighbors) != 0 {
		t.Fatalf("stale deletion persisted: %+v %v", saved, err)
	}
	delete(h.failOn, "NetGoBGPGCGet")
	ok, err := e.RecoverBGPAfterRestart(context.Background(), false)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	waitIntentRecovery(t)
	if len(h.bgpNeighbors) != 0 || BGPPending() {
		t.Fatal("deleted neighbor resurrected")
	}
}

func TestBGPFailedMutationKeepsIntentAndQueuedReplacementWins(t *testing.T) {
	h, d, e := intentFixture(t)
	RememberBGPIntent(d)
	failure := errors.New("delete rejected")
	_, err := ChangeBGPIntent(h, &cmn.GoBGPGlobalConfig{LocalAs: 64599}, true, func() (int, error) { return 0, failure })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	bgpRecovery.mu.RLock()
	got := bgpRecovery.intent.Domains.BGP.GlobalConfig.LocalAs
	bgpRecovery.mu.RUnlock()
	if got != 65122 {
		t.Fatal("failed API changed intent")
	}
	unlock := LockBGPRecovery()
	if err = e.StartPendingBGP(encodeDoc(t, d), bgpComponents); err != nil {
		unlock()
		t.Fatal(err)
	}
	bgpRecovery.mu.RLock()
	p := bgpRecovery.pending
	bgpRecovery.mu.RUnlock()
	ResolvePendingBGP()
	replacement := cloneBGPDocument(d)
	replacement.Domains.BGP.GlobalConfig.LocalAs = 64512
	RememberBGPIntent(replacement)
	unlock()
	<-p.done
	bgpRecovery.mu.RLock()
	got = bgpRecovery.intent.Domains.BGP.GlobalConfig.LocalAs
	bgpRecovery.mu.RUnlock()
	if got != 64512 || len(h.Calls) > 0 {
		t.Fatalf("obsolete retry ran: %d %v", got, h.Calls)
	}
}

func TestBGPMutationSerializesWithDaemonRecovery(t *testing.T) {
	h, d, e := intentFixture(t)
	RememberBGPIntent(d)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = ChangeBGPIntent(h, &cmn.GoBGPNeighMod{Addr: net.ParseIP("192.0.2.99"), RemoteAS: 65199}, true, func() (int, error) { close(entered); <-release; return 0, nil })
	}()
	<-entered
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = e.RecoverBGPAfterRestart(context.Background(), false) }()
	close(release)
	<-done
	wg.Wait()
	waitIntentRecovery(t)
	if len(h.bgpNeighbors) != 1 || h.bgpNeighbors[0].Addr != "192.0.2.99" {
		t.Fatal("recovery used pre-ack intent")
	}
}

func TestBGPIntentAppendDeleteAndOwnership(t *testing.T) {
	_, d, _ := intentFixture(t)
	for _, v := range []any{
		&cmn.GoBGPPolicyDefinedSetMod{Name: "set", DefinedTypeString: "Community", List: []string{"65122:1"}},
		&cmn.GoBGPPolicyDefinedSetMod{Name: "set", DefinedTypeString: "community", List: []string{"65122:1", "65122:2"}},
		&cmn.GoBGPPolicyApply{NeighIPAddress: "global", PolicyType: "export", Polices: []string{"first"}, RouteAction: "reject"},
		&cmn.GoBGPPolicyApply{NeighIPAddress: "global", PolicyType: "export", Polices: []string{"second"}},
	} {
		if err := editBGPIntent(d, v, true); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.Domains.BGP.DefinedSets) != 1 || len(d.Domains.BGP.DefinedSets[0].List) != 2 {
		t.Fatal(d.Domains.BGP.DefinedSets)
	}
	if a := d.Domains.BGPPolicyAssignment[0]; strings.Join(a.Polices, ",") != "first,second" || a.RouteAction != "reject" {
		t.Fatal(a)
	}
	_ = editBGPIntent(d, &cmn.GoBGPPolicyApply{NeighIPAddress: "global", PolicyType: "export", Polices: []string{"first"}}, false)
	if a := d.Domains.BGPPolicyAssignment[0]; len(a.Polices) != 1 || a.Polices[0] != "second" || a.RouteAction != "reject" {
		t.Fatal(a)
	}
	RememberBGPIntent(d)
	d.Domains.BGP.DefinedSets[0].List[0] = "changed"
	bgpRecovery.mu.RLock()
	cached := bgpRecovery.intent.Domains.BGP.DefinedSets[0].List[0]
	bgpRecovery.mu.RUnlock()
	if cached == "changed" {
		t.Fatal("intent aliases caller data")
	}
}

func waitIntentRecovery(t *testing.T) {
	t.Helper()
	unlock := LockBGPRecovery()
	bgpRecovery.mu.RLock()
	p := bgpRecovery.pending
	bgpRecovery.mu.RUnlock()
	unlock()
	if p == nil {
		return
	}
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		t.Fatal("recovery stuck")
	}
}

func TestBGPPersistedIntentSuppressesObsoleteYAML(t *testing.T) {
	_, d, e := intentFixture(t)
	if BGPIntentOwnsSpeaker(e.PreRestoreDir, true) {
		t.Fatal("fresh speaker incorrectly owned by API")
	}
	d.BGPAPIAdopted = true
	if _, _, _, err := Persist(d, e.PreRestoreDir); err != nil {
		t.Fatal(err)
	}
	if !BGPIntentOwnsSpeaker(e.PreRestoreDir, true) {
		t.Fatal("durable BGP did not own replacement")
	}
	path := filepath.Join(e.PreRestoreDir, PersistFileName)
	if err := os.WriteFile(path, []byte(`{"broken":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if BGPIntentOwnsSpeaker(e.PreRestoreDir, true) {
		t.Fatal("corrupt snapshot took ownership")
	}
}

func TestBGPPartialReplacementPreservesUnselectedIntent(t *testing.T) {
	_, d, e := intentFixture(t)
	RememberBGPIntent(d)
	replacement := cloneBGPDocument(d)
	replacement.Domains.BGP.GlobalConfig.LocalAs = 64513 // deliberately unselected
	replacement.Domains.BGPPolicyAssignment = []cmn.GoBGPPolicyApply{{NeighIPAddress: "global", PolicyType: "export", Polices: []string{"new"}, RouteAction: "reject"}}
	selected, _ := Select([]string{DomainBGPPolicyAssignment})
	e.rememberBGPSelection(replacement, selected, true)
	bgpRecovery.mu.RLock()
	got := cloneBGPDocument(bgpRecovery.intent)
	bgpRecovery.mu.RUnlock()
	if got.Domains.BGP.GlobalConfig.LocalAs != 65122 || got.Domains.BGPPolicyAssignment[0].Polices[0] != "new" {
		t.Fatal("partial restore changed unselected BGP", got.Domains)
	}
}

func TestBGPPendingCrashRetainsActiveTarget(t *testing.T) {
	h, d, e := intentFixture(t)
	RememberBGPIntent(d)
	pending := cloneBGPDocument(d)
	pending.Domains.BGP.GlobalConfig.LocalAs = 65133
	start, err := e.PreparePendingBGP(encodeDoc(t, pending), bgpComponents)
	if err != nil {
		t.Fatal(err)
	}
	bgpRecovery.mu.RLock()
	before := bgpRecovery.pending
	bgpRecovery.mu.RUnlock()
	if active, err := e.RecoverBGPAfterRestart(context.Background(), false); err != nil || !active {
		t.Fatal(active, err)
	}
	bgpRecovery.mu.RLock()
	after := bgpRecovery.pending
	bgpRecovery.mu.RUnlock()
	if before != after {
		t.Fatal("restart replaced pending target with obsolete completed intent")
	}
	start()
	waitIntentRecovery(t)
	if h.bgpGC.LocalAs != 65133 {
		t.Fatal("wrong pending target applied")
	}
}
