package snapshot

import (
	"context"
	"errors"
	"fmt"
	cmn "github.com/loxilb-io/loxilb/common"
	"strings"
	"testing"
	"time"
)

func TestBGPOwnershipMatrix(t *testing.T) {
	for _, static := range []bool{false, true} {
		for _, marker := range []bool{false, true} {
			for _, retained := range []bool{false, true} {
				t.Run(fmt.Sprintf("static=%t/marker=%t/retained=%t", static, marker, retained), func(t *testing.T) {
					_, d, e := intentFixture(t)
					d.BGPAPIAdopted = marker
					if _, _, _, err := Persist(d, e.PreRestoreDir); err != nil {
						t.Fatal(err)
					}
					if retained {
						RememberBGPIntent(d)
					}
					if got := BGPIntentOwnsSpeaker(e.PreRestoreDir, static); got != (!static || marker) {
						t.Fatalf("ownership %t", got)
					}
					if BGPIntentAdopted() {
						t.Fatal("retention or persist adopted YAML")
					}
				})
			}
		}
	}
}

func TestBGPUnadoptedYAMLDoesNotReplayOnCrash(t *testing.T) {
	h, d, e := intentFixture(t)
	RememberBGPIntent(d)
	active, err := e.RecoverBGPAfterRestart(context.Background(), true)
	if err != nil || active || BGPPending() || len(h.Calls) != 0 {
		t.Fatalf("YAML recovery replayed: %t %v %v", active, err, h.Calls)
	}
}

type healthyBGPFixture struct {
	*mockHooks
	healthy    bool
	generation uint64
}

func (h *healthyBGPFixture) NetBGPRecoveryHealthy() bool      { return h.healthy }
func (h *healthyBGPFixture) NetBGPRecoveryGeneration() uint64 { return h.generation }
func TestBGPHealthyCaptureRefreshesOutOfBandChanges(t *testing.T) {
	h, d, _ := intentFixture(t)
	h.bgpGC = d.Domains.BGP.GlobalConfig
	RememberBGPIntent(d)
	live := &healthyBGPFixture{mockHooks: h, healthy: true}
	h.bgpNeighbors = []cmn.GoBGPNeighGetMod{{Addr: "192.0.2.77", RemoteAS: 65177}}
	captured, err := Capture(live, "test", "test", TriggerManual, bgpComponents)
	if err != nil || len(captured.Domains.BGP.Neighbors) != 1 {
		t.Fatalf("out-of-band omitted: %+v %v", captured, err)
	}
	live.healthy = false
	h.bgpGC = nil
	h.bgpNeighbors = nil
	captured, err = Capture(live, "test", "test", TriggerWriteThrough, bgpComponents)
	if err != nil || len(captured.Domains.BGP.Neighbors) != 1 || captured.Domains.BGP.GlobalConfig == nil {
		t.Fatalf("outage erased intent: %+v %v", captured, err)
	}
	if captured.BGPAPIAdopted {
		t.Fatal("live capture adopted YAML")
	}
}

type crashingBGPFixture struct{ *healthyBGPFixture }

func (h *crashingBGPFixture) NetGoBGPNeighGet() ([]cmn.GoBGPNeighGetMod, error) {
	h.healthy = false
	h.generation++
	return nil, errors.New("daemon killed mid-capture")
}
func TestBGPCrashMidCaptureKeepsPriorIntent(t *testing.T) {
	h, d, _ := intentFixture(t)
	h.bgpGC = d.Domains.BGP.GlobalConfig
	d.Domains.BGP.Neighbors = []cmn.GoBGPNeighGetMod{{Addr: "192.0.2.88", RemoteAS: 65188}}
	RememberBGPIntent(d)
	live := &crashingBGPFixture{&healthyBGPFixture{mockHooks: h, healthy: true}}
	got, err := Capture(live, "test", "test", TriggerWriteThrough, bgpComponents)
	if err != nil || got.Domains.BGP.GlobalConfig == nil || len(got.Domains.BGP.Neighbors) != 1 {
		t.Fatalf("crash captured empty: %+v %v", got, err)
	}
}

func TestBGPInteractiveAdoptionPersistsAndBootDoesNotInventIt(t *testing.T) {
	h, d, e := intentFixture(t)
	h.bgpGC = d.Domains.BGP.GlobalConfig
	selected, _ := Select(bgpComponents)
	e.rememberBGPSelection(d, selected, false)
	if BGPIntentAdopted() {
		t.Fatal("unmarked boot adopted")
	}
	e.rememberBGPSelection(d, selected, true)
	if !BGPIntentAdopted() {
		t.Fatal("interactive restore did not adopt")
	}
	_, saved, err := WriteThrough(h, e.GatewayVersion, e.Hostname, e.PreRestoreDir)
	if err != nil || !saved.BGPAPIAdopted {
		t.Fatalf("marker lost: %+v %v", saved, err)
	}
}

func TestBGPPolicyFallbackDeduplicates(t *testing.T) {
	_, d, _ := intentFixture(t)
	a := &cmn.GoBGPPolicyApply{NeighIPAddress: "global", PolicyType: "export", Polices: []string{"one", "one", "two"}}
	for i := 0; i < 2; i++ {
		if err := editBGPIntent(d, a, true); err != nil {
			t.Fatal(err)
		}
	}
	if p := d.Domains.BGPPolicyAssignment[0].Polices; len(p) != 2 || p[0] != "one" || p[1] != "two" {
		t.Fatal(p)
	}
}

type replacedBGPFixture struct{ *healthyBGPFixture }

func (h *replacedBGPFixture) NetGoBGPNeighGet() ([]cmn.GoBGPNeighGetMod, error) {
	h.generation++ // Replacement answers successfully with the same ASN, no peers.
	return nil, nil
}
func TestBGPGenerationChangeWithoutReadErrorKeepsPriorIntent(t *testing.T) {
	h, d, _ := intentFixture(t)
	h.bgpGC = d.Domains.BGP.GlobalConfig
	d.Domains.BGP.Neighbors = []cmn.GoBGPNeighGetMod{{Addr: "192.0.2.88", RemoteAS: 65188}}
	RememberBGPIntent(d)
	live := &replacedBGPFixture{&healthyBGPFixture{mockHooks: h, healthy: true}}
	got, err := Capture(live, "test", "test", TriggerWriteThrough, bgpComponents)
	if err != nil || got.Domains.BGP.GlobalConfig == nil || len(got.Domains.BGP.Neighbors) != 1 {
		t.Fatalf("replacement erased intent: %+v %v", got, err)
	}
}

type staticBGPReviewHook struct {
	*mockHooks
	static    bool
	completed bool
}

func (h *staticBGPReviewHook) NetBGPStaticConfigPresent() bool { return h.static }
func (h *staticBGPReviewHook) NetBGPRecoveryComplete() {
	h.completed = true
	SetBGPDaemonConfigPending(false)
}
func TestBGPUnadoptedDifferingYAMLBootSkipsEntireGroup(t *testing.T) {
	h, d, e := intentFixture(t)
	live := &staticBGPReviewHook{mockHooks: h, static: true}
	e.Hooks = live
	d.IncludedDomains = append([]string(nil), bgpComponents...)
	d.Domains = Domains{BGP: BGPDomain{GlobalConfig: d.Domains.BGP.GlobalConfig, Neighbors: []cmn.GoBGPNeighGetMod{{Addr: "192.0.2.23", RemoteAS: 65123}}}}
	h.bgpGC = &cmn.GoBGPGlobalConfig{LocalAs: 65199, RouterID: "192.0.2.99"}
	h.bgpNeighbors = []cmn.GoBGPNeighGetMod{{Addr: "192.0.2.99", RemoteAS: 65199}}
	raw := encodeDoc(t, d)
	independent, bgp, result, err := e.BootDomainGroups(raw)
	if err != nil || result.Result != ResultOK || len(independent) != 0 || len(bgp) != 0 {
		t.Fatalf("groups: %v %v %+v %v", independent, bgp, result, err)
	}
	result, err = e.Restore(raw, RestoreOptions{Boot: true})
	if err != nil || result.Result != ResultOK || len(result.Plan) != 0 {
		t.Fatalf("boot: %+v %v", result, err)
	}
	start, err := e.PreparePendingBGP(raw, bgpComponents)
	if err != nil {
		t.Fatal(err)
	}
	start()
	if BGPPending() {
		t.Fatal("unadopted group published")
	}
	for _, call := range h.Calls {
		if strings.HasPrefix(call, "NetGoBGP") {
			t.Fatal("boot touched YAML", h.Calls)
		}
	}
	if h.bgpGC.LocalAs != 65199 || len(h.bgpNeighbors) != 1 || h.bgpNeighbors[0].Addr != "192.0.2.99" || BGPIntentAdopted() {
		t.Fatal("YAML changed or adopted")
	}
}
func TestBGPUnadoptedPendingCrashCancelsOverlayAndReleasesGate(t *testing.T) {
	h, d, e := intentFixture(t)
	live := &staticBGPReviewHook{mockHooks: h, static: true}
	e.Hooks = live
	holdPendingForTest(t, d)
	SetBGPDaemonConfigPending(true)
	active, err := e.RecoverBGPAfterRestart(context.Background(), true)
	if err != nil || active || BGPPending() || BGPDaemonConfigPending() || !live.completed || len(h.Calls) != 0 {
		t.Fatalf("pending YAML overlay survived: %t %v %v", active, err, h.Calls)
	}
}
func TestBGPUnhealthyFirstCaptureDoesNotRetainPartialIntent(t *testing.T) {
	h, d, _ := intentFixture(t)
	h.bgpGC = d.Domains.BGP.GlobalConfig
	live := &healthyBGPFixture{mockHooks: h, healthy: false}
	got, err := Capture(live, "test", "test", TriggerManual, bgpComponents)
	if err != nil || got.Domains.BGP.GlobalConfig == nil {
		t.Fatal(got, err)
	}
	bgpRecovery.mu.RLock()
	retained := bgpRecovery.intent
	bgpRecovery.mu.RUnlock()
	if retained != nil {
		t.Fatal("unhealthy first read seeded recovery")
	}
}

type waitingIntentHook struct {
	*mockHooks
	checked bool
}

func (h *waitingIntentHook) NetBGPWaitForStartup() error {
	acquired := make(chan struct{})
	go func() { unlock := LockBGPRecovery(); unlock(); close(acquired) }()
	select {
	case <-acquired:
		h.checked = true
		return nil
	case <-time.After(time.Second):
		return errors.New("startup wait held recovery op")
	}
}
func TestBGPStartupWaitPrecedesIntentOperationLock(t *testing.T) {
	h, d, _ := intentFixture(t)
	h.bgpGC = d.Domains.BGP.GlobalConfig
	startup := &waitingIntentHook{mockHooks: h}
	_, err := ChangeBGPIntent(startup, d.Domains.BGP.GlobalConfig, true, func() (int, error) { return 0, nil })
	if err != nil || !startup.checked {
		t.Fatal("wait/op order", err)
	}
}

func TestBGPYAMLCrashPreservesIndependentBootFailure(t *testing.T) {
	h, _, e := intentFixture(t)
	e.Hooks = &staticBGPReviewHook{mockHooks: h, static: true}
	RecordBootRestoreState(BootRestoreState{Degraded: true, Reasons: []string{"independent-domain failure"}})
	if active, err := e.RecoverBGPAfterRestart(context.Background(), true); err != nil || active {
		t.Fatal(active, err)
	}
	state := BootRestoreStateGet()
	if !state.Degraded || state.Succeeded || len(state.Reasons) != 1 || state.Reasons[0] != "independent-domain failure" {
		t.Fatal("YAML skip masked independent failure", state)
	}
}

func TestBGPUnconfiguredFirstCaptureDoesNotRetainIntent(t *testing.T) {
	h, _, _ := intentFixture(t)
	live := &healthyBGPFixture{mockHooks: h, healthy: true} // stale Connected, no ASN
	got, err := Capture(live, "test", "test", TriggerManual, bgpComponents)
	if err != nil || got.Domains.BGP.GlobalConfig != nil {
		t.Fatal(got, err)
	}
	bgpRecovery.mu.RLock()
	retained := bgpRecovery.intent
	bgpRecovery.mu.RUnlock()
	if retained != nil {
		t.Fatal("unconfigured speaker seeded recovery")
	}
}
