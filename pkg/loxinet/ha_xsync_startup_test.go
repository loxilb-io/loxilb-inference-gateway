package loxinet

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

type probeRPC struct {
	mu      sync.Mutex
	calls   map[string]int
	failing string
	entered chan struct{}
	release chan struct{}
}

func (r *probeRPC) RPCConnect(p *DpPeer) int { p.Client = true; return 0 }
func (r *probeRPC) RPCReset(p *DpPeer) int   { p.Client = nil; return 0 }
func (r *probeRPC) RPCClose(p *DpPeer) int   { p.Client = nil; return 0 }
func (r *probeRPC) RPCSend(p *DpPeer, _ string, _ any) (int, error) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[p.Peer.String()]++
	fail := p.Peer.String() == r.failing
	r.mu.Unlock()
	if fail {
		if r.entered != nil {
			select {
			case r.entered <- struct{}{}:
			default:
			}
			<-r.release
		}
		return -1, errors.New("failed peer")
	}
	return 0, nil
}
func addProbePeer(t *testing.T, dp *DpH, ip string) {
	t.Helper()
	if dp.DpWorkOnPeerOp(&PeerDpWorkQ{Work: DpCreate, PeerIP: net.ParseIP(ip)}) != 0 {
		t.Fatal("add", ip)
	}
}

func TestHAPeerHelloIdentityAndFailureIsolation(t *testing.T) {
	now := time.Now()
	rpc := &probeRPC{}
	dp := &DpH{RPC: &XSync{RPCHooks: rpc}, syncNow: func() time.Time { return now }}
	dp.FinishPeerInit()
	addProbePeer(t, dp, "192.0.2.2")
	addProbePeer(t, dp, "192.0.2.3")
	dp.RequestPeerSync()
	if dp.receivePeerHello("192.0.2.99", 0) {
		t.Fatal("unconfigured source accepted")
	}
	dp.receivePeerHello("192.0.2.2", 0)
	dp.receivePeerHello("192.0.2.3", 0)
	if !dp.DpXsyncInSync() {
		t.Fatal("distinct peers with equal legacy self ID did not become ready")
	}
	rpc.failing = "192.0.2.2"
	now = now.Add(peerHelloInterval)
	dp.RequestPeerSync()
	dp.remoteMtx.Lock()
	kept := dp.Remotes["192.0.2.3"].RPCState
	failed := dp.Remotes["192.0.2.2"].RPCState
	dp.remoteMtx.Unlock()
	if !kept || failed || dp.DpXsyncInSync() {
		t.Fatal("failure cleared unrelated hello or retained failed readiness")
	}
	if dp.DpWorkOnPeerOp(&PeerDpWorkQ{Work: DpRemove, PeerIP: net.ParseIP("192.0.2.2")}) != 0 {
		t.Fatal("remove")
	}
	if !dp.DpXsyncInSync() {
		t.Fatal("removing failed peer invalidated surviving peer")
	}
	addProbePeer(t, dp, "192.0.2.4")
	if dp.DpXsyncInSync() {
		t.Fatal("new peer inherited unrelated hello")
	}
	dp.RequestPeerSync()
	dp.receivePeerHello("192.0.2.4", 0)
	if !dp.DpXsyncInSync() {
		t.Fatal("matching all configured peers not ready")
	}
}

func TestHAPeerBackoffAndHealthyHelloCadence(t *testing.T) {
	now := time.Now()
	rpc := &probeRPC{failing: "192.0.2.2"}
	dp := &DpH{RPC: &XSync{RPCHooks: rpc}, syncNow: func() time.Time { return now }}
	dp.FinishPeerInit()
	addProbePeer(t, dp, "192.0.2.2")
	addProbePeer(t, dp, "192.0.2.3")
	dp.RequestPeerSync()
	for i := 0; i < 10; i++ {
		dp.RequestPeerSync()
	}
	if rpc.calls["192.0.2.2"] != 1 || rpc.calls["192.0.2.3"] != 2 {
		t.Fatal("unbounded retry/hello", rpc.calls)
	}
	now = now.Add(peerRetryMin)
	dp.RequestPeerSync()
	if rpc.calls["192.0.2.2"] != 2 || rpc.calls["192.0.2.3"] != 2 {
		t.Fatal("peer backoff affected healthy peer", rpc.calls)
	}
	now = now.Add(peerHelloInterval)
	dp.RequestPeerSync()
	if rpc.calls["192.0.2.3"] != 3 {
		t.Fatal("healthy accepted peer did not receive slower hello")
	}
}

func TestHASlowProbeDoesNotBlockMembershipOrBarrier(t *testing.T) {
	rpc := &probeRPC{failing: "192.0.2.2", entered: make(chan struct{}, 1), release: make(chan struct{})}
	dp := &DpH{RPC: &XSync{RPCHooks: rpc}}
	dp.FinishPeerInit()
	addProbePeer(t, dp, "192.0.2.2")
	done := make(chan struct{})
	go func() { defer close(done); dp.RequestPeerSync() }()
	<-rpc.entered
	began := time.Now()
	addProbePeer(t, dp, "192.0.2.3")
	if time.Since(began) > 100*time.Millisecond {
		t.Fatal("membership waited on outbound I/O")
	}
	if dp.DpWorkOnPeerOp(&PeerDpWorkQ{Work: DpRemove, PeerIP: net.ParseIP("192.0.2.2")}) != 0 {
		t.Fatal("remove")
	}
	close(rpc.release)
	<-done
	dp.SyncMtx.RLock()
	for _, pe := range dp.Peers {
		if pe.Peer.String() == "192.0.2.2" {
			t.Fatal("removed generation resurrected")
		}
	}
	dp.SyncMtx.RUnlock()
}

func TestHALegacyNetRPCHelloUsesTransportIdentity(t *testing.T) {
	oldDP, oldReady := mh.dp, mh.ready
	defer func() { mh.dp, mh.ready = oldDP, oldReady }()
	dp := &DpH{}
	dp.expectPeer("127.0.0.1", true)
	mh.dp, mh.ready = dp, true
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(serveXsyncHTTP)}
	go server.Serve(listener)
	defer server.Close()
	client, err := dialHTTPPath("tcp", listener.Addr().String(), "/_goRPC_")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	reply := 0
	if err := client.Call("XSync.DpWorkOnCtAdd", DpCtInfo{Proto: "xsync", Sport: 0}, &reply); err != nil {
		t.Fatal(err)
	}
	dp.remoteMtx.Lock()
	defer dp.remoteMtx.Unlock()
	if !dp.Remotes["127.0.0.1"].RPCState {
		t.Fatal("legacy hello not bound to TCP source")
	}
}

func TestHAIndependentSyncWorkerStops(t *testing.T) {
	dp := &DpH{syncWake: make(chan struct{}, 1), syncDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	go dp.runPeerSync(ctx)
	cancel()
	select {
	case <-dp.syncDone:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestHAStalePeerFailurePreservesReplacementHello(t *testing.T) {
	rpc := &probeRPC{failing: "192.0.2.2", entered: make(chan struct{}, 1), release: make(chan struct{})}
	dp := &DpH{RPC: &XSync{RPCHooks: rpc}}
	dp.FinishPeerInit()
	addProbePeer(t, dp, "192.0.2.2")
	done := make(chan struct{})
	go func() { defer close(done); dp.DpXsyncRPC(DpSyncBcast, &DpCtInfo{Proto: "xsync"}) }()
	<-rpc.entered
	if dp.DpWorkOnPeerOp(&PeerDpWorkQ{Work: DpRemove, PeerIP: net.ParseIP("192.0.2.2")}) != 0 {
		t.Fatal("remove")
	}
	addProbePeer(t, dp, "192.0.2.2")
	if !dp.receivePeerHello("192.0.2.2", 0) {
		t.Fatal("replacement hello rejected")
	}
	close(rpc.release)
	<-done
	dp.remoteMtx.Lock()
	kept := dp.Remotes["192.0.2.2"].RPCState
	dp.remoteMtx.Unlock()
	if !kept {
		t.Fatal("stale failed generation cleared replacement hello")
	}
	if dp.DpXsyncInSync() {
		t.Fatal("replacement inherited an accepted request from the removed peer")
	}
}
