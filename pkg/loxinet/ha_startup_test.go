package loxinet

import (
	"context"
	"errors"
	cmn "github.com/loxilb-io/loxilb/common"
	opts "github.com/loxilb-io/loxilb/options"
	api "github.com/osrg/gobgp/v3/api"
	"net"
	"sync"
	"testing"
	"time"
)

func TestHAStartupUndefinedRoleBlocksAllAdvertisements(t *testing.T) {
	old := opts.Opts.ClusterNodes
	opts.Opts.ClusterNodes = "192.0.2.2"
	defer func() { opts.Opts.ClusterNodes = old }()
	for _, path := range []string{"add", "recovery"} {
		t.Run(path, func(t *testing.T) {
			c := &pendingPathClient{}
			h := GoBgpH{client: c, localAs: 65122, state: BGPConnected, ciMap: map[string]*goCI{"llb-inst0": {vip: net.IPv4zero, hastate: cmn.CIStateNotDefined, rules: map[string]int{}}}}
			h.requireRole.Store(true) // role management, not CT peer presence
			if path == "add" {
				h.AddBGPRule("llb-inst0", []string{"192.0.2.23"})
			} else {
				h.ciMap["llb-inst0"].rules["192.0.2.23"] = 1
				h.reAdvertise = true
				h.goBGPHouseKeeper()
			}
			if len(c.paths) != 0 {
				t.Fatalf("undefined HA role advertised %d routes via %s", len(c.paths), path)
			}
		})
	}
}
func TestHAStartupEmptyPeerListIsNotConfiguredSync(t *testing.T) {
	oldHas, oldDP, oldNodes := mh.has, mh.dp, opts.Opts.ClusterNodes
	defer func() { mh.has, mh.dp, opts.Opts.ClusterNodes = oldHas, oldDP, oldNodes }()
	opts.Opts.ClusterNodes = "192.0.2.2"
	mh.has = &CIStateH{NodeMap: map[string]*ClusterNode{}}
	dp := &DpH{}
	mh.dp = dp
	if dp.DpXsyncRPC(DpSyncGet, nil) == 0 {
		t.Fatal("first ticker accepted empty peers before configured peer registration")
	}
}

type startupRPC struct {
	connects, gets, hellos int
	fail                   bool
}

func (r *startupRPC) RPCConnect(p *DpPeer) int { r.connects++; p.Client = true; return 0 }
func (r *startupRPC) RPCReset(p *DpPeer) int   { p.Client = nil; return 0 }
func (r *startupRPC) RPCClose(p *DpPeer) int   { p.Client = nil; return 0 }
func (r *startupRPC) RPCSend(p *DpPeer, method string, _ any) (int, error) {
	if r.fail {
		return -1, errors.New("disconnected")
	}
	if method == "XSync.DpWorkOnCtGet" {
		r.gets++
	} else {
		r.hellos++
	}
	return 0, nil
}

func TestHAStartupPeerRegistrationReconnectAndDelete(t *testing.T) {
	rpc := &startupRPC{}
	now := time.Now()
	dp := &DpH{RPC: &XSync{RPCHooks: rpc}, syncNow: func() time.Time { return now }}
	// The first ticker may run before initialization/peer registration.
	dp.RequestPeerSync()
	if rpc.gets != 0 || dp.DpXsyncInSync() {
		t.Fatal("uninitialized peer set became ready")
	}
	dp.FinishPeerInit()
	if !dp.DpXsyncInSync() {
		t.Fatal("standalone zero-peer node is not ready")
	}
	add := func(ip string) {
		t.Helper()
		if dp.DpWorkOnPeerOp(&PeerDpWorkQ{Work: DpCreate, PeerIP: net.ParseIP(ip)}) != 0 {
			t.Fatal("add failed")
		}
	}
	add("192.0.2.2")
	if dp.DpXsyncInSync() {
		t.Fatal("new peer inherited standalone readiness")
	}
	dp.RequestPeerSync()
	dp.RequestPeerSync()
	if rpc.gets != 1 || rpc.hellos != 1 {
		t.Fatalf("initial requests: %+v", rpc)
	}
	// An accepted async request alone cannot prove the reverse hello or CT transfer.
	if dp.DpXsyncInSync() {
		t.Fatal("async acceptance mistaken for hello readiness")
	}
	dp.remoteMtx.Lock()
	dp.Remotes = map[string]XSync{"192.0.2.2": {RemoteID: 2, RPCState: true}}
	dp.remoteMtx.Unlock()
	if !dp.DpXsyncInSync() {
		t.Fatal("hello not observed")
	}
	add("192.0.2.3")
	dp.RequestPeerSync()
	if rpc.gets != 2 {
		t.Fatalf("dynamic add did not request exactly new peer: %+v", rpc)
	}
	rpc.fail = true
	now = now.Add(peerHelloInterval)
	dp.RequestPeerSync()
	if dp.DpXsyncInSync() {
		t.Fatal("failed transport retained readiness")
	}
	rpc.fail = false
	now = now.Add(peerRetryMin)
	dp.RequestPeerSync()
	dp.RequestPeerSync()
	if rpc.gets != 4 {
		t.Fatalf("reconnected peers not requested exactly once: %+v", rpc)
	}
	for _, ip := range []string{"192.0.2.2", "192.0.2.3"} {
		if dp.DpWorkOnPeerOp(&PeerDpWorkQ{Work: DpRemove, PeerIP: net.ParseIP(ip)}) != 0 {
			t.Fatal("delete failed")
		}
	}
	dp.RequestPeerSync()
	if !dp.DpXsyncInSync() || rpc.gets != 4 {
		t.Fatal("deleted peers retained sync work")
	}
	add("192.0.2.2")
	dp.RequestPeerSync()
	if rpc.gets != 5 {
		t.Fatal("readded peer inherited removed transport state")
	}
}

func TestHAStartupWaitOutcomesAndDeadline(t *testing.T) {
	if xsyncReadyTimeout != 90*time.Second {
		t.Fatal("default changed")
	}
	dp := &DpH{}
	if got := dp.waitXsyncReady(context.Background(), 15*time.Millisecond, time.Millisecond); got != xsyncTimeout {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := dp.waitXsyncReady(ctx, time.Hour, time.Millisecond); got != xsyncCancelled {
		t.Fatal(got)
	}
	dp.FinishPeerInit()
	if got := dp.waitXsyncReady(context.Background(), time.Second, time.Millisecond); got != xsyncReady {
		t.Fatal(got)
	}
	// A blocked outbound RPC must not hold the deadline or cancellation hostage.
	dp.SyncMtx.Lock()
	begin := time.Now()
	got := dp.waitXsyncReady(context.Background(), 15*time.Millisecond, time.Millisecond)
	dp.SyncMtx.Unlock()
	if got != xsyncTimeout || time.Since(begin) > time.Second {
		t.Fatal("outbound lock extended deadline", got)
	}
}

func TestHAStartupSimultaneousGetDoesNotWaitOnOutboundTicker(t *testing.T) {
	oldDP, oldReady := mh.dp, mh.ready
	defer func() { mh.dp, mh.ready = oldDP, oldReady }()
	e := &DpEbpfH{ctBcast: make(chan bool, 1), stop: make(chan struct{})}
	dp := &DpH{DpHooks: e, expectedPeers: map[string]bool{"192.0.2.2": true}}
	mh.dp, mh.ready = dp, true
	dp.SyncMtx.Lock()
	defer dp.SyncMtx.Unlock()
	done := make(chan error, 1)
	go func() {
		xs := &XSync{peerIP: "192.0.2.2"}
		reply := 0
		if err := xs.DpWorkOnCtAdd(DpCtInfo{Proto: "xsync", Sport: 2}, &reply); err != nil {
			done <- err
			return
		}
		for i := 0; i < 3; i++ {
			if err := xs.DpWorkOnCtGet(1, &reply); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("hello/get blocked behind outbound RPC")
	}
	if len(e.ctBcast) != 1 {
		t.Fatal("broadcast requests not coalesced")
	}
}

func TestHAStartupMembershipConcurrentWithTick(t *testing.T) {
	rpc := &startupRPC{}
	dp := &DpH{RPC: &XSync{RPCHooks: rpc}}
	dp.FinishPeerInit()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			dp.RequestPeerSync()
			dp.DpXsyncInSync()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			dp.DpWorkOnPeerOp(&PeerDpWorkQ{Work: DpCreate, PeerIP: net.ParseIP("192.0.2.2")})
			dp.DpWorkOnPeerOp(&PeerDpWorkQ{Work: DpRemove, PeerIP: net.ParseIP("192.0.2.2")})
		}
	}()
	wg.Wait()
}

func TestHAStartupRoleSelectionAndRecovery(t *testing.T) {
	oldNodes, oldHas := opts.Opts.ClusterNodes, mh.has
	opts.Opts.ClusterNodes = "192.0.2.2"
	mh.has = &CIStateH{ClusterMap: map[string]*ClusterInstance{}}
	defer func() { opts.Opts.ClusterNodes, mh.has = oldNodes, oldHas }()
	c := &pendingPathClient{}
	h := GoBgpH{client: c, localAs: 65122, state: BGPConnected, ciMap: map[string]*goCI{}}
	h.requireRole.Store(true)
	h.AddBGPRule(cmn.CIDefault, []string{"192.0.2.23"})
	h.reAdvertise = true
	h.goBGPHouseKeeper()
	if len(c.paths) != 0 {
		t.Fatal("recovery bypassed role gate")
	}
	h.UpdateCIState(cmn.CIDefault, cmn.CIStateMaster, net.IPv4zero)
	h.UpdateCIState(cmn.CIDefault, cmn.CIStateBackup, net.IPv4zero)
	if len(c.paths) != 2 {
		t.Fatal("role selection failed to replay cached intent", len(c.paths))
	}
	for i, want := range []uint32{cmn.HighMed, cmn.LowMed} {
		found := false
		for _, a := range c.paths[i].Path.Pattrs {
			var v api.MultiExitDiscAttribute
			if a.UnmarshalTo(&v) == nil {
				found = true
				if v.Med != want {
					t.Fatal("role priority changed", v.Med, want)
				}
			}
		}
		if !found {
			t.Fatal("MED missing")
		}
	}
	// Deleted intent while disconnected cannot return on recovery/role change.
	h.state = BGPDisconnected
	h.DelBGPRule(cmn.CIDefault, []string{"192.0.2.23"})
	h.state = BGPConnected
	h.reAdvertise = true
	h.goBGPHouseKeeper()
	if len(c.paths) != 2 {
		t.Fatal("deleted intent resurrected")
	}
}

func TestHAStartupCancelledKAGateStaysClosed(t *testing.T) {
	oldCtx, oldDP := mh.shutdownCtx, mh.dp
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mh.shutdownCtx, mh.dp = ctx, &DpH{}
	defer func() { mh.shutdownCtx, mh.dp = oldCtx, oldDP }()
	ch := &CIStateH{initSync: make(chan struct{})}
	ch.waitInitialSync()
	select {
	case <-ch.initSync:
		t.Fatal("shutdown opened BFD gate")
	default:
	}
}

func TestHAStartupPausedHTTPHandshakeIsBounded(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	begin := time.Now()
	client, err := dialHTTPPath("tcp", listener.Addr().String(), "/_goRPC_")
	if client != nil {
		client.Close()
	}
	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("no connection accepted")
	}
	if err == nil || time.Since(begin) > 4*time.Second {
		t.Fatal("paused HTTP CONNECT escaped deadline", err, time.Since(begin))
	}
}

func TestHAStartupBGPWorkersCancel(t *testing.T) {
	oldCtx := mh.shutdownCtx
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mh.shutdownCtx = ctx
	defer func() { mh.shutdownCtx = oldCtx }()
	h := &GoBgpH{eventCh: make(chan goBgpEvent), ticker: time.NewTicker(time.Hour), fTicker: time.NewTicker(time.Hour)}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); h.goBgpConnect("127.0.0.1:1") }()
	go func() { defer wg.Done(); h.goBgpMonitor() }()
	go func() { defer wg.Done(); h.goBGPTicker() }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("BGP workers outlived cancellation")
	}
	begin := time.Now()
	waitBGPDelay(ctx, time.Hour)
	if time.Since(begin) > time.Second {
		t.Fatal("BGP retry delay ignored cancellation")
	}
}
