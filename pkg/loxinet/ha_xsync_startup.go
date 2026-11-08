package loxinet

import (
	"context"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const peerHelloInterval = 30 * time.Second
const peerRetryMin = 2 * time.Second
const peerRetryMax = 30 * time.Second

// A generation belongs to one membership entry. Removal never waits for its
// network call, and a result from an old generation cannot republish a client.
type peerSyncState struct {
	mu          sync.Mutex
	removed     atomic.Bool
	nextAttempt time.Time
	nextHello   time.Time
	backoff     time.Duration
}

func (dp *DpH) peerTime() time.Time {
	if dp.syncNow != nil {
		return dp.syncNow()
	}
	return time.Now()
}
func (dp *DpH) wakePeerSync() {
	select {
	case dp.syncWake <- struct{}{}:
	default:
	}
}

func (dp *DpH) runPeerSync(ctx context.Context) {
	defer close(dp.syncDone)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-dp.syncWake:
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return
		}
		dp.RequestPeerSync()
	}
}

func (dp *DpH) peerSnapshot() ([]DpPeer, bool) {
	dp.SyncMtx.Lock()
	defer dp.SyncMtx.Unlock()
	if !dp.peerInitDone {
		return nil, false
	}
	for i := range dp.Peers {
		if dp.Peers[i].syncState == nil {
			dp.Peers[i].syncState = &peerSyncState{}
		}
	}
	return append([]DpPeer(nil), dp.Peers...), true
}

func (dp *DpH) expectPeer(key string, present bool) {
	dp.remoteMtx.Lock()
	defer dp.remoteMtx.Unlock()
	if dp.expectedPeers == nil {
		dp.expectedPeers = make(map[string]bool)
	}
	if present {
		dp.expectedPeers[key] = true
	} else {
		delete(dp.expectedPeers, key)
	}
	delete(dp.Remotes, key)
}
func (dp *DpH) forgetPeerHello(key string) {
	dp.remoteMtx.Lock()
	delete(dp.Remotes, key)
	dp.remoteMtx.Unlock()
}

// A failed call can finish after remove/re-add of the same address. Keep the
// membership read lock through hello invalidation so it cannot clear the new
// generation's hello. Lock order remains SyncMtx -> remoteMtx.
func (dp *DpH) forgetPeerGenerationHello(peer DpPeer) {
	dp.SyncMtx.RLock()
	defer dp.SyncMtx.RUnlock()
	for _, current := range dp.Peers {
		if current.syncState == peer.syncState {
			dp.forgetPeerHello(peer.Peer.String())
			return
		}
	}
}

func (dp *DpH) receivePeerHello(key string, id int) bool {
	ip := net.ParseIP(key)
	if ip == nil {
		return false
	}
	key = ip.String()
	dp.remoteMtx.Lock()
	defer dp.remoteMtx.Unlock()
	if !dp.expectedPeers[key] {
		return false
	}
	if dp.Remotes == nil {
		dp.Remotes = make(map[string]XSync)
	}
	dp.Remotes[key] = XSync{RemoteID: id, RPCState: true}
	return true
}

func (dp *DpH) callPeer(snapshot DpPeer, op DpSyncOpT, arg interface{}) int {
	state := snapshot.syncState
	// A CT update on the datapath ticker must not queue behind a slow probe.
	if state == nil || !state.mu.TryLock() {
		return -1
	}
	defer state.mu.Unlock()
	if state.removed.Load() {
		return -1
	}
	var pe DpPeer
	found := false
	dp.SyncMtx.RLock()
	for _, p := range dp.Peers {
		if p.syncState == state {
			pe = p
			found = true
			break
		}
	}
	dp.SyncMtx.RUnlock()
	if !found {
		return -1
	}
	defer func() {
		dp.SyncMtx.Lock()
		defer dp.SyncMtx.Unlock()
		for i := range dp.Peers {
			if dp.Peers[i].syncState == state && !state.removed.Load() {
				dp.Peers[i].Client = pe.Client
				dp.Peers[i].ctRequested = pe.ctRequested
				return
			}
		}
		if pe.Client != nil {
			dp.RPC.RPCHooks.RPCClose(&pe)
		}
	}()
	now := dp.peerTime()
	if now.Before(state.nextAttempt) {
		return -1
	}
	hello := false
	if c, ok := arg.(*DpCtInfo); ok && c != nil {
		hello = c.Proto == "xsync"
	}
	if hello && now.Before(state.nextHello) {
		return 0
	}
	if op == DpSyncGet && pe.ctRequested {
		return 0
	}
	fail := func() int {
		pe.ctRequested = false
		dp.forgetPeerGenerationHello(pe)
		if pe.Client != nil {
			dp.RPC.RPCHooks.RPCClose(&pe)
		}
		if state.backoff == 0 {
			state.backoff = peerRetryMin
		} else {
			state.backoff *= 2
		}
		if state.backoff > peerRetryMax {
			state.backoff = peerRetryMax
		}
		state.nextAttempt = dp.peerTime().Add(state.backoff)
		return -1
	}
	if pe.Client == nil {
		// Only the independent hello/get worker opens connections. Datapath updates
		// retain their retry state instead of dialing a failed peer on the ticker.
		if !hello && op != DpSyncGet {
			dp.wakePeerSync()
			return -1
		}
		if dp.RPC.RPCHooks.RPCConnect(&pe) != 0 {
			return fail()
		}
	}
	reply, err := dp.sendPeerRPC(&pe, op, arg)
	if err != nil || reply != 0 {
		return fail()
	}
	state.backoff = 0
	state.nextAttempt = time.Time{}
	if hello {
		state.nextHello = dp.peerTime().Add(peerHelloInterval)
	}
	if op == DpSyncGet {
		pe.ctRequested = true
		tk.LogIt(tk.LogInfo, "HA stage=ct-request peer=%s result=accepted ct_complete=unverified\n", pe.Peer.String())
	}
	return 0
}

func (dp *DpH) sendPeerRPC(pe *DpPeer, op DpSyncOpT, arg interface{}) (int, error) {
	var cti *DpCtInfo
	var block []DpCtInfo
	switch a := arg.(type) {
	case *DpCtInfo:
		cti = a
	case []DpCtInfo:
		block = a
	}
	method := ""
	if op == DpSyncAdd || op == DpSyncDelete || op == DpSyncBcast {
		if op != DpSyncBcast {
			var one *DpCtInfo
			if cti != nil {
				one = cti
			} else if len(block) > 0 {
				one = &block[0]
			} else {
				return -1, nil
			}
			role, _ := mh.has.CIStateGetInst(one.CI)
			if role != cmn.CIMasterStateString {
				return 0, nil
			}
		}
		method = "XSync.DpWorkOnCtAdd"
		if op == DpSyncDelete {
			method = "XSync.DpWorkOnCtDelete"
		}
		if len(block) > 0 {
			method = "XSync.DpWorkOnBlockCtAdd"
			if op == DpSyncDelete {
				method = "XSync.DpWorkOnBlockCtDelete"
			}
		}
		if cti != nil {
			return dp.RPC.RPCHooks.RPCSend(pe, method, *cti)
		}
		return dp.RPC.RPCHooks.RPCSend(pe, method, block)
	}
	switch op {
	case DpSyncGet:
		method = "XSync.DpWorkOnCtGet"
	case DpSyncSockproxySession:
		method = "XSync.SockproxySessionMod"
	case DpSyncSockproxyBulkGet:
		method = "XSync.SockproxySessionBulkGet"
	case DpSyncRateLimiter:
		method = "XSync.RateLimiterSync"
	case DpSyncSockproxySnapshot:
		method = "XSync.GetSockproxySnapshot"
	default:
		return -1, nil
	}
	return dp.RPC.RPCHooks.RPCSend(pe, method, int32(1))
}
