/*
 * Copyright (c) 2022 NetLOX Inc
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

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CONV_ID_LEN 128

typedef struct proxy_sync_event {
    int      kind;
    char     service_key[64];
    char     conv_id[MAX_CONV_ID_LEN];
    int      prefill_ep_idx;
    int      decode_ep_idx;
    int      ep_idx;
    uint64_t created_ts;
    uint64_t last_access_ts;
    uint32_t request_count;
} proxy_sync_event_t;

extern int sockproxy_snapshot_all_sessions(proxy_sync_event_t **out_events, uint32_t *out_count);
*/
import "C"
import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"runtime/debug"
	"unsafe"

	opts "github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
	"google.golang.org/grpc"
)

// DpWorkOnBlockCtAdd - Add block CT entries from remote goRPC client
func (xs *XSync) DpWorkOnBlockCtAdd(blockCtis []DpCtInfo, ret *int) error {
	if !mh.ready {
		return errors.New("Not-Ready")
	}

	*ret = 0

	for _, cti := range blockCtis {

		tk.LogIt(tk.LogDebug, "RPC - Block CT Add %s\n", cti.Key())
		r := mh.dp.DpHooks.DpCtAdd(&cti)
		if r != 0 {
			*ret = r
		}
	}

	return nil
}

// DpWorkOnBlockCtDelete - Add block CT entries from remote
func (xs *XSync) DpWorkOnBlockCtDelete(blockCtis []DpCtInfo, ret *int) error {
	if !mh.ready {
		return errors.New("Not-Ready")
	}

	*ret = 0

	for _, cti := range blockCtis {

		tk.LogIt(tk.LogDebug, "RPC - Block CT Del %s\n", cti.Key())
		r := mh.dp.DpHooks.DpCtDel(&cti)
		if r != 0 {
			*ret = r
		}
	}

	return nil
}

// DpWorkOnCtAdd - Add a CT entry from remote goRPC client
func (xs *XSync) DpWorkOnCtAdd(cti DpCtInfo, ret *int) error {
	if !mh.ready {
		*ret = -1
		tk.LogIt(tk.LogDebug, "RPC - CT Xsync Not-Ready")
		return errors.New("Not-Ready")
	}

	if cti.Proto == "xsync" {
		mh.dp.SyncMtx.Lock()
		defer mh.dp.SyncMtx.Unlock()

		for idx := range mh.dp.Remotes {
			r := &mh.dp.Remotes[idx]
			if r.RemoteID == int(cti.Sport) {
				r.RPCState = true
				*ret = 0
				tk.LogIt(tk.LogDebug, "RPC - CT Xsync Remote-%v Already present\n", cti.Sport)
				return nil
			}
		}

		r := XSync{RemoteID: int(cti.Sport), RPCState: true}
		mh.dp.Remotes = append(mh.dp.Remotes, r)

		tk.LogIt(tk.LogDebug, "RPC - CT Xsync Remote-%v\n", cti.Sport)

		*ret = 0
		return nil
	}

	tk.LogIt(tk.LogDebug, "RPC - CT Add %s\n", cti.Key())

	r := mh.dp.DpHooks.DpCtAdd(&cti)
	*ret = r
	return nil
}

// DpWorkOnCtDelete - Delete a CT entry from remote goRPC client
func (xs *XSync) DpWorkOnCtDelete(cti DpCtInfo, ret *int) error {
	if !mh.ready {
		return errors.New("Not-Ready")
	}
	tk.LogIt(tk.LogDebug, "RPC -  CT Del %s\n", cti.Key())
	r := mh.dp.DpHooks.DpCtDel(&cti)
	*ret = r
	return nil
}

// DpWorkOnCtGet - Get all CT entries asynchronously goRPC client
func (xs *XSync) DpWorkOnCtGet(async int, ret *int) error {
	if !mh.ready {
		return errors.New("Not-Ready")
	}

	// Most likely need to reset reverse rpc channel
	mh.dp.DpXsyncRPCReset()

	tk.LogIt(tk.LogDebug, "RPC -  CT Get %d\n", async)
	mh.dp.DpHooks.DpCtGetAsync()
	*ret = 0

	return nil
}

func (xs *XSync) DpWorkOnCtGetGRPC(ctx context.Context, m *ConnGet) (*XSyncReply, error) {

	var resp int
	err := xs.DpWorkOnCtGet(int(m.Async), &resp)

	return &XSyncReply{Response: int32(resp)}, err
}

func (ci *CtInfo) ConvertToDpCtInfo() DpCtInfo {

	cti := DpCtInfo{
		DIP: ci.Dip, SIP: ci.Sip,
		Dport: uint16(ci.Dport), Sport: uint16(ci.Sport),
		Proto: ci.Proto, CState: ci.Cstate, CAct: ci.Cact, CI: ci.Ci,
		Packets: uint64(ci.Packets), Bytes: uint64(ci.Bytes), Deleted: int(ci.Deleted),
		PKey: ci.Pkey, PVal: ci.Pval,
		XSync: ci.Xsync, ServiceIP: ci.Serviceip, ServProto: ci.Servproto,
		L4ServPort: uint16(ci.L4Servport), BlockNum: uint32(ci.Blocknum),
	}
	return cti
}

func (xs *XSync) DpWorkOnBlockCtModGRPC(ctx context.Context, m *BlockCtInfoMod) (*XSyncReply, error) {
	var ctis []DpCtInfo
	var resp int
	var err error

	for _, ci := range m.Ct {
		cti := ci.ConvertToDpCtInfo()
		ctis = append(ctis, cti)
	}
	if m.Add {
		err = xs.DpWorkOnBlockCtAdd(ctis, &resp)
	} else {
		err = xs.DpWorkOnBlockCtDelete(ctis, &resp)
	}
	return &XSyncReply{Response: int32(resp)}, err
}

func (xs *XSync) DpWorkOnCtModGRPC(ctx context.Context, m *CtInfoMod) (*XSyncReply, error) {

	var resp int
	var err error

	ci := m.Ct
	cti := ci.ConvertToDpCtInfo()

	if m.Add {
		err = xs.DpWorkOnCtAdd(cti, &resp)
	} else {
		err = xs.DpWorkOnCtDelete(cti, &resp)
	}
	return &XSyncReply{Response: int32(resp)}, err
}

// sockproxy HA state sync handler stubs.
// Real implementations land in Task A3 (server-side install via CGO into
// proxy_sync_apply_session_entry); Task A1 ships these as Not-Ready /
// not-implemented-yet sentinel returns so that:
//   1. The XSyncServer interface is satisfied without depending on the
//      generated UnimplementedXSyncServer mixin.
//   2. The rolling-upgrade graceful-degrade test (SPEC D1) can probe via
//      the client side without needing the receiver to be feature-complete.

// SockproxySessionMod handles bulk session insert/delete batches from peers.
// Iterates m.Entries and CGO-calls proxy_sync_apply_session_entry for each;
// the receiver-side health gate + first-writer-wins conflict resolution live
// inside that C function (SPEC A5, A6). Per-entry outcome metric labels are
// incremented inside ApplyOne.
func (xs *XSync) SockproxySessionMod(ctx context.Context, m *SockproxySessionModReq) (*XSyncReply, error) {
	if !mh.ready {
		return &XSyncReply{Response: -1}, errors.New("Not-Ready")
	}
	tk.LogIt(tk.LogInfo, "[XSYNC_RCV] SockproxySessionMod add=%v entries=%d\n", m.Add, len(m.Entries))
	coord := NewSockproxySync()
	for _, e := range m.Entries {
		if e == nil {
			continue
		}
		coord.ApplyOne(e)
	}
	return &XSyncReply{Response: 0}, nil
}

// SockproxySessionBulkGet serves a chunked snapshot pull (page_size = 500).
// -L: iterates all services via sockproxy_snapshot_all_sessions CGO
// and paginates using a numeric cursor (offset into the flat array).
// An empty NextCursor in the reply signals the final page.
func (xs *XSync) SockproxySessionBulkGet(ctx context.Context, req *SockproxyBulkReq) (*SockproxySessionBulkReply, error) {
	if !mh.ready {
		return &SockproxySessionBulkReply{}, errors.New("Not-Ready")
	}

	const defaultPageSize = 500
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	// Parse cursor (decimal offset into the snapshot array; "" means 0).
	offset := 0
	if cur := req.GetCursor(); cur != "" {
		if n, err := fmt.Sscanf(cur, "%d", &offset); n != 1 || err != nil || offset < 0 {
			offset = 0
		}
	}

	// Call C-side snapshot: walks proxy_struct->head under per-map rdlocks.
	var cEventsPtr *C.proxy_sync_event_t
	var cCount C.uint32_t
	if rc := C.sockproxy_snapshot_all_sessions(&cEventsPtr, &cCount); rc != 0 {
		tk.LogIt(tk.LogError, "[XSYNC] sockproxy_snapshot_all_sessions failed rc=%d\n", rc)
		return &SockproxySessionBulkReply{}, nil
	}
	total := int(cCount)
	if total == 0 || cEventsPtr == nil {
		tk.LogIt(tk.LogDebug, "[XSYNC] SockproxySessionBulkGet: no sessions to transfer\n")
		return &SockproxySessionBulkReply{NextCursor: ""}, nil
	}
	// Ensure C memory is freed when we return.
	defer C.free(unsafe.Pointer(cEventsPtr))

	// Convert the C array to a Go slice view (zero-copy).
	allEvents := unsafe.Slice(cEventsPtr, total)

	// Slice the requested page.
	if offset >= total {
		return &SockproxySessionBulkReply{NextCursor: ""}, nil
	}
	end := offset + pageSize
	if end > total {
		end = total
	}
	page := allEvents[offset:end]

	entries := make([]*SockproxySessionEntry, 0, len(page))
	for i := range page {
		ev := &page[i]
		entries = append(entries, &SockproxySessionEntry{
			ServiceKey:   C.GoString(&ev.service_key[0]),
			ConvId:       C.GoString(&ev.conv_id[0]),
			EpIdx:        int32(ev.ep_idx),
			PrefillEpIdx: int32(ev.prefill_ep_idx),
			DecodeEpIdx:  int32(ev.decode_ep_idx),
			CreatedTs:    int64(ev.created_ts),
			LastAccessTs: int64(ev.last_access_ts),
			RequestCount: uint32(ev.request_count),
		})
	}

	nextCursor := ""
	if end < total {
		nextCursor = fmt.Sprintf("%d", end)
	}

	tk.LogIt(tk.LogInfo, "[XSYNC] SockproxySessionBulkGet offset=%d page=%d total=%d next=%q\n",
		offset, len(entries), total, nextCursor)
	return &SockproxySessionBulkReply{Entries: entries, NextCursor: nextCursor}, nil
}

// RateLimiterSync receives a token-bucket / quota-window batch from a peer.
// -B implementation: routes to RateLimiterStore.ImportState (when
// the batch is an absolute snapshot from A-P master OR the every-10th
// drift-insurance push in A-A) or .ApplyGossipDelta (when the batch is an
// A-A consumed-delta), based on the batch's IsDelta flag.
//
// The coordinator (sockproxy_sync.go) owns the routing; this handler
// delegates to coord.ApplyRateLimiterBatch which (a) checks for nil
// store gracefully (debug-log + success-return so the wire path is
// observable before the AI gateway has registered the store) and (b)
// translates the proto entries into Go-side ratelimit.RateLimiterEntry
// values before calling the store.
func (xs *XSync) RateLimiterSync(ctx context.Context, m *RateLimiterBatch) (*XSyncReply, error) {
	if !mh.ready {
		return &XSyncReply{Response: -1}, errors.New("Not-Ready")
	}
	tk.LogIt(tk.LogDebug, "RPC - RateLimiterSync delta=%v entries=%d\n", m.IsDelta, len(m.Entries))
	coord := NewSockproxySync()
	if err := coord.ApplyRateLimiterBatch(m); err != nil {
		return &XSyncReply{Response: -1}, err
	}
	return &XSyncReply{Response: 0}, nil
}

// GetSockproxySnapshot serves the combined session+rate-limiter+metrics
// snapshot used on BFD master-promotion (SPEC A7). Sessions delegate to
// SockproxySessionBulkGet (L implemented). rl_state populated by
// Phase B; metrics by Phase C — both return empty payload until those phases
// ship.
func (xs *XSync) GetSockproxySnapshot(ctx context.Context, req *SockproxyBulkReq) (*SockproxySnapshotReply, error) {
	if !mh.ready {
		return &SockproxySnapshotReply{}, errors.New("Not-Ready")
	}
	// Delegate to SockproxySessionBulkGet for session state.
	bulkReply, err := xs.SockproxySessionBulkGet(ctx, req)
	if err != nil {
		return &SockproxySnapshotReply{}, err
	}
	tk.LogIt(tk.LogDebug, "[XSYNC] GetSockproxySnapshot cursor=%q sessions=%d next=%q\n",
		req.GetCursor(), len(bulkReply.GetEntries()), bulkReply.GetNextCursor())
	return &SockproxySnapshotReply{
		Sessions:   bulkReply.GetEntries(),
		NextCursor: bulkReply.GetNextCursor(),
	}, nil
}

func (xs *XSync) mustEmbedUnimplementedXSyncServer() {}

func startxSyncGRPCServer() {
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", XSyncPort))
	if err != nil {
		tk.LogIt(tk.LogEmerg, "gRPC -  Server Start Error\n")
		return
	}
	grpcServer := grpc.NewServer()
	s := XSync{}
	RegisterXSyncServer(grpcServer, &s)
	tk.LogIt(tk.LogNotice, "*******************gRPC -  Server Started*****************\n")
	grpcServer.Serve(lis)
}

// startSockproxyXSyncGRPCServer starts a dedicated gRPC server on SockproxyXSyncPort
// (22223) that handles sockproxy session-sync RPCs. It is always started alongside
// the main xSync server so that the sockproxy consumerLoop can use gRPC/HTTP2
// even when the main xSync server runs in "netrpc" mode on port 22222.
// Fix: separates sockproxy gRPC transport from CT-sync net/rpc transport.
func startSockproxyXSyncGRPCServer() {
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", SockproxyXSyncPort))
	if err != nil {
		tk.LogIt(tk.LogEmerg, "[XSYNC] sockproxy gRPC server listen error on :%d: %v\n", SockproxyXSyncPort, err)
		return
	}
	grpcServer := grpc.NewServer()
	s := XSync{}
	RegisterXSyncServer(grpcServer, &s)
	tk.LogIt(tk.LogNotice, "[XSYNC] sockproxy gRPC server started on :%d\n", SockproxyXSyncPort)
	grpcServer.Serve(lis)
}

// LoxiXsyncMain - State Sync subsystem init
func LoxiXsyncMain(mode string) {
	if opts.Opts.ClusterNodes == "none" {
		return
	}

	// Stack trace logger
	defer func() {
		if e := recover(); e != nil {
			if mh.logger != nil {
				tk.LogIt(tk.LogCritical, "%s: %s", e, debug.Stack())
			}
			if mh.dp != nil {
				mh.dp.DpHooks.DpEbpfUnInit()
			}
			os.Exit(1)
		}
	}()
	if mode == "netrpc" {
		// always start the sockproxy gRPC server on SockproxyXSyncPort (22223)
		// so that the sockproxy consumerLoop can deliver session entries via gRPC/HTTP2
		// even while CT-sync continues to use net/rpc on XSyncPort (22222).
		go startSockproxyXSyncGRPCServer()
		for {
			rpcObj := new(XSync)
			err := rpc.Register(rpcObj)
			if err != nil {
				panic("Failed to register rpc")
			}

			rpc.HandleHTTP()

			http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
				io.WriteString(res, "loxilb-xsync\n")
			})

			listener := fmt.Sprintf(":%d", XSyncPort)
			err = http.ListenAndServe(listener, nil)
			if err != nil {
				panic("Failed to rpc-listen")
			}
		}
	} else {
		go startxSyncGRPCServer()
	}
}
