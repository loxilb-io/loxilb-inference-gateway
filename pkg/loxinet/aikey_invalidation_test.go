/*
 * Copyright (c) 2025 LoxiLB Authors
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
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// The key-store half of the revocation fan-out is gated inside pkg/aikey. What
// is gated here is the wire between two gateways: that a revocation performed
// on one becomes an ApiKeyInvalidate call carrying both identifiers to every
// peer, and that a peer which does not implement the RPC degrades to a warning
// instead of failing the revocation that triggered it.

// mockInvalidationServer records the invalidations it is told about, and can
// pretend to be a peer from before the RPC existed.
type mockInvalidationServer struct {
	UnimplementedXSyncServer

	unimplemented bool

	mu       sync.Mutex
	received []*ApiKeyInvalidation
	calls    atomic.Int32
}

func (m *mockInvalidationServer) ApiKeyInvalidate(_ context.Context, msg *ApiKeyInvalidation) (*XSyncReply, error) {
	m.calls.Add(1)
	if m.unimplemented {
		return nil, status.Errorf(codes.Unimplemented, "method ApiKeyInvalidate not implemented")
	}
	m.mu.Lock()
	m.received = append(m.received, msg)
	m.mu.Unlock()
	return &XSyncReply{Response: 0}, nil
}

func (m *mockInvalidationServer) snapshot() []*ApiKeyInvalidation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*ApiKeyInvalidation, len(m.received))
	copy(out, m.received)
	return out
}

// startMockInvalidationServer serves srv over an in-process connection and
// returns a client for it.
func startMockInvalidationServer(t *testing.T, srv *mockInvalidationServer) (XSyncClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	RegisterXSyncServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock())
	if err != nil {
		gs.Stop()
		t.Fatalf("dial the in-process peer: %v", err)
	}
	return NewXSyncClient(conn), func() {
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	}
}

// invalidationFixture wires a coordinator to one peer served in-process.
func invalidationFixture(t *testing.T, srv *mockInvalidationServer) *SockproxySync {
	t.Helper()

	client, cleanup := startMockInvalidationServer(t, srv)
	t.Cleanup(cleanup)

	coord := NewSockproxySync()
	peer := DpPeer{Peer: net.ParseIP("127.0.0.21"), CapMask: 0xFFFFFFFF}
	coord.peersFn = func() []DpPeer { return []DpPeer{peer} }
	coord.StoreGRPCClient(peer.Peer.String(), client)
	return coord
}

// Both identifiers have to travel. The authentication path caches by hash and
// the management read path by key id, so a message carrying only one of them
// leaves the other view of a revoked key readable until it expires.
func TestKeyInvalidationCarriesBothIdentifiers(t *testing.T) {
	srv := &mockInvalidationServer{}
	coord := invalidationFixture(t, srv)

	coord.BroadcastKeyInvalidation("hash-of-the-revoked-key", "key-id-42")

	got := srv.snapshot()
	if len(got) != 1 {
		t.Fatalf("peer received %d invalidations, want 1", len(got))
	}
	if got[0].KeyHash != "hash-of-the-revoked-key" {
		t.Errorf("key_hash = %q, want the revoked key's hash", got[0].KeyHash)
	}
	if got[0].KeyId != "key-id-42" {
		t.Errorf("key_id = %q, want key-id-42", got[0].KeyId)
	}
}

// A peer from before this RPC existed must not turn a revocation into an
// error. It has no separate key cache to evict, so the notice is all that is
// lost, and it converges when its own entry expires.
func TestKeyInvalidationDegradesOnUnimplementedPeer(t *testing.T) {
	srv := &mockInvalidationServer{unimplemented: true}
	coord := invalidationFixture(t, srv)

	coord.BroadcastKeyInvalidation("some-hash", "some-id")

	if srv.calls.Load() != 1 {
		t.Fatalf("peer was called %d times, want 1", srv.calls.Load())
	}
	// The warning is emitted once per (peer, RPC), so a second revocation must
	// not re-warn. Nothing observable is asserted about the log itself; what
	// matters here is that the second call still happens and still does not
	// fail — a peer that upgrades has to start receiving these again.
	coord.BroadcastKeyInvalidation("some-hash", "some-id")
	if srv.calls.Load() != 2 {
		t.Fatalf("peer was called %d times after a second revocation, want 2", srv.calls.Load())
	}
}

// With no peers there is nothing to do, and a coordinator that was never
// started has no peer source at all. Neither may panic: both are reached from
// the ordinary single-gateway revocation path.
func TestKeyInvalidationWithoutPeersIsSafe(t *testing.T) {
	coord := NewSockproxySync()
	coord.BroadcastKeyInvalidation("h", "i")

	coord.peersFn = func() []DpPeer { return nil }
	coord.BroadcastKeyInvalidation("h", "i")

	var nilCoord *SockproxySync
	nilCoord.BroadcastKeyInvalidation("h", "i")
}
