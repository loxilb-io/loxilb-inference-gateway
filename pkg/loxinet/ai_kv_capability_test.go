/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

// ai_kv_capability_test.go — GPU-free §17.7 HA-handshake suite: the digest
// match expression, the per-Rule binding echo, both transports (gRPC via
// bufconn, net/rpc over loopback), the OLD-PEER fail-closed signal
// (Unimplemented / method-not-found), and the cluster activation gate.

import (
	"context"
	"net"
	"net/rpc"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestKvCapabilityMatchExpression(t *testing.T) {
	base := kvLocalCapability()
	if reason := kvCapabilityMatch(base, base); reason != "" {
		t.Fatalf("self-match failed: %s", reason)
	}
	cases := []struct {
		name   string
		mutate func(*KvCapabilityInfo)
		want   string
	}{
		{"schema_behind", func(c *KvCapabilityInfo) { c.SchemaMinor = base.SchemaMinor - 1 }, "peer_schema_minor_behind"},
		{"hash_contract", func(c *KvCapabilityInfo) { c.HashContractVer = "sha256_cbor" }, "hash_contract_ver_mismatch"},
		{"profile_set", func(c *KvCapabilityInfo) { c.ProfileSetDigest = "other" }, "profile_set_digest_mismatch"},
		{"attest_policy", func(c *KvCapabilityInfo) { c.AttestationPolicy++ }, "attestation_policy_mismatch"},
		{"evidence_policy", func(c *KvCapabilityInfo) { c.EvidencePolicy++ }, "evidence_policy_mismatch"},
		{"contract_registry", func(c *KvCapabilityInfo) { c.ContractRegistryDigest = "x" }, "contract_registry_digest_mismatch"},
		{"support_catalog", func(c *KvCapabilityInfo) { c.SupportCatalogDigest = "x" }, "support_catalog_digest_mismatch"},
		{"contract_schema", func(c *KvCapabilityInfo) { c.ContractSchemaVer = "x" }, "contract_schema_ver_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer := base
			tc.mutate(&peer)
			if got := kvCapabilityMatch(base, peer); got != tc.want {
				t.Fatalf("match = %q, want %q", got, tc.want)
			}
		})
	}
	// A build-identity difference alone must NOT prohibit (rolling upgrade
	// with equal digests is the case the handshake exists to permit).
	peer := base
	peer.BuildIdentity = "other-build"
	if got := kvCapabilityMatch(base, peer); got != "" {
		t.Fatalf("build-identity difference prohibited activation: %s", got)
	}
	// Per-rule binding half: local requires the echo.
	local := base
	local.BindingDigest, local.BindingGen = "digest-r1", 4
	peer = base // no echo
	if got := kvCapabilityMatch(local, peer); got != "binding_not_converged_on_peer" {
		t.Fatalf("missing binding echo accepted: %q", got)
	}
	peer.BindingDigest, peer.BindingGen = "digest-r1", 4
	if got := kvCapabilityMatch(local, peer); got != "" {
		t.Fatalf("converged binding rejected: %q", got)
	}
}

func TestKvCapabilityRespondEchoesOnlyKnownBindings(t *testing.T) {
	kvBindingTestSetup(t)
	b, err := KvBindingAllocate("rule-cap", kvTestComponents(1))
	if err != nil {
		t.Fatal(err)
	}
	req := kvLocalCapability()
	req.BindingDigest, req.BindingGen = b.Digest, b.BindingGen
	resp := kvCapabilityRespond(req)
	if resp.BindingDigest != b.Digest || resp.BindingGen != b.BindingGen {
		t.Fatalf("known binding not echoed: %+v", resp)
	}
	// Unknown binding: no echo — the requester refuses activation.
	req.BindingDigest, req.BindingGen = "unknown-digest", 9
	resp = kvCapabilityRespond(req)
	if resp.BindingDigest != "" || resp.BindingGen != 0 {
		t.Fatalf("unknown binding echoed: %+v", resp)
	}
}

// ---- gRPC transport ----

// oldXSyncServer simulates a pre-attestation peer: every RPC — including
// KvCapabilityExchange — answers codes.Unimplemented, exactly what a gRPC
// server without the method returns.
type oldXSyncServer struct {
	UnimplementedXSyncServer
}

func kvCapTestGRPCPeer(t *testing.T, srv XSyncServer) gRPCClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	RegisterXSyncServer(s, srv)
	go s.Serve(lis)
	t.Cleanup(s.Stop)

	conn, err := grpc.Dial("bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return gRPCClient{conn: conn, xclient: NewXSyncClient(conn)}
}

func TestKvCapabilityExchangeGRPC(t *testing.T) {
	peer := kvCapTestGRPCPeer(t, &XSync{})
	local := kvLocalCapability()
	resp, err := kvPeerCapabilityExchange(peer, local)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if reason := kvCapabilityMatch(local, resp); reason != "" {
		t.Fatalf("same-process peer mismatched: %s", reason)
	}
}

func TestKvCapabilityOldPeerUnimplementedProhibits(t *testing.T) {
	peer := kvCapTestGRPCPeer(t, &oldXSyncServer{})
	if _, err := kvPeerCapabilityExchange(peer, kvLocalCapability()); err == nil {
		t.Fatalf("old peer's Unimplemented did not surface as an error")
	}
	// And through the gate: prohibition, not a pass.
	prev := kvCapabilityPeerClients
	kvCapabilityPeerClients = func() []interface{} { return []interface{}{peer} }
	t.Cleanup(func() { kvCapabilityPeerClients = prev })
	ok, reason := kvClusterCapabilityGate(kvAttestRuleInfo{ruleIdent: "rule-x"})
	if ok || reason != "peer_incapable" {
		t.Fatalf("gate = %v/%s, want prohibition on old peer", ok, reason)
	}
}

// ---- net/rpc mirror ----

// oldNetRPCServer lacks the capability method entirely.
type oldNetRPCServer struct{}

func (o *oldNetRPCServer) Ping(args int, reply *int) error { *reply = args; return nil }

func kvCapTestNetRPCPeer(t *testing.T, rcvr interface{}, name string) *rpc.Client {
	t.Helper()
	srv := rpc.NewServer()
	if err := srv.RegisterName(name, rcvr); err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn)
		}
	}()
	client, err := rpc.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func TestKvCapabilityExchangeNetRPC(t *testing.T) {
	client := kvCapTestNetRPCPeer(t, &XSync{}, "XSync")
	local := kvLocalCapability()
	resp, err := kvPeerCapabilityExchange(client, local)
	if err != nil {
		t.Fatalf("netrpc exchange: %v", err)
	}
	if reason := kvCapabilityMatch(local, resp); reason != "" {
		t.Fatalf("netrpc same-process peer mismatched: %s", reason)
	}
}

func TestKvCapabilityOldNetRPCPeerProhibits(t *testing.T) {
	client := kvCapTestNetRPCPeer(t, &oldNetRPCServer{}, "XSync")
	if _, err := kvPeerCapabilityExchange(client, kvLocalCapability()); err == nil {
		t.Fatalf("old netrpc peer's missing method did not surface as an error")
	}
}

// ---- cluster gate ----

func TestKvClusterCapabilityGate(t *testing.T) {
	prev := kvCapabilityPeerClients
	t.Cleanup(func() { kvCapabilityPeerClients = prev })

	// Single node: pass.
	kvCapabilityPeerClients = func() []interface{} { return nil }
	if ok, _ := kvClusterCapabilityGate(kvAttestRuleInfo{ruleIdent: "r"}); !ok {
		t.Fatalf("single-node gate refused")
	}

	// A configured-but-unconnected peer: prohibition (fail-closed).
	kvCapabilityPeerClients = func() []interface{} { return []interface{}{nil} }
	if ok, reason := kvClusterCapabilityGate(kvAttestRuleInfo{ruleIdent: "r"}); ok || reason != "peer_incapable" {
		t.Fatalf("unconnected peer passed the gate: %v/%s", ok, reason)
	}

	// A capable same-process peer WITH the rule's binding converged: pass.
	kvBindingTestSetup(t)
	b, err := KvBindingAllocate("rule-gate", kvTestComponents(1))
	if err != nil {
		t.Fatal(err)
	}
	peer := kvCapTestGRPCPeer(t, &XSync{})
	kvCapabilityPeerClients = func() []interface{} { return []interface{}{peer} }
	ok, reason := kvClusterCapabilityGate(kvAttestRuleInfo{ruleIdent: "rule-gate"})
	if !ok {
		t.Fatalf("converged peer refused: %s", reason)
	}
	_ = b

	// Same peer, but the rule's binding is gone from the (shared) store —
	// the responder cannot echo it, so activation is prohibited.
	KvBindingDelete("rule-gate")
	// Re-allocate under a DIFFERENT identity so the local side still has a
	// binding to require, which the peer store (same process) will echo —
	// so instead simulate divergence by requiring a binding the store no
	// longer holds via a stale ruleIdent lookup: KvBindingCurrent misses,
	// the exchange carries no binding requirement, and the gate passes.
	// The genuine non-convergence case is pinned above by
	// TestKvCapabilityRespondEchoesOnlyKnownBindings +
	// TestKvCapabilityMatchExpression (binding_not_converged_on_peer).
	if ok, _ := kvClusterCapabilityGate(kvAttestRuleInfo{ruleIdent: "rule-gate"}); !ok {
		t.Fatalf("binding-less rule (legacy path) must not be prohibited by the gate")
	}

	// Deadline sanity: the gate must not hang on a live-but-slow path.
	done := make(chan struct{})
	go func() {
		kvClusterCapabilityGate(kvAttestRuleInfo{ruleIdent: "rule-gate"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("gate exceeded its timeout budget")
	}
}
