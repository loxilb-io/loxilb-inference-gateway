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

// ai_kv_capability.go — the §10.2/§17.7 live-HA capability handshake for
// strict KV-exact rules: KvCapabilityExchange over xsync (gRPC + net/rpc
// mirror), and the cluster activation gate the attestation controller
// consults before READY.
//
// Fail-closed inversion (v3 marker design withdrawn): the NEW node detects
// the OLD node. An old peer answers gRPC codes.Unimplemented (or net/rpc
// "method not found") — that response IS the prohibition signal; the old
// node needs no new behavior. xsync is protobuf, so old peers silently
// IGNORE unknown fields — which is exactly why a passive marker cannot work
// and an explicit RPC must.

import (
	"context"
	"errors"
	"net/rpc"
	"strconv"
	"strings"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/pkg/enginecontract"
	"github.com/loxilb-io/loxilb/pkg/snapshot"
	tk "github.com/loxilb-io/loxilib"
)

// KvCapabilityInfo is the transport-neutral capability set (also the
// net/rpc mirror's wire struct — plain exported fields, gob-encodable).
type KvCapabilityInfo struct {
	SchemaMinor            uint32
	HashContractVer        string
	ProfileSetDigest       string
	AttestationPolicy      uint32
	BuildIdentity          string
	ContractRegistryDigest string
	SupportCatalogDigest   string
	ContractSchemaVer      string
	EvidencePolicy         uint32
	BindingDigest          string
	BindingGen             uint32
}

// kvCapabilityPolicyVersion / kvEvidencePolicyVersion version the
// attestation and evidence policies this build implements (bumped on
// incompatible policy changes; equality is required for activation).
const (
	kvCapabilityPolicyVersion = 1
	kvEvidencePolicyVersion   = 1
	kvCapabilityRPCTimeout    = 2 * time.Second
)

// kvLocalCapability builds this node's capability set.
func kvLocalCapability() KvCapabilityInfo {
	minor := uint32(0)
	if parts := strings.SplitN(snapshot.SchemaVersion, ".", 2); len(parts) == 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil && n >= 0 {
			minor = uint32(n)
		}
	}
	psd := ""
	if gen := kvProfileCurrent(); gen != nil {
		psd = gen.SetDigest
	}
	return KvCapabilityInfo{
		SchemaMinor:       minor,
		HashContractVer:   "sha256_cbor,xxhash_cbor",
		ProfileSetDigest:  psd,
		AttestationPolicy: kvCapabilityPolicyVersion,
		BuildIdentity:     cmn.Version + "+" + cmn.BuildInfo,
		EvidencePolicy:    kvEvidencePolicyVersion,
		// Engine-contract identity comes from the compiled registry: the
		// digests cover the exact contracts.yaml / support-catalog.yaml
		// bytes this build embeds. Equality is required for strict
		// activation — a peer compiled from a different manifest (or one
		// with no registry at all, whose fields are empty) cannot
		// co-activate.
		ContractRegistryDigest: enginecontract.ManifestDigest,
		SupportCatalogDigest:   enginecontract.SupportCatalogDigest,
		ContractSchemaVer:      enginecontract.SchemaVersion,
	}
}

func kvCapabilityToPb(c KvCapabilityInfo) *KvCapability {
	return &KvCapability{
		SchemaMinor:            c.SchemaMinor,
		HashContractVer:        c.HashContractVer,
		ProfileSetDigest:       c.ProfileSetDigest,
		AttestationPolicy:      c.AttestationPolicy,
		BuildIdentity:          c.BuildIdentity,
		ContractRegistryDigest: c.ContractRegistryDigest,
		SupportCatalogDigest:   c.SupportCatalogDigest,
		ContractSchemaVer:      c.ContractSchemaVer,
		EvidencePolicy:         c.EvidencePolicy,
		BindingDigest:          c.BindingDigest,
		BindingGen:             c.BindingGen,
	}
}

func kvCapabilityFromPb(m *KvCapability) KvCapabilityInfo {
	return KvCapabilityInfo{
		SchemaMinor:            m.GetSchemaMinor(),
		HashContractVer:        m.GetHashContractVer(),
		ProfileSetDigest:       m.GetProfileSetDigest(),
		AttestationPolicy:      m.GetAttestationPolicy(),
		BuildIdentity:          m.GetBuildIdentity(),
		ContractRegistryDigest: m.GetContractRegistryDigest(),
		SupportCatalogDigest:   m.GetSupportCatalogDigest(),
		ContractSchemaVer:      m.GetContractSchemaVer(),
		EvidencePolicy:         m.GetEvidencePolicy(),
		BindingDigest:          m.GetBindingDigest(),
		BindingGen:             m.GetBindingGen(),
	}
}

// kvCapabilityRespond builds the reply to a peer's exchange: this node's
// capability, echoing the requester's binding identity only when this node
// KNOWS the same composed binding (digest match in the binding store). A
// standby that has not yet converged on the rule replies without the echo —
// the requester then refuses strict activation (fail-closed until the
// cluster converges).
func kvCapabilityRespond(req KvCapabilityInfo) KvCapabilityInfo {
	resp := kvLocalCapability()
	if req.BindingDigest != "" {
		for _, m := range KvBindingExport() {
			if m.BindingDigest == req.BindingDigest && m.BindingGen == req.BindingGen {
				resp.BindingDigest = req.BindingDigest
				resp.BindingGen = req.BindingGen
				break
			}
		}
	}
	return resp
}

// KvCapabilityExchange is the gRPC server half.
func (xs *XSync) KvCapabilityExchange(ctx context.Context, m *KvCapability) (*KvCapability, error) {
	resp := kvCapabilityRespond(kvCapabilityFromPb(m))
	return kvCapabilityToPb(resp), nil
}

// KvCapabilityExchangeNetRPC is the net/rpc mirror.
func (xs *XSync) KvCapabilityExchangeNetRPC(args KvCapabilityInfo, reply *KvCapabilityInfo) error {
	*reply = kvCapabilityRespond(args)
	return nil
}

// kvPeerCapabilityExchange runs one exchange against one peer connection.
// Any transport error — including gRPC Unimplemented and net/rpc "method
// not found" from an old peer — surfaces as an error; the caller treats
// every error as prohibition.
func kvPeerCapabilityExchange(client interface{}, local KvCapabilityInfo) (KvCapabilityInfo, error) {
	switch cl := client.(type) {
	case gRPCClient:
		ctx, cancel := context.WithTimeout(context.Background(), kvCapabilityRPCTimeout)
		defer cancel()
		resp, err := cl.XSyncClient().KvCapabilityExchange(ctx, kvCapabilityToPb(local))
		if err != nil {
			return KvCapabilityInfo{}, err
		}
		return kvCapabilityFromPb(resp), nil
	case *rpc.Client:
		var reply KvCapabilityInfo
		call := cl.Go("XSync.KvCapabilityExchangeNetRPC", local, &reply, make(chan *rpc.Call, 1))
		select {
		case <-time.After(kvCapabilityRPCTimeout):
			return KvCapabilityInfo{}, errors.New("netrpc capability exchange timeout")
		case resp := <-call.Done:
			if resp != nil && resp.Error != nil {
				return KvCapabilityInfo{}, resp.Error
			}
		}
		return reply, nil
	default:
		return KvCapabilityInfo{}, errors.New("peer not connected")
	}
}

// kvCapabilityMatch compares the digest set that must agree for strict
// activation ("" reason = match). Build identity is carried for receipts
// but deliberately NOT compared — a rolling upgrade with equal digests is
// exactly the case the handshake must permit.
func kvCapabilityMatch(local, peer KvCapabilityInfo) string {
	switch {
	case peer.SchemaMinor < local.SchemaMinor:
		return "peer_schema_minor_behind"
	case peer.HashContractVer != local.HashContractVer:
		return "hash_contract_ver_mismatch"
	case peer.ProfileSetDigest != local.ProfileSetDigest:
		return "profile_set_digest_mismatch"
	case peer.AttestationPolicy != local.AttestationPolicy:
		return "attestation_policy_mismatch"
	case peer.EvidencePolicy != local.EvidencePolicy:
		return "evidence_policy_mismatch"
	case peer.ContractRegistryDigest != local.ContractRegistryDigest:
		return "contract_registry_digest_mismatch"
	case peer.SupportCatalogDigest != local.SupportCatalogDigest:
		return "support_catalog_digest_mismatch"
	case peer.ContractSchemaVer != local.ContractSchemaVer:
		return "contract_schema_ver_mismatch"
	case local.BindingDigest != "" && (peer.BindingDigest != local.BindingDigest ||
		peer.BindingGen != local.BindingGen):
		return "binding_not_converged_on_peer"
	}
	return ""
}

// kvCapabilityPeerClients snapshots the connected peer clients (seam for the
// GPU-free HA suite; production reads mh.dp.Peers under SyncMtx and never
// holds the lock across the network calls).
var kvCapabilityPeerClients = func() []interface{} {
	if mh.dp == nil {
		return nil
	}
	mh.dp.SyncMtx.Lock()
	defer mh.dp.SyncMtx.Unlock()
	clients := make([]interface{}, 0, len(mh.dp.Peers))
	for i := range mh.dp.Peers {
		clients = append(clients, mh.dp.Peers[i].Client)
	}
	return clients
}

// kvClusterCapabilityGate is the §17.7 activation expression consulted by
// the attestation controller before READY: every eligible peer must
// understand the exchange AND match every digest relevant to the rule. No
// peers ⇒ single-node ⇒ pass.
func kvClusterCapabilityGate(info kvAttestRuleInfo) (bool, string) {
	clients := kvCapabilityPeerClients()
	if len(clients) == 0 {
		return true, ""
	}
	local := kvLocalCapability()
	if b, ok := KvBindingCurrent(info.ruleIdent); ok {
		local.BindingDigest = b.Digest
		local.BindingGen = b.BindingGen
	}
	for _, client := range clients {
		peer, err := kvPeerCapabilityExchange(client, local)
		if err != nil {
			tk.LogIt(tk.LogWarning, "kv-capability: rule %s peer exchange failed (%v) — strict activation prohibited cluster-wide\n",
				info.ruleIdent, err)
			return false, "peer_incapable"
		}
		if reason := kvCapabilityMatch(local, peer); reason != "" {
			tk.LogIt(tk.LogWarning, "kv-capability: rule %s peer mismatch (%s) — strict activation prohibited\n",
				info.ruleIdent, reason)
			return false, reason
		}
	}
	return true, ""
}
