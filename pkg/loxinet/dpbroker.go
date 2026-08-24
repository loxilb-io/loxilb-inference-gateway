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

import (
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// man names constants
const (
	MapNameCt4  = "CT4"
	MapNameCt6  = "CT6"
	MapNameNat  = "NAT"
	MapNameBD   = "BD"
	MapNameRxBD = "RXBD"
	MapNameTxBD = "TXBD"
	MapNameRt4  = "RT4"
	MapNameULCL = "ULCL"
	MapNameIpol = "IPOL"
	MapNameFw4  = "FW4"
	// MapNameNatEp - Octavia : the per-rule NAT endpoint-actions map (nat_ep_map), keyed by
	// rule mark (ruleNum). A DpMapGet on this name returns map[uint32]*NatEpStats carrying the
	// datapath-maintained CUMULATIVE statistics the /stats endpoint needs.
	MapNameNatEp = "NATEP"
)

// NatEpStats - Octavia : per-rule statistics read straight from the data-plane nat_ep_map
// (struct dp_nat_epacts). ActiveConns is a live gauge (conc_conns); TotalConns/BytesIn/BytesOut are
// CUMULATIVE totals the datapath maintains on every CT create/teardown, so they capture short-lived
// flows the control-plane live-CT walk would miss between RulesSync ticks.
type NatEpStats struct {
	ActiveConns uint64 // live concurrent connections (conc_conns)
	TotalConns  uint64 // cumulative connections ever (total_conns, ++ on CT-create)
	BytesIn     uint64 // cumulative client->VIP request bytes (cum_bytes_in)
	BytesOut    uint64 // cumulative VIP->client response bytes (cum_bytes_out)
}

// error codes
const (
	DpErrBase = iota - 103000
	DpWqUnkErr
)

// DpWorkT - type of requested work
type DpWorkT uint8

// dp work codes
const (
	DpCreate DpWorkT = iota + 1
	DpRemove
	DpChange
	DpStatsGet
	DpStatsClr
	DpMapGet
	DpStatsGetImm
)

// DpStatusT - status of a dp work
type DpStatusT uint8

// dp work status codes
const (
	DpCreateErr DpStatusT = iota + 1
	DpRemoveErr
	DpChangeErr
	DpUknownErr
	DpInProgressErr
)

// SessionResetT - type of session reset operation
type SessionResetT int

// session reset operation types
const (
	ResetAll       SessionResetT = iota // Reset all endpoint session counts
	ResetSpecific  SessionResetT = iota // Reset specific endpoint session count
	ResetSelective SessionResetT = iota // Reset only changed endpoints, preserve unchanged
)

// maximum dp work queue lengths
const (
	DpWorkQLen         = 1024
	XSyncPort          = 22222
	SockproxyXSyncPort = 22223 // dedicated gRPC port for sockproxy session sync
	DpTiVal            = 20
)

// MirrDpWorkQ - work queue entry for mirror operation
type MirrDpWorkQ struct {
	Work      DpWorkT
	Name      string
	Mark      int
	MiPortNum int
	MiBD      int
	Status    *DpStatusT
}

// PortDpWorkQ - work queue entry for port operation
type PortDpWorkQ struct {
	Work       DpWorkT
	Status     *DpStatusT
	OsPortNum  int
	PortNum    int
	IngVlan    int
	SetBD      int
	SetZoneNum int
	Prop       cmn.PortProp
	SetMirr    int
	SetPol     int
	SetPolEgr  int // egress-direction policer id (needs --egr-hooks)
	LoadEbpf   string
}

// L2AddrDpWorkQ - work queue entry for l2 address operation
type L2AddrDpWorkQ struct {
	Work    DpWorkT
	Status  *DpStatusT
	L2Addr  [6]uint8
	Tun     DpTunT
	NhNum   int
	PortNum int
	BD      int
	Tagged  int
}

// DpTunT - type of a dp tunnel
type DpTunT uint8

// tunnel type constants
const (
	DpTunVxlan DpTunT = iota + 1
	DpTunGre
	DpTunGtp
	DpTunStt
	DpTunIPIP
)

// RouterMacDpWorkQ - work queue entry for rt-mac operation
type RouterMacDpWorkQ struct {
	Work    DpWorkT
	Status  *DpStatusT
	L2Addr  [6]uint8
	PortNum int
	BD      int
	TunID   uint32
	TunType DpTunT
	NhNum   int
}

// NextHopDpWorkQ - work queue entry for nexthop operation
type NextHopDpWorkQ struct {
	Work        DpWorkT
	Status      *DpStatusT
	TunNh       bool
	TunID       uint32
	TunType     DpTunT
	RIP         net.IP
	SIP         net.IP
	NNextHopNum int
	NextHopNum  int
	Resolved    bool
	DstAddr     [6]uint8
	SrcAddr     [6]uint8
	BD          int
}

// RouteDpWorkQ - work queue entry for rt operation
type RouteDpWorkQ struct {
	Work    DpWorkT
	Status  *DpStatusT
	ZoneNum int
	Dst     net.IPNet
	RtType  int
	RtMark  int
	NMax    int
	NMark   [8]int
}

// StatDpWorkQ - work queue entry for stat operation
type StatDpWorkQ struct {
	Work        DpWorkT
	Name        string
	Mark        uint32
	Packets     *uint64
	Bytes       *uint64
	DropPackets *uint64
}

// TableDpWorkQ - work queue entry for map related operation
type TableDpWorkQ struct {
	Work DpWorkT
	Name string
}

// PolDpWorkQ - work queue entry for policer related operation
type PolDpWorkQ struct {
	Work         DpWorkT
	Name         string
	Mark         int
	Cir          uint64
	Pir          uint64
	Cbs          uint64
	Ebs          uint64
	Color        bool
	Srt          bool
	Status       *DpStatusT
	DscpRemark   uint8  // DSCP remark value for YELLOW traffic (if HW supports it)
	TargetLBMark int    // target LB rule's HwNum for policer-to-LB association
	MeterDstIP   uint32 // meter pipe match dst IP (network byte order)
	MeterDstPort uint16 // meter pipe match dst port (network byte order)
	MeterProto   uint8  // meter pipe match protocol (6=TCP, 17=UDP, 0=any)
}

// PeerDpWorkQ - work queue entry for peer association
type PeerDpWorkQ struct {
	Work   DpWorkT
	PeerIP net.IP
	Status *DpStatusT
}

// FwOpT - type of firewall operation
type FwOpT uint8

// Fw type constants
const (
	DpFwDrop FwOpT = iota + 1
	DpFwFwd
	DpFwRdr
	DpFwTrap
)

// FwDpWorkQ - work queue entry for fw related operation
type FwDpWorkQ struct {
	Work     DpWorkT
	Status   *DpStatusT
	ZoneNum  int
	SrcIP    net.IPNet
	DstIP    net.IPNet
	L4SrcMin uint16
	L4SrcMax uint16
	L4DstMin uint16
	L4DstMax uint16
	Port     uint16
	Pref     uint16
	Proto    uint8
	Mark     int
	FwType   FwOpT
	FwVal1   uint16
	FwVal2   uint32
	FwRecord bool
	OnDflt   bool
	// HwOffload - mirror of FwRuleArg.HwOffload. When
	// true, the data-path side (DpDocaBf2.FwRuleAdd) installs this rule
	// into the DOCA DENY_PIPE / ALLOW_PIPE in addition to the eBPF
	// firewall map. Default false → eBPF-only behaviour (unchanged from
	// stub posture).
	HwOffload bool
}

// IPFilterType - type of IP filter (whitelist or blacklist)
type IPFilterType uint8

// IP filter type constants
const (
	IPFilterWhitelist IPFilterType = iota
	IPFilterBlacklist
)

// IPFilterDpWorkQ - work queue entry for IP filter related operation
type IPFilterDpWorkQ struct {
	Work       DpWorkT
	Status     *DpStatusT
	FilterType IPFilterType // Whitelist or Blacklist
	IPNet      net.IPNet    // CIDR block (e.g., 192.168.1.0/24)
	Zone       uint8        // Security zone (0 = all zones)
	Priority   uint16       // Rule priority (higher = more important)
	Action     uint8        // 0 = allow, 1 = drop
}

// NatT - type of NAT
type NatT uint8

// nat type constants
const (
	DpNat NatT = iota + 1
	DpSnat
	DpDnat
	DpHsnat
	DpHdnat
	DpFullNat
	DpFullProxy
)

// NatSel - type of nat end-point selection algorithm
type NatSel uint8

// nat selection algorithm constants
const (
	EpRR NatSel = iota + 1
	EpHash
	EpPrio
	EpRRPersist
	EpLeastConn
	EpN2
	EpN3
	_ // 7 - reserved (was QUIC LB)
	EpCHWBL
	EpGPUAware
	EpWRRHash // P3.5: Weighted Consistent Hash + Bounded Loads
)

// NatEP - a nat end-point
type NatEP struct {
	XIP      net.IP
	RIP      net.IP
	XPort    uint16
	Weight   uint8
	InActive bool
	EpRole   int    // P/D endpoint role: 0=normal, 1=prefill, 2=decode
	NixlPort uint16 // NIXL side-channel port; 0=use XPort
}

// SecT - type of SecT
type SecT uint8

// security type constants
const (
	DpTermHTTPS SecT = iota + 1
	DpE2EHTTPS
)

// LBDpWorkQ - work queue entry for lb related operation
type LBDpWorkQ struct {
	Work                        DpWorkT
	Status                      *DpStatusT
	ZoneNum                     int
	ServiceIP                   net.IP
	L4Port                      uint16
	BlockNum                    uint32
	DsrMode                     bool
	CsumDis                     bool
	SrcCheck                    bool
	Ppv2En                      bool
	SecMode                     SecT
	HostURL                     string
	PathPrefix                  string                  // P6: URL path prefix for L7 routing
	PathMatchMode               string                  // P6: Path matching mode (disabled, prefix, exact)
	BackendProtocol             string                  // Backend protocol capability: "http1", "http2", or "both"
	SessionHeaderName           string                  // Custom session header for persist mode (e.g., "mcp-session-id")
	ModelName                   string                  // AI model name for pool selection (e.g. "llama-70b"); empty = wildcard
	CatalogID                   uint16                  // Tracing catalog ID for deep inspection (0 = no tracing)
	SSEMode                     bool                    // SSE (Server-Sent Events) mode: suppress idle-timeout during streaming
	MaxStreamDurationSec        uint32                  // Absolute wall-clock cap for streaming connections in seconds (0=system hard cap)
	BackendKeepaliveIntervalSec uint32                  // Sets SO_KEEPALIVE+TCP_KEEPIDLE on backend socket in seconds (0=disabled)
	TimeoutMemberConnect        uint32                  // backend connect-poll deadline in ms (0=500ms default)
	TimeoutMemberData           uint32                  // member-side relay idle deadline in ms (0=existing idle)
	TimeoutTcpInspect           uint32                  // header-accumulation deadline in ms (0=bounded default)
	PDDisaggMode                bool                    // P/D disaggregation mode: orchestrate prefill→decode flow
	PDCacheAwareMode            bool                    // P/D cache-aware routing (US-PD801)
	PDSessionTTLSec             uint32                  // Session stickiness TTL in seconds
	PDCacheThreshold            uint8                   // Cache match threshold (0-100)
	PDBalanceAbsThreshold       uint8                   // Load imbalance threshold
	CbEnable                    bool                    // per-endpoint circuit breaker for full-proxy rules
	KvExactMode                 uint8                   // KV-cache exact routing: 0=off, 1=zmq
	KvBlockSize                 uint32                  // Token block size for KV hash computation
	KvHashAlgo                  string                  // "sha256_cbor" or "xxhash_cbor"
	KvZmqPort                   uint16                  // ZMQ PUB port (default 5557)
	KvWarmupSec                 uint32                  // Warmup seconds before Tier 1.5 activates
	KvEngineType                string                  // KV-event engine: ""/"vllm" (default) or "sglang" (SGL-03)
	KvDpRankCount               uint16                  // SGLang DP rank count (1..8, 0 ⇒ 1)
	PDBootstrapPort             uint16                  // SGLang P/D bootstrap port on prefill EPs (0 ⇒ 8998 at proxy_add)
	MTLSFrontend                *cmn.MTLSFrontendConfig // mTLS frontend configuration
	MTLSBackend                 *cmn.MTLSBackendConfig  // mTLS backend configuration
	// TLS-hardening scalars. All additive/default-off — empty/0
	// preserves today's behaviour. Threaded into proxy_arg in DpLBRuleMod.
	AlpnProtocols         []string // mapped to backend_protocol_cap on listener+pool
	TlsCiphers            string   // inline OpenSSL cipher string → tls_ciphers[256]
	TlsVersions           []string // collapsed to tls_version_min/max range
	HstsMaxAge            uint32   // 0 ⇒ no HSTS injection
	HstsIncludeSubdomains bool     // "; includeSubDomains"
	HstsPreload           bool     // "; preload"
	BackendCaCertId       string   // backend CA certId → backend_ca_cert_id
	BackendClientCertId   string   // backend client certId → backend_client_cert_id
	CHWBLPrefixHashLevel  int      // CHWBL prefix hash level: 1=model, 2=model+prompt, 3=full
	CHWBLMeanLoadFactor   int      // CHWBL bounded load factor % (100-300, default 175)
	CHWBLReplication      int      // CHWBL virtual nodes per endpoint (1-1024, default 256)
	CHWBLPrefixHashFlags  int      // CHWBL optional field flags bitfield
	Proto                 uint8
	Mark                  int
	NatType               NatT
	EpSel                 NatSel
	InActTo               uint64
	PersistTo             uint64
	ConnLimit             uint32 // Octavia per-service concurrent-connection ceiling; 0 = unlimited
	PolId                 uint16 // Tier-0 rule-attached policer id (polx_map key); 0 = none
	endPoints             []NatEP
	secIP                 []net.IP
}

// LBSessionResetWorkQ - Load balancer session reset work queue
type LBSessionResetWorkQ struct {
	Mark        int           // Load balancer rule mark identifier
	EndpointIdx int           // Specific endpoint index (1 for selective reset)
	ResetType   SessionResetT // Type of reset operation
	Status      *DpStatusT    // Operation status pointer
	// Selective reset support
	EndpointMask []bool // Which endpoints to reset (true = reset, false = preserve)
}

// LBCtDpWorkQ - work queue entry for service-level CT/FC cleanup
type LBCtDpWorkQ struct {
	ZoneNum   int
	ServiceIP net.IP
	L4Port    uint16
	Proto     uint8
	BlockNum  uint32
	RuleID    uint32
	FlushMode uint8
}

const (
	CtFlushRidMatchOrZero uint8 = iota
	CtFlushRidZeroOnly
)

// DpCtInfo - representation of a datapath conntrack information
type DpCtInfo struct {
	DIP     net.IP    `json:"dip"`
	SIP     net.IP    `json:"sip"`
	Dport   uint16    `json:"dport"`
	Sport   uint16    `json:"sport"`
	Proto   string    `json:"proto"`
	Ident   uint32    `json:"ident"`
	IdType  uint32    `json:"type"`
	CState  string    `json:"cstate"`
	CAct    string    `json:"cact"`
	CI      string    `json:"ci"`
	Packets uint64    `json:"packets"`
	Bytes   uint64    `json:"bytes"`
	Deleted int       `json:"deleted"`
	PKey    []byte    `json:"pkey"`
	PVal    []byte    `json:"pval"`
	LTs     time.Time `json:"lts"`
	NTs     time.Time `json:"nts"`
	XSync   bool      `json:"xsync"`

	// LB Association Data
	ServiceIP     net.IP `json:"serviceip"`
	ServProto     string `json:"servproto"`
	L4ServPort    uint16 `json:"l4servproto"`
	L4ServPortMax uint16 `json:"l4servprotomax"`
	BlockNum      uint32 `json:"blocknum"`
	RuleID        uint32 `json:"ruleid"`

	// Dir - per-CT-entry direction (Octavia verdict (a)). loxilb allocates
	// a SEPARATE CT entry for each direction of a flow: CT_DIR_IN (0) = forward = client->VIP
	// request path; CT_DIR_OUT (1) = reverse = VIP->client response path. The DP CT collector
	// surfaces ctd.dir here (previously the two directions were summed into one Bytes field and
	// the direction discarded). The /stats rollup uses this to attribute per-entry bytes to
	// bytes_in (CT_DIR_IN) vs bytes_out (CT_DIR_OUT) per rule WITHOUT a 50/50 heuristic and
	// WITHOUT the direction-collapsed nat_stats_map. -1 = direction unknown/not populated.
	Dir int `json:"dir"`

	// NAT target fields for DOCA shadow offload
	NatIP    net.IP `json:"natip"`    // NAT target IP (backend)
	NatPort  uint16 `json:"natport"`  // NAT target port
	NatFlags uint8  `json:"natflags"` // 0=none, 1=DNAT, 2=SNAT, 3=HDNAT, 4=HSNAT

	// Extended NAT mode fields for multi-mode DOCA offload
	NatRIP net.IP `json:"natrip"` // Reverse IP for One-Arm/FullNAT (src rewrite)
	NatDsr bool   `json:"natdsr"` // DSR flag -- skip IP rewrite in DOCA
}

const (
	RPCTypeNetRPC = iota
	RPCTypeGRPC
)

type RPCHookInterface interface {
	RPCConnect(*DpPeer) int
	RPCClose(*DpPeer) int
	RPCReset(*DpPeer) int
	RPCSend(*DpPeer, string, any) (int, error)
}

// XSync - Remote sync peer information
type XSync struct {
	RemoteID int
	RPCState bool
	// For peer to peer RPC
	RPCType  int
	RPCHooks RPCHookInterface
}

// UlClDpWorkQ - work queue entry for ul-cl filter related operation
type UlClDpWorkQ struct {
	Work   DpWorkT
	Status *DpStatusT
	MDip   net.IP
	MSip   net.IP
	mTeID  uint32
	Zone   int
	Qfi    uint8
	Mark   int
	TDip   net.IP
	TSip   net.IP
	TTeID  uint32
	Type   DpTunT
}

// SockVIPDpWorkQ - work queue entry for local VIP-port rewrite
type SockVIPDpWorkQ struct {
	Work   DpWorkT
	VIP    net.IP
	Port   uint16
	RwPort uint16
	Status *DpStatusT
}

// DpSyncOpT - Sync Operation type
type DpSyncOpT uint8

// Sync Operation type codes
//
// APPENDS new opcodes after DpSyncBcast (DO NOT reorder existing
// values — the wire interpretation downstream depends on the iota ordering).
const (
	DpSyncAdd DpSyncOpT = iota + 1
	DpSyncDelete
	DpSyncGet
	DpSyncBcast
	// sockproxy HA state sync opcodes (SPEC §Req 4).
	DpSyncSockproxySession  // SockproxySessionMod (push)
	DpSyncSockproxyBulkGet  // SockproxySessionBulkGet (chunked pull)
	DpSyncRateLimiter       // RateLimiterSync (Phase B)
	DpSyncSockproxySnapshot // GetSockproxySnapshot (chunked pull combined)
)

// Key - outputs a key string for given DpCtInfo pointer
func (ct *DpCtInfo) Key() string {
	str := fmt.Sprintf("%s%s%d%d%s%v%v", ct.DIP.String(), ct.SIP.String(), ct.Dport, ct.Sport, ct.Proto, ct.IdType, ct.Ident)
	return str
}

// KeyState - outputs a key string for given DpCtInfo pointer with state info
func (ct *DpCtInfo) KeyState() string {
	str := fmt.Sprintf("%s%s%d%d%s%v%v-%s", ct.DIP.String(), ct.SIP.String(), ct.Dport, ct.Sport, ct.Proto, ct.IdType, ct.Ident, ct.CState)
	return str
}

// String - stringify the given DpCtInfo
func (ct *DpCtInfo) String() string {
	str := fmt.Sprintf("%s:%d->%s:%d (%s) (%v:%v), ", ct.SIP.String(), ct.Sport, ct.DIP.String(), ct.Dport, ct.Proto, ct.IdType, ct.Ident)
	str += fmt.Sprintf("%s:%s [%v:%v]", ct.CState, ct.CAct, ct.Packets, ct.Bytes)
	return str
}

// DpRetT - an empty interface to represent immediate operation result
type DpRetT interface {
}

// DpHookInterface - represents a go interface which should be implemented to
// integrate with loxinet realm
type DpHookInterface interface {
	DpMirrAdd(*MirrDpWorkQ) int
	DpMirrDel(*MirrDpWorkQ) int
	DpPolAdd(*PolDpWorkQ) int
	DpPolDel(*PolDpWorkQ) int
	DpPortPropAdd(*PortDpWorkQ) int
	DpPortPropDel(*PortDpWorkQ) int
	DpL2AddrAdd(*L2AddrDpWorkQ) int
	DpL2AddrDel(*L2AddrDpWorkQ) int
	DpRouterMacAdd(*RouterMacDpWorkQ) int
	DpRouterMacDel(*RouterMacDpWorkQ) int
	DpNextHopAdd(*NextHopDpWorkQ) int
	DpNextHopDel(*NextHopDpWorkQ) int
	DpRouteAdd(*RouteDpWorkQ) int
	DpRouteDel(*RouteDpWorkQ) int
	DpLBRuleAdd(*LBDpWorkQ) int
	DpLBRuleDel(*LBDpWorkQ) int
	DpLBCtFlush(*LBCtDpWorkQ) int
	DpLBSessionReset(*LBSessionResetWorkQ) int
	DpLBEndpointHealthUpdate(svcIP net.IP, svcPort uint16, proto uint8, epIndex int, inactive bool) int
	DpLBEndpointHostStateUpdate(svcIP net.IP, svcPort uint16, proto uint8, epIP net.IP, hostState string) int
	DpLBSetCircuitBreaker(svcIP net.IP, svcPort uint16, proto uint8, enabled bool, failureThreshold uint32, openTimeoutSec uint32) int
	DpFwRuleAdd(w *FwDpWorkQ) int
	DpFwRuleDel(w *FwDpWorkQ) int
	DpIPFilterAdd(w *IPFilterDpWorkQ) int
	DpIPFilterDel(w *IPFilterDpWorkQ) int
	DpIPFilterGet(filterType IPFilterType) ([]cmn.IPFilterEntry, error)
	DpStat(*StatDpWorkQ) int
	DpUlClAdd(w *UlClDpWorkQ) int
	DpUlClDel(w *UlClDpWorkQ) int
	DpTableGet(w *TableDpWorkQ) (DpRetT, error)
	DpCtAdd(w *DpCtInfo) int
	DpCtDel(w *DpCtInfo) int
	DpSockVIPAdd(w *SockVIPDpWorkQ) int
	DpSockVIPDel(w *SockVIPDpWorkQ) int
	DpTableGC()
	DpCtGetAsync()
	DpGetLock()
	DpRelLock()
	DpEbpfUnInit()
	GetOrAssignEndpointIndex(endpointIP string) (uint32, error)
	UpdateEndpointToGPUIndexMap(epIP net.IP, epPort uint16, gpuIdx uint32) error
	DeleteEndpointFromGPUIndexMap(epIP net.IP, epPort uint16) error
}

// DpPeer - Remote DP Peer information
type DpPeer struct {
	Peer net.IP
	//Client *rpc.Client
	Client interface{}
	// CapMask is the per-peer RPC-family capability bitmask.
	// Bits start ALL-ONES on construction; the sockproxy coordinator clears
	// a bit when it observes codes.Unimplemented from that peer for an RPC
	// in the family, then logs WARN once per (peer, RPC-family).
	// See pkg/loxinet/sockproxy_sync.go for the canonical bit constants
	// (capSessionSync, capSessionBulkGet, capRateLimiterSync, capSockproxySnapshot).
	// Default = 0xFFFFFFFF until the coordinator sees its first Unimplemented.
	CapMask uint32
}

// DpH - datapath context container
type DpH struct {
	ToDpCh   chan interface{}
	FromDpCh chan interface{}
	ToFinCh  chan int
	DpHooks  DpHookInterface
	SyncMtx  sync.RWMutex
	Peers    []DpPeer
	RPC      *XSync
	Remotes  []XSync
}

// DpXsyncRPCReset - Routine to reset Sunc RPC Client connections
func (dp *DpH) DpXsyncRPCReset() int {
	dp.SyncMtx.Lock()
	defer dp.SyncMtx.Unlock()
	for idx := range mh.dp.Peers {
		pe := &mh.dp.Peers[idx]
		dp.RPC.RPCHooks.RPCReset(pe)
	}
	return 0
}

// DpXsyncInSync - Routine to check if remote peer is in sync
func (dp *DpH) DpXsyncInSync() bool {
	dp.SyncMtx.Lock()
	defer dp.SyncMtx.Unlock()

	return len(dp.Remotes) >= len(mh.has.NodeMap)
}

// WaitXsyncReady - Routine to wait till it ready for syncing the peer entity
func (dp *DpH) WaitXsyncReady(who string) {
	begin := time.Now()
	for {
		if dp.DpXsyncInSync() {
			return
		}
		if time.Duration(time.Since(begin).Seconds()) >= 90 {
			return
		}
		tk.LogIt(tk.LogDebug, "%s:waiting for Xsync..\n", who)
		time.Sleep(2 * time.Second)
	}
}

// DpXsyncRPC - Routine for syncing connection information with peers
func (dp *DpH) DpXsyncRPC(op DpSyncOpT, arg interface{}) int {
	var ret int
	var err error

	dp.SyncMtx.Lock()
	defer dp.SyncMtx.Unlock()

	if len(mh.has.NodeMap) != len(mh.dp.Peers) {
		return -1
	}

	rpcRetries := 0
	rpcErr := false
	var cti *DpCtInfo
	var blkCti []DpCtInfo

	switch na := arg.(type) {
	case *DpCtInfo:
		cti = na
	case []DpCtInfo:
		blkCti = na
	}

	for idx := range mh.dp.Peers {
	restartRPC:
		pe := &mh.dp.Peers[idx]
		if pe.Client == nil {
			ret = dp.RPC.RPCHooks.RPCConnect(pe)
			if ret != 0 {
				rpcErr = true
				continue
			}
		}

		reply := 0
		rpcCallStr := ""
		if op == DpSyncAdd || op == DpSyncBcast {
			if len(blkCti) > 0 {
				rpcCallStr = "XSync.DpWorkOnBlockCtAdd"
			} else {
				rpcCallStr = "XSync.DpWorkOnCtAdd"
			}
		} else if op == DpSyncDelete {
			if len(blkCti) > 0 {
				rpcCallStr = "XSync.DpWorkOnBlockCtDelete"
			} else {
				rpcCallStr = "XSync.DpWorkOnCtDelete"
			}
		} else if op == DpSyncGet {
			rpcCallStr = "XSync.DpWorkOnCtGet"
		} else if op == DpSyncSockproxySession {
			// the sockproxy coordinator (sockproxy_sync.go) maintains
			// its own per-peer dispatch goroutines and does NOT funnel through
			// DpXsyncRPC. These cases exist so callers that DO route through
			// this orchestrator (e.g. future bulk-broadcast paths) have a
			// well-known rpcCallStr; the client-side switch in callGRPC
			// (xsync_client.go) recognises it and falls through to its
			// gRPC-method invocation. Task A3 wires the real Args type.
			rpcCallStr = "XSync.SockproxySessionMod"
		} else if op == DpSyncSockproxyBulkGet {
			rpcCallStr = "XSync.SockproxySessionBulkGet"
		} else if op == DpSyncRateLimiter {
			rpcCallStr = "XSync.RateLimiterSync"
		} else if op == DpSyncSockproxySnapshot {
			rpcCallStr = "XSync.GetSockproxySnapshot"
		} else {
			return -1
		}

		if op == DpSyncAdd || op == DpSyncDelete || op == DpSyncBcast {
			if op != DpSyncBcast {
				if cti == nil && len(blkCti) <= 0 {
					return -1
				}

				var tmpCti *DpCtInfo
				if cti == nil {
					tmpCti = &blkCti[0]
				} else {
					tmpCti = cti
				}
				// NOTE: the cluster-instance state is read without synchronizing
				// against concurrent HA transitions — a racing failover can observe
				// a stale state for one cycle; the next sync pass converges it.
				cIState, _ := mh.has.CIStateGetInst(tmpCti.CI)
				if cIState != cmn.CIMasterStateString {
					return 0
				}
			}
			if cti != nil {
				reply, err = dp.RPC.RPCHooks.RPCSend(pe, rpcCallStr, *cti)
			} else {
				reply, err = dp.RPC.RPCHooks.RPCSend(pe, rpcCallStr, blkCti)
			}
		} else {
			async := 1
			reply, err = dp.RPC.RPCHooks.RPCSend(pe, rpcCallStr, int32(async))
		}

		if err != nil {
			tk.LogIt(tk.LogError, "XSync call failed(%s)\n", err)
			rpcErr = true
			pe.Client = nil
			rpcRetries++
			if rpcRetries < 2 {
				goto restartRPC
			}
		}
		if reply != 0 {
			tk.LogIt(tk.LogError, "Xsync server returned error (%d)\n", reply)
			rpcErr = true
		}
	}

	if rpcErr {
		return -1
	}
	return 0
}

// DpBrokerInit - initialize the DP broker subsystem
func DpBrokerInit(dph DpHookInterface, rpcMode int) *DpH {
	nDp := new(DpH)

	nDp.ToDpCh = make(chan interface{}, DpWorkQLen)
	nDp.FromDpCh = make(chan interface{}, DpWorkQLen)
	nDp.ToFinCh = make(chan int)
	nDp.DpHooks = dph
	nDp.RPC = new(XSync)

	nDp.RPC.RPCType = rpcMode
	if rpcMode == RPCTypeNetRPC {
		nDp.RPC.RPCHooks = &netRPCClient{}
	} else {
		nDp.RPC.RPCHooks = &gRPCClient{}
	}

	go DpWorker(nDp, nDp.ToFinCh, nDp.ToDpCh)

	return nDp
}

// DpWorkOnPort - routine to work on a port work queue request
func (dp *DpH) DpWorkOnPort(pWq *PortDpWorkQ) DpRetT {
	if pWq.Work == DpCreate {
		return dp.DpHooks.DpPortPropAdd(pWq)
	} else if pWq.Work == DpRemove {
		return dp.DpHooks.DpPortPropDel(pWq)
	}

	return DpWqUnkErr
}

// DpWorkOnL2Addr - routine to work on a l2 addr work queue request
func (dp *DpH) DpWorkOnL2Addr(pWq *L2AddrDpWorkQ) DpRetT {
	if pWq.Work == DpCreate {
		return dp.DpHooks.DpL2AddrAdd(pWq)
	} else if pWq.Work == DpRemove {
		return dp.DpHooks.DpL2AddrDel(pWq)
	}

	return DpWqUnkErr
}

// DpWorkOnRtMac - routine to work on a rt-mac work queue request
func (dp *DpH) DpWorkOnRtMac(rmWq *RouterMacDpWorkQ) DpRetT {
	if rmWq.Work == DpCreate {
		return dp.DpHooks.DpRouterMacAdd(rmWq)
	} else if rmWq.Work == DpRemove {
		return dp.DpHooks.DpRouterMacDel(rmWq)
	}

	return DpWqUnkErr
}

// DpWorkOnNextHop - routine to work on a nexthop work queue request
func (dp *DpH) DpWorkOnNextHop(nhWq *NextHopDpWorkQ) DpRetT {
	if nhWq.Work == DpCreate {
		return dp.DpHooks.DpNextHopAdd(nhWq)
	} else if nhWq.Work == DpRemove {
		return dp.DpHooks.DpNextHopDel(nhWq)
	}

	return DpWqUnkErr
}

// DpWorkOnRoute - routine to work on a route work queue request
func (dp *DpH) DpWorkOnRoute(rtWq *RouteDpWorkQ) DpRetT {
	if rtWq.Work == DpCreate {
		return dp.DpHooks.DpRouteAdd(rtWq)
	} else if rtWq.Work == DpRemove {
		return dp.DpHooks.DpRouteDel(rtWq)
	}

	return DpWqUnkErr
}

// DpWorkOnNatLb - routine  to work on a NAT lb work queue request
func (dp *DpH) DpWorkOnNatLb(nWq *LBDpWorkQ) DpRetT {
	// [CP-DEBUG] Stage 4: DpWorkOnNatLb entry - log work item
	tk.LogIt(tk.LogInfo, "[CP-DEBUG] DpWorkOnNatLb: VIP=%s port=%d proto=%d work=%d eps=%d\n",
		nWq.ServiceIP.String(), nWq.L4Port, nWq.Proto, nWq.Work, len(nWq.endPoints))
	if nWq.Work == DpCreate {
		return dp.DpHooks.DpLBRuleAdd(nWq)
	} else if nWq.Work == DpRemove {
		return dp.DpHooks.DpLBRuleDel(nWq)
	}

	return DpWqUnkErr
}

// DpWorkOnUlCl - routine to work on a ulcl work queue request
func (dp *DpH) DpWorkOnUlCl(nWq *UlClDpWorkQ) DpRetT {
	if nWq.Work == DpCreate {
		return dp.DpHooks.DpUlClAdd(nWq)
	} else if nWq.Work == DpRemove {
		return dp.DpHooks.DpUlClDel(nWq)
	}

	return DpWqUnkErr
}

// DpWorkOnStat - routine to work on a stat work queue request
func (dp *DpH) DpWorkOnStat(nWq *StatDpWorkQ) DpRetT {
	return dp.DpHooks.DpStat(nWq)
}

// DpWorkOnTableOp - routine to work on a table work queue request
func (dp *DpH) DpWorkOnTableOp(nWq *TableDpWorkQ) (DpRetT, error) {
	return dp.DpHooks.DpTableGet(nWq)
}

// DpWorkOnPol - routine to work on a policer work queue request
func (dp *DpH) DpWorkOnPol(pWq *PolDpWorkQ) DpRetT {
	if pWq.Work == DpCreate {
		return dp.DpHooks.DpPolAdd(pWq)
	} else if pWq.Work == DpRemove {
		return dp.DpHooks.DpPolDel(pWq)
	}

	return DpWqUnkErr
}

// DpWorkOnMirr - routine to work on a mirror work queue request
func (dp *DpH) DpWorkOnMirr(mWq *MirrDpWorkQ) DpRetT {
	if mWq.Work == DpCreate {
		return dp.DpHooks.DpMirrAdd(mWq)
	} else if mWq.Work == DpRemove {
		return dp.DpHooks.DpMirrDel(mWq)
	}

	return DpWqUnkErr
}

// DpWorkOnFw - routine to work on a firewall work queue request
func (dp *DpH) DpWorkOnFw(fWq *FwDpWorkQ) DpRetT {
	if fWq.Work == DpCreate {
		return dp.DpHooks.DpFwRuleAdd(fWq)
	} else if fWq.Work == DpRemove {
		return dp.DpHooks.DpFwRuleDel(fWq)
	}

	return DpWqUnkErr
}

// DpWorkOnSockVIP - routine to work on local VIP-port rewrite
func (dp *DpH) DpWorkOnSockVIP(vsWq *SockVIPDpWorkQ) DpRetT {
	if vsWq.Work == DpCreate {
		return dp.DpHooks.DpSockVIPAdd(vsWq)
	} else if vsWq.Work == DpRemove {
		return dp.DpHooks.DpSockVIPDel(vsWq)
	}

	return DpWqUnkErr
}

// DpWorkOnPeerOp - routine to work on a peer request for clustering
func (dp *DpH) DpWorkOnPeerOp(pWq *PeerDpWorkQ) DpRetT {
	if pWq.Work == DpCreate {
		var newPeer DpPeer
		for _, pe := range dp.Peers {
			if pe.Peer.Equal(pWq.PeerIP) {
				return DpCreateErr
			}
		}
		newPeer.Peer = pWq.PeerIP
		// start with all RPC-family bits set; coordinator clears bits
		// on codes.Unimplemented (per-peer graceful degrade, SPEC D1).
		newPeer.CapMask = 0xFFFFFFFF
		dp.Peers = append(dp.Peers, newPeer)
		tk.LogIt(tk.LogInfo, "Added cluster-peer %s\n", newPeer.Peer.String())
		return 0
	} else if pWq.Work == DpRemove {
		for idx := range dp.Peers {
			pe := &dp.Peers[idx]
			if pe.Peer.Equal(pWq.PeerIP) {
				if pe.Client != nil {
					dp.RPC.RPCHooks.RPCClose(pe)
				}
				dp.Peers = append(dp.Peers[:idx], dp.Peers[idx+1:]...)
				tk.LogIt(tk.LogInfo, "Deleted cluster-peer %s\n", pWq.PeerIP.String())
				return 0
			}
		}
	}

	return DpWqUnkErr
}

// DpWorkSingle - routine to work on a single dp work queue request
// DpSyncBarrier - token sent on ToDpCh to wait for all preceding work to complete
type DpSyncBarrier struct {
	Done chan struct{}
}

// DpBrokerSyncBarrier - enqueue a barrier and block until DpWorker processes it,
// guaranteeing all work items queued before the barrier are fully applied to BPF maps
func DpBrokerSyncBarrier(dp *DpH) {
	b := &DpSyncBarrier{Done: make(chan struct{})}
	dp.ToDpCh <- b
	<-b.Done
}

func DpWorkSingle(dp *DpH, m interface{}) DpRetT {
	var ret DpRetT
	switch mq := m.(type) {
	case *DpSyncBarrier:
		close(mq.Done)
		return 0
	case *MirrDpWorkQ:
		ret = dp.DpWorkOnMirr(mq)
	case *PolDpWorkQ:
		ret = dp.DpWorkOnPol(mq)
	case *PortDpWorkQ:
		ret = dp.DpWorkOnPort(mq)
	case *L2AddrDpWorkQ:
		ret = dp.DpWorkOnL2Addr(mq)
	case *RouterMacDpWorkQ:
		ret = dp.DpWorkOnRtMac(mq)
	case *NextHopDpWorkQ:
		ret = dp.DpWorkOnNextHop(mq)
	case *RouteDpWorkQ:
		ret = dp.DpWorkOnRoute(mq)
	case *LBDpWorkQ:
		ret = dp.DpWorkOnNatLb(mq)
	case *UlClDpWorkQ:
		ret = dp.DpWorkOnUlCl(mq)
	case *StatDpWorkQ:
		ret = dp.DpWorkOnStat(mq)
	case *TableDpWorkQ:
		ret, _ = dp.DpWorkOnTableOp(mq)
	case *FwDpWorkQ:
		ret = dp.DpWorkOnFw(mq)
	case *PeerDpWorkQ:
		ret = dp.DpWorkOnPeerOp(mq)
	case *SockVIPDpWorkQ:
		ret = dp.DpWorkOnSockVIP(mq)
	default:
		tk.LogIt(tk.LogError, "unexpected type %T\n", mq)
		ret = DpWqUnkErr
	}
	return ret
}

// DpWorker - DP worker routine listening on a channel
func DpWorker(dp *DpH, f chan int, ch chan interface{}) {
	// Stack trace logger
	defer func() {
		if e := recover(); e != nil {
			tk.LogIt(tk.LogCritical, "%s: %s", e, debug.Stack())
		}
		if mh.dp != nil {
			mh.dp.DpHooks.DpEbpfUnInit()
		}
		os.Exit(1)
	}()
	for {
		for n := 0; n < DpWorkQLen; n++ {
			select {
			case m := <-ch:
				DpWorkSingle(dp, m)
			case <-f:
				return
			default:
				continue
			}
		}
		time.Sleep(1000 * time.Millisecond)
	}
}

// DpMapGetCt4 - get DP conntrack information as a map
func (dp *DpH) DpMapGetCt4() []cmn.CtInfo {
	var CtInfoArr []cmn.CtInfo
	var servName string

	nTable := new(TableDpWorkQ)
	nTable.Work = DpMapGet
	nTable.Name = MapNameCt4

	ret, err := mh.dp.DpWorkOnTableOp(nTable)
	if err != nil {
		return nil
	}

	switch r := ret.(type) {
	case map[string]*DpCtInfo:
		for _, dCti := range r {
			servName = "-"
			mh.mtx.Lock()
			rule := mh.zr.Rules.GetLBRuleByID(dCti.RuleID)
			mh.mtx.Unlock()
			if rule != nil {
				servName = rule.name
			}
			cti := cmn.CtInfo{Dip: dCti.DIP, Sip: dCti.SIP, Dport: dCti.Dport, Sport: dCti.Sport,
				Proto: dCti.Proto, Ident: fmt.Sprintf("%v:%v", dCti.IdType, dCti.Ident),
				CState: dCti.CState, CAct: dCti.CAct,
				Pkts: dCti.Packets, Bytes: dCti.Bytes, ServiceName: servName}
			CtInfoArr = append(CtInfoArr, cti)
		}
	}

	dp.DpHooks.DpTableGC()

	return CtInfoArr
}

// DpCtStatsRollup - Octavia : refresh each rule's in-memory statistics
// (ruleEnt.activeConns / totalConns / bytesIn / bytesOut) from the data plane.
//
// Octavia's statistics quad must be CUMULATIVE: totalConnections and bytesIn/bytesOut count
// everything the rule has ever served, not just what is live at this instant. A pure live-CT
// walk cannot deliver that — a flow created and torn down between two RulesSync ticks is invisible
// to the walk (10 short curls were once counted as 1). So the authoritative source for the
// cumulative fields is the datapath itself: 74-02's per-rule nat_ep_map (struct dp_nat_epacts)
// now carries total_conns (++ on CT-create) and cum_bytes_in/out (summed at CT-teardown), which
// see every flow. This rollup reads those per rule and adds the live-CT walk only as an in-flight
// refinement for bytes, so a long-lived connection's bytes show up before it closes.
//
//   - activeConns = conc_conns, the datapath live gauge — the SAME selector-agnostic count the
//     connLimit gate enforces.
//   - totalConns  = total_conns, datapath cumulative; never decremented.
//
// - bytesIn = cum_bytes_in (closed flows) + Σ live CT_DIR_IN bytes (in-flight) ((a)).
//   - bytesOut = cum_bytes_out (closed flows) + Σ live CT_DIR_OUT bytes (in-flight).
//
// A live CT contributes to cum_bytes only at teardown, so summing the live walk on top of the
// cumulative totals neither double-counts a closed flow nor misses an open one. Counters reset to
// zero on restart / rule delete (datapath maps are recreated; the CP copy is in-memory).
//
// LOCKING: the sole caller chain is ZoneTicker -> RulesTicker -> RulesSync -> here, and
// ZoneTicker already holds mh.mtx for the entire tick (zones.go ZoneTicker: mh.mtx.Lock).
// mh.mtx is a plain (non-reentrant) sync.Mutex, so this function MUST NOT re-acquire it —
// doing so self-deadlocks the ticker goroutine while it still holds mh.mtx, which then wedges
// every mh.mtx writer (e.g. NetLbRuleAdd) and hangs all REST POSTs. The reset+refill below is
// therefore already atomic against concurrent writers under the caller's lock.
func (dp *DpH) DpCtStatsRollup() {
	// NOTE: mh.mtx is already held by the ZoneTicker caller — do NOT lock it here (see LOCKING).

	// Zero every rule's per-pass counters, then refill them from the datapath this pass. All four
	// fields are recomputed each pass now (the cumulative ones live in the data plane, not in Go),
	// so a rule whose last CT just tore down still reports its cumulative totals and a 0 active.
	mh.zr.Rules.resetRuleLiveStats()

	// Authoritative cumulative source: the per-rule nat_ep_map (datapath counters).
	epTable := new(TableDpWorkQ)
	epTable.Work = DpMapGet
	epTable.Name = MapNameNatEp
	if epRet, err := mh.dp.DpWorkOnTableOp(epTable); err == nil {
		if epMap, ok := epRet.(map[uint32]*NatEpStats); ok {
			for mark, st := range epMap {
				rule := mh.zr.Rules.GetLBRuleByID(mark)
				if rule == nil {
					continue
				}
				rule.activeConns = st.ActiveConns
				rule.totalConns = st.TotalConns
				rule.bytesIn = st.BytesIn
				rule.bytesOut = st.BytesOut
			}
		}
	}

	// In-flight refinement: add the bytes of currently-live CTs on top of the cumulative totals so
	// long-lived connections report progress before they tear down (closed flows are already in
	// cum_bytes_in/out; live ones are not yet, so there is no double count).
	ctTable := new(TableDpWorkQ)
	ctTable.Work = DpMapGet
	ctTable.Name = MapNameCt4
	ret, err := mh.dp.DpWorkOnTableOp(ctTable)
	if err != nil {
		return
	}
	ctMap, ok := ret.(map[string]*DpCtInfo)
	if !ok {
		return
	}
	for _, dCti := range ctMap {
		rule := mh.zr.Rules.GetLBRuleByID(dCti.RuleID)
		if rule == nil {
			continue
		}
		switch dCti.Dir {
		case 0: // CT_DIR_IN — forward, client->VIP request
			rule.bytesIn += dCti.Bytes
		case 1: // CT_DIR_OUT — reverse, VIP->client response
			rule.bytesOut += dCti.Bytes
		default:
			// Unknown direction (proxy/aggregate) — no heuristic split, leave byte buckets.
		}
	}
}
