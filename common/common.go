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

package common

import (
	"errors"
	"net"
	"time"
)

// Version is the release identifier, stamped at link time by the build:
//
//	go build -ldflags "-X github.com/loxilb-io/loxilb/common.Version=v0.9.8.7"
//
// The Makefile derives it from `git describe --tags`, so a tagged build
// reports the tag verbatim and a working build reports its distance from the
// last tag (e.g. v0.9.8.7-3-gabc1234-dirty). It must stay a var, not a const:
// -ldflags -X cannot write to a const, which is why this used to be pinned to
// a stale literal that disagreed with the tag it shipped under.
//
// "dev" is only ever seen when the tree has no git metadata and no VERSION was
// passed in — notably inside container builds, since .dockerignore strips
// .git. Those pass VERSION explicitly as a build-arg.
var Version = "dev"

var BuildInfo string = ""

// Product is the flavor identifier surfaced on GET /version so shared
// clients (loxilb-ui) can distinguish this gateway from plain upstream
// loxilb, which never sets the field. Clients treat an absent product as
// upstream loxilb, so this must ship in any release the UI flavor-gates on.
const Product = "loxilb-inference-gateway"

// This file defines the go interface implementation needed to interact with loxinet go module

const (
	// CIStateMaster - HA Master state
	CIStateMaster = 1 + iota
	// CIStateBackup - HA Backup/Slave state
	CIStateBackup
	// CIStateConflict - HA Fault/Conflict State
	CIStateConflict
	// CIStateNotDefined - HA State not enabled or stopped
	CIStateNotDefined
)

const BFDPort = 3784
const BFDDefRetryCount = 3

const (
	KAHookScript = "/opt/loxilb/ka_hook.sh"
)

const (
	// CIDefault - Default CI Instance name
	CIDefault = "llb-inst0"
	// CIMasterStateString - Master state string for a cluster instance
	CIMasterStateString = "MASTER"
	// CIBackupStateString - Backup state string for a cluster instance
	CIBackupStateString = "BACKUP"
	// CIFaultStateString - Fault state string for a cluster instance
	CIFaultStateString = "FAULT"
	// CIStopStateString - Stop state string for a cluster instance
	CIStopStateString = "STOP"
	// CIUnDefStateString - Undefined state string for a cluster instance
	CIUnDefStateString = "NOT_DEFINED"
)

const (
	// HighLocalPref - High local preference for advertising BGP route(Default or Master)
	HighLocalPref = 5000
	// LowLocalPref - Low local preference for advertising BGP route(Backup)
	LowLocalPref = 100
	// HighMed - Low metric means higher probability for selection outside AS
	HighMed = 10
	// LowMed - High metric means lower probability for selection outside AS
	LowMed = 20
)

const (
	// CertPath - SSL certificates path
	CertPath = "/opt/loxilb/cert/"

	// CACertFileName - loxilb CA cert file
	CACertFileName = "rootCA.crt"

	// PrivateCertName - loxilb private certificate name
	PrivateCertName = "server.crt"

	// PrivateKeyName - loxilb private key name
	PrivateKeyName = "server.key"
)

const (
	// AuWorkqLen - Address worker channel depth
	AuWorkqLen = 2048
	// LuWorkQLen - Link worker channel depth
	LuWorkQLen = 2048
	// NuWorkQLen - Neigh worker channel depth
	NuWorkQLen = 2048
	// RuWorkQLen - Route worker channel depth
	RuWorkQLen = 40827
)

const (
	// PortReal - Base port type
	PortReal = 1 << iota
	// PortBondSif - Bond slave port type
	PortBondSif
	// PortBond - Bond port type
	PortBond
	// PortVlanSif - Vlan slave port type
	PortVlanSif
	// PortVlanBr - Vlan Br port type
	PortVlanBr
	// PortVxlanSif - Vxlan slave port type
	PortVxlanSif
	// PortVxlanBr - Vxlan br port type
	PortVxlanBr
	// PortWg - Wireguard port type
	PortWg
	// PortVti - Vti port type
	PortVti
	// PortIPTun - IPInIP port type
	PortIPTun
	// PortGre - GRE port type
	PortGre
)

// PortProp - Defines auxiliary port properties
type PortProp uint8

const (
	// PortPropUpp - User-plane processing enabled
	PortPropUpp PortProp = 1 << iota
	// PortPropSpan - SPAN is enabled
	PortPropSpan
	// PortPropPol - Policer is active
	PortPropPol
	// PortPropPolEgress - egress-direction policer is active
	PortPropPolEgress
)

// DpStatusT - Generic status of operation
type DpStatusT uint8

// PortDump - Generic dump info of a port
type PortDump struct {
	// Name - name of the port
	Name string `json:"portName"`
	// PortNo - port number
	PortNo int `json:"portNo"`
	// Zone - security zone info
	Zone string `json:"zone"`
	// SInfo - software specific port information
	SInfo PortSwInfo `json:"portSoftwareInformation"`
	// HInfo - hardware specific port information
	HInfo PortHwInfo `json:"portHardwareInformation"`
	// Stats - port statistics related information
	Stats PortStatsInfo `json:"portStatisticInformation"`
	// L3 - layer3 info related to port
	L3 PortLayer3Info `json:"portL3Information"`
	// L2 - layer2 info related to port
	L2 PortLayer2Info `json:"portL2Information"`
	// Sync - sync state
	Sync DpStatusT `json:"DataplaneSync"`
}

// PortStatsInfo - stats information of port
type PortStatsInfo struct {
	// RxBytes - rx Byte count
	RxBytes uint64 `json:"rxBytes"`
	// TxBytes - tx Byte count
	TxBytes uint64 `json:"txBytes"`
	// RxPackets - tx Packets count
	RxPackets uint64 `json:"rxPackets"`
	// TxPackets - tx Packets count
	TxPackets uint64 `json:"txPackets"`
	// RxError - rx error count
	RxError uint64 `json:"rxErrors"`
	// TxError - tx error count
	TxError uint64 `json:"txErrors"`
}

// PortHwInfo - hw info of a port
type PortHwInfo struct {
	// MacAddr - mac address as byte array
	MacAddr [6]byte `json:"rawMacAddress"`
	// MacAddrStr - mac address in string format
	MacAddrStr string `json:"macAddress"`
	// Link - lowerlayer state
	Link bool `json:"link"`
	// State - administrative state
	State bool `json:"state"`
	// Mtu - maximum transfer unit
	Mtu int `json:"mtu"`
	// Master - master of this port if any
	Master string `json:"master"`
	// Real - underlying real dev info if any
	Real string `json:"real"`
	// TunID - tunnel info if any
	TunID uint32 `json:"tunnelId"`
}

// PortLayer3Info - layer3 info of a port
type PortLayer3Info struct {
	// Routed - routed mode or not
	Routed bool `json:"routed"`
	// Ipv4Addrs - ipv4 address set
	Ipv4Addrs []string `json:"IPv4Address"`
	// Ipv6Addrs - ipv6 address set
	Ipv6Addrs []string `json:"IPv6Address"`
}

// PortSwInfo - software specific info of a port
type PortSwInfo struct {
	// OsID - interface id of an OS
	OsID int `json:"osId"`
	// PortType - type of port
	PortType int `json:"portType"`
	// PortProp - port property
	PortProp PortProp `json:"portProp"`
	// PortActive - port enabled/disabled
	PortActive bool `json:"portActive"`
	// PortReal - pointer to real port if any
	PortReal *PortDump `json:"portReal"`
	// PortOvl - pointer to ovl port if any
	PortOvl *PortDump `json:"portOvl"`
	// BpfLoaded - eBPF loaded or not flag
	BpfLoaded bool `json:"bpfLoaded"`
}

// PortLayer2Info - layer2 info of a port
type PortLayer2Info struct {
	// IsPvid - this vid is Pvid or not
	IsPvid bool `json:"isPvid"`
	// Vid - vid related to prot
	Vid int `json:"vid"`
}

// PortMod - port modification info
type PortMod struct {
	// Dev - name of port
	Dev string
	// LinkIndex - OS allocated index
	LinkIndex int
	// Ptype - port type
	Ptype int
	// MacAddr - mac address
	MacAddr [6]byte
	// Link - lowerlayer state
	Link bool
	// State - administrative state
	State bool
	// Mtu - maximum transfer unit
	Mtu int
	// Master - master of this port if any
	Master string
	// Real - underlying real dev info if any
	Real string
	// TunID - tunnel info if any
	TunID int
	// TunSrc - tunnel source
	TunSrc net.IP
	// TunDst - tunnel dest
	TunDst net.IP
}

// VlanMod - Info about a vlan
type VlanMod struct {
	// Vid - vlan identifier
	Vid int `json:"vid"`
	// Dev - name of the related device
	Dev string `json:"dev"`
	// LinkIndex - OS allocated index
	LinkIndex int
	// MacAddr - mac address
	MacAddr [6]byte
	// Link - lowerlayer state
	Link bool
	// State - administrative state
	State bool
	// Mtu - maximum transfer unit
	Mtu int
	// TunID - tunnel info if any
	TunID uint32
}

// VlanPortMod - Info about a port attached to a vlan
type VlanPortMod struct {
	// Vid - vlan identifier
	Vid int `json:"vid"`
	// Dev - name of the related device
	Dev string `json:"dev"`
	// Tagged - tagged or not
	Tagged bool `json:"tagged"`
}

// VlanStat - statistics for vlan interface
type VlanStat struct {
	InBytes    uint64
	InPackets  uint64
	OutBytes   uint64
	OutPackets uint64
}

// VlanGet - Info for vlan interface to get
type VlanGet struct {
	// Vid - vlan identifier
	Vid int `json:"vid"`
	// Dev - name of port
	Dev string `json:"dev"`
	// Slaves - name of slave ports
	Member []VlanPortMod `json:"member"`
	// Stat Vlan traffic statistics
	Stat VlanStat `json:"vlanStatistic"`
}

const (
	// FdbPhy - fdb of a real dev
	FdbPhy = 0
	// FdbTun - fdb of a tun dev
	FdbTun = 1
	// FdbVlan - fdb of a vlan dev
	FdbVlan = 2
)

// FdbMod - Info about a forwarding data-base
type FdbMod struct {
	// MacAddr - mac address
	MacAddr [6]byte
	// BridgeID - bridge domain-id
	BridgeID int
	// Dev - name of the related device
	Dev string
	// Dst - ip addr related to fdb
	Dst net.IP
	// Type - One of FdbPhy/FdbTun/FdbVlan
	Type int
}

// IPAddrMod - Info about an ip address
type IPAddrMod struct {
	// Dev - name of the related device
	Dev string
	// IP - Actual IP address
	IP string
}

// NeighMod - Info about an neighbor
type NeighMod struct {
	// IP - The IP address
	IP net.IP
	// LinkIndex - OS allocated index
	LinkIndex int
	// State - active or inactive
	State int
	// HardwareAddr - resolved hardware address if any
	HardwareAddr net.HardwareAddr
}

// IPAddrGet - Info about an ip addresses
type IPAddrGet struct {
	// Dev - name of the related device
	Dev string
	// IP - Actual IP address
	IP []string
	// Sync - sync state
	Sync DpStatusT
}

// RouteGetEntryStatistic - Info about an route statistic
type RouteGetEntryStatistic struct {
	// Statistic of the ingress port bytes.
	Bytes int
	// Statistic of the egress port bytes.
	Packets int
}

// RouteGet - Info about an route
type RouteGet struct {
	// Protocol - Protocol type
	Protocol int
	// Flags - flag type
	Flags string
	// Gw - gateway information if any
	Gw string
	// LinkIndex - OS allocated index
	LinkIndex int
	// Dst - ip addr
	Dst string
	// index of the route
	HardwareMark int
	// statistic
	Statistic RouteGetEntryStatistic
	// sync
	Sync DpStatusT
}

// GWInfo - Info about gateway
type GWInfo struct {
	// Gw - gateway information if any
	Gw net.IP
	// LinkIndex - OS allocated index
	LinkIndex int
}

// RouteMod - Info about a route
type RouteMod struct {
	// Protocol - Protocol type
	Protocol int
	// Flags - flag type
	Flags int
	// GWs - gateway information if any
	GWs []GWInfo
	// Dst - ip addr
	Dst net.IPNet
}

// FwOptArg - Information related to Firewall options
type FwOptArg struct {
	// Drop - Drop any matching rule
	Drop bool `json:"drop"`
	// Trap - Trap anything matching rule
	Trap bool `json:"trap"`
	// Record - Record packets matching rule
	Record bool `json:"record"`
	// Redirect - Redirect any matching rule
	Rdr     bool   `json:"redirect"`
	RdrPort string `json:"redirectPortName"`
	// Allow - Allow any matching rule
	Allow bool `json:"allow"`
	// Mark - Mark the matching rule
	Mark uint32 `json:"fwMark"`
	// DoSnat - Do snat on matching rule
	DoSnat bool   `json:"doSnat"`
	ToIP   string `json:"toIP"`
	ToPort uint16 `json:"toPort"`
	// OnDefault - Trigger only on default cases
	OnDefault bool `json:"onDefault"`
	// Counter - Traffic counter
	Counter string `json:"counter"`
}

// FwRuleArg - Information related to firewall rule
type FwRuleArg struct {
	// SrcIP - Source IP in CIDR notation
	SrcIP string `json:"sourceIP"`
	// DstIP - Destination IP in CIDR notation
	DstIP string `json:"destinationIP"`
	// SrcPortMin - Minimum source port range
	SrcPortMin uint16 `json:"minSourcePort"`
	// SrcPortMax - Maximum source port range
	SrcPortMax uint16 `json:"maxSourcePort"`
	// DstPortMin - Minimum destination port range
	DstPortMin uint16 `json:"minDestinationPort"`
	// SrcPortMax - Maximum source port range
	DstPortMax uint16 `json:"maxDestinationPort"`
	// Proto - the protocol
	Proto uint8 `json:"protocol"`
	// InPort - the incoming port
	InPort string `json:"portName"`
	// Pref - User preference for ordering
	Pref uint32 `json:"preference"`
	// HwOffload - Opt-IN per-rule flag requesting DOCA HW offload via the
	// ingress ACL pipeline (DENY_PIPE + ALLOW_PIPE). Default false.
	// When true, the rule MUST be expressible in HW (5-tuple TRANSPORT,
	// IPv4, no port range, no proto-specific match); rules.go hard-rejects
	// at AddFwRule. HW-flagged rules are mirrored into
	// both eBPF and HW (eBPF is the authoritative fallback).
	// Operator owns Pref-ordering correctness across the HW/eBPF split per
	// See
	HwOffload bool `json:"hwOffload"`
}

// FwRuleMod - Info related to a firewall entry
type FwRuleMod struct {
	// Rule - service argument of type FwRuleArg
	Rule FwRuleArg `json:"ruleArguments"`
	// Opts - firewall options
	Opts FwOptArg `json:"opts"`
}

// IPFilterMod - Info related to an IP filter entry (whitelist/blacklist)
type IPFilterMod struct {
	// FilterType - "whitelist" or "blacklist"
	FilterType string `json:"filterType"`
	// CIDR - CIDR notation (e.g., "192.168.1.0/24" or "2001:db8::/32")
	CIDR string `json:"cidr"`
	// Zone - Security zone (0 = all zones)
	Zone uint8 `json:"zone"`
	// Priority - Rule priority (higher = more important)
	Priority uint16 `json:"priority"`
	// Action - "allow" or "drop"
	Action string `json:"action"`
}

// IPFilterEntry - Information related to an existing IP filter rule
type IPFilterEntry struct {
	IPFilterMod
	// Packets - Number of packets matched
	Packets uint64 `json:"packets"`
	// Bytes - Number of bytes matched
	Bytes uint64 `json:"bytes"`
}

// SecurityRateConfig - Unified configuration for P0-5 SYN Flood + P0-6 Connection Rate Limiting + P0-7 UDP Flood
// This is the NEW unified approach that combines all three features into single eBPF maps
type SecurityRateConfig struct {
	// P0-5: SYN Flood Protection
	SYNEnabled      bool   `json:"synEnabled"`
	SYNThreshold    uint32 `json:"synThreshold"`    // Max SYNs/sec before dropping (default: 100)
	CookieThreshold uint32 `json:"cookieThreshold"` // Enable SYN cookies above this rate (default: 50)

	// P0-6: Connection Rate Limiting
	ConnRateEnabled bool   `json:"connRateEnabled"`
	RatePerSec      uint32 `json:"ratePerSec"` // Max connections/sec (default: 50)

	// P0-7: UDP Flood Protection (NEW)
	UDPEnabled      bool   `json:"udpEnabled"`
	UDPPktThreshold uint32 `json:"udpPktThreshold"` // Max UDP packets/sec before dropping (default: 1000)
	UDPBandwidthMB  uint32 `json:"udpBandwidthMB"`  // Max UDP bandwidth in MB/sec (default: 100)

	// Shared Configuration
	WhitelistIPs []string `json:"whitelistIps"` // IPs to bypass all rate limiting
}

// SecurityRateStats - Unified statistics for P0-5 + P0-6 + P0-7 from eBPF maps
type SecurityRateStats struct {
	// P0-5: SYN Flood Statistics
	SYNBlocked uint64 `json:"synBlocked"` // SYN packets blocked
	SYNPassed  uint64 `json:"synPassed"`  // SYN packets passed
	SYNCookies uint64 `json:"synCookies"` // SYN cookie activations

	// P0-6: Connection Rate Statistics
	ConnBlocked uint64 `json:"connBlocked"` // Connections blocked by rate
	ConnPassed  uint64 `json:"connPassed"`  // Connections passed

	// P0-7: UDP Flood Statistics (NEW)
	UDPBlocked      uint64 `json:"udpBlocked"`      // UDP packets blocked
	UDPPassed       uint64 `json:"udpPassed"`       // UDP packets passed
	UDPBytesBlocked uint64 `json:"udpBytesBlocked"` // UDP bytes blocked
	UDPBytesPassed  uint64 `json:"udpBytesPassed"`  // UDP bytes passed

	// Shared Statistics
	UniqueIPs uint64 `json:"uniqueIps"` // Unique source IPs tracked
}

// CtErrorStats - always-on, unsampled L4 connection-error counters (metric-only,
// trace-independent). Populated by the CT state machine on RST/abort/error
// transitions and surfaced as loxilb_l4_error_events_total. See CtErrorStats in
// pkg/loxinet/dpebpf_linux.go and CT_ERR_STAT_* in llb_kern_ct.c.
type CtErrorStats struct {
	TCPRstClient uint64 `json:"tcpRstClient"` // TCP RST from client  (CT_TCP_CW, dir IN)
	TCPRstServer uint64 `json:"tcpRstServer"` // TCP RST from backend (CT_TCP_CW, dir OUT)
	TCPErr       uint64 `json:"tcpErr"`       // TCP protocol error / half-open (CT_TCP_ERR)
	SCTPAbort    uint64 `json:"sctpAbort"`    // SCTP ABORT (CT_SCTP_ABRT)
	SCTPErr      uint64 `json:"sctpErr"`      // SCTP error (CT_SCTP_ERR)
}

// SecurityRateState - Combined configuration and statistics for unified security rate limiting
type SecurityRateState struct {
	Config SecurityRateConfig `json:"config"`
	Stats  SecurityRateStats  `json:"stats"`
}

// EndPointMod - Info related to a end-point entry
type EndPointMod struct {
	// HostName - hostname in CIDR
	HostName string `json:"hostName"`
	//  Name - Endpoint Identifier
	Name string `json:"name"`
	// InActTries - No. of inactive probes to mark
	// an end-point inactive
	InActTries int `json:"inactiveReTries"`
	// ProbeType - Type of probe : "icmp","connect-tcp", "connect-udp", "connect-sctp", "http", "https"
	ProbeType string `json:"probeType"`
	// ProbeReq - Request string in case of http probe
	ProbeReq string `json:"probeReq"`
	// ProbeResp - Response string in case of http probe
	ProbeResp string `json:"probeResp"`
	// ProbeDuration - How frequently (in seconds) to check activity
	ProbeDuration uint32 `json:"probeDuration"`
	// ProbePort - Port to probe for connect type
	ProbePort uint16 `json:"probePort"`
	// RuleManaged - true when this end-point entry exists because an LB
	// rule references it (loxinet ruleCount > 0), not because a client
	// created it via the endpoint API. Such entries are (re)created
	// automatically when their LB rule is applied, so snapshot capture
	// skips them (pkg/snapshot registry).
	RuleManaged bool `json:"ruleManaged,omitempty"`
	// MinDelay - Minimum delay in this end-point
	MinDelay string `json:"minDelay"`
	// AvgDelay - Average delay in this end-point
	AvgDelay string `json:"avgDelay"`
	// MaxDelay - Max delay in this end-point
	MaxDelay string `json:"maxDelay"`
	// CurrState - Current state of this end-point
	CurrState string `json:"currState"`
	// Octavia HTTP(S) health-monitor content checks.
	// All additive + optional (omitempty) — unset ⇒ today's behaviour (probeReq/probeResp
	// retained as the lower-level escape hatch). Control-plane only (no has_l7_policy gate).
	// HttpMethod - HM HTTP method (e.g. "GET","HEAD"); empty ⇒ GET
	HttpMethod string `json:"httpMethod,omitempty"`
	// UrlPath - HM request path (e.g. "/healthz"); empty ⇒ probeReq / "/"
	UrlPath string `json:"urlPath,omitempty"`
	// ExpectedCodes - Octavia expected_codes: single "200", list "200,202", range "200-204"; empty ⇒ "200"
	ExpectedCodes string `json:"expectedCodes,omitempty"`
	// HttpVersion - "1.0" or "1.1"; when "1.1" a Host header is sent (DomainName, else member addr)
	HttpVersion string `json:"httpVersion,omitempty"`
	// DomainName - doubles as TLS SNI for HTTPS monitors AND the Host header
	DomainName string `json:"domainName,omitempty"`
	// residual: per-health-monitor CA override + verify opt-out.
	// Additive + optional, control-plane only (no proxy_arg / data-plane impact). Parallels the
	// health-monitor field pattern. Maps onto epHostOpts in NetEpHostAdd.
	// ProbeCaPath - override CA bundle (PEM file) for the HTTPS content probe; empty ⇒ default pool
	ProbeCaPath string `json:"probeCaPath,omitempty"`
	// ProbeVerify - probe TLS verification toggle. POINTER on purpose for back-compat (mirrors
	// AdminStateUp): verification defaults to ON, so nil/absent (a legacy entry or a body
	// that omits the field) MUST resolve to verify-ON, never verify-off. Only an explicit false
	// sets InsecureSkipVerify (: a conscious operator opt-out, never the default).
	ProbeVerify *bool `json:"probeVerify,omitempty"`
	// ProbeCrlPath - residual: optional static CRL (PEM file) the HTTPS
	// content probe checks the server-cert chain against (leaf-only revocation). Additive +
	// optional, control-plane only — empty ⇒ no CRL (today's behaviour). Rides the same health/
	// verify surface as ProbeCaPath; maps onto epHostOpts in NetEpHostAdd.
	ProbeCrlPath string `json:"probeCrlPath,omitempty"`
}

const (
	// HostStateGreen - Host is healthy
	HostStateGreen = "green"
	// HostStateYellow - Host is under load
	HostStateYellow = "yellow"
	// HostStateRed - Host is not healthy
	HostStateRed = "red"
	// HostStateUnknown - Host state is not known
	HostStateUnknown = ""
)

// EndPointHostMod - Info related to an end-point host entry
type EndPointHostMod struct {
	// HostName - hostname in CIDR
	HostName string `json:"hostName"`
	// EPPort - The end-point port (0 if not applicable)
	EPPort uint16 `json:"epPort"`
	// EPProto - The end-point prototype (empty if not applicable)
	EPProto string `json:"epProto"`
	//  State - Host state string
	State string `json:"state"`
}

// EpSelect - Selection method of load-balancer end-point
type EpSelect uint

const (
	// LbSelRr - select the lb end-points based on round-robin
	LbSelRr EpSelect = iota
	// LbSelHash - select the lb end-points based on hashing
	LbSelHash
	// LbSelPrio - select the lb based on weighted round-robin
	LbSelPrio
	// LbSelRrPersist - persist connections from same client
	LbSelRrPersist
	// LbSelLeastConnections - select client based on least connections
	LbSelLeastConnections
	// LbSelN2 - select client based on N2 SCTP interface
	LbSelN2
	// LbSelN3 - select client based on N3 interface
	LbSelN3
	_ // 7 - reserved (was QUIC selection)
	// LbSelCHWBL - Consistent Hash with Bounded Loads (for FullProxy mode)
	LbSelCHWBL
	// LbSelGPUAware - GPU-aware load balancing (for LLM workloads)
	LbSelGPUAware
	// LbSelWRRHash - Weighted Consistent Hash with Bounded Loads (P3.5)
	LbSelWRRHash
)

// LBMode - Variable to define LB mode
type LBMode int32

const (
	// LBModeDefault - Default Mode(DNAT)
	LBModeDefault LBMode = iota
	// LBModeOneArm - One Arm Mode
	LBModeOneArm
	// LBModeFullNAT - Full NAT Mode
	LBModeFullNAT
	// LBModeDSR - DSR Mode
	LBModeDSR
	// LBModeFullProxy
	LBModeFullProxy
	// LBModeHostOneArm
	LBModeHostOneArm
)

// LBOp - Variable to LB operation
type LBOp int32

const (
	// LBOPAdd - Add the LB rule (replace if existing)
	LBOPAdd LBOp = iota
	// LBOPAttach - Attach End-Points
	LBOPAttach
	// LBOPDetach - Detach End-Points
	LBOPDetach
)

// LBSec - Variable to define LB front-end security
type LBSec int32

const (
	// LBServPlain - Plain mode
	LBServPlain LBSec = iota
	// LBServHTTPS - HTTPS termination
	LBServHTTPS
	// LBServE2EHTTPS - HTTPS proxy
	LBServE2EHTTPS
)

// MTLSFrontendConfig - Client certificate verification configuration
type MTLSFrontendConfig struct {
	// ClientCertMode - Client certificate requirement level
	// "disabled" = No client cert verification (default)
	// "optional" = Accept connections with or without client cert
	// "required" = Reject connections without valid client cert
	ClientCertMode string `json:"client_cert_mode"`

	// ClientCAPath - Path to client CA certificate bundle (PEM format)
	// Example: "/opt/loxilb/cert/client_ca_bundle.crt"
	ClientCAPath string `json:"client_ca_path,omitempty"`

	// ClientCACertData - Inline CA certificate data (base64-encoded PEM)
	// Alternative to ClientCAPath for Kubernetes secrets or dynamic config
	// If both are provided, ClientCAPath takes precedence
	ClientCACertData string `json:"client_ca_cert_data,omitempty"`

	// RequireClientCN - Require specific CN pattern in client certificate
	// Provides additional security by restricting accepted certificates
	RequireClientCN bool `json:"require_client_cn,omitempty"`

	// ClientCNPattern - Required CN pattern (e.g., "*.corp.example.com")
	// Supports wildcard matching (*, ?)
	// Only used if RequireClientCN is true
	ClientCNPattern string `json:"client_cn_pattern,omitempty"`

	// ClientCRLPath - (08): operator-supplied static CRL file (PEM) loaded into
	// the verify X509_STORE with leaf-only X509_V_FLAG_CRL_CHECK. A revoked client LEAF cert is
	// rejected; a valid one passes. Empty ⇒ no CRL (today's behaviour). This is the explicit
	// drop-in replacement for 77-04's convention-derived sibling crl.pem (mtls_derive_crl_path).
	ClientCRLPath string `json:"client_crl_path,omitempty"`
}

// MTLSBackendConfig - Backend server certificate verification + client cert
type MTLSBackendConfig struct {
	// VerifyServerCert - Enable backend server certificate verification
	// true = verify backend server cert (SSL_VERIFY_PEER)
	// false = skip verification (SSL_VERIFY_NONE, default for backward compatibility)
	VerifyServerCert bool `json:"verify_server_cert"`

	// BackendCAPath - Path to backend CA bundle (PEM format)
	// Empty = use system CA store (etc/ssl/certs)
	// Example: "/opt/loxilb/cert/backend_ca_bundle.crt"
	BackendCAPath string `json:"backend_ca_path,omitempty"`

	// ClientCertPath - Path to loxilb's client certificate for backend mTLS
	// Example: "/opt/loxilb/cert/loxilb_client.crt"
	ClientCertPath string `json:"client_cert_path,omitempty"`

	// ClientKeyPath - Path to loxilb's private key for backend mTLS
	// Example: "/opt/loxilb/cert/loxilb_client.key"
	ClientKeyPath string `json:"client_key_path,omitempty"`

	// ClientCertData - Inline client certificate (base64-encoded PEM)
	// Alternative to ClientCertPath
	ClientCertData string `json:"client_cert_data,omitempty"`

	// ClientKeyData - Inline client key (base64-encoded PEM)
	// Alternative to ClientKeyPath
	ClientKeyData string `json:"client_key_data,omitempty"`
}

// CertArg - (11/12/13/16): the canonical TLS-material handle.
// An opaque short certId plus the inline PEM material (cert + key [+ chain]). The
// hostnames are AUTO-DERIVED from the leaf cert SAN-DNS (CN fallback) on upload
// — the operator never supplies them; they are populated on GET round-trip
// only. The handler persists the inline PEM to PROXY_SSL_CERTID_DIR/<certId>/ (0700 dir,
// 0600 key —) and drives the 77-02 C registry (proxy_register_cert /
// proxy_rotate_cert / proxy_delete_cert). certId is purely the upload/rotate/delete
// handle; the SNI selection path stays keyed by hostname.
type CertArg struct {
	// CertId - opaque management handle (<= CERTID_MAX-1 chars). Client-supplied verbatim;
	// when absent on POST the handler mints one. Stable across rotation.
	CertId string `json:"certId"`
	// CertPEM - the leaf (server) certificate in PEM. REQUIRED on POST/PUT.
	CertPEM string `json:"certPem"`
	// KeyPEM - the private key in PEM. REQUIRED on POST/PUT. Persisted 0600.
	KeyPEM string `json:"keyPem"`
	// ChainPEM - optional intermediate-chain PEM appended after the leaf.
	ChainPEM string `json:"chainPem,omitempty"`
	// Hostnames - SAN-DNS/CN auto-derived hostnames the certId registered into the SNI
	// store. Output-only — populated on GET, ignored on POST/PUT.
	Hostnames []string `json:"hostnames,omitempty"`
}

// LbServiceArg - Information related to load-balancer service
type LbServiceArg struct {
	// ServIP - the service ip or vip  of the load-balancer rule
	ServIP string `json:"externalIP"`
	// PrivateIP - the private service ip or vip of the load-balancer rule
	PrivateIP string `json:"privateIP"`
	// ServPort - the min service port of the load-balancer rule
	ServPort uint16 `json:"port"`
	// ServPortMax - the max service port of the load-balancer rule
	ServPortMax uint16 `json:"portMax"`
	// Proto - the service protocol of the load-balancer rule
	Proto string `json:"protocol"`
	// BlockNum - An arbitrary block num to further segregate a service
	BlockNum uint32 `json:"block"`
	// Sel - one of LbSelRr,LbSelHash, or LbSelHash
	Sel EpSelect `json:"sel"`
	// Bgp - export this rule with goBGP
	Bgp bool `json:"bgp"`
	// Monitor - monitor end-points of this rule
	Monitor bool `json:"monitor"`
	// Oper - Attach/Detach if the LB already exists
	Oper LBOp `json:"oper"`
	// Security - Security mode if any
	Security LBSec `json:"lbsec"`
	// Mode - NAT mode
	Mode LBMode `json:"mode"`
	// InactiveTimeout - Forced session reset after inactive timeout
	InactiveTimeout uint32 `json:"inactiveTimeout"`
	// Managed - This rule is managed by external entity e.g k8s
	Managed bool `json:"managed"`
	// ProbeType - Liveness check type for this rule : ping, tcp, udp, sctp, none, http(s)
	ProbeType string `json:"probetype"`
	// ProbePort - Liveness check port number. Only valid for tcp, udp, sctp, http(s)
	ProbePort uint16 `json:"probeport"`
	// ProbeReq - Request string for liveness check
	ProbeReq string `json:"probereq"`
	// ProbeResp - Response string for liveness check
	ProbeResp string `json:"proberesp"`
	// ProbeTimeout - Probe Timeout
	ProbeTimeout uint32 `json:"probeTimeout"`
	// ProbeRetries - Probe Retries
	ProbeRetries int `json:"probeRetries"`
	// Name - Service name
	Name string `json:"name"`
	// PersistTimeout - Persistence timeout in seconds
	PersistTimeout uint32 `json:"persistTimeout"`
	// Snat - Do SNAT
	Snat bool `json:"snat"`
	// HostUrl - Ingress Specific URL path
	HostUrl string `json:"path"`
	// PathPrefix - URL path prefix for L7 routing (P6)
	PathPrefix string `json:"path_prefix,omitempty"`
	// PathMatchMode - Path matching mode: disabled, prefix, exact (P6)
	PathMatchMode string `json:"path_match_mode,omitempty"`
	// ProxyProtocolV2 - Enable proxy protocol v2
	ProxyProtocolV2 bool `json:"proxyprotocolv2"`
	// Egress - Egress Rule
	Egress bool `json:"egress"`
	// Id - Stable opaque identifier for the LB rule (Octavia).
	// Client-supplied (e.g. the Octavia driver's loadbalancer UUID) is stored verbatim;
	// when absent a UUIDv4 is minted control-plane side. Persisted to lbconfig.txt so the
	// id->rule index rebuilds on restart. Optional/omitempty for back-compat.
	Id string `json:"id,omitempty"`
	// AdminStateUp - Octavia admin_state_up lifecycle flag. POINTER on purpose for
	// back-compat: Octavia's admin_state_up defaults to true (enabled), so nil/absent (a
	// legacy lbconfig.txt entry or a POST that omits the field) MUST resolve to enabled,
	// never paused. Only an explicit false pauses the rule. nil also makes
	// merge-patch presence detection natural (nil = "not in body"). Dedicated field —
	// NEVER reuse Managed.
	AdminStateUp *bool `json:"adminStateUp,omitempty"`
	// ProjectId - Octavia tenant/project identifier. First-class
	// typed AND indexed field (NOT folded into Annotations) because the
	// GET /config/loadbalancer/all?projectId={id} filter needs an efficient queryable
	// lookup. Opaque tenant string: stored verbatim, persisted to lbconfig.txt, echoed
	// on GET, filtered on /all. NOT a tenant-isolation/authz boundary — a rule with a
	// non-matching projectId is still visible to an unfiltered GET (Octavia RBAC stays
	// driver-side). Optional/omitempty for back-compat. NEVER interpreted at the dataplane.
	ProjectId string `json:"projectId,omitempty"`
	// Annotations - General opaque key/value map that round-trips
	// octaviaProtocol and any future Octavia field verbatim. Store-as-given, return-as-
	// stored; loxilb NEVER interprets it. Persisted to lbconfig.txt. Optional/omitempty
	// for back-compat. Input bounds (key count / value length) applied in AddLbRule
	// validation to prevent unbounded-storage DoS (T-73-DOS).
	Annotations map[string]string `json:"annotations,omitempty"`
	// ConnectionLimit - Octavia listener/pool concurrent-connection ceiling.
	// Per-SERVICE (per-rule) max number of simultaneous connections across ALL the rule's
	// endpoints. 0 (or absent) = unlimited (legacy behavior). Additive omitempty (same discipline
	// as Id/ProjectId), persisted to lbconfig.txt so the limit survives restart. Enforced in the
	// eBPF data plane: when the rule's live concurrent count >= ConnectionLimit the SYN is refused
	// via the sel=-1 -> pm.nf=0 no-EP drop path (no CT created), and a slot frees on teardown
	// (05). This Octavia per-rule ceiling is DISTINCT from the SecurityRate per-SOURCE-IP
	// limiters (P0-5/P0-6/P0-7) — do NOT conflate. NOT per-EP. Bounded to uint32 at ingest.
	ConnectionLimit uint32 `json:"connectionLimit,omitempty"`
	// MustExist - Octavia PATCH must-exist semantics. When true, AddLbRule
	// refuses to CREATE an absent rule and returns the RuleNotExistsErr sentinel so the
	// PATCH handler can map it to 404. POST callers leave this false (default), preserving
	// the forgiving create-or-update upsert behavior. In-memory only (json:"-"): it is a
	// per-request control flag, never persisted to lbconfig.txt.
	MustExist bool `json:"-"`
	// ActiveConns - Octavia live concurrent-connection count for the rule,
	// surfaced from the control-plane ruleEnt.activeConns on the GET read path so the stats
	// endpoint reports the SAME selector-agnostic live count the connectionLimit gate enforces
	// (NOT the LC-only active_sess[]). Transient (json:"-"): recomputed each RulesSync from the
	// CT walk, in-memory only, reset to zero on restart. Populated by GetNatLbRule.
	ActiveConns uint64 `json:"-"`
	// TotalConns - Octavia monotonic cumulative connection count (++ on
	// first-seen CT for the rule, never decremented). The only genuinely new counter. Transient
	// (json:"-"): in-memory only, reset to zero on restart (mirrors LastUpdated). Populated by
	// GetNatLbRule from ruleEnt.totalConns.
	TotalConns uint64 `json:"-"`
	// BytesIn - Octavia (a) real per-direction byte total for the forward
	// CT_DIR_IN (client->VIP request) entries of the rule. Transient (json:"-"): recomputed each
	// RulesSync from the CT walk, in-memory, reset on restart. NOT a 50/50 heuristic and NOT the
	// direction-collapsed nat_stats_map. Populated by GetNatLbRule from ruleEnt.bytesIn.
	BytesIn uint64 `json:"-"`
	// BytesOut - Octavia (a) real per-direction byte total for the reverse
	// CT_DIR_OUT (VIP->client response) entries of the rule. Transient (json:"-"): in-memory,
	// reset on restart. Populated by GetNatLbRule from ruleEnt.bytesOut.
	BytesOut uint64 `json:"-"`
	// LastUpdated - Octavia in-memory monotonic last-mutation timestamp,
	// surfaced from the control-plane ruleEnt.lastUpdated on the GET read path so the
	// status endpoint reflects the ACTUAL last mutation (not the request time). Transient
	// and json:"-": it is NEVER serialized to lbconfig.txt (keeps lastUpdated in
	// memory only, reset-to-now on restart). Populated by GetNatLbRule from data.lastUpdated.
	LastUpdated time.Time `json:"-"`
	// TraceType - Tracing catalog name for deep inspection (e.g., "v1", "anthropic", "default")
	// Optional: If not specified, no deep inspection.
	TraceType string `json:"trace_type,omitempty"`
	// BackendProtocol - Backend protocol capability for ALPN negotiation
	// "http1" = HTTP/1.1 only (default), "http2" = HTTP/2 only, "both" = supports both
	// Optional: Defaults to "http1" for backward compatibility
	BackendProtocol string `json:"backend_protocol,omitempty"`
	// SessionHeaderName - Custom session header for persist mode (sel=3)
	// e.g., "mcp-session-id", "x-session-token", "authorization"
	// If empty and sel=3, falls back to IP-based persistence
	SessionHeaderName string `json:"session_header_name,omitempty"`
	// ModelName - LB endpoint pool selection key for AI model routing
	// e.g. "llama-70b", "mistral-7b"; empty = wildcard pool (backward compatible)
	ModelName string `json:"model_name,omitempty"`
	// SSEMode - Enable SSE (Server-Sent Events) streaming mode for this rule.
	// When enabled, idle-timeout is suppressed while a streaming LLM response is active.
	SSEMode bool `json:"sse_mode,omitempty"`
	// ApiKeyAuth - data-plane X-Api-Key enforcement policy for this service.
	// "disabled" (default) admits without a key; "required" enforces.
	// Independent of the management-plane authentication mode, and independent
	// of sse_mode and pd_disagg_mode: an unset value resolves to "disabled" on
	// every rule, with no reference to how the service streams.
	ApiKeyAuth string `json:"api_key_auth,omitempty"`
	// MaxStreamDurationSec - Absolute wall-clock cap for SSE streams in seconds.
	// 0 = use system hard cap (PROXY_SSE_HARD_CAP_SEC = 86400s / 24h).
	MaxStreamDurationSec uint32 `json:"max_stream_duration_sec,omitempty"`
	// BackendKeepaliveIntervalSec - Sets SO_KEEPALIVE + TCP_KEEPIDLE on backend socket.
	// Keeps TCP CT entries alive through cloud NAT. 0 = disabled.
	BackendKeepaliveIntervalSec uint32 `json:"backend_keepalive_interval_sec,omitempty"`
	// PDDisaggMode - Enable prefill/decode disaggregation for vLLM P/D serving
	// Requires mode=FullProxy(4) and backend_protocol=http1. Endpoints must have ep_role set.
	PDDisaggMode bool `json:"pd_disagg_mode,omitempty"`
	// PDCacheAwareMode - Enable P/D cache-aware routing (session + trie + min-load)
	// Requires PDDisaggMode=true. When false (default), P/D uses basic first-healthy selection.
	PDCacheAwareMode bool `json:"pd_cache_aware_mode,omitempty"`
	// PDSessionTTLSec - Session stickiness TTL in seconds for P/D cache-aware routing. 0 = no expiry.
	PDSessionTTLSec uint32 `json:"pd_session_ttl_sec,omitempty"`
	// PDCacheThreshold - Cache match threshold (0-100, default 20)
	PDCacheThreshold uint8 `json:"pd_cache_threshold,omitempty"`
	// PDBalanceAbsThreshold - Load imbalance threshold (default 3)
	PDBalanceAbsThreshold uint8 `json:"pd_balance_abs_threshold,omitempty"`
	// CbEnable - Enable the per-endpoint circuit breaker for full-proxy rules.
	// After 5 consecutive backend connect failures an endpoint is skipped by all
	// selection paths until a 30s open-timeout expires and a half-open probe
	// succeeds. Complements (does not replace) the liveness prober: the breaker
	// reacts within one failed request, the prober within one probe interval.
	CbEnable bool `json:"cb_enable,omitempty"`

	// KV-Cache Exact Routing configuration
	// KvExactMode - KV-cache exact routing mode: 0=off, 1=zmq
	KvExactMode uint8 `json:"kvExactMode,omitempty"`
	// KvBlockSize - Token block size for KV hash computation (default 16)
	KvBlockSize uint32 `json:"kvBlockSize,omitempty"`
	// KvHashAlgo - Hash algorithm for KV block matching: "sha256_cbor" or "xxhash_cbor"
	KvHashAlgo string `json:"kvHashAlgo,omitempty"`
	// KvZmqPort - ZMQ PUB socket port on vLLM prefill endpoints (default 5557)
	KvZmqPort uint16 `json:"kvZmqPort,omitempty"`
	// KvWarmupSec - Seconds to wait after ZMQ connect before activating Tier 1.5 (default 30)
	KvWarmupSec uint32 `json:"kvWarmupSec,omitempty"`
	// KvEngineType - KV-event engine behind this rule: "vllm" (default, ""≡"vllm") or "sglang".
	// One framework per VIP; immutable after create (delete+recreate to change).
	// Drives the hash-algo default: sglang ⇒ sha256_sglang when KvHashAlgo is unset.
	KvEngineType string `json:"kvEngineType,omitempty"`
	// PDBootstrapPort - SGLang disaggregation bootstrap port on every prefill EP
	// (0 ⇒ SGLang's default 8998). Only meaningful with PDDisaggMode=true and
	// KvEngineType="sglang"; rejected on any other rule shape.
	PDBootstrapPort uint16 `json:"pdBootstrapPort,omitempty"`
	// KvDpRankCount - SGLang data-parallel rank count (18, 0 ⇒ default 1).
	// Rank N publishes KV events at KvZmqPort+N; all ranks union into one per-EP inventory.
	KvDpRankCount uint16 `json:"kvDpRankCount,omitempty"`
	// KvExactApiMode - request API surfaces this KV-exact rule serves:
	// "completions", "chat" or "both". Absent ("") on a profile-less rule
	// keeps the legacy behavior (both surfaces, unattested); with a bound
	// model profile the effective surface set defaults to the profile's
	// declared supportedApis and an explicit value must be a subset of them.
	// Declaring a chat surface requires a validated chat renderer for the
	// rule's model — an unsupported chat declaration is refused at create
	// time, never degraded into a silent runtime fallback.
	// Immutable on a live rule (delete+recreate to change).
	KvExactApiMode string `json:"kvExactApiMode,omitempty"`
	// KvModelProfile - ID of the ModelPromptProfile this rule binds to.
	// Naming a profile makes the rule STRICT: the profile must be published,
	// its alias policy must admit the rule's model_name, its tokenizer
	// artifacts must load and digest-match, and a composed KV-exact binding
	// (profile@generation + engine-contract@generation) is allocated at
	// create time. Empty = legacy profile-less rule (no binding, documented
	// migration behavior). Immutable on a live rule (delete+recreate).
	KvModelProfile string `json:"kvModelProfile,omitempty"`
	// RestoreReplay - set by the snapshot engine when this rule add is a
	// restore replay rather than a fresh POST. A replayed strict rule must
	// NOT allocate a new KV-exact binding generation: the snapshot's
	// kvexactbinding domain applies right after the loadbalancer domain and
	// carries the authoritative binding (including the allocation high-water
	// mark that prevents generation reuse). In-memory only (json:"-").
	RestoreReplay bool `json:"-"`

	// CHWBL-specific configuration (only used when Sel=LbSelCHWBL)
	// CHWBLPrefixHashLevel - Prefix hash level for CHWBL: 1=Level1, 2=Level1+2, 3=Level1+2+3
	CHWBLPrefixHashLevel int `json:"chwbl_prefix_hash_level,omitempty"`
	// CHWBLPrefixHashFlags - Optional field inclusion bitfield (0=auto-detect)
	CHWBLPrefixHashFlags int `json:"chwbl_prefix_hash_flags,omitempty"`
	// CHWBLMeanLoadFactor - Max load factor percentage (100-300, default 125)
	CHWBLMeanLoadFactor int `json:"chwbl_mean_load_factor,omitempty"`
	// CHWBLReplication - Virtual nodes per endpoint (1-1024, default 100)
	CHWBLReplication int `json:"chwbl_replication,omitempty"`
	// CHWBLEnableCacheSalt - Require cache_salt field for multi-tenant isolation
	CHWBLEnableCacheSalt bool `json:"chwbl_enable_cache_salt,omitempty"`

	// MTLSFrontend - Frontend mTLS configuration (optional)
	// Enables client certificate verification
	// Only valid with Security=LBServHTTPS or LBServE2EHTTPS and Mode=LBModeFullProxy
	MTLSFrontend *MTLSFrontendConfig `json:"mtls_frontend,omitempty"`

	// MTLSBackend - Backend mTLS configuration (optional)
	// Enables backend server cert verification and/or client cert presentation
	// Only valid with Security=LBServE2EHTTPS and Mode=LBModeFullProxy
	MTLSBackend *MTLSBackendConfig `json:"mtls_backend,omitempty"`

	// per-listener member timeouts in MILLISECONDS (Octavia native unit).
	// All additive + optional (omitempty) — 0/absent ⇒ preserve today's hardcoded behaviour:
	// connect default 500ms (NOT Octavia's 5000ms —). Enforced only on the L7_Proxy peer
	// (has_l7_policy==1) in the sockproxy data plane (Plans 06/07); plumbed via proxy_arg.
	// TimeoutMemberConnect - backend connect-poll deadline (ms); 0 ⇒ 500
	TimeoutMemberConnect uint32 `json:"timeoutMemberConnect,omitempty"`
	// TimeoutMemberData - member-side relay idle timeout (ms); 0 ⇒ existing client-idle value
	TimeoutMemberData uint32 `json:"timeoutMemberData,omitempty"`
	// TimeoutTcpInspect - header-accumulation deadline (ms). NO Gateway-API equivalent —
	// Octavia-only; a future Gateway controller MUST hard-error, never silent-drop.
	TimeoutTcpInspect uint32 `json:"timeoutTcpInspect,omitempty"`
	// VipQosPolicyId - : references an EXISTING loxilb policy ident (pre-created
	// by the external Octavia driver via /config/policy). On LB-create, when non-empty, loxilb
	// ASSOCIATES that policy to the VIP rule reusing policer association
	// (GetLBRuleMarkByKey / PolAttachLbRule). loxilb adds only the reference field — the driver
	// owns the Neutron-QoS→loxilb-policy translation (separate-repos boundary). Additive +
	// optional (omitempty): empty/absent ⇒ rule unchanged, round-trips byte-identical
	// An UNRESOLVABLE ident surfaces an error (no silent-drop).
	VipQosPolicyId string `json:"vip_qos_policy_id,omitempty"`

	// ----------------------------------------------------------------------------
	// TLS-hardening additive fields. All optional + omitempty,
	// default-off: empty/nil/0 ⇒ today's behaviour, round-trips byte-identical when unset
	//. Threaded to the proxy_arg scalars 77-02 added via the CGO export in
	// dpebpf_linux.go (enforced only on the L7_Proxy peer; the AI peer is unchanged).
	// ----------------------------------------------------------------------------

	// AlpnProtocols - : Octavia alpn_protocols list. Mapped to the EXISTING
	// backend_protocol_cap enum: [h2,http/1.1]⇒2, [h2]⇒1, [http/1.1]⇒0. Empty ⇒ today's
	// BackendProtocol-driven value (no override). Advertised on listener + pool.
	AlpnProtocols []string `json:"alpn_protocols,omitempty"`
	// TlsCiphers - : OpenSSL cipher string, passed to BOTH SSL_CTX_set_cipher_list
	// (TLS1.2) and SSL_CTX_set_ciphersuites (TLS1.3). Empty ⇒ today's hardcoded ciphers.
	TlsCiphers string `json:"tls_ciphers,omitempty"`
	// TlsVersions - : Octavia tls_versions list (e.g. ["TLSv1.2","TLSv1.3"]).
	// Collapsed to a min..max range driving tls_version_min/max. Empty ⇒ today's TLS1.2..1.3.
	TlsVersions []string `json:"tls_versions,omitempty"`
	// HstsMaxAge - : Strict-Transport-Security max-age. 0 ⇒ no HSTS injection.
	HstsMaxAge uint32 `json:"hsts_max_age,omitempty"`
	// HstsIncludeSubdomains - : append "; includeSubDomains" when true.
	HstsIncludeSubdomains bool `json:"hsts_include_subdomains,omitempty"`
	// HstsPreload - : append "; preload" when true.
	HstsPreload bool `json:"hsts_preload,omitempty"`
	// BackendCaCertId - (16): certId of the backend re-encryption CA bundle
	// (resolved to managed-dir ca.crt at backend SSL_CTX build). Empty ⇒ system default.
	BackendCaCertId string `json:"backend_ca_cert_id,omitempty"`
	// BackendClientCertId - (16): certId of loxilb's backend client cert+key.
	// Empty ⇒ no backend client cert (today's behaviour).
	BackendClientCertId string `json:"backend_client_cert_id,omitempty"`
}

// LbEndPointArg - Information related to load-balancer end-point
type LbEndPointArg struct {
	// EpIP - endpoint IP address
	EpIP string `json:"endpointIP"`
	// EpPort - endpoint Port
	EpPort uint16 `json:"targetPort"`
	// Weight - weight associated with end-point
	// Only valid for weighted round-robin selection
	Weight uint8 `json:"weight"`
	// EpRole - P/D endpoint role: 0=normal (default), 1=prefill, 2=decode
	EpRole int `json:"ep_role,omitempty"`
	// NixlPort - NIXL side-channel port for KV cache transfer; 0=use targetPort
	NixlPort uint16 `json:"nixl_port,omitempty"`
	// Backup - Octavia standby member flag. A backup endpoint carries
	// traffic ONLY when all primary endpoints are effectively unavailable, and auto-
	// deactivates the instant any primary recovers. Additive omitempty: absent ⇒
	// backup=false ⇒ a primary (today's behavior, no standby tier). wires the
	// dataplane selection semantics; declared here so the struct is complete.
	Backup bool `json:"backup,omitempty"`
	// SubnetId - Octavia member subnet identifier. Additive omitempty
	// round-trip field: stored verbatim, returned as stored, NOT interpreted (no routing
	// effect this phase). Optional for back-compat.
	SubnetId string `json:"subnetId,omitempty"`
	// MonitorAddress - Octavia per-member health-probe address. When
	// set, the health probe targets this address (with the existing probePort/monitorPort)
	// instead of the traffic IP; when absent, probe falls back to the traffic IP. Additive
	// omitempty. wires the prober override; declared here so the struct is complete.
	MonitorAddress string `json:"monitorAddress,omitempty"`
	// State - current state of the end-point
	State string `json:"state"`
	// Counters -  traffic counters of the end-point
	Counters string `json:"counters"`
}

// ============================================================================
// L7 content-routing policy.
//
// A dedicated L7_POLICY resource (policy + ordered child rules) attached to an
// existing L4 load-balancer by its stable opaque id. The model
// types below mirror the swagger L7Policy/L7Rule/L7Condition/L7Action shape and
// are the translation-neutral SUPERSET of OpenStack Octavia l7policy/l7rule AND
// the Kubernetes Gateway API HTTPRoute. They are additive omitempty; the L7 API
// is unreleased so there is NO backward-compat debt to carry.
//
// The handler validates these server-side (Octavia per-type rules), translates
// them to the L7RouteArg IR carried across the CGO boundary to the running
// sockproxy via a SEPARATE proxy_attach_l7_policy call (NEVER inline on the
// 4096-byte proxy_arg —).
// ============================================================================

// L7ConditionArg - one predicate, AND-combined within a match set.
type L7ConditionArg struct {
	// Field - one of HOST/PATH/HEADER/COOKIE/FILE_TYPE/METHOD/QUERY. The SSL_*
	// field range is reserved rejected here.
	Field string `json:"field,omitempty"`
	// Op - one of EQUAL_TO/STARTS_WITH/SEGMENT_PREFIX/ENDS_WITH/CONTAINS/REGEX.
	Op string `json:"op,omitempty"`
	// Key - header/cookie/query NAME; required for HEADER/COOKIE/QUERY.
	Key string `json:"key,omitempty"`
	// Value - operand the request field is compared against.
	Value string `json:"value,omitempty"`
	// Invert - negate this condition's result (Octavia-only; HARD ERROR on Gateway export).
	Invert bool `json:"invert,omitempty"`
}

// L7MatchSetArg - a set of AND-combined conditions (OR across sets at the route).
type L7MatchSetArg struct {
	Conditions []L7ConditionArg `json:"conditions,omitempty"`
}

// L7BackendRefArg - a weighted FORWARD backend (Gateway weighted backendRefs).
type L7BackendRefArg struct {
	Ep     uint32 `json:"ep,omitempty"`
	Weight int    `json:"weight,omitempty"`
}

// L7ForwardArg - FORWARD action target (re-enters the existing intra-pool EP-select).
type L7ForwardArg struct {
	PoolId      uint32            `json:"poolId,omitempty"`
	BackendRefs []L7BackendRefArg `json:"backendRefs,omitempty"`
}

// L7RedirectArg - REDIRECT action target. StatusCode restricted to {301,302,303,307,308} (default 302).
type L7RedirectArg struct {
	Scheme     string `json:"scheme,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	PathOp     string `json:"pathOp,omitempty"`
	Value      string `json:"value,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
}

// L7RejectArg - REJECT action target. StatusCode defaults to 403.
type L7RejectArg struct {
	StatusCode int `json:"statusCode,omitempty"`
}

// L7ActionArg - the single tagged-union action for a route.
type L7ActionArg struct {
	// Kind - FORWARD/REDIRECT/REJECT. REJECT is a HARD ERROR on Gateway export.
	Kind     string         `json:"kind,omitempty"`
	Forward  *L7ForwardArg  `json:"forward,omitempty"`
	Redirect *L7RedirectArg `json:"redirect,omitempty"`
	Reject   *L7RejectArg   `json:"reject,omitempty"`
}

// L7HeaderFilterArg - one request-header insertion op. A tagged
// op {SET|ADD|REMOVE} + name(+value) — a faithful superset of BOTH Octavia insert_headers
// (SET/ADD) AND Gateway API RequestHeaderModifier (set/add/remove). Additive/optional.
// Maps to the C l7_hdr_filter_t on l7_route_t; the data-plane engine is Plans 06/07.
type L7HeaderFilterArg struct {
	// Op - one of SET/ADD/REMOVE.
	Op string `json:"op,omitempty"`
	// Name - header name (required).
	Name string `json:"name,omitempty"`
	// Value - header value (ignored for REMOVE).
	Value string `json:"value,omitempty"`
}

// L7RuleArg - one ordered L7 route: explicit position + OR-of-AND match sets + one action.
type L7RuleArg struct {
	// Position - explicit precedence; routes evaluated ascending, FIRST-MATCH-WINS.
	Position int `json:"position,omitempty"`
	// MatchSets - OR across sets; AND within a set.
	MatchSets []L7MatchSetArg `json:"matchSets,omitempty"`
	// Action - the tagged-union action.
	Action L7ActionArg `json:"action,omitempty"`
	// InsertHeaders - bounded SET/ADD/REMOVE request-header filter list.
	// Additive/optional — empty ⇒ no header insertion. Bounded at ingest (Plans 06/07) to the
	// C-side L7_MAX_HDR_FILTERS (DoS bound).
	InsertHeaders []L7HeaderFilterArg `json:"insertHeaders,omitempty"`
	// SessionPersistence - session-persistence mode for this route.
	// "HTTP_COOKIE" enables LB-generated Set-Cookie + read-back affinity; empty ⇒ off. Mutually
	// exclusive with APP_COOKIE/SOURCE_IP per pool (Octavia semantics). Maps to cookie_persist.
	SessionPersistence string `json:"sessionPersistence,omitempty"`
}

// L7PolicyArg - a dedicated L7_POLICY resource attached to an L4 LB by its stable
// opaque id. CRUD'd independently of the LB.
type L7PolicyArg struct {
	// Id - stable opaque identifier for this policy (minted control-plane side if absent).
	Id string `json:"id,omitempty"`
	// Name - human-readable policy name.
	Name string `json:"name,omitempty"`
	// LbId - the stable opaque id of the L4 load-balancer this policy attaches to.
	LbId string `json:"lbId,omitempty"`
	// Rules - the ordered L7 routes (FIRST-MATCH-WINS by ascending position).
	Rules []L7RuleArg `json:"rules,omitempty"`
}

// LbSecIPArg - Secondary IP
type LbSecIPArg struct {
	// SecIP - Secondary IP address
	SecIP string `json:"secondaryIP"`
}

// LbSecVIPArg - Structured secondary VIP (Octavia additional_vips).
// Added ALONGSIDE the flat LbSecIPArg (which stays unchanged for back-compat). Stored and
// round-tripped for ALL protocols (data-model fidelity), even though SCTP
// multi-homing remains the only protocol that consumes secondary VIPs at the dataplane.
// All fields are opaque store-verbatim strings; NEVER interpreted at the dataplane.
type LbSecVIPArg struct {
	// Address - secondary VIP address
	Address string `json:"address,omitempty"`
	// SubnetId - opaque Octavia subnet identifier for this VIP (round-trip only)
	SubnetId string `json:"subnetId,omitempty"`
	// PortId - opaque Octavia port identifier for this VIP (round-trip only)
	PortId string `json:"portId,omitempty"`
	// Proto - opaque protocol hint for this VIP (round-trip only)
	Proto string `json:"proto,omitempty"`
}

// LbAllowedSrcIPArg - Allowed Src IPs
type LbAllowedSrcIPArg struct {
	// Prefix - Allowed Prefix
	Prefix string `json:"prefix"`
}

// LbRuleMod - Info related to a load-balancer entry
type LbRuleMod struct {
	// Serv - service argument of type LbServiceArg
	Serv LbServiceArg `json:"serviceArguments"`
	// SecIPs - Secondary IPs for SCTP multi-homed service
	SecIPs []LbSecIPArg `json:"secondaryIPs"`
	// SecVIPs - Structured secondary VIPs (Octavia additional_vips).
	// Additive ALONGSIDE the flat SecIPs (kept unchanged). Stored and round-tripped for
	// all protocols; round-trip uncapped for fidelity, only ≤3 consumed by SCTP.
	SecVIPs []LbSecVIPArg `json:"secondaryVIPs,omitempty"`
	// SrcIPs - Allowed Source IPs
	SrcIPs []LbAllowedSrcIPArg `json:"allowedSources"`
	// Eps - slice containing LbEndPointArg
	Eps []LbEndPointArg `json:"endpoints"`
}

// CtInfo - Conntrack Information
type CtInfo struct {
	// Dip - destination ip address
	Dip net.IP `json:"destinationIP"`
	// Sip - source ip address
	Sip net.IP `json:"sourceIP"`
	// Dport - destination port information
	Dport uint16 `json:"destinationPort"`
	// Sport - source port information
	Sport uint16 `json:"sourcePort"`
	// Proto - IP protocol information
	Proto string `json:"protocol"`
	// Ident - Identity val
	Ident string `json:"ident"`
	// CState - current state of conntrack
	CState string `json:"conntrackState"`
	// CAct - any related action
	CAct string `json:"conntrackAct"`
	// Pkts - packets tracked by ct entry
	Pkts uint64 `json:"packets"`
	// Bytes - bytes tracked by ct entry
	Bytes uint64 `json:"bytes"`
	// ServiceName - Connection's service name
	ServiceName string `json:"servName"`
}

// UlClArg - ulcl argument information
type UlClArg struct {
	// Addr - filter ip addr
	Addr net.IP `json:"ulclIP"`
	// Qfi - qfi id related to this filter
	Qfi uint8 `json:"qfi"`
}

// SessTun - session tunnel(l3) information
type SessTun struct {
	// TeID - tunnel-id
	TeID uint32 `json:"TeID"`
	// Addr - tunnel ip addr of remote-end
	Addr net.IP `json:"tunnelIP"`
}

// ParamMod - Info related to a operational parameters
type ParamMod struct {
	// LogLevel - log level of loxilb
	LogLevel string `json:"logLevel"`
}

// GoBGPGlobalConfig - Info related to goBGP global config
type GoBGPGlobalConfig struct {
	// Local AS number
	LocalAs int64 `json:"localAs,omitempty"`
	// BGP Router ID
	RouterID   string `json:"routerId,omitempty"`
	SetNHSelf  bool   `json:"setNextHopSelf,omitempty"`
	ListenPort uint16 `json:"listenPort,omitempty"`
}

// GoBGPNeighMod - Info related to goBGP neigh
type GoBGPNeighMod struct {
	Addr       net.IP `json:"neighIP"`
	RemoteAS   uint32 `json:"remoteAS"`
	RemotePort uint16 `json:"remotePort"`
	MultiHop   bool   `json:"multiHop"`
}

// GoBGPNeighGetMod - Info related to goBGP neigh
type GoBGPNeighGetMod struct {
	Addr     string `json:"neighIP"`
	RemoteAS uint32 `json:"remoteAS"`
	State    string `json:"state"`
	Uptime   string `json:"uptime"`
	// RemotePort/MultiHop mirror the Add-side GoBGPNeighMod fields so a
	// neighbor's transport config survives a get/re-add round trip
	// (snapshot restore). Additive + omitempty: absent in older payloads,
	// zero values mean "defaults" (port 179, no multihop).
	RemotePort uint16 `json:"remotePort,omitempty"`
	MultiHop   bool   `json:"multiHop,omitempty"`
}

type GoBGPPolicyDefinedSetMod struct {
	Name              string   `json:"name"`
	DefinedTypeString string   `json:"definedTypeString"`
	List              []string `json:"list,omitempty"`
	PrefixList        []Prefix `json:"prefixList,omitempty"`
}

// GoBGPPolicyNeighMod - Info related to goBGP policy about neigh
type GoBGPPolicyNeighMod struct {
	Name             string   `json:"name"`
	NeighborInfoList []string `json:"neighborInfoList"`
}

// GoBGPPolicyCommunityMod - Info related to goBGP policy about neigh
type GoBGPPolicyCommunityMod struct {
	Name          string   `json:"name"`
	CommunityList []string `json:"communityList"`
}

// GoBGPPolicyExtCommunityListMod - Info related to goBGP policy about neigh
type GoBGPPolicyExtCommunityMod struct {
	Name             string   `json:"name"`
	ExtCommunityList []string `json:"extCommunityList"`
}

// GoBGPPolicyAsPAthMod - Info related to goBGP policy about neigh
type GoBGPPolicyAsPathMod struct {
	Name       string   `json:"name"`
	AsPathList []string `json:"asPathList"`
}

// GoBGPPolicyLargeCommunityMod - Info related to goBGP policy about neigh
type GoBGPPolicyLargeCommunityMod struct {
	Name               string   `json:"name"`
	LargeCommunityList []string `json:"largeCommunityList"`
}

// GoBGPPolicyPrefixSetMod - Info related to goBGP Policy prefix
type GoBGPPolicyPrefixSetMod struct {
	Name       string   `json:"name"`
	PrefixList []Prefix `json:"prefixList"`
}

// Prefix - Info related to goBGP Policy Prefix
type Prefix struct {
	IpPrefix        string `json:"ipPrefix"`
	MasklengthRange string `json:"masklengthRange"`
}

// GoBGPPolicyDefineSetMod -
type GoBGPPolicyDefinitionsMod struct {
	Name      string      `json:"name"`
	Statement []Statement `json:"prefixList"`
}

type Statement struct {
	Name       string     `json:"name,omitempty"`
	Conditions Conditions `json:"conditions,omitempty"`
	Actions    Actions    `json:"actions,omitempty"`
}

type Actions struct {
	RouteDisposition string     `json:"routeDisposition"`
	BGPActions       BGPActions `json:"bgpActions,omitempty"`
}

type BGPActions struct {
	SetMed            string           `json:"setMed,omitempty"`
	SetCommunity      SetCommunity     `json:"setCommunity,omitempty"`
	SetExtCommunity   SetCommunity     `json:"setExtCommunity,omitempty"`
	SetLargeCommunity SetCommunity     `json:"setLargeCommunity,omitempty"`
	SetNextHop        string           `json:"setNextHop,omitempty"`
	SetLocalPerf      int              `json:"setLocalPerf,omitempty"`
	SetAsPathPrepend  SetAsPathPrepend `json:"setAsPathPrepend,omitempty"`
}

type SetCommunity struct {
	Options            string   `json:"options,omitempty"`
	SetCommunityMethod []string `json:"setCommunityMethod,omitempty"`
}

type SetAsPathPrepend struct {
	ASN     string `json:"as,omitempty"`
	RepeatN int    `json:"repeatN,omitempty"`
}

type Conditions struct {
	PrefixSet     MatchPrefixSet   `json:"matchPrefixSet,omitempty"`
	NeighborSet   MatchNeighborSet `json:"matchNeighborSet,omitempty"`
	BGPConditions BGPConditions    `json:"bgpconditions"`
}

type MatchNeighborSet struct {
	MatchSetOption string `json:"matchSetOption,omitempty"`
	NeighborSet    string `json:"NeighborSet,omitempty"`
}

type MatchPrefixSet struct {
	MatchSetOption string `json:"matchSetOption,omitempty"`
	PrefixSet      string `json:"prefixSet,omitempty"`
}

type BGPConditions struct {
	AfiSafiIn         []string        `json:"afiSafiIn,omitempty"`
	AsPathSet         BGPAsPathSet    `json:"matchAsPathSet,omitempty"`
	AsPathLength      BGPAsPathLength `json:"asPathLength,omitempty"`
	CommunitySet      BGPCommunitySet `json:"matchCommunitySet,omitempty"`
	ExtCommunitySet   BGPCommunitySet `json:"matchExtCommunitySet,omitempty"`
	LargeCommunitySet BGPCommunitySet `json:"largeCommunitySet,omitempty"`
	RouteType         string          `json:"routeType,omitempty"`
	NextHopInList     []string        `json:"nextHopInList,omitempty"`
	Rpki              string          `json:"rpki,omitempty"`
}

type BGPAsPathLength struct {
	Operator string `json:"Operator,omitempty"`
	Value    int    `json:"Value,omitempty"`
}
type BGPAsPathSet struct {
	AsPathSet       string `json:"asPathSet,omitempty"`
	MatchSetOptions string `json:"matchSetOptions,omitempty"`
}
type BGPCommunitySet struct {
	CommunitySet    string `json:"communitySet,omitempty"`
	MatchSetOptions string `json:"matchSetOptions,omitempty"`
}

type GoBGPPolicyApply struct {
	NeighIPAddress string   `json:"ipAddress,omitempty"`
	PolicyType     string   `json:"policyType,omitempty"`
	Polices        []string `json:"polices,omitempty"`
	RouteAction    string   `json:"routeAction,omitempty"`
}

// Equal - check if two session tunnel entries are equal
func (ut *SessTun) Equal(ut1 *SessTun) bool {
	if ut.TeID == ut1.TeID && ut.Addr.Equal(ut1.Addr) {
		return true
	}
	return false
}

// SessionMod - information related to a user-session
type SessionMod struct {
	// Ident - unique identifier for this session
	Ident string `json:"ident"`
	// IP - ip address of the end-user of this session
	IP net.IP `json:"sessionIP"`
	// AnTun - access tunnel network information
	AnTun SessTun `json:"accessNetworkTunnel"`
	// CnTun - core tunnel network information
	CnTun SessTun `json:"coreNetworkTunnel"`
}

// SessionUlClMod - information related to a ulcl filter
type SessionUlClMod struct {
	// Ident - identifier of the session for this filter
	Ident string `json:"ulclIdent"`
	// Args - ulcl filter information
	Args UlClArg `json:"ulclArgument"`
}

// HASMod - information related to a cluster HA instance
type HASMod struct {
	// Instance - Cluster Instance
	Instance string `json:"instance"`
	// State - current HA state
	State string `json:"haState"`
	// Vip - Instance virtual IP address
	Vip net.IP `json:"Addr"`
}

// BFDMod - information related to a BFD session
type BFDMod struct {
	// Instance - Cluster Instance
	Instance string `json:"instance"`
	// RemoteIP - Remote IP for BFD session
	RemoteIP net.IP `json:"remoteIp"`
	// Interval - Tx Interval between BFD packets
	SourceIP net.IP `json:"sourceIp"`
	// Port - BFD session port
	Port uint16 `json:"port"`
	// Interval - Tx Interval between BFD packets
	Interval uint64 `json:"interval"`
	// RetryCount - Retry Count for detecting failure
	RetryCount uint8 `json:"retryCount"`
	// State - BFD session state
	State string `json:"state"`
}

// ClusterNodeMod - information related to a cluster node instance
type ClusterNodeMod struct {
	// Instance - Cluster Instance
	Addr   net.IP `json:"Addr"`
	Egress bool   `json:"egress"`
}

const (
	// PolTypeTrtcm - Policer type trtcm
	PolTypeTrtcm = 0 // Default
	// PolTypeSrtcm - Policer type srtcm
	PolTypeSrtcm = 1
)

// PolInfo - information related to a policer
type PolInfo struct {
	// PolType - one of PolTypeTrtcm or PolTypeSrtcm
	PolType int
	// ColorAware - color aware or not
	ColorAware bool
	// CommittedInfoRate - CIR in Mbps
	CommittedInfoRate uint64
	// PeakInfoRate - PIR in Mbps
	PeakInfoRate uint64
	// CommittedBlkSize -  CBS in bytes
	// 0 for default selection
	CommittedBlkSize uint64
	// ExcessBlkSize - EBS in bytes
	// 0 for default selection
	ExcessBlkSize uint64
}

// PolObjType - type  of a policer attachment object
type PolObjType uint

const (
	// PolAttachPort - attach policer to port
	PolAttachPort PolObjType = 1 << iota
	// PolAttachLbRule - attach policer to a rule
	PolAttachLbRule
	// PolAttachPortEgress - attach policer to a port's egress direction
	// (needs the eBPF egress hook, --egr-hooks)
	PolAttachPortEgress
)

// PolObj - Information related to policer attachment point
type PolObj struct {
	// PolObjName - name of the object
	PolObjName string
	// AttachMent - attach point type of the object
	AttachMent PolObjType
}

// PolMod - Information related to policer entry
type PolMod struct {
	// Ident - identifier
	Ident string
	// Info - policer info of type PolInfo
	Info PolInfo
	// Target - target object information
	Target PolObj
}

const (
	// MirrTypeSpan - simple SPAN
	MirrTypeSpan = 0 // Default
	// MirrTypeRspan - type RSPAN
	MirrTypeRspan = 1
	// MirrTypeErspan - type ERSPAN
	MirrTypeErspan = 2
)

// MirrInfo - information related to a mirror entry
type MirrInfo struct {
	// MirrType - one of MirrTypeSpan, MirrTypeRspan or MirrTypeErspan
	MirrType int
	// MirrPort - port where mirrored traffic needs to be sent
	MirrPort string
	// MirrVlan - for RSPAN we may need to send tagged mirror traffic
	MirrVlan int
	// MirrRip - RemoteIP. For ERSPAN we may need to send tunnelled mirror traffic
	MirrRip net.IP
	// MirrRip - SourceIP. For ERSPAN we may need to send tunnelled mirror traffic
	MirrSip net.IP
	// MirrTid - mirror tunnel-id. For ERSPAN we may need to send tunnelled mirror traffic
	MirrTid uint32
}

// MirrObjType - type of mirror attachment
type MirrObjType uint

const (
	// MirrAttachPort - mirror attachment to a port
	MirrAttachPort MirrObjType = 1 << iota
	// MirrAttachRule - mirror attachment to a lb rule
	MirrAttachRule
)

// MirrObj - information of object attached to mirror
type MirrObj struct {
	// MirrObjName - object name to be attached to mirror
	MirrObjName string
	// AttachMent - one of MirrAttachPort or MirrAttachRule
	AttachMent MirrObjType
}

// MirrMod - information related to a  mirror entry
type MirrMod struct {
	// Ident - unique identifier for the mirror
	Ident string
	// Info - information about the mirror
	Info MirrInfo
	// Target - information about object to which mirror needs to be attached
	Target MirrObj
}

// MirrGetMod - information related to Get a mirror entry
type MirrGetMod struct {
	// Ident - unique identifier for the mirror
	Ident string
	// Info - information about the mirror
	Info MirrInfo
	// Target - information about object to which mirror needs to be attached
	Target MirrObj
	// Sync - sync state
	Sync DpStatusT
}

// User - information related to a user
type User struct {
	// Username - username of the user
	Username string `json:"username"`
	// Password - password of the user
	Password string `json:"password"`
	// createdAt - time of creation
	CreatedAt time.Time `json:"created_at"`
	//ID - unique identifier for the user
	ID int `json:"id"`
	// Role - role of the user
	Role string `json:"role"`
}

// L4TraceStatus - L4 connection tracing status and statistics
type L4TraceStatus struct {
	Enabled       bool         `json:"enabled"`
	SamplingRate  uint32       `json:"sampling_rate"`
	ConfigVersion uint32       `json:"config_version"`
	Stats         L4TraceStats `json:"stats"`
}

// L4TraceStats - L4 tracing statistics counters
type L4TraceStats struct {
	TotalEvents     uint64 `json:"total_events"`
	SampledEvents   uint64 `json:"sampled_events"`
	DroppedEvents   uint64 `json:"dropped_events"`
	TCPEvents       uint64 `json:"tcp_events"`
	SCTPEvents      uint64 `json:"sctp_events"`
	UDPEvents       uint64 `json:"udp_events"`
	ConnNew         uint64 `json:"conn_new"`
	ConnEstablished uint64 `json:"conn_established"`
	ConnClosed      uint64 `json:"conn_closed"`
	ConnTimeout     uint64 `json:"conn_timeout"`
	ConnReset       uint64 `json:"conn_reset"`
	ConnError       uint64 `json:"conn_error"`
}

// NetTraceParserMeta represents trace parser metadata for API responses
type NetTraceParserMeta struct {
	Name           string
	Version        string
	Protocol       string
	SupportedPaths []string
}

// Data-plane X-Api-Key enforcement policies for LbServiceArg.ApiKeyAuth.
//
// The set is closed and the default is refusal to enforce, not refusal to
// serve: an operator who has never heard of this field gets the behaviour
// they have today. Enforcement is opt-in per service and says nothing about
// how that service streams — that is the whole point of the field existing
// separately from sse_mode and pd_disagg_mode.
const (
	// ApiKeyAuthDisabled admits requests without an X-Api-Key header. It is
	// what an unset field resolves to.
	ApiKeyAuthDisabled = "disabled"
	// ApiKeyAuthRequired enforces X-Api-Key validation in the data plane.
	ApiKeyAuthRequired = "required"
)

// ResolveApiKeyAuth maps a service's configured policy onto the closed set,
// resolving the unset value to ApiKeyAuthDisabled.
//
// It exists so that the default lives in exactly one place. The datapath, the
// REST read path and the rule installer each need the resolved value, and a
// default spelled out at three call sites is a default that will eventually
// disagree with itself.
func ResolveApiKeyAuth(policy string) string {
	if policy == "" {
		return ApiKeyAuthDisabled
	}
	return policy
}

// IsValidApiKeyAuth reports whether a configured policy is one this build
// implements. The empty string is valid and means "unset".
func IsValidApiKeyAuth(policy string) bool {
	switch policy {
	case "", ApiKeyAuthDisabled, ApiKeyAuthRequired:
		return true
	}
	return false
}

// ErrInvalidApiKeyAuth is returned when a service names an api_key_auth value
// outside the closed set. It is a distinct sentinel so the REST layer can
// answer 400 rather than installing a rule whose enforcement policy the data
// plane would have to guess at — and guessing here means guessing between
// "admit everything" and "reject everything".
var ErrInvalidApiKeyAuth = errors.New("invalid api_key_auth: must be one of disabled, required")

// ErrDBUnavailable is returned when the credential store is not initialised or
// its connection has been lost. It is a server-side condition, not a verdict on
// the credential, and maps to HTTP 503.
var ErrDBUnavailable = errors.New("user database unavailable")

// ErrKeyStoreUnconfigured is returned by the data-plane API-key hooks when no
// key store has been configured at all. It is distinct from ErrDBUnavailable:
// that one means a store exists and cannot be reached, this one means the
// operator never named one.
//
// Both map to HTTP 503. The key lifecycle routes are registered whether or not
// a store exists, so the honest answer to a call against a gateway without one
// is "this is not configured here" — not 501, which would claim the feature
// does not exist, and not 500, which would claim a fault.
var ErrKeyStoreUnconfigured = errors.New("ai_key_store_unconfigured")

// ErrTokenNotFound is returned when a token is well-formed but unknown to the
// store. It is a verdict on the credential and maps to HTTP 401. It exists as a
// sentinel because the authentication chain has to tell it apart from a store
// failure, and comparing error strings to make that distinction is how the two
// came to be reported with the same status.
var ErrTokenNotFound = errors.New("Token not found")

// ErrInvalidRole is returned when a create or update names a role outside the
// closed set the authorizer implements. It is a distinct sentinel so the REST
// layer can answer 400 — the request is malformed, not unauthorized — rather
// than storing a role that would silently carry no authority.
var ErrInvalidRole = errors.New("invalid role: must be one of admin, viewer")

// ErrBootstrapClosed is returned by NetUserBootstrap when a user already
// exists. Unauthenticated creation is a one-time bootstrap, so this is a
// credential failure rather than a server fault and maps to HTTP 401.
var ErrBootstrapClosed = errors.New("user bootstrap is closed")

// NetHookInterface - Go interface which needs to be implemented to talk to loxinet module
type NetHookInterface interface {
	NetMirrorGet() ([]MirrGetMod, error)
	NetMirrorAdd(*MirrMod) (int, error)
	NetMirrorDel(*MirrMod) (int, error)
	NetPortGet() ([]PortDump, error)
	NetPortAdd(*PortMod) (int, error)
	NetPortDel(*PortMod) (int, error)
	NetVlanGet() ([]VlanGet, error)
	NetVlanAdd(*VlanMod) (int, error)
	NetVlanDel(*VlanMod) (int, error)
	NetVlanPortAdd(*VlanPortMod) (int, error)
	NetVlanPortDel(*VlanPortMod) (int, error)
	NetFdbAdd(*FdbMod) (int, error)
	NetFdbDel(*FdbMod) (int, error)
	NetAddrGet() ([]IPAddrGet, error)
	NetAddrAdd(*IPAddrMod) (int, error)
	NetAddrDel(*IPAddrMod) (int, error)
	NetNeighGet() ([]NeighMod, error)
	NetNeighAdd(*NeighMod) (int, error)
	NetNeighDel(*NeighMod) (int, error)
	NetRouteGet() ([]RouteGet, error)
	NetRouteAdd(*RouteMod) (int, error)
	NetRouteDel(*RouteMod) (int, error)
	NetLbRuleAdd(*LbRuleMod) (int, error)
	NetLbRuleDel(*LbRuleMod) (int, error)
	NetLbRuleGet() ([]LbRuleMod, error)
	NetKvExactBindingGet() ([]KvExactBindingMod, error)
	NetKvExactBindingAdd(*KvExactBindingMod) (int, error)
	NetKvExactBindingDel(*KvExactBindingMod) (int, error)
	// NetKvExactStatusGet returns the resolved KV-exact composition status of
	// every KV-exact rule on vip:port:proto (modelName "" = all models).
	// Served from a DEDICATED read model: resolved status must never ride the
	// GET/POST-shared LoadbalanceEntry, where a client echoing a GET body back
	// into a POST would replay resolved state as configuration.
	NetKvExactStatusGet(vip string, port uint16, proto string, modelName string) ([]KvExactStatusMod, error)
	// NetL7PolicyApply attaches an ordered L7 content-routing route array to the
	// running sockproxy rule fronting the given VIP:port:proto.
	// Driven from the dedicated /config/l7policy REST resource: the route IR
	// reaches the eBPF userspace proxy via DpProxyAttachL7Policy (a SEPARATE CGO
	// call — never inline on the 4096-byte proxy_arg).
	NetL7PolicyApply(vip string, port uint16, proto string, routes []L7RuleArg) (int, error)
	// NetL7PolicyRemove detaches any L7 policy from the VIP:port:proto rule
	// (regfrees every compiled REGEX program on the C side).
	NetL7PolicyRemove(vip string, port uint16, proto string) (int, error)
	NetCtInfoGet() ([]CtInfo, error)
	NetSessionGet() ([]SessionMod, error)
	NetSessionUlClGet() ([]SessionUlClMod, error)
	NetSessionAdd(*SessionMod) (int, error)
	NetSessionDel(*SessionMod) (int, error)
	NetSessionUlClAdd(*SessionUlClMod) (int, error)
	NetSessionUlClDel(*SessionUlClMod) (int, error)
	NetPolicerGet() ([]PolMod, error)
	NetPolicerAdd(*PolMod) (int, error)
	NetPolicerDel(*PolMod) (int, error)
	NetCIStateMod(*HASMod) (int, error)
	NetCIStateGet() ([]HASMod, error)
	NetFwRuleAdd(*FwRuleMod) (int, error)
	NetFwRuleDel(*FwRuleMod) (int, error)
	NetFwRuleGet() ([]FwRuleMod, error)
	NetSecurityRateStatsGet() (SecurityRateStats, error)
	NetCtErrorStatsGet() (CtErrorStats, error)
	NetIPFilterAdd(*IPFilterMod) (int, error)
	NetIPFilterDel(*IPFilterMod) (int, error)
	NetIPFilterGet() ([]IPFilterEntry, error)
	NetSecurityRateSet(*SecurityRateConfig) (int, error)
	NetSecurityRateGet() (*SecurityRateState, error)
	NetSecurityRateResetStats() (int, error)
	NetEpHostAdd(fm *EndPointMod) (int, error)
	NetEpHostDel(fm *EndPointMod) (int, error)
	NetEpHostGet() ([]EndPointMod, error)
	NetEpHostStateSet(fm *EndPointHostMod) (int, error)
	NetParamSet(param ParamMod) (int, error)
	NetParamGet(param *ParamMod) (int, error)
	NetGoBGPNeighGet() ([]GoBGPNeighGetMod, error)
	NetGoBGPNeighAdd(nm *GoBGPNeighMod) (int, error)
	NetGoBGPNeighDel(nm *GoBGPNeighMod) (int, error)

	NetGoBGPPolicyDefinedSetGet(string, string) ([]GoBGPPolicyDefinedSetMod, error)
	NetGoBGPPolicyDefinedSetAdd(nm *GoBGPPolicyDefinedSetMod) (int, error)
	NetGoBGPPolicyDefinedSetDel(nm *GoBGPPolicyDefinedSetMod) (int, error)

	NetGoBGPPolicyDefinitionsGet() ([]GoBGPPolicyDefinitionsMod, error)
	NetGoBGPPolicyDefinitionAdd(nm *GoBGPPolicyDefinitionsMod) (int, error)
	NetGoBGPPolicyDefinitionDel(nm *GoBGPPolicyDefinitionsMod) (int, error)

	NetGoBGPPolicyApplyAdd(nm *GoBGPPolicyApply) (int, error)

	NetGoBGPPolicyApplyDel(nm *GoBGPPolicyApply) (int, error)
	NetGoBGPGCAdd(gc *GoBGPGlobalConfig) (int, error)
	NetGoBGPGCGet() (GoBGPGlobalConfig, error)
	NetBFDGet() ([]BFDMod, error)
	NetBFDAdd(bm *BFDMod) (int, error)
	NetBFDDel(bm *BFDMod) (int, error)

	NetUserAdd(um *User) (int, error)
	NetUserBootstrap(um *User) (int, error)
	NetUserGet() ([]User, error)
	NetUserDel(ID int) error
	NetUserUpdate(um *User) error
	NetUserLogin(um *User) (string, bool, error)
	NetUserLogout(token string) error
	NetUserValidate(token string) (interface{}, error)

	// OAuth2
	NetOauthUserTokenStore(userEmail, token, refreshToken string, expiry time.Time) (string, bool, error)
	NetOauthUserValidate(token string) (interface{}, error)
	NetOauthValidateAllTokens(token, refreshToken string) (interface{}, error)
	NetOauthDeleteToken(token string) error

	NetPrometheusEnable() error
	NetHandlePanic()

	// GPU-Aware Load Balancing
	NetDpEbpfIsGPUMonitoringEnabled() bool
	NetDpEbpfEnableGPUMonitoring() error
	NetDpEbpfDisableGPUMonitoring() error
	NetDpEbpfGetGPUMonitoringStatus() interface{}
	NetDpEbpfUpdateWorkerMetrics(endpointIP string, req interface{}) error
	NetDpEbpfGetAllWorkerMetrics() []interface{}
	NetDpEbpfCleanupStaleConversations(cutoffTime time.Time) (int, float64, error)

	// Trace Parser Management (for dynamic parser selection)
	NetTraceParserRegistryGet() (interface{}, error)
	NetTraceCatalogInfoGet(catalogID uint16) (catalogName string, parserType string, err error)
	NetTraceParserListGet() ([]NetTraceParserMeta, error)
	NetTraceCatalogParserGet(catalogID uint16) (parserName string, err error)
	NetTraceCatalogParserUpdate(catalogID uint16, parserName string) error
	NetTraceCatalogParserDelete(catalogID uint16) error

	// L4 Connection Tracing (TCP/SCTP)
	NetL4TraceEnable(samplingRate uint32) error
	NetL4TraceDisable() error
	NetL4TraceGetStatus() (*L4TraceStatus, error)
	NetL4TraceUpdateSampling(samplingRate uint32) error
	NetL4TraceResetStats() error

	// IPsec Configuration and Management
	NetIPsecGetConfig() (*IPsecConfig, error)
	NetIPsecConfigSet(cfg *IPsecConfigMod) (int, error)
	NetIPsecTunnelAdd(tunnel *IPsecTunnelMod) (int, error)
	NetIPsecTunnelUpdate(tunnel *IPsecTunnelMod) (int, error)
	NetIPsecTunnelDel(name string) (int, error)
	NetIPsecTunnelAction(name string, action string) (int, error)
	NetIPsecTunnelGet(name string) (*IPsecTunnel, error)
	NetIPsecTunnelGetAll() ([]*IPsecTunnel, error)
	NetIPsecTunnelPeerConfig(name string) (*IPsecPeerConfig, error)
	NetIPsecSAGetAll() ([]*IPsecSA, error)
	NetIPsecStatsGet() (*IPsecStats, error)
	NetIPsecStatsReset() (int, error)

	// IPsec Certificate Management
	NetIPsecCertificateAdd(cm *IPsecCertificateMod) (int, error)
	NetIPsecCertificateGet(name string) (*IPsecCertificate, error)
	NetIPsecCertificateDel(name string) (int, error)
	NetIPsecCertificateGetAll() ([]*IPsecCertificate, error)
	NetIPsecCertificateValidate(certPEM, keyPEM, passphrase string) (*IPsecCertValidation, error)
	NetIPsecCACertificateAdd(cm *IPsecCACertificateMod) (int, error)
	NetIPsecCACertificateGet(name string) (*IPsecCACertificate, error)
	NetIPsecCACertificateDel(name string) (int, error)
	NetIPsecCACertificateGetAll() ([]*IPsecCACertificate, error)
	// Snapshot-only exports: full PEM material (certificate + private key)
	// in the exact Mod shapes the Add hooks accept, so snapshots round-trip.
	// SENSITIVE — served only through the authenticated snapshot/restore
	// surface, never through the regular certificate GET endpoints.
	// A private key uploaded encrypted is exported encrypted as stored; its
	// passphrase is never persisted, so restoring it fails validation loudly.
	NetIPsecCertificateExportAll() ([]IPsecCertificateMod, error)
	NetIPsecCACertificateExportAll() ([]IPsecCACertificateMod, error)

	// AI Gateway - API key lifecycle management
	NetAPIKeyCreate(entry ApiKeyEntry) (string, string, error)
	NetAPIKeyList(tenantID string) ([]ApiKeySummary, error)
	NetAPIKeyGet(keyID string) (*ApiKeySummary, error)
	NetAPIKeyRevoke(keyID string) error
	NetAPIKeyDelete(keyID string) error
	NetAPIKeyPatch(keyID string, allowedModels []string, enabled *bool) error
	NetTenantRateLimitSet(tenantID string, rps, tokensPerMin, burstPct int, modelLimits []TenantModelRateLimit) error
	NetTenantRateLimitGet(tenantID string) (*TenantRateLimitEntry, error)

	// Bridge-VID allocator indirection.
	// Thin wrappers over pkg/loxinet.{GetOrAllocBridgeVid,LookupBridgeVid,
	// ReleaseBridgeVid} so api/loxinlp can reach the allocator without
	// importing pkg/loxinet (which imports api/loxinlp; breaks import cycle).
	NetGetOrAllocBridgeVid(name string) (int, error)
	NetLookupBridgeVid(name string) (int, bool)
	NetReleaseBridgeVid(name string) error
}

// IPsec Configuration and Data Structures

// IPsecConfig - Global IPsec configuration
type IPsecConfig struct {
	FastPathEnabled       bool     `json:"fastPathEnabled"`
	HwOffloadEnabled      bool     `json:"hwOffloadEnabled"`
	HwOffloadType         string   `json:"hwOffloadType"`
	AntiReplayEnabled     bool     `json:"antiReplayEnabled"`
	SALifetimeWarnSeconds uint32   `json:"saLifetimeWarnSeconds"`
	SeqOverflowAction     string   `json:"seqOverflowAction"`
	MTU                   uint16   `json:"mtu"`
	SupportedAlgorithms   []string `json:"supportedAlgorithms"`
	HwCapabilities        struct {
		QATAvailable   bool `json:"qatAvailable"`
		QATDevices     int  `json:"qatDevices"`
		DPAA2Available bool `json:"dpaa2Available"`
	} `json:"hwCapabilities"`
}

// IPsecConfigMod - Modifiable IPsec configuration
type IPsecConfigMod struct {
	FastPathEnabled       *bool   `json:"fastPathEnabled,omitempty"`
	HwOffloadEnabled      *bool   `json:"hwOffloadEnabled,omitempty"`
	HwOffloadType         *string `json:"hwOffloadType,omitempty"`
	AntiReplayEnabled     *bool   `json:"antiReplayEnabled,omitempty"`
	SALifetimeWarnSeconds *uint32 `json:"saLifetimeWarnSeconds,omitempty"`
	SeqOverflowAction     *string `json:"seqOverflowAction,omitempty"`
	MTU                   *uint16 `json:"mtu,omitempty"`
}

// IPsecSelector - Traffic selector for IPsec tunnel
type IPsecSelector struct {
	SrcCIDR  string `json:"srcCidr"`
	DstCIDR  string `json:"dstCidr"`
	Protocol uint8  `json:"protocol"`
	SrcPort  uint16 `json:"srcPort"`
	DstPort  uint16 `json:"dstPort"`
}

// IPsecTunnelMod - IPsec tunnel configuration for creation/update
type IPsecTunnelMod struct {
	Name           string        `json:"name"`
	LocalIP        string        `json:"localIp"`
	RemoteIP       string        `json:"remoteIp"`
	AuthMode       string        `json:"authMode"`             // "psk" or "cert"
	PSK            string        `json:"psk,omitempty"`        // Pre-shared key (for PSK mode)
	LocalID        string        `json:"localId"`              // IKE local identifier
	RemoteID       string        `json:"remoteId"`             // IKE remote identifier
	CertName       string        `json:"certName,omitempty"`   // Certificate name (for cert mode)
	CACertName     string        `json:"caCertName,omitempty"` // CA certificate name (for cert mode)
	IKEVersion     string        `json:"ikeVersion"`           // "ikev1" or "ikev2"
	IKEEncryption  string        `json:"ikeEncryption"`        // IKE encryption algorithm
	IKEIntegrity   string        `json:"ikeIntegrity"`         // IKE integrity algorithm
	IKEDHGroup     string        `json:"ikeDhGroup"`           // IKE DH group
	IKELifetime    uint32        `json:"ikeLifetime"`          // IKE lifetime in seconds
	ESPEncryption  string        `json:"espEncryption"`        // ESP encryption algorithm
	ESPIntegrity   string        `json:"espIntegrity"`         // ESP integrity algorithm
	ESPDHGroup     string        `json:"espDhGroup"`           // ESP PFS DH group
	ESPLifetime    uint32        `json:"espLifetime"`          // ESP lifetime in seconds
	Mark           uint32        `json:"mark"`                 // Netfilter mark for VTI routing (0 = no mark)
	TunnelMode     string        `json:"tunnelMode"`           // "tunnel" or "transport"
	InstallPolicy  bool          `json:"installPolicy"`        // Automatically install XFRM policies
	Compress       bool          `json:"compress"`             // Enable IP compression
	Mobike         bool          `json:"mobike"`               // Enable MOBIKE (IKEv2 mobility)
	Rekey          bool          `json:"rekey"`                // Enable automatic rekeying
	Reauth         bool          `json:"reauth"`               // Re-authenticate on rekey (vs just rekey)
	Auto           string        `json:"auto"`                 // "start" (initiator/client), "add" (responder/server), or "route"
	CompatFallback bool          `json:"compatFallback"`       // Append weak legacy proposal (aes128-sha1[-modp1024]) for old peers
	Selector       IPsecSelector `json:"selector"`
	DPD            IPsecDPD      `json:"dpd"` // Dead Peer Detection
}

// IPsecDPD - Dead Peer Detection configuration
type IPsecDPD struct {
	Action  string `json:"action"`  // "restart", "clear", "hold"
	Delay   uint32 `json:"delay"`   // Seconds between DPD checks
	Timeout uint32 `json:"timeout"` // Timeout for DPD response
}

// IPsecTunnel - IPsec tunnel state (for GET operations)
type IPsecTunnel struct {
	IPsecTunnelMod
	State        string    `json:"state"` // "down", "connecting", "up"
	InstalledAt  time.Time `json:"installedAt"`
	BytesIn      uint64    `json:"bytesIn"`
	BytesOut     uint64    `json:"bytesOut"`
	PacketsIn    uint64    `json:"packetsIn"`
	PacketsOut   uint64    `json:"packetsOut"`
	LastRekeyAt  time.Time `json:"lastRekeyAt"`
	SAsInstalled int       `json:"sasInstalled"`
}

// IPsecPeerConfig - Generated strongSwan configuration for the remote peer
// of a tunnel (mirrored conn block + secrets entry)
type IPsecPeerConfig struct {
	TunnelName   string `json:"tunnelName"`
	IPsecConf    string `json:"ipsecConf"`
	IPsecSecrets string `json:"ipsecSecrets"`
	Notes        string `json:"notes"`
}

// IPsecSA - Security Association state
type IPsecSA struct {
	SPI            string    `json:"spi"`
	TunnelName     string    `json:"tunnelName"`
	Direction      string    `json:"direction"` // "in" or "out"
	LocalIP        string    `json:"localIp"`
	RemoteIP       string    `json:"remoteIp"`
	Encryption     string    `json:"encryption"`
	Integrity      string    `json:"integrity"`
	State          string    `json:"state"` // "active", "expired", "rekeying"
	BytesIn        uint64    `json:"bytesIn"`
	BytesOut       uint64    `json:"bytesOut"`
	PacketsIn      uint64    `json:"packetsIn"`
	PacketsOut     uint64    `json:"packetsOut"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	SequenceNumber uint64    `json:"sequenceNumber"`
	ReplayWindow   uint32    `json:"replayWindow"`
}

// IPsecStats - Aggregated IPsec statistics
type IPsecStats struct {
	TotalTunnels    int       `json:"totalTunnels"`
	TunnelsUp       int       `json:"tunnelsUp"`
	TunnelsDown     int       `json:"tunnelsDown"`
	TotalSAs        int       `json:"totalSas"`
	TotalBytesIn    uint64    `json:"totalBytesIn"`
	TotalBytesOut   uint64    `json:"totalBytesOut"`
	TotalPacketsIn  uint64    `json:"totalPacketsIn"`
	TotalPacketsOut uint64    `json:"totalPacketsOut"`
	EncryptErrors   uint64    `json:"encryptErrors"`
	DecryptErrors   uint64    `json:"decryptErrors"`
	AuthErrors      uint64    `json:"authErrors"`
	ReplayErrors    uint64    `json:"replayErrors"`
	SeqOverflows    uint64    `json:"seqOverflows"`
	LastUpdated     time.Time `json:"lastUpdated"`
}

// IPsec Certificate Management

// IPsecCertificateMod - Certificate upload request
type IPsecCertificateMod struct {
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate"`
	PrivateKeyPEM  string `json:"privateKey"`
	Passphrase     string `json:"passphrase,omitempty"`
	Description    string `json:"description,omitempty"`
}

// IPsecCertificate - Certificate information (no private key in responses)
type IPsecCertificate struct {
	Name        string    `json:"name"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	SAN         []string  `json:"san"`
	KeyUsage    []string  `json:"keyUsage"`
	InstalledAt time.Time `json:"installedAt"`
	Description string    `json:"description,omitempty"`
}

// IPsecCertValidation - Certificate validation result
type IPsecCertValidation struct {
	Valid        bool      `json:"valid"`
	Errors       []string  `json:"errors,omitempty"`
	Warnings     []string  `json:"warnings,omitempty"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	KeyAlgorithm string    `json:"keyAlgorithm"`
	KeySize      int       `json:"keySize"`
}

// IPsecCACertificateMod - CA certificate upload request
type IPsecCACertificateMod struct {
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate"`
	Description    string `json:"description,omitempty"`
}

// IPsecCACertificate - CA certificate information
type IPsecCACertificate struct {
	Name        string    `json:"name"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	InstalledAt time.Time `json:"installedAt"`
	Description string    `json:"description,omitempty"`
}

// ApiKeyEntry - API key entry with all fields including the secret hash
type ApiKeyEntry struct {
	KeyID   string `json:"key_id"`
	KeyHash string `json:"-"`
	// ApiKey carries caller-supplied key material on create, for importing a
	// tenant whose key was minted elsewhere. Empty on the primary path, where
	// the gateway mints the key itself.
	//
	// Write-only, and `json:"-"` rather than a write-only convention: the REST
	// layer copies it in from the request body explicitly, so no marshalling
	// path can return it in a response, a listing or a log line by accident.
	ApiKey        string     `json:"-"`
	TenantID      string     `json:"tenant_id"`
	Name          string     `json:"name"`
	AllowedModels []string   `json:"allowed_models"`
	RateLimitRPS  int        `json:"rate_limit_rps"`
	BurstSize     int        `json:"burst_size"`
	TokensPerMin  int        `json:"tokens_per_min"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Enabled       bool       `json:"enabled"`
}

// ApiKeySummary - API key summary without the secret hash
type ApiKeySummary struct {
	KeyID         string     `json:"key_id"`
	TenantID      string     `json:"tenant_id"`
	Name          string     `json:"name"`
	AllowedModels []string   `json:"allowed_models"`
	RateLimitRPS  int        `json:"rate_limit_rps"`
	BurstSize     int        `json:"burst_size"`
	TokensPerMin  int        `json:"tokens_per_min"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Enabled       bool       `json:"enabled"`
}

// TenantModelRateLimit - one model's token quota inside a tenant's rate
// limit configuration
type TenantModelRateLimit struct {
	Model        string `json:"model"`
	TokensPerMin int    `json:"tokens_per_min"`
}

// TenantRateLimitEntry - per-tenant rate limit configuration with metadata
type TenantRateLimitEntry struct {
	TenantID     string `json:"tenant_id"`
	RPS          int    `json:"rps"`
	TokensPerMin int    `json:"tokens_per_min"`
	// BurstPct is the tenant's token-bucket capacity as a percentage of
	// TokensPerMin: how much of a minute's quota a fully idle tenant may
	// spend at once. Zero means the tenant has no override and the
	// process-wide default (LLB_AI_QUOTA_BURST_PCT, itself defaulting to
	// 100) applies.
	BurstPct    int                    `json:"burst_pct"`
	ModelLimits []TenantModelRateLimit `json:"model_limits,omitempty"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// KvExactBindingMod - persisted form of one rule's KV-exact binding: the
// composed model-profile + engine-contract identity, its rule-scoped
// binding generation, the full binding digest, and the highest generation
// ever allocated for the rule (so a restarted allocator never reuses a
// generation that may still be in flight).
type KvExactBindingMod struct {
	// RuleIdent identifies the bound load-balancer rule (its stable id).
	RuleIdent string `json:"ruleIdent"`
	// ModelProfileID/ModelProfileGen reference exactly one ModelPromptProfile
	// at exactly one registry generation (scalars by schema).
	ModelProfileID  string `json:"modelProfileId"`
	ModelProfileGen uint64 `json:"modelProfileGen"`
	// EngineContractID/EngineContractGen reference exactly one engine
	// contract at exactly one generation (scalars by schema).
	EngineContractID  string `json:"engineContractId"`
	EngineContractGen uint64 `json:"engineContractGen"`
	// AttestationPolicyGen versions the attestation policy the binding was
	// admitted under.
	AttestationPolicyGen uint32 `json:"attestationPolicyGen"`
	// RequiredEvidenceLevel is the support-catalog evidence level this
	// binding requires of its engine tuple.
	RequiredEvidenceLevel string `json:"requiredEvidenceLevel"`
	// ConsensusPolicy names the endpoint-consensus policy.
	ConsensusPolicy string `json:"consensusPolicy"`
	// BindingGen is the rule-scoped monotonic data-plane generation (0 is
	// reserved and never a valid generation).
	BindingGen uint32 `json:"bindingGen"`
	// BindingDigest is the full digest over the composed binding identity.
	// It, not BindingGen, is the identity proof.
	BindingDigest string `json:"bindingDigest"`
	// MaxAllocatedGen is the highest BindingGen the rule's allocator has
	// handed out; restore resumes allocation above it.
	MaxAllocatedGen uint32 `json:"maxAllocatedGen"`
}

// KvExactStatusMod - resolved KV-exact composition status of one rule. A
// DEDICATED read model, deliberately not the LoadbalanceEntry: status echoed
// from a GET must never be replayable into a POST as configuration. Every
// identity field is a scalar — one rule composes exactly one model profile
// with exactly one engine contract at exactly one generation each.
type KvExactStatusMod struct {
	// RuleIdentity is the rule's stable opaque id.
	RuleIdentity string `json:"ruleIdentity"`
	// ModelName/EngineFamily identify what the rule serves and through which
	// KV-event engine family (effective value; "" resolves to vllm).
	ModelName    string `json:"modelName"`
	EngineFamily string `json:"engineFamily"`
	// ApiMode is the rule's effective KV-exact API surface declaration.
	ApiMode string `json:"apiMode"`
	// ModelProfileID/ModelProfileGen reference the bound ModelPromptProfile
	// (empty/0 on a legacy profile-less rule).
	ModelProfileID  string `json:"modelProfileId,omitempty"`
	ModelProfileGen uint64 `json:"modelProfileGen,omitempty"`
	// EngineContractID/EngineContractGen reference the bound engine contract
	// (empty/0 on a legacy profile-less rule).
	EngineContractID  string `json:"engineContractId,omitempty"`
	EngineContractGen uint64 `json:"engineContractGen,omitempty"`
	// BindingGen/BindingDigest are the rule's current composed-binding
	// data-plane generation and its identity-proving digest (0/"" legacy).
	BindingGen    uint32 `json:"bindingGen,omitempty"`
	BindingDigest string `json:"bindingDigest,omitempty"`
	// HashContractID names the block-hash contract the rule's data plane
	// computes with (the effective kvHashAlgo).
	HashContractID string `json:"hashContractId"`
	// WireSchemaID/PdDialectID are engine-contract identities; empty until an
	// engine-contract registry serves them.
	WireSchemaID string `json:"wireSchemaId,omitempty"`
	PdDialectID  string `json:"pdDialectId,omitempty"`
	// RequiredEvidenceLevel is the support-catalog evidence level the
	// binding requires of its engine tuple ("" on legacy rules).
	RequiredEvidenceLevel string `json:"requiredEvidenceLevel,omitempty"`
	// DesiredState/EnforcedState report the rule's position on the
	// attestation ladder. A legacy profile-less rule reports
	// LEGACY_ACTIVE_UNATTESTED on both; a strict rule reports its validated
	// desired state and the honestly-pending enforced state until the
	// data-plane contract word and the attestation controller enforce it.
	DesiredState  string `json:"desiredState"`
	EnforcedState string `json:"enforcedState"`
	// ReasonCodes are bounded typed reasons explaining EnforcedState.
	ReasonCodes []string `json:"reasonCodes,omitempty"`
	// Enforcement is the data-plane enforcement position of a strict rule
	// (absent on legacy rules): the Go deny-set fence, the last recorded
	// enforcement fault, and the last full contract-word ACK.
	Enforcement *KvExactEnforcement `json:"enforcement,omitempty"`
}

// KvExactEnforcement - the enforcement half of a strict rule's status: what
// the control plane wants vs what the data plane provably enforces.
type KvExactEnforcement struct {
	Desired  string `json:"desired"`
	Enforced string `json:"enforced"`
	// LastAckAt is the RFC3339 time of the last full contract-word ACK
	// (readback + binding-digest halves both verified); empty before the
	// first ACK after registration or restart.
	LastAckAt string `json:"lastAckAt,omitempty"`
	// Fault is the last enforcement fault reason ("" = none).
	Fault string `json:"fault,omitempty"`
	// GoFenced reports the authoritative tokenize-bridge deny-set fence.
	GoFenced bool `json:"goFenced"`
}
