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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	ghttp "net/http"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/loxilb-io/loxilb/api/loxinlp"
	cmn "github.com/loxilb-io/loxilb/common"
	utils "github.com/loxilb-io/loxilb/pkg/utils"
	tk "github.com/loxilb-io/loxilib"
	probing "github.com/prometheus-community/pro-bing"
)

// error codes
const (
	RuleErrBase = iota - 7000
	RuleUnknownServiceErr
	RuleUnknownEpErr
	RuleExistsErr
	RuleAllocErr
	RuleNotExistsErr
	RuleEpCountErr
	RuleTupleErr
	RuleArgsErr
	RuleEpNotExistErr
	RuleEpHostUnkErr
)

// HwOffload expressibility — typed error for FW rules
// flagged with HwOffload=true whose shape cannot be expressed in the
// BF2 DOCA ACL pipes (DENY_PIPE + ALLOW_PIPE 5-tuple TRANSPORT match).
//
// The error carries a machine-readable Reason code so callers (REST
// handlers, unit tests, future operator tooling) can branch on the
// specific violation without parsing the human-readable message.

// HwOffloadUnexpressibleReason - reason code for hard-reject branches
// of validateHwOffloadExpressible. Stable across loxilb versions: REST
// clients and callers may switch on the value.
type HwOffloadUnexpressibleReason int

const (
	// HwOffloadReasonNone - sentinel for "expressible". Never returned
	// as an error reason; reserved for forward-compat composition.
	HwOffloadReasonNone HwOffloadUnexpressibleReason = iota
	// HwOffloadReasonIPv6Src - source CIDR is IPv6; ACL pipes are
	// L3_TYPE_IP4-only.
	HwOffloadReasonIPv6Src
	// HwOffloadReasonIPv6Dst - destination CIDR is IPv6; ACL pipes are
	// L3_TYPE_IP4-only.
	HwOffloadReasonIPv6Dst
	// HwOffloadReasonPortRangeSrc - source port range (min != max);
	// DOCA per-entry match_mask supports single mask per port.
	HwOffloadReasonPortRangeSrc
	// HwOffloadReasonPortRangeDst - destination port range (min != max);
	// DOCA per-entry match_mask supports single mask per port.
	HwOffloadReasonPortRangeDst
	// HwOffloadReasonProtoTCP - explicit Proto=6 (TCP). The ACL pipes
	// use L4_TYPE_EXT=TRANSPORT (proto-agnostic), so proto-pinned
	// intent cannot be correctly enforced in HW
	// rule, re-affirmed).
	HwOffloadReasonProtoTCP
	// HwOffloadReasonProtoUDP - explicit Proto=17 (UDP). Same rationale
	// as HwOffloadReasonProtoTCP.
	HwOffloadReasonProtoUDP
	// HwOffloadReasonCIDRSrc - source IPv4 prefix length is not /32.
	// DOCA 2.9.4 BASIC pipes use a single pipe-level template mask set
	// at create time (UINT32_MAX → exact match per the validated sample);
	// per-entry CIDR masks are NOT supported. original "CIDR via
	// per-entry mask" was infeasible — corrected to exact-IP-only.
	HwOffloadReasonCIDRSrc
	// HwOffloadReasonCIDRDst - destination IPv4 prefix length is not /32.
	// Same rationale as HwOffloadReasonCIDRSrc.
	HwOffloadReasonCIDRDst
)

// errHwOffloadUnexpressible - typed error returned by AddFwRule when a
// HwOffload=true rule fails expressibility check. Wraps a
// reason code + a human-readable message naming the violating constraint
// + a suggested operator action.
type errHwOffloadUnexpressible struct {
	Reason  HwOffloadUnexpressibleReason
	Message string
}

// Error - implements the error interface.
func (e *errHwOffloadUnexpressible) Error() string {
	return e.Message
}

// validateHwOffloadExpressible - hard-reject gate. Returns
// nil if fwRule is expressible in the DOCA ingress ACL pipeline; returns
// a *errHwOffloadUnexpressible naming the violating constraint otherwise.
//
// This function is invoked by AddFwRule only when fwRule.HwOffload == true.
// Non-HW-flagged rules bypass the check entirely
// eBPF-only posture unchanged).
//
// Branches (enumerates 5 categories; we split port range into src
// vs dst, proto-specific into TCP vs UDP, and added 2 CIDR branches as
// part of SDK correction — 8 distinct reason codes total so
// callers can localize the operator remediation hint):
//
// 1. IPv6 source CIDR — ACL pipes are L3_TYPE_IP4-only.
//  2. IPv6 destination CIDR — same.
//  3. Non-/32 IPv4 source CIDR — corrected: DOCA 2.9.4 BASIC pipes
//     support exact-IP match only.
//  4. Non-/32 IPv4 destination CIDR — same.
//  5. Port range source (L4SrcMin != L4SrcMax, both non-zero) — DOCA
//     mask per entry supports a single port per template field.
//  6. Port range destination — same.
//  7. Proto-specific TCP (Proto == 6) — L4_TYPE_EXT=TRANSPORT match is
//     proto-agnostic; pinning to TCP cannot be correctly enforced.
//  8. Proto-specific UDP (Proto == 17) — same.
//
// Hint for operator: every error message ends with the explicit
// remediation ("use HwOffload=false or split into ").
// REST handler propagates this text into the 4xx response body.
func validateHwOffloadExpressible(fwRule cmn.FwRuleArg) error {
	// 1+2: IPv6 src / dst. Re-use the tk.IsNetIPv6 helper that AddFwRule
	// already trusts for the SNAT family-coercion path.
	if tk.IsNetIPv6(fwRule.SrcIP) {
		return &errHwOffloadUnexpressible{
			Reason: HwOffloadReasonIPv6Src,
			Message: fmt.Sprintf(
				"HwOffload=true incompatible with IPv6 source %q: "+
					" ACL pipes are IPv4-only;"+
					"use HwOffload=false to keep this rule on eBPF",
				fwRule.SrcIP),
		}
	}
	if tk.IsNetIPv6(fwRule.DstIP) {
		return &errHwOffloadUnexpressible{
			Reason: HwOffloadReasonIPv6Dst,
			Message: fmt.Sprintf(
				"HwOffload=true incompatible with IPv6 destination %q: "+
					" ACL pipes are IPv4-only;"+
					"use HwOffload=false to keep this rule on eBPF",
				fwRule.DstIP),
		}
	}
	// 2.5: Non-/32 IPv4 prefixes — DOCA 2.9.4 correction.
	// BASIC pipes apply a SINGLE pipe-level template mask set at create
	// time (UINT32_MAX → exact match) and `doca_flow_pipe_add_entry` is
	// a 9-arg call that does NOT take a per-entry mask. Per-entry CIDR
	// is only available via PIPE_ACL (chose BASIC). The
	// validated flow_acl_basic sample uses exact-IP entries only.
	//
	// Parse failures are silently passed through — AddFwRule itself
	// performs the canonical net.ParseCIDR validation; we only short-
	// circuit when the parse SUCCEEDS and the prefix is not /32.
	if _, srcNet, err := net.ParseCIDR(fwRule.SrcIP); err == nil {
		if ones, bits := srcNet.Mask.Size(); bits == 32 && ones != 32 {
			return &errHwOffloadUnexpressible{
				Reason: HwOffloadReasonCIDRSrc,
				Message: fmt.Sprintf(
					"HwOffload=true incompatible with source CIDR /%d in %q: "+
						"DOCA 2.9.4 BASIC pipes support exact-IP match only "+
						"(no per-entry mask corrected);"+
						"use HwOffload=false or expand to per-host /32 rules",
					ones, fwRule.SrcIP),
			}
		}
	}
	if _, dstNet, err := net.ParseCIDR(fwRule.DstIP); err == nil {
		if ones, bits := dstNet.Mask.Size(); bits == 32 && ones != 32 {
			return &errHwOffloadUnexpressible{
				Reason: HwOffloadReasonCIDRDst,
				Message: fmt.Sprintf(
					"HwOffload=true incompatible with destination CIDR /%d in %q: "+
						"DOCA 2.9.4 BASIC pipes support exact-IP match only "+
						"(no per-entry mask corrected);"+
						"use HwOffload=false or expand to per-host /32 rules",
					ones, fwRule.DstIP),
			}
		}
	}
	// 3+4: Port ranges. Mirror AddFwRule's guard: a port-tuple is
	// "active" only when at least one of min/max is non-zero. A range
	// is min != max. Single-port (min == max != 0) is expressible.
	if (fwRule.SrcPortMin != 0 || fwRule.SrcPortMax != 0) &&
		fwRule.SrcPortMin != fwRule.SrcPortMax {
		return &errHwOffloadUnexpressible{
			Reason: HwOffloadReasonPortRangeSrc,
			Message: fmt.Sprintf(
				"HwOffload=true incompatible with source port range "+
					"L4SrcMin=%d L4SrcMax=%d: DOCA per-entry match_mask "+
					"supports a single port per template field;"+
					"use HwOffload=false or split into single-port rules",
				fwRule.SrcPortMin, fwRule.SrcPortMax),
		}
	}
	if (fwRule.DstPortMin != 0 || fwRule.DstPortMax != 0) &&
		fwRule.DstPortMin != fwRule.DstPortMax {
		return &errHwOffloadUnexpressible{
			Reason: HwOffloadReasonPortRangeDst,
			Message: fmt.Sprintf(
				"HwOffload=true incompatible with destination port range "+
					"L4DstMin=%d L4DstMax=%d: DOCA per-entry match_mask "+
					"supports a single port per template field;"+
					"use HwOffload=false or split into single-port rules",
				fwRule.DstPortMin, fwRule.DstPortMax),
		}
	}
	// 5+6: Proto-specific. ACL pipes use L4_TYPE_EXT=TRANSPORT which is
	// proto-agnostic; pinning Proto=6 (TCP) or Proto=17 (UDP) cannot be
	// correctly enforced. Proto=0 (any) is expressible. Other proto
	// values are out of scope (not enumerated by);
	// future expressibility cases land here as additional branches.
	switch fwRule.Proto {
	case 0:
		// Proto=any — TRANSPORT match handles it.
	case 6:
		return &errHwOffloadUnexpressible{
			Reason: HwOffloadReasonProtoTCP,
			Message: "HwOffload=true incompatible with Proto=6 (TCP-specific): " +
				" ACL pipes use L4_TYPE_EXT=TRANSPORT (proto-agnostic)" +
				"so proto-pinned intent cannot be correctly enforced;" +
				"use HwOffload=false or set Proto=0 (any)",
		}
	case 17:
		return &errHwOffloadUnexpressible{
			Reason: HwOffloadReasonProtoUDP,
			Message: "HwOffload=true incompatible with Proto=17 (UDP-specific): " +
				" ACL pipes use L4_TYPE_EXT=TRANSPORT (proto-agnostic)" +
				"so proto-pinned intent cannot be correctly enforced;" +
				"use HwOffload=false or set Proto=0 (any)",
		}
	default:
		// Other proto values (SCTP=132, ICMP=1, …) are silently accepted
		// at this layer; DOCA wire-up validates them
		// further. Add explicit branches here when new restrictions
		// surface during DOCA-side validation.
	}
	return nil
}

type ruleTMatch uint

// rm tuples
const (
	RmPort ruleTMatch = 1 << iota
	RmL2Src
	RmL2Dst
	RmVlanID
	RmL3Src
	RmL3Dst
	RmL4Src
	RmL4Dst
	RmL4Prot
	RmInL2Src
	RmInL2Dst
	RmInL3Src
	RmInL3Dst
	RmInL4Src
	RmInL4Dst
	RmInL4Port
	RmMax
)

// constants
const (
	MaxLBEndPoints             = 32         // Max number of supported LB end-points
	DflLbaInactiveTries        = 2          // Default number of inactive tries before LB arm is turned off
	MaxDflLbaInactiveTries     = 100        // Max number of inactive tries before LB arm is turned off
	DflLbaCheckTimeout         = 10         // Default timeout for checking LB arms
	DflHostProbeTimeout        = 60         // Default probe timeout for end-point host
	InitHostProbeTimeout       = 15         // Initial probe timeout for end-point host
	MaxHostProbeTime           = 24 * 3600  // Max possible host health check duration
	LbDefaultInactiveTimeout   = 4 * 60     // Default inactive timeout for established sessions
	LbDefaultInactiveNSTimeout = 20         // Default inactive timeout for non-session oriented protocols
	LbMaxInactiveTimeout       = 24 * 3600  // Maximum inactive timeout for established sessions
	MaxEndPointCheckers        = 4          // Maximum helpers to check endpoint health
	EndPointCheckerDuration    = 2          // Duration at which ep-helpers will run
	MaxEndPointSweeps          = 20         // Maximum end-point sweeps per round
	VIPSweepDuration           = 30         // Duration of periodic VIP maintenance
	DefaultPersistTimeOut      = 10800      // Default persistent LB session timeout
	NatFwMark                  = 0x80000000 // NAT Marker
	SrcChkFwMark               = 0x40000000 // Src check Marker
	OnDfltSnatFwMark           = 0x20000000 // Ondefault Snat Marker
	MaxSrcLBMarkerNum          = 28         // Max LB indexes which support source checks
)

type ruleTType uint

// rt types
const (
	RtEm ruleTType = iota + 1
	RtMf
)

type rule8Tuple struct {
	val   uint8
	valid uint8
}

type rule16Tuple struct {
	val   uint16
	valid uint16
}

type rule16RTuple struct {
	valMin uint16
	valMax uint16
	valid  bool
}

type rule32Tuple struct {
	val   uint32
	valid uint32
}

type rule64Tuple struct {
	val   uint64
	valid uint64
}

type ruleIPTuple struct {
	addr net.IPNet
}

type ruleMacTuple struct {
	addr  [6]uint8
	valid [6]uint8
}

type ruleStringTuple struct {
	val string
}

type ruleTuples struct {
	port          ruleStringTuple
	l2Src         ruleMacTuple
	l2Dst         ruleMacTuple
	vlanID        rule16Tuple
	l3Src         ruleIPTuple
	l3Dst         ruleIPTuple
	l4Prot        rule8Tuple
	l4Src         rule16RTuple
	l4Dst         rule16RTuple
	tunID         rule32Tuple
	inL2Src       ruleMacTuple
	inL2Dst       ruleMacTuple
	inL3Src       ruleIPTuple
	inL3Dst       ruleIPTuple
	inL4Prot      rule8Tuple
	inL4Src       rule16RTuple
	inL4Dst       rule16RTuple
	pref          uint32
	path          string
	pathPrefix    string // P6: URL path prefix for L7 routing
	pathMatchMode string // P6: Path matching mode (disabled, prefix, exact)
	modelName     string // AI model name for pool selection (e.g. "llama-70b"); empty = wildcard
}

type ruleTActType uint

// possible actions for a rt-entry
const (
	RtActDrop ruleTActType = iota + 1
	RtActFwd
	RtActTrap
	RtActRedirect
	RtActDnat
	RtActSnat
	RtActFullNat
	RtActFullProxy
)

// possible types of end-point probe
const (
	HostProbePing        = "ping"
	HostProbeConnectTCP  = "tcp"
	HostProbeConnectUDP  = "udp"
	HostProbeConnectSCTP = "sctp"
	HostProbeHTTP        = "http"
	HostProbeHTTPS       = "https"
	// HostProbeTLSHello - : handshake-only TLS liveness probe.
	// UP = the TLS handshake completes (ANY cert accepted; the chain is NOT validated —
	// this is liveness, not a trust probe). SNI = epHostOpts.domainName (consistency).
	// A non-TLS port fails the handshake ⇒ DOWN.
	HostProbeTLSHello = "tls-hello"
	HostProbeNone     = "none"
)

type epHostOpts struct {
	inActTryThr       int
	probeType         string
	probeReq          string
	probeResp         string
	probeDuration     uint32
	currProbeDuration uint32
	probePort         uint16
	probeActivated    bool
	egress            bool
	// structured Octavia HTTP(S) health-monitor content fields.
	// All default-empty; when unset the prober falls back to the probeReq/probeResp
	// escape hatch, so existing behaviour is unchanged.
	probeMethod   string // HM HTTP method (e.g. "GET","HEAD"); empty ⇒ GET
	probePath     string // HM request path (e.g. "/healthz"); empty ⇒ probeReq / "/"
	expectedCodes string // Octavia expected_codes: "200" | "200,202" | "200-204"; empty ⇒ "200"
	httpVersion   string // "1.0" or "1.1"; when "1.1" a Host header is sent
	domainName    string // TLS SNI for HTTPS monitors AND the Host header
	// per-health-monitor CA override + verify opt-out. Control-plane only
	// (no proxy_arg / data-plane impact). probeVerify is the RESOLVED value (NetEpHostAdd
	// defaults a nil REST field to true ⇒ verification ON by default); only an
	// explicit probe_verify=false sets InsecureSkipVerify. probeCAPath overrides the CA bundle
	// used by the HTTPS content probe; empty ⇒ R.rootCAPool (today's behaviour, unchanged).
	// probeCAPath: override CA bundle for the HTTPS content probe; empty ⇒ R.rootCAPool.
	probeCAPath string
	// probeVerify: resolved verify toggle; true ⇒ verify on (default), false ⇒ InsecureSkipVerify.
	probeVerify bool
	// probeCRLPath: residual optional static CRL (PEM) the HTTPS content probe
	// checks the server-cert chain against (leaf-only revocation). Empty ⇒ no CRL (today's
	// behaviour). Carried here on the same health/verify surface as probeCAPath.
	probeCRLPath string
}

// parseExpectedCodes parses Octavia health-monitor expected_codes syntax:
// single ("200"), comma-list ("200,202"), and range ("200-204"); the empty string
// defaults to "200". Each part becomes an inclusive [lo,hi] pair. Malformed parts
// degrade safely (strconv.Atoi error ⇒ 0, a value no real HTTP status hits) so the
// health goroutine never panics.
func parseExpectedCodes(s string) [][2]uint16 {
	if s == "" {
		return [][2]uint16{{200, 200}}
	}
	var out [][2]uint16
	for _, part := range strings.Split(s, ",") {
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, _ := strconv.Atoi(strings.TrimSpace(lo))
			h, _ := strconv.Atoi(strings.TrimSpace(hi))
			out = append(out, [2]uint16{uint16(l), uint16(h)})
		} else {
			c, _ := strconv.Atoi(strings.TrimSpace(part))
			out = append(out, [2]uint16{uint16(c), uint16(c)})
		}
	}
	return out
}

// expectedCodeOK reports whether the HTTP status code falls within ANY parsed
// expected_codes pair. Replaces the old "2xx || 405" literal in the prober.
func expectedCodeOK(pairs [][2]uint16, code int) bool {
	c := uint16(code)
	for _, p := range pairs {
		if c >= p[0] && c <= p[1] {
			return true
		}
	}
	return false
}

type epHost struct {
	epKey        string
	hostName     string
	hostState    string
	ruleCount    int
	inactive     bool
	initProberOn bool
	sT           time.Time
	avgDelay     time.Duration
	minDelay     time.Duration
	maxDelay     time.Duration
	hID          uint8
	inActTries   int
	opts         epHostOpts
}

type ruleLBEp struct {
	xIP           net.IP
	rIP           net.IP
	xPort         uint16
	weight        uint8
	epRole        int    // P/D endpoint role: 0=normal, 1=prefill, 2=decode
	nixlPort      uint16 // NIXL side-channel port; 0=use xPort
	inActTries    int
	inActiveEP    bool
	noService     bool
	chkVal        bool
	epCreated     bool
	subnetId      string // opaque member subnet id, round-trip only, never interpreted
	backup        bool   // standby member flag; wires dataplane selection semantics
	monAddr       string // per-member health-probe address override; wires the prober
	selInactive   bool   // TRANSIENT per-DpCreate selection flag computed by applyMemberSelection in LB2DP (backup gating + weight=0 drain + admin pause). NOT membership/persistence state — NEVER mutate inActiveEP for selection, the GET serializer skips inActiveEP EPs so a weight=0/backup-standby EP must still round-trip.
	stat          ruleStat
	foldEndPoints []ruleLBEp
	foldRuleKey   string
}

type ruleLBSIP struct {
	sIP net.IP
}

type ruleLBActs struct {
	mode      cmn.LBMode
	sel       cmn.EpSelect
	endPoints []ruleLBEp
}

type ruleFwOpt struct {
	rdrMirr  string
	rdrPort  string
	fwMark   uint32
	record   bool
	snatIP   string
	snatPort uint16
	onDflt   bool
}

type ruleFwOpts struct {
	op  ruleTActType
	opt ruleFwOpt
}

type ruleTAct interface{}

type ruleAct struct {
	actType ruleTActType
	action  ruleTAct
}

type ruleStat struct {
	bytes   uint64
	packets uint64
}

type ruleProbe struct {
	actChk     bool
	prbType    string
	prbPort    uint16
	prbReq     string
	prbResp    string
	prbTimeo   uint32
	prbRetries int
}

type ruleEnt struct {
	zone                        *Zone
	ruleNum                     uint64
	sync                        DpStatusT
	tuples                      ruleTuples
	ci                          string
	hChk                        ruleProbe
	managed                     bool
	bgp                         bool
	addrRslv                    bool
	sT                          time.Time
	iTO                         uint32
	pTO                         uint32
	act                         ruleAct
	privIP                      net.IP
	secIP                       []ruleLBSIP
	stat                        ruleStat
	name                        string
	inst                        string
	secMode                     cmn.LBSec
	ppv2En                      bool
	egress                      bool
	traceType                   string                  // Tracing catalog name for deep inspection
	tracingCatalogID            uint16                  // Resolved catalog_id for tracing (0 = no tracing)
	backendProtocol             string                  // Backend protocol capability: "http1", "http2", or "both"
	sessionHeaderName           string                  // Custom session header for persist mode (e.g., "mcp-session-id")
	sseMode                     bool                    // SSE mode: suppress idle-timeout during streaming
	maxStreamDurationSec        uint32                  // Absolute wall-clock cap for SSE streams in seconds
	backendKeepaliveIntervalSec uint32                  // Backend SO_KEEPALIVE+TCP_KEEPIDLE interval in seconds
	timeoutMemberConnectMs      uint32                  // backend connect-poll deadline in ms (0=500ms default)
	timeoutMemberDataMs         uint32                  // member-side relay idle deadline in ms (0=existing idle)
	timeoutTcpInspectMs         uint32                  // header-accumulation deadline in ms (0=bounded default)
	alpnProtocols               []string                // ALPN list → backend_protocol_cap on listener+pool
	tlsCiphers                  string                  // inline OpenSSL cipher string (empty=hardcoded)
	tlsVersions                 []string                // version list → tls_version_min/max range
	hstsMaxAge                  uint32                  // HSTS max-age (0=no injection)
	hstsIncludeSubdomains       bool                    // "; includeSubDomains"
	hstsPreload                 bool                    // "; preload"
	backendCaCertId             string                  // backend CA certId (empty=system default)
	backendClientCertId         string                  // backend client certId (empty=none)
	pdDisaggMode                bool                    // P/D disaggregation mode: orchestrate prefill→decode flow
	pdCacheAwareMode            bool                    // P/D cache-aware routing: session + trie + min-load (US-PD801)
	pdSessionTTLSec             uint32                  // Session stickiness TTL in seconds (0 = no expiry)
	pdCacheThreshold            uint8                   // Cache match threshold (0-100, default 20)
	pdBalanceAbsThreshold       uint8                   // Load imbalance threshold (default 3)
	cbEnable                    bool                    // per-endpoint circuit breaker for full-proxy rules
	kvExactMode                 uint8                   // KV-cache exact routing: 0=off, 1=zmq P/D, 2=nats (reserved), 3=zmq single-role
	kvBlockSize                 uint32                  // Token block size for KV hash computation
	kvHashAlgo                  string                  // "sha256_cbor" or "xxhash_cbor"
	kvZmqPort                   uint16                  // ZMQ PUB port (default 5557)
	kvWarmupSec                 uint32                  // Warmup seconds before Tier 1.5 activates
	kvEngineType                string                  // KV-event engine: ""/"vllm" (default) or "sglang" — immutable after create
	kvDpRankCount               uint16                  // SGLang DP rank count (1..8, 0 ⇒ 1; rank N publishes at kvZmqPort+N)
	pdBootstrapPort             uint16                  // SGLang P/D bootstrap port on prefill EPs (0 ⇒ 8998 downstream)
	chwblPrefixHashLevel        int                     // CHWBL prefix hash level: 1, 2, or 3
	chwblPrefixHashFlags        int                     // CHWBL optional field flags bitfield
	chwblMeanLoadFactor         int                     // CHWBL max load factor percentage (100-300)
	chwblReplication            int                     // CHWBL virtual nodes per endpoint (1-1024)
	chwblEnableCacheSalt        bool                    // CHWBL require cache_salt field
	vllmScraper                 *VllmScraper            // vLLM metrics scraper for queue-depth routing (COMP-01)
	mtlsFrontend                *cmn.MTLSFrontendConfig // mTLS frontend configuration
	mtlsBackend                 *cmn.MTLSBackendConfig  // mTLS backend configuration
	srcList                     []*allowedSrcElem
	locIPs                      map[string]struct{}
	hwOffload                   bool              // FwRuleArg.HwOffload mirror, plumbed through Fw2DP to FwDpWorkQ.HwOffload
	id                          string            // stable opaque id (client-supplied verbatim, or minted UUIDv4)
	adminStateUp                bool              // EFFECTIVE resolved admin_state_up (nil/absent in body => true/enabled)
	lastUpdated                 time.Time         // in-memory only, reset-to-now on restart, NEVER serialized
	projectId                   string            // opaque tenant id, stored verbatim, filtered on GET /all (NOT authz)
	connLimit                   uint32            // per-service concurrent-connection ceiling (0 = unlimited); plumbed to the dataplane conn_limit
	activeConns                 uint64            // live concurrent-connection count, snapshotted each RulesSync from the datapath nat_ep_map conc_conns (selector-agnostic — the SAME notion of "current" the connLimit gate enforces; NOT the LC-only active_sess[]). In-memory, reset to 0 on restart.
	totalConns                  uint64            // cumulative connection count, snapshotted each RulesSync from the datapath nat_ep_map total_conns (++ on CT-create in the datapath so even sub-tick flows count; never decremented). In-memory, reset to 0 on restart.
	bytesIn                     uint64            // cumulative client->VIP request bytes = datapath cum_bytes_in (closed flows) + live CT_DIR_IN bytes (in-flight). Real per-direction split; NOT a 50/50 heuristic, NOT the direction-collapsed nat_stats_map. In-memory, reset on restart.
	bytesOut                    uint64            // cumulative VIP->client response bytes = datapath cum_bytes_out (closed flows) + live CT_DIR_OUT bytes (in-flight). In-memory, reset on restart.
	annotations                 map[string]string // opaque key/value map, round-tripped verbatim, never interpreted
	secVIPs                     []cmn.LbSecVIPArg // Octavia /07: structured secondary VIPs, stored opaque/round-tripped for ALL protocols; SEPARATE from the flat secIP slice (never merged), NOT SCTP-gated
}

type ruleTable struct {
	tableType  ruleTType
	tableMatch ruleTMatch
	eMap       map[string]*ruleEnt
	rArr       [RtMaximumLbs]*ruleEnt
	pMap       []*ruleEnt
	Mark       *utils.Marker
}

type ruleTableType uint

// rt types
const (
	RtFw ruleTableType = iota + 1
	RtLB
	RtMax
)

// rule specific loxilb constants
const (
	RtMaximumFw4s = (8 * 1024)
	RtMaximumLbs  = (2 * 1024)
	// RtMaximumFwActive caps the number of installed fw rules well below the
	// eBPF per-lookup tail-call ceiling (~33 tail calls, ~6400 rules), beyond
	// which the datapath would drop packets during the fw scan.
	RtMaximumFwActive = 6000
)

// RuleCfg - tunable parameters related to inactive rules
type RuleCfg struct {
	RuleInactTries   int
	RuleInactChkTime int
}

type epChecker struct {
	hChk *time.Ticker
	tD   chan bool
}

type vipElem struct {
	ref  int
	pVIP net.IP
	inst string
	egr  bool
}

type allowedSrcElem struct {
	ref     int
	srcPref *net.IPNet
	mark    uint64
	lbmark  uint32
}

// RuleH - context container
type RuleH struct {
	zone       *Zone
	cfg        RuleCfg
	tables     [RtMax]ruleTable
	epMap      map[string]*epHost
	vipMap     map[string]*vipElem
	srcMark    *tk.Counter
	lbSrcMap   map[string]*allowedSrcElem
	epCs       [MaxEndPointCheckers]epChecker
	wg         sync.WaitGroup
	lepHID     uint8
	epMx       sync.RWMutex
	rootCAPool *x509.CertPool
	tlsCert    tls.Certificate
	vipST      time.Time
	// opaqueID - Octavia : in-memory id->ruleEnt index. Rebuilt from persisted
	// config on restart (no separate persisted structure) since the id round-trips through
	// lbconfig.txt and replays via NetLbRuleAdd -> AddLbRule on boot.
	opaqueID map[string]*ruleEnt
}

// RulesInit - initialize the Rules subsystem
func RulesInit(zone *Zone) *RuleH {
	var nRh = new(RuleH)
	nRh.zone = zone

	nRh.cfg.RuleInactChkTime = DflLbaCheckTimeout
	nRh.cfg.RuleInactTries = DflLbaInactiveTries

	nRh.vipMap = make(map[string]*vipElem)
	nRh.epMap = make(map[string]*epHost)
	nRh.lbSrcMap = make(map[string]*allowedSrcElem)
	nRh.srcMark = tk.NewCounter(1, RtMaximumFw4s)
	nRh.tables[RtFw].tableMatch = RmMax - 1
	nRh.tables[RtFw].tableType = RtMf
	nRh.tables[RtFw].eMap = make(map[string]*ruleEnt)
	nRh.tables[RtFw].Mark = utils.NewMarker(1, RtMaximumFw4s)

	nRh.tables[RtLB].tableMatch = RmL3Dst | RmL4Dst | RmL4Prot
	nRh.tables[RtLB].tableType = RtEm
	nRh.tables[RtLB].eMap = make(map[string]*ruleEnt)
	nRh.tables[RtLB].Mark = utils.NewMarker(1, RtMaximumLbs)
	// opaque id -> rule index, rebuilt from persisted config on restart.
	nRh.opaqueID = make(map[string]*ruleEnt)

	for i := 0; i < MaxEndPointCheckers; i++ {
		nRh.epCs[i].tD = make(chan bool)
		nRh.epCs[i].hChk = time.NewTicker(EndPointCheckerDuration * time.Second)
		// B1: best-effort skip; relies on process exit (RESEARCH §Open Q5).
		go epTicker(nRh, i)
	}
	rootCAPool, err := x509.SystemCertPool()
	if err == nil {
		nRh.rootCAPool = rootCAPool
	} else {
		nRh.rootCAPool = x509.NewCertPool()
	}
	rootCACertile := cmn.CertPath + cmn.CACertFileName

	// Check if there exist a common CA certificate
	if exists := utils.FileExists(rootCACertile); exists {

		rootCA, err := os.ReadFile(rootCACertile)
		if err != nil {
			tk.LogIt(tk.LogError, "RootCA cert load failed : %v\n", err)
		} else {
			nRh.rootCAPool.AppendCertsFromPEM(rootCA)
			tk.LogIt(tk.LogDebug, "RootCA cert loaded\n")
		}
	}

	certFile := cmn.CertPath + cmn.PrivateCertName
	keyFile := cmn.CertPath + cmn.PrivateKeyName

	certExists := utils.FileExists(certFile)
	keyExists := utils.FileExists(keyFile)

	if certExists == true && keyExists == true {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			tk.LogIt(tk.LogError, "Error loading loxilb certificate %s and key file %s",
				certFile, keyFile)
		}
		nRh.tlsCert = cert
	}
	nRh.wg.Add(MaxEndPointCheckers)
	nRh.vipST = time.Now()

	return nRh
}

// lbPathMatchMode returns the canonical rule-key spelling of an LB rule's
// PathMatchMode. "disabled" (the REST handlers' backward-compat default) and
// "" (the zero value carried by config dumps, legacy *.txt replay, and
// snapshot documents) mean the same thing — no path matching — but keyed
// verbatim they produced two DIFFERENT rule keys for otherwise identical
// rules: a rule re-added from a dump/snapshot could not be found (404) or
// deduplicated by any REST tuple lookup (snapshot G-8/9 E2E finding). The
// datapath already folds both spellings to mode 0 (dpebpf_linux.go).
func lbPathMatchMode(mode string) string {
	if mode == "disabled" {
		return ""
	}
	return mode
}

func (r *ruleTuples) ruleKey() string {
	ks := ""
	if r.path != "" {
		ks += r.path
	}
	// P6: Include path prefix and match mode in rule key to support multiple rules per VIP:port
	if r.pathPrefix != "" {
		ks += "|" + r.pathPrefix
	}
	if r.pathMatchMode != "" {
		ks += "|" + r.pathMatchMode
	}
	// Include model name in rule key so rules differing only in ModelName are distinct
	if r.modelName != "" {
		ks += "|model:" + r.modelName
	}
	ks += fmt.Sprintf("%s", r.port.val)
	ks += fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		r.l2Dst.addr[0]&r.l2Dst.valid[0],
		r.l2Dst.addr[1]&r.l2Dst.valid[1],
		r.l2Dst.addr[2]&r.l2Dst.valid[2],
		r.l2Dst.addr[3]&r.l2Dst.valid[3],
		r.l2Dst.addr[4]&r.l2Dst.valid[4],
		r.l2Dst.addr[5]&r.l2Dst.valid[5])
	ks += fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		r.l2Src.addr[0]&r.l2Src.valid[0],
		r.l2Src.addr[1]&r.l2Src.valid[1],
		r.l2Src.addr[2]&r.l2Src.valid[2],
		r.l2Src.addr[3]&r.l2Src.valid[3],
		r.l2Src.addr[4]&r.l2Src.valid[4],
		r.l2Src.addr[5]&r.l2Src.valid[5])
	ks += fmt.Sprintf("%d", r.vlanID.val&r.vlanID.valid)
	ks += fmt.Sprintf("%s", r.l3Dst.addr.String())
	ks += fmt.Sprintf("%s", r.l3Src.addr.String())
	ks += fmt.Sprintf("%d", r.l4Prot.val&r.l4Prot.valid)

	// Tag and delimit port ranges so a src-port rule never collides with an
	// otherwise-identical dst-port rule, and exact port N (rendered N-N) never
	// collides with range that concatenated to the same digits (e.g. 1-23 vs 123).
	if r.l4Src.valid {
		ks += fmt.Sprintf("|sp:%d-%d", r.l4Src.valMin, r.l4Src.valMax)
	}

	if r.l4Dst.valid {
		ks += fmt.Sprintf("|dp:%d-%d", r.l4Dst.valMin, r.l4Dst.valMax)
	}

	ks += fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		r.inL2Dst.addr[0]&r.inL2Dst.valid[0],
		r.inL2Dst.addr[1]&r.inL2Dst.valid[1],
		r.inL2Dst.addr[2]&r.inL2Dst.valid[2],
		r.inL2Dst.addr[3]&r.inL2Dst.valid[3],
		r.inL2Dst.addr[4]&r.inL2Dst.valid[4],
		r.inL2Dst.addr[5]&r.inL2Dst.valid[5])
	ks += fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		r.inL2Src.addr[0]&r.inL2Src.valid[0],
		r.inL2Src.addr[1]&r.inL2Src.valid[1],
		r.inL2Src.addr[2]&r.inL2Src.valid[2],
		r.inL2Src.addr[3]&r.inL2Src.valid[3],
		r.inL2Src.addr[4]&r.inL2Src.valid[4],
		r.inL2Src.addr[5]&r.inL2Src.valid[5])

	ks += fmt.Sprintf("%s", r.inL3Dst.addr.String())
	ks += fmt.Sprintf("%s", r.inL3Src.addr.String())
	ks += fmt.Sprintf("%d", r.inL4Prot.val&r.inL4Prot.valid)
	if r.inL4Src.valid {
		ks += fmt.Sprintf("|isp:%d-%d", r.inL4Src.valMin, r.inL4Src.valMax)
	}
	if r.inL4Dst.valid {
		ks += fmt.Sprintf("|idp:%d-%d", r.inL4Dst.valMin, r.inL4Dst.valMax)
	}
	ks += fmt.Sprintf("|pref:%d", r.pref)
	return ks
}

func checkValidMACTuple(mt ruleMacTuple) bool {
	if mt.valid[0] != 0 ||
		mt.valid[1] != 0 ||
		mt.valid[2] != 0 ||
		mt.valid[3] != 0 ||
		mt.valid[4] != 0 ||
		mt.valid[5] != 0 {
		return true
	}
	return false
}

func (r *ruleTuples) String() string {

	ks := ""
	if r.path != "" {
		ks += fmt.Sprintf("%s:", r.path)
	}

	if r.port.val != "" {
		ks += fmt.Sprintf("inp-%s,", r.port.val)
	}

	if checkValidMACTuple(r.l2Dst) {
		ks += fmt.Sprintf("dmac-%02x:%02x:%02x:%02x:%02x:%02x,",
			r.l2Dst.addr[0]&r.l2Dst.valid[0],
			r.l2Dst.addr[1]&r.l2Dst.valid[1],
			r.l2Dst.addr[2]&r.l2Dst.valid[2],
			r.l2Dst.addr[3]&r.l2Dst.valid[3],
			r.l2Dst.addr[4]&r.l2Dst.valid[4],
			r.l2Dst.addr[5]&r.l2Dst.valid[5])
	}

	if checkValidMACTuple(r.l2Src) {
		ks += fmt.Sprintf("smac-%02x:%02x:%02x:%02x:%02x:%02x",
			r.l2Src.addr[0]&r.l2Src.valid[0],
			r.l2Src.addr[1]&r.l2Src.valid[1],
			r.l2Src.addr[2]&r.l2Src.valid[2],
			r.l2Src.addr[3]&r.l2Src.valid[3],
			r.l2Src.addr[4]&r.l2Src.valid[4],
			r.l2Src.addr[5]&r.l2Src.valid[5])
	}

	if r.vlanID.valid != 0 {
		ks += fmt.Sprintf("vid-%d,", r.vlanID.val&r.vlanID.valid)
	}

	if r.l3Dst.addr.String() != "<nil>" {
		ks += fmt.Sprintf("dst-%s,", r.l3Dst.addr.String())
	}

	if r.l3Src.addr.String() != "<nil>" {
		ks += fmt.Sprintf("src-%s,", r.l3Src.addr.String())
	}

	if r.l4Prot.valid != 0 {
		ks += fmt.Sprintf("proto-%d,", r.l4Prot.val&r.l4Prot.valid)
	}

	if r.l4Dst.valid {
		if r.l4Dst.valMin == r.l4Dst.valMax {
			ks += fmt.Sprintf("dport-%d,", r.l4Dst.valMin)
		} else {
			ks += fmt.Sprintf("dport-%d:%d,", r.l4Dst.valMin, r.l4Dst.valMax)
		}
	}

	if r.l4Src.valid {
		if r.l4Src.valMin == r.l4Src.valMax {
			ks += fmt.Sprintf("sport-%d,", r.l4Src.valMin)
		} else {
			ks += fmt.Sprintf("sport-%d:%d,", r.l4Src.valMin, r.l4Src.valMax)
		}
	}

	if checkValidMACTuple(r.inL2Dst) {
		ks += fmt.Sprintf("idmac-%02x:%02x:%02x:%02x:%02x:%02x,",
			r.inL2Dst.addr[0]&r.inL2Dst.valid[0],
			r.inL2Dst.addr[1]&r.inL2Dst.valid[1],
			r.inL2Dst.addr[2]&r.inL2Dst.valid[2],
			r.inL2Dst.addr[3]&r.inL2Dst.valid[3],
			r.inL2Dst.addr[4]&r.inL2Dst.valid[4],
			r.inL2Dst.addr[5]&r.inL2Dst.valid[5])
	}

	if checkValidMACTuple(r.inL2Src) {
		ks += fmt.Sprintf("ismac-%02x:%02x:%02x:%02x:%02x:%02x,",
			r.inL2Src.addr[0]&r.inL2Src.valid[0],
			r.inL2Src.addr[1]&r.inL2Src.valid[1],
			r.inL2Src.addr[2]&r.inL2Src.valid[2],
			r.inL2Src.addr[3]&r.inL2Src.valid[3],
			r.inL2Src.addr[4]&r.inL2Src.valid[4],
			r.inL2Src.addr[5]&r.inL2Src.valid[5])
	}

	if r.inL3Dst.addr.String() != "<nil>" {
		ks += fmt.Sprintf("idst-%s,", r.inL3Dst.addr.String())
	}

	if r.inL3Src.addr.String() != "<nil>" {
		ks += fmt.Sprintf("isrc-%s,", r.inL3Src.addr.String())
	}

	if r.inL4Prot.valid != 0 {
		ks += fmt.Sprintf("iproto-%d,", r.inL4Prot.val&r.inL4Prot.valid)
	}

	if r.inL4Dst.valid {
		if r.inL4Dst.valMin == r.inL4Dst.valMax {
			ks += fmt.Sprintf("idport-%d,", r.inL4Dst.valMin)
		} else {
			ks += fmt.Sprintf("idport-%d:%d,", r.inL4Dst.valMin, r.inL4Dst.valMax)
		}
	}

	if r.inL4Src.valid {
		if r.inL4Src.valMin == r.inL4Src.valMax {
			ks += fmt.Sprintf("isport-%d,", r.inL4Src.valMin)
		} else {
			ks += fmt.Sprintf("isport-%d:%d,", r.inL4Src.valMin, r.inL4Src.valMax)
		}
	}

	return ks
}

func (a *ruleAct) String() string {
	var ks string

	if a.actType == RtActDrop {
		ks += fmt.Sprintf("%s", "drop")
	} else if a.actType == RtActFwd {
		ks += fmt.Sprintf("%s", "allow")
	} else if a.actType == RtActTrap {
		ks += fmt.Sprintf("%s", "trap")
	} else if a.actType == RtActDnat ||
		a.actType == RtActSnat ||
		a.actType == RtActFullNat ||
		a.actType == RtActFullProxy {
		if a.actType == RtActSnat {
			ks += fmt.Sprintf("%s", "do-snat:")
		} else if a.actType == RtActDnat {
			ks += fmt.Sprintf("%s", "do-dnat:")
		} else if a.actType == RtActFullProxy {
			ks += fmt.Sprintf("%s", "do-fullproxy:")
		} else {
			ks += fmt.Sprintf("%s", "do-fullnat:")
		}

		switch na := a.action.(type) {
		case *ruleLBActs:
			if na.mode == cmn.LBModeOneArm {
				ks += fmt.Sprintf("%s", "onearm:")
			} else if na.mode == cmn.LBModeHostOneArm {
				ks += fmt.Sprintf("%s", "armhost:")
			}
			for _, n := range na.endPoints {
				if len(n.foldEndPoints) > 0 {
					for _, nf := range n.foldEndPoints {
						ks += fmt.Sprintf("feip-%s,fep-%d,fw-%d,",
							nf.xIP.String(), nf.xPort, nf.weight)
						if nf.inActiveEP || nf.noService {
							ks += fmt.Sprintf("dead|")
						} else {
							ks += fmt.Sprintf("alive|")
						}
					}
				} else {
					ks += fmt.Sprintf("eip-%s,ep-%d,w-%d,",
						n.xIP.String(), n.xPort, n.weight)
					if n.inActiveEP || n.noService {
						ks += fmt.Sprintf("dead|")
					} else {
						ks += fmt.Sprintf("alive|")
					}
				}
			}
		case *ruleFwOpts:
			if na.opt.fwMark != 0 {
				ks += fmt.Sprintf("Mark:%v ", na.opt.fwMark)
			}
			if a.actType == RtActSnat {
				ks += fmt.Sprintf("%s:%d ", na.opt.snatIP, na.opt.snatPort)
			}
			if na.opt.onDflt {
				ks += fmt.Sprintf("egress ")
			}
		}
	}

	return ks
}

// Rules2Json - output all rules into json and write to the byte array
func (R *RuleH) Rules2Json() ([]byte, error) {
	var t cmn.LbServiceArg
	var eps []cmn.LbEndPointArg
	var ret cmn.LbRuleMod
	var bret []byte
	for _, data := range R.tables[RtLB].eMap {
		// Make Service Arguments
		t.ServIP = data.tuples.l3Dst.addr.IP.String()
		if data.tuples.l4Prot.val == 6 {
			t.Proto = "tcp"
		} else if data.tuples.l4Prot.val == 17 {
			t.Proto = "udp"
		} else if data.tuples.l4Prot.val == 1 {
			t.Proto = "icmp"
		} else if data.tuples.l4Prot.val == 132 {
			t.Proto = "sctp"
		} else {
			return nil, errors.New("malformed service proto")
		}
		t.ServPort = data.tuples.l4Dst.valMin
		t.ServPortMax = data.tuples.l4Dst.valMax
		t.Sel = data.act.action.(*ruleLBActs).sel
		t.Mode = data.act.action.(*ruleLBActs).mode

		// Make Endpoints
		tmpEp := data.act.action.(*ruleLBActs).endPoints
		for _, ep := range tmpEp {
			eps = append(eps, cmn.LbEndPointArg{
				EpIP:     ep.xIP.String(),
				EpPort:   ep.xPort,
				Weight:   ep.weight,
				EpRole:   ep.epRole,
				NixlPort: ep.nixlPort,
			})
		}
		// Make LB rule
		ret.Serv = t
		ret.Eps = eps

		js, err := json.Marshal(ret)
		if err != nil {
			return nil, err
		}
		bret = append(bret, js...)
	}

	return bret, nil
}

// GetLBRule - get all rules and pack them into a cmn.LbRuleMod slice
func (R *RuleH) GetLBRule() ([]cmn.LbRuleMod, error) {
	var res []cmn.LbRuleMod

	for _, data := range R.tables[RtLB].eMap {
		var ret cmn.LbRuleMod
		// Make Service Arguments
		ret.Serv.ServIP = data.tuples.l3Dst.addr.IP.String()
		if data.tuples.l4Prot.val == 6 {
			ret.Serv.Proto = "tcp"
		} else if data.tuples.l4Prot.val == 17 {
			ret.Serv.Proto = "udp"
		} else if data.tuples.l4Prot.val == 1 {
			ret.Serv.Proto = "icmp"
		} else if data.tuples.l4Prot.val == 132 {
			ret.Serv.Proto = "sctp"
		} else if data.tuples.l4Prot.val == 0 {
			ret.Serv.Proto = "none"
		} else {
			return []cmn.LbRuleMod{}, errors.New("malformed service proto")
		}
		ret.Serv.ServPort = data.tuples.l4Dst.valMin
		ret.Serv.ServPortMax = data.tuples.l4Dst.valMax
		if ret.Serv.ServPort == ret.Serv.ServPortMax {
			ret.Serv.ServPortMax = 0
		}
		ret.Serv.Sel = data.act.action.(*ruleLBActs).sel
		ret.Serv.Mode = data.act.action.(*ruleLBActs).mode
		ret.Serv.Monitor = data.hChk.actChk
		ret.Serv.InactiveTimeout = data.iTO
		ret.Serv.Bgp = data.bgp
		ret.Serv.BlockNum = data.tuples.pref
		ret.Serv.Managed = data.managed
		ret.Serv.Security = data.secMode
		ret.Serv.ProbeType = data.hChk.prbType
		ret.Serv.ProbePort = data.hChk.prbPort
		ret.Serv.ProbeReq = data.hChk.prbReq
		ret.Serv.ProbeResp = data.hChk.prbResp
		ret.Serv.ProbeTimeout = data.hChk.prbTimeo
		ret.Serv.ProbeRetries = data.hChk.prbRetries
		ret.Serv.Name = data.name
		ret.Serv.HostUrl = data.tuples.path
		ret.Serv.PathPrefix = data.tuples.pathPrefix       // P6: Return path prefix in GET
		ret.Serv.PathMatchMode = data.tuples.pathMatchMode // P6: Return path match mode in GET
		ret.Serv.ModelName = data.tuples.modelName         // Return model name in GET
		ret.Serv.ProxyProtocolV2 = data.ppv2En
		ret.Serv.Egress = data.egress
		ret.Serv.TraceType = data.traceType                 // Tracing catalog
		ret.Serv.BackendProtocol = data.backendProtocol     // Backend protocol capability
		ret.Serv.SessionHeaderName = data.sessionHeaderName // Custom session header for persist mode
		ret.Serv.SSEMode = data.sseMode                     // SSE streaming mode
		ret.Serv.MaxStreamDurationSec = data.maxStreamDurationSec
		ret.Serv.BackendKeepaliveIntervalSec = data.backendKeepaliveIntervalSec
		ret.Serv.TimeoutMemberConnect = data.timeoutMemberConnectMs // Octavia
		ret.Serv.TimeoutMemberData = data.timeoutMemberDataMs       // Octavia
		ret.Serv.TimeoutTcpInspect = data.timeoutTcpInspectMs       // Octavia
		// TLS-hardening fields — round-trip on GET.
		ret.Serv.AlpnProtocols = data.alpnProtocols
		ret.Serv.TlsCiphers = data.tlsCiphers
		ret.Serv.TlsVersions = data.tlsVersions
		ret.Serv.HstsMaxAge = data.hstsMaxAge
		ret.Serv.HstsIncludeSubdomains = data.hstsIncludeSubdomains
		ret.Serv.HstsPreload = data.hstsPreload
		ret.Serv.BackendCaCertId = data.backendCaCertId
		ret.Serv.BackendClientCertId = data.backendClientCertId
		ret.Serv.PDDisaggMode = data.pdDisaggMode         // P/D disaggregation mode
		ret.Serv.PDCacheAwareMode = data.pdCacheAwareMode // P/D cache-aware routing (US-PD801)
		ret.Serv.PDSessionTTLSec = data.pdSessionTTLSec
		ret.Serv.PDCacheThreshold = data.pdCacheThreshold
		ret.Serv.PDBalanceAbsThreshold = data.pdBalanceAbsThreshold
		ret.Serv.CbEnable = data.cbEnable
		ret.Serv.KvExactMode = data.kvExactMode // KV-cache exact routing
		ret.Serv.KvBlockSize = data.kvBlockSize
		ret.Serv.KvHashAlgo = data.kvHashAlgo
		ret.Serv.KvZmqPort = data.kvZmqPort
		ret.Serv.KvWarmupSec = data.kvWarmupSec
		ret.Serv.KvEngineType = data.kvEngineType // zero value ⇒ omitempty ⇒ absent on legacy rules
		ret.Serv.KvDpRankCount = data.kvDpRankCount
		ret.Serv.PDBootstrapPort = data.pdBootstrapPort // zero value ⇒ omitempty ⇒ absent on legacy rules
		// CHWBL configuration (sel=8)
		ret.Serv.CHWBLPrefixHashLevel = data.chwblPrefixHashLevel
		ret.Serv.CHWBLPrefixHashFlags = data.chwblPrefixHashFlags
		ret.Serv.CHWBLMeanLoadFactor = data.chwblMeanLoadFactor
		ret.Serv.CHWBLReplication = data.chwblReplication
		ret.Serv.CHWBLEnableCacheSalt = data.chwblEnableCacheSalt
		// mTLS configuration
		ret.Serv.MTLSFrontend = data.mtlsFrontend
		ret.Serv.MTLSBackend = data.mtlsBackend
		// surface the opaque id + effective admin_state on GET so they
		// round-trip through lbconfig.txt and are visible to clients. adminStateUp is the
		// EFFECTIVE resolved bool; expose as a pointer for merge-patch symmetry.
		ret.Serv.Id = data.id
		adminStateUp := data.adminStateUp
		ret.Serv.AdminStateUp = &adminStateUp
		// Octavia + : surface the opaque projectId + annotations
		// on GET so they round-trip through lbconfig.txt verbatim. Never interpreted.
		ret.Serv.ProjectId = data.projectId
		ret.Serv.Annotations = data.annotations
		// surface the per-service connectionLimit on GET so it
		// round-trips through lbconfig.txt and is visible to clients. 0 = unlimited (omitempty).
		ret.Serv.ConnectionLimit = data.connLimit
		// surface the per-rule statistics quad (recomputed each RulesSync from
		// the CT walk by DpCtStatsRollup) on the GET read path so GET .../stats serializes the
		// real {activeConnections, bytesIn, bytesOut, totalConnections}. All transient (json:"-")
		// — in-memory only, reset to zero on restart. activeConns is the same
		// selector-agnostic live count the connLimit gate enforces; bytesIn/bytesOut
		// are the real per-direction CT_DIR_IN/CT_DIR_OUT split ((a)).
		ret.Serv.ActiveConns = data.activeConns
		ret.Serv.TotalConns = data.totalConns
		ret.Serv.BytesIn = data.bytesIn
		ret.Serv.BytesOut = data.bytesOut
		// surface the in-memory last-mutation timestamp on the read
		// path so GET .../status reports the ACTUAL last mutation, not the request time.
		// Transient (json:"-") — never serialized to lbconfig.txt.
		ret.Serv.LastUpdated = data.lastUpdated
		if data.act.actType == RtActSnat {
			ret.Serv.Snat = true
		}

		for _, sip := range data.secIP {
			ret.SecIPs = append(ret.SecIPs, cmn.LbSecIPArg{SecIP: sip.sIP.String()})
		}

		// Octavia /07: structured secondaryVIPs round-trip for ALL protocols,
		// stored opaque on a slot SEPARATE from the flat SCTP secIP slice (never merged).
		ret.SecVIPs = append(ret.SecVIPs, data.secVIPs...)

		for _, src := range data.srcList {
			ret.SrcIPs = append(ret.SrcIPs, cmn.LbAllowedSrcIPArg{Prefix: src.srcPref.String()})
		}

		data.DP(DpStatsGetImm)

		// Make Endpoints
		tmpEp := data.act.action.(*ruleLBActs).endPoints
		for _, ep := range tmpEp {
			state := "active"
			if ep.noService {
				state = "inactive"
			}

			if ep.inActiveEP {
				continue
			}

			counterStr := fmt.Sprintf("%v:%v", ep.stat.packets, ep.stat.bytes)

			ret.Eps = append(ret.Eps, cmn.LbEndPointArg{
				EpIP:     ep.xIP.String(),
				EpPort:   ep.xPort,
				Weight:   ep.weight,
				EpRole:   ep.epRole,
				NixlPort: ep.nixlPort,
				// round-trip the additive member fields verbatim.
				// wires backup/monitorAddress dataplane behavior; subnetId is round-trip only.
				Backup:         ep.backup,
				SubnetId:       ep.subnetId,
				MonitorAddress: ep.monAddr,
				State:          state,
				Counters:       counterStr,
			})
		}
		// Make LB rule
		res = append(res, ret)
	}

	return res, nil
}

// validateXlateEPWeights - validate and adjust weights if necessary
func validateXlateEPWeights(servEndPoints []cmn.LbEndPointArg) (int, error) {
	sum := 0
	for _, se := range servEndPoints {
		sum += int(se.Weight)
	}

	if sum > 100 {
		return -1, errors.New("malformed-weight error")
	} else if sum < 100 {
		rem := (100 - sum) / len(servEndPoints)
		for idx := range servEndPoints {
			pSe := &servEndPoints[idx]
			pSe.Weight += uint8(rem)
		}
	}

	return 0, nil
}

// probeHost - Octavia : the health-probe target for an endpoint.
//
// When the endpoint sets a monitorAddress (monAddr), the health prober dials that IP
// (with the service-level probePort/monitorPort) instead of the traffic IP; when absent
// it falls back to the traffic IP — today's behavior, back-compat. Selection, CT, and
// traffic ALWAYS use the traffic IP (ep.xIP); monitorAddress affects the probe path ONLY.
//
// This single helper MUST be used at EVERY makeEPKey/AddEPHost/DeleteEPHost site for an
// endpoint so the probe key is SYMMETRIC across build (modNatEpHost), lookup
// (syncEPHostState2Rule), AND teardown (DeleteEPHost). An asymmetric key (build keyed on
// the monitor IP but lookup/teardown keyed on the traffic IP, or vice-versa) would
// permanently mismark the EP / leave a stale epMap entry (T-73-mismark).
//
// Per Assumption A1 / Open Q1, per-EP monitor_port is OUT of scope: the service-level
// probePort covers monitor_port, so only a distinct monitor *address* is wired here.
func probeHost(ep ruleLBEp) string {
	if ep.monAddr != "" {
		return ep.monAddr
	}
	return ep.xIP.String()
}

func (R *RuleH) modNatEpHost(r *ruleEnt, endpoints []ruleLBEp, doAddOp bool, liveCheckEn bool, egressEps bool) {
	var hopts epHostOpts
	pType := ""
	pPort := uint16(0)
	if r.hChk.prbRetries == 0 {
		hopts.inActTryThr = DflLbaInactiveTries
	} else {
		hopts.inActTryThr = r.hChk.prbRetries
	}
	if r.hChk.prbTimeo == 0 {
		hopts.probeDuration = DflHostProbeTimeout
	} else {
		hopts.probeDuration = r.hChk.prbTimeo
	}
	for idx := range endpoints {
		nep := &endpoints[idx]
		if r.tuples.l4Prot.val == 6 {
			pType = HostProbeConnectTCP
			pPort = nep.xPort
		} else if r.tuples.l4Prot.val == 17 {
			pType = HostProbeConnectUDP
			pPort = nep.xPort
		} else if r.tuples.l4Prot.val == 1 {
			pType = HostProbePing
		} else if r.tuples.l4Prot.val == 132 {
			pType = HostProbeConnectSCTP
			pPort = nep.xPort
		} else {
			pType = HostProbePing
		}

		if r.hChk.prbType != "" {
			// If probetype is specified as a part of rule,
			// override per end-point liveness settings
			hopts.probeType = r.hChk.prbType
			hopts.probePort = r.hChk.prbPort
			hopts.probeReq = r.hChk.prbReq
			hopts.probeResp = r.hChk.prbResp
		} else {
			hopts.probeType = pType
			hopts.probePort = pPort
		}

		if mh.pProbe || liveCheckEn {
			hopts.probeActivated = true
		}

		if egressEps {
			hopts.egress = true
		}

		// probe key + dial host use the monitor address when set
		// (probeHost), else the traffic IP. Build, teardown, AND the lookup site
		// (syncEPHostState2Rule) MUST all route through probeHost(nep) so the epMap key is
		// symmetric — an asymmetric key permanently mismarks the EP.
		pHost := probeHost(*nep)
		epKey := makeEPKey(pHost, pType, pPort)

		if doAddOp {
			if !nep.inActiveEP && !nep.epCreated {
				_, err := R.AddEPHost(false, pHost, epKey, hopts)
				if err == nil {
					nep.epCreated = true
				} else {
					tk.LogIt(tk.LogError, "add ep-host error %v : %s\n", epKey, err)
				}
			} else if nep.inActiveEP {
				nep.epCreated = false
			}
		} else {
			if nep.epCreated {
				_, err := R.DeleteEPHost(false, epKey, pHost, hopts.probeType, hopts.probePort)
				if err == nil {
					nep.epCreated = false
				} else {
					tk.LogIt(tk.LogError, "delete ep-host error %v : %s\n", epKey, err)
				}
			}
		}
	}
}

// GetLBRuleByID - Get a LB rule by its identifier
func (R *RuleH) GetLBRuleByID(ruleID uint32) *ruleEnt {
	if ruleID < RtMaximumLbs {
		return R.tables[RtLB].rArr[ruleID]
	}

	return nil
}

// resetRuleLiveStats - Octavia : zero every LB rule's statistics quad (activeConns,
// totalConns, bytesIn, bytesOut) before DpCtStatsRollup refills all four from the data plane
// this pass. Unlike the previous live-CT-walk design, totalConns and the cumulative byte totals
// are no longer accumulated in Go — they live in the datapath nat_ep_map, so the Go
// copy is just a per-pass snapshot of the authoritative counters and is safe to fully clear here.
// The caller (DpCtStatsRollup) holds the RuleH lock, so this reset+refill is atomic against a
// concurrent GET read.
func (R *RuleH) resetRuleLiveStats() {
	for _, rule := range R.tables[RtLB].eMap {
		rule.activeConns = 0
		rule.totalConns = 0
		rule.bytesIn = 0
		rule.bytesOut = 0
	}
}

// GetLBRuleByOpaqueID - Get a LB rule by its stable opaque id (Octavia).
// This keys on the client-supplied/minted UUID, NOT the internal ruleNum (use
// GetLBRuleByID for that). Returns nil when no rule carries the id.
//
// WR-05 CONCURRENCY CONTRACT: R.opaqueID is a plain map with NO internal synchronization;
// it is guarded by the same RuleH-wide lock that guards R.tables[RtLB].eMap. The CALLER
// MUST HOLD THE RuleH LOCK for the duration of this read — a concurrent register/unregister
// (AddLbRule/DeleteLbRule) is a map write and racing it here is a data race.
func (R *RuleH) GetLBRuleByOpaqueID(id string) *ruleEnt {
	if id == "" || R.opaqueID == nil {
		return nil
	}
	return R.opaqueID[id]
}

// resolveAdminStateUp - Octavia back-compat resolution: nil/absent (legacy
// lbconfig.txt entry or a POST that omits the field) resolves to enabled (true);
// only an explicit false pauses the rule.
func resolveAdminStateUp(v *bool) bool {
	return v == nil || *v
}

// Octavia input bounds (threat T-73-DOS): the opaque annotations map is
// stored verbatim but unbounded growth would bloat lbconfig.txt and the in-memory rule.
// Cap the key count and per-value length so a malicious/runaway driver cannot exhaust
// storage. Excess keys are dropped (deterministic by sorted key) and over-long values are
// truncated; contents are never interpreted. Returns nil for an empty/nil input.
const (
	maxAnnotationKeys   = 32
	maxAnnotationValLen = 256
)

func boundAnnotations(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(keys))
	for i, k := range keys {
		if i >= maxAnnotationKeys {
			break
		}
		v := in[k]
		if len(v) > maxAnnotationValLen {
			// Truncate on a rune boundary so a verbatim-round-trip annotation
			// is never stored as invalid/partial UTF-8 (WR-02): slicing by raw
			// byte count could split a multibyte sequence, which then serializes
			// back as U+FFFD and corrupts the driver's view of its own value.
			v = v[:maxAnnotationValLen]
			for len(v) > 0 && !utf8.ValidString(v) {
				v = v[:len(v)-1]
			}
		}
		out[k] = v
	}
	return out
}

// applyAdminStateUpDrain - Octavia block-new (Option B, STATE-BASED).
//
// adminUp is the EFFECTIVE admin_state of the rule (ruleEnt.adminStateUp, already
// resolved via resolveAdminStateUp in BOTH the new-rule/boot-replay path AND the
// existing-rule branch). When adminUp is false the service is paused: every built
// dataplane backend is marked InActive so that dp_sel_nat_ep yields sel=-1 (no
// selectable backend) and the NAT pipeline sets xf->pm.nf=0 — i.e. NEW flows are not
// forwarded (drain). Established conntrack entries match BEFORE backend selection in
// the eBPF pipeline, so in-flight connections are untouched and survive the pause.
//
// This is STATE-BASED, not transition-based: because it keys on the effective state
// and runs inside LB2DP (consulted by EVERY DpCreate — live add, boot replay, in-place
// PATCH mutate, member reconcile), a rule whose effective adminStateUp is false at
// creation/boot programs zero active backends immediately, so the pause SURVIVES a
// loxilb restart. A rule with nil/absent adminStateUp resolves to enabled=true and its
// backends are programmed UP — legacy rules are NEVER drained on load.
//
// keys ONLY on adminStateUp; it does NOT consult or mutate Managed/inActiveEP/
// per-EP membership. The endpoint membership set (ruleLBActs.endPoints) is authoritative
// and is left untouched — admin_state gates SELECTION, not membership. No DpRemove, no
// probe detach: the same in-place DpCreate carries both pause and resume (Assumptions A5).
//
// When adminUp is true the set is returned unchanged (normal active-backend programming).
func applyAdminStateUpDrain(eps []NatEP, adminUp bool) []NatEP {
	if adminUp {
		return eps
	}
	for i := range eps {
		eps[i].InActive = true
	}
	return eps
}

// isEffectivelyAvailable - Octavia unified "down" predicate.
//
// A backend is effectively available for traffic selection iff ALL of:
// - the SERVICE-level effective admin_state is up (svcAdminUp pause),
//   - the endpoint is NOT probe/health down (!inActiveEP && !noService), and
//   - the endpoint weight is non-zero (weight=0 drain — a weight=0 member blocks
//     NEW connections while keeping in-flight CT and staying in the rule).
//
// This is the single "down" definition that drives backup-tier gating: a primary is
// "down" for backup activation if it is probe-down OR weight=0 OR adminStateUp=false.
// (svcAdminUp is the SERVICE-level flag; if a future phase adds a per-EP
// admin_state it folds in here the same way.)
//
// CRITICAL: this is a READ-ONLY predicate over ruleLBEp metadata. It must
// NOT mutate inActiveEP (membership/persistence state — the GET serializer skips
// inActiveEP EPs at the serializer's `if ep.noService`/inActiveEP continue, so a
// weight=0/backup-standby EP would VANISH from GET). Selection is carried on the
// transient ruleLBEp.selInactive flag, computed fresh on every DpCreate.
func isEffectivelyAvailable(ep ruleLBEp, svcAdminUp bool) bool {
	if !svcAdminUp {
		return false // service pause — subsumes applyAdminStateUpDrain
	}
	if ep.inActiveEP || ep.noService {
		return false // probe-down / health-down
	}
	if ep.weight == 0 {
		return false // weight=0 drain
	}
	return true
}

// applyMemberSelection - Octavia tier-aware per-EP selection.
//
// SUBSUMES and replaces the blanket applyAdminStateUpDrain call in LB2DP: it folds in
// service admin_state (via the svcAdminUp gate inside isEffectivelyAvailable — all EPs
// go selInactive when paused) AND adds weight=0 drain + backup-tier gating.
//
// Semantics:
//   - A primary (backup=false) EP is selectable iff it is effectivelyAvailable.
//   - A backup (backup=true) EP is selectable iff it is effectivelyAvailable AND NO
//     primary is effectivelyAvailable (anyPrimaryUp==false). Backups therefore carry
//     ZERO traffic while any primary is up, and activate the instant ALL primaries are
//     down (probe-down / weight=0 / admin-paused).
//   - Immediate failback (no hysteresis): because this runs inside LB2DP — the single
//
// DpCreate funnel that the syncEPImmediate health-flip push re-enters — the
//
//	instant a primary recovers, anyPrimaryUp flips true and the backups go selInactive
//	again on the very next DpCreate.
//
// CRITICAL: this writes ONLY the transient ruleLBEp.selInactive flag, NEVER
// inActiveEP. Membership/persistence is left untouched so a weight=0 / backup-standby EP
// still round-trips on GET and survives reconcile. Selection flip only — the caller does
// NOT DpRemove or flush CT, so in-flight survives a tier/weight transition (T-73-ctflush).
func applyMemberSelection(eps []ruleLBEp, svcAdminUp bool) {
	anyPrimaryUp := false
	for i := range eps {
		if !eps[i].backup && isEffectivelyAvailable(eps[i], svcAdminUp) {
			anyPrimaryUp = true
			break
		}
	}
	for i := range eps {
		avail := isEffectivelyAvailable(eps[i], svcAdminUp)
		if eps[i].backup {
			// Backups carry traffic ONLY when no primary is effectively available.
			eps[i].selInactive = !(avail && !anyPrimaryUp)
		} else {
			eps[i].selInactive = !avail
		}
	}
}

// resolveOpaqueID - Octavia : resolve the opaque id for a rule being added.
// If supplied is empty, mint a UUIDv4. If supplied is non-empty and already maps to a
// DIFFERENT rule (different ruleKey), reject with a conflict sentinel. When it
// maps to the SAME rule (same ruleKey) it is a stable no-op. Does NOT mutate the index;
// the caller registers via registerOpaqueID after a successful add.
//
// WR-05 CONCURRENCY CONTRACT: reads R.opaqueID (a plain map, no internal sync). The CALLER
// MUST HOLD THE RuleH LOCK that also guards R.tables[RtLB].eMap.
func (R *RuleH) resolveOpaqueID(supplied string, r *ruleEnt) (string, error) {
	if supplied == "" {
		return uuid.NewString(), nil
	}
	if R.opaqueID != nil {
		if existing := R.opaqueID[supplied]; existing != nil && existing != r &&
			existing.tuples.ruleKey() != r.tuples.ruleKey() {
			return "", errors.New("lbrule-id conflict: id already bound to a different rule")
		}
	}
	return supplied, nil
}

// registerOpaqueID - Octavia : register r.id -> r in the opaque-id index. Idempotent
// for the same rule; called on both live add and boot replay.
//
// WR-05 CONCURRENCY CONTRACT: writes R.opaqueID (a plain map, no internal sync). The CALLER
// MUST HOLD THE RuleH LOCK that also guards R.tables[RtLB].eMap.
func (R *RuleH) registerOpaqueID(r *ruleEnt) {
	if r == nil || r.id == "" {
		return
	}
	if R.opaqueID == nil {
		R.opaqueID = make(map[string]*ruleEnt)
	}
	R.opaqueID[r.id] = r
}

// unregisterOpaqueID - Octavia : remove a rule's id from the opaque-id index on delete.
//
// WR-05 CONCURRENCY CONTRACT: writes R.opaqueID (a plain map, no internal sync). The CALLER
// MUST HOLD THE RuleH LOCK that also guards R.tables[RtLB].eMap.
func (R *RuleH) unregisterOpaqueID(r *ruleEnt) {
	if r == nil || r.id == "" || R.opaqueID == nil {
		return
	}
	if R.opaqueID[r.id] == r {
		delete(R.opaqueID, r.id)
	}
}

// GetLBRuleMarkByKey - Find LB rule matching the given key and return its mark (ruleNum).
// key format: "VIP:PORT:PROTO" (e.g., "20.20.20.1:5201:tcp") for exact match,
// or just "VIP" (e.g., "20.20.20.1") for first-match by IP only (legacy compat).
// Used QoS policer to associate DOCA meters with LB rules.
func (R *RuleH) GetLBRuleMarkByKey(key string) int {
	parts := strings.SplitN(key, ":", 3)
	vipIP := parts[0]
	var port uint16
	var proto uint8
	exactMatch := false
	if len(parts) == 3 {
		if p, err := strconv.ParseUint(parts[1], 10, 16); err == nil {
			port = uint16(p)
		}
		switch parts[2] {
		case "tcp":
			proto = 6
		case "udp":
			proto = 17
		case "sctp":
			proto = 132
		}
		exactMatch = true
	}

	for _, data := range R.tables[RtLB].eMap {
		if data.tuples.l3Dst.addr.IP.String() != vipIP {
			continue
		}
		if exactMatch {
			if data.tuples.l4Dst.valMin != port || data.tuples.l4Prot.val != proto {
				continue
			}
		}
		return int(data.ruleNum)
	}
	return 0
}

// GetLBRuleByServArgs - Get a LB rule by its service args
func (R *RuleH) GetLBRuleByServArgs(serv cmn.LbServiceArg) *ruleEnt {
	var ipProto uint8
	service := ""
	if tk.IsNetIPv4(serv.ServIP) {
		service = serv.ServIP + "/32"
	} else {
		service = serv.ServIP + "/128"
	}
	_, sNetAddr, err := net.ParseCIDR(service)
	if err != nil {
		return nil
	}

	if serv.Proto == "tcp" {
		ipProto = 6
	} else if serv.Proto == "udp" {
		ipProto = 17
	} else if serv.Proto == "icmp" {
		ipProto = 1
	} else if serv.Proto == "sctp" {
		ipProto = 132
	} else if serv.Proto == "none" {
		ipProto = 0
	} else {
		return nil
	}

	l4prot := rule8Tuple{ipProto, 0xff}
	l3dst := ruleIPTuple{*sNetAddr}
	l4dst := rule16RTuple{serv.ServPort, serv.ServPortMax, true}
	rt := ruleTuples{
		l3Dst:         l3dst,
		l4Prot:        l4prot,
		l4Dst:         l4dst,
		pref:          serv.BlockNum,
		path:          serv.HostUrl,
		pathPrefix:    serv.PathPrefix,                     // P6: Path prefix routing
		pathMatchMode: lbPathMatchMode(serv.PathMatchMode), // P6: Path match mode (canonicalized)
		modelName:     serv.ModelName,                      // AI model name for pool selection
	}
	return R.tables[RtLB].eMap[rt.ruleKey()]
}

// GetLBRuleSecIPs - Get secondary IPs for LB rule by its service args
func (R *RuleH) GetLBRuleSecIPs(serv cmn.LbServiceArg) []string {
	var ipProto uint8
	var ips []string
	service := ""
	if tk.IsNetIPv4(serv.ServIP) {
		service = serv.ServIP + "/32"
	} else {
		service = serv.ServIP + "/128"
	}
	_, sNetAddr, err := net.ParseCIDR(service)
	if err != nil {
		return nil
	}

	if serv.Proto == "sctp" {
		ipProto = 132
	} else {
		return nil
	}

	l4prot := rule8Tuple{ipProto, 0xff}
	l3dst := ruleIPTuple{*sNetAddr}
	l4dst := rule16RTuple{serv.ServPort, serv.ServPortMax, true}
	rt := ruleTuples{
		l3Dst:         l3dst,
		l4Prot:        l4prot,
		l4Dst:         l4dst,
		pref:          serv.BlockNum,
		path:          serv.HostUrl,
		pathPrefix:    serv.PathPrefix,                     // P6: Path prefix routing
		pathMatchMode: lbPathMatchMode(serv.PathMatchMode), // P6: Path match mode (canonicalized)
		modelName:     serv.ModelName,                      // AI model name for pool selection
	}
	if R.tables[RtLB].eMap[rt.ruleKey()] != nil {
		for _, ip := range R.tables[RtLB].eMap[rt.ruleKey()].secIP {
			ips = append(ips, ip.sIP.String())
		}
	}
	return ips
}

func (R *RuleH) addAllowedLbSrc(CIDR string, lbMark uint32) *allowedSrcElem {

	_, srcPref, err := net.ParseCIDR(CIDR)
	if err != nil {
		tk.LogIt(tk.LogError, "allowed-cidr parse failed\n")
		return nil
	}

	if lbMark > MaxSrcLBMarkerNum {
		tk.LogIt(tk.LogError, "allowed-src lbmark out-of-range\n")
		return nil
	}

	added := false
	srcElem := R.lbSrcMap[CIDR]
	if srcElem != nil {
		srcElem.lbmark |= 1 << lbMark
		srcElem.ref++
		added = true
		goto addFw
	}

	srcElem = new(allowedSrcElem)
	srcElem.ref = 1
	srcElem.srcPref = srcPref
	srcElem.lbmark = 1 << lbMark
	srcElem.mark, err = R.srcMark.GetCounter()
	if err != nil {
		tk.LogIt(tk.LogError, "allowed-cidr failed to alloc id\n")
		return nil
	}

addFw:
	fwarg := cmn.FwRuleArg{SrcIP: srcPref.String(), DstIP: "0.0.0.0/0"}
	if tk.IsNetIPv6(srcPref.String()) {
		fwarg.DstIP = "::/0"
	}
	fwOpts := cmn.FwOptArg{Allow: true, Mark: srcElem.lbmark | SrcChkFwMark}
	_, err = R.AddFwRule(fwarg, fwOpts)
	if err != nil {
		if !strings.Contains(err.Error(), "fwrule-exists") {
			R.srcMark.PutCounter(srcElem.mark)
			tk.LogIt(tk.LogError, "allowed-src failed to add fw %s\n", err)
			return nil
		}
	}

	if !added {
		R.lbSrcMap[CIDR] = srcElem
	}

	tk.LogIt(tk.LogInfo, "added allowed-cidr %s: 0x%x(%v)\n", srcPref.String(), srcElem.lbmark, srcElem.ref)

	return srcElem
}

func (R *RuleH) deleteAllowedLbSrc(CIDR string, lbMark uint32) error {
	srcElem := R.lbSrcMap[CIDR]
	if srcElem == nil {
		return errors.New("no such allowed src prefix")
	}

	if lbMark > MaxSrcLBMarkerNum {
		tk.LogIt(tk.LogError, "allowed-src lbmark out-of-range\n")
		return nil
	}

	srcElem.ref--

	if srcElem.ref == 0 {
		fwarg := cmn.FwRuleArg{SrcIP: srcElem.srcPref.String(), DstIP: "0.0.0.0/0"}
		if tk.IsNetIPv6(srcElem.srcPref.String()) {
			fwarg.DstIP = "::/0"
		}
		_, err := R.DeleteFwRule(fwarg)
		if err != nil {
			tk.LogIt(tk.LogError, "Failed to delete allowedSRC %s\n", srcElem.srcPref.String())
		}
		R.srcMark.PutCounter(srcElem.mark)
		delete(R.lbSrcMap, CIDR)
		tk.LogIt(tk.LogInfo, "delete allowed-cidr %s\n", srcElem.srcPref.String())
	} else {
		srcElem.lbmark &= ^(1 << lbMark)
		fwarg := cmn.FwRuleArg{SrcIP: srcElem.srcPref.String()}
		fwOpts := cmn.FwOptArg{Allow: true, Mark: srcElem.lbmark | SrcChkFwMark}
		R.AddFwRule(fwarg, fwOpts)
		tk.LogIt(tk.LogInfo, "updated allowed-cidr %s : 0x%x\n", srcElem.srcPref.String(), srcElem.lbmark)

	}

	return nil
}

func (R *RuleH) addLbRuleWithFW(Dst string, dPortMin, dPortMax uint16, proto uint8, lbMark uint32) error {

	// When this routine is called, we are certain all in-args are valid
	// So, these are not rechecked in this routine

	fwarg := cmn.FwRuleArg{SrcIP: "0.0.0.0/0", DstIP: Dst + "/32", DstPortMin: dPortMin, DstPortMax: dPortMax, Proto: proto}
	if tk.IsNetIPv6(Dst) {
		fwarg.SrcIP = "::/0"
		fwarg.DstIP = Dst + "/128"
	}
	fwOpts := cmn.FwOptArg{Allow: true, Mark: lbMark<<16 | NatFwMark}
	_, err := R.AddFwRule(fwarg, fwOpts)
	if err != nil {
		if !strings.Contains(err.Error(), "fwrule-exists") {
			tk.LogIt(tk.LogError, "lbRuleWithFW failed to add fw %v:%s\n", fwarg, err)
			return err
		}
	}

	tk.LogIt(tk.LogInfo, "lbRuleWithFW added fw %v\n", fwarg)

	return nil
}

func (R *RuleH) deleteLbRuleWithFW(Dst string, dPortMin, dPortMax uint16, proto uint8) error {

	// When this routine is called, we are certain all in-args are valid
	// So, these are not rechecked in this routine
	if tk.IsNetIPv6(Dst) {
		return errors.New("proto error")
	}

	fwarg := cmn.FwRuleArg{SrcIP: "0.0.0.0/0", DstIP: Dst + "/32", DstPortMin: dPortMin, DstPortMax: dPortMax, Proto: proto}
	_, err := R.DeleteFwRule(fwarg)
	if err != nil {
		tk.LogIt(tk.LogError, "lbRuleWithFW failed to delete fw %v:%s\n", fwarg, err)
		return err
	}

	tk.LogIt(tk.LogInfo, "lbRuleWithFW delete fw %v\n", fwarg)

	return nil
}

func (R *RuleH) electEPSrc(r *ruleEnt) bool {
	var sip net.IP
	var e int
	chg := false
	mode := "default"
	addrRslv := false

	switch na := r.act.action.(type) {
	case *ruleLBActs:
		{
			for idx := range na.endPoints {
				np := &na.endPoints[idx]

				if np.foldRuleKey != "" {
					fr := R.tables[RtLB].eMap[np.foldRuleKey]
					if fr == nil || fr.addrRslv {
						addrRslv = true
						continue
					}
				}
				sip = np.rIP
				if na.mode == cmn.LBModeOneArm || na.mode == cmn.LBModeHostOneArm {
					mode = "onearm"

					// First, try routing table lookup for the backend IP directly
					var err int
					var tDat tk.TrieData
					var routeIfObj string

					if tk.IsNetIPv4(np.xIP.String()) {
						err, _, tDat = R.zone.Rt.Trie4.FindTrie(np.xIP.String())
					} else {
						err, _, tDat = R.zone.Rt.Trie6.FindTrie(np.xIP.String())
					}

					if err == 0 {
						// Extract interface from routing table entry for backend IP
						switch rtn := tDat.(type) {
						case *Neigh:
							if rtn != nil && rtn.OifPort != nil {
								routeIfObj = rtn.OifPort.Name
							}
						case *int:
							p := R.zone.Ports.PortFindByOSID(*rtn)
							if p != nil {
								routeIfObj = p.Name
							}
						}

						// Get IP from the routed interface
						if routeIfObj != "" && routeIfObj != "lo" {
							rErr, rSip, _ := R.zone.L3.IfaSelect(routeIfObj, np.xIP, true)
							if rErr == 0 && !rSip.IsUnspecified() {
								// Check if this is the EIP interface - if so, we need to use default gateway instead
								if r.privIP != nil && !r.privIP.IsUnspecified() && rSip.Equal(r.privIP) {
									tk.LogIt(tk.LogDebug, "[OneARM] Route to %s uses EIP interface %s, looking up default gateway\n",
										np.xIP.String(), r.privIP.String())
									// Continue to default gateway lookup below
								} else {
									// Perfect! Use this interface
									sip = rSip
									tk.LogIt(tk.LogInfo, "[OneARM] Using routed interface %s (%s) for backend %s\n",
										routeIfObj, sip.String(), np.xIP.String())
									goto skipDefaultGW
								}
							}
						}
					}

					// If routing lookup failed or returned EIP interface, try default gateway
					if tk.IsNetIPv4(np.xIP.String()) {
						err, _, tDat = R.zone.Rt.Trie4.FindTrie("0.0.0.0")
					} else {
						err, _, tDat = R.zone.Rt.Trie6.FindTrie("::")
					}

					if err == 0 {
						gwIfObj := ""
						switch rtn := tDat.(type) {
						case *Neigh:
							if rtn != nil && rtn.OifPort != nil {
								gwIfObj = rtn.OifPort.Name
							}
						case *int:
							p := R.zone.Ports.PortFindByOSID(*rtn)
							if p != nil {
								gwIfObj = p.Name
							}
						}

						if gwIfObj != "" && gwIfObj != "lo" {
							gwErr, gwSip, _ := R.zone.L3.IfaSelect(gwIfObj, np.xIP, true)
							if gwErr == 0 && !gwSip.IsUnspecified() && !gwSip.Equal(r.privIP) {
								sip = gwSip
								tk.LogIt(tk.LogInfo, "[OneARM] Using default gateway interface %s (%s) for backend %s\n",
									gwIfObj, sip.String(), np.xIP.String())
							} else {
								tk.LogIt(tk.LogWarning, "[OneARM] Failed to get IP from default gateway interface %s\n", gwIfObj)
								// Fall back to unreliable IfaSelectAny
								e, sip, _ = R.zone.L3.IfaSelectAny(np.xIP, true)
								if e != 0 {
									tk.LogIt(tk.LogError, "[OneARM] All routing lookups failed for %s\n", np.xIP.String())
									addrRslv = true
								}
							}
						} else {
							tk.LogIt(tk.LogWarning, "[OneARM] Could not extract interface from default route\n")
							e, sip, _ = R.zone.L3.IfaSelectAny(np.xIP, true)
							if e != 0 {
								addrRslv = true
							}
						}
					} else {
						tk.LogIt(tk.LogWarning, "[OneARM] Default route lookup failed\n")
						e, sip, _ = R.zone.L3.IfaSelectAny(np.xIP, true)
						if e != 0 {
							addrRslv = true
						}
					}

				skipDefaultGW:
					if np.xIP.Equal(sip) {
						sip = net.IPv4(0, 0, 0, 0)
					}
				} else if na.mode == cmn.LBModeFullNAT {
					mode = "fullnat"
					if !mh.has.IsCIKAMode() {
						sip = r.RuleVIP2PrivIP()
						if np.xIP.Equal(sip) {
							sip = net.IPv4(0, 0, 0, 0)
						} else if utils.IsIPHostAddr(np.xIP.String()) {
							sip = net.IPv4(0, 0, 0, 0)
						}
					} else {
						vip, err := mh.has.CIVipGet(r.ci)
						if err == nil {
							tk.LogIt(tk.LogDebug, "vip for %s: %s\n", r.ci, vip.String())
							sip = vip
						} else {
							tk.LogIt(tk.LogError, "vip for %s not found \n", r.ci)
							addrRslv = true
						}
					}
				} else {
					serviceIP := r.tuples.l3Dst.addr.IP.Mask(r.tuples.l3Dst.addr.Mask)
					if tk.IsNetIPv6(serviceIP.String()) && tk.IsNetIPv4(np.xIP.String()) {
						e, sip, _ = r.zone.L3.IfaSelectAny(np.xIP, false)
						if e != 0 {
							addrRslv = true
						}
					} else {
						sip = net.IPv4(0, 0, 0, 0)
					}
				}

				if !np.rIP.Equal(sip) || r.addrRslv && !addrRslv {
					np.rIP = sip
					chg = true
					tk.LogIt(tk.LogDebug, "%s:suitable source for %s: %s\n", mode, np.xIP.String(), np.rIP.String())
				}
			}
		}
	}
	r.addrRslv = addrRslv
	return chg
}

func (R *RuleH) mkHostAssocs(r *ruleEnt) bool {
	chg := false
	curLocIPS := make(map[string]int)

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return chg
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsUnspecified() {
			// check if IPv4 or IPv6 is not nil
			if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
				if tk.IsNetIPv4(ipnet.IP.String()) && r.tuples.l3Dst.addr.IP.String() != ipnet.IP.String() {
					if _, found := curLocIPS[ipnet.IP.String()]; !found {
						curLocIPS[ipnet.IP.String()] = 0
					}
				}
			}
		}
	}

	for locIP := range r.locIPs {
		if _, found := curLocIPS[locIP]; found {
			curLocIPS[locIP]++
		} else {
			curLocIPS[locIP] = -1
		}
	}

	for clocIP, exists := range curLocIPS {
		if exists == 0 {
			chg = true
			r.locIPs[clocIP] = struct{}{}
			tk.LogIt(tk.LogInfo, "%s: added loc %s\n", r.tuples.String(), clocIP)
		} else if exists < 0 {
			chg = true
			delete(r.locIPs, clocIP)
			tk.LogIt(tk.LogInfo, "%s: deleted loc %s\n", r.tuples.String(), clocIP)
		}
	}

	return chg
}

func (R *RuleH) syncEPHostState2Rule(rule *ruleEnt, checkNow bool) bool {
	var sType string
	rChg := false
	if checkNow || time.Duration(time.Now().Sub(rule.sT).Seconds()) >= time.Duration(R.cfg.RuleInactChkTime) {
		switch na := rule.act.action.(type) {
		case *ruleLBActs:
			if rule.tuples.l4Prot.val == 6 {
				sType = HostProbeConnectTCP
			} else if rule.tuples.l4Prot.val == 17 {
				sType = HostProbeConnectUDP
			} else if rule.tuples.l4Prot.val == 1 {
				sType = HostProbePing
			} else if rule.tuples.l4Prot.val == 132 {
				sType = HostProbeConnectSCTP
			} else {
				return rChg
			}

			for idx, n := range na.endPoints {
				// look up by the SAME monitor-address key the build
				// site used (probeHost), so a monitorAddress-set EP's probe result maps back
				// to the EP (— asymmetric key permanently mismarks the EP).
				sOk := R.IsEPHostActive(makeEPKey(probeHost(n), sType, n.xPort))
				np := &na.endPoints[idx]
				if sOk == false {
					if np.noService == false {
						np.noService = true
						tk.LogIt(tk.LogDebug, "lb-rule service-down ep - %s:%s\n", sType, n.xIP.String())

						// P2.2: Lightweight health update (ONLY for FullProxy mode)
						if mh.dp != nil && mh.dp.DpHooks != nil && na.mode == cmn.LBModeFullProxy {
							svcIP := rule.tuples.l3Dst.addr.IP
							svcPort := rule.tuples.l4Dst.valMin
							proto := rule.tuples.l4Prot.val
							ret := mh.dp.DpHooks.DpLBEndpointHealthUpdate(svcIP, svcPort, proto, idx, true)
							if ret == 0 {
								// Lightweight update succeeded - no need for full rule sync
								tk.LogIt(tk.LogDebug, "P2: Lightweight EP health update succeeded (no full sync needed)\n")
							} else {
								// Fallback to full rule sync if lightweight update failed
								rChg = true
							}
						} else {
							// Non-FullProxy rules require full sync
							rChg = true
						}
					}
				} else {
					if n.noService {
						np.noService = false
						np.inActTries = 0
						tk.LogIt(tk.LogDebug, "lb-rule service-up ep - %s:%s\n", sType, n.xIP.String())

						// P2.2: Lightweight health update (ONLY for FullProxy mode)
						if mh.dp != nil && mh.dp.DpHooks != nil && na.mode == cmn.LBModeFullProxy {
							svcIP := rule.tuples.l3Dst.addr.IP
							svcPort := rule.tuples.l4Dst.valMin
							proto := rule.tuples.l4Prot.val
							ret := mh.dp.DpHooks.DpLBEndpointHealthUpdate(svcIP, svcPort, proto, idx, false)
							if ret == 0 {
								// Lightweight update succeeded - no need for full rule sync
								tk.LogIt(tk.LogDebug, "P2: Lightweight EP health update succeeded (no full sync needed)\n")
							} else {
								// Fallback to full rule sync if lightweight update failed
								rChg = true
							}
						} else {
							// Non-FullProxy rules require full sync
							rChg = true
						}
					}
				}
			}
			rule.sT = time.Now()
		}
	}

	return rChg
}

// foldRecursiveEPs - Check if this rule's key matches endpoint of another rule.
// If so, replace that rule's endpoints to this rule's endpoints
func (R *RuleH) foldRecursiveEPs(r *ruleEnt) {

	for _, tr := range R.tables[RtLB].eMap {
		switch atr := r.act.action.(type) {
		case *ruleLBActs:
			for i := range atr.endPoints {
				rep := &atr.endPoints[i]
				service := ""
				if tk.IsNetIPv4(rep.xIP.String()) {
					service = rep.xIP.String() + "/32"
				} else {
					service = rep.xIP.String() + "/128"
				}
				_, sNetAddr, err := net.ParseCIDR(service)
				if err != nil {
					continue
				}
				l4prot := rule8Tuple{r.tuples.l4Prot.val, 0xff}
				l3dst := ruleIPTuple{*sNetAddr}
				l4dst := rule16RTuple{rep.xPort, rep.xPort, true}
				rtk := ruleTuples{l3Dst: l3dst, l4Prot: l4prot, l4Dst: l4dst, pref: r.tuples.pref}
				if rtk.ruleKey() == tr.tuples.ruleKey() {
					rep.foldEndPoints = tr.act.action.(*ruleLBActs).endPoints
					rep.foldRuleKey = tr.tuples.ruleKey()
				}
			}
		}

		switch at := tr.act.action.(type) {
		case *ruleLBActs:
			if r.act.action.(*ruleLBActs).sel != at.sel || r.act.action.(*ruleLBActs).sel == cmn.LbSelPrio {
				continue
			}
			fold := false
			for i := range at.endPoints {
				ep := &at.endPoints[i]
				service := ""
				if tk.IsNetIPv4(ep.xIP.String()) {
					service = ep.xIP.String() + "/32"
				} else {
					service = ep.xIP.String() + "/128"
				}
				_, sNetAddr, err := net.ParseCIDR(service)
				if err != nil {
					continue
				}

				l4prot := rule8Tuple{r.tuples.l4Prot.val, 0xff}
				l3dst := ruleIPTuple{*sNetAddr}
				l4dst := rule16RTuple{ep.xPort, ep.xPort, true}
				rtk := ruleTuples{l3Dst: l3dst, l4Prot: l4prot, l4Dst: l4dst, pref: r.tuples.pref}
				if r.tuples.ruleKey() == rtk.ruleKey() {
					ep.foldEndPoints = r.act.action.(*ruleLBActs).endPoints
					ep.foldRuleKey = r.tuples.ruleKey()
					fold = true
				}
				if fold {
					tr.DP(DpCreate)
					tk.LogIt(tk.LogDebug, "lb-rule folded - %d:%s-%s\n", tr.ruleNum, tr.tuples.String(), tr.act.String())
				}
			}
		}
	}
}

// unFoldRecursiveEPs - Check if this rule's key matches endpoint of another rule.
// If so, replace that rule's original endpoint
func (R *RuleH) unFoldRecursiveEPs(r *ruleEnt) {

	selPolicy := cmn.LbSelRr
	switch at := r.act.action.(type) {
	case *ruleLBActs:
		selPolicy = at.sel
	}

	for _, tr := range R.tables[RtLB].eMap {
		if tr == r {
			continue
		}
		switch atr := r.act.action.(type) {
		case *ruleLBActs:
			for i := range atr.endPoints {
				rep := &atr.endPoints[i]
				if rep.foldRuleKey == tr.tuples.ruleKey() {
					rep.foldEndPoints = nil
					rep.foldRuleKey = ""
				}
			}
		}
		switch at := tr.act.action.(type) {
		case *ruleLBActs:
			if selPolicy != at.sel || selPolicy == cmn.LbSelPrio {
				continue
			}
			for i := range at.endPoints {
				ep := &at.endPoints[i]
				if r.tuples.ruleKey() == ep.foldRuleKey {
					ep.foldEndPoints = nil
					ep.foldRuleKey = ""
					tr.DP(DpCreate)
					tk.LogIt(tk.LogDebug, "lb-rule unfolded - %d:%s-%s\n", tr.ruleNum, tr.tuples.String(), tr.act.String())
				}
			}
		}
	}
}

// addVIPSys - system specific operations for VIPs of a LB rule
func (R *RuleH) addVIPSys(r *ruleEnt) {
	if r.act.actType != RtActSnat && !strings.Contains(r.name, "ipvs") && !strings.Contains(r.name, "static") {
		R.AddRuleVIP(r.tuples.l3Dst.addr.IP, r.RuleVIP2PrivIP(), r.inst, r.egress)

		// Take care of any secondary VIPs
		for _, sVIP := range r.secIP {
			R.AddRuleVIP(sVIP.sIP, sVIP.sIP, r.inst, r.egress)
		}
	}
}

// snapshotLBEndpoints returns a deep copy of an LB rule's endpoint slice so the
// pre-reconcile member set can be restored on an atomic-reconcile rollback
// The copy is independent of the original: the backing array, the per-EP
// net.IP byte slices (xIP/rIP) and any nested foldEndPoints are duplicated so that a
// later in-place mutation of the live slice (modNatEpHost / electEPSrc) cannot bleed
// into the snapshot. Endpoint identity is (xIP,xPort); the deep copy preserves
// that identity verbatim, which is what keeps an UNCHANGED member's conntrack marker
// intact when the snapshot is restored.
func snapshotLBEndpoints(eps []ruleLBEp) []ruleLBEp {
	if eps == nil {
		return nil
	}
	snap := make([]ruleLBEp, len(eps))
	for i := range eps {
		snap[i] = eps[i]
		if eps[i].xIP != nil {
			snap[i].xIP = append(net.IP(nil), eps[i].xIP...)
		}
		if eps[i].rIP != nil {
			snap[i].rIP = append(net.IP(nil), eps[i].rIP...)
		}
		if eps[i].foldEndPoints != nil {
			snap[i].foldEndPoints = snapshotLBEndpoints(eps[i].foldEndPoints)
		}
	}
	return snap
}

// lbEndpointsAddedSince returns the subset of desired endpoints whose (xIP,xPort)
// identity is NOT present in the old set — i.e. the members genuinely ADDED by a
// reconcile. It is used on the atomic-reconcile rollback path (WR-02): only
// the genuinely-new members must be detached on rollback, so an UNCHANGED, CT-bearing
// member that was present pre-reconcile is NEVER detached/re-attached (no churn). The
// returned slice aliases the desired entries (read-only on the rollback path).
func lbEndpointsAddedSince(oldEps, desired []ruleLBEp) []ruleLBEp {
	var added []ruleLBEp
	for i := range desired {
		d := &desired[i]
		found := false
		for j := range oldEps {
			o := &oldEps[j]
			if d.xIP.Equal(o.xIP) && d.xPort == o.xPort {
				found = true
				break
			}
		}
		if !found {
			added = append(added, *d)
		}
	}
	return added
}

// reconcileLBEndpointsAtomic applies a declarative endpoint reconcile (retEps =
// desired set, delEps = members to detach) onto an existing LB rule with
// all-or-nothing semantics. It snapshots the pre-reconcile member set,
// performs the probe-registration detach/attach (modNatEpHost touches only the
// EP-host health-probe registry, NOT the conntrack map, so UNCHANGED members keep
// their CT —), re-elects the source, then pushes the dataplane via
// DpCreate. If the DpCreate push fails (non-zero rc), it ROLLS BACK in place: the
// snapshot is restored onto the rule, the original member set is re-attached via
// modNatEpHost, and DpCreate is re-pushed to restore the pre-PATCH dataplane state —
// the rule is left effectively unchanged and an error is returned for the PATCH
// handler to surface. Rollback NEVER uses DpRemove (it stays on the in-place
// DpCreate path). A no-op reconcile (retEps identical, no delEps) is a
// successful pass-through that performs the same attach/elect/push but never trips
// the rollback. Returns nil on success, a non-nil error on a rolled-back failure.
func (R *RuleH) reconcileLBEndpointsAtomic(eRule *ruleEnt, retEps []ruleLBEp, delEps []ruleLBEp, activateProbe bool) error {
	lbActs, ok := eRule.act.action.(*ruleLBActs)
	if !ok {
		return errors.New("lb-reconcile error: rule has no lb action")
	}

	// Snapshot the pre-reconcile member set for rollback (in-place, no DpRemove).
	snapshot := snapshotLBEndpoints(lbActs.endPoints)

	// Apply the declarative reconcile: detach removed (probe reg only), (re)attach
	// the desired set, re-elect source, then push to the dataplane in place.
	lbActs.endPoints = retEps
	R.modNatEpHost(eRule, delEps, false, activateProbe, eRule.egress)
	R.modNatEpHost(eRule, retEps, true, activateProbe, eRule.egress)
	R.electEPSrc(eRule)

	if rc := eRule.DP(DpCreate); rc != 0 {
		// Mid-reconcile dataplane push failed: restore the pre-PATCH member set and
		// re-push so the rule is left unchanged (atomic all-or-nothing —).
		tk.LogIt(tk.LogError, "lb-rule %s reconcile failed (rc=%d) - rolling back to pre-patch member set\n",
			eRule.tuples.String(), rc)
		lbActs.endPoints = snapshot
		// WR-02 / : detach ONLY the members genuinely ADDED by the failed
		// reconcile (desired-minus-snapshot by (xIP,xPort) identity), not the full retEps.
		// Detaching the whole desired set would churn the probe registration of UNCHANGED
		// members that were present pre-reconcile and must stay continuously attached. Then
		// re-attach the original snapshot members so the pre-PATCH state is restored exactly.
		addedEps := lbEndpointsAddedSince(snapshot, retEps)
		R.modNatEpHost(eRule, addedEps, false, activateProbe, eRule.egress)
		R.modNatEpHost(eRule, snapshot, true, activateProbe, eRule.egress)
		R.electEPSrc(eRule)
		eRule.DP(DpCreate)
		return errors.New("lb-rule reconcile error: endpoint set rolled back to pre-patch state")
	}

	return nil
}

func getLBConsolidatedEPs(oldEps []ruleLBEp, newEps []ruleLBEp, oper cmn.LBOp) (bool, []ruleLBEp, []ruleLBEp) {
	var retEps []ruleLBEp
	var delEps []ruleLBEp
	ruleChg := false
	found := false

	// Single pass: match endpoints and build retEps/delEps
	for i, eEp := range oldEps {
		e := &oldEps[i]
		matched := false

		// Check if this old endpoint exists in new endpoints
		for j, nEp := range newEps {
			if eEp.xIP.Equal(nEp.xIP) && eEp.xPort == nEp.xPort {
				n := &newEps[j]
				if eEp.inActiveEP && oper != cmn.LBOPDetach {
					ruleChg = true
					e.inActiveEP = false
				}
				if e.weight != nEp.weight {
					ruleChg = true
					e.weight = nEp.weight
				}
				e.chkVal = true
				n.chkVal = true
				matched = true
				found = true
				break
			}
		}

		// Handle based on oper type
		if oper == cmn.LBOPDetach {
			if e.chkVal {
				delEps = append(delEps, *e)
			} else {
				retEps = append(retEps, *e)
			}
		} else {
			// For default operation: keep matched or inactive endpoints, delete others
			if !matched && !eEp.inActiveEP {
				// Endpoint not in new list and not inactive -> mark for deletion
				ruleChg = true // Endpoint deletion is a rule change
				delEps = append(delEps, *e)
			} else {
				// Endpoint matched or is inactive -> keep in retEps
				retEps = append(retEps, *e)
			}
		}
	}

	// Remove LB arms from an existing LB
	if oper == cmn.LBOPDetach {
		if !found {
			return false, oldEps, nil
		}
		// Reset chkVal flags
		for i := range retEps {
			retEps[i].chkVal = false
		}
		for i := range delEps {
			delEps[i].chkVal = false
		}
		return true, retEps, delEps
	}

	// Attach LB endpoints to an existing LB
	for i, nEp := range newEps {
		n := &newEps[i]
		if !nEp.chkVal {
			ruleChg = true
			n.chkVal = true
			retEps = append(retEps, *n)
		}
	}

	for i, eEp := range retEps {
		e := &retEps[i]
		if !eEp.chkVal && oper == cmn.LBOPAdd {
			ruleChg = true
			e.inActiveEP = true
		}
		e.chkVal = false
	}

	return ruleChg, retEps, delEps
}

// strSliceEqual reports whether two string slices are element-wise equal (order-sensitive).
// Used by the LB-rule change detector for ALPN/TLS-version list fields, which
// cannot use != (slices are not comparable). nil and empty are treated as equal.
func strSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// KvExactModeSingleRole is the single-role KV-exact routing mode
// SGL-01). Mirrors sockproxy.h's kv_exact_mode enum: 0=off, 1=zmq (P/D),
// 2=nats (reserved), 3=zmq single-role. Under mode 3 the rule's endpoints carry
// no P/D roles (Assumption A2) and EVERY one of them publishes KV events, so
// the subscriber gate starts subscribers for ALL EPs — the Go half (Gate 2) of
// the Tier-1.5 decouple whose C half (Gate 1) landed.
const KvExactModeSingleRole uint8 = 3

// kvSubscriberTargets returns the endpoint indexes the KV subscriber gate must
// start subscribers for under the given kvExactMode (SGL-01 Gate 2):
//   - mode 1 (zmq P/D): prefill EPs only (epRole == 1) — the shipped KV-12
//     filter. AddLbRule's mode-1 loop stays textually verbatim for the
//     byte-identity discipline; this arm is its semantic twin, kept in lockstep
//     and pinned by TestKvSingleRoleSubscriberTargets so any future divergence
//
// is caught at remote gate.
//   - mode 3 (KvExactModeSingleRole): ALL EPs — single-role endpoints have no
//     roles, so there is nothing to filter on.
//   - any other mode (0=off, 2=nats reserved): no subscribers.
//
// Pure function: the gate's fan-out contract is unit-testable without a full
// rule fixture (pkg/loxinet is CGO — tests execute on the remote gate).
func kvSubscriberTargets(mode uint8, endPoints []ruleLBEp) []int {
	var targets []int
	switch mode {
	case 1:
		for i, ep := range endPoints {
			if ep.epRole == 1 {
				targets = append(targets, i)
			}
		}
	case KvExactModeSingleRole:
		for i := range endPoints {
			targets = append(targets, i)
		}
	}
	return targets
}

// kvEngineEffective resolves default: an absent kvEngineType means
// vllm (the established default-OFF pattern — absent field ⇒ today's behavior).
func kvEngineEffective(engine string) string {
	if engine == "" {
		return "vllm"
	}
	return engine
}

// kvEngineEqual reports whether two engine strings denote the SAME engine,
// treating "" and "vllm" as equal: a PUT that starts spelling
// the default out loud must not brick an existing rule.
func kvEngineEqual(a, b string) bool {
	return kvEngineEffective(a) == kvEngineEffective(b)
}

// kvEngineConfigValidate is (SGL-04) config-time input validation
// for the per-rule KV engine surface (ASVS V4/V5):
//   - kvEngineType allowlist: "", "vllm", "sglang", "trtllm", "llamacpp" —
//     unknown strings are REJECTED, never silently treated as vllm.
//   - kvDpRankCount bounds: 0 (default 1 downstream) or 18. Values >8
//     are rejected — rank N subscribes kvZmqPort+N on every EP host, so the
//     cap bounds the port-range walk.
//
// Pure function: unit-testable without a rule fixture (pkg/loxinet is CGO —
// tests execute at remote gate; kvSubscriberTargets
// precedent).
func kvEngineConfigValidate(engine string, dpRankCount uint16) error {
	switch engine {
	case "", "vllm", "sglang", "trtllm", "llamacpp":
	default:
		return errors.New("kv-engine-type must be one of \"vllm\", \"sglang\", \"trtllm\", \"llamacpp\"")
	}
	if dpRankCount > 8 {
		return errors.New("kv-dp-rank-count must be within 1..8 (0 = default 1)")
	}
	return nil
}

// kvTrtllmFeatureGuard rejects the TRT-LLM rule shapes the engine cannot
// speak, and the knobs that are structurally meaningless for it. Plain L7
// LB, single-role Tier-1.5 (kvExactMode=3) and P/D disaggregation with the
// P/D-coupled KV plane (pd_disagg_mode, kvExactMode=1 — both over the
// HTTP-polled event drain in ai_kv_trtllm_source.go, orchestrated by the
// pd_dialect_trtllm rewriter table in the C data plane) are accepted.
//
// The meaningless-knob rejections are deliberate loud failures: TRT-LLM KV
// events ride the EP's own serving port (no ZMQ, so kvZmqPort would be dead
// config) and expose no client-visible DP-rank concept (kvDpRankCount likewise
// — and its event_id sequences are per-attention-DP-rank, so accepting >1 here
// would arm a permanent gap-resync failure the rank-blind poller cannot
// survive).
//
// Pure function: unit-testable without a rule fixture (kvEngineConfigValidate
// precedent).
func kvTrtllmFeatureGuard(engine string, kvExactMode uint8, pdDisagg bool, zmqPort uint16, dpRankCount uint16) error {
	if kvEngineEffective(engine) != "trtllm" {
		return nil
	}
	if kvExactMode != 0 && kvExactMode != 1 &&
		kvExactMode != KvExactModeSingleRole {
		// Mode 2 (nats) is reserved; only the polled-drain shapes exist for
		// this engine.
		return errors.New("kv-engine-type trtllm supports kvExactMode 1 or 3 (HTTP-polled event plane)")
	}
	// 0 = absent; 5557 = the swagger default the API layer may materialize.
	if zmqPort != 0 && zmqPort != 5557 {
		return errors.New("kvZmqPort is meaningless for kv-engine-type trtllm (events ride the endpoint's serving port)")
	}
	if dpRankCount > 1 {
		return errors.New("kvDpRankCount is meaningless for kv-engine-type trtllm (no client-visible DP ranks)")
	}
	return nil
}

// kvLlamacppFeatureGuard rejects every KV/P/D rule shape for llama.cpp,
// because the engine has neither surface: no KV/cache event plane of any
// kind (nothing for a Tier-1.5 subscriber to consume — prompt caching is
// per-slot contiguous-prefix state plus a host-RAM store, not a
// content-addressed block pool) and no P/D disaggregation (the upstream
// design direction is server-internal, so the gateway will never need an
// orchestration dialect for it). The supported shape is plain L7 LB with
// CHWBL/session affinity — the engine-agnostic ladder, no engine-specific
// fields at all.
//
// The knob rejections are deliberate loud failures over silently-dead
// config: kvZmqPort/kvDpRankCount/kvBlockSize configure subscribers and
// hashing that can never run for this engine. 0 always passes; so do the
// swagger-materialized defaults (5557, 16) that the API layer may fill in.
//
// Pure function: unit-testable without a rule fixture (kvEngineConfigValidate
// precedent).
func kvLlamacppFeatureGuard(engine string, kvExactMode uint8, pdDisagg bool, zmqPort uint16, dpRankCount uint16, blockSize uint32) error {
	if kvEngineEffective(engine) != "llamacpp" {
		return nil
	}
	if kvExactMode != 0 {
		return errors.New("kvExactMode is unsupported for kv-engine-type llamacpp (no KV event plane; use select=chwbl for prefix affinity)")
	}
	if pdDisagg {
		return errors.New("pd_disagg_mode is unsupported for kv-engine-type llamacpp (engine has no P/D disaggregation)")
	}
	if zmqPort != 0 && zmqPort != 5557 {
		return errors.New("kvZmqPort is meaningless for kv-engine-type llamacpp (no KV event transport)")
	}
	if dpRankCount > 1 {
		return errors.New("kvDpRankCount is meaningless for kv-engine-type llamacpp (no client-visible DP ranks)")
	}
	if blockSize != 0 && blockSize != 16 {
		return errors.New("kvBlockSize is meaningless for kv-engine-type llamacpp (no block table, no gateway-side hashing)")
	}
	return nil
}

// kvHashAlgoEffective resolves the block-hash contract a rule actually runs.
// It mirrors dpebpf_linux.go's resolution order EXACTLY (the single source of
// truth for what the C data plane hashes with): an explicit kvHashAlgo always
// wins; an absent one takes the engine default — "sglang" ⇒ "sha256_sglang",
// "vllm"/absent ⇒ "sha256_cbor". Kept here so the config-time guard, the
// subscriber's self-describing inventory dump and the data plane cannot drift.
func kvHashAlgoEffective(algo, engine string) string {
	if algo != "" {
		return algo
	}
	switch kvEngineEffective(engine) {
	case "sglang":
		return "sha256_sglang"
	case "trtllm":
		return "blockhash_trtllm"
	}
	return "sha256_cbor"
}

// kvEngineAlgoTable is the engine → allowed-hash-algo coherence table (the
// structural replacement for the old boolean-XOR check, which could not admit
// a third engine). Every algo is exclusive to one engine family because the
// wire contracts are mutually exclusive: the vLLM cbor family CBOR-encodes and
// truncates to the LAST 8 digest bytes, and sha256_sglang hashes
// parent||tokens raw and takes the FIRST 8. blockhash_trtllm names the
// TRT-LLM binding of that same raw chained-SHA256 function, applied on BOTH
// sides by us — the C pager over request tokens and the event decoder over
// each stored block's token list (the engine's own unversioned uint64 mixing
// hash is deliberately never consumed as a routing key; it serves only as
// the decoder's local translation handle). A distinct name rather than
// "sha256_sglang" because the ENGINE binding differs (HTTP-drain events,
// full-block-only indexing) even though the digest math is shared.
var kvEngineAlgoTable = map[string]map[string]bool{
	"vllm":   {"sha256_cbor": true, "xxhash_cbor": true},
	"sglang": {"sha256_sglang": true},
	"trtllm": {"blockhash_trtllm": true},
	// llamacpp: EMPTY on purpose — the engine exports no block-hash contract
	// to mirror (no event plane, no block table), so no explicit kvHashAlgo
	// can ever be coherent. kvHashAlgoValidate turns the empty set into a
	// dedicated rejection message.
	"llamacpp": {},
}

// kvHashAlgoValidate rejects a kvHashAlgo that cannot serve the rule's engine.
//
// The failure this prevents is silent and total: the C hasher picks its
// contract from kv_hash_algo alone, so an engine/algo mismatch (e.g. an SGLang
// rule pinned to "sha256_cbor" because the API spec used to advertise it as the
// default) makes EVERY computed block hash miss the engine-published inventory.
// Tier 1.5 then scores zero forever with no config-time signal — only the
// [KV_ZEROHIT] watchdog eventually warns. The contracts are mutually exclusive:
// sha256_sglang hashes parent||tokens raw and truncates to the FIRST 8 digest
// bytes, where the vLLM cbor family CBOR-encodes and truncates to the LAST 8.
//
// An ABSENT algo is always accepted — that is the recommended shape, and
// kvHashAlgoEffective derives the coherent contract from the engine.
//
// Pure function: unit-testable without a rule fixture (pkg/loxinet is CGO —
// tests execute at the remote gate; kvEngineConfigValidate precedent).
func kvHashAlgoValidate(algo, engine string) error {
	if algo == "" {
		return nil // engine default — coherent by construction
	}
	known := false
	for _, algos := range kvEngineAlgoTable {
		if algos[algo] {
			known = true
			break
		}
	}
	if !known {
		return errors.New("kv-hash-algo must be one of \"sha256_cbor\", \"xxhash_cbor\", \"sha256_sglang\", \"blockhash_trtllm\"")
	}
	allowed := kvEngineAlgoTable[kvEngineEffective(engine)]
	if len(allowed) == 0 {
		// engines with an empty row (llamacpp) have NO hash contract at all —
		// "take the engine default" would be misleading advice here.
		return fmt.Errorf("kv-hash-algo %q is meaningless for kv-engine-type %q (no KV-exact tier; omit it)",
			algo, kvEngineEffective(engine))
	}
	if !allowed[algo] {
		return fmt.Errorf("kv-hash-algo %q is incompatible with kv-engine-type %q (omit kvHashAlgo to take the engine default %q)",
			algo, kvEngineEffective(engine), kvHashAlgoEffective("", engine))
	}
	return nil
}

// pdBootstrapPortValidate bounds the SGLang bootstrap-port knob to the only
// shape it means anything in: pdBootstrapPort is the disaggregation bootstrap
// port on every prefill EP, consumed exclusively by the SGLang P/D
// orchestrator when it injects the bootstrap triple. On a vLLM rule or a
// non-P/D rule the value would be silently dead config — reject it so a
// mis-pasted rule fails loudly at create time. Absent (0) always passes and
// defaults to SGLang's 8998 downstream.
//
// Pure function: unit-testable without a rule fixture (the
// kvEngineConfigValidate precedent).
func pdBootstrapPortValidate(port uint16, pdDisagg bool, engine string) error {
	if port != 0 && !(pdDisagg && kvEngineEffective(engine) == "sglang") {
		return errors.New("pd-bootstrap-port requires pd_disagg_mode=true and kv-engine-type sglang")
	}
	return nil
}

// kvEngineImmutabilityCheck is guard: kvEngineType on an existing
// rule is IMMUTABLE — delete+recreate is the sanctioned path (a live engine
// flip would silently re-key the whole Tier-1.5 hash space).
// ""≡"vllm" per kvEngineEqual. Returns the exact rejection error (paired with
// RuleExistsErr at the single AddLbRule call site) or nil when unchanged.
func kvEngineImmutabilityCheck(existing, incoming string) error {
	if !kvEngineEqual(existing, incoming) {
		return errors.New("lbrule-exist error: cant modify rule kv engine type (delete and recreate)")
	}
	return nil
}

// kvEngineMixDetect reports whether any co-VIP rule runs a DIFFERENT KV engine
// than the incoming rule. Mixing engines across ports of one VIP IP is
// ACCEPTED — that IS multi-framework coexistence story
// one framework per VIP:port is what the immutability guard enforces) — but
// it must be observable: the caller emits one WARN naming both engines.
// Returns the first differing engine's effective name.
func kvEngineMixDetect(newEngine string, otherEngines []string) (string, bool) {
	for _, e := range otherEngines {
		if !kvEngineEqual(newEngine, e) {
			return kvEngineEffective(e), true
		}
	}
	return "", false
}

// AddLbRule - Add a service LB rule. The service details are passed in serv argument,
// and end-point information is passed in the slice servEndPoints. On success,
// it will return 0 and nil error, else appropriate return code and error string will be set
func (R *RuleH) AddLbRule(serv cmn.LbServiceArg, servSecIPs []cmn.LbSecIPArg, servSecVIPs []cmn.LbSecVIPArg, allowedSources []cmn.LbAllowedSrcIPArg, servEndPoints []cmn.LbEndPointArg) (int, error) {
	var lBActs ruleLBActs
	var nSecIP []ruleLBSIP
	var ipProto uint8
	var privIP net.IP

	// Validate service args
	service := ""
	if tk.IsNetIPv4(serv.ServIP) {
		service = serv.ServIP + "/32"
		if service == "0.0.0.0/32" && serv.Egress && mh.has.ClusterGw != "" {
			service = mh.has.ClusterGw + "/32"
		}
	} else {
		service = serv.ServIP + "/128"
		if service == "::/128" && serv.Egress && mh.has.ClusterGw != "" {
			service = mh.has.ClusterGw + "/128"
		}
	}

	_, sNetAddr, err := net.ParseCIDR(service)
	if err != nil {
		return RuleUnknownServiceErr, errors.New("malformed-service error")
	}

	privIP = nil
	if serv.PrivateIP != "" {
		privIP = net.ParseIP(serv.PrivateIP)
		if privIP == nil {
			return RuleUnknownServiceErr, errors.New("malformed-service privateIP error")
		}
	}

	// Validate inactivity timeout
	if serv.InactiveTimeout > LbMaxInactiveTimeout {
		return RuleArgsErr, errors.New("service-args error")
	} else if serv.InactiveTimeout == 0 {
		serv.InactiveTimeout = LbDefaultInactiveTimeout
		if serv.Proto != "tcp" && serv.Proto != "sctp" {
			serv.InactiveTimeout = LbDefaultInactiveNSTimeout
		}
	}

	// Validate liveness probetype and port
	if serv.ProbeType != "" {
		if serv.ProbeType != HostProbeConnectSCTP &&
			serv.ProbeType != HostProbeConnectTCP &&
			serv.ProbeType != HostProbeConnectUDP &&
			serv.ProbeType != HostProbePing &&
			serv.ProbeType != HostProbeNone &&
			serv.ProbeType != HostProbeHTTP &&
			serv.ProbeType != HostProbeHTTPS {
			return RuleArgsErr, errors.New("malformed-service-ptype error")
		}

		if (serv.ProbeType == HostProbeConnectSCTP ||
			serv.ProbeType == HostProbeConnectTCP ||
			serv.ProbeType == HostProbeConnectUDP ||
			serv.ProbeType == HostProbeHTTP ||
			serv.ProbeType == HostProbeHTTPS) &&
			(serv.ProbePort == 0) {
			return RuleArgsErr, errors.New("malformed-service-pport error")
		}

		if (serv.ProbeType == HostProbeNone || serv.ProbeType == HostProbePing) &&
			(serv.ProbePort != 0) {
			return RuleArgsErr, errors.New("malformed-service-pport error")
		}

		// Override monitor flag to true if certain conditions meet
		if serv.ProbeType != HostProbeNone {
			serv.Monitor = true
		}
	} else if serv.ProbePort != 0 {
		return RuleArgsErr, errors.New("malformed-service-pport error")
	}

	// Currently support a maximum of MaxLBEndPoints
	if len(servEndPoints) <= 0 || len(servEndPoints) > MaxLBEndPoints {
		return RuleEpCountErr, errors.New("endpoints-range error")
	}

	// Validate persist timeout
	if serv.Sel == cmn.LbSelRrPersist {
		if serv.PersistTimeout == 0 || serv.PersistTimeout > 24*60*60 {
			serv.PersistTimeout = DefaultPersistTimeOut
		}
	}

	// For ICMP service, non-zero port can't be specified
	if serv.Proto == "icmp" && serv.ServPort != 0 {
		return RuleUnknownServiceErr, errors.New("malformed-service error")
	}

	if serv.ProxyProtocolV2 && serv.Proto != "tcp" {
		return RuleUnknownServiceErr, errors.New("proxy-proto-v2 not tcp service error")
	}

	if serv.Proto == "tcp" {
		ipProto = 6
	} else if serv.Proto == "udp" {
		ipProto = 17
	} else if serv.Proto == "icmp" {
		ipProto = 1
	} else if serv.Proto == "sctp" {
		ipProto = 132
	} else if serv.Proto == "none" {
		ipProto = 0
	} else {
		return RuleUnknownServiceErr, errors.New("malformed-proto error")
	}

	if serv.Proto != "sctp" && len(servSecIPs) > 0 {
		return RuleArgsErr, errors.New("secondaryIP-args error")
	}

	if serv.Proto != "udp" && serv.Sel == cmn.LbSelN3 {
		return RuleArgsErr, errors.New("non-udp-n3-args error")
	}

	if len(servSecIPs) > 3 {
		return RuleArgsErr, errors.New("secondaryIP-args len error")
	}

	if serv.ServPortMax != 0 && serv.ServPortMax < serv.ServPort {
		return RuleArgsErr, errors.New("serv-port-args range error")
	}

	activateProbe := false

	for _, k := range servSecIPs {
		pNetAddr := net.ParseIP(k.SecIP)
		if pNetAddr == nil {
			return RuleUnknownServiceErr, errors.New("malformed-secIP error")
		}
		if tk.IsNetIPv4(serv.ServIP) && tk.IsNetIPv6(k.SecIP) {
			return RuleUnknownServiceErr, errors.New("malformed-secIP nat46 error")
		}
		sip := ruleLBSIP{pNetAddr}
		nSecIP = append(nSecIP, sip)
	}

	sort.SliceStable(nSecIP, func(i, j int) bool {
		a := tk.IPtonl(nSecIP[i].sIP)
		b := tk.IPtonl(nSecIP[j].sIP)
		return a < b
	})

	if serv.Mode == cmn.LBModeHostOneArm && !sNetAddr.IP.IsUnspecified() {
		tk.LogIt(tk.LogInfo, "lb-rule %s-%v-%s hostarm needs unspec VIP\n", serv.ServIP, serv.ServPort, serv.Proto)
		return RuleArgsErr, errors.New("hostarm-args error")
	}

	lBActs.sel = serv.Sel
	lBActs.mode = cmn.LBMode(serv.Mode)

	if lBActs.mode == cmn.LBModeOneArm || lBActs.mode == cmn.LBModeFullNAT || lBActs.mode == cmn.LBModeHostOneArm || serv.Monitor {
		activateProbe = true
	}

	// [CP-DEBUG] Stage 1: AddLbRule entry - log service and endpoints
	tk.LogIt(tk.LogInfo, "[CP-DEBUG] AddLbRule: VIP=%s port=%d proto=%s mode=%d sel=%d eps=%d\n",
		serv.ServIP, serv.ServPort, serv.Proto, serv.Mode, serv.Sel, len(servEndPoints))
	for i, ep := range servEndPoints {
		tk.LogIt(tk.LogInfo, "[CP-DEBUG]   EP[%d] ip=%s port=%d weight=%d\n",
			i, ep.EpIP, ep.EpPort, ep.Weight)
	}

	for _, k := range servEndPoints {
		pNetAddr := net.ParseIP(k.EpIP)
		xNetAddr := net.IPv4(0, 0, 0, 0)
		if pNetAddr == nil {
			return RuleUnknownEpErr, errors.New("malformed-lbep error")
		}
		if tk.IsNetIPv4(serv.ServIP) && tk.IsNetIPv6(k.EpIP) {
			return RuleUnknownServiceErr, errors.New("malformed-service nat46 error")
		}
		if serv.Proto == "icmp" && k.EpPort != 0 {
			return RuleUnknownServiceErr, errors.New("malformed-service error")
		}

		if lBActs.mode == cmn.LBModeDSR && k.EpPort != serv.ServPort {
			return RuleUnknownServiceErr, errors.New("malformed-service dsr-port error")
		}
		// Keyed literal (was positional) so additive Octavia member fields (subnetId/backup/
		// monAddr) thread in without a fragile positional append. subnetId/backup/monAddr come
		// from the cmn.LbEndPointArg source k; wires backup/monAddr dataplane behavior.
		ep := ruleLBEp{
			xIP:      pNetAddr,
			rIP:      xNetAddr,
			xPort:    k.EpPort,
			weight:   k.Weight,
			epRole:   k.EpRole,
			nixlPort: k.NixlPort,
			subnetId: k.SubnetId,
			backup:   k.Backup,
			monAddr:  k.MonitorAddress,
			stat:     ruleStat{0, 0},
		}
		lBActs.endPoints = append(lBActs.endPoints, ep)
	}

	// L4/kernel vs L7/sockproxy selector guard. The request-content selectors below
	// (N2, CHWBL, GPU-aware, WRR-hash) have NO kernel-datapath implementation — their
	// selection runs entirely in the userspace sockproxy (PROXY_SEL_*), which only
	// fullproxy traffic reaches. In any non-fullproxy mode the rule is programmed as
	// DP_SET_DNAT, so the kernel selector dp_sel_nat_ep hits no matching sel_type case,
	// returns sel=-1 -> xf->pm.nf=0, and every SYN is silently black-holed. Reject at
	// config time with an actionable error instead of shipping a rule that dead-drops.
	// NOTE: LbSelPrio (WRR, sel=2) is intentionally NOT gated here — it IS kernel-capable
	// via control-plane weight-slot replication (LB2DP prio branch) + kernel round-robin.
	if lBActs.mode != cmn.LBModeFullProxy {
		switch lBActs.sel {
		case cmn.LbSelN2:
			return RuleUnknownServiceErr, errors.New("sel=n2(5) requires mode=fullproxy (no L4 datapath selector)")
		case cmn.LbSelCHWBL:
			return RuleUnknownServiceErr, errors.New("sel=chwbl(8) requires mode=fullproxy (no L4 datapath selector)")
		case cmn.LbSelGPUAware:
			return RuleUnknownServiceErr, errors.New("sel=gpu-aware(9) requires mode=fullproxy (no L4 datapath selector)")
		case cmn.LbSelWRRHash:
			return RuleUnknownServiceErr, errors.New("sel=wrr-hash(10) requires mode=fullproxy (no L4 datapath selector)")
		}
	}

	// P/D disaggregation validation
	if serv.PDDisaggMode {
		if lBActs.mode != cmn.LBModeFullProxy {
			return RuleUnknownServiceErr, errors.New("pd-disagg requires mode=fullproxy")
		}
		hasPrefill := false
		hasDecode := false
		for _, ep := range lBActs.endPoints {
			if ep.epRole == 1 {
				hasPrefill = true
			} else if ep.epRole == 2 {
				hasDecode = true
			}
		}
		if !hasPrefill || !hasDecode {
			return RuleUnknownServiceErr, errors.New("pd-disagg requires at least 1 prefill (ep_role=1) and 1 decode (ep_role=2) endpoint")
		}
	}

	// P/D cache-aware validation (US-PD801)
	if serv.PDCacheAwareMode {
		if !serv.PDDisaggMode {
			return RuleUnknownServiceErr, errors.New("pd-cache-aware requires pd_disagg_mode=true")
		}
	}

	// Single-role KV-exact validation (SGL-01)
	if serv.KvExactMode == KvExactModeSingleRole {
		// Mode 3 means role-less EPs; P/D means role-partitioned EPs — a rule
		// cannot be both (contradictory topology).
		if serv.PDDisaggMode {
			return RuleUnknownServiceErr, errors.New("kv-exact single-role mode is incompatible with pd-disagg (use kvExactMode=1 for P/D)")
		}
		// The Tier-1.5 selection hot path lives in sockproxy, which only
		// fullproxy traffic reaches. Mode 1 inherits this precondition via the
		// P/D validation above (pd-disagg requires mode=fullproxy); mirror it
		// here so mode 3 is never creatable in a topology where the seam can
		// never run.
		if lBActs.mode != cmn.LBModeFullProxy {
			return RuleUnknownServiceErr, errors.New("kv-exact single-role mode requires mode=fullproxy")
		}
	}

	// Mode-1 precondition, the sibling of the two mode-3 guards above. Tier 1.5
	// for kv_exact_mode==1 is reachable ONLY from pd_select_prefill(), whose
	// every call site sits inside the pd_disagg_enabled branch of the C endpoint
	// selector — so on a rule without pd-disagg, mode 1 populates inventories and
	// burns a subscriber goroutine per prefill EP while never influencing
	// selection. Rejecting it at config time turns a silent no-op (the "legacy
	// bring-up tooling" shape, doc 10 §6) into an actionable error.
	if serv.KvExactMode == 1 && !serv.PDDisaggMode {
		return RuleUnknownServiceErr, errors.New("kv-exact zmq mode requires pd_disagg_mode=true (use kvExactMode=3 for a single pool)")
	}

	// engine allowlist + DP rank bounds — covers
	// both the create and update paths (everything below flows through here).
	if err := kvEngineConfigValidate(serv.KvEngineType, serv.KvDpRankCount); err != nil {
		return RuleUnknownServiceErr, err
	}

	// engine ⇔ hash-algo coherence. Placed beside the engine allowlist so create
	// and update are both covered, and BEFORE the eRule lookup so an incoherent
	// pair can never reach the data plane. An absent kvHashAlgo (the recommended
	// shape) always passes.
	if err := kvHashAlgoValidate(serv.KvHashAlgo, serv.KvEngineType); err != nil {
		return RuleUnknownServiceErr, err
	}

	// pdBootstrapPort is meaningful only on an sglang P/D rule — anywhere else
	// it would be silently dead config.
	if err := pdBootstrapPortValidate(serv.PDBootstrapPort, serv.PDDisaggMode, serv.KvEngineType); err != nil {
		return RuleUnknownServiceErr, err
	}

	// TRT-LLM per-feature guards: plain LB is accepted today; KV-exact and P/D
	// stay rejected until their phases land, and the engine's meaningless knobs
	// (kvZmqPort, kvDpRankCount) fail loudly instead of riding as dead config.
	if err := kvTrtllmFeatureGuard(serv.KvEngineType, serv.KvExactMode, serv.PDDisaggMode, serv.KvZmqPort, serv.KvDpRankCount); err != nil {
		return RuleUnknownServiceErr, err
	}

	// llama.cpp per-feature guards: plain LB (+ CHWBL/session affinity) is the
	// whole supported surface — the engine has no KV event plane and no P/D,
	// so every kv*/pd* shape fails loudly instead of riding as dead config.
	if err := kvLlamacppFeatureGuard(serv.KvEngineType, serv.KvExactMode, serv.PDDisaggMode, serv.KvZmqPort, serv.KvDpRankCount, serv.KvBlockSize); err != nil {
		return RuleUnknownServiceErr, err
	}

	sort.SliceStable(lBActs.endPoints, func(i, j int) bool {
		a := tk.IPtonl(lBActs.endPoints[i].xIP)
		b := tk.IPtonl(lBActs.endPoints[j].xIP)
		return a < b
	})

	l4prot := rule8Tuple{ipProto, 0xff}
	l3dst := ruleIPTuple{*sNetAddr}
	servPortMax := serv.ServPort
	if serv.ServPortMax != 0 {
		servPortMax = serv.ServPortMax
	}
	l4dst := rule16RTuple{serv.ServPort, servPortMax, true}
	rt := ruleTuples{
		l3Dst:         l3dst,
		l4Prot:        l4prot,
		l4Dst:         l4dst,
		pref:          serv.BlockNum,
		path:          serv.HostUrl,
		pathPrefix:    serv.PathPrefix,                     // P6: Include path prefix in rule key
		pathMatchMode: lbPathMatchMode(serv.PathMatchMode), // P6: Include path match mode in rule key (canonicalized)
		modelName:     serv.ModelName,                      // AI model name for pool selection
	}
	tk.LogIt(tk.LogDebug, "lb-rule key (add): %q\n", rt.ruleKey())

	eRule := R.tables[RtLB].eMap[rt.ruleKey()]

	// two rules on the same VIP IP but different ports MAY run
	// different engines — that IS the multi-framework coexistence story. Accepted,
	// but observable: one WARN naming both engines.
	{
		var otherEngines []string
		for _, er := range R.tables[RtLB].eMap {
			if er != eRule && er.tuples.l3Dst.addr.IP.Equal(sNetAddr.IP) {
				otherEngines = append(otherEngines, er.kvEngineType)
			}
		}
		if other, mixed := kvEngineMixDetect(serv.KvEngineType, otherEngines); mixed {
			tk.LogIt(tk.LogWarning, "lb-rule %s:%d kv-engine mix on VIP: new=%s existing=%s (accepted — one framework per VIP:port)\n",
				serv.ServIP, serv.ServPort, kvEngineEffective(serv.KvEngineType), other)
		}
	}

	if eRule != nil {
		if !reflect.DeepEqual(eRule.secIP, nSecIP) {
			return RuleUnknownServiceErr, errors.New("secIP modify error")
		}
		// If a LB rule already exists, we try not reschuffle the order of the end-points.
		// We will try to append the new end-points at the end, while marking any other end-points
		// not in the new list as inactive
		ruleChg, retEps, delEps := getLBConsolidatedEPs(eRule.act.action.(*ruleLBActs).endPoints, lBActs.endPoints, serv.Oper)

		if eRule.hChk.prbType != serv.ProbeType || eRule.hChk.prbPort != serv.ProbePort ||
			eRule.hChk.prbReq != serv.ProbeReq || eRule.hChk.prbResp != serv.ProbeResp ||
			eRule.pTO != serv.PersistTimeout || eRule.act.action.(*ruleLBActs).sel != lBActs.sel ||
			eRule.act.action.(*ruleLBActs).mode != lBActs.mode ||
			eRule.ppv2En != serv.ProxyProtocolV2 ||
			eRule.hChk.actChk != serv.Monitor ||
			len(allowedSources) != len(eRule.srcList) {
			ruleChg = true
		}

		// Detect changes to all extended mutable fields
		if eRule.traceType != serv.TraceType ||
			eRule.backendProtocol != serv.BackendProtocol ||
			eRule.sessionHeaderName != serv.SessionHeaderName ||
			eRule.sseMode != serv.SSEMode ||
			eRule.maxStreamDurationSec != serv.MaxStreamDurationSec ||
			eRule.backendKeepaliveIntervalSec != serv.BackendKeepaliveIntervalSec ||
			eRule.timeoutMemberConnectMs != serv.TimeoutMemberConnect ||
			eRule.timeoutMemberDataMs != serv.TimeoutMemberData ||
			eRule.timeoutTcpInspectMs != serv.TimeoutTcpInspect ||
			eRule.pdDisaggMode != serv.PDDisaggMode ||
			eRule.pdCacheAwareMode != serv.PDCacheAwareMode ||
			eRule.pdSessionTTLSec != serv.PDSessionTTLSec ||
			(serv.PDCacheThreshold != 0 && eRule.pdCacheThreshold != serv.PDCacheThreshold) ||
			(serv.PDBalanceAbsThreshold != 0 && eRule.pdBalanceAbsThreshold != serv.PDBalanceAbsThreshold) ||
			eRule.cbEnable != serv.CbEnable ||
			eRule.kvExactMode != serv.KvExactMode ||
			eRule.kvBlockSize != serv.KvBlockSize ||
			eRule.kvHashAlgo != serv.KvHashAlgo ||
			eRule.kvZmqPort != serv.KvZmqPort ||
			eRule.kvWarmupSec != serv.KvWarmupSec ||
			// kvEngineType is deliberately ABSENT here — an engine
			// change must REJECT (RuleExistsErr below), never ruleChg delete+re-add.
			eRule.kvDpRankCount != serv.KvDpRankCount ||
			eRule.pdBootstrapPort != serv.PDBootstrapPort ||
			eRule.chwblPrefixHashLevel != serv.CHWBLPrefixHashLevel ||
			eRule.chwblPrefixHashFlags != serv.CHWBLPrefixHashFlags ||
			eRule.chwblMeanLoadFactor != serv.CHWBLMeanLoadFactor ||
			eRule.chwblReplication != serv.CHWBLReplication ||
			eRule.chwblEnableCacheSalt != serv.CHWBLEnableCacheSalt ||
			eRule.iTO != serv.InactiveTimeout ||
			eRule.connLimit != serv.ConnectionLimit || // connectionLimit change re-pushes the dataplane gate
			// TLS-hardening fields — a change re-pushes the dataplane.
			eRule.tlsCiphers != serv.TlsCiphers ||
			eRule.hstsMaxAge != serv.HstsMaxAge ||
			eRule.hstsIncludeSubdomains != serv.HstsIncludeSubdomains ||
			eRule.hstsPreload != serv.HstsPreload ||
			eRule.backendCaCertId != serv.BackendCaCertId ||
			eRule.backendClientCertId != serv.BackendClientCertId ||
			!strSliceEqual(eRule.alpnProtocols, serv.AlpnProtocols) ||
			!strSliceEqual(eRule.tlsVersions, serv.TlsVersions) ||
			eRule.name != serv.Name {
			ruleChg = true
		}

		if len(allowedSources) == len(eRule.srcList) {
			for _, newSrc := range allowedSources {
				srcMatch := false
				for _, src := range eRule.srcList {
					if src.srcPref.String() != newSrc.Prefix {
						srcMatch = true
						break
					}
				}
				if !srcMatch {
					ruleChg = true
					break
				}
			}
		}

		// an explicit admin_state that differs from the current
		// effective state is itself a rule change (pause/resume must reach DpCreate).
		// Without this, an admin_state-only PATCH (every other field identical to
		// current) leaves ruleChg false, short-circuits at the RuleExistsErr return
		// below, and never reaches the admin_state apply / LB2DP drain.
		if serv.AdminStateUp != nil && resolveAdminStateUp(serv.AdminStateUp) != eRule.adminStateUp {
			ruleChg = true
		}

		// kvEngineType is IMMUTABLE on a live rule — delete+
		// recreate is the sanctioned path. Checked BEFORE the !ruleChg
		// short-circuit so an engine-only PUT (kvEngineType deliberately absent
		// from the ruleChg OR-chain above) still gets the exact rejection.
		if err := kvEngineImmutabilityCheck(eRule.kvEngineType, serv.KvEngineType); err != nil {
			return RuleExistsErr, err
		}

		if !ruleChg {
			return RuleExistsErr, errors.New("lbrule-exists error")
		}

		if eRule.secMode != serv.Security {
			return RuleExistsErr, errors.New("lbrule-exist error: cant modify rule security mode")
		}

		if eRule.egress != serv.Egress {
			return RuleExistsErr, errors.New("lbrule-exist error: cant modify rule egress mode")
		}

		if len(retEps) == 0 {
			tk.LogIt(tk.LogDebug, "lb-rule %s has no-endpoints: to be deleted\n", eRule.tuples.String())
			return R.DeleteLbRule(serv)
		}

		if eRule.act.action.(*ruleLBActs).mode == cmn.LBModeFullProxy && lBActs.mode != cmn.LBModeFullProxy ||
			eRule.act.action.(*ruleLBActs).mode != cmn.LBModeFullProxy && lBActs.mode == cmn.LBModeFullProxy {
			return RuleExistsErr, errors.New("lbrule-exist error: cant modify fullproxy rule mode")
		}

		if eRule.act.action.(*ruleLBActs).mode == cmn.LBModeFullProxy || len(retEps) > MaxLBEndPoints {
			eRule.DP(DpRemove)
			if len(retEps) > MaxLBEndPoints {
				tk.LogIt(tk.LogInfo, "lb-rule %s-%v-%s reset all end-points (too many)\n", serv.ServIP, serv.ServPort, serv.Proto)
				delEps = eRule.act.action.(*ruleLBActs).endPoints
				retEps = lBActs.endPoints
			}
		}

		eSrcList := eRule.srcList
		eRule.srcList = nil

		for _, allowedSource := range allowedSources {
			srcElem := R.addAllowedLbSrc(allowedSource.Prefix, uint32(eRule.ruleNum))
			if srcElem == nil {
				for _, src := range eRule.srcList {
					R.deleteAllowedLbSrc(src.srcPref.String(), uint32(eRule.ruleNum))
				}
				eRule.srcList = eSrcList
				tk.LogIt(tk.LogError, "nat lb-rule - %s:%s allowedSRC error\n", eRule.tuples.String(), eRule.act.String())
				return RuleAllocErr, errors.New("rule-allowed-src error")
			}
			eRule.srcList = append(eRule.srcList, srcElem)
		}

		for _, srcElem := range eSrcList {
			R.deleteAllowedLbSrc(srcElem.srcPref.String(), uint32(eRule.ruleNum))
		}

		// Update the rule
		eRule.hChk.prbType = serv.ProbeType
		eRule.hChk.prbPort = serv.ProbePort
		eRule.hChk.prbReq = serv.ProbeReq
		eRule.hChk.prbResp = serv.ProbeResp
		eRule.hChk.prbRetries = serv.ProbeRetries
		eRule.hChk.prbTimeo = serv.ProbeTimeout
		eRule.hChk.actChk = serv.Monitor
		eRule.pTO = serv.PersistTimeout
		eRule.ppv2En = serv.ProxyProtocolV2
		eRule.act.action.(*ruleLBActs).sel = lBActs.sel

		// Update all extended mutable fields
		eRule.traceType = serv.TraceType
		if serv.BackendProtocol != "" {
			eRule.backendProtocol = serv.BackendProtocol
		}
		eRule.sessionHeaderName = serv.SessionHeaderName
		eRule.sseMode = serv.SSEMode
		eRule.maxStreamDurationSec = serv.MaxStreamDurationSec
		eRule.backendKeepaliveIntervalSec = serv.BackendKeepaliveIntervalSec
		// update per-listener member timeouts (ms). Assigned
		// like maxStreamDurationSec so an explicit 0 can clear a previously-set value.
		eRule.timeoutMemberConnectMs = serv.TimeoutMemberConnect
		eRule.timeoutMemberDataMs = serv.TimeoutMemberData
		eRule.timeoutTcpInspectMs = serv.TimeoutTcpInspect
		// TLS-hardening fields. Assigned verbatim so an explicit
		// empty/0 can clear a previously-set value (additive/default-off).
		eRule.alpnProtocols = serv.AlpnProtocols
		eRule.tlsCiphers = serv.TlsCiphers
		eRule.tlsVersions = serv.TlsVersions
		eRule.hstsMaxAge = serv.HstsMaxAge
		eRule.hstsIncludeSubdomains = serv.HstsIncludeSubdomains
		eRule.hstsPreload = serv.HstsPreload
		eRule.backendCaCertId = serv.BackendCaCertId
		eRule.backendClientCertId = serv.BackendClientCertId
		// update the per-service connectionLimit (0 = unlimited).
		// Assigned like maxStreamDurationSec so an explicit 0 can clear a previously-set limit;
		// the change is detected above and re-pushed to the dataplane conn_limit gate.
		eRule.connLimit = serv.ConnectionLimit
		eRule.pdDisaggMode = serv.PDDisaggMode
		eRule.pdCacheAwareMode = serv.PDCacheAwareMode
		eRule.pdSessionTTLSec = serv.PDSessionTTLSec
		if serv.PDCacheThreshold != 0 {
			eRule.pdCacheThreshold = serv.PDCacheThreshold
		}
		if serv.PDBalanceAbsThreshold != 0 {
			eRule.pdBalanceAbsThreshold = serv.PDBalanceAbsThreshold
		}
		eRule.cbEnable = serv.CbEnable
		eRule.kvExactMode = serv.KvExactMode
		eRule.kvBlockSize = serv.KvBlockSize
		eRule.kvHashAlgo = serv.KvHashAlgo
		eRule.kvZmqPort = serv.KvZmqPort
		eRule.kvWarmupSec = serv.KvWarmupSec
		eRule.kvEngineType = serv.KvEngineType // immutability enforced above
		eRule.kvDpRankCount = serv.KvDpRankCount
		eRule.pdBootstrapPort = serv.PDBootstrapPort
		eRule.chwblPrefixHashLevel = serv.CHWBLPrefixHashLevel
		eRule.chwblPrefixHashFlags = serv.CHWBLPrefixHashFlags
		eRule.chwblMeanLoadFactor = serv.CHWBLMeanLoadFactor
		eRule.chwblReplication = serv.CHWBLReplication
		eRule.chwblEnableCacheSalt = serv.CHWBLEnableCacheSalt
		eRule.mtlsFrontend = serv.MTLSFrontend
		eRule.mtlsBackend = serv.MTLSBackend

		// Re-apply tracing catalog if trace_type changed
		if serv.Mode == cmn.LBModeFullProxy && serv.TraceType != "" {
			if mh.dpEbpf != nil && mh.dpEbpf.catalogSyncManager != nil {
				newCatalogID := mh.dpEbpf.catalogSyncManager.GetCatalogID(serv.TraceType)
				if newCatalogID != 0 && newCatalogID != eRule.tracingCatalogID {
					eRule.tracingCatalogID = newCatalogID
					_ = mh.dpEbpf.catalogSyncManager.AddServiceCatalogMapping(
						eRule.tuples.l3Dst.addr.IP,
						eRule.tuples.l4Dst.valMin,
						eRule.tuples.l4Prot.val,
						newCatalogID,
					)
				}
			}
		} else if serv.TraceType == "" && eRule.tracingCatalogID != 0 {
			// trace_type removed — clear catalog mapping
			eRule.tracingCatalogID = 0
		}

		// Capture old endpoints before updating for selective session reset
		oldEndPoints := eRule.act.action.(*ruleLBActs).endPoints

		eRule.act.action.(*ruleLBActs).endPoints = retEps
		eRule.act.action.(*ruleLBActs).mode = lBActs.mode
		// Managed flag can't be modified on the fly
		// eRule.managed = serv.Managed

		// Apply selective session reset for endpoint changes (only for LC algorithm)
		if len(delEps) > 0 || len(eRule.act.action.(*ruleLBActs).endPoints) != len(lBActs.endPoints) {
			// Only apply session reset for Least Connection algorithm
			if lBActs.sel == cmn.LbSelLeastConnections {
				tk.LogIt(tk.LogInfo, "[RULE] Applying selective session reset for LC rule %s (mark=%d)\n",
					eRule.tuples.String(), int(eRule.ruleNum))

				// Apply selective session reset to preserve session counts for unchanged endpoints
				err := R.applySelectiveSessionReset(eRule, oldEndPoints, retEps, delEps)
				if err != nil {
					tk.LogIt(tk.LogError, "[RULE] Selective session reset failed: %v\n", err)
					// Continue with rule update even if session reset fails
				}
			}
		}

		if !serv.Snat {
			// GPU-Aware: Clean up GPU map entries for deleted endpoints BEFORE modNatEpHost
			// This ensures the eBPF endpoint_to_gpu_index_map is synchronized with ep-host changes
			// Skip for FullProxy mode since DpRemove already handles cleanup
			if len(delEps) > 0 && mh.dp != nil && mh.dp.DpHooks != nil && lBActs.sel == cmn.LbSelGPUAware &&
				eRule.act.action.(*ruleLBActs).mode != cmn.LBModeFullProxy {
				for _, delEp := range delEps {
					err := mh.dp.DpHooks.DeleteEndpointFromGPUIndexMap(delEp.xIP, delEp.xPort)
					if err != nil {
						tk.LogIt(tk.LogWarning, "GPU-Aware: Failed to delete endpoint %s:%d from GPU map: %v\n",
							delEp.xIP.String(), delEp.xPort, err)
					} else {
						tk.LogIt(tk.LogInfo, "GPU-Aware: Cleaned up deleted endpoint %s:%d from GPU map during update\n",
							delEp.xIP.String(), delEp.xPort)
					}
				}
			}

		}

		// keep the opaque id stable (set from a supplied id when
		// present — same-rule no-op), resolve the effective admin_state, and bump the
		// in-memory lastUpdated timestamp.
		if serv.Id != "" && serv.Id != eRule.id {
			if _, idErr := R.resolveOpaqueID(serv.Id, eRule); idErr != nil {
				return RuleExistsErr, idErr
			}
			R.unregisterOpaqueID(eRule)
			eRule.id = serv.Id
			R.registerOpaqueID(eRule)
		}
		// only an EXPLICIT admin_state in the
		// request mutates the effective flag. A nil/absent AdminStateUp (a member-only
		// PATCH, a non-admin-state mutate, or a kube-loxilb/boot re-sync that never sets
		// the field) must PRESERVE the current effective state — so a paused rule is not
		// silently resumed by an unrelated update, and a legacy resync does not flip a
		// rule. The PATCH handler carries the rule's current value when the key
		// is absent in the body, so PATCH presence semantics are end-to-end consistent.
		if serv.AdminStateUp != nil {
			eRule.adminStateUp = resolveAdminStateUp(serv.AdminStateUp)
		}
		// only
		// an EXPLICIT non-empty value in the request mutates the stored opaque field, so a
		// member-only/unrelated PATCH or a boot/kube-loxilb re-sync that omits these does not
		// silently clear them. Annotations bounded for T-73-DOS; secondaryVIPs round-trip uncapped.
		if serv.ProjectId != "" {
			eRule.projectId = serv.ProjectId
		}
		if serv.Annotations != nil {
			eRule.annotations = boundAnnotations(serv.Annotations)
		}
		if servSecVIPs != nil {
			eRule.secVIPs = servSecVIPs
		}
		eRule.lastUpdated = time.Now()

		eRule.sT = time.Now()
		eRule.iTO = serv.InactiveTimeout
		tk.LogIt(tk.LogDebug, "lb-rule updated - %s:%s\n", eRule.tuples.String(), eRule.act.String())
		R.flushLBCtEntries(eRule, CtFlushRidMatchOrZero)

		// route the L4 member reconcile through the atomic
		// all-or-nothing guard. It performs the probe-registry detach/attach + source
		// re-election + in-place DpCreate, and rolls back to the pre-patch member set
		// (in place, NO DpRemove) if the dataplane push fails. The SNAT path has no
		// per-EP NAT reconcile, so it keeps the plain in-place DpCreate.
		if !serv.Snat {
			if recErr := R.reconcileLBEndpointsAtomic(eRule, retEps, delEps, activateProbe); recErr != nil {
				return RuleExistsErr, recErr
			}
		} else {
			eRule.DP(DpCreate)
		}
		DpBrokerSyncBarrier(mh.dp)
		R.flushLBCtEntries(eRule, CtFlushRidZeroOnly)

		return 0, nil
	} else if serv.Oper == cmn.LBOPDetach {
		tk.LogIt(tk.LogInfo, "lb-rule %s-%v-%s does not exist\n", serv.ServIP, serv.ServPort, serv.Proto)
		return RuleNotExistsErr, errors.New("lbrule not-exists error")
	}

	// PATCH must-exist semantics. The caller (the PATCH handler)
	// sets MustExist when the rule MUST already exist; an absent target must surface as a
	// 404, NOT be silently created. POST leaves MustExist=false, so its forgiving upsert
	// (create-or-update) behavior is unchanged.
	if serv.MustExist {
		tk.LogIt(tk.LogInfo, "lb-rule %s-%v-%s does not exist (patch must-exist)\n", serv.ServIP, serv.ServPort, serv.Proto)
		return RuleNotExistsErr, errors.New("lbrule not-exists error")
	}

	r := new(ruleEnt)
	r.tuples = rt
	// resolve the opaque id up-front (mint when absent, reject a supplied
	// id that collides with a DIFFERENT rule's VIP-key —) before any marker alloc.
	resolvedID, idErr := R.resolveOpaqueID(serv.Id, r)
	if idErr != nil {
		return RuleExistsErr, idErr
	}
	r.id = resolvedID
	// effective admin_state (nil/absent => enabled). : in-memory lastUpdated.
	r.adminStateUp = resolveAdminStateUp(serv.AdminStateUp)
	r.lastUpdated = time.Now()
	// store the opaque data-fidelity fields verbatim. Input
	// bounds (T-73-DOS) cap the annotations map; secondaryVIPs round-trip is uncapped for
	// fidelity (only ≤3 consumed by SCTP, RESEARCH Open Q2). Never interpreted at the dataplane.
	r.projectId = serv.ProjectId
	r.annotations = boundAnnotations(serv.Annotations)
	r.secVIPs = servSecVIPs
	// per-service concurrent-connection ceiling (0 = unlimited).
	// Plumbed to the dataplane conn_limit; the eBPF gate refuses the (N+1)th SYN at sel=-1.
	r.connLimit = serv.ConnectionLimit
	r.zone = R.zone
	r.name = serv.Name
	names := strings.Split(r.name, ":")
	if len(names) >= 2 {
		r.inst = names[1]
	} else {
		r.inst = cmn.CIDefault
	}
	if serv.Snat {
		r.act.actType = RtActSnat
	} else if serv.Mode == cmn.LBModeFullNAT || serv.Mode == cmn.LBModeOneArm || serv.Mode == cmn.LBModeHostOneArm {
		r.act.actType = RtActFullNat
	} else if serv.Mode == cmn.LBModeFullProxy {
		r.act.actType = RtActFullProxy
	} else {
		r.act.actType = RtActDnat
	}
	r.managed = serv.Managed
	r.secIP = nSecIP
	r.secMode = serv.Security
	r.ppv2En = serv.ProxyProtocolV2
	r.egress = serv.Egress
	r.traceType = serv.TraceType // Tracing catalog

	// Backend protocol capability - default to "http1" for backward compatibility
	if serv.BackendProtocol == "" {
		r.backendProtocol = "http1" // Safe default: HTTP/1.1 only
	} else {
		r.backendProtocol = serv.BackendProtocol
	}

	// Store custom session header name for persist mode
	r.sessionHeaderName = serv.SessionHeaderName

	// Store SSE streaming configuration
	r.sseMode = serv.SSEMode
	r.maxStreamDurationSec = serv.MaxStreamDurationSec
	r.backendKeepaliveIntervalSec = serv.BackendKeepaliveIntervalSec

	// Store Octavia per-listener member timeouts (ms, native unit).
	r.timeoutMemberConnectMs = serv.TimeoutMemberConnect
	r.timeoutMemberDataMs = serv.TimeoutMemberData
	r.timeoutTcpInspectMs = serv.TimeoutTcpInspect

	// Store TLS-hardening fields. Additive/default-off.
	r.alpnProtocols = serv.AlpnProtocols
	r.tlsCiphers = serv.TlsCiphers
	r.tlsVersions = serv.TlsVersions
	r.hstsMaxAge = serv.HstsMaxAge
	r.hstsIncludeSubdomains = serv.HstsIncludeSubdomains
	r.hstsPreload = serv.HstsPreload
	r.backendCaCertId = serv.BackendCaCertId
	r.backendClientCertId = serv.BackendClientCertId

	// Store P/D disaggregation configuration
	r.pdDisaggMode = serv.PDDisaggMode

	// Store P/D cache-aware routing configuration (US-PD801)
	r.pdCacheAwareMode = serv.PDCacheAwareMode
	r.pdSessionTTLSec = serv.PDSessionTTLSec
	r.pdCacheThreshold = serv.PDCacheThreshold
	r.pdBalanceAbsThreshold = serv.PDBalanceAbsThreshold

	// Store the per-endpoint circuit-breaker enable
	r.cbEnable = serv.CbEnable

	// Store KV-cache exact routing configuration
	r.kvExactMode = serv.KvExactMode
	r.kvBlockSize = serv.KvBlockSize
	r.kvHashAlgo = serv.KvHashAlgo
	r.kvZmqPort = serv.KvZmqPort
	r.kvWarmupSec = serv.KvWarmupSec
	r.kvEngineType = serv.KvEngineType // engine + DP rank count
	r.kvDpRankCount = serv.KvDpRankCount
	r.pdBootstrapPort = serv.PDBootstrapPort

	// Store CHWBL configuration (sel=8)
	r.chwblPrefixHashLevel = serv.CHWBLPrefixHashLevel
	r.chwblPrefixHashFlags = serv.CHWBLPrefixHashFlags
	r.chwblMeanLoadFactor = serv.CHWBLMeanLoadFactor
	r.chwblReplication = serv.CHWBLReplication
	r.chwblEnableCacheSalt = serv.CHWBLEnableCacheSalt

	// Store mTLS configuration
	r.mtlsFrontend = serv.MTLSFrontend
	r.mtlsBackend = serv.MTLSBackend

	// Per LB end-point health-check is supposed to be handled at kube-loxilb/CCM,
	// but it certain cases like stand-alone mode, loxilb can do its own
	// lb end-point health monitoring
	r.hChk.prbType = serv.ProbeType
	r.hChk.prbPort = serv.ProbePort
	r.hChk.prbReq = serv.ProbeReq
	r.hChk.prbResp = serv.ProbeResp
	r.hChk.prbRetries = serv.ProbeRetries
	r.hChk.prbTimeo = serv.ProbeTimeout
	r.hChk.actChk = serv.Monitor

	r.act.action = &lBActs
	r.ruleNum, err = R.tables[RtLB].Mark.GetMarker()
	if err != nil {
		tk.LogIt(tk.LogError, "nat lb-rule - %s:%s hwm error\n", r.tuples.String(), r.act.String())
		return RuleAllocErr, errors.New("rule-hwm error")
	}
	for _, allowedSource := range allowedSources {
		srcElem := R.addAllowedLbSrc(allowedSource.Prefix, uint32(r.ruleNum))
		if srcElem == nil {
			R.tables[RtLB].Mark.ReleaseMarker(r.ruleNum)
			for _, src := range r.srcList {
				R.deleteAllowedLbSrc(src.srcPref.String(), uint32(r.ruleNum))
			}
			tk.LogIt(tk.LogError, "nat lb-rule - %s:%s allowedSRC error\n", r.tuples.String(), r.act.String())
			return RuleAllocErr, errors.New("rule-allowed-src error")
		}
		r.srcList = append(r.srcList, srcElem)
	}
	r.sT = time.Now()
	r.iTO = serv.InactiveTimeout
	r.bgp = serv.Bgp
	r.ci = cmn.CIDefault
	r.privIP = privIP
	r.pTO = serv.PersistTimeout

	r.locIPs = make(map[string]struct{})

	if !serv.Snat {
		R.foldRecursiveEPs(r)
		R.modNatEpHost(r, lBActs.endPoints, true, activateProbe, r.egress)
		R.electEPSrc(r)

		// [CP-DEBUG] Stage 2: electEPSrc result - log addrRslv and EP state
		tk.LogIt(tk.LogInfo, "[CP-DEBUG] electEPSrc result: addrRslv=%v\n", r.addrRslv)
		switch at := r.act.action.(type) {
		case *ruleLBActs:
			for i, ep := range at.endPoints {
				tk.LogIt(tk.LogInfo, "[CP-DEBUG]   EP[%d] xIP=%s rIP=%s inactive=%v foldKey=%q\n",
					i, ep.xIP.String(), ep.rIP.String(), ep.inActiveEP, ep.foldRuleKey)
			}
		}

		if serv.Mode == cmn.LBModeHostOneArm {
			R.mkHostAssocs(r)
		}
		if serv.ServPortMax != 0 {
			R.addLbRuleWithFW(serv.ServIP, serv.ServPort, serv.ServPortMax, ipProto, uint32(r.ruleNum))
		}
	}

	R.tables[RtLB].eMap[rt.ruleKey()] = r
	if r.ruleNum < RtMaximumLbs {
		R.tables[RtLB].rArr[r.ruleNum] = r
	}
	// register id->rule. Runs on both live add and boot replay
	// (nlp.go applyLoadBalancerConfig -> NetLbRuleAdd -> AddLbRule), so the index
	// rebuilds on restart with no separate persisted structure.
	R.registerOpaqueID(r)
	R.addVIPSys(r)

	// Part 8B: Prepare tracing catalog ID if trace_type specified (Deep Inspection)
	// This happens BEFORE r.DP(DpCreate) so the catalog_id can be passed through the DP work queue
	// ONLY for FullProxy mode - independent from GPU routing
	var tracingCatalogID uint16 = 0
	if serv.Mode == cmn.LBModeFullProxy && serv.TraceType != "" {
		traceCatalogName := serv.TraceType

		if mh.dpEbpf != nil && mh.dpEbpf.catalogSyncManager != nil {
			// On first trace_type usage, sync catalogs to shared memory
			if !mh.dpEbpf.catalogSyncManager.IsSynced() {
				tk.LogIt(tk.LogInfo, "[CATALOG] First trace_type usage - syncing catalogs to shared memory\n")
				if err := mh.dpEbpf.catalogSyncManager.SyncToSharedMemory(); err != nil {
					tk.LogIt(tk.LogError, "[CATALOG] Failed to sync catalogs: %v\n", err)
				} else {
					tk.LogIt(tk.LogInfo, "[CATALOG] Synced %d catalog(s) to shared memory\n",
						len(mh.dpEbpf.tracingCatalogManager.ListCatalogs()))
				}
			}

			// Get catalog_id from sync manager
			tracingCatalogID = mh.dpEbpf.catalogSyncManager.GetCatalogID(traceCatalogName)

			if tracingCatalogID == 0 {
				tk.LogIt(tk.LogWarning, "[CATALOG] Unknown trace_type catalog '%s', service created without tracing\n", traceCatalogName)
			} else {
				tk.LogIt(tk.LogInfo, "[CATALOG] Service %s:%d will use tracing catalog '%s' (catalog_id=%d)\n",
					serv.ServIP, r.tuples.l4Dst.valMin, traceCatalogName, tracingCatalogID)
			}
		}
	}

	// Store catalog_id in rule for later DP operations
	r.tracingCatalogID = tracingCatalogID

	R.flushLBCtEntries(r, CtFlushRidMatchOrZero)
	r.DP(DpCreate)
	DpBrokerSyncBarrier(mh.dp)
	R.flushLBCtEntries(r, CtFlushRidZeroOnly)

	// Enable circuit breaker for P/D disaggregation services (fix)
	// proxy_set_circuit_breaker requires the proxy entry to exist first (created async by DP worker),
	// so we retry with backoff until the entry is available.
	if r.pdDisaggMode && mh.dpEbpf != nil {
		svcIP := r.tuples.l3Dst.addr.IP
		svcPort := r.tuples.l4Dst.valMin
		svcProto := r.tuples.l4Prot.val
		go func() {
			for attempt := 0; attempt < 20; attempt++ {
				time.Sleep(200 * time.Millisecond)
				ret := mh.dpEbpf.DpLBSetCircuitBreaker(svcIP, svcPort, svcProto, true, 3, 30)
				if ret == 0 {
					tk.LogIt(tk.LogInfo, "[CB] Circuit breaker enabled for P/D service %v:%d (attempt %d)\n",
						svcIP, svcPort, attempt+1)
					return
				}
			}
			tk.LogIt(tk.LogWarning, "[CB] Failed to enable circuit breaker for P/D service %v:%d after retries\n",
				svcIP, svcPort)
		}()
	}

	// Auto-start ZMQ subscribers for KV-cache routing (KV-12)
	if serv.KvExactMode == 1 {
		zmqPort := serv.KvZmqPort
		if zmqPort == 0 {
			zmqPort = 5557
		}
		serviceID := uint32(r.ruleNum)
		// DP-rank fan-out — SGLang data-parallel
		// engines publish per-rank on consecutive ports (kvZmqPort+rank), one
		// subscriber goroutine per rank merging into the shared per-EP
		// inventory. kvDpRankCount 0 ⇒ 1 (the default idiom) reproduces
		// today's single KvSubscriberStart call byte-identically.
		dpRanks := r.kvDpRankCount
		if dpRanks == 0 {
			dpRanks = 1
		}
		for i, ep := range lBActs.endPoints {
			// Start subscriber for prefill EPs only (epRole == 1)
			if ep.epRole == 1 {
				for rank := uint16(0); rank < dpRanks; rank++ {
					// TRT-LLM events ride the EP's own SERVING port (HTTP
					// drain, no separate event port — kvZmqPort is rejected
					// non-default at validation), so the subscriber dials
					// xPort there. Mirrors the single-role gate below.
					subPort := zmqPort + rank
					if r.kvEngineType == "trtllm" {
						subPort = ep.xPort
					}
					KvSubscriberStartRank(serviceID, i, rank, ep.xIP.String(), subPort,
						kvHashAlgoEffective(r.kvHashAlgo, r.kvEngineType), r.kvEngineType, r.kvBlockSize)
				}
			}
		}
	} else if serv.KvExactMode == KvExactModeSingleRole {
		// SGL-01 Gate 2: single-role services have role-less EPs —
		// start a subscriber for EVERY endpoint (no epRole filter), with the
		// same zmqPort default and serviceID computation as mode 1. Teardown
		// stays the generic KvSubscriberStopAll (already service-scoped —
		// it cancels every (epIdx, rank) entry).
		zmqPort := serv.KvZmqPort
		if zmqPort == 0 {
			zmqPort = 5557
		}
		serviceID := uint32(r.ruleNum)
		// same DP-rank fan-out as the mode-1 gate —
		// rank N subscribes at kvZmqPort+N; 0 ⇒ 1 default keeps the shipped
		// single-rank behavior byte-identical.
		dpRanks := r.kvDpRankCount
		if dpRanks == 0 {
			dpRanks = 1
		}
		for _, i := range kvSubscriberTargets(serv.KvExactMode, lBActs.endPoints) {
			for rank := uint16(0); rank < dpRanks; rank++ {
				// The RESOLVED contract, not the raw field: an SGLang rule takes
				// the documented shape (kvHashAlgo omitted), which would
				// otherwise leave svc.algo empty and make the KV-inventory
				// audit API self-describe as vLLM "sha256_cbor".
				// TRT-LLM events ride the EP's own SERVING port (HTTP drain,
				// no separate event port — kvZmqPort is rejected non-default
				// at validation), so the subscriber dials xPort there.
				subPort := zmqPort + rank
				if r.kvEngineType == "trtllm" {
					subPort = lBActs.endPoints[i].xPort
				}
				KvSubscriberStartRank(serviceID, i, rank, lBActs.endPoints[i].xIP.String(), subPort,
					kvHashAlgoEffective(r.kvHashAlgo, r.kvEngineType), r.kvEngineType, r.kvBlockSize)
			}
		}
	}

	// llama.cpp typed rules run no subscribers (guards force kvExactMode=0) —
	// their admission surface is the soft /props consistency probe: warn +
	// counter on model/build/slot skew or a sleeping endpoint, never refuse.
	// Bounded goroutine (probe-internal deadline), so no teardown coupling.
	if r.kvEngineType == "llamacpp" {
		probeEps := make([]llamacppProbeEp, 0, len(lBActs.endPoints))
		for _, ep := range lBActs.endPoints {
			probeEps = append(probeEps, llamacppProbeEp{IP: ep.xIP.String(), Port: ep.xPort})
		}
		go LlamacppAdmissionProbe(uint32(r.ruleNum), probeEps)
	}

	// COMP-01 : Start vLLM metrics scraper for queue-depth routing
	if r.pdDisaggMode {
		endpoints := make(map[int]string)
		for i, ep := range lBActs.endPoints {
			endpoints[i] = fmt.Sprintf("%s:%d", ep.xIP.String(), ep.xPort)
		}
		svcIP := tk.IPtonl(r.tuples.l3Dst.addr.IP)
		svcPort := r.tuples.l4Dst.valMin
		// updateFn mirrors samples into the Go-side worker-metrics cache so
		// the REST introspection/staleness APIs see the built-in scraper
		// (cache only — the eBPF queue-depth push happens inside the sink).
		r.vllmScraper = NewVllmScraper(endpoints, svcIP, svcPort, 0,
			func(epIP string, m WorkerMetrics) {
				if mh.dpEbpf != nil {
					mh.dpEbpf.StoreWorkerMetricsCache(m.EndpointIP, m)
				}
			})
		// thread the mh-owned shutdown ctx so
		// the scraper exits when the workers stage cancels.
		go r.vllmScraper.Run(mh.shutdownCtx)
	}

	// For FullProxy mode with tracing, add service-to-catalog mapping to shared memory
	// Sockproxy will look up the catalog_id when creating proxy entries
	if serv.Mode == cmn.LBModeFullProxy && tracingCatalogID != 0 && mh.dpEbpf != nil && mh.dpEbpf.catalogSyncManager != nil {
		err := mh.dpEbpf.catalogSyncManager.AddServiceCatalogMapping(
			r.tuples.l3Dst.addr.IP,
			r.tuples.l4Dst.valMin,
			r.tuples.l4Prot.val,
			tracingCatalogID,
		)

		if err != nil {
			tk.LogIt(tk.LogWarning, "[CATALOG] Failed to add service mapping: %v\n", err)
		}
	}

	// when vip_qos_policy_id is set, associate the PRE-EXISTING policy
	// ident to this VIP rule reusing policer association. The rule is now in
	// R.tables[RtLB] (DP'd above), so GetLBRuleMarkByKey resolves its mark. loxilb only
	// associates an EXISTING ident — an unresolvable ident surfaces an error here (no
	// silent-drop). Empty ⇒ no-op (round-trips byte-identical,
	// The lbKey mirrors GetLBRuleMarkByKey's "VIP:PORT:PROTO" format.
	if serv.VipQosPolicyId != "" && R.zone != nil && R.zone.Pols != nil {
		lbKey := fmt.Sprintf("%s:%d:%s", serv.ServIP, serv.ServPort, serv.Proto)
		if _, qerr := R.zone.Pols.PolAssociateLbRule(serv.VipQosPolicyId, lbKey); qerr != nil {
			tk.LogIt(tk.LogError, "lb-rule %s: vip_qos_policy_id %q association failed: %v\n",
				lbKey, serv.VipQosPolicyId, qerr)
			return RuleArgsErr, qerr
		}
	}

	tk.LogIt(tk.LogDebug, "lb-rule added - %d:%s-%s\n", r.ruleNum, r.tuples.String(), r.act.String())

	return 0, nil
}

// deleteVIPSys - system specific operations for deleting VIPs of a LB rule
func (R *RuleH) deleteVIPSys(r *ruleEnt) {
	if r.act.actType != RtActSnat && !strings.Contains(r.name, "ipvs") && !strings.Contains(r.name, "static") {
		R.DeleteRuleVIP(r.tuples.l3Dst.addr.IP)

		// Take care of any secondary VIPs
		for _, sVIP := range r.secIP {
			R.DeleteRuleVIP(sVIP.sIP)
		}
	}
}

// DeleteLbRule - Delete a service LB rule. The service details are passed in serv argument.
// On success, it will return 0 and nil error, else appropriate return code and
// error string will be set
func (R *RuleH) DeleteLbRule(serv cmn.LbServiceArg) (int, error) {
	var ipProto uint8

	service := ""
	if tk.IsNetIPv4(serv.ServIP) {
		service = serv.ServIP + "/32"
		if service == "0.0.0.0/32" && serv.Egress && mh.has.ClusterGw != "" {
			service = mh.has.ClusterGw + "/32"
		}
	} else {
		service = serv.ServIP + "/128"
		if service == "::/128" && serv.Egress && mh.has.ClusterGw != "" {
			service = mh.has.ClusterGw + "/128"
		}
	}
	_, sNetAddr, err := net.ParseCIDR(service)
	if err != nil {
		return RuleUnknownServiceErr, errors.New("malformed-service error")
	}

	if serv.ServPortMax != 0 && serv.ServPortMax < serv.ServPort {
		return RuleArgsErr, errors.New("serv-port-args range error")
	}

	if serv.Proto == "tcp" {
		ipProto = 6
	} else if serv.Proto == "udp" {
		ipProto = 17
	} else if serv.Proto == "icmp" {
		ipProto = 1
	} else if serv.Proto == "sctp" {
		ipProto = 132
	} else if serv.Proto == "none" {
		ipProto = 0
	} else {
		return RuleUnknownServiceErr, errors.New("malformed-proto error")
	}

	l4prot := rule8Tuple{ipProto, 0xff}
	l3dst := ruleIPTuple{*sNetAddr}
	servPortMax := serv.ServPort
	if serv.ServPortMax != 0 {
		servPortMax = serv.ServPortMax
	}
	l4dst := rule16RTuple{serv.ServPort, servPortMax, true}
	rt := ruleTuples{
		l3Dst:         l3dst,
		l4Prot:        l4prot,
		l4Dst:         l4dst,
		pref:          serv.BlockNum,
		path:          serv.HostUrl,
		pathPrefix:    serv.PathPrefix,                     // P6: Include path prefix in rule key
		pathMatchMode: lbPathMatchMode(serv.PathMatchMode), // P6: Include path match mode in rule key (canonicalized)
		modelName:     serv.ModelName,                      // AI model name for pool selection
	}
	tk.LogIt(tk.LogDebug, "lb-rule key (del): %q\n", rt.ruleKey())

	rule := R.tables[RtLB].eMap[rt.ruleKey()]
	if rule == nil {
		return RuleNotExistsErr, errors.New("no-rule error")
	}

	defer R.tables[RtLB].Mark.ReleaseMarker(rule.ruleNum)

	eEps := rule.act.action.(*ruleLBActs).endPoints
	activatedProbe := false
	if rule.act.action.(*ruleLBActs).mode == cmn.LBModeOneArm || rule.act.action.(*ruleLBActs).mode == cmn.LBModeFullNAT || rule.act.action.(*ruleLBActs).mode == cmn.LBModeHostOneArm || rule.hChk.actChk {
		activatedProbe = true
	}
	if rule.act.actType != RtActSnat {
		R.modNatEpHost(rule, eEps, false, activatedProbe, rule.egress)
		R.unFoldRecursiveEPs(rule)
		if serv.ServPortMax != 0 {
			R.deleteLbRuleWithFW(serv.ServIP, serv.ServPort, serv.ServPortMax, ipProto)
		}
	}

	for _, srcElem := range rule.srcList {
		R.deleteAllowedLbSrc(srcElem.srcPref.String(), uint32(rule.ruleNum))
	}
	rule.srcList = nil

	delete(R.tables[RtLB].eMap, rt.ruleKey())
	// drop the opaque-id index entry alongside the rule.
	R.unregisterOpaqueID(rule)
	if rule.ruleNum < RtMaximumLbs {
		R.tables[RtLB].rArr[rule.ruleNum] = nil
	}

	R.deleteVIPSys(rule)
	R.flushLBCtEntries(rule, CtFlushRidMatchOrZero)

	// Clean up GPU worker metrics mappings for all endpoints (GPU-aware routing)
	if mh.dpEbpf != nil && mh.dpEbpf.IsGPUMonitoringEnabled() {
		for _, ep := range eEps {
			endpointIP := fmt.Sprintf("%s:%d", ep.xIP.String(), ep.xPort)
			mh.dpEbpf.DeleteWorkerMetrics(endpointIP)
		}
	}

	// Stop all KV subscribers for this service
	KvSubscriberStopAll(uint32(rule.ruleNum))

	// COMP-01 : Stop vLLM metrics scraper
	if rule.vllmScraper != nil {
		rule.vllmScraper.Stop()
		rule.vllmScraper = nil
	}

	tk.LogIt(tk.LogDebug, "lb-rule deleted %s-%s\n", rule.tuples.String(), rule.act.String())

	rule.DP(DpRemove)

	return 0, nil
}

// flushLBCtEntries - service scoped CT/FC cleanup hook before delete/recreate
func (R *RuleH) flushLBCtEntries(r *ruleEnt, flushMode uint8) {
	if r == nil || mh.dp == nil || mh.dp.DpHooks == nil {
		return
	}

	if r.tuples.l4Prot.val != 132 {
		return
	}

	if r.tuples.l4Dst.valMin != r.tuples.l4Dst.valMax {
		tk.LogIt(tk.LogDebug, "lb-rule ct-flush skipped (port-range) - %s\n", r.tuples.String())
		return
	}

	work := &LBCtDpWorkQ{
		ZoneNum:   r.zone.ZoneNum,
		ServiceIP: r.RuleVIP2PrivIP(),
		L4Port:    r.tuples.l4Dst.valMin,
		Proto:     r.tuples.l4Prot.val,
		BlockNum:  uint32(r.ruleNum),
		RuleID:    uint32(r.ruleNum),
		FlushMode: flushMode,
	}

	if ret := mh.dp.DpHooks.DpLBCtFlush(work); ret != 0 {
		tk.LogIt(tk.LogError, "lb-rule ct-flush failed - %s:%d:%d\n", r.tuples.String(), r.ruleNum, ret)
	}
}

// GetFwRule - get all Fwrules and pack them into a cmn.FwRuleMod slice
func (R *RuleH) GetFwRule() ([]cmn.FwRuleMod, error) {
	var res []cmn.FwRuleMod

	for _, data := range R.tables[RtFw].eMap {
		var ret cmn.FwRuleMod
		// Make Fw Arguments
		ret.Rule.DstIP = data.tuples.l3Dst.addr.String()
		ret.Rule.SrcIP = data.tuples.l3Src.addr.String()
		if data.tuples.l4Dst.valid {
			ret.Rule.DstPortMin = data.tuples.l4Dst.valMin
			ret.Rule.DstPortMax = data.tuples.l4Dst.valMax
		}
		if data.tuples.l4Src.valid {
			ret.Rule.SrcPortMin = data.tuples.l4Src.valMin
			ret.Rule.SrcPortMax = data.tuples.l4Src.valMax
		}

		ret.Rule.Proto = data.tuples.l4Prot.val
		ret.Rule.InPort = data.tuples.port.val
		ret.Rule.Pref = data.tuples.pref

		// Make Fw Opts
		fwOpts := data.act.action.(*ruleFwOpts)
		if fwOpts.op == RtActFwd {
			ret.Opts.Allow = true
		} else if fwOpts.op == RtActDrop {
			ret.Opts.Drop = true
		} else if fwOpts.op == RtActRedirect {
			ret.Opts.Rdr = true
			ret.Opts.RdrPort = fwOpts.opt.rdrPort
		} else if fwOpts.op == RtActTrap {
			ret.Opts.Trap = true
		} else if fwOpts.op == RtActSnat {
			ret.Opts.DoSnat = true
			ret.Opts.ToIP = fwOpts.opt.snatIP
			ret.Opts.ToPort = uint16(fwOpts.opt.snatPort)
		}
		if fwOpts.op != RtActSnat {
			ret.Opts.Mark = fwOpts.opt.fwMark
		}
		ret.Opts.Record = fwOpts.opt.record
		ret.Opts.OnDefault = fwOpts.opt.onDflt

		data.Fw2DP(DpStatsGetImm)
		ret.Opts.Counter = fmt.Sprintf("%v:%v", data.stat.packets, data.stat.bytes)

		// Make FwRule
		res = append(res, ret)
	}

	return res, nil
}

// AddFwRule - Add a firewall rule. The rule details are passed in fwRule argument
// it will return 0 and nil error, else appropriate return code and error string will be set
func (R *RuleH) AddFwRule(fwRule cmn.FwRuleArg, fwOptArgs cmn.FwOptArg) (int, error) {
	var fwOpts ruleFwOpts
	var l4src rule16RTuple
	var l4dst rule16RTuple
	var l4prot rule8Tuple

	// hard-reject gate. Runs before any state mutation
	// (mark allocation, eBPF install, snat-rule side effects) so a
	// rejected HwOffload=true rule leaves no residue in either layer.
	// contract: rejected rule is NOT installed in eBPF either —
	// operator decides whether to retry with HwOffload=false.
	if fwRule.HwOffload {
		if err := validateHwOffloadExpressible(fwRule); err != nil {
			return RuleArgsErr, err
		}
	}

	// Validate rule args
	if fwOptArgs.DoSnat {
		if tk.IsNetIPv6(fwOptArgs.ToIP) {
			if fwRule.DstIP == "0.0.0.0/0" {
				fwRule.DstIP = "::/0"
			}
			if fwRule.SrcIP == "0.0.0.0/0" {
				fwRule.SrcIP = "::/0"
			}
		}
	}

	_, dNetAddr, err := net.ParseCIDR(fwRule.DstIP)
	if err != nil {
		return RuleTupleErr, errors.New("malformed-rule dst error")
	}

	_, sNetAddr, err := net.ParseCIDR(fwRule.SrcIP)
	if err != nil {
		tk.LogIt(tk.LogError, "fw-rule src parse failure %s\n", err)
		return RuleTupleErr, errors.New("malformed-rule src error")
	}

	// Reject mixed IPv4/IPv6 src/dst up front. The datapath cannot express a
	// cross-family rule and would otherwise reject it asynchronously after we
	// had already reported success to the caller.
	if (sNetAddr.IP.To4() == nil) != (dNetAddr.IP.To4() == nil) {
		return RuleArgsErr, errors.New("malformed-rule invalid mixed ipv4/ipv6 src/dst")
	}

	l3dst := ruleIPTuple{*dNetAddr}
	l3src := ruleIPTuple{*sNetAddr}

	if fwRule.Proto == 0 {
		l4prot = rule8Tuple{0, 0}
	} else {
		l4prot = rule8Tuple{fwRule.Proto, 0xff}
	}
	// Reject inverted port ranges instead of silently dropping the tuple, which
	// would make the rule match ALL ports (over-broad allow/drop).
	if fwRule.SrcPortMax != 0 || fwRule.SrcPortMin != 0 {
		if fwRule.SrcPortMax < fwRule.SrcPortMin {
			return RuleArgsErr, errors.New("invalid src port range")
		}
		l4src = rule16RTuple{fwRule.SrcPortMin, fwRule.SrcPortMax, true}
	}
	if fwRule.DstPortMax != 0 || fwRule.DstPortMin != 0 {
		if fwRule.DstPortMax < fwRule.DstPortMin {
			return RuleArgsErr, errors.New("invalid dst port range")
		}
		l4dst = rule16RTuple{fwRule.DstPortMin, fwRule.DstPortMax, true}
	}
	inport := ruleStringTuple{fwRule.InPort}
	rt := ruleTuples{l3Src: l3src, l3Dst: l3dst, l4Prot: l4prot,
		l4Src: l4src, l4Dst: l4dst, port: inport, pref: fwRule.Pref}

	eFw := R.tables[RtFw].eMap[rt.ruleKey()]

	if eFw != nil {
		if !fwOptArgs.DoSnat {
			if eFw.act.action.(*ruleFwOpts).opt.fwMark != fwOptArgs.Mark {
				eFw.Fw2DP(DpRemove)
				eFw.act.action.(*ruleFwOpts).opt.fwMark = fwOptArgs.Mark
				eFw.Fw2DP(DpCreate)
			}
		}
		// If a FW rule already exists
		return RuleExistsErr, errors.New("fwrule-exists error")
	}

	// Cap active fw rules below the datapath tail-call ceiling so the eBPF fw
	// scan never overruns and starts dropping packets.
	if len(R.tables[RtFw].eMap) >= RtMaximumFwActive {
		tk.LogIt(tk.LogError, "fw-rule capacity reached (%d)\n", RtMaximumFwActive)
		return RuleAllocErr, errors.New("fw rule-hwm capacity reached")
	}

	r := new(ruleEnt)
	r.tuples = rt
	r.zone = R.zone
	// persist the opt-IN HW offload flag on the
	// rule entity. Fw2DP copies this into FwDpWorkQ.HwOffload so the
	// DOCA-side dispatcher routes to DENY_PIPE / ALLOW_PIPE.
	r.hwOffload = fwRule.HwOffload

	/* Default is drop */
	fwOpts.op = RtActDrop
	fwOpts.opt.fwMark = fwOptArgs.Mark
	fwOpts.opt.record = fwOptArgs.Record
	fwOpts.opt.onDflt = fwOptArgs.OnDefault

	if fwOptArgs.Allow {
		r.act.actType = RtActFwd
		fwOpts.op = RtActFwd
	} else if fwOptArgs.Drop {
		r.act.actType = RtActDrop
		fwOpts.op = RtActDrop
	} else if fwOptArgs.Rdr {
		r.act.actType = RtActRedirect
		fwOpts.op = RtActRedirect
		fwOpts.opt.rdrPort = fwOptArgs.RdrPort
	} else if fwOptArgs.Trap {
		r.act.actType = RtActTrap
		fwOpts.op = RtActTrap
	} else if fwOptArgs.DoSnat {
		r.act.actType = RtActSnat
		fwOpts.op = RtActSnat
		fwOpts.opt.snatIP = fwOptArgs.ToIP
		fwOpts.opt.snatPort = fwOptArgs.ToPort

		if sIP := net.ParseIP(fwOptArgs.ToIP); sIP == nil {
			return RuleArgsErr, errors.New("malformed-args error")
		}

		if fwOpts.opt.fwMark != 0 {
			return RuleArgsErr, errors.New("malformed-args fwmark !=0 for snat-error")
		}

		if fwOpts.opt.onDflt {
			R.AddRuleVIP(net.ParseIP(fwOptArgs.ToIP), nil, cmn.CIDefault, true)
		}
	}

	r.act.action = &fwOpts
	r.ruleNum, err = R.tables[RtFw].Mark.GetMarker()
	if err != nil {
		tk.LogIt(tk.LogError, "fw-rule - %s:%s mark error\n", r.tuples.String(), r.act.String())
		return RuleAllocErr, errors.New("rule-mark error")
	}
	r.sT = time.Now()

	if fwOptArgs.DoSnat {
		// Create SNAT Rule
		var servArg cmn.LbServiceArg
		servArg.ServIP = "0.0.0.0"
		if tk.IsNetIPv6(fwOpts.opt.snatIP) {
			servArg.ServIP = "::"
		}
		servArg.ServPort = 0
		servArg.Proto = "none"
		servArg.BlockNum = uint32(r.ruleNum) | NatFwMark
		servArg.Sel = cmn.LbSelRr
		servArg.Mode = cmn.LBModeDefault
		servArg.Snat = true
		servArg.InactiveTimeout = LbDefaultInactiveTimeout
		servArg.Name = fmt.Sprintf("%s:%s:%d", "snat", fwOpts.opt.snatIP, fwOpts.opt.snatPort)

		snatEP := []cmn.LbEndPointArg{{EpIP: fwOpts.opt.snatIP, EpPort: fwOpts.opt.snatPort}}

		_, err := R.AddLbRule(servArg, nil, nil, nil, snatEP)
		if err != nil {
			tk.LogIt(tk.LogError, "fw-rule - %s:%s (%s) snat create error\n", r.tuples.String(), r.act.String(), err)
			return RuleArgsErr, errors.New("rule-snat error")
		}

		if !fwOptArgs.OnDefault {
			fwOpts.opt.fwMark = uint32(r.ruleNum) | NatFwMark
		} else {
			fwOpts.opt.fwMark = uint32(r.ruleNum) | OnDfltSnatFwMark
		}
	}

	tk.LogIt(tk.LogDebug, "fw-rule added - %d:%s-%s\n", r.ruleNum, r.tuples.String(), r.act.String())

	R.tables[RtFw].eMap[rt.ruleKey()] = r

	if fwOptArgs.OnDefault {
		state, err := mh.has.CIStateGetInst(cmn.CIDefault)
		if err == nil {
			if state == cmn.CIBackupStateString {
				return 0, nil
			}
		}
	}

	r.Fw2DP(DpCreate)

	return 0, nil
}

// DeleteFwRule - Delete a firewall rule,
// On success, it will return 0 and nil error, else appropriate return code and
// error string will be set
func (R *RuleH) DeleteFwRule(fwRule cmn.FwRuleArg) (int, error) {
	var l4src rule16RTuple
	var l4dst rule16RTuple
	var l4prot rule8Tuple

	// Vaildate rule args
	_, dNetAddr, err := net.ParseCIDR(fwRule.DstIP)
	if err != nil {
		return RuleTupleErr, errors.New("malformed-rule dst error")
	}

	_, sNetAddr, err := net.ParseCIDR(fwRule.SrcIP)
	if err != nil {
		return RuleTupleErr, errors.New("malformed-rule src error")
	}

	l3dst := ruleIPTuple{*dNetAddr}
	l3src := ruleIPTuple{*sNetAddr}

	if fwRule.Proto == 0 {
		l4prot = rule8Tuple{0, 0}
	} else {
		l4prot = rule8Tuple{fwRule.Proto, 0xff}
	}

	if (fwRule.SrcPortMax != 0 || fwRule.SrcPortMin != 0) && fwRule.SrcPortMax >= fwRule.SrcPortMin {
		l4src = rule16RTuple{fwRule.SrcPortMin, fwRule.SrcPortMax, true}
	}
	if (fwRule.DstPortMax != 0 || fwRule.DstPortMin != 0) && fwRule.DstPortMax >= fwRule.DstPortMin {
		l4dst = rule16RTuple{fwRule.DstPortMin, fwRule.DstPortMax, true}
	}
	inport := ruleStringTuple{fwRule.InPort}
	rt := ruleTuples{l3Src: l3src, l3Dst: l3dst, l4Prot: l4prot, l4Src: l4src, l4Dst: l4dst, port: inport, pref: fwRule.Pref}

	rule := R.tables[RtFw].eMap[rt.ruleKey()]
	if rule == nil {
		return RuleNotExistsErr, errors.New("no-rule error")
	}

	if rule.act.actType == RtActSnat {
		// Delete implicit SNAT Rule
		var servArg cmn.LbServiceArg
		servArg.ServIP = "0.0.0.0"
		servArg.ServPort = 0
		servArg.Proto = "none"
		servArg.BlockNum = uint32(rule.ruleNum) | NatFwMark
		servArg.Sel = cmn.LbSelRr
		servArg.Mode = cmn.LBModeDefault
		servArg.Snat = true

		switch fwOpts := rule.act.action.(type) {
		case *ruleFwOpts:
			if tk.IsNetIPv6(fwOpts.opt.snatIP) {
				servArg.ServIP = "::"
				if fwRule.DstIP == "0.0.0.0/0" {
					fwRule.DstIP = "::/0"
				}
				if fwRule.SrcIP == "0.0.0.0/0" {
					fwRule.SrcIP = "::/0"
				}
			}

			servArg.Name = fmt.Sprintf("%s:%s:%d", "Masq", fwOpts.opt.snatIP, fwOpts.opt.snatPort)
			if fwOpts.opt.onDflt {
				R.DeleteRuleVIP(net.ParseIP(fwOpts.opt.snatIP))
			}
		}

		_, err := R.DeleteLbRule(servArg)
		if err != nil {
			tk.LogIt(tk.LogError, "fw-rule - %s:%s snat delete error\n", rule.tuples.String(), rule.act.String())
		}
	}

	defer R.tables[RtFw].Mark.ReleaseMarker(rule.ruleNum)

	delete(R.tables[RtFw].eMap, rt.ruleKey())

	tk.LogIt(tk.LogDebug, "fw-rule deleted %s-%s\n", rule.tuples.String(), rule.act.String())

	rule.Fw2DP(DpRemove)

	return 0, nil
}

// GetEpHosts - get all end-points and pack them into a cmn.EndPointMod slice
func (R *RuleH) GetEpHosts() ([]cmn.EndPointMod, error) {
	var res []cmn.EndPointMod

	for _, data := range R.epMap {
		var ret cmn.EndPointMod
		// Make end-point
		ret.HostName = data.hostName
		ret.Name = data.epKey
		ret.RuleManaged = data.ruleCount > 0
		if !data.opts.probeActivated {
			ret.ProbeType = HostProbeNone
		} else {
			ret.ProbeType = data.opts.probeType
			ret.ProbeDuration = data.opts.probeDuration
			ret.InActTries = data.opts.inActTryThr
		}
		ret.ProbeReq = data.opts.probeReq
		ret.ProbeResp = data.opts.probeResp
		ret.ProbePort = data.opts.probePort
		if ret.ProbeType == HostProbePing {
			ret.MinDelay = fmt.Sprintf("%v", data.minDelay)
			ret.AvgDelay = fmt.Sprintf("%v", data.avgDelay)
			ret.MaxDelay = fmt.Sprintf("%v", data.maxDelay)
		}
		if data.inactive {
			ret.CurrState = "nok"
		} else {
			ret.CurrState = "ok"
		}

		if data.hostState == cmn.HostStateRed {
			ret.CurrState = "red"
		}

		// Append to slice
		res = append(res, ret)
	}

	return res, nil
}

// IsEPHostActive - Check if end-point is active
func (R *RuleH) IsEPHostActive(epKey string) bool {
	ep := R.epMap[epKey]
	if ep == nil {
		return true // Are we sure ??
	}

	if ep.hostState == cmn.HostStateRed {
		return false
	}

	return !ep.inactive
}

func validateEPHostOpts(hostName string, args epHostOpts) (int, error) {
	// Validate hostopts
	if net.ParseIP(hostName) == nil {
		return RuleArgsErr, errors.New("host-parse error")
	}

	if args.inActTryThr > MaxDflLbaInactiveTries ||
		args.probeDuration > MaxHostProbeTime {
		return RuleArgsErr, errors.New("host-args error")
	}

	if args.probeType != HostProbePing &&
		args.probeType != HostProbeConnectTCP &&
		args.probeType != HostProbeConnectUDP &&
		args.probeType != HostProbeConnectSCTP &&
		args.probeType != HostProbeHTTP &&
		args.probeType != HostProbeHTTPS &&
		args.probeType != HostProbeTLSHello &&
		args.probeType != HostProbeNone {
		return RuleArgsErr, errors.New("host-args unknown probe type")
	}

	if (args.probeType == HostProbeConnectTCP ||
		args.probeType == HostProbeConnectUDP ||
		args.probeType == HostProbeConnectSCTP) &&
		args.probePort == 0 {
		return RuleArgsErr, errors.New("host-args unknown probe port")
	}

	return 0, nil
}

func makeEPKey(hostName string, probeType string, probePort uint16) string {
	return hostName + "_" + probeType + "_" + strconv.Itoa(int(probePort))
}

// AddEPHost - Add an end-point host
// name, if present will be used as endpoint key
// It will return 0 and nil error, else appropriate return code and error string will be set
func (R *RuleH) AddEPHost(apiCall bool, hostName string, name string, args epHostOpts) (int, error) {
	var epKey string

	if apiCall && args.probeType != HostProbeNone {
		args.probeActivated = true
	}

	R.epMx.Lock()
	defer R.epMx.Unlock()

	// Validate hostopts
	_, err := validateEPHostOpts(hostName, args)
	if err != nil {
		tk.LogIt(tk.LogError, "Failed to add EP :%s\n", err)
		return RuleArgsErr, err
	}
	// Load CA cert into pool
	if args.probeType == HostProbeHTTPS {
		// Check if there exist a CA certificate particularly for this EP
		rootCACertile := cmn.CertPath + hostName + "/" + cmn.CACertFileName
		if exists := utils.FileExists(rootCACertile); exists {
			rootCA, err := os.ReadFile(rootCACertile)
			if err != nil {
				tk.LogIt(tk.LogError, "RootCA cert load failed : %v", err)
				return RuleArgsErr, errors.New("rootca cert load failed")
			}
			R.rootCAPool.AppendCertsFromPEM(rootCA)
			tk.LogIt(tk.LogDebug, "RootCA cert loaded for %s\n", hostName)
		}
	}
	if name == "" {
		epKey = makeEPKey(hostName, args.probeType, args.probePort)
	} else {
		epKey = name
	}

	ep := R.epMap[epKey]
	if ep != nil {
		if apiCall {
			egress := ep.opts.egress
			ep.opts = args
			if egress {
				ep.opts.egress = egress
			}
			ep.opts.currProbeDuration = ep.opts.probeDuration
			ep.initProberOn = true
			return 0, nil
		}
		ep.ruleCount++
		return 0, nil
	}

	ep = new(epHost)
	ep.epKey = epKey
	ep.hostName = hostName
	ep.opts = args
	ep.initProberOn = true
	ep.opts.currProbeDuration = ep.opts.probeDuration

	if apiCall != true {
		ep.ruleCount = 1
	}
	// if args.probeType != HostProbeConnectUDP
	// Set ep.hID = 0, if we need to disable threads
	ep.hID = R.lepHID % MaxEndPointCheckers
	//ep.sT = time.Now
	R.lepHID++

	if args.egress {
		epNode := cmn.ClusterNodeMod{Addr: net.ParseIP(hostName),
			Egress: true}
		_, err := mh.has.ClusterNodeAdd(epNode)
		if err != nil {
			return -1, errors.New("ep-host add failed as cluster node")
		}
	}

	R.epMap[epKey] = ep

	tk.LogIt(tk.LogDebug, "ep-host added %v:%d\n", epKey, ep.hID)

	return 0, nil
}

// DeleteEPHost - Delete an end-point host
// It will return 0 and nil error, else appropriate return code and error string will be set
func (R *RuleH) DeleteEPHost(apiCall bool, name string, hostName string, probeType string, probePort uint16) (int, error) {
	var key string

	R.epMx.Lock()
	defer R.epMx.Unlock()
	if name == "" {
		key = makeEPKey(hostName, probeType, probePort)
	} else {
		key = name
	}
	ep := R.epMap[key]
	if ep == nil {
		return RuleEpNotExistErr, errors.New("host-notfound error")
	}

	if apiCall == false {
		ep.ruleCount--
	}

	if ep.ruleCount > 0 {
		return RuleEpCountErr, errors.New("LB Rule-referred")
	}

	delete(R.epMap, ep.epKey)

	tk.LogIt(tk.LogDebug, "ep-host deleted %v\n", key)

	return 0, nil
}

// SetEPHostState - Set an end-point host state
// It will return 0 and nil error, else appropriate return code and error string will be set
func (R *RuleH) SetEPHostState(hostName string, epPort uint16, epProto string, state string) (int, error) {

	if state != cmn.HostStateGreen && state != cmn.HostStateYellow && state != cmn.HostStateRed {
		return RuleEpHostUnkErr, errors.New("unknown ep-host-state")
	}

	key := ""
	if epPort != 0 && epProto == "" ||
		epPort == 0 && epProto != "" {
		return RuleEpHostUnkErr, errors.New("ep-host-state args error")
	}

	if epProto != "" {
		key = makeEPKey(hostName, epProto, epPort)
	}

	R.epMx.Lock()
	defer R.epMx.Unlock()

	if key != "" {
		ep := R.epMap[key]
		if ep == nil {
			return RuleEpNotExistErr, errors.New("ephost-notfound error")
		}
		oldState := ep.hostState
		ep.hostState = state
		tk.LogIt(tk.LogDebug, "ep %s - %s\n", ep.epKey, ep.hostState)

		// P2 GPU-Aware: Immediately update sockproxy for FullProxy rules
		// This provides sub-second response to GPU state changes (vs 5-10s periodic sync)
		if oldState != state && mh.dp != nil && mh.dp.DpHooks != nil {
			R.applyHostStateToRules(ep.hostName, epPort, epProto, state)
		}
	} else {
		updatedEPs := make(map[string]bool)
		for _, ep := range R.epMap {
			if ep.hostName == hostName {
				oldState := ep.hostState
				ep.hostState = state
				tk.LogIt(tk.LogDebug, "ep %s - %s\n", ep.epKey, ep.hostState)

				// Track unique endpoints to avoid duplicate updates
				if oldState != state && !updatedEPs[ep.epKey] {
					updatedEPs[ep.epKey] = true
				}
			}
		}

		// P2 GPU-Aware: Apply state changes to all matching endpoints
		if len(updatedEPs) > 0 && mh.dp != nil && mh.dp.DpHooks != nil {
			R.applyHostStateToRules(hostName, 0, "", state)
		}
	}

	return 0, nil
}

// applyHostStateToRules - P2 GPU-Aware: Apply hostState changes to FullProxy rules immediately
// This function finds all FullProxy LB rules using the specified endpoint and updates sockproxy
func (R *RuleH) applyHostStateToRules(hostName string, epPort uint16, epProto string, state string) {
	// Iterate through all LB rules
	for _, rule := range R.tables[RtLB].eMap {
		switch na := rule.act.action.(type) {
		case *ruleLBActs:
			// Only process FullProxy mode rules
			if na.mode != cmn.LBModeFullProxy {
				continue
			}

			// Find matching endpoint in this rule
			for idx, ep := range na.endPoints {
				// Match by hostname (IP address)
				if ep.xIP.String() != hostName {
					continue
				}

				// If specific port/proto specified, match those too
				if epPort != 0 && ep.xPort != epPort {
					continue
				}

				// Determine protocol type
				var sType string
				if rule.tuples.l4Prot.val == 6 {
					sType = HostProbeConnectTCP
				} else if rule.tuples.l4Prot.val == 17 {
					sType = HostProbeConnectUDP
				} else if rule.tuples.l4Prot.val == 132 {
					sType = HostProbeConnectSCTP
				} else {
					continue
				}

				if epProto != "" && epProto != sType {
					continue
				}

				// Found matching endpoint - update sockproxy
				svcIP := rule.tuples.l3Dst.addr.IP
				svcPort := rule.tuples.l4Dst.valMin
				proto := rule.tuples.l4Prot.val
				epIP := ep.xIP

				ret := mh.dp.DpHooks.DpLBEndpointHostStateUpdate(svcIP, svcPort, proto, epIP, state)
				if ret == 0 {
					tk.LogIt(tk.LogInfo, "P2 GPU: Applied hostState '%s' to sockproxy - svc=%v:%v ep=%v\n",
						state, svcIP, svcPort, epIP)
				} else {
					tk.LogIt(tk.LogError, "P2 GPU: Failed to apply hostState to sockproxy - svc=%v:%v ep=%v\n",
						svcIP, svcPort, epIP)
				}

				// Note: idx variable is available but unused in this context
				_ = idx
			}
		}
	}
}

func (ep *epHost) transitionEPState(currState bool, inactThr int) {
	if currState {
		// Reset the failure counter on ANY successful probe, not only when
		// transitioning back from inactive. Otherwise inActTries accumulates
		// across the endpoint's entire active lifetime, so sporadic, non-
		// consecutive probe misses eventually trip inactThr and flap a healthy
		// endpoint to inactive. proberetries is documented as the number of
		// retries before marking an endpoint inactive (consecutive failures).
		ep.inActTries = 0
		if ep.inactive {
			ep.inactive = false
			ep.opts.currProbeDuration = ep.opts.probeDuration
			tk.LogIt(tk.LogDebug, "active ep - %s:%s:%d(%v)\n",
				ep.epKey, ep.opts.probeType, ep.opts.probePort, ep.avgDelay)
		}
	} else {
		if ep.inActTries < inactThr {
			ep.inActTries++
			if ep.inActTries >= inactThr {
				if !ep.inactive {
					tk.LogIt(tk.LogDebug, "inactive ep - %s:%s:%d(next try after %ds)\n",
						ep.epKey, ep.opts.probeType, ep.opts.probePort, ep.opts.currProbeDuration)
				}
				ep.inactive = true
			}
		} else {
			ep.inActTries++
			// Inactive eps are moved back
			if ep.opts.currProbeDuration < 3*DflHostProbeTimeout {
				ep.opts.currProbeDuration += 20
			}
			//tk.LogIt(tk.LogDebug, "inactive ep - %s:%s:%d(next try after %ds)\n",
			//	ep.epKey, ep.opts.probeType, ep.opts.probePort, ep.opts.currProbeDuration)
		}
	}
}

// syncEPImmediate immediately syncs all LB rules' DP state when an EP's health
// status changes. This avoids the up-to-20-second lag that would otherwise occur
// waiting for the periodic (10s) RulesSync ticker to pick up the change.
// Must be called without mh.mtx held (it acquires the lock internally).
func (R *RuleH) syncEPImmediate() {
	mh.mtx.Lock()
	defer mh.mtx.Unlock()
	for _, rule := range R.tables[RtLB].eMap {
		if !rule.hChk.actChk {
			continue
		}
		rChg := R.syncEPHostState2Rule(rule, true)
		if rChg {
			rule.DP(DpCreate)
		}
	}
}

func (R *RuleH) epCheckNow(ep *epHost) {
	var sType string
	sHint := ""

	// Capture inactive state before probe so we can detect transitions
	prevInactive := ep.inactive
	defer func() {
		if prevInactive != ep.inactive {
			// EP state flipped (active↔inactive) — immediately push DP update
			// instead of waiting up to 20s for the periodic RulesSync ticker
			R.syncEPImmediate()
		}
	}()

	inActTryThr := ep.opts.inActTryThr
	if ep.initProberOn {
		inActTryThr = 1
		ep.initProberOn = false
	}

	sName := fmt.Sprintf("%s:%d", ep.hostName, ep.opts.probePort)
	if tk.IsNetIPv6(ep.hostName) {
		sName = fmt.Sprintf("[%s]:%d", ep.hostName, ep.opts.probePort)
	}

	if !ep.opts.probeActivated {
		ep.inactive = false
		ep.inActTries = 0
		return
	}

	if ep.opts.probeType == HostProbeConnectTCP ||
		ep.opts.probeType == HostProbeConnectUDP ||
		ep.opts.probeType == HostProbeConnectSCTP {
		if ep.opts.probeType == HostProbeConnectTCP {
			sType = "tcp"
		} else if ep.opts.probeType == HostProbeConnectUDP {
			sType = "udp"
		} else {
			sType = "sctp"
		}

		if mh.cloudHook == nil {
			ret, sIP, _ := R.zone.L3.IfaSelectAny(net.ParseIP(ep.hostName), true)
			if ret == 0 {
				sHint = sIP.String()
			}
		} else {
			// For AWS/EKS environments we need to rely on system tables as compared to
			// internal tables due to how elastic VIPs are maintained
			IfObj := FindSysOifForHost(ep.hostName)
			if IfObj != "" && IfObj != "lo" {
				ret, sIP, _ := R.zone.L3.IfaSelect(IfObj, net.ParseIP(ep.hostName), true)
				if ret == 0 {
					sHint = sIP.String()
				}
			}
		}
		sOk := tk.L4ServiceProber(sType, sName, sHint, ep.opts.probeReq, ep.opts.probeResp)
		ep.transitionEPState(sOk, inActTryThr)
	} else if ep.opts.probeType == HostProbePing {
		pinger, err := probing.NewPinger(ep.hostName)
		if err != nil {
			return
		}

		pinger.Count = ep.opts.inActTryThr
		pinger.Size = 100
		pinger.Interval = time.Duration(200000000)
		pinger.Timeout = time.Duration(500000000)
		pinger.SetPrivileged(true)

		//pinger.OnFinish = func(stats *ping.Statistics) {
		//	fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
		//	fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
		//		stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		//	fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
		//		stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
		//}

		//pinger.OnRecv = func(pkt *probing.Packet) {
		//	fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
		//		pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
		//}
		err = pinger.Run()
		if err != nil {
			return
		}

		stats := pinger.Statistics()

		if stats.PacketsRecv != 0 {
			ep.avgDelay = stats.AvgRtt
			ep.minDelay = stats.MinRtt
			ep.maxDelay = stats.MaxRtt
			ep.transitionEPState(true, 1)
		} else {
			ep.avgDelay = time.Duration(0)
			ep.minDelay = time.Duration(0)
			ep.maxDelay = time.Duration(0)
			ep.transitionEPState(false, 1)
		}
		pinger.Stop()
	} else if ep.opts.probeType == HostProbeHTTP {
		var addr net.IP
		if addr = net.ParseIP(ep.hostName); addr == nil {
			// This is already verified
			return
		}

		// structured path/method/Host build with probeReq as the
		// escape hatch. probePath wins when set; else fall back to probeReq.
		path := ep.opts.probePath
		if path == "" {
			path = ep.opts.probeReq
		}
		urlStr := fmt.Sprintf("http://%s:%d/%s", addr.String(), ep.opts.probePort, strings.TrimPrefix(path, "/"))
		method := ep.opts.probeMethod
		if method == "" {
			method = ghttp.MethodGet
		}
		hclient := &ghttp.Client{Timeout: 5 * time.Second}
		hreq, rerr := ghttp.NewRequest(method, urlStr, nil)
		if rerr != nil {
			ep.transitionEPState(false, inActTryThr)
			return
		}
		// http_version 1.1 ⇒ send Host = domain_name (else member address).
		if ep.opts.httpVersion == "1.1" {
			if ep.opts.domainName != "" {
				hreq.Host = ep.opts.domainName
			} else {
				hreq.Host = addr.String()
			}
		}
		hresp, herr := hclient.Do(hreq)
		sOk := herr == nil && expectedCodeOK(parseExpectedCodes(ep.opts.expectedCodes), hresp.StatusCode)
		if herr == nil {
			hresp.Body.Close()
		}
		ep.transitionEPState(sOk, inActTryThr)
	} else if ep.opts.probeType == HostProbeHTTPS {
		var addr net.IP
		if addr = net.ParseIP(ep.hostName); addr == nil {
			// This is already verified
			return
		}

		var sOk bool
		// when any structured HM-content field is configured, run a
		// local crypto/tls + net/http prober that sets SNI = domain_name and
		// Host = domain_name, uses http_method/url_path, and matches
		// the StatusCode against expected_codes. When none are set, fall back to the
		// existing utils.HTTPSProber substring match (probeResp escape hatch).
		if ep.opts.expectedCodes != "" || ep.opts.probeMethod != "" ||
			ep.opts.probePath != "" || ep.opts.httpVersion == "1.1" || ep.opts.domainName != "" {
			sOk = R.httpsContentProbe(addr, ep.opts)
		} else {
			urlStr := fmt.Sprintf("https://%s:%d/%s", addr.String(), ep.opts.probePort, strings.TrimPrefix(ep.opts.probeReq, "/"))
			sOk = utils.HTTPSProber(urlStr, R.tlsCert, R.rootCAPool, ep.opts.probeResp)
		}
		//tk.LogIt(tk.LogDebug, "[PROBE] https ep - URL[%s:%d] Resp[%s] %v\n", ep.hostName, ep.opts.probePort, ep.opts.probeResp, sOk)
		ep.transitionEPState(sOk, inActTryThr)
	} else if ep.opts.probeType == HostProbeTLSHello {
		// handshake-only TLS liveness. UP iff the TLS handshake
		// completes; the cert chain is NOT validated (any cert accepted — this is
		// liveness, not a trust probe). SNI = domain_name (consistency). A non-TLS
		// port (no ServerHello) fails the handshake ⇒ DOWN.
		var addr net.IP
		if addr = net.ParseIP(ep.hostName); addr == nil {
			// This is already verified
			return
		}
		sOk := tlsHelloProbe(addr, ep.opts.probePort, ep.opts.domainName)
		ep.transitionEPState(sOk, inActTryThr)
	} else {
		// TODO
		ep.inactive = false
		ep.inActTries = 0
	}
}

// tlsHelloProbe runs handshake-only TLS liveness probe against
// addr:port. It returns true iff the TLS handshake completes. The cert chain is
// INTENTIONALLY NOT validated (InsecureSkipVerify) — tls-hello is a liveness probe,
// not a trust probe (any cert, including self-signed, marks the port UP). SNI is set
// to sni (the health-monitor's domain_name consistency); an empty sni falls back
// to the member address so a bare-IP TLS listener still completes. A non-TLS port never
// sends a ServerHello, so the handshake fails ⇒ the port is DOWN.
func tlsHelloProbe(addr net.IP, port uint16, sni string) bool {
	serverName := sni
	if serverName == "" {
		serverName = addr.String()
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp",
		fmt.Sprintf("%s:%d", addr.String(), port),
		&tls.Config{
			InsecureSkipVerify: true, // handshake-only liveness — chain NOT validated
			ServerName:         serverName,
		})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// httpsContentProbe runs HTTPS health probe with structured
// content semantics: TLS SNI = domain_name, Host = domain_name (else
// member address), the configured http_method + url_path, and a StatusCode match
// against expected_codes. It reuses R.tlsCert / R.rootCAPool exactly as the legacy
// utils.HTTPSProber path does. Returns true iff the response status is expected.
func (R *RuleH) httpsContentProbe(addr net.IP, opts epHostOpts) bool {
	path := opts.probePath
	if path == "" {
		path = opts.probeReq
	}
	urlStr := fmt.Sprintf("https://%s:%d/%s", addr.String(), opts.probePort, strings.TrimPrefix(path, "/"))
	method := opts.probeMethod
	if method == "" {
		method = ghttp.MethodGet
	}

	// SNI = domain_name (else member address) so a shared backend is probed for
	// the intended vhost.
	serverName := opts.domainName
	if serverName == "" {
		serverName = addr.String()
	}
	// per-probe CA override + verify opt-out.
	//   - probeVerify==false ⇒ InsecureSkipVerify (explicit operator opt-out; the default
	// resolved value is true ⇒ verification ON).
	//   - probeCAPath != "" ⇒ build the RootCAs pool from that file instead of R.rootCAPool;
	//     empty ⇒ R.rootCAPool (today's behaviour, unchanged).
	rootCAs := R.rootCAPool
	if opts.probeCAPath != "" {
		if pool := probeCAPool(opts.probeCAPath); pool != nil {
			rootCAs = pool
		}
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		Certificates:       []tls.Certificate{R.tlsCert},
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: !opts.probeVerify,
	}
	tr := &ghttp.Transport{TLSClientConfig: tlsCfg}
	hclient := &ghttp.Client{Timeout: 5 * time.Second, Transport: tr}
	defer tr.CloseIdleConnections()

	hreq, rerr := ghttp.NewRequest(method, urlStr, nil)
	if rerr != nil {
		return false
	}
	// Host header mirrors the HTTP path: domain_name when set, else member address.
	hreq.Host = serverName

	hresp, herr := hclient.Do(hreq)
	if herr != nil {
		return false
	}
	defer hresp.Body.Close()
	return expectedCodeOK(parseExpectedCodes(opts.expectedCodes), hresp.StatusCode)
}

// probeCAPool builds an x509 CertPool from the PEM file at caPath
// per-probe CA-bundle override). It returns nil on any read/parse failure so the caller
// falls back to R.rootCAPool (the override is best-effort; a missing file must not panic
// the health goroutine). An empty caPath is never passed here (guarded by the caller).
func probeCAPool(caPath string) *x509.CertPool {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		tk.LogIt(tk.LogError, "[PROBE] probe_ca_path read failed (%s): %v\n", caPath, err)
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		tk.LogIt(tk.LogError, "[PROBE] probe_ca_path has no valid PEM certs (%s)\n", caPath)
		return nil
	}
	return pool
}

func epTicker(R *RuleH, helper int) {
	epc := R.epCs[helper]

	idx := 0
	tlen := 0
	var run uint32
	run = 0

	for {
		select {
		case <-epc.tD:
			return
		case t := <-epc.hChk.C:
			epHosts := make([]*epHost, 0)
			tk.LogIt(-1, "Tick at %v:%d\n", t, helper)

			R.epMx.Lock()
			if tlen != len(R.epMap) || idx >= len(R.epMap) {
				idx = 0
				tlen = len(R.epMap)
			}
			if idx > 0 {
				idx = 0
				// We restart the sweep from beginning while taking a short break
				// Due to how goLang range works, we would be sweeping eps mostly randomly
				R.epMx.Unlock()
				break
			}
			tidx := 0
			for _, host := range R.epMap {

				if host.hID == uint8(helper) {

					if run%2 == 0 {
						if (host.opts.probeType == HostProbePing && host.avgDelay == 0) || host.inactive ||
							(host.initProberOn && time.Duration(t.Sub(host.sT).Seconds()) >= time.Duration(InitHostProbeTimeout)) {
							epHosts = append(epHosts, host)
						}
					} else {
						if (host.initProberOn && time.Duration(t.Sub(host.sT).Seconds()) >= time.Duration(InitHostProbeTimeout)) ||
							time.Duration(t.Sub(host.sT).Seconds()) >= time.Duration(host.opts.currProbeDuration) {
							epHosts = append(epHosts, host)
						}
					}
					if len(epHosts) >= MaxEndPointSweeps {
						idx = tidx + 1
						break
					}
				}
				tidx++
			}
			R.epMx.Unlock()
			run++

			begin := time.Now()
			for _, eph := range epHosts {
				R.epCheckNow(eph)
				eph.sT = time.Now()
				if time.Duration(eph.sT.Sub(begin).Seconds()) >= EndPointCheckerDuration {
					break
				}
			}
		}
	}
}

// RulesSync - This is periodic ticker routine which does two main things :
// 1. Syncs rule statistics counts
// 2. Check health of lb-rule end-points
func (R *RuleH) RulesSync() {
	rChg := false
	for _, rule := range R.tables[RtLB].eMap {
		ruleKeys := rule.tuples.String()
		ruleActs := rule.act.String()
		rChg = R.electEPSrc(rule)
		rlChg := false
		switch at := rule.act.action.(type) {
		case *ruleLBActs:
			if at.mode == cmn.LBModeHostOneArm {
				rlChg = R.mkHostAssocs(rule)
			}
		}
		if rlChg {
			// Dont support modify currently
			rule.DP(DpRemove)
			rule.DP(DpCreate)
		} else if rule.sync != 0 || rChg {
			rule.DP(DpCreate)
		}

		if !rule.hChk.actChk {
			continue
		}

		rChg = R.syncEPHostState2Rule(rule, false)
		if rChg {
			tk.LogIt(tk.LogDebug, "lb-Rule updated %d:%s,%s\n", rule.ruleNum, ruleKeys, ruleActs)
			rule.DP(DpCreate)
		}
	}

	if time.Duration(time.Since(R.vipST).Seconds()) > time.Duration(VIPSweepDuration) {
		for vip, vipElem := range R.vipMap {
			ip := vipElem.pVIP
			if ip == nil {
				ip = net.ParseIP(vip)
			}
			if ip != nil {
				R.AdvRuleVIP(ip, net.ParseIP(vip), vipElem.inst, vipElem.egr)
			}
		}
		R.vipST = time.Now()
	}

	for _, rule := range R.tables[RtFw].eMap {
		//ruleKeys := rule.tuples.String
		//ruleActs := rule.act.String
		if rule.sync != 0 {
			rule.Fw2DP(DpCreate)
		}
		//rule.DP(DpStatsGet)
		//tk.LogIt(-1, "%d:%s,%s pc %v bc %v \n",
		//	rule.ruleNum, ruleKeys, ruleActs,
		//	rule.stat.packets, rule.stat.bytes)
	}

	// recompute per-rule live/total/directional connection statistics
	// (activeConns / totalConns / bytesIn / bytesOut) from a single conntrack-map walk.
	// This is the cheapest race-free recompute pass (RulesSync ticker); the rollup folds
	// the per-direction CT byte split + the selector-agnostic live count + the monotonic
	// total directly into each ruleEnt's in-memory counters, which the GET .../stats
	// handler then serializes. The counters reset to zero on restart.
	if mh.dp != nil {
		mh.dp.DpCtStatsRollup()
	}
}

// RulesTicker - Ticker for all rules
func (R *RuleH) RulesTicker() {
	R.RulesSync()
}

// RuleDestructAll - Destructor routine for all rules
func (R *RuleH) RuleDestructAll() {
	var lbs cmn.LbServiceArg
	var fwr cmn.FwRuleArg
	fmt.Printf("Deleting Rules\n")

	for _, r := range R.tables[RtLB].eMap {
		lbs.ServIP = r.tuples.l3Dst.addr.IP.String()
		tk.LogIt(tk.LogDebug, "Deleting %s\n", r.tuples.l3Dst.addr.IP.String())

		if r.tuples.l4Prot.val == 6 {
			lbs.Proto = "tcp"
		} else if r.tuples.l4Prot.val == 1 {
			lbs.Proto = "icmp"
		} else if r.tuples.l4Prot.val == 17 {
			lbs.Proto = "udp"
		} else if r.tuples.l4Prot.val == 132 {
			lbs.Proto = "sctp"
		} else if r.tuples.l4Prot.val == 0 {
			lbs.Proto = "none"
		} else {
			continue
		}

		lbs.ServPort = r.tuples.l4Dst.valMin
		lbs.ServPortMax = r.tuples.l4Dst.valMax
		R.DeleteLbRule(lbs)
	}
	for _, r := range R.tables[RtFw].eMap {
		fwr.DstIP = r.tuples.l3Dst.addr.String()
		fwr.SrcIP = r.tuples.l3Src.addr.String()
		if r.tuples.l4Src.valid {
			fwr.SrcPortMin = r.tuples.l4Src.valMin
			fwr.SrcPortMax = r.tuples.l4Src.valMax
		}
		if r.tuples.l4Dst.valid {
			fwr.DstPortMin = r.tuples.l4Dst.valMin
			fwr.DstPortMax = r.tuples.l4Dst.valMax
		}

		fwr.Proto = r.tuples.l4Prot.val
		fwr.InPort = r.tuples.port.val

		R.DeleteFwRule(fwr)
	}
}

// VIP2DP - Sync state of nat-rule for local sock VIP-port rewrite
func (r *ruleEnt) VIP2DP(work DpWorkT) int {
	portMap := make(map[int]struct{})
	if mh.lSockPolicy {
		switch at := r.act.action.(type) {
		case *ruleLBActs:
			for _, ep := range at.endPoints {
				if _, ok := portMap[int(ep.xPort)]; ok {
					continue
				}
				portMap[int(ep.xPort)] = struct{}{}
				nVIPWork := new(SockVIPDpWorkQ)
				nVIPWork.Work = work
				if ep.inActiveEP {
					nVIPWork.Work = DpRemove
				}
				nVIPWork.VIP = r.tuples.l3Dst.addr.IP.Mask(r.tuples.l3Dst.addr.Mask)
				nVIPWork.Port = r.tuples.l4Dst.valMin
				nVIPWork.RwPort = ep.xPort
				nVIPWork.Status = new(DpStatusT)
				mh.dp.ToDpCh <- nVIPWork
			}
		}
	}
	return 0
}

// LB2DP - Sync state of lb-rule entity to data-path
func (r *ruleEnt) LB2DP(work DpWorkT) int {

	// [CP-DEBUG] Stage 3: LB2DP gate - log entry and addrRslv state
	if r.addrRslv {
		tk.LogIt(tk.LogWarning, "[CP-DEBUG] LB2DP: VIP=%s port=%d DP BLOCKED - addrRslv=true\n",
			r.tuples.l3Dst.addr.IP.String(), r.tuples.l4Dst.valMin)
		return -1
	}

	if r.egress {
		return 0
	}

	tk.LogIt(tk.LogInfo, "[CP-DEBUG] LB2DP: VIP=%s port=%d work=%d - proceeding to DP\n",
		r.tuples.l3Dst.addr.IP.String(), r.tuples.l4Dst.valMin, work)

	nWork := new(LBDpWorkQ)

	nWork.Work = work
	nWork.Status = &r.sync
	nWork.ZoneNum = r.zone.ZoneNum
	if r.tuples.l4Dst.valMax == r.tuples.l4Dst.valMin {
		nWork.ServiceIP = r.RuleVIP2PrivIP()
		nWork.L4Port = r.tuples.l4Dst.valMin
		nWork.Proto = r.tuples.l4Prot.val
		nWork.BlockNum = r.tuples.pref
	} else {
		nWork.BlockNum = uint32(r.ruleNum) << 16
	}
	nWork.Mark = int(r.ruleNum)
	nWork.InActTo = uint64(r.iTO)
	nWork.PersistTo = uint64(r.pTO)
	nWork.ConnLimit = r.connLimit // per-service concurrent-conn ceiling (0 = unlimited)
	nWork.HostURL = r.tuples.path
	nWork.PathPrefix = r.tuples.pathPrefix                            // P6: Pass path prefix
	nWork.PathMatchMode = r.tuples.pathMatchMode                      // P6: Pass path match mode
	nWork.ModelName = r.tuples.modelName                              // AI model name for pool selection
	nWork.BackendProtocol = r.backendProtocol                         // Backend protocol capability
	nWork.SessionHeaderName = r.sessionHeaderName                     // Custom session header name for persist mode
	nWork.SSEMode = r.sseMode                                         // SSE streaming mode
	nWork.MaxStreamDurationSec = r.maxStreamDurationSec               // SSE max stream duration cap
	nWork.BackendKeepaliveIntervalSec = r.backendKeepaliveIntervalSec // SSE backend keepalive
	nWork.TimeoutMemberConnect = r.timeoutMemberConnectMs             // connect ms
	nWork.TimeoutMemberData = r.timeoutMemberDataMs                   // member-data ms
	nWork.TimeoutTcpInspect = r.timeoutTcpInspectMs                   // inspect ms
	// TLS-hardening scalars → LBDpWorkQ → dp_proxy_tacts → proxy_arg.
	nWork.AlpnProtocols = r.alpnProtocols
	nWork.TlsCiphers = r.tlsCiphers
	nWork.TlsVersions = r.tlsVersions
	nWork.HstsMaxAge = r.hstsMaxAge
	nWork.HstsIncludeSubdomains = r.hstsIncludeSubdomains
	nWork.HstsPreload = r.hstsPreload
	nWork.BackendCaCertId = r.backendCaCertId
	nWork.BackendClientCertId = r.backendClientCertId
	nWork.PDDisaggMode = r.pdDisaggMode         // P/D disaggregation mode
	nWork.PDCacheAwareMode = r.pdCacheAwareMode // P/D cache-aware routing (US-PD801)
	nWork.PDSessionTTLSec = r.pdSessionTTLSec
	nWork.PDCacheThreshold = r.pdCacheThreshold
	nWork.PDBalanceAbsThreshold = r.pdBalanceAbsThreshold
	nWork.CbEnable = r.cbEnable
	nWork.KvExactMode = r.kvExactMode // KV-cache exact routing
	nWork.KvBlockSize = r.kvBlockSize
	nWork.KvHashAlgo = r.kvHashAlgo
	nWork.KvZmqPort = r.kvZmqPort
	nWork.KvWarmupSec = r.kvWarmupSec
	nWork.KvEngineType = r.kvEngineType // engine + DP rank count
	nWork.KvDpRankCount = r.kvDpRankCount
	nWork.PDBootstrapPort = r.pdBootstrapPort
	nWork.CatalogID = r.tracingCatalogID // Tracing catalog ID for deep inspection
	nWork.MTLSFrontend = r.mtlsFrontend  // mTLS frontend configuration
	nWork.MTLSBackend = r.mtlsBackend    // mTLS backend configuration
	nWork.Ppv2En = r.ppv2En
	if r.secMode == cmn.LBServHTTPS {
		nWork.SecMode = DpTermHTTPS
	} else if r.secMode == cmn.LBServE2EHTTPS {
		nWork.SecMode = DpE2EHTTPS
	}
	if len(r.srcList) > 0 {
		nWork.SrcCheck = true
	}

	if r.act.actType == RtActDnat {
		nWork.NatType = DpDnat
	} else if r.act.actType == RtActSnat {
		nWork.NatType = DpSnat
	} else if r.act.actType == RtActFullNat {
		nWork.NatType = DpFullNat
	} else if r.act.actType == RtActFullProxy {
		nWork.NatType = DpFullProxy
	} else {
		return -1
	}

	// Special case
	if r.tuples.l4Dst.valMax != r.tuples.l4Dst.valMin {
		nWork.NatType = DpNat
	}

	mode := cmn.LBModeDefault

	for _, sip := range r.secIP {
		nWork.secIP = append(nWork.secIP, sip.sIP)
	}

	switch at := r.act.action.(type) {
	case *ruleLBActs:
		switch {
		case at.sel == cmn.LbSelRr:
			nWork.EpSel = EpRR
		case at.sel == cmn.LbSelHash:
			nWork.EpSel = EpHash
		case at.sel == cmn.LbSelPrio:
			// P3: Use WRR (Weighted Round-Robin) for priority-based selection
			nWork.EpSel = EpPrio
		case at.sel == cmn.LbSelRrPersist:
			nWork.EpSel = EpRRPersist
		case at.sel == cmn.LbSelLeastConnections:
			nWork.EpSel = EpLeastConn
		case at.sel == cmn.LbSelN2:
			nWork.EpSel = EpN2
		case at.sel == cmn.LbSelN3:
			nWork.EpSel = EpN3
		case at.sel == cmn.LbSelCHWBL:
			nWork.EpSel = EpCHWBL
			nWork.CHWBLPrefixHashLevel = r.chwblPrefixHashLevel
			nWork.CHWBLPrefixHashFlags = r.chwblPrefixHashFlags
			nWork.CHWBLMeanLoadFactor = r.chwblMeanLoadFactor
			nWork.CHWBLReplication = r.chwblReplication
		case at.sel == cmn.LbSelGPUAware:
			nWork.EpSel = EpGPUAware
		case at.sel == cmn.LbSelWRRHash: // P3.5: WRR_HASH
			nWork.EpSel = EpWRRHash
		default:
			nWork.EpSel = EpRR
		}
		mode = at.mode
		if mode == cmn.LBModeDSR {
			nWork.DsrMode = true
		}
		nWork.CsumDis = mh.sumDis

		// Octavia member selection (replaces the blanket
		// applyAdminStateUpDrain that used to run after this build): compute the
		// transient per-EP selInactive marks ONCE over the authoritative member set.
		// This subsumes service admin_state (svcAdminUp gate -> all selInactive when
		// paused) AND adds weight=0 drain + backup-tier gating. It writes ONLY the
		// transient selInactive flag (never inActiveEP), so weight=0/backup-standby EPs
		// still round-trip on GET. The marks are OR'd into NatEP.InActive in BOTH the
		// priority branch (below) and the non-prio loop so a sel=2/prio rule gets backup
		// gating + weight=0 drain identically to a default-selection rule. Because this
		// runs in LB2DP — the single DpCreate funnel the syncEPImmediate health-flip
		// push re-enters — failover and failback are immediate.
		applyMemberSelection(at.endPoints, r.adminStateUp)

		if at.sel == cmn.LbSelPrio {
			j := 0
			k := 0
			var small [MaxLBEndPoints]int
			var neps [MaxLBEndPoints]ruleLBEp
			for i, ep := range at.endPoints {
				if ep.inActiveEP {
					continue
				}
				oEp := &at.endPoints[i]
				sw := (int(ep.weight) * MaxLBEndPoints) / 100
				if sw == 0 {
					small[k] = i
					k++
				}
				for x := 0; x < sw && j < MaxLBEndPoints; x++ {
					neps[j].xIP = oEp.xIP
					neps[j].rIP = oEp.rIP
					neps[j].xPort = oEp.xPort
					neps[j].inActiveEP = oEp.inActiveEP
					// carry the transient member-selection mark so
					// the prio branch gets backup gating + weight=0 drain identically to
					// the non-prio loop (a mark in only one branch silently breaks one mode).
					neps[j].selInactive = oEp.selInactive
					neps[j].weight = oEp.weight
					neps[j].epRole = oEp.epRole
					neps[j].nixlPort = oEp.nixlPort
					if sw == 1 {
						small[k] = i
						k++
					}
					j++
				}
			}
			if j < MaxLBEndPoints {
				v := 0
				if k == 0 {
					k = len(at.endPoints)
				}
				for j < MaxLBEndPoints {
					idx := small[v%k]
					oEp := &at.endPoints[idx]
					neps[j].xIP = oEp.xIP
					neps[j].rIP = oEp.rIP
					neps[j].xPort = oEp.xPort
					neps[j].inActiveEP = oEp.inActiveEP
					// carry the transient member-selection mark (prio branch).
					neps[j].selInactive = oEp.selInactive
					neps[j].weight = oEp.weight
					neps[j].epRole = oEp.epRole
					neps[j].nixlPort = oEp.nixlPort
					j++
					v++
				}
			}
			for _, e := range neps {
				var ep NatEP

				ep.XIP = e.xIP
				ep.RIP = e.rIP
				ep.XPort = e.xPort
				ep.Weight = e.weight
				ep.EpRole = e.epRole
				ep.NixlPort = e.nixlPort
				// selInactive folds in backup gating +
				// weight=0 drain + service admin pause (prio branch).
				if e.inActiveEP || e.noService || e.selInactive {
					ep.InActive = true
				}
				nWork.endPoints = append(nWork.endPoints, ep)
			}
		} else {
			for _, k := range at.endPoints {
				if len(k.foldEndPoints) > 0 {
					for _, kf := range k.foldEndPoints {
						var ep NatEP

						ep.XIP = kf.xIP
						ep.RIP = kf.rIP
						ep.XPort = kf.xPort
						ep.Weight = kf.weight
						ep.EpRole = kf.epRole
						ep.NixlPort = kf.nixlPort
						// the member-selection mark is
						// computed over the top-level member set; folded children inherit
						// the parent EP's selInactive (k.selInactive) in addition to their
						// own probe/health state.
						if kf.inActiveEP || kf.noService || k.selInactive {
							ep.InActive = true
						}

						nWork.endPoints = append(nWork.endPoints, ep)
					}
				} else {
					var ep NatEP

					ep.XIP = k.xIP
					ep.RIP = k.rIP
					ep.XPort = k.xPort
					ep.Weight = k.weight
					ep.EpRole = k.epRole
					ep.NixlPort = k.nixlPort
					// selInactive folds in backup gating +
					// weight=0 drain + service admin pause (non-prio branch).
					if k.inActiveEP || k.noService || k.selInactive {
						ep.InActive = true
					}

					nWork.endPoints = append(nWork.endPoints, ep)
				}
			}
		}
	default:
		return -1
	}

	// Octavia service admin_state pause is now SUBSUMED by the
	// applyMemberSelection call above: isEffectivelyAvailable returns false for EVERY EP
	// when r.adminStateUp is false (the svcAdminUp gate), so a paused rule programs zero
	// selectable backends (sel=-1 -> xf->pm.nf=0, new flows not forwarded) exactly as the
	// old blanket applyAdminStateUpDrain did — plus weight=0 drain + backup-tier gating.
	// The marks were OR'd into NatEP.InActive in both build branches; established CT
	// survives (matched before selection), membership is untouched, no DpRemove. State-
	// based + restart-durable (runs on every DpCreate); legacy nil rules resolve enabled.
	// (applyAdminStateUpDrain is retained for the isolated unit tests.)

	if !nWork.ServiceIP.IsUnspecified() || nWork.BlockNum != 0 {
		mh.dp.ToDpCh <- nWork
		r.VIP2DP(nWork.Work)
	}

	if mode == cmn.LBModeHostOneArm {
		for locIP := range r.locIPs {
			if sIP := net.ParseIP(locIP); sIP != nil {
				nWork1 := new(LBDpWorkQ)
				*nWork1 = *nWork
				nWork1.ServiceIP = sIP
				mh.dp.ToDpCh <- nWork1
			}
		}
	}

	return 0
}

// Fw2DP - Sync state of fw-rule entity to data-path
func (r *ruleEnt) Fw2DP(work DpWorkT) int {

	if work == DpStatsGet || work == DpStatsGetImm {
		nStat := new(StatDpWorkQ)
		nStat.Work = work
		nStat.Mark = uint32(r.ruleNum)
		nStat.Name = MapNameFw4
		nStat.Bytes = &r.stat.bytes
		nStat.Packets = &r.stat.packets

		if work != DpStatsGetImm {
			mh.dp.ToDpCh <- nStat
		} else {
			DpWorkSingle(mh.dp, nStat)
		}
		return 0
	}

	nWork := new(FwDpWorkQ)

	nWork.Work = work
	nWork.Status = &r.sync
	nWork.ZoneNum = r.zone.ZoneNum
	nWork.SrcIP = r.tuples.l3Src.addr
	nWork.DstIP = r.tuples.l3Dst.addr
	if r.tuples.l4Src.valid {
		nWork.L4SrcMin = r.tuples.l4Src.valMin
		nWork.L4SrcMax = r.tuples.l4Src.valMax
	}
	if r.tuples.l4Dst.valid {
		nWork.L4DstMin = r.tuples.l4Dst.valMin
		nWork.L4DstMax = r.tuples.l4Dst.valMax
	}
	if r.tuples.port.val != "" {
		port := r.zone.Ports.PortFindByName(r.tuples.port.val)
		if port == nil {
			r.sync = DpChangeErr
			return -1
		}
		nWork.Port = uint16(port.PortNo)
	}
	nWork.Proto = r.tuples.l4Prot.val
	nWork.Mark = int(r.ruleNum)
	nWork.Pref = uint16(r.tuples.pref)
	// pass-through to the DP work queue. The eBPF
	// firewall handler ignores this field (mirrored install path is
	// unchanged); the DpDocaBf2 FwRuleAdd handler routes
	// HwOffload=true entries into DENY_PIPE / ALLOW_PIPE.
	nWork.HwOffload = r.hwOffload

	switch at := r.act.action.(type) {
	case *ruleFwOpts:
		switch at.op {
		case RtActFwd:
			nWork.FwType = DpFwFwd
		case RtActDrop:
			nWork.FwType = DpFwDrop
		case RtActRedirect:
			nWork.FwType = DpFwRdr
			port := r.zone.Ports.PortFindByName(at.opt.rdrPort)
			if port == nil {
				r.sync = DpChangeErr
				return -1
			}
			nWork.FwVal1 = uint16(port.PortNo)
		case RtActTrap:
			nWork.FwType = DpFwTrap
		case RtActSnat:
			nWork.FwType = DpFwFwd
		default:
			nWork.FwType = DpFwDrop
		}
		nWork.FwVal2 = at.opt.fwMark
		nWork.FwRecord = at.opt.record
		nWork.OnDflt = at.opt.onDflt
		if nWork.OnDflt && work == DpRemove {
			r.sync = 0
		}
	default:
		return -1
	}

	mh.dp.ToDpCh <- nWork

	return 0
}

// DP - sync state of rule entity to data-path
func (r *ruleEnt) DP(work DpWorkT) int {
	isNat := false

	if r.act.actType == RtActDnat ||
		r.act.actType == RtActSnat ||
		r.act.actType == RtActFullNat ||
		r.act.actType == RtActFullProxy {
		isNat = true
	}

	if work == DpMapGet {
		nTable := new(TableDpWorkQ)
		nTable.Work = DpMapGet
		nTable.Name = MapNameCt4
		mh.dp.ToDpCh <- nTable
		return 0
	}

	if work == DpStatsGet || work == DpStatsGetImm {
		if isNat {
			switch at := r.act.action.(type) {
			case *ruleLBActs:
				// Special handling for priority mode
				if at.sel == cmn.LbSelPrio {
					// Reset all endpoint stats first
					for i := range at.endPoints {
						at.endPoints[i].stat.bytes = 0
						at.endPoints[i].stat.packets = 0
					}

					// Create the exact same neps array as in LB2DP to map indices correctly
					j := 0
					k := 0
					var small [MaxLBEndPoints]int
					var neps [MaxLBEndPoints]ruleLBEp

					// Initialize neps array with zero values
					for i := 0; i < MaxLBEndPoints; i++ {
						neps[i] = ruleLBEp{}
					}

					// Reproduce the exact LB2DP algorithm
					for i, ep := range at.endPoints {
						if ep.inActiveEP {
							continue
						}
						oEp := &at.endPoints[i]
						sw := (int(ep.weight) * MaxLBEndPoints) / 100
						if sw == 0 {
							small[k] = i
							k++
						}
						for x := 0; x < sw && j < MaxLBEndPoints; x++ {
							neps[j].xIP = oEp.xIP
							neps[j].rIP = oEp.rIP
							neps[j].xPort = oEp.xPort
							neps[j].inActiveEP = oEp.inActiveEP
							neps[j].weight = oEp.weight
							if sw == 1 {
								small[k] = i
								k++
							}
							j++
						}
					}
					if j < MaxLBEndPoints {
						v := 0
						if k == 0 {
							k = len(at.endPoints)
						}
						for j < MaxLBEndPoints {
							idx := small[v%k]
							oEp := &at.endPoints[idx]
							neps[j].xIP = oEp.xIP
							neps[j].rIP = oEp.rIP
							neps[j].xPort = oEp.xPort
							neps[j].inActiveEP = oEp.inActiveEP
							neps[j].weight = oEp.weight
							j++
							v++
						}
					}

					// Collect stats from all eBPF array indices with corrected Mark calculation
					for arrayIdx := 0; arrayIdx < MaxLBEndPoints; arrayIdx++ {
						bytes := uint64(0)
						packets := uint64(0)
						nStat := new(StatDpWorkQ)
						nStat.Work = DpStatsGetImm
						// Fix Mark calculation using LLB_NAT_STAT_CID formula: ((rid & 0x7ff) << 5) | (aid & 0x1f)
						nStat.Mark = (((uint32(r.ruleNum)) & 0x7ff) << 5) | (uint32(arrayIdx) & 0x1f)
						nStat.Name = MapNameNat
						nStat.Bytes = &bytes
						nStat.Packets = &packets
						DpWorkSingle(mh.dp, nStat)

						// Only accumulate if neps[arrayIdx] has valid xIP (not zero)
						if !neps[arrayIdx].xIP.IsUnspecified() {
							// Find which original endpoint this arrayIdx maps to by comparing IPs
							for epIdx := range at.endPoints {
								if at.endPoints[epIdx].xIP.Equal(neps[arrayIdx].xIP) &&
									at.endPoints[epIdx].xPort == neps[arrayIdx].xPort {
									at.endPoints[epIdx].stat.bytes += bytes
									at.endPoints[epIdx].stat.packets += packets
									break
								}
							}
						}
					}
				} else {
					// Original logic for non-priority modes
					numEndPoints := 0
					for i := range at.endPoints {
						nEP := &at.endPoints[i]
						if len(nEP.foldEndPoints) > 0 {
							totBytes := uint64(0)
							totPackets := uint64(0)
							for range nEP.foldEndPoints {
								bytes := uint64(0)
								packets := uint64(0)
								nStat := new(StatDpWorkQ)
								nStat.Work = DpStatsGetImm
								nStat.Mark = (((uint32(r.ruleNum)) & 0x7ff) << 5) | (uint32(numEndPoints) & 0x1f)
								nStat.Name = MapNameNat
								nStat.Bytes = &bytes
								nStat.Packets = &packets
								DpWorkSingle(mh.dp, nStat)
								numEndPoints++
								totBytes += bytes
								totPackets += packets
							}
							nEP.stat.bytes = totBytes
							nEP.stat.packets = totPackets
						} else {
							nStat := new(StatDpWorkQ)
							nStat.Work = work
							nStat.Mark = (((uint32(r.ruleNum)) & 0x7ff) << 5) | (uint32(numEndPoints) & 0x1f)
							nStat.Name = MapNameNat
							nStat.Bytes = &nEP.stat.bytes
							nStat.Packets = &nEP.stat.packets
							if work == DpStatsGetImm {
								DpWorkSingle(mh.dp, nStat)
							} else {
								mh.dp.ToDpCh <- nStat
							}
							numEndPoints++
						}
					}
				}
			}
		} else {
			nStat := new(StatDpWorkQ)
			nStat.Work = work
			nStat.Mark = uint32(r.ruleNum)
			nStat.Name = MapNameFw4
			nStat.Bytes = &r.stat.bytes
			nStat.Packets = &r.stat.packets

			mh.dp.ToDpCh <- nStat
		}
		return 0
	}

	if isNat {
		return r.LB2DP(work)
	}

	return r.Fw2DP(work)

}

func (R *RuleH) AdvRuleVIP(IP net.IP, eIP net.IP, inst string, egress bool) error {
	if inst == "" {
		inst = cmn.CIDefault
	}

	if IP.String() == "0.0.0.0" || IP.String() == "::" {
		return nil
	}

	ciState, _ := mh.has.CIStateGetInst(inst)
	if ciState == cmn.CIMasterStateString {
		dev := fmt.Sprintf("llb-rule-%s", IP.String())
		ret, _ := R.zone.L3.IfaFindAddr(dev, IP)
		if ret == 0 {
			R.zone.L3.IfaDelete(dev, utils.IPHostCIDRString(IP))
		}
		ev, _, iface := R.zone.L3.IfaSelectAny(IP, false)
		if ev == 0 {
			ifname := "lo"
			if tk.IsNetIPv6(IP.String()) {
				ifname = iface
			}
			if !utils.IsIPHostAddr(IP.String()) {
				if mh.cloudHook != nil {
					err := mh.cloudHook.CloudUpdatePrivateIP(IP, eIP, true)
					if err != nil {
						tk.LogIt(tk.LogError, "%s: lb-rule vip %s add failed. err: %v\n", mh.cloudLabel, IP.String(), err)
						return err
					}
				}

				if loxinlp.AddAddrNoHook(utils.IPHostCIDRString(IP), ifname) != 0 {
					tk.LogIt(tk.LogError, "lb-rule vip %s:%s add failed\n", IP.String(), ifname)
				} else {
					tk.LogIt(tk.LogInfo, "lb-rule vip %s:%s added\n", IP.String(), ifname)
				}
				loxinlp.DelNeighNoHook(IP.String(), "")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			rCh := make(chan int)
			go utils.NetAdvertiseVIPReqWithCtx(ctx, rCh, IP, iface)
			select {
			case <-rCh:
				break
			case <-ctx.Done():
				tk.LogIt(tk.LogInfo, "lb-rule vip %s - iface %s : GratARP timeout\n", IP.String(), iface)
			}
		}

		if egress {
			mh.has.CIAddClusterRoute(IP.String(), false)
		}

	} else if ciState != cmn.CIUnDefStateString {
		if utils.IsIPHostAddr(IP.String()) {
			ifname := "lo"
			ev, _, iface := R.zone.L3.IfaSelectAny(IP, false)
			if ev == 0 {
				if tk.IsNetIPv6(IP.String()) {
					ifname = iface
				}
			}
			if loxinlp.DelAddrNoHook(utils.IPHostCIDRString(IP), ifname) != 0 {
				tk.LogIt(tk.LogError, "lb-rule vip %s:%s delete failed\n", IP.String(), ifname)
			} else {
				tk.LogIt(tk.LogInfo, "lb-rule vip %s:%s deleted\n", IP.String(), ifname)
			}
		}

		if egress {
			mh.has.CIAddClusterRoute(IP.String(), true)
		}

	} else {
		if _, foundIP := R.zone.L3.IfaAddrLocal(IP); foundIP == nil {
			dev := fmt.Sprintf("llb-rule-%s", IP.String())
			ret, _ := R.zone.L3.IfaFindAddr(dev, IP)
			if ret != 0 {
				_, err := R.zone.L3.IfaAdd(dev, utils.IPHostCIDRString(IP))
				if err != nil {
					fmt.Printf("Failed to add IP : %s:%s\n", dev, err)
				}
			}
		}

		if egress {
			mh.has.CIAddClusterRoute(IP.String(), false)
		}
	}

	return nil
}

func (R *RuleH) RulesSyncToClusterState(inst, ciStateStr string) {

	// For Cloud integrations, certain operations are performed only on default instance state changes
	if mh.cloudHook != nil && inst == cmn.CIDefault {
		if ciStateStr == cmn.CIMasterStateString {
			mh.cloudHook.CloudPrepareVIPNetWork()
		} else if ciStateStr == cmn.CIBackupStateString {
			mh.cloudHook.CloudUnPrepareVIPNetWork()
		}
	}

	if inst == cmn.CIDefault {
		for _, eFw := range R.tables[RtFw].eMap {
			if eFw.act.action.(*ruleFwOpts).opt.onDflt {
				if ciStateStr == cmn.CIMasterStateString || ciStateStr != cmn.CIBackupStateString {
					eFw.Fw2DP(DpCreate)
				} else if ciStateStr == cmn.CIBackupStateString {
					eFw.Fw2DP(DpRemove)
				}
			}
		}
	}

	for vip, vipElem := range R.vipMap {
		if vipElem.inst != inst {
			continue
		}
		ip := vipElem.pVIP
		if ip == nil {
			ip = net.ParseIP(vip)
		}
		if ip != nil {
			R.AdvRuleVIP(ip, net.ParseIP(vip), vipElem.inst, vipElem.egr)
		}
	}
}

func (r *ruleEnt) RuleVIP2PrivIP() net.IP {
	if r.privIP == nil || r.privIP.IsUnspecified() {
		return r.tuples.l3Dst.addr.IP.Mask(r.tuples.l3Dst.addr.Mask)
	} else {
		return r.privIP
	}
}

func (R *RuleH) AddRuleVIP(VIP net.IP, pVIP net.IP, inst string, egress bool) {
	vipEnt := R.vipMap[VIP.String()]
	if vipEnt == nil {
		vipEnt = new(vipElem)
		vipEnt.ref = 1
		vipEnt.pVIP = pVIP
		vipEnt.inst = inst
		vipEnt.egr = egress
		R.vipMap[VIP.String()] = vipEnt
	} else {
		vipEnt.ref++
	}

	if vipEnt.ref == 1 {
		if pVIP == nil {
			R.AdvRuleVIP(VIP, VIP, inst, vipEnt.egr)
		} else {
			R.AdvRuleVIP(pVIP, VIP, inst, vipEnt.egr)
		}
	}
}

func (R *RuleH) DeleteRuleVIP(VIP net.IP) {

	vipEnt := R.vipMap[VIP.String()]
	if vipEnt != nil {
		vipEnt.ref--
	}

	if vipEnt != nil && vipEnt.ref == 0 {
		xVIP := VIP
		if vipEnt.pVIP != nil {
			xVIP = vipEnt.pVIP
		}
		if utils.IsIPHostAddr(xVIP.String()) {
			ifname := "lo"
			ev, _, iface := R.zone.L3.IfaSelectAny(xVIP, false)
			if ev == 0 {
				if tk.IsNetIPv6(xVIP.String()) {
					ifname = iface
				}
			}
			loxinlp.DelAddrNoHook(utils.IPHostCIDRString(xVIP), ifname)
			if mh.cloudHook != nil {
				err := mh.cloudHook.CloudUpdatePrivateIP(xVIP, VIP, false)
				if err != nil {
					tk.LogIt(tk.LogError, "%s: lb-rule vip %s delete failed. err: %v\n", mh.cloudLabel, xVIP.String(), err)
				}
			}
		}
		dev := fmt.Sprintf("llb-rule-%s", xVIP.String())
		ret, _ := mh.zr.L3.IfaFindAddr(dev, xVIP)
		if ret == 0 {
			mh.zr.L3.IfaDelete(dev, utils.IPHostCIDRString(xVIP))
		}
		delete(R.vipMap, VIP.String())
	}
}

func (R *RuleH) IsIPRuleVIP(IP net.IP) bool {
	if _, found := R.vipMap[IP.String()]; found {
		return true
	}
	return false
}

// createEndpointMask - Create mask for selective session reset based on endpoint changes
func (R *RuleH) createEndpointMask(oldEps []ruleLBEp, newEps []ruleLBEp, delEps []ruleLBEp) []bool {
	endpointMask := make([]bool, len(oldEps))

	// Create maps for efficient lookup
	newEpMap := make(map[string]bool)
	for _, ep := range newEps {
		key := fmt.Sprintf("%s:%d", ep.xIP.String(), ep.xPort)
		newEpMap[key] = true
	}

	delEpMap := make(map[string]bool)
	for _, ep := range delEps {
		key := fmt.Sprintf("%s:%d", ep.xIP.String(), ep.xPort)
		delEpMap[key] = true
	}

	// Determine which endpoints need reset vs preservation
	for i, oldEp := range oldEps {
		oldKey := fmt.Sprintf("%s:%d", oldEp.xIP.String(), oldEp.xPort)

		if delEpMap[oldKey] {
			// Endpoint was deleted, reset it
			endpointMask[i] = true
		} else if newEpMap[oldKey] {
			// Endpoint still exists, preserve its session count
			endpointMask[i] = false
			// Note: The eBPF layer will read current session counts automatically
		} else {
			// Endpoint was modified/replaced, reset it
			endpointMask[i] = true
		}
	}

	return endpointMask
}

// applySelectiveSessionReset - Apply selective session reset after endpoint changes
func (R *RuleH) applySelectiveSessionReset(rule *ruleEnt, oldEps []ruleLBEp, newEps []ruleLBEp, delEps []ruleLBEp) error {
	if rule == nil {
		return fmt.Errorf("rule is nil")
	}

	// Only apply selective reset if we have endpoint changes
	if len(delEps) == 0 && len(oldEps) == len(newEps) {
		// No endpoints changed, no need for selective reset
		return nil
	}

	// Create endpoint mask for selective reset
	endpointMask := R.createEndpointMask(oldEps, newEps, delEps)

	// Apply selective session reset
	w := &LBSessionResetWorkQ{
		Mark:         int(rule.ruleNum),
		EndpointIdx:  -1,
		ResetType:    ResetSelective,
		Status:       new(DpStatusT),
		EndpointMask: endpointMask,
	}

	// Execute the selective reset
	ret := mh.dp.DpHooks.DpLBSessionReset(w)
	if ret != 0 {
		tk.LogIt(tk.LogError, "[RULE] Selective session reset failed for rule mark %d: %d\n", int(rule.ruleNum), ret)
		return fmt.Errorf("selective session reset failed: %d", ret)
	}

	// Count changes for logging
	changedEndpoints := 0
	preservedEndpoints := 0
	for _, reset := range endpointMask {
		if reset {
			changedEndpoints++
		} else {
			preservedEndpoints++
		}
	}

	tk.LogIt(tk.LogInfo, "[RULE] Selective session reset completed for rule mark %d: reset=%d, preserved=%d\n",
		int(rule.ruleNum), changedEndpoints, preservedEndpoints)

	return nil
}
