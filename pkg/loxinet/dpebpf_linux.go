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
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#include "../../loxilb-ebpf/kernel/loxilb_libdp.h"
// Define proxy_ent structure for health updates (avoid pulling in full sockproxy.h with uthash)
struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint8_t inv;
  uint8_t protocol;
};
int proxy_update_ep_health(struct proxy_ent *key, int ep_index, uint8_t inactive);
int proxy_update_ep_health_by_ip(struct proxy_ent *key, uint32_t ep_ip, uint8_t inactive);
int proxy_set_drain_policy(struct proxy_ent *key, unsigned int policy, uint32_t timeout_sec);
int proxy_set_circuit_breaker(struct proxy_ent *key, uint8_t enabled, uint32_t failure_threshold, uint32_t open_timeout_sec);
int proxy_set_service_catalog(uint32_t xip, uint16_t xport, uint8_t protocol, uint16_t catalog_id);
// Note: chwbl_prefix_hash_level is now propagated via dp_proxy_tacts.chwbl_prefix_hash_level during proxy_add_entry

// mTLS configuration structures (matching proxy_arg_t fields)
struct mtls_frontend_config {
  uint8_t mode;                      // 0=disabled, 1=optional, 2=required
  char client_ca_path[256];          // Client CA bundle path
  char client_ca_cert_data[4096];    // Client CA certificate data (PEM)
  uint8_t require_client_cn;         // 1=require CN pattern match
  char client_cn_pattern[256];       // CN pattern (e.g., "*.corp.example.com")
};

struct mtls_backend_config {
  uint8_t verify_server_cert;        // 1=verify server cert
  char backend_ca_path[256];         // Backend CA bundle path
  char client_cert_path[256];        // Client cert for backend
  char client_key_path[256];         // Client key for backend
  char client_cert_data[4096];       // Client cert data (PEM)
  char client_key_data[4096];        // Client key data (PEM)
};

// Function to update proxy mTLS configuration after proxy entry is created
int proxy_update_mtls_config(struct proxy_ent *key,
                              struct mtls_frontend_config *frontend,
                              struct mtls_backend_config *backend);

// Function to clean up mTLS configuration when rule is deleted
int proxy_cleanup_mtls_config(struct proxy_ent *key);

// (-10..13): certId registry entry points (declared in
// loxilb-ebpf/common/sockproxy_ssl.h). Prototyped inline here — like struct proxy_ent
// above — to avoid pulling sockproxy.h/uthash into this preamble. These persist-free
// management calls layer over the hostname-keyed SNI store; the CGO layer (the cert.go
// handler) persists the inline PEM to PROXY_SSL_CERTID_DIR/<certId>/ FIRST, then drives
// these. Exposed here as the dpebpf bridge so the control plane can register/rotate/delete
// certIds through the same data-plane CGO surface as the rest of proxy_arg.
int proxy_register_cert(const char *certId);
int proxy_rotate_cert(const char *certId);
int proxy_delete_cert(const char *certId);

// ---------------------------------------------------------------------------
// L7 content-routing policy attach/detach.
//
// A SEPARATE CGO attach call carries the variable-length ordered route array to
// the running sockproxy — NEVER inline on proxy_arg (the 4096-byte _Static_assert
// forbids it). Modeled on proxy_update_mtls_config. The l7_route_t IR below is an
// ABI-IDENTICAL mirror of the canonical definition in
// loxilb-ebpf/common/sockproxy_l7policy.h — we mirror it here (instead of including
// that header) for the SAME reason this preamble mirrors struct proxy_ent: pulling
// sockproxy.h drags in uthash. Keep these layouts byte-for-byte in lock-step with
// sockproxy_l7policy.h. <regex.h> is a standalone POSIX header (no uthash), so the
// embedded regex_t is the real type and the struct size matches the C side exactly.
//
// IMPORTANT: the Go side leaves every cond->re_valid == 0 and never compiles a
// pattern — regcomp is the C attach's job (the single compile site, ReDoS).
#include <regex.h>

#define L7_MAX_CONDS_PER_SET   8
#define L7_MAX_SETS_PER_ROUTE  8
#define L7_KEY_MAX             64
#define L7_VALUE_MAX           256
#define FILTER_RESERVED_BYTES  64
#define L7_MAX_PROXY_EP        32   // == MAX_PROXY_EP (sockproxy.h)
// / — keep these byte-for-byte in lock-step with
// sockproxy_l7policy.h (the l7_route_t below grew by the insertHeaders filter
// list + cookie_persist marker; the deep-copy ABI depends on identical layout).
#define L7_HDR_NAME_MAX        64
#define L7_HDR_VALUE_MAX       256
#define L7_MAX_HDR_FILTERS     8

typedef struct {
  int      field;                   // l7_field_t
  int      op;                      // l7_op_t
  char     key[L7_KEY_MAX];
  char     value[L7_VALUE_MAX];
  uint8_t  invert;
  regex_t  re;                      // compiled by the C attach, NOT by Go
  uint8_t  re_valid;
} l7_condition_t;

typedef struct {
  l7_condition_t conds[L7_MAX_CONDS_PER_SET];
  uint8_t        n_conds;
} l7_match_set_t;

typedef struct {
  uint32_t pool_id;
  struct {
    uint32_t ep;
    uint8_t  weight;
  } refs[L7_MAX_PROXY_EP];
  uint8_t  n_refs;
} l7_forward_t;

typedef struct {
  char     scheme[8];
  char     host[256];
  uint16_t port;
  int      path_op;                 // l7_path_op_t
  char     value[L7_VALUE_MAX];
  uint16_t status_code;
} l7_redirect_t;

typedef struct {
  uint16_t status_code;
} l7_reject_t;

typedef struct {
  int kind;                         // l7_action_kind_t
  union {
    l7_forward_t  fwd;
    l7_redirect_t redir;
    l7_reject_t   reject;
  } u;
} l7_action_t;

typedef struct {
  uint8_t op;
  char    name[L7_HDR_NAME_MAX];
  char    value[L7_HDR_VALUE_MAX];
} l7_hdr_filter_t;

typedef struct {
  int             position;
  l7_match_set_t  sets[L7_MAX_SETS_PER_ROUTE];
  uint8_t         n_sets;
  l7_action_t     action;
 l7_hdr_filter_t hdr_filters[L7_MAX_HDR_FILTERS]; //
  uint8_t         n_hdr_filters;
 uint8_t cookie_persist; //
} l7_route_t;

// Attach the ordered route array (regcomp's each REGEX once, sets has_l7_policy);
// detach regfrees + clears. Defined in loxilb-ebpf/common/sockproxy_l7policy.c.
int proxy_attach_l7_policy(struct proxy_ent *key, const l7_route_t *routes,
                           int n_routes);
int proxy_detach_l7_policy(struct proxy_ent *key);

int bpf_map_get_next_key(int fd, const void *key, void *next_key);
int bpf_map_lookup_elem(int fd, const void *key, void *value);
int llb_flush_ct_by_nat(void *k, uint32_t rid);
int bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags);
int bpf_map_delete_elem(int fd, const void *key);
extern void goMapNotiHandler(struct ll_dp_map_notif *);
extern void goProxyEntCollector(struct dp_proxy_ct_ent *);
extern void goLinuxArpResolver(unsigned int);

// Conditional XDP attachment based on IP filter feature
#ifdef HAVE_DP_IP_FILTER
#define XDP_ALL_INTERFACES 1
#else
#define XDP_ALL_INTERFACES 0
#endif

// Conditional unified security rate runtime configuration
#ifdef HAVE_DP_SECURITY_RATE_RUNTIME_CONFIG
#define SECURITY_RATE_RUNTIME_CONFIG 1

// Helper to get security rate config map ID (only in runtime config mode)
static inline int get_security_rate_config_map_id() {
  return LL_DP_SECURITY_RATE_CONFIG_MAP;
}
#else
#define SECURITY_RATE_RUNTIME_CONFIG 0

// Dummy helper when runtime config is disabled
static inline int get_security_rate_config_map_id() {
  return -1;
}
#endif

// Conditional GPU-aware load balancing feature
#ifdef HAVE_DP_GPU_ROUTING
#define GPU_ROUTING_ENABLED 1
#else
#define GPU_ROUTING_ENABLED 0
// Define dummy map IDs when GPU routing is disabled (prevents Go compile errors)
#define LL_DP_ROUTING_MODE_MAP -1
#define LL_DP_WORKER_GPU_STATS_MAP -1
#define LL_DP_ENDPOINT_TO_GPU_INDEX_MAP -1
#define LL_DP_SERVICE_SCORING_CONFIG_MAP -1

// Define dummy structs when GPU routing is disabled (prevents Go field access errors)
struct endpoint_to_gpu_key {
  __u32 ip;
  __u16 port;
  __u16 _pad;
};

struct worker_gpu_stats {
  __u32 queued_requests;
  __u32 swapped_requests;
  __u32 kv_cache_usage_perc;
  __u32 num_gpu_blocks;
  __u8 is_overloaded;
  __u8 _pad1[3];
  __u64 overload_start_ts;
  __u64 last_update_ts;
  __u64 metrics_version;
};

struct service_scoring_config {
  __u32 queue_weight;
  __u32 swap_weight;
  __u32 kv_cache_weight;
  __u32 queue_overload_threshold;
  __u32 queue_recovery_threshold;
  __u32 kv_cache_overload_threshold;
  __u32 kv_cache_recovery_threshold;
  __u64 recovery_grace_period_sec;
  __u8 catalog_name[32];
  __u8 _pad[4];
};
#endif

#cgo CFLAGS:  -I./../../loxilb-ebpf/libbpf/src/ -I./../../loxilb-ebpf/common -DHAVE_DP_IP_FILTER=1 -DHAVE_DP_SECURITY_RATE_LIMIT=1 -DHAVE_DP_SECURITY_RATE_RUNTIME_CONFIG=1 -DHAVE_DP_GPU_ROUTING=1
#cgo LDFLAGS: -L. -L/lib64 -L./../../loxilb-ebpf/kernel -L./../../loxilb-ebpf/libbpf/src/build/usr/lib64/ -Wl,-rpath=/lib64/ -l:libloxilbdp.a -l:libbpf.a -lelf -lz -lssl -lcrypto -lnghttp2 -ljson-c
*/
import "C"
import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	prom "github.com/loxilb-io/loxilb/api/prometheus"
	cmn "github.com/loxilb-io/loxilb/common"
	utils "github.com/loxilb-io/loxilb/pkg/utils"
	tk "github.com/loxilb-io/loxilib"
	nlp "github.com/vishvananda/netlink"
)

// This file implements the interface DpHookInterface
// The implementation is specific to loxilb ebpf datapath for linux

// XDP attachment behavior based on compile-time flag
// When HAVE_DP_IP_FILTER is defined: attach XDP to all interfaces (hybrid XDP+TC)
// Otherwise: attach XDP only to llb0 or RSS-enabled interfaces (legacy behavior)
const xdpAllInterfaces = (C.XDP_ALL_INTERFACES == 1)

// Unified security rate runtime configuration availability
// When HAVE_DP_SECURITY_RATE_RUNTIME_CONFIG is defined: runtime config available via eBPF map
// Otherwise: hardcoded thresholds only
const securityRateRuntimeConfig = (C.SECURITY_RATE_RUNTIME_CONFIG == 1)

// GPU-aware load balancing feature availability
// When HAVE_DP_GPU_ROUTING is defined: GPU routing maps available
// Otherwise: GPU features are disabled (graceful degradation)
const gpuRoutingEnabled = (C.GPU_ROUTING_ENABLED == 1)

// error codes
const (
	EbpfErrBase = iota - 50000
	EbpfErrPortPropAdd
	EbpfErrPortPropDel
	EbpfErrEbpfLoad
	EbpfErrEbpfUnload
	EbpfErrL2AddrAdd
	EbpfErrL2AddrDel
	EbpfErrTmacAdd
	EbpfErrTmacDel
	EbpfErrNhAdd
	EbpfErrNhDel
	EbpfErrRt4Add
	EbpfErrRt4Del
	EbpfErrNat4Add
	EbpfErrNat4Del
	EbpfErrSess4Add
	EbpfErrSess4Del
	EbpfErrPolAdd
	EbpfErrPolDel
	EbpfErrMirrAdd
	EbpfErrMirrDel
	EbpfErrFwAdd
	EbpfErrFwDel
	EbpfErrCtAdd
	EbpfErrCtDel
	EbpfErrSockVIPMod
	EbpfErrSockVIPAdd
	EbpfErrSockVIPDel
	EbpfErrWqUnk
)

// constants
const (
	dpEbpfLinuxTiVal     = 5
	ctGCTiValDefault     = 15
	ctiDeleteSyncRetries = 3
	blkCtiMaxLen         = 8192
	mapNotifierChLen     = 8096
	mapNotifierWorkers   = 1
)

// ebpf table related defines in go
type (
	sActValue  C.struct_dp_cmn_act
	intfMapKey C.struct_intf_key
	intfMapDat C.struct_dp_intf_tact
	intfSetIfi C.struct_dp_intf_tact_set_ifi
	sMacKey    C.struct_dp_smac_key
	dMacKey    C.struct_dp_dmac_key
	dMacMapDat C.struct_dp_dmac_tact
	l2VlanAct  C.struct_dp_l2vlan_act
	tMacKey    C.struct_dp_tmac_key
	tMacDat    C.struct_dp_tmac_tact
	rtNhAct    C.struct_dp_rt_nh_act
	nhKey      C.struct_dp_nh_key
	nhDat      C.struct_dp_nh_tact
	rtL2NhAct  C.struct_dp_rt_l2nh_act
	rtTunNhAct C.struct_dp_rt_tunnh_act
	rt4Key     C.struct_dp_rtv4_key
	rt6Key     C.struct_dp_rtv6_key
	rtDat      C.struct_dp_rt_tact
	rtL3NhAct  C.struct_dp_rt_nh_act
	natKey     C.struct_dp_nat_key
	proxyActs  C.struct_dp_proxy_tacts
	nxfrmAct   C.struct_mf_xfrm_inf
	sess4Key   C.struct_dp_sess4_key
	sessAct    C.struct_dp_sess_tact
	polTact    C.struct_dp_pol_tact
	polAct     C.struct_dp_policer_act
	mirrTact   C.struct_dp_mirr_tact
	fw4Ent     C.struct_dp_fwv4_ent
	fw6Ent     C.struct_dp_fwv6_ent
	portAct    C.struct_dp_rdr_act
	mapNoti    C.struct_ll_dp_map_notif
	vipKey     C.struct_sock_rwr_key
	vipAct     C.struct_sock_rwr_action
	proxtCT    C.struct_dp_proxy_ct_ent
)

var (
	proxyCtInfo []*DpCtInfo
)

// SecurityRateConfig - Unified configuration for P0-5 SYN Flood + P0-6 Connection Rate Limiting
type SecurityRateConfig struct {
	// P0-5: SYN Flood Protection
	SYNEnabled      bool   `json:"synEnabled"`
	SYNThreshold    uint32 `json:"synThreshold"`    // Max SYNs/sec before dropping (default: 100)
	CookieThreshold uint32 `json:"cookieThreshold"` // Enable SYN cookies above this rate (default: 50)

	// P0-6: Connection Rate Limiting
	ConnRateEnabled bool   `json:"connRateEnabled"`
	RatePerSec      uint32 `json:"ratePerSec"` // Max connections/sec (default: 50)

	// P0-7: UDP Flood Protection
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

	// P0-7: UDP Flood Statistics
	UDPBlocked      uint64 `json:"udpBlocked"`      // UDP packets blocked
	UDPPassed       uint64 `json:"udpPassed"`       // UDP packets passed
	UDPBytesBlocked uint64 `json:"udpBytesBlocked"` // UDP bytes blocked
	UDPBytesPassed  uint64 `json:"udpBytesPassed"`  // UDP bytes passed

	// Shared Statistics
	UniqueIPs uint64 `json:"uniqueIps"` // Unique source IPs tracked
}

// CtErrorStats - always-on, unsampled L4 connection-error counters read from the
// ct_err_stats eBPF ARRAY map. These are trace-INDEPENDENT (populated directly by
// the CT state machine, not the sampled/compile-gated L4 trace path) and feed the
// loxilb_l4_error_events_total metric. Indices must match CT_ERR_STAT_* in
// loxilb-ebpf/kernel/llb_kern_ct.c.
type CtErrorStats struct {
	TCPRstClient uint64 `json:"tcpRstClient"` // idx 0: TCP RST from client  (CT_TCP_CW, dir IN)
	TCPRstServer uint64 `json:"tcpRstServer"` // idx 1: TCP RST from backend (CT_TCP_CW, dir OUT)
	TCPErr       uint64 `json:"tcpErr"`       // idx 2: TCP protocol error / half-open (CT_TCP_ERR)
	SCTPAbort    uint64 `json:"sctpAbort"`    // idx 3: SCTP ABORT (CT_SCTP_ABRT)
	SCTPErr      uint64 `json:"sctpErr"`      // idx 4: SCTP error (CT_SCTP_ERR)
}

// DpEbpfH - context container
type DpEbpfH struct {
	ticker  *time.Ticker
	tDone   chan bool
	trigGC  chan bool
	gcTS    time.Time
	gcTiVal uint
	ctBcast chan bool
	nID     uint
	tbN     uint
	CtSync  bool
	RssEn   bool
	ToMapCh chan interface{}
	ToFinCh [mapNotifierWorkers]chan int
	mtx     sync.RWMutex
	ctMap   map[string]*DpCtInfo

	// GPU-Aware Load Balancing: Runtime configuration and storage
	gpuMonitoringEnabled      atomic.Bool            // Runtime enable/disable flag
	workerMetrics             sync.Map               // map[endpoint_ip]WorkerMetrics
	workerIndexMap            sync.Map               // map[endpoint_ip]endpoint_index
	nextEndpointIndex         atomic.Uint32          // Auto-increment for new endpoints
	conversationCleanupTicker *time.Ticker           // Background cleanup (every 5 minutes)
	conversationCleanupStop   chan struct{}          // Signal to stop cleanup thread
	conversationMapMutex      sync.RWMutex           // Protect conversation cleanup operations
	workerGPUStatsMapFD       int                    // eBPF map FD: worker_gpu_stats_map
	routingModeMapFD          int                    // eBPF map FD: routing_mode_map
	endpointToGPUIndexMapFD   int                    // eBPF map FD: endpoint_to_gpu_index_map
	serviceScoringConfigMapFD int                    // eBPF map FD: service_scoring_config_map
	tracingCatalogManager     *TracingCatalogManager // Tracing catalog manager (trace_type)
	catalogSyncManager        *CatalogSyncManager    // Deep inspection catalog sync to C dataplane

	// L4 Connection Tracing: Ring buffer for L4 connection events
	l4TraceRingBufFD int // eBPF map FD: l4_trace_ringbuf

	// Security Rate: Track whitelist IPs added by security rate config to avoid deleting IP Filter rules
	prevSecurityRateWhitelistIPs []string // Previous whitelist IPs from security rate config
}

// WorkerMetrics stores GPU metrics for a worker endpoint (vLLM 0.9.x)
type WorkerMetrics struct {
	EndpointIP string // "192.168.1.10:8000"

	// Queue metrics. The built-in scraper populates QueuedRequests from
	// vllm:num_requests_waiting ONLY (waiting is the load-scoring signal;
	// running is not parsed). SwappedRequests is populated only by the REST
	// push API (external agents deriving it from vllm:num_preemptions_total);
	// the built-in scraper leaves it 0.
	QueuedRequests  uint32
	SwappedRequests uint32

	// Memory metrics (from vLLM)
	KVCacheUsagePerc uint32 // vllm:kv_cache_usage_perc * 100 (0-100)
	NumGPUBlocks     uint32 // vllm:cache_config_info{num_gpu_blocks} (static)

	LastUpdate time.Time // Last metrics update

	// Hysteresis state (synced from eBPF)
	IsOverloaded  bool
	OverloadStart time.Time
}

// GPUMonitoringStatus represents current GPU monitoring state
type GPUMonitoringStatus struct {
	Enabled           bool      `json:"enabled"`
	RoutingMode       string    `json:"routing_mode"`
	WorkerCount       int       `json:"worker_count"`
	LastMetricsUpdate time.Time `json:"last_metrics_update"`
	EbpfMapLoaded     bool      `json:"ebpf_map_loaded"`
}

// dpEbpfTicker - this ticker routine runs every DpEbpfLinuxTiVal seconds
func dpEbpfTicker() {

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

	tbls := []int{int(C.LL_DP_RTV4_STATS_MAP),
		int(C.LL_DP_TMAC_STATS_MAP),
		int(C.LL_DP_BD_STATS_MAP),
		int(C.LL_DP_TX_BD_STATS_MAP),
		int(C.LL_DP_SESS4_STATS_MAP),
		int(C.LL_DP_FW_STATS_MAP)}
	tLen := uint(len(tbls))

	for {
		if mh.dpEbpf == nil {
			continue
		}
		select {
		case <-mh.dpEbpf.tDone:
			return
		case <-mh.dpEbpf.ctBcast:
			tk.LogIt(tk.LogDebug, "CT Bcast\n")
			dpCTMapBcast()
			continue
		case <-mh.dpEbpf.trigGC:
			C.llb_age_map_entries(C.LL_DP_CT_MAP)
			C.llb_age_map_entries(C.LL_DP_FCV4_MAP)
			mh.dpEbpf.gcTS = time.Now()
		case <-mh.dpEbpf.ticker.C:
			sel := mh.dpEbpf.tbN % tLen

			// For every tick collect stats for an eBPF map
			// This routine caches stats in a local statsDB
			// which can be collected from a separate gothread
			C.llb_collect_map_stats(C.int(tbls[sel]))

			// Age any entries related to Conntrack
			/* No need to fetch all stats in this fashion */
			//C.llb_collect_map_stats(C.int(C.LL_DP_CT_STATS_MAP))
			/* Per entry stats will be fetched in C.ll_ct_map_ent_has_aged */
			if mh.dpEbpf.gcTiVal == 0 || time.Duration(time.Since(mh.dpEbpf.gcTS).Seconds()) > time.Duration(mh.dpEbpf.gcTiVal) {
				C.llb_age_map_entries(C.LL_DP_CT_MAP)
				C.llb_age_map_entries(C.LL_DP_FCV4_MAP)
				mh.dpEbpf.gcTS = time.Now()
			}

			// This means around 10s from start
			if !mh.dpEbpf.CtSync {
				tk.LogIt(tk.LogDebug, "Get xsync()\n")
				ret := mh.dp.DpXsyncRPC(DpSyncGet, nil)
				if ret == 0 {
					mh.dpEbpf.CtSync = true
				}
			}
			dpCTMapChkUpdates()
			mh.dpEbpf.tbN++
		}
	}
}

// DpEbpfDPLogLevel - Routine to set log level for DP
func DpEbpfDPLogLevel(cfg *C.struct_ebpfcfg, debug tk.LogLevelT) {
	switch debug {
	case tk.LogAlert:
		cfg.loglevel = 5 // LOG_FATAL
	case tk.LogCritical:
		cfg.loglevel = 5 // LOG_FATAL
	case tk.LogError:
		cfg.loglevel = 4 // LOG_ERROR
	case tk.LogWarning:
		cfg.loglevel = 3 // LOG_WARNING
	case tk.LogNotice:
		cfg.loglevel = 3 // LOG_WARNING
	case tk.LogInfo:
		cfg.loglevel = 2 // LOG_INFO
	case tk.LogTrace:
		cfg.loglevel = 0 // LOG_TRACE
	case tk.LogDebug:
	default:
		cfg.loglevel = 1 // LOG_DEBUG
	}
}

// DpEbpfSetLogLevel - Set log level for ebpf subsystem
func DpEbpfSetLogLevel(logLevel tk.LogLevelT) {
	cfg := C.struct_ebpfcfg{loglevel: 1}

	DpEbpfDPLogLevel(&cfg, logLevel)
	C.loxilb_set_loglevel(&cfg)
}

// DpEbpfInit - initialize the ebpf dp subsystem
func DpEbpfInit(clusterEn, rssEn, egrHooks, localSockPolicy, sockMapEn, ktlsEn bool, nodeNum int, disBPF bool, logLevel tk.LogLevelT, dpuMtraceEn ...bool) *DpEbpfH {
	var cfg C.struct_ebpfcfg

	if clusterEn || (len(dpuMtraceEn) > 0 && dpuMtraceEn[0]) {
		cfg.have_mtrace = 1
	} else {
		cfg.have_mtrace = 0
	}
	if egrHooks {
		cfg.egr_hooks = 1
	} else {
		cfg.egr_hooks = 0
	}
	if localSockPolicy {
		cfg.have_sockrwr = 1
	} else {
		cfg.have_sockrwr = 0
	}
	if sockMapEn {
		cfg.have_sockmap = 1
	} else {
		cfg.have_sockmap = 0
	}
	if ktlsEn {
		cfg.have_ktls = 1
	} else {
		cfg.have_ktls = 0
	}

	if disBPF {
		cfg.have_noebpf = 1
	} else {
		cfg.have_noebpf = 0
	}

	cfg.nodenum = C.int(nodeNum)
	cfg.loglevel = 1
	cfg.no_loader = 0

	DpEbpfDPLogLevel(&cfg, logLevel)

	C.loxilb_main(&cfg)

	// Make sure to unload eBPF programs at init time
	ifList, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, intf := range ifList {
		if intf.Name == "llb0" {
			continue
		}
		tk.LogIt(tk.LogInfo, "ebpf unload - %s\n", intf.Name)
		ifStr := C.CString(intf.Name)
		section := C.CString(string(C.TC_LL_SEC_DEFAULT))
		C.llb_dp_link_attach(ifStr, section, C.LL_BPF_MOUNT_TC, 1)
		if rssEn {
			xSection := C.CString(string(C.XDP_LL_SEC_DEFAULT))
			C.llb_dp_link_attach(ifStr, xSection, C.LL_BPF_MOUNT_XDP, 1)
			C.free(unsafe.Pointer(xSection))
		}
		C.free(unsafe.Pointer(ifStr))
		C.free(unsafe.Pointer(section))
	}

	ne := new(DpEbpfH)
	ne.tDone = make(chan bool)
	ne.trigGC = make(chan bool)
	ne.gcTS = time.Now()
	ne.gcTiVal = ctGCTiValDefault
	ne.ToMapCh = make(chan interface{}, mapNotifierChLen)
	for i := 0; i < mapNotifierWorkers; i++ {
		ne.ToFinCh[i] = make(chan int)
	}
	ne.ctBcast = make(chan bool)
	ne.ticker = time.NewTicker(dpEbpfLinuxTiVal * time.Second)
	ne.ctMap = make(map[string]*DpCtInfo)
	ne.RssEn = rssEn
	ne.nID = uint((C.LLB_CT_MAP_ENTRIES / C.LLB_MAX_LB_NODES) * nodeNum)
	prom.SetConntrackMaxEntries(int(C.LLB_CT_MAP_ENTRIES))

	// Initialize GPU map file descriptors (if GPU routing is compiled in)
	// Note: GPU routing requires HAVE_DP_GPU_ROUTING=1 in CFLAGS (line 80)
	// If not compiled, these FDs will be <= 0 and GPU functions will gracefully skip
	if !gpuRoutingEnabled {
		// GPU routing not compiled - set FDs to -1
		ne.routingModeMapFD = -1
		ne.workerGPUStatsMapFD = -1
		ne.endpointToGPUIndexMapFD = -1
		ne.serviceScoringConfigMapFD = -1
		tk.LogIt(tk.LogInfo, "GPU routing disabled: rebuild with -DHAVE_DP_GPU_ROUTING=1 to enable\n")
	} else {
		ne.routingModeMapFD = int(C.llb_map2fd(C.LL_DP_ROUTING_MODE_MAP))
		ne.workerGPUStatsMapFD = int(C.llb_map2fd(C.LL_DP_WORKER_GPU_STATS_MAP))
		ne.endpointToGPUIndexMapFD = int(C.llb_map2fd(C.LL_DP_ENDPOINT_TO_GPU_INDEX_MAP))
		ne.serviceScoringConfigMapFD = int(C.llb_map2fd(C.LL_DP_SERVICE_SCORING_CONFIG_MAP))

		if ne.routingModeMapFD > 0 {
			tk.LogIt(tk.LogDebug, "GPU routing_mode_map FD initialized: %d\n", ne.routingModeMapFD)
		} else {
			tk.LogIt(tk.LogWarning, "GPU routing_mode_map failed to load (map missing in eBPF)\n")
		}
		if ne.workerGPUStatsMapFD > 0 {
			tk.LogIt(tk.LogDebug, "GPU worker_gpu_stats_map FD initialized: %d\n", ne.workerGPUStatsMapFD)
		} else {
			tk.LogIt(tk.LogWarning, "GPU worker_gpu_stats_map failed to load (map missing in eBPF)\n")
		}
		if ne.endpointToGPUIndexMapFD > 0 {
			tk.LogIt(tk.LogDebug, "GPU endpoint_to_gpu_index_map FD initialized: %d\n", ne.endpointToGPUIndexMapFD)
		} else {
			tk.LogIt(tk.LogWarning, "GPU endpoint_to_gpu_index_map failed to load (map missing in eBPF)\n")
		}
		if ne.serviceScoringConfigMapFD > 0 {
			tk.LogIt(tk.LogDebug, "GPU service_scoring_config_map FD initialized: %d\n", ne.serviceScoringConfigMapFD)
		} else {
			tk.LogIt(tk.LogWarning, "GPU service_scoring_config_map failed to load (map missing in eBPF)\n")
		}
	}

	// Initialize tracing catalog manager (trace_type) - load templates only
	// Templates are loaded but NOT synced to shared memory until both:
	// 1. A service is configured with trace_type
	// 2. Tracing is enabled via API
	ne.tracingCatalogManager = NewTracingCatalogManager()
	tracingCatalogCount := len(ne.tracingCatalogManager.ListCatalogs())

	if tracingCatalogCount == 0 {
		ne.tracingCatalogManager = nil
		ne.catalogSyncManager = nil
		tk.LogIt(tk.LogDebug, "Tracing catalog manager disabled (no catalog templates found)\n")
	} else {
		// Load catalog templates (not synced yet - will sync on first use)
		tk.LogIt(tk.LogInfo, "Loaded %d tracing catalog template(s) (trace_type)\n", tracingCatalogCount)

		// Create sync manager but DON'T sync yet - wait for actual usage
		syncMgr, err := NewCatalogSyncManager(ne.tracingCatalogManager)
		if err != nil {
			tk.LogIt(tk.LogError, "Failed to initialize catalog sync manager: %v\n", err)
			ne.catalogSyncManager = nil
		} else {
			ne.catalogSyncManager = syncMgr
			tk.LogIt(tk.LogDebug, "Catalog sync manager ready (will sync on first trace_type usage)\n")
		}
	}

	// Initialize L4 trace ring buffer FD and config (build-tag protected)
	ne.initL4TraceRingBuffer()
	ne.initL4TraceConfig()

	go dpEbpfTicker()
	for i := 0; i < mapNotifierWorkers; i++ {
		go dpMapNotifierWorker(ne.ToFinCh[i], ne.ToMapCh)
	}

	return ne
}

// DpEbpfUnInit - uninitialize the ebpf dp subsystem
func (e *DpEbpfH) DpEbpfUnInit() {

	// bounded sends on the unbuffered control
	// channels. The receivers (dpEbpfTicker + dpMapNotifierWorker) block
	// inside CGO calls during a shutdown, so a bare `e.tDone <- true`
	// would wedge the SIGINT handler indefinitely (this is the EVIDENCE
	// hang). On send-timeout we log and proceed; the second-
	// SIGINT escalation path in loxinet.go is the safety net that
	// guarantees process exit even if the eBPF cleanup below stalls.
	select {
	case e.tDone <- true:
	case <-time.After(1 * time.Second):
		tk.LogIt(tk.LogWarning, "[shutdown] eBPF tDone send timed out — ticker may be in CGO\n")
	}
	for i := 0; i < mapNotifierWorkers; i++ {
		select {
		case e.ToFinCh[i] <- 1:
		case <-time.After(500 * time.Millisecond):
			tk.LogIt(tk.LogWarning, "[shutdown] eBPF ToFinCh[%d] send timed out\n", i)
		}
	}

	tk.LogIt(tk.LogInfo, "ebpf uninit : %s\n", debug.Stack())

	// Make sure to unload eBPF programs
	ifList, err := net.Interfaces()
	if err != nil {
		return
	}

	tk.LogIt(tk.LogInfo, "ebpf uninit begin\n")

	for _, intf := range ifList {

		tk.LogIt(tk.LogInfo, "ebpf unload - %s\n", intf.Name)
		ifStr := C.CString(intf.Name)
		section := C.CString(string(C.TC_LL_SEC_DEFAULT))
		C.llb_dp_link_attach(ifStr, section, C.LL_BPF_MOUNT_TC, 1)

		// Conditional XDP detachment based on HAVE_DP_IP_FILTER compile flag
		// If IP filter enabled: detach XDP from all interfaces (hybrid XDP+TC architecture)
		// Otherwise: detach XDP only from llb0 or RSS-enabled interfaces (legacy behavior)
		if xdpAllInterfaces || e.RssEn || intf.Name == "llb0" {
			xSection := C.CString(string(C.XDP_LL_SEC_DEFAULT))
			C.llb_dp_link_attach(ifStr, xSection, C.LL_BPF_MOUNT_XDP, 1)
			C.free(unsafe.Pointer(xSection))
		}

		C.free(unsafe.Pointer(ifStr))
		C.free(unsafe.Pointer(section))
	}

	C.llb_unload_kern_all()
}

func convNetIP2DPv6Addr(addr unsafe.Pointer, goIP net.IP) {
	aPtr := (*C.uchar)(addr)
	for bp := 0; bp < 16; bp++ {
		*aPtr = C.uchar(goIP[bp])
		aPtr = (*C.uchar)(getPtrOffset(unsafe.Pointer(aPtr),
			C.sizeof_uchar))
	}
}

func convDPv6Addr2NetIP(addr unsafe.Pointer) net.IP {
	var goIP net.IP
	aPtr := (*C.uchar)(addr)

	for i := 0; i < 16; i++ {
		goIP = append(goIP, uint8(*aPtr))
		aPtr = (*C.uchar)(getPtrOffset(unsafe.Pointer(aPtr),
			C.sizeof_uchar))
	}
	return goIP
}

// loadEbpfPgm - load loxilb eBPF program to an interface
func (e *DpEbpfH) loadEbpfPgm(name string) int {
	if mh.disBPF {
		return 0
	}
	ifStr := C.CString(name)
	xSection := C.CString(string(C.XDP_LL_SEC_DEFAULT))
	link, err := nlp.LinkByName(name)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[DP] Port %s not found\n", name)
		return -1
	}

	// Conditional XDP attachment based on HAVE_DP_IP_FILTER compile flag
	// If IP filter enabled: attach XDP to all interfaces (hybrid XDP+TC architecture)
	// Otherwise: attach XDP only to llb0 or RSS-enabled interfaces (legacy behavior)
	if xdpAllInterfaces || e.RssEn || name == "llb0" {
		C.llb_dp_link_attach(ifStr, xSection, C.LL_BPF_MOUNT_XDP, 0)
	}

	section := C.CString(string(C.TC_LL_SEC_DEFAULT))
	C.llb_dp_link_attach(ifStr, section, C.LL_BPF_MOUNT_TC, 0)

	filters, err := nlp.FilterList(link, nlp.HANDLE_MIN_INGRESS)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[DP] Filter on %s not found\n", name)
		return -1
	}
	ret := -1
	for _, f := range filters {
		if t, ok := f.(*nlp.BpfFilter); ok {
			if strings.Contains(t.Name, "tc_packet_func") {
				ret = 0
				break
			}
		}
	}
	C.free(unsafe.Pointer(ifStr))
	C.free(unsafe.Pointer(xSection))
	C.free(unsafe.Pointer(section))
	return int(ret)
}

// unLoadEbpfPgm - unload loxilb eBPF program from an interface
func (e *DpEbpfH) unLoadEbpfPgm(name string) int {
	if mh.disBPF {
		return 0
	}
	ifStr := C.CString(name)
	xSection := C.CString(string(C.XDP_LL_SEC_DEFAULT))

	// Conditional XDP detachment based on HAVE_DP_IP_FILTER compile flag
	// If IP filter enabled: detach XDP from all interfaces (hybrid XDP+TC architecture)
	// Otherwise: detach XDP only from llb0 or RSS-enabled interfaces (legacy behavior)
	if xdpAllInterfaces || e.RssEn || name == "llb0" {
		C.llb_dp_link_attach(ifStr, xSection, C.LL_BPF_MOUNT_XDP, 1)
	}

	section := C.CString(string(C.TC_LL_SEC_DEFAULT))
	ret := C.llb_dp_link_attach(ifStr, section, C.LL_BPF_MOUNT_TC, 1)
	C.free(unsafe.Pointer(ifStr))
	C.free(unsafe.Pointer(section))
	C.free(unsafe.Pointer(xSection))
	return int(ret)
}

func getPtrOffset(ptr unsafe.Pointer, size uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(ptr) + size)
}

func osPortIsRunning(portName string) bool {
	sfd, err := syscall.Socket(syscall.AF_INET,
		syscall.SOCK_DGRAM,
		syscall.IPPROTO_IP)
	if err != nil {
		tk.LogIt(tk.LogError, "Error %s", err)
		return false
	}

	ifstr := C.CString(portName)
	ifrStruct := make([]byte, 32)
	C.memcpy(unsafe.Pointer(&ifrStruct[0]), unsafe.Pointer(ifstr), 16)

	r0, _, err := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(sfd),
		syscall.SIOCGIFFLAGS,
		uintptr(unsafe.Pointer(&ifrStruct[0])))
	if r0 != 0 {
		C.free(unsafe.Pointer(ifstr))
		syscall.Close(sfd)
		tk.LogIt(tk.LogError, "Error %s", err)
		return false
	}

	C.free(unsafe.Pointer(ifstr))
	syscall.Close(sfd)

	var flags uint16
	C.memcpy(unsafe.Pointer(&flags), unsafe.Pointer(&ifrStruct[16]), 2)

	return flags&syscall.IFF_RUNNING != 0
}

// DpPortPropMod - routine to work on a ebpf port property request
func (e *DpEbpfH) DpPortPropMod(w *PortDpWorkQ) int {
	var txK C.uint
	var txV C.uint
	var setIfi *intfSetIfi

	// This is a special case
	if w.LoadEbpf == "llb0" {
		w.PortNum = C.LLB_INTERFACES - 1
	}

	key := new(intfMapKey)
	key.ing_vid = C.ushort(tk.Htons(uint16(w.IngVlan)))
	key.ifindex = C.uint(w.OsPortNum)

	txK = C.uint(w.PortNum)

	if w.Work == DpCreate {

		if w.LoadEbpf != "" && w.LoadEbpf != "lo" && w.LoadEbpf != "llb0" {
			lRet := e.loadEbpfPgm(w.LoadEbpf)
			if lRet != 0 {
				tk.LogIt(tk.LogError, "ebpf load - %d error\n", w.PortNum)
				/* Shouldn't exit if the interface is not there, so return -1 and continue*/
				_, err := nlp.LinkByName(w.LoadEbpf)
				if err != nil {
					return -1
				}
				syscall.Exit(1)
			}
		}
		data := new(intfMapDat)
		C.memset(unsafe.Pointer(data), 0, C.sizeof_struct_dp_intf_tact)
		data.ca.act_type = C.DP_SET_IFI
		setIfi = (*intfSetIfi)(getPtrOffset(unsafe.Pointer(data),
			C.sizeof_struct_dp_cmn_act))

		setIfi.xdp_ifidx = C.ushort(w.PortNum)
		setIfi.zone = C.ushort(w.SetZoneNum)

		setIfi.bd = C.ushort(uint16(w.SetBD))
		setIfi.mirr = C.ushort(w.SetMirr)
		setIfi.polid = C.ushort(w.SetPol)

		if w.Prop&cmn.PortPropUpp == cmn.PortPropUpp {
			setIfi.pprop = C.LLB_DP_PORT_UPP
		}

		ret := C.llb_add_map_elem(C.LL_DP_INTF_MAP, unsafe.Pointer(key), unsafe.Pointer(data))

		if ret != 0 {
			tk.LogIt(tk.LogError, "ebpf intfmap - %d vlan %d error\n", w.OsPortNum, w.IngVlan)
			return EbpfErrPortPropAdd
		}

		tk.LogIt(tk.LogDebug, "ebpf intfmap added - %d vlan %d -> %d\n", w.OsPortNum, w.IngVlan, w.PortNum)

		txV = C.uint(w.OsPortNum)
		ret = C.llb_add_map_elem(C.LL_DP_TX_INTF_MAP, unsafe.Pointer(&txK), unsafe.Pointer(&txV))
		if ret != 0 {
			C.llb_del_map_elem(C.LL_DP_INTF_MAP, unsafe.Pointer(key))
			tk.LogIt(tk.LogError, "ebpf txintfmap - %d error\n", w.OsPortNum)
			return EbpfErrPortPropAdd
		}
		tk.LogIt(tk.LogDebug, "ebpf txintfmap added - %d -> %d\n", w.PortNum, w.OsPortNum)
		return 0
	} else if w.Work == DpRemove {

		// TX_INTF_MAP is array type so we can't delete it
		// Rather we need to zero it out first
		txV = C.uint(0)
		C.llb_add_map_elem(C.LL_DP_TX_INTF_MAP, unsafe.Pointer(&txK), unsafe.Pointer(&txV))
		C.llb_del_map_elem(C.LL_DP_TX_INTF_MAP, unsafe.Pointer(&txK))

		C.llb_del_map_elem(C.LL_DP_INTF_MAP, unsafe.Pointer(key))

		if w.LoadEbpf != "" {
			lRet := e.unLoadEbpfPgm(w.LoadEbpf)
			if lRet != 0 {
				tk.LogIt(tk.LogError, "ebpf unload - ifi %d error\n", w.OsPortNum)
				return EbpfErrEbpfLoad
			}
			tk.LogIt(tk.LogDebug, "ebpf unloaded - ifi %d\n", w.OsPortNum)
		}

		return 0
	}

	return EbpfErrWqUnk
}

// DpPortPropAdd - routine to work on a ebpf port property add
func (e *DpEbpfH) DpPortPropAdd(w *PortDpWorkQ) int {
	return e.DpPortPropMod(w)
}

// DpPortPropDel - routine to work on a ebpf port property delete
func (e *DpEbpfH) DpPortPropDel(w *PortDpWorkQ) int {
	return e.DpPortPropMod(w)
}

// DpL2AddrMod - routine to work on a ebpf l2 addr request
func DpL2AddrMod(w *L2AddrDpWorkQ) int {
	var l2va *l2VlanAct

	skey := new(sMacKey)
	C.memcpy(unsafe.Pointer(&skey.smac[0]), unsafe.Pointer(&w.L2Addr[0]), 6)
	skey.bd = C.ushort((uint16(w.BD)))

	dkey := new(dMacKey)
	C.memcpy(unsafe.Pointer(&dkey.dmac[0]), unsafe.Pointer(&w.L2Addr[0]), 6)
	dkey.bd = C.ushort((uint16(w.BD)))

	if w.Work == DpCreate {
		sdat := new(sActValue)
		sdat.act_type = C.DP_SET_NOP

		ddat := new(dMacMapDat)
		C.memset(unsafe.Pointer(ddat), 0, C.sizeof_struct_dp_dmac_tact)

		if w.Tun == 0 {
			l2va = (*l2VlanAct)(getPtrOffset(unsafe.Pointer(ddat),
				C.sizeof_struct_dp_cmn_act))
			if w.Tagged != 0 {
				ddat.ca.act_type = C.DP_SET_ADD_L2VLAN
				l2va.vlan = C.ushort(tk.Htons(uint16(w.BD)))
				l2va.oport = C.ushort(w.PortNum)
			} else {
				ddat.ca.act_type = C.DP_SET_RM_L2VLAN
				l2va.vlan = C.ushort(tk.Htons(uint16(w.BD)))
				l2va.oport = C.ushort(w.PortNum)
			}
		}

		ret := C.llb_add_map_elem(C.LL_DP_SMAC_MAP,
			unsafe.Pointer(skey),
			unsafe.Pointer(sdat))
		if ret != 0 {
			return EbpfErrL2AddrAdd
		}

		if w.Tun == 0 {
			ret = C.llb_add_map_elem(C.LL_DP_DMAC_MAP,
				unsafe.Pointer(dkey),
				unsafe.Pointer(ddat))
			if ret != 0 {
				C.llb_del_map_elem(C.LL_DP_SMAC_MAP, unsafe.Pointer(skey))
				return EbpfErrL2AddrAdd
			}
		}

		return 0
	} else if w.Work == DpRemove {

		C.llb_del_map_elem(C.LL_DP_SMAC_MAP, unsafe.Pointer(skey))

		if w.Tun == 0 {
			C.llb_del_map_elem(C.LL_DP_DMAC_MAP, unsafe.Pointer(dkey))
		}

		return 0
	}

	return EbpfErrWqUnk
}

// DpL2AddrAdd - routine to work on a ebpf l2 addr add
func (e *DpEbpfH) DpL2AddrAdd(w *L2AddrDpWorkQ) int {
	return DpL2AddrMod(w)
}

// DpL2AddrDel - routine to work on a ebpf l2 addr delete
func (e *DpEbpfH) DpL2AddrDel(w *L2AddrDpWorkQ) int {
	return DpL2AddrMod(w)
}

// DpRouterMacMod - routine to work on a ebpf rt-mac change request
func DpRouterMacMod(w *RouterMacDpWorkQ) int {

	key := new(tMacKey)
	C.memcpy(unsafe.Pointer(&key.mac[0]), unsafe.Pointer(&w.L2Addr[0]), 6)
	switch {
	case w.TunType == DpTunVxlan:
		key.tun_type = C.LLB_TUN_VXLAN
	case w.TunType == DpTunGre:
		key.tun_type = C.LLB_TUN_GRE
	case w.TunType == DpTunGtp:
		key.tun_type = C.LLB_TUN_GTP
	case w.TunType == DpTunStt:
		key.tun_type = C.LLB_TUN_STT
	}

	key.tunnel_id = C.uint(w.TunID)

	if w.Work == DpCreate {
		dat := new(tMacDat)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_tmac_tact)
		if w.TunID != 0 {
			if w.NhNum == 0 {
				dat.ca.act_type = C.DP_SET_RM_VXLAN
				rtNhAct := (*rtNhAct)(getPtrOffset(unsafe.Pointer(dat),
					C.sizeof_struct_dp_cmn_act))
				C.memset(unsafe.Pointer(rtNhAct), 0, C.sizeof_struct_dp_rt_nh_act)
				rtNhAct.nh_num[0] = 0
				rtNhAct.tid = 0
				rtNhAct.bd = C.ushort(w.BD)
			} else {
				/* No need for tunnel ID in case of Access side */
				key.tunnel_id = 0
				key.tun_type = 0
				dat.ca.act_type = C.DP_SET_RT_TUN_NH
				rtNhAct := (*rtNhAct)(getPtrOffset(unsafe.Pointer(dat),
					C.sizeof_struct_dp_cmn_act))
				C.memset(unsafe.Pointer(rtNhAct), 0, C.sizeof_struct_dp_rt_nh_act)

				rtNhAct.nh_num[0] = C.ushort(w.NhNum)
				tid := ((w.TunID << 8) & 0xffffff00)
				rtNhAct.tid = C.uint(tk.Htonl(tid))
			}
		} else {
			dat.ca.act_type = C.DP_SET_L3_EN
		}

		ret := C.llb_add_map_elem(C.LL_DP_TMAC_MAP,
			unsafe.Pointer(key),
			unsafe.Pointer(dat))

		if ret != 0 {
			if w.Status != nil {
				*w.Status = DpCreateErr
			}
			return EbpfErrTmacAdd
		}

		if w.Status != nil {
			*w.Status = 0
		}

		return 0
	} else if w.Work == DpRemove {

		C.llb_del_map_elem(C.LL_DP_TMAC_MAP, unsafe.Pointer(key))
	}

	return EbpfErrWqUnk
}

// DpRouterMacAdd - routine to work on a ebpf rt-mac add request
func (e *DpEbpfH) DpRouterMacAdd(w *RouterMacDpWorkQ) int {
	return DpRouterMacMod(w)
}

// DpRouterMacDel - routine to work on a ebpf rt-mac delete request
func (e *DpEbpfH) DpRouterMacDel(w *RouterMacDpWorkQ) int {
	return DpRouterMacMod(w)
}

// DpNextHopMod - routine to work on a ebpf next-hop change request
func DpNextHopMod(w *NextHopDpWorkQ) int {
	var act *rtL2NhAct
	var tunAct *rtTunNhAct

	var key C.uint = C.uint(w.NextHopNum)

	if w.Work == DpCreate {
		dat := new(nhDat)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_nh_tact)
		if !w.Resolved {
			dat.ca.act_type = C.DP_SET_TOCP
		} else {
			if w.TunNh {
				tk.LogIt(tk.LogDebug, "Setting tunNh 0x%x\n", key)
				if w.TunType == DpTunIPIP {
					dat.ca.act_type = C.DP_SET_NEIGH_IPIP
				} else {
					dat.ca.act_type = C.DP_SET_NEIGH_VXLAN
				}
				tunAct = (*rtTunNhAct)(getPtrOffset(unsafe.Pointer(dat),
					C.sizeof_struct_dp_cmn_act))

				ipAddr := tk.IPtonl(w.RIP)
				tunAct.l3t.rip = C.uint(ipAddr)
				tunAct.l3t.sip = C.uint(tk.IPtonl(w.SIP))
				tid := ((w.TunID << 8) & 0xffffff00)
				tunAct.l3t.tid = C.uint(tk.Htonl(tid))

				act = (*rtL2NhAct)(&tunAct.l2nh)
				C.memcpy(unsafe.Pointer(&act.dmac[0]), unsafe.Pointer(&w.DstAddr[0]), 6)
				C.memcpy(unsafe.Pointer(&act.smac[0]), unsafe.Pointer(&w.SrcAddr[0]), 6)
				act.bd = C.ushort(w.BD)
			} else {
				dat.ca.act_type = C.DP_SET_NEIGH_L2
				act = (*rtL2NhAct)(getPtrOffset(unsafe.Pointer(dat),
					C.sizeof_struct_dp_cmn_act))
				C.memcpy(unsafe.Pointer(&act.dmac[0]), unsafe.Pointer(&w.DstAddr[0]), 6)
				C.memcpy(unsafe.Pointer(&act.smac[0]), unsafe.Pointer(&w.SrcAddr[0]), 6)
				act.bd = C.ushort(w.BD)
				act.rnh_num = C.ushort(w.NNextHopNum)
			}
		}

		ret := C.llb_add_map_elem(C.LL_DP_NH_MAP,
			unsafe.Pointer(&key),
			unsafe.Pointer(dat))
		if ret != 0 {
			return EbpfErrNhAdd
		}
		return 0
	} else if w.Work == DpRemove {
		dat := new(nhDat)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_nh_tact)
		//C.llb_del_table_elem(C.LL_DP_NH_MAP, unsafe.Pointer(key))
		// eBPF array elements cant be deleted. Instead we just reset it
		C.llb_add_map_elem(C.LL_DP_NH_MAP,
			unsafe.Pointer(&key),
			unsafe.Pointer(dat))
		return 0
	}

	return EbpfErrWqUnk
}

// DpNextHopAdd - routine to work on a ebpf next-hop add request
func (e *DpEbpfH) DpNextHopAdd(w *NextHopDpWorkQ) int {
	return DpNextHopMod(w)
}

// DpNextHopDel - routine to work on a ebpf next-hop delete request
func (e *DpEbpfH) DpNextHopDel(w *NextHopDpWorkQ) int {
	return DpNextHopMod(w)
}

// DpRouteMod - routine to work on a ebpf route change request
func DpRouteMod(w *RouteDpWorkQ) int {
	var mapNum C.int
	var mapSnum C.int
	var act *rtL3NhAct
	var kPtr *[6]uint8
	var key unsafe.Pointer

	if w.ZoneNum == 0 {
		tk.LogIt(tk.LogError, "ZoneNum must be specified\n")
		syscall.Exit(1)
	}

	if tk.IsNetIPv4(w.Dst.IP.String()) {
		key4 := new(rt4Key)

		mlen, _ := w.Dst.Mask.Size()
		mlen += 16 /* 16-bit ZoneNum + prefix-len */
		key4.l.prefixlen = C.uint(mlen)
		kPtr = (*[6]uint8)(getPtrOffset(unsafe.Pointer(key4),
			C.sizeof_struct_bpf_lpm_trie_key))

		kPtr[0] = uint8(w.ZoneNum >> 8 & 0xff)
		kPtr[1] = uint8(w.ZoneNum & 0xff)
		kPtr[2] = uint8(w.Dst.IP[0])
		kPtr[3] = uint8(w.Dst.IP[1])
		kPtr[4] = uint8(w.Dst.IP[2])
		kPtr[5] = uint8(w.Dst.IP[3])
		key = unsafe.Pointer(key4)
		mapNum = C.LL_DP_RTV4_MAP
		mapSnum = C.LL_DP_RTV4_STATS_MAP
	} else {
		key6 := new(rt6Key)

		mlen, _ := w.Dst.Mask.Size()
		key6.l.prefixlen = C.uint(mlen)

		k6Ptr := (*C.uchar)(getPtrOffset(unsafe.Pointer(key6),
			C.sizeof_struct_bpf_lpm_trie_key))

		for bp := 0; bp < 16; bp++ {
			*k6Ptr = C.uchar(w.Dst.IP[bp])
			k6Ptr = (*C.uchar)(getPtrOffset(unsafe.Pointer(k6Ptr),
				C.sizeof_uchar))
		}
		key = unsafe.Pointer(key6)
		mapNum = C.LL_DP_RTV6_MAP
		mapSnum = C.LL_DP_RTV6_STATS_MAP
	}

	if w.Work == DpCreate {
		dat := new(rtDat)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_rt_tact)

		if w.NMax > 0 {
			if w.Dst.IP.IsUnspecified() {
				dat.ca.act_type = C.DP_SET_RT_NHNUM_DFLT
			} else {
				dat.ca.act_type = C.DP_SET_RT_NHNUM
			}
			act = (*rtL3NhAct)(getPtrOffset(unsafe.Pointer(dat),
				C.sizeof_struct_dp_cmn_act))
			act.naps = C.ushort(w.NMax)
			for i := range w.NMark {
				if i < C.DP_MAX_ACTIVE_PATHS {
					act.nh_num[i] = C.ushort(w.NMark[i])
				}
			}
		} else {
			mLen, _ := w.Dst.Mask.Size()
			if mLen == 32 || mLen == 128 {
				dat.ca.act_type = C.DP_SET_TOCP
			} else {
				dat.ca.act_type = C.DP_SET_NOP
			}
		}

		if w.RtMark > 0 {
			dat.ca.cidx = C.uint(w.RtMark)
		}

		ret := C.llb_add_map_elem(mapNum,
			unsafe.Pointer(key),
			unsafe.Pointer(dat))
		if ret != 0 {
			return EbpfErrRt4Add
		}

		// shadow route offload after eBPF success
		if tk.IsNetIPv4(w.Dst.IP.String()) && w.NMax > 0 && mh.dpuMgr != nil {
			mh.dpuMgr.ShadowRouteAdd(w)
		}

		return 0
	} else if w.Work == DpRemove {
		// shadow route remove before eBPF delete
		if tk.IsNetIPv4(w.Dst.IP.String()) && w.NMax > 0 && mh.dpuMgr != nil {
			mh.dpuMgr.ShadowRouteDel(w)
		}

		C.llb_del_map_elem(mapNum, unsafe.Pointer(key))

		if w.RtMark > 0 {
			C.llb_clear_map_stats(mapSnum, C.uint(w.RtMark))
		}
		return 0
	}

	return EbpfErrWqUnk
}

// DpRouteAdd - routine to work on a ebpf route add request
func (e *DpEbpfH) DpRouteAdd(w *RouteDpWorkQ) int {
	return DpRouteMod(w)
}

// DpRouteDel - routine to work on a ebpf route delete request
func (e *DpEbpfH) DpRouteDel(w *RouteDpWorkQ) int {
	return DpRouteMod(w)
}

// alpnToBackendCap maps the Octavia alpn_protocols list onto the backend_protocol_cap enum
// : [h2,http/1.1]⇒2 (both), [h2]⇒1 (h2-only), [http/1.1]⇒0 (h1-only). It
// returns (cap, true) when the list is non-empty and recognizable; (0, false) when the list is
// empty so the caller leaves the BackendProtocol-derived cap untouched (no override). An h2
// entry is only honored as cap>=1 when the list contains h2; (no h2→h1 downgrade) is
// enforced in the data plane (the cap drives alpn_select_callback), not here.
func alpnToBackendCap(alpn []string) (uint8, bool) {
	if len(alpn) == 0 {
		return 0, false
	}
	hasH2 := false
	hasH1 := false
	for _, p := range alpn {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "h2":
			hasH2 = true
		case "http/1.1", "http1.1", "http/1", "h1":
			hasH1 = true
		}
	}
	switch {
	case hasH2 && hasH1:
		return 2, true
	case hasH2:
		return 1, true
	case hasH1:
		return 0, true
	default:
		// Unrecognized ALPN tokens: leave the BackendProtocol-derived cap untouched rather than
		// silently forcing h1 (no silent semantic change —).
		return 0, false
	}
}

// tlsVersionsToRange collapses the Octavia tls_versions list to a min..max range encoded as the
// low-byte 0x03xx OpenSSL ordinal (TLSv1.0⇒0x01, TLSv1.1⇒0x02, TLSv1.2⇒0x03, TLSv1.3⇒0x04);
// 0 ⇒ today's hardcoded floor/ceiling. Non-contiguous selections collapse to
// the [min..max] span (Octavia documents this approximation). An empty list ⇒ (0,0) ⇒ unchanged.
func tlsVersionsToRange(versions []string) (uint8, uint8) {
	ord := func(v string) uint8 {
		switch strings.ToUpper(strings.TrimSpace(v)) {
		case "TLSV1.0", "TLS1.0", "TLSV1":
			return 0x01
		case "TLSV1.1", "TLS1.1":
			return 0x02
		case "TLSV1.2", "TLS1.2":
			return 0x03
		case "TLSV1.3", "TLS1.3":
			return 0x04
		default:
			return 0
		}
	}
	var minV, maxV uint8
	for _, v := range versions {
		o := ord(v)
		if o == 0 {
			continue
		}
		if minV == 0 || o < minV {
			minV = o
		}
		if o > maxV {
			maxV = o
		}
	}
	return minV, maxV
}

// DpLBRuleMod - routine to work on a ebpf lb change request
func DpLBRuleMod(w *LBDpWorkQ) int {

	key := new(natKey)

	key.mark = C.uint(w.BlockNum)

	if w.NatType == DpSnat || w.NatType == DpNat {
		key.mark |= NatFwMark
		fmt.Printf("mark %v\n", key.mark)
	} else {
		key.daddr = [4]C.uint{0, 0, 0, 0}
		if tk.IsNetIPv4(w.ServiceIP.String()) {
			key.daddr[0] = C.uint(tk.IPtonl(w.ServiceIP))
			key.v6 = 0
		} else {
			convNetIP2DPv6Addr(unsafe.Pointer(&key.daddr[0]), w.ServiceIP)
			key.v6 = 1
		}
		key.mark = C.uint(w.BlockNum)
		key.dport = C.ushort(tk.Htons(w.L4Port))
		key.l4proto = C.ushort(w.Proto)
		key.zone = C.ushort(w.ZoneNum)
	}

	dat := new(proxyActs)
	C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_proxy_tacts)
	if w.NatType == DpSnat {
		dat.ca.act_type = C.DP_SET_SNAT
	} else if w.NatType == DpDnat || w.NatType == DpFullNat || w.NatType == DpNat {
		dat.ca.act_type = C.DP_SET_DNAT
	} else if w.NatType == DpFullProxy {
		dat.ca.act_type = C.DP_SET_FULLPROXY
	} else {
		tk.LogIt(tk.LogDebug, "[DP] LB rule %s add[NOK] - EbpfErrNat4Add\n", w.ServiceIP.String())
		return EbpfErrNat4Add
	}

	// seconds to nanoseconds
	dat.ito = C.uint64_t(w.InActTo * 1000000000)
	dat.pto = C.uint64_t(w.PersistTo * 1000000000)
	dat.base_to = 0

	/*dat.npmhh = 2
	dat.pmhh[0] = 0x64646464
	dat.pmhh[1] = 0x65656565*/
	for i, k := range w.secIP {
		dat.pmhh[i] = C.uint(tk.IPtonl(k))
	}
	dat.npmhh = C.uchar(len(w.secIP))

	switch {
	case w.EpSel == EpRR:
		dat.sel_type = C.NAT_LB_SEL_RR
	case w.EpSel == EpHash:
		dat.sel_type = C.NAT_LB_SEL_HASH
	case w.EpSel == EpRRPersist:
		dat.sel_type = C.NAT_LB_SEL_RR_PERSIST
	case w.EpSel == EpLeastConn:
		dat.sel_type = C.NAT_LB_SEL_LC
	case w.EpSel == EpN2:
		dat.sel_type = C.NAT_LB_SEL_N2
	case w.EpSel == EpN3:
		dat.sel_type = C.NAT_LB_SEL_N3
	case w.EpSel == EpCHWBL:
		dat.sel_type = C.NAT_LB_SEL_CHWBL
		// Propagate CHWBL prefix hash level through dp_proxy_tacts
		// This replaces the old pad3[1] field (same size, no ABI change)
		if w.CHWBLPrefixHashLevel > 0 {
			dat.chwbl_prefix_hash_level = C.uint8_t(w.CHWBLPrefixHashLevel)
		}
	case w.EpSel == EpGPUAware:
		dat.sel_type = C.NAT_LB_SEL_GPU_AWARE
	case w.EpSel == EpPrio: // P3: WRR (Weighted Round-Robin)
		dat.sel_type = C.NAT_LB_SEL_PRIO
	case w.EpSel == EpWRRHash: // P3.5: WRR_HASH (Weighted Consistent Hash + Bounded Loads)
		dat.sel_type = C.NAT_LB_SEL_WRR_HASH
	default:
		dat.sel_type = C.NAT_LB_SEL_RR
	}
	dat.ca.cidx = C.uint(w.Mark)
	// Octavia connectionLimit: write the per-rule concurrent-connection
	// ceiling into the dataplane rule act. 0 = unlimited (no gate). The eBPF gate (dp_do_nat)
	// reads this conn_limit and compares it against the live conc_conns count (nat_ep_map),
	// forcing sel=-1 -> pm.nf=0 (SYN refuse, no CT) when the live count has reached the ceiling.
	dat.conn_limit = C.uint32_t(w.ConnLimit)
	if w.DsrMode {
		dat.ca.oaux = 1
	}
	if w.SrcCheck {
		dat.opflags = C.NAT_LB_OP_CHKSRC
	}
	if w.Ppv2En {
		dat.ppv2 = 1
	}

	nxfa := (*nxfrmAct)(unsafe.Pointer(&dat.nxfrms[0]))

	for _, k := range w.endPoints {
		nxfa.wprio = C.uchar(k.Weight)
		nxfa.nat_xport = C.ushort(tk.Htons(k.XPort))
		if tk.IsNetIPv6(k.XIP.String()) {
			convNetIP2DPv6Addr(unsafe.Pointer(&nxfa.nat_xip[0]), k.XIP)

			if tk.IsNetIPv6(k.RIP.String()) {
				convNetIP2DPv6Addr(unsafe.Pointer(&nxfa.nat_rip[0]), k.RIP)
			}
			nxfa.nv6 = 1
		} else {
			nxfa.nat_xip[0] = C.uint(tk.IPtonl(k.XIP))
			nxfa.nat_rip[0] = C.uint(tk.IPtonl(k.RIP))
			nxfa.nv6 = 0
		}

		if k.InActive {
			nxfa.inactive = 1
		}
		nxfa.ep_role = C.uchar(k.EpRole)
		nxfa.nixl_xport = C.ushort(tk.Htons(k.NixlPort))

		nxfa = (*nxfrmAct)(getPtrOffset(unsafe.Pointer(nxfa),
			C.sizeof_struct_mf_xfrm_inf))
	}

	// Any unused end-points should be marked inactive
	for i := len(w.endPoints); i < C.LLB_MAX_NXFRMS; i++ {
		nxfa := (*nxfrmAct)(unsafe.Pointer(&dat.nxfrms[i]))
		nxfa.inactive = 1
	}

	dat.nxfrm = C.uchar(len(w.endPoints))
	if w.CsumDis {
		dat.cdis = 1
	} else {
		dat.cdis = 0
	}

	if w.SecMode == DpTermHTTPS {
		dat.sec_mode = C.SEC_MODE_HTTPS
	} else if w.SecMode == DpE2EHTTPS {
		dat.sec_mode = C.SEC_MODE_HTTPS_E2E
	}

	hostURLStr := C.CString(w.HostURL)
	defer C.free(unsafe.Pointer(hostURLStr))
	C.memcpy(unsafe.Pointer(&dat.host_url[0]), unsafe.Pointer(hostURLStr), C.ulong(len(w.HostURL))+1)

	// P6: Path prefix routing support
	pathPrefixStr := C.CString(w.PathPrefix)
	defer C.free(unsafe.Pointer(pathPrefixStr))
	C.memcpy(unsafe.Pointer(&dat.path_prefix[0]), unsafe.Pointer(pathPrefixStr), C.ulong(len(w.PathPrefix))+1)

	// P6: Path match mode (0=disabled, 1=prefix, 2=exact)
	switch w.PathMatchMode {
	case "prefix":
		dat.path_match_mode = 1
	case "exact":
		dat.path_match_mode = 2
	default:
		dat.path_match_mode = 0 // disabled
	}

	// Backend protocol capability (0=http1, 1=http2, 2=both)
	// Default to http1 for backward compatibility
	switch w.BackendProtocol {
	case "http2":
		dat.backend_protocol_cap = 1
	case "both":
		dat.backend_protocol_cap = 2
	default: // "http1" or empty
		dat.backend_protocol_cap = 0
	}

	// Custom session header - supports both RR and Persist modes
	if w.SessionHeaderName != "" {
		sessionHeaderStr := C.CString(w.SessionHeaderName)
		defer C.free(unsafe.Pointer(sessionHeaderStr))
		C.memcpy(unsafe.Pointer(&dat.session_header_name[0]), unsafe.Pointer(sessionHeaderStr), C.ulong(len(w.SessionHeaderName))+1)
		dat.session_header_enabled = 1
		tk.LogIt(tk.LogDebug, "[DP] LB rule %s:%v session_header_name='%s' enabled=1\n", w.ServiceIP.String(), key.mark, w.SessionHeaderName)
	} else {
		dat.session_header_enabled = 0
	}

	// AI model name for pool selection (empty = wildcard, backward compatible)
	modelNameStr := C.CString(w.ModelName)
	defer C.free(unsafe.Pointer(modelNameStr))
	C.memcpy(unsafe.Pointer(&dat.model_name[0]), unsafe.Pointer(modelNameStr), C.ulong(len(w.ModelName))+1)

	// SSE (Server-Sent Events) streaming configuration
	if w.SSEMode {
		dat.sse_mode = 1
	} else {
		dat.sse_mode = 0
	}
	dat.max_stream_duration_sec = C.uint32_t(w.MaxStreamDurationSec)
	dat.backend_keepalive_sec = C.uint32_t(w.BackendKeepaliveIntervalSec)

	// per-listener member timeouts in MILLISECONDS (native unit,
	// no conversion —). Default-off (0 ⇒ preserve today's behaviour). Copied verbatim into
	// proxy_arg by llb_conv_nat2proxy; enforced in the data plane only on the L7_Proxy peer.
	dat.timeout_member_connect_ms = C.uint32_t(w.TimeoutMemberConnect)
	dat.timeout_member_data_ms = C.uint32_t(w.TimeoutMemberData)
	dat.timeout_tcp_inspect_ms = C.uint32_t(w.TimeoutTcpInspect)

	// TLS-hardening scalars. All additive/default-off — empty/0
	// preserves today's behaviour. Threaded into dp_proxy_tacts, copied verbatim
	// into proxy_arg by llb_conv_nat2proxy; consumed only on the L7_Proxy peer (has_l7_policy==1).

	// ALPN list → backend_protocol_cap. When alpn_protocols is set it OVERRIDES
	// the BackendProtocol-derived cap above: [h2,http/1.1]⇒2, [h2]⇒1, [http/1.1]⇒0. Empty ⇒ leave
	// the BackendProtocol-driven value untouched (no override).
	if cap, ok := alpnToBackendCap(w.AlpnProtocols); ok {
		dat.backend_protocol_cap = C.uint8_t(cap)
	}

	// TLS version range. The Octavia tls_versions list is collapsed to a
	// min..max range encoded as the low-byte 0x03xx ordinal (TLSv1.2⇒0x03, TLSv1.3⇒0x04);
	// 0 ⇒ today's TLS1.2..TLS1.3 (the C helper defaults when 0).
	tlsMin, tlsMax := tlsVersionsToRange(w.TlsVersions)
	dat.tls_version_min = C.uint8_t(tlsMin)
	dat.tls_version_max = C.uint8_t(tlsMax)

	// inline OpenSSL cipher string → tls_ciphers[256] (TLS1.2 + TLS1.3).
	if w.TlsCiphers != "" {
		cCiphers := C.CString(w.TlsCiphers)
		defer C.free(unsafe.Pointer(cCiphers))
		C.strncpy(&dat.tls_ciphers[0], cCiphers, 255)
	}

	// HSTS scalars. hsts_max_age==0 ⇒ no injection (default-off).
	dat.hsts_max_age = C.uint32_t(w.HstsMaxAge)
	if w.HstsIncludeSubdomains {
		dat.hsts_include_subdomains = 1
	}
	if w.HstsPreload {
		dat.hsts_preload = 1
	}

	// backend re-encryption material referenced by certId. The registry
	// resolves these to managed-dir paths at backend SSL_CTX build time. Empty ⇒ today's behaviour.
	if w.BackendCaCertId != "" {
		cID := C.CString(w.BackendCaCertId)
		defer C.free(unsafe.Pointer(cID))
		C.strncpy(&dat.backend_ca_cert_id[0], cID, 63)
	}
	if w.BackendClientCertId != "" {
		cID := C.CString(w.BackendClientCertId)
		defer C.free(unsafe.Pointer(cID))
		C.strncpy(&dat.backend_client_cert_id[0], cID, 63)
	}

	// P/D disaggregation configuration
	if w.PDDisaggMode {
		dat.pd_disagg_mode = 1
		dat.ai_gw_mode = 1
	}

	// P/D cache-aware routing configuration (US-PD801)
	if w.PDCacheAwareMode {
		dat.pd_cache_aware_mode = 1
	}
	dat.pd_session_ttl_sec = C.uint32_t(w.PDSessionTTLSec)
	cacheThreshold := w.PDCacheThreshold
	if cacheThreshold == 0 {
		cacheThreshold = 20
	}
	balanceThreshold := w.PDBalanceAbsThreshold
	if balanceThreshold == 0 {
		balanceThreshold = 3
	}
	dat.pd_cache_threshold = C.uint8_t(cacheThreshold)
	dat.pd_balance_abs_threshold = C.uint8_t(balanceThreshold)

	// Per-endpoint circuit breaker (opt-in per rule)
	if w.CbEnable {
		dat.cb_enable = 1
	}

	// KV-Cache Exact Routing (: wire KV config through dp_proxy_tacts)
	dat.kv_exact_mode = C.uint8_t(w.KvExactMode)
	if w.KvHashAlgo == "xxhash_cbor" {
		dat.kv_hash_algo = 1
	} else if w.KvHashAlgo == "sha256_sglang" {
		dat.kv_hash_algo = 2
	} else if w.KvHashAlgo == "blockhash_trtllm" {
		// KV_HASH_TRTLLM (3) — the C arm ships with the conditional Option-B
		// phase; unreachable until then because the trtllm feature guard
		// rejects kvExactMode>0 at config time.
		dat.kv_hash_algo = 3
	} else if w.KvHashAlgo == "" && w.KvEngineType == "sglang" {
		// engine drives the hash-algo default — sglang with
		// kvHashAlgo unset defaults to KV_HASH_SHA256_SGLANG (2). An explicit
		// kvHashAlgo always wins (the branches above); vllm/absent keeps 0.
		dat.kv_hash_algo = 2
	} else if w.KvHashAlgo == "" && w.KvEngineType == "trtllm" {
		dat.kv_hash_algo = 3
	}
	dat.kv_zmq_port = C.uint16_t(w.KvZmqPort)
	dat.kv_block_size = C.uint32_t(w.KvBlockSize)
	dat.kv_warmup_sec = C.uint32_t(w.KvWarmupSec)
	// per-rule engine + SGLang DP rank count. "vllm"/"" ⇒ 0
	// (byte-identical default); rank 0 ⇒ 1 (PDCacheThreshold defaulting idiom).
	// "trtllm" ⇒ 2 matches PD_ENGINE_TRTLLM in the C dialect resolver, whose
	// table entry is a vLLM placeholder until the dedicated dialect lands —
	// safe because the feature guard keeps trtllm off every P/D path.
	if w.KvEngineType == "sglang" {
		dat.kv_engine_type = 1
	} else if w.KvEngineType == "trtllm" {
		dat.kv_engine_type = 2
	}
	rankCount := w.KvDpRankCount
	if rankCount == 0 {
		rankCount = 1
	}
	dat.kv_dp_rank_count = C.uint8_t(rankCount)
	// SGLang P/D bootstrap port. 0 rides through unchanged — the 8998 default
	// is applied at proxy_add (pd_cache_threshold defaulting idiom lives C-side
	// here so the wire value stays the operator's literal config).
	dat.pd_bootstrap_port = C.uint16_t(w.PDBootstrapPort)

	// ai_gw_mode also derived from SSE mode (for non-P/D AI Gateway services)
	if w.SSEMode && dat.ai_gw_mode == 0 {
		dat.ai_gw_mode = 1
	}

	if w.Work == DpCreate {
		// Set mTLS frontend config directly in dat (when mTLS build tag active)
		DpLBRuleSetMTLS(dat, w)

		ret := C.llb_add_map_elem(C.LL_DP_NAT_MAP,
			unsafe.Pointer(key),
			unsafe.Pointer(dat))

		// [CP-DEBUG] Stage 5: eBPF map write result
		if ret != 0 {
			tk.LogIt(tk.LogWarning, "[CP-DEBUG] DpLBRuleMod: VIP=%s mark=%v NAT map write FAILED ret=%d\n",
				w.ServiceIP.String(), key.mark, ret)
			return EbpfErrTmacAdd
		}
		tk.LogIt(tk.LogInfo, "[CP-DEBUG] DpLBRuleMod: VIP=%s mark=%v NAT map write OK eps=%d\n",
			w.ServiceIP.String(), key.mark, len(w.endPoints))

		// GPU-Aware: Populate endpoint_to_gpu_index_map for GPU-aware selection
		// This is CRITICAL - without this mapping, GPU selection algorithm fails with "not mapped to GPU worker"
		if w.EpSel == EpGPUAware && mh.dp != nil {
			for idx, ep := range w.endPoints {
				// Get or assign GPU worker index for this endpoint
				gpuIdx, err := mh.dp.DpHooks.GetOrAssignEndpointIndex(ep.XIP.String())
				if err != nil {
					tk.LogIt(tk.LogError, "[DP] GPU-Aware: Failed to assign index for endpoint %s: %v\n",
						ep.XIP.String(), err)
					continue
				}

				// Map endpoint IP:port → GPU worker index in eBPF
				err = mh.dp.DpHooks.UpdateEndpointToGPUIndexMap(ep.XIP, ep.XPort, gpuIdx)
				if err != nil {
					tk.LogIt(tk.LogError, "[DP] GPU-Aware: Failed to map endpoint %s:%d → GPU %d: %v\n",
						ep.XIP.String(), ep.XPort, gpuIdx, err)
				} else {
					tk.LogIt(tk.LogInfo, "[DP] GPU-Aware: Service EP[%d] (%s:%d) → GPU global index %d\n",
						idx, ep.XIP.String(), ep.XPort, gpuIdx)
				}
			}
		}

		return 0
	} else if w.Work == DpRemove {
		// GPU-Aware: Clean up endpoint mappings when rule is deleted
		if w.EpSel == EpGPUAware && mh.dp != nil {
			for _, ep := range w.endPoints {
				_ = mh.dp.DpHooks.DeleteEndpointFromGPUIndexMap(ep.XIP, ep.XPort)
			}
		}

		// Clean up mTLS configuration when rule is deleted
		if w.NatType == DpFullProxy {
			DpProxyCleanupMTLS(w.ServiceIP, w.L4Port, w.Proto)
		}

		C.llb_del_map_elem_wval(C.LL_DP_NAT_MAP,
			unsafe.Pointer(key),
			unsafe.Pointer(dat))
		return 0
	}

	return EbpfErrWqUnk
}

// DpLBRuleAdd - routine to work on a ebpf lb add request
func (e *DpEbpfH) DpLBRuleAdd(w *LBDpWorkQ) int {
	ec := DpLBRuleMod(w)
	if ec != 0 {
		*w.Status = DpCreateErr
	} else {
		*w.Status = 0
	}
	return ec
}

// DpLBRuleDel - routine to work on a ebpf lb delete request
func (e *DpEbpfH) DpLBRuleDel(w *LBDpWorkQ) int {
	return DpLBRuleMod(w)
}

// DpLBCtFlush - cleanup CT/FC entries for a specific LB service tuple
func (e *DpEbpfH) DpLBCtFlush(w *LBCtDpWorkQ) int {
	if w == nil || w.ServiceIP == nil || w.Proto == 0 {
		return -1
	}

	key := new(natKey)
	key.daddr = [4]C.uint{0, 0, 0, 0}
	if tk.IsNetIPv4(w.ServiceIP.String()) {
		key.daddr[0] = C.uint(tk.IPtonl(w.ServiceIP))
		key.v6 = 0
	} else {
		convNetIP2DPv6Addr(unsafe.Pointer(&key.daddr[0]), w.ServiceIP)
		key.v6 = 1
	}

	key.dport = C.ushort(tk.Htons(w.L4Port))
	key.l4proto = C.ushort(w.Proto)
	key.zone = C.ushort(w.ZoneNum)

	rid := w.RuleID
	if rid == 0 {
		rid = w.BlockNum
	}

	encodedRid := rid
	if w.FlushMode == CtFlushRidZeroOnly {
		encodedRid = rid | (1 << 31)
	}

	ret := int(C.llb_flush_ct_by_nat(unsafe.Pointer(key), C.uint(encodedRid)))
	if ret < 0 {
		C.llb_age_map_entries(C.LL_DP_CT_MAP)
		C.llb_age_map_entries(C.LL_DP_FCV4_MAP)
		return ret
	}

	tk.LogIt(tk.LogDebug, "[DP] LB CT flush tuple %s:%d proto=%d zone=%d rid=%d aged=%d\n",
		w.ServiceIP.String(), w.L4Port, w.Proto, w.ZoneNum, rid, ret)

	return 0
}

// DpLBEndpointHealthUpdate - P2: Lightweight endpoint health state update
// This function updates ONLY the inactive flag for FullProxy sockproxy rules
// Parameters:
//   - svcIP: Service VIP
//   - svcPort: Service port
//   - proto: Protocol (TCP=6, UDP=17)
//   - epIndex: Endpoint index (0-based)
//   - inactive: true = mark inactive, false = mark active
//
// Returns: 0 on success, -1 on error
func (e *DpEbpfH) DpLBEndpointHealthUpdate(svcIP net.IP, svcPort uint16, proto uint8, epIndex int, inactive bool) int {
	// Build proxy key for sockproxy lookup
	var proxyKey C.struct_proxy_ent

	// Convert service IP to uint32 (IPv4 only for now)
	if svcIP.To4() != nil {
		proxyKey.xip = C.uint(tk.IPtonl(svcIP))
	} else {
		tk.LogIt(tk.LogError, "[DP] P2: IPv6 not yet supported for health updates\n")
		return -1
	}

	proxyKey.xport = C.ushort(tk.Htons(svcPort))
	proxyKey.protocol = C.uchar(proto)

	// Convert inactive bool to C uint8_t
	var inact C.uchar
	if inactive {
		inact = 1
	} else {
		inact = 0
	}

	// Call sockproxy C function directly
	ret := C.proxy_update_ep_health(&proxyKey, C.int(epIndex), inact)
	if ret != 0 {
		tk.LogIt(tk.LogError, "[DP] P2: Failed to update sockproxy ep health - VIP=%v, port=%v, ep=%d\n",
			svcIP, svcPort, epIndex)
		return -1
	}

	tk.LogIt(tk.LogDebug, "[DP] P2: Sockproxy EP health updated - VIP=%v, port=%v, ep=%d, inactive=%v\n",
		svcIP, svcPort, epIndex, inactive)

	return 0
}

// DpLBEndpointHostStateUpdate - P2 GPU-Aware: Update endpoint state based on GPU hostState
// This function updates endpoint inactive flag for FullProxy sockproxy rules based on
// external GPU monitoring state (red/yellow/green). Reuses P2 health update infrastructure.
// Parameters:
//   - svcIP: Service VIP
//   - svcPort: Service port
//   - proto: Protocol (TCP=6, UDP=17)
//   - epIP: Endpoint IP address (to find endpoint index)
//   - hostState: GPU state ("red"|"yellow"|"green")
//
// Returns: 0 on success, -1 on error
func (e *DpEbpfH) DpLBEndpointHostStateUpdate(svcIP net.IP, svcPort uint16, proto uint8, epIP net.IP, hostState string) int {
	// Build proxy key for sockproxy lookup
	var proxyKey C.struct_proxy_ent

	// Convert service IP to uint32 (IPv4 only for now)
	if svcIP.To4() != nil {
		proxyKey.xip = C.uint(tk.IPtonl(svcIP))
	} else {
		tk.LogIt(tk.LogError, "[DP] P2 GPU: IPv6 not yet supported for GPU state updates\n")
		return -1
	}

	proxyKey.xport = C.ushort(tk.Htons(svcPort))
	proxyKey.protocol = C.uchar(proto)

	// Map hostState to inactive flag
	// RED = inactive, YELLOW = inactive (conservative), GREEN = active
	var inact C.uchar
	switch hostState {
	case "red":
		inact = 1 // Red = fully inactive
	case "yellow":
		inact = 1 // Yellow = inactive (conservative approach)
	case "green":
		inact = 0 // Green = active
	default:
		tk.LogIt(tk.LogError, "[DP] P2 GPU: Invalid hostState: %s (expected red/yellow/green)\n", hostState)
		return -1
	}

	// Find endpoint index by matching IP
	// Note: This requires calling a C helper to lookup endpoint by IP
	// For now, we'll need to search through the endpoints
	epIP4 := epIP.To4()
	if epIP4 == nil {
		tk.LogIt(tk.LogError, "[DP] P2 GPU: IPv6 endpoint not yet supported\n")
		return -1
	}

	epIPUint := C.uint(tk.IPtonl(epIP))

	// Call C helper to find endpoint index and update state
	ret := C.proxy_update_ep_health_by_ip(&proxyKey, epIPUint, inact)
	if ret < 0 {
		tk.LogIt(tk.LogError, "[DP] P2 GPU: Failed to update sockproxy GPU state - VIP=%v, port=%v, epIP=%v, state=%s\n",
			svcIP, svcPort, epIP, hostState)
		return -1
	}

	tk.LogIt(tk.LogInfo, "[DP] P2 GPU: Sockproxy GPU state updated - VIP=%v, port=%v, epIP=%v, state=%s → inactive=%v\n",
		svcIP, svcPort, epIP, hostState, inact == 1)

	return 0
}

// DpLBSetDrainPolicy - P2 : Configure draining policy for FullProxy service
// This function sets the draining behavior when endpoints are marked inactive
// Parameters:
//   - svcIP: Service VIP
//   - svcPort: Service port
//   - proto: Protocol (TCP=6, UDP=17)
//   - policy: Draining policy ("graceful", "timed", or "immediate")
//   - timeoutSec: Timeout in seconds for timed draining (ignored for other policies)
//
// Returns: 0 on success, -1 on error
func (e *DpEbpfH) DpLBSetDrainPolicy(svcIP net.IP, svcPort uint16, proto uint8, policy string, timeoutSec uint32) int {
	// Build proxy key for sockproxy lookup
	var proxyKey C.struct_proxy_ent

	// Convert service IP to uint32 (IPv4 only for now)
	if svcIP.To4() != nil {
		proxyKey.xip = C.uint(tk.IPtonl(svcIP))
	} else {
		tk.LogIt(tk.LogError, "[DP] P2 : IPv6 not yet supported for drain policy\n")
		return -1
	}

	proxyKey.xport = C.ushort(tk.Htons(svcPort))
	proxyKey.protocol = C.uchar(proto)

	// Convert policy string to C enum
	var policyEnum C.uint
	switch policy {
	case "graceful":
		policyEnum = 0 // DRAIN_POLICY_GRACEFUL
	case "timed":
		policyEnum = 1 // DRAIN_POLICY_TIMED
	case "immediate":
		policyEnum = 2 // DRAIN_POLICY_IMMEDIATE
	default:
		tk.LogIt(tk.LogError, "[DP] P2 : Invalid drain policy: %s\n", policy)
		return -1
	}

	// Call sockproxy C function
	ret := C.proxy_set_drain_policy(&proxyKey, policyEnum, C.uint(timeoutSec))
	if ret != 0 {
		tk.LogIt(tk.LogError, "[DP] P2 : Failed to set drain policy - VIP=%v, port=%v\n",
			svcIP, svcPort)
		return -1
	}

	tk.LogIt(tk.LogInfo, "[DP] P2 : Drain policy set - VIP=%v, port=%v, policy=%s, timeout=%ds\n",
		svcIP, svcPort, policy, timeoutSec)

	return 0
}

// DpLBSetCircuitBreaker - P2.3: Configure circuit breaker for FullProxy service
// This function enables/disables circuit breaker and sets failure thresholds
// Parameters:
//   - svcIP: Service VIP
//   - svcPort: Service port
//   - proto: Protocol (TCP=6, UDP=17)
//   - enabled: true = enable circuit breaker, false = disable
//   - failureThreshold: Number of consecutive failures before opening circuit (0 = use default 5)
//   - openTimeoutSec: Timeout in seconds before transitioning to HALF_OPEN (0 = use default 30)
//
// Returns: 0 on success, -1 on error
func (e *DpEbpfH) DpLBSetCircuitBreaker(svcIP net.IP, svcPort uint16, proto uint8,
	enabled bool, failureThreshold uint32, openTimeoutSec uint32) int {
	// Build proxy key for sockproxy lookup
	var proxyKey C.struct_proxy_ent

	// Convert service IP to uint32 (IPv4 only for now)
	if svcIP.To4() != nil {
		proxyKey.xip = C.uint(tk.IPtonl(svcIP))
	} else {
		tk.LogIt(tk.LogError, "[DP] P2.3: IPv6 not yet supported for circuit breaker\n")
		return -1
	}

	proxyKey.xport = C.ushort(tk.Htons(svcPort))
	proxyKey.protocol = C.uchar(proto)

	// Convert enabled bool to C uint8_t
	var enabledVal C.uchar
	if enabled {
		enabledVal = 1
	} else {
		enabledVal = 0
	}

	// Call sockproxy C function
	ret := C.proxy_set_circuit_breaker(&proxyKey, enabledVal,
		C.uint(failureThreshold), C.uint(openTimeoutSec))
	if ret != 0 {
		tk.LogIt(tk.LogError, "[DP] P2.3: Failed to set circuit breaker - VIP=%v, port=%v\n",
			svcIP, svcPort)
		return -1
	}

	tk.LogIt(tk.LogInfo, "[DP] P2.3: Circuit breaker configured - VIP=%v, port=%v, enabled=%v, threshold=%d, timeout=%ds\n",
		svcIP, svcPort, enabled, failureThreshold, openTimeoutSec)

	return 0
}

// getNatEpMapFd - Get file descriptor for NAT endpoint map
func (e *DpEbpfH) getNatEpMapFd() int {
	// Get map file descriptor using the same pattern as existing code
	return int(C.llb_map2fd(C.LL_DP_NAT_EP_MAP))
}

// getNatEpaByMark - Get NAT endpoint actions by mark
func (e *DpEbpfH) getNatEpaByMark(mark int) unsafe.Pointer {
	fd := e.getNatEpMapFd()
	if fd < 0 {
		return nil
	}

	// Allocate memory for the EPA structure
	epa := (*C.struct_dp_nat_epacts)(C.malloc(C.sizeof_struct_dp_nat_epacts))
	if epa == nil {
		return nil
	}

	key := C.uint(mark)
	ret := C.bpf_map_lookup_elem(C.int(fd), unsafe.Pointer(&key), unsafe.Pointer(epa))
	if ret != 0 {
		C.free(unsafe.Pointer(epa))
		return nil
	}

	return unsafe.Pointer(epa)
}

func updateEpaEntry(mark int, epa *C.struct_dp_nat_epacts) int {
	key := C.uint(mark)
	ret := C.llb_add_map_elem(C.LL_DP_NAT_EP_MAP, unsafe.Pointer(&key), unsafe.Pointer(epa))
	return int(ret)
}

// DpLBSessionReset - Reset session counts for load balancer endpoints
func (e *DpEbpfH) DpLBSessionReset(w *LBSessionResetWorkQ) int {
	fd := e.getNatEpMapFd()
	if fd < 0 {
		return -1
	}

	mark := w.Mark
	epaPtr := e.getNatEpaByMark(mark)
	if epaPtr == nil {
		return -1
	}
	epa := (*C.struct_dp_nat_epacts)(epaPtr)

	// Ensure memory cleanup
	defer C.free(epaPtr)

	var result int
	switch w.ResetType {
	case ResetAll:
		result = resetAllSessions(epa, mark)
	case ResetSpecific:
		if w.EndpointIdx < 0 {
			return -1
		}
		result = resetSpecificSession(epa, mark, w.EndpointIdx)
	case ResetSelective:
		if w.EndpointMask == nil {
			return -1
		}
		result = resetSelectiveSessions(epa, mark, w.EndpointMask)
	default:
		return -1
	}

	return result
}

// Reset all endpoint session counts
func resetAllSessions(epa *C.struct_dp_nat_epacts, mark int) int {
	// Reset all session counts to 0
	for i := 0; i < int(C.LLB_MAX_NXFRMS); i++ {
		epa.active_sess[i] = 0
	}
	return updateEpaEntry(mark, epa)
}

// Reset specific endpoint session count
func resetSpecificSession(epa *C.struct_dp_nat_epacts, mark int, endpointIdx int) int {
	if endpointIdx >= int(C.LLB_MAX_NXFRMS) {
		return -1
	}
	// Reset specific endpoint session count to 0
	epa.active_sess[endpointIdx] = 0
	return updateEpaEntry(mark, epa)
}

// Reset only specified endpoints, preserve others
func resetSelectiveSessions(epa *C.struct_dp_nat_epacts, mark int,
	endpointMask []bool) int {

	// First, preserve current session counts for unchanged endpoints
	savedCounts := make([]uint16, int(C.LLB_MAX_NXFRMS))
	for i := 0; i < int(C.LLB_MAX_NXFRMS); i++ {
		savedCounts[i] = uint16(epa.active_sess[i])
	}

	// Apply selective reset based on mask (true = reset, false = preserve)
	for i := 0; i < int(C.LLB_MAX_NXFRMS) && i < len(endpointMask); i++ {
		if endpointMask[i] {
			// Reset this endpoint
			epa.active_sess[i] = 0
		} else {
			// Preserve this endpoint with current session count
			epa.active_sess[i] = C.ushort(savedCounts[i])
		}
	}

	return updateEpaEntry(mark, epa)
}

// DpStat - routine to work on a ebpf map statistics request
func (e *DpEbpfH) DpStat(w *StatDpWorkQ) int {
	var packets, bytes, dropPackets uint64
	var tbl []int
	var polTbl []int
	sync := 0
	switch {
	case w.Name == MapNameNat:
		tbl = append(tbl, int(C.LL_DP_NAT_STATS_MAP))
		sync = 1
	case w.Name == MapNameBD:
		tbl = append(tbl, int(C.LL_DP_BD_STATS_MAP), int(C.LL_DP_TX_BD_STATS_MAP))
	case w.Name == MapNameRxBD:
		tbl = append(tbl, int(C.LL_DP_BD_STATS_MAP))
	case w.Name == MapNameTxBD:
		tbl = append(tbl, int(C.LL_DP_TX_BD_STATS_MAP))
	case w.Name == MapNameRt4:
		tbl = append(tbl, int(C.LL_DP_RTV4_MAP))
	case w.Name == MapNameULCL:
		tbl = append(tbl, int(C.LL_DP_SESS4_MAP))
	case w.Name == MapNameIpol:
		polTbl = append(polTbl, int(C.LL_DP_POL_MAP))
	case w.Name == MapNameFw4:
		tbl = append(tbl, int(C.LL_DP_FW4_MAP))
	default:
		return EbpfErrWqUnk
	}

	if w.Work == DpStatsGet || w.Work == DpStatsGetImm {
		var b C.longlong
		var p C.longlong

		packets = 0
		bytes = 0
		dropPackets = 0

		if w.Work == DpStatsGetImm {
			sync = 1
		}

		for _, t := range tbl {

			ret := C.llb_fetch_map_stats_cached(C.int(t), C.uint(w.Mark), C.int(sync),
				(unsafe.Pointer(&b)), unsafe.Pointer(&p))
			if ret != 0 {
				return EbpfErrTmacAdd
			}

			packets += uint64(p)
			bytes += uint64(b)
		}

		for _, t := range polTbl {

			ret := C.llb_fetch_pol_map_stats(C.int(t), C.uint(w.Mark), (unsafe.Pointer(&p)), unsafe.Pointer(&b))
			if ret != 0 {
				return EbpfErrTmacAdd
			}

			packets += uint64(p)
			dropPackets += uint64(b)
		}

		if packets != 0 || bytes != 0 || dropPackets != 0 {
			if w.Packets != nil {
				*w.Packets = uint64(packets)
			}
			if w.Bytes != nil {
				*w.Bytes = uint64(bytes)
			}
			if w.DropPackets != nil {
				*w.DropPackets = uint64(dropPackets)
			}
		}
	} else if w.Work == DpStatsClr {
		for _, t := range tbl {
			C.llb_clear_map_stats(C.int(t), C.uint(w.Mark))
		}
	}

	return 0
}

func (ct *DpCtInfo) convDPCt2GoObjFixup(ctKey *C.struct_dp_ct_key, ctDat *C.struct_dp_ct_dat, fixup bool) *DpCtInfo {
	if ctKey.v6 == 0 {
		ct.DIP = tk.NltoIP(uint32(ctKey.daddr[0]))
		ct.SIP = tk.NltoIP(uint32(ctKey.saddr[0]))
	} else {
		ct.SIP = convDPv6Addr2NetIP(unsafe.Pointer(&ctKey.saddr[0]))
		ct.DIP = convDPv6Addr2NetIP(unsafe.Pointer(&ctKey.daddr[0]))
	}
	ct.Dport = tk.Ntohs(uint16(ctKey.dport))
	ct.Sport = tk.Ntohs(uint16(ctKey.sport))

	p := uint8(ctKey.l4proto)
	switch {
	case p == 1 || p == 58:
		if p == 1 {
			ct.Proto = "icmp"
		} else {
			ct.Proto = "icmp6"
		}
	case p == 6:
		ct.Proto = "tcp"
	case p == 17:
		ct.Proto = "udp"
	case p == 132:
		ct.Proto = "sctp"
	default:
		ct.Proto = fmt.Sprintf("%d", p)
	}

	ct.IdType = uint32(ctKey._type)
	ct.Ident = uint32(ctKey.ident)

	if ctDat == nil {
		ct.CAct = "n/a"
		ct.CState = "closed"
		return ct
	}

	switch {
	case p == 1 || p == 58:
		if p == 1 {
			ct.Proto = "icmp"
		} else {
			ct.Proto = "icmp6"
		}
		i := (*C.ct_icmp_pinf_t)(unsafe.Pointer(&ctDat.pi))
		switch {
		case i.state&C.CT_ICMP_DUNR != 0:
			ct.CState = "dest-unr"
		case i.state&C.CT_ICMP_TTL != 0:
			ct.CState = "ttl-exp"
		case i.state&C.CT_ICMP_RDR != 0:
			ct.CState = "icmp-redir"
		case i.state == C.CT_ICMP_CLOSED:
			ct.CState = "closed"
		case i.state == C.CT_ICMP_REQS:
			ct.CState = "req-sent"
		case i.state == C.CT_ICMP_REPS:
			ct.CState = "bidir"
		}
	case p == 6:
		ct.Proto = "tcp"
		t := (*C.ct_tcp_pinf_t)(unsafe.Pointer(&ctDat.pi))
		switch {
		case t.state == C.CT_TCP_CLOSED:
			ct.CState = "closed"
		case t.state == C.CT_TCP_SS:
			ct.CState = "sync-sent"
		case t.state == C.CT_TCP_SA:
			ct.CState = "sync-ack"
		case t.state == C.CT_TCP_EST:
			ct.CState = "est"
		case t.state == C.CT_TCP_PEST:
			ct.CState = "est"
		case t.state == C.CT_TCP_ERR:
			ct.CState = "h/e"
		case t.state == C.CT_TCP_CW:
			ct.CState = "closed-wait"
		default:
			ct.CState = "fini"
		}
	case p == 17:
		ct.Proto = "udp"
		u := (*C.ct_udp_pinf_t)(unsafe.Pointer(&ctDat.pi))
		switch {
		case u.state == C.CT_UDP_CNI:
			ct.CState = "closed"
		case u.state == C.CT_UDP_UEST:
			ct.CState = "udp-uni"
		case u.state == C.CT_UDP_EST:
			ct.CState = "udp-est"
		default:
			ct.CState = "unk"
		}
	case p == 132:
		ct.Proto = "sctp"
		s := (*C.ct_sctp_pinf_t)(unsafe.Pointer(&ctDat.pi))
		switch {
		case s.state == C.CT_SCTP_PRE_EST:
			ct.CState = "pre-est"
		case s.state == C.CT_SCTP_EST:
			ct.CState = "est"
		case s.state == C.CT_SCTP_CLOSED:
			ct.CState = "closed"
		case s.state == C.CT_SCTP_ERR:
			ct.CState = "err"
		case s.state == C.CT_SCTP_INIT:
			ct.CState = "init"
		case s.state == C.CT_SCTP_INITA:
			ct.CState = "init-ack"
		case s.state == C.CT_SCTP_COOKIE:
			ct.CState = "cookie-echo"
		case s.state == C.CT_SCTP_COOKIEA:
			ct.CState = "cookie-echo-resp"
		case s.state == C.CT_SCTP_SHUT:
			ct.CState = "shut"
		case s.state == C.CT_SCTP_SHUTA:
			ct.CState = "shut-ack"
		case s.state == C.CT_SCTP_SHUTC:
			ct.CState = "shut-complete"
		case s.state == C.CT_SCTP_ABRT:
			ct.CState = "abort"
		default:
			ct.CState = "unk"
		}
	default:
		ct.Proto = fmt.Sprintf("%d", p)
	}

	ct.Packets = uint64(ctDat.pb.packets)
	ct.Bytes = uint64(ctDat.pb.bytes)

	if ctDat.xi.nat_flags == C.LLB_NAT_DST ||
		ctDat.xi.nat_flags == C.LLB_NAT_SRC ||
		ctDat.xi.nat_flags == C.LLB_NAT_HDST ||
		ctDat.xi.nat_flags == C.LLB_NAT_HSRC {
		var xip net.IP

		if ctDat.xi.nv6 == 0 {
			xip = append(xip, uint8(ctDat.xi.nat_xip[0]&0xff))
			xip = append(xip, uint8(ctDat.xi.nat_xip[0]>>8&0xff))
			xip = append(xip, uint8(ctDat.xi.nat_xip[0]>>16&0xff))
			xip = append(xip, uint8(ctDat.xi.nat_xip[0]>>24&0xff))
		} else {
			xip = convDPv6Addr2NetIP(unsafe.Pointer(&ctDat.xi.nat_xip[0]))
		}

		port := tk.Ntohs(uint16(ctDat.xi.nat_xport))

		// populate NAT target fields for DOCA shadow offload
		ct.NatIP = xip
		ct.NatPort = port
		switch ctDat.xi.nat_flags {
		case C.LLB_NAT_DST:
			ct.NatFlags = 1
		case C.LLB_NAT_SRC:
			ct.NatFlags = 2
		case C.LLB_NAT_HDST:
			ct.NatFlags = 3
		case C.LLB_NAT_HSRC:
			ct.NatFlags = 4
		}

		// Extract DSR flag for DOCA graceful degradation
		if ctDat.xi.dsr != 0 {
			ct.NatDsr = true
		}

		if fixup {
			if ctDat.xi.osp != 0 {
				aSport := tk.Ntohs(uint16(ctDat.xi.osp))
				aDport := tk.Ntohs(uint16(ctDat.xi.odp))
				ct.CState = fmt.Sprintf("frag:%d->%d", aSport, aDport)
			}
		}

		if ctDat.xi.nat_flags == C.LLB_NAT_DST || ctDat.xi.nat_flags == C.LLB_NAT_HDST {
			if ctDat.xi.nat_rip[0] == 0 && ctDat.xi.nat_rip[1] == 0 &&
				ctDat.xi.nat_rip[2] == 0 && ctDat.xi.nat_rip[3] == 0 {
				nmode := ""
				if ctDat.xi.dsr != 0 {
					nmode = "ddsr"
				} else {
					if ctDat.xi.nat_flags == C.LLB_NAT_HDST {
						nmode = "hdnat"
					} else {
						nmode = "dnat"
					}
				}
				ct.CAct = fmt.Sprintf("%s-%s:%d:w%d", nmode, xip.String(), port, ctDat.xi.wprio)
			} else {
				var rip net.IP

				if ctDat.xi.nv6 == 0 {
					rip = append(rip, uint8(ctDat.xi.nat_rip[0]&0xff))
					rip = append(rip, uint8(ctDat.xi.nat_rip[0]>>8&0xff))
					rip = append(rip, uint8(ctDat.xi.nat_rip[0]>>16&0xff))
					rip = append(rip, uint8(ctDat.xi.nat_rip[0]>>24&0xff))
				} else {
					rip = convDPv6Addr2NetIP(unsafe.Pointer(&ctDat.xi.nat_rip[0]))
				}
				ct.NatRIP = rip // store reverse IP for One-Arm DOCA offload
				ct.CAct = fmt.Sprintf("fdnat-%s,%s:%d:w%d", rip.String(), xip.String(), port, ctDat.xi.wprio)
			}
		} else if ctDat.xi.nat_flags == C.LLB_NAT_SRC || ctDat.xi.nat_flags == C.LLB_NAT_HSRC {
			if ctDat.xi.nat_rip[0] == 0 && ctDat.xi.nat_rip[1] == 0 &&
				ctDat.xi.nat_rip[2] == 0 && ctDat.xi.nat_rip[3] == 0 {
				nmode := ""
				if ctDat.xi.dsr != 0 {
					nmode = "sdsr"
				} else {
					if ctDat.xi.nat_flags == C.LLB_NAT_HSRC {
						nmode = "hsnat"
					} else {
						nmode = "snat"
					}
				}
				ct.CAct = fmt.Sprintf("%s-%s:%d:w%d", nmode, xip.String(), port, ctDat.xi.wprio)
			} else {
				var rip net.IP

				if ctDat.xi.nv6 == 0 {
					rip = append(rip, uint8(ctDat.xi.nat_rip[0]&0xff))
					rip = append(rip, uint8(ctDat.xi.nat_rip[0]>>8&0xff))
					rip = append(rip, uint8(ctDat.xi.nat_rip[0]>>16&0xff))
					rip = append(rip, uint8(ctDat.xi.nat_rip[0]>>24&0xff))
				} else {
					rip = convDPv6Addr2NetIP(unsafe.Pointer(&ctDat.xi.nat_rip[0]))
				}
				ct.NatRIP = rip // store reverse IP for One-Arm DOCA offload
				ct.CAct = fmt.Sprintf("fsnat-%s,%s:%d:w%d", xip.String(), rip.String(), port, ctDat.xi.wprio)
			}
		}
	}

	return ct
}

func (ct *DpCtInfo) convDPCt2GoObj(ctKey *C.struct_dp_ct_key, ctDat *C.struct_dp_ct_dat) *DpCtInfo {
	return ct.convDPCt2GoObjFixup(ctKey, ctDat, false)
}

func (ct *DpCtInfo) convDPCtKey2GoObj(ctKey *C.struct_dp_ct_key) *DpCtInfo {
	if ctKey.v6 == 0 {
		ct.DIP = tk.NltoIP(uint32(ctKey.daddr[0]))
		ct.SIP = tk.NltoIP(uint32(ctKey.saddr[0]))
	} else {
		ct.SIP = convDPv6Addr2NetIP(unsafe.Pointer(&ctKey.saddr[0]))
		ct.DIP = convDPv6Addr2NetIP(unsafe.Pointer(&ctKey.daddr[0]))
	}
	ct.Dport = tk.Ntohs(uint16(ctKey.dport))
	ct.Sport = tk.Ntohs(uint16(ctKey.sport))

	p := uint8(ctKey.l4proto)
	switch {
	case p == 1 || p == 58:
		if p == 1 {
			ct.Proto = "icmp"
		} else {
			ct.Proto = "icmp6"
		}
	case p == 6:
		ct.Proto = "tcp"
	case p == 17:
		ct.Proto = "udp"
	case p == 132:
		ct.Proto = "sctp"
	default:
		ct.Proto = fmt.Sprintf("%d", p)
	}

	return ct
}

func (ct *DpCtInfo) convDPCtProxy2ActString(ctKey *C.struct_dp_ct_key) {
	var DIP net.IP
	var SIP net.IP

	if ctKey.v6 == 0 {
		DIP = tk.NltoIP(uint32(ctKey.daddr[0]))
		SIP = tk.NltoIP(uint32(ctKey.saddr[0]))
	} else {
		SIP = convDPv6Addr2NetIP(unsafe.Pointer(&ctKey.saddr[0]))
		DIP = convDPv6Addr2NetIP(unsafe.Pointer(&ctKey.daddr[0]))
	}
	Dport := tk.Ntohs(uint16(ctKey.dport))
	Sport := tk.Ntohs(uint16(ctKey.sport))
	Proto := ""

	p := uint8(ctKey.l4proto)
	switch {
	case p == 1 || p == 58:
		if p == 1 {
			Proto = "icmp"
		} else {
			Proto = "icmp6"
		}
	case p == 6:
		Proto = "tcp"
	case p == 17:
		Proto = "udp"
	case p == 132:
		Proto = "sctp"
	default:
		Proto = fmt.Sprintf("%d", p)
	}

	ct.CAct = fmt.Sprintf("fp|%s:%d->%s:%d|%s", SIP.String(), Sport, DIP.String(), Dport, Proto)
}

//export goProxyEntCollector
func goProxyEntCollector(e *proxtCT) {

	proxyCt := new(DpCtInfo)
	proxyCt.convDPCtKey2GoObj(&e.ct_in)
	proxyCt.convDPCtProxy2ActString(&e.ct_out)
	proxyCt.Bytes = uint64(e.st_out.bytes)
	proxyCt.Bytes += uint64(e.st_in.bytes)

	proxyCt.Packets = uint64(e.st_out.packets)
	proxyCt.Packets += uint64(e.st_in.packets)
	proxyCt.RuleID = uint32(e.rid)
	proxyCt.CState = "est"
	// Proxy CT entries carry a pre-summed both-direction byte count (st_in + st_out
	// above), so there is no single per-direction figure to attribute. Mark the
	// direction as unknown (1) so the /stats rollup does not mislabel these as
	// CT_DIR_IN (0) and skew bytes_in.
	proxyCt.Dir = -1

	proxyCtInfo = append(proxyCtInfo, proxyCt)
}

// DpTableGet - routine to work on a ebpf map get request
func (e *DpEbpfH) DpTableGet(w *TableDpWorkQ) (DpRetT, error) {
	var tbl int

	if w.Work != DpMapGet {
		return EbpfErrWqUnk, errors.New("unknown work type")
	}

	switch {
	case w.Name == MapNameCt4:
		tbl = C.LL_DP_CT_MAP
	case w.Name == MapNameNatEp:
		tbl = C.LL_DP_NAT_EP_MAP
	default:
		return EbpfErrWqUnk, errors.New("unknown work type")
	}

	if tbl == C.LL_DP_NAT_EP_MAP {
		// walk the per-rule nat_ep_map and surface the datapath's CUMULATIVE
		// statistics (total_conns / cum_bytes_in / cum_bytes_out) plus the live conc_conns gauge,
		// keyed by rule mark (ruleNum). DpCtStatsRollup reads these as the authoritative source
		// for total/bytes so sub-tick flows are not lost. Plain lookup (no BPF_F_LOCK) — a stats
		// snapshot, same as getNatEpaByMark.
		epMap := make(map[uint32]*NatEpStats)
		var key *C.uint // nil on the first get_next_key => start from the first entry
		nextKey := new(C.uint)
		var epa C.struct_dp_nat_epacts
		fd := C.llb_map2fd(C.int(tbl))

		for C.bpf_map_get_next_key(C.int(fd), (unsafe.Pointer)(key), (unsafe.Pointer)(nextKey)) == 0 {
			if C.bpf_map_lookup_elem(C.int(fd), (unsafe.Pointer)(nextKey), (unsafe.Pointer)(&epa)) == 0 {
				epMap[uint32(*nextKey)] = &NatEpStats{
					ActiveConns: uint64(epa.conc_conns),
					TotalConns:  uint64(epa.total_conns),
					BytesIn:     uint64(epa.cum_bytes_in),
					BytesOut:    uint64(epa.cum_bytes_out),
				}
			}
			key = nextKey
		}

		return epMap, nil
	}

	if tbl == C.LL_DP_CT_MAP {
		ctMap := make(map[string]*DpCtInfo)
		var key *C.struct_dp_ct_key
		nextKey := new(C.struct_dp_ct_key)
		var tact C.struct_dp_ct_tact
		var act *C.struct_dp_ct_dat

		n := 0
		fd := C.llb_map2fd(C.int(tbl))

		for C.bpf_map_get_next_key(C.int(fd), (unsafe.Pointer)(key), (unsafe.Pointer)(nextKey)) == 0 {
			ctKey := (*C.struct_dp_ct_key)(unsafe.Pointer(nextKey))

			if C.bpf_map_lookup_elem(C.int(fd), (unsafe.Pointer)(nextKey), (unsafe.Pointer)(&tact)) != 0 {
				continue
			}

			act = &tact.ctd

			if act.dir == C.CT_DIR_IN || act.dir == C.CT_DIR_OUT {
				var b, p uint64
				goCt4Ent := new(DpCtInfo)
				goCt4Ent.convDPCt2GoObjFixup(ctKey, act, true)
				ret := C.llb_fetch_map_stats_cached(C.int(C.LL_DP_CT_STATS_MAP), C.uint(tact.ca.cidx), C.int(1),
					(unsafe.Pointer(&b)), unsafe.Pointer(&p))
				if ret == 0 {
					goCt4Ent.Bytes += b
					goCt4Ent.Packets += p
				}
				goCt4Ent.RuleID = uint32(act.rid)
				// carry the per-entry CT direction so the
				// /stats rollup can attribute bytes per-direction (CT_DIR_IN=bytes_in
				// forward client->VIP request; CT_DIR_OUT=bytes_out reverse VIP->client
				// response) instead of collapsing both into one figure.
				goCt4Ent.Dir = int(act.dir)
				//fmt.Println(goCt4Ent)
				ctMap[goCt4Ent.Key()] = goCt4Ent
			}
			key = nextKey
			n++
		}

		proxyCtInfo = nil
		C.llb_trigger_get_proxy_entries()
		for e, proxyCt := range proxyCtInfo {
			ePCT := ctMap[proxyCt.Key()]
			if ePCT != nil {
				if e > 0 {
					ePCT.CAct += " "
				}
				ePCT.CAct += proxyCt.CAct
				ePCT.Bytes += proxyCt.Bytes
				ePCT.Packets += proxyCt.Packets
			} else {
				ctMap[proxyCt.Key()] = proxyCt
			}
		}
		proxyCtInfo = nil

		return ctMap, nil
	}

	return EbpfErrWqUnk, errors.New("unknown work type")
}

// DpUlClMod - routine to work on a ebpf ul-cl filter change request
func (e *DpEbpfH) DpUlClMod(w *UlClDpWorkQ) int {
	key := new(sess4Key)

	key.daddr = C.uint(tk.IPtonl(w.MDip))
	key.saddr = C.uint(tk.IPtonl(w.MSip))
	key.teid = C.uint(tk.Htonl(w.mTeID))
	key.r = 0

	if w.Work == DpCreate {
		dat := new(sessAct)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_sess_tact)

		if key.teid != 0 || w.Type == DpTunIPIP {
			if w.Type == DpTunIPIP {
				dat.ca.act_type = C.DP_SET_RM_IPIP
			} else {
				dat.ca.act_type = C.DP_SET_RM_GTP
			}

			dat.ca.cidx = C.uint(w.Mark)
			dat.qfi = C.uchar(w.Qfi)
		} else {
			dat.ca.act_type = C.DP_SET_ADD_GTP
			dat.ca.cidx = C.uint(w.Mark)
			dat.qfi = C.uchar(w.Qfi)
			dat.rip = C.uint(tk.IPtonl(w.TDip))
			dat.sip = C.uint(tk.IPtonl(w.TSip))
			dat.teid = C.uint(tk.Htonl(w.TTeID))
		}

		ret := C.llb_add_map_elem(C.LL_DP_SESS4_MAP,
			unsafe.Pointer(key),
			unsafe.Pointer(dat))

		if ret != 0 {
			return EbpfErrSess4Add
		}

		return 0
	} else if w.Work == DpRemove {
		C.llb_del_map_elem(C.LL_DP_SESS4_MAP, unsafe.Pointer(key))
		return 0
	}
	return EbpfErrWqUnk
}

// DpUlClAdd - routine to work on a ebpf ul-cl filter add request
func (e *DpEbpfH) DpUlClAdd(w *UlClDpWorkQ) int {
	return e.DpUlClMod(w)
}

// DpUlClDel - routine to work on a ebpf ul-cl filter delete request
func (e *DpEbpfH) DpUlClDel(w *UlClDpWorkQ) int {
	return e.DpUlClMod(w)
}

// DpPolMod - routine to work on a ebpf policer change request
func (e *DpEbpfH) DpPolMod(w *PolDpWorkQ) int {
	key := C.uint(w.Mark)

	if w.Work == DpCreate {
		dat := new(polTact)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_pol_tact)
		dat.ca.act_type = C.DP_SET_DO_POLICER
		// For finding pa, we need to account for padding of 4
		pa := (*polAct)(getPtrOffset(unsafe.Pointer(dat),
			C.sizeof_struct_dp_cmn_act+C.sizeof_struct_bpf_spin_lock+4))

		if w.Srt == false {
			pa.trtcm = 1
		} else {
			pa.trtcm = 0
		}

		if w.Color == false {
			pa.color_aware = 0
		} else {
			pa.color_aware = 1
		}

		pa.toksc_pus = C.ulonglong(w.Cir / (8000000))
		pa.tokse_pus = C.ulonglong(w.Pir / (8000000))
		pa.cbs = C.uint(w.Cbs)
		pa.ebs = C.uint(w.Ebs)
		pa.tok_c = pa.cbs
		pa.tok_e = pa.ebs
		pa.lastc_uts = C.get_os_usecs()
		pa.laste_uts = pa.toksc_pus
		pa.drop_prio = C.LLB_PIPE_COL_YELLOW

		ret := C.llb_add_map_elem(C.LL_DP_POL_MAP,
			unsafe.Pointer(&key),
			unsafe.Pointer(dat))

		if ret != 0 {
			*w.Status = 1
			return EbpfErrPolAdd
		}

		*w.Status = 0

	} else if w.Work == DpRemove {
		// Array map types need to be zeroed out first
		dat := new(polTact)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_pol_tact)
		C.llb_add_map_elem(C.LL_DP_POL_MAP, unsafe.Pointer(&key), unsafe.Pointer(dat))
		// This operation is unnecessary
		C.llb_del_map_elem(C.LL_DP_POL_MAP, unsafe.Pointer(&key))
		return 0
	}
	return 0
}

// DpPolAdd - routine to work on a ebpf policer add request
func (e *DpEbpfH) DpPolAdd(w *PolDpWorkQ) int {
	ec := e.DpPolMod(w)
	if ec != 0 {
		*w.Status = DpCreateErr
	} else {
		*w.Status = 0
		// shadow meter offload after eBPF success (non-blocking, non-fatal)
		if mh.dpuMgr != nil {
			mh.dpuMgr.ShadowPolAdd(w)
		}
	}
	return ec
}

// DpPolDel - routine to work on a ebpf policer delete request
func (e *DpEbpfH) DpPolDel(w *PolDpWorkQ) int {
	// shadow meter remove before eBPF delete (non-blocking, non-fatal)
	if mh.dpuMgr != nil {
		mh.dpuMgr.ShadowPolDel(w)
	}
	return e.DpPolMod(w)
}

// DpMirrMod - routine to work on a ebpf mirror modify request
func (e *DpEbpfH) DpMirrMod(w *MirrDpWorkQ) int {
	key := C.uint(w.Mark)

	if w.Work == DpCreate {
		dat := new(mirrTact)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_mirr_tact)

		if w.MiBD != 0 {
			dat.ca.act_type = C.DP_SET_ADD_L2VLAN
		} else {
			dat.ca.act_type = C.DP_SET_RM_L2VLAN
		}

		la := (*l2VlanAct)(getPtrOffset(unsafe.Pointer(dat), C.sizeof_struct_dp_cmn_act))

		la.oport = C.ushort(w.MiPortNum)
		la.vlan = C.ushort(w.MiBD)

		ret := C.llb_add_map_elem(C.LL_DP_MIRROR_MAP, unsafe.Pointer(&key), unsafe.Pointer(dat))

		if ret != 0 {
			*w.Status = 1
			return EbpfErrMirrAdd
		}

		*w.Status = 0

	} else if w.Work == DpRemove {
		// Array map types need to be zeroed out first
		dat := new(mirrTact)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_dp_mirr_tact)
		C.llb_add_map_elem(C.LL_DP_MIRROR_MAP, unsafe.Pointer(&key), unsafe.Pointer(dat))
		C.llb_del_map_elem(C.LL_DP_MIRROR_MAP, unsafe.Pointer(&key))
		return 0
	}
	return 0
}

// DpMirrAdd - routine to work on a ebpf mirror add request
func (e *DpEbpfH) DpMirrAdd(w *MirrDpWorkQ) int {
	return e.DpMirrMod(w)
}

// DpMirrDel - routine to work on a ebpf mirror delete request
func (e *DpEbpfH) DpMirrDel(w *MirrDpWorkQ) int {
	return e.DpMirrMod(w)
}

func (e *DpEbpfH) dpFwRuleMod4(w *FwDpWorkQ) int {
	fwe := new(fw4Ent)

	C.memset(unsafe.Pointer(fwe), 0, C.sizeof_struct_dp_fwv4_ent)

	if len(w.DstIP.IP) != 0 {
		fwe.k.dest.val = C.uint(tk.Ntohl(tk.IPtonl(w.DstIP.IP)))
		fwe.k.dest.valid = C.uint(tk.Ntohl(tk.IPtonl(net.IP(w.DstIP.Mask))))
	}

	if len(w.SrcIP.IP) != 0 {
		fwe.k.source.val = C.uint(tk.Ntohl(tk.IPtonl(w.SrcIP.IP)))
		fwe.k.source.valid = C.uint(tk.Ntohl(tk.IPtonl(net.IP(w.SrcIP.Mask))))
	}

	if w.L4SrcMin == w.L4SrcMax {
		if w.L4SrcMin != 0 {
			fwe.k.sport.has_range = C.uint(0)
			ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[0]))
			*ptr = C.ushort(w.L4SrcMin)
			ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[2]))
			*ptr = C.ushort(0xffff)
		}
	} else {
		fwe.k.sport.has_range = C.uint(1)
		ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[0]))
		*ptr = C.ushort(w.L4SrcMin)
		ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[2]))
		*ptr = C.ushort(w.L4SrcMax)
	}

	if w.L4DstMin == w.L4DstMax {
		if w.L4DstMin != 0 {
			fwe.k.dport.has_range = C.uint(0)
			ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[0]))
			*ptr = C.ushort(w.L4DstMin)
			ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[2]))
			*ptr = C.ushort(0xffff)
		}
	} else {
		fwe.k.dport.has_range = C.uint(1)
		ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[0]))
		*ptr = C.ushort(w.L4DstMin)
		ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[2]))
		*ptr = C.ushort(w.L4DstMax)
	}

	if w.Port != 0 {
		fwe.k.inport.val = C.ushort(w.Port)
		fwe.k.inport.valid = C.ushort(0xffff)
	}

	if w.Proto != 0 {
		fwe.k.protocol.val = C.uchar(w.Proto)
		fwe.k.protocol.valid = C.uchar(255)
	}

	if w.ZoneNum != 0 {
		fwe.k.zone.val = C.ushort(w.ZoneNum)
		fwe.k.zone.valid = C.ushort(0xffff)
	}

	fwe.fwa.ca.cidx = C.uint(w.Mark)
	fwe.fwa.ca.oaux = C.ushort(w.Pref) // Overloaded field

	if w.Work == DpCreate {
		if w.FwType == DpFwFwd {
			fwe.fwa.ca.act_type = C.DP_SET_NOP
		} else if w.FwType == DpFwDrop {
			fwe.fwa.ca.act_type = C.DP_SET_DROP
		} else if w.FwType == DpFwRdr {
			fwe.fwa.ca.act_type = C.DP_SET_RDR_PORT
			pRdr := (*portAct)(getPtrOffset(unsafe.Pointer(&fwe.fwa),
				C.sizeof_struct_dp_cmn_act))
			pRdr.oport = C.ushort(w.FwVal1)
		} else if w.FwType == DpFwTrap {
			fwe.fwa.ca.act_type = C.DP_SET_TOCP
		}
		fwe.fwa.ca.mark = C.uint(w.FwVal2)
		if w.FwRecord {
			fwe.fwa.ca.record = C.ushort(1)
		}

		ret := C.llb_add_map_elem(C.LL_DP_FW4_MAP, unsafe.Pointer(fwe), unsafe.Pointer(nil))
		if ret != 0 {
			tk.LogIt(tk.LogError, "ebpf fw error\n")
			return EbpfErrFwAdd
		}
	} else if w.Work == DpRemove {
		C.llb_del_map_elem(C.LL_DP_FW4_MAP, unsafe.Pointer(fwe))
	}

	return 0
}

func (e *DpEbpfH) dpFwRuleMod6(w *FwDpWorkQ) int {
	fwe := new(fw6Ent)

	C.memset(unsafe.Pointer(fwe), 0, C.sizeof_struct_dp_fwv6_ent)

	if len(w.DstIP.IP) != 0 {
		for i, v := range w.DstIP.IP {
			fwe.k.dest.val[i] = C.uchar(v)
			fwe.k.dest.valid[i] = C.uchar(w.DstIP.Mask[i])
		}
	}

	if len(w.SrcIP.IP) != 0 {
		for i, v := range w.SrcIP.IP {
			fwe.k.source.val[i] = C.uchar(v)
			fwe.k.source.valid[i] = C.uchar(w.SrcIP.Mask[i])
		}
	}

	if w.L4SrcMin == w.L4SrcMax {
		if w.L4SrcMin != 0 {
			fwe.k.sport.has_range = C.uint(0)
			ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[0]))
			*ptr = C.ushort(w.L4SrcMin)
			ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[2]))
			*ptr = C.ushort(0xffff)
		}
	} else {
		fwe.k.sport.has_range = C.uint(1)
		ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[0]))
		*ptr = C.ushort(w.L4SrcMin)
		ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.sport.u[2]))
		*ptr = C.ushort(w.L4SrcMax)
	}

	if w.L4DstMin == w.L4DstMax {
		if w.L4DstMin != 0 {
			fwe.k.dport.has_range = C.uint(0)
			ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[0]))
			*ptr = C.ushort(w.L4DstMin)
			ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[2]))
			*ptr = C.ushort(0xffff)
		}
	} else {
		fwe.k.dport.has_range = C.uint(1)
		ptr := (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[0]))
		*ptr = C.ushort(w.L4DstMin)
		ptr = (*C.ushort)(unsafe.Pointer(&fwe.k.dport.u[2]))
		*ptr = C.ushort(w.L4DstMax)
	}

	if w.Port != 0 {
		fwe.k.inport.val = C.ushort(w.Port)
		fwe.k.inport.valid = C.ushort(0xffff)
	}

	if w.Proto != 0 {
		fwe.k.protocol.val = C.uchar(w.Proto)
		fwe.k.protocol.valid = C.uchar(255)
	}

	if w.ZoneNum != 0 {
		fwe.k.zone.val = C.ushort(w.ZoneNum)
		fwe.k.zone.valid = C.ushort(0xffff)
	}

	fwe.fwa.ca.cidx = C.uint(w.Mark)
	fwe.fwa.ca.oaux = C.ushort(w.Pref) // Overloaded field

	if w.Work == DpCreate {
		if w.FwType == DpFwFwd {
			fwe.fwa.ca.act_type = C.DP_SET_NOP
		} else if w.FwType == DpFwDrop {
			fwe.fwa.ca.act_type = C.DP_SET_DROP
		} else if w.FwType == DpFwRdr {
			fwe.fwa.ca.act_type = C.DP_SET_RDR_PORT
			pRdr := (*portAct)(getPtrOffset(unsafe.Pointer(&fwe.fwa),
				C.sizeof_struct_dp_cmn_act))
			pRdr.oport = C.ushort(w.FwVal1)
		} else if w.FwType == DpFwTrap {
			fwe.fwa.ca.act_type = C.DP_SET_TOCP
		}
		fwe.fwa.ca.mark = C.uint(w.FwVal2)
		if w.FwRecord {
			fwe.fwa.ca.record = C.ushort(1)
		}

		ret := C.llb_add_map_elem(C.LL_DP_FW6_MAP, unsafe.Pointer(fwe), unsafe.Pointer(nil))
		if ret != 0 {
			tk.LogIt(tk.LogError, "ebpf fw6 error\n")
			return EbpfErrFwAdd
		}
	} else if w.Work == DpRemove {
		C.llb_del_map_elem(C.LL_DP_FW6_MAP, unsafe.Pointer(fwe))
	}

	return 0
}

// DpFwRuleMod - routine to work on a ebpf fw mod request
func (e *DpEbpfH) DpFwRuleMod(w *FwDpWorkQ) int {

	if len(w.DstIP.IP) == 0 && len(w.SrcIP.IP) == 0 {
		return e.dpFwRuleMod4(w)
	}

	if tk.IsNetIPv4(w.DstIP.IP.String()) && tk.IsNetIPv6(w.SrcIP.IP.String()) ||
		tk.IsNetIPv6(w.DstIP.IP.String()) && tk.IsNetIPv4(w.SrcIP.IP.String()) {
		return EbpfErrFwAdd
	}

	if tk.IsNetIPv4(w.DstIP.IP.String()) {
		return e.dpFwRuleMod4(w)
	}

	return e.dpFwRuleMod6(w)
}

// DpFwRuleAdd - routine to work on a ebpf fw add request
func (e *DpEbpfH) DpFwRuleAdd(w *FwDpWorkQ) int {
	ec := e.DpFwRuleMod(w)
	if ec != 0 {
		*w.Status = DpCreateErr
	} else {
		*w.Status = 0
		// shadow ACL offload after eBPF success (BF2: no-op via capability gating)
		if mh.dpuMgr != nil {
			mh.dpuMgr.ShadowFwRuleAdd(w)
		}
	}
	return ec
}

// DpFwRuleDel - routine to work on a ebpf fw delete request
func (e *DpEbpfH) DpFwRuleDel(w *FwDpWorkQ) int {
	// shadow ACL remove before eBPF delete (BF2: no-op via capability gating)
	if mh.dpuMgr != nil {
		mh.dpuMgr.ShadowFwRuleDel(w)
	}
	return e.DpFwRuleMod(w)
}

// DpIPFilterMod - routine to work on a ebpf IP filter modification
func (e *DpEbpfH) DpIPFilterMod(w *IPFilterDpWorkQ) int {
	// The kernel keeps separate v4/v6 LPM tries so a short IPv4 prefix can
	// never match an IPv6 source (and vice-versa). The map is selected below,
	// once the CIDR family is known.
	var mapNum C.int
	var filterTypeName string
	if w.FilterType == IPFilterWhitelist {
		filterTypeName = "whitelist"
	} else {
		filterTypeName = "blacklist"
	}

	tk.LogIt(tk.LogDebug, "[IPFILTER] >>> DpIPFilterMod: filterType=%s cidr=%s action=%d zone=%d priority=%d work=%d\n",
		filterTypeName, w.IPNet.String(), w.Action, w.Zone, w.Priority, w.Work)

	// Prepare LPM trie key
	key := (*C.struct_dp_ip_filter_key)(C.malloc(C.sizeof_struct_dp_ip_filter_key))
	if key == nil {
		return EbpfErrSockVIPAdd // Reuse existing error code
	}
	defer C.free(unsafe.Pointer(key))

	C.memset(unsafe.Pointer(key), 0, C.sizeof_struct_dp_ip_filter_key)

	// Set prefix length based on CIDR mask - use direct prefixlen field
	ones, bits := w.IPNet.Mask.Size()
	key.prefixlen = C.uint(ones)

	if bits == 32 {
		// IPv4
		ip4 := w.IPNet.IP.To4()
		if ip4 == nil {
			return EbpfErrSockVIPAdd
		}
		// Access data byte array at offset 4 (after prefixlen __u32)
		// Structure: [prefixlen:4 bytes][data:16 bytes]
		dataPtr := getPtrOffset(unsafe.Pointer(key), C.sizeof_uint)
		// Copy IPv4 bytes directly into first 4 bytes of data array
		C.memcpy(dataPtr, unsafe.Pointer(&ip4[0]), 4)

		tk.LogIt(tk.LogDebug, "[IPFILTER] IPv4 key: prefixlen=%d ip_bytes=[%d.%d.%d.%d] (%s)\n",
			ones, ip4[0], ip4[1], ip4[2], ip4[3], w.IPNet.IP.String())

	} else if bits == 128 {
		// IPv6
		ip6 := w.IPNet.IP.To16()
		if ip6 == nil {
			tk.LogIt(tk.LogError, "[IPFILTER] Invalid IPv6 address\n")
			return EbpfErrSockVIPAdd
		}
		// Access data byte array at offset 4 (after prefixlen __u32)
		// Copy all 16 bytes of IPv6 address into data array
		dataPtr := getPtrOffset(unsafe.Pointer(key), C.sizeof_uint)
		C.memcpy(dataPtr, unsafe.Pointer(&ip6[0]), 16)
	} else {
		tk.LogIt(tk.LogError, "[IPFILTER] Unsupported IP version\n")
		return EbpfErrSockVIPAdd
	}

	if w.FilterType == IPFilterWhitelist {
		if bits == 128 {
			mapNum = C.LL_DP_IP_WHITELIST6_MAP
		} else {
			mapNum = C.LL_DP_IP_WHITELIST_MAP
		}
	} else {
		if bits == 128 {
			mapNum = C.LL_DP_IP_BLACKLIST6_MAP
		} else {
			mapNum = C.LL_DP_IP_BLACKLIST_MAP
		}
	}

	if w.Work == DpCreate {
		// Prepare value
		rule := (*C.struct_dp_ip_filter_rule)(C.malloc(C.sizeof_struct_dp_ip_filter_rule))
		if rule == nil {
			tk.LogIt(tk.LogError, "[IPFILTER] Failed to allocate rule memory\n")
			return EbpfErrSockVIPAdd
		}
		defer C.free(unsafe.Pointer(rule))

		C.memset(unsafe.Pointer(rule), 0, C.sizeof_struct_dp_ip_filter_rule)
		rule.action = C.uchar(w.Action)
		rule.zone = C.uchar(w.Zone)
		rule.priority = C.ushort(w.Priority)
		// Don't set packets/bytes - they're in packed struct, will be initialized to 0 by memset

		tk.LogIt(tk.LogDebug, "[IPFILTER] Inserting into %s map: action=%d zone=%d priority=%d\n",
			filterTypeName, w.Action, w.Zone, w.Priority)

		// Add to eBPF map
		ret := C.llb_add_map_elem(mapNum, unsafe.Pointer(key), unsafe.Pointer(rule))
		if ret != 0 {
			tk.LogIt(tk.LogError, "[IPFILTER] ✗ Failed to add rule to %s eBPF map (ret=%d)\n", filterTypeName, ret)
			return EbpfErrSockVIPAdd
		}
		tk.LogIt(tk.LogDebug, "[IPFILTER] ✓ Successfully added %s rule: %s action=%d\n",
			filterTypeName, w.IPNet.String(), w.Action)

	} else if w.Work == DpRemove {
		// Delete from eBPF map; a miss (no such entry) must not report Success
		ret := C.llb_del_map_elem(mapNum, unsafe.Pointer(key))
		if ret != 0 {
			tk.LogIt(tk.LogError, "[IPFILTER] delete miss/fail for %s rule %s (ret=%d)\n",
				filterTypeName, w.IPNet.String(), ret)
			return EbpfErrSockVIPAdd
		}
	}

	return 0
}

// DpIPFilterAdd - routine to work on a ebpf IP filter add request
func (e *DpEbpfH) DpIPFilterAdd(w *IPFilterDpWorkQ) int {
	ec := e.DpIPFilterMod(w)
	if ec != 0 {
		*w.Status = DpCreateErr
	} else {
		*w.Status = 0
	}
	return ec
}

// DpIPFilterDel - routine to work on a ebpf IP filter delete request
func (e *DpEbpfH) DpIPFilterDel(w *IPFilterDpWorkQ) int {
	return e.DpIPFilterMod(w)
}

// DpIPFilterGet - Get IP filter rules from eBPF map
func (e *DpEbpfH) DpIPFilterGet(filterType IPFilterType) ([]cmn.IPFilterEntry, error) {
	var ret []cmn.IPFilterEntry

	// v4 and v6 rules live in separate kernel LPM tries (see DpIPFilterMod);
	// iterate both. The address family comes from which map an entry lives in,
	// not from guessing by prefix length (a v6 rule with prefix <= 32 used to
	// be mis-rendered as a bogus IPv4 CIDR).
	var v4Map, v6Map C.int
	var filterTypeName string
	if filterType == IPFilterWhitelist {
		v4Map = C.LL_DP_IP_WHITELIST_MAP
		v6Map = C.LL_DP_IP_WHITELIST6_MAP
		filterTypeName = "whitelist"
	} else {
		v4Map = C.LL_DP_IP_BLACKLIST_MAP
		v6Map = C.LL_DP_IP_BLACKLIST6_MAP
		filterTypeName = "blacklist"
	}

	// Allocate key and nextKey for iteration
	key := (*C.struct_dp_ip_filter_key)(C.malloc(C.sizeof_struct_dp_ip_filter_key))
	if key == nil {
		return ret, fmt.Errorf("failed to allocate memory for key")
	}
	defer C.free(unsafe.Pointer(key))

	nextKey := (*C.struct_dp_ip_filter_key)(C.malloc(C.sizeof_struct_dp_ip_filter_key))
	if nextKey == nil {
		return ret, fmt.Errorf("failed to allocate memory for nextKey")
	}
	defer C.free(unsafe.Pointer(nextKey))

	for _, fam := range []struct {
		mapNum C.int
		isV6   bool
	}{{v4Map, false}, {v6Map, true}} {
		fd := C.llb_map2fd(fam.mapNum)
		if fd < 0 {
			return ret, fmt.Errorf("failed to get map fd for %s", filterTypeName)
		}

		// Iterate over map entries. The first call passes a NULL cursor so the
		// kernel returns the true first key; passing an all-zero key instead
		// would SKIP a 0.0.0.0/0 (prefixlen-0, all-zero) entry, since
		// get_next_key returns the key *after* an existing cursor.
		C.memset(unsafe.Pointer(key), 0, C.sizeof_struct_dp_ip_filter_key)
		cur := unsafe.Pointer(nil)

		// Iterate over map entries
		for C.bpf_map_get_next_key(C.int(fd), cur, unsafe.Pointer(nextKey)) == 0 {
			cur = unsafe.Pointer(key)
			// Allocate rule structure
			rule := (*C.struct_dp_ip_filter_rule)(C.malloc(C.sizeof_struct_dp_ip_filter_rule))
			if rule == nil {
				C.memcpy(unsafe.Pointer(key), unsafe.Pointer(nextKey), C.sizeof_struct_dp_ip_filter_key)
				continue
			}

			// Lookup value for this key
			if C.bpf_map_lookup_elem(C.int(fd), unsafe.Pointer(nextKey), unsafe.Pointer(rule)) != 0 {
				C.free(unsafe.Pointer(rule))
				C.memcpy(unsafe.Pointer(key), unsafe.Pointer(nextKey), C.sizeof_struct_dp_ip_filter_key)
				continue
			}

			// Convert to Go structure
			entry := cmn.IPFilterEntry{}
			entry.FilterType = filterTypeName

			prefixLen := uint32(nextKey.prefixlen)
			dataPtr := getPtrOffset(unsafe.Pointer(nextKey), C.sizeof_uint)
			if !fam.isV6 {
				// IPv4 - first 4 bytes of the data array, network byte order
				ip4Bytes := (*[4]byte)(dataPtr)
				ip4 := net.IPv4(ip4Bytes[0], ip4Bytes[1], ip4Bytes[2], ip4Bytes[3])
				entry.CIDR = fmt.Sprintf("%s/%d", ip4.String(), prefixLen)
			} else {
				// IPv6 - all 16 bytes of the data array
				ip6Bytes := (*[16]byte)(dataPtr)
				ip6 := net.IP(ip6Bytes[:])
				entry.CIDR = fmt.Sprintf("%s/%d", ip6.String(), prefixLen)
			}

			entry.Zone = uint8(rule.zone)
			entry.Priority = uint16(rule.priority)

			if rule.action == 0 {
				entry.Action = "allow"
			} else {
				entry.Action = "drop"
			}

			// Read stats via direct memory access (packed struct with explicit
			// alignment pad; see dp_ip_filter_rule in llb_dpapi.h)
			statsPtr := getPtrOffset(unsafe.Pointer(rule), 8) // Skip action, zone, priority, pad
			packets := *(*C.ulonglong)(statsPtr)
			bytes := *(*C.ulonglong)(getPtrOffset(statsPtr, 8))
			entry.Packets = uint64(packets)
			entry.Bytes = uint64(bytes)

			ret = append(ret, entry)

			C.free(unsafe.Pointer(rule))

			// Move to next key
			C.memcpy(unsafe.Pointer(key), unsafe.Pointer(nextKey), C.sizeof_struct_dp_ip_filter_key)
		}
	}

	return ret, nil
}

// DpSecurityRateConfigSet - Set unified security rate limiting configuration (P0-5 + P0-6)
// Unified SYN-flood + connection-rate + UDP-flood config in a single eBPF map
// Pattern: Follows P0-7 IP filter map operations (DpIPFilterMod lines 2543-2622)
func (e *DpEbpfH) DpSecurityRateConfigSet(config SecurityRateConfig) error {
	if !securityRateRuntimeConfig {
		// Runtime configuration not compiled in (hardcoded mode).
		tk.LogIt(tk.LogWarning, "[DPEBPF] Security rate runtime config not available (hardcoded mode)\n")
		return fmt.Errorf("security rate runtime configuration not enabled at build time")
	}

	// Get config map file descriptor
	configFd := C.llb_map2fd(C.int(C.get_security_rate_config_map_id()))
	if configFd < 0 {
		return fmt.Errorf("failed to get security rate config map fd")
	}

	// C structure matches: struct dp_security_rate_config (llb_kern_cdefs.h)
	// CRITICAL: Field order MUST match C struct exactly (byte-for-byte alignment).
	// 10 x uint32 = 40 bytes packed.
	type dpSecurityRateConfig struct {
		Version               uint32 // Incremented on each config change
		SynThreshold          uint32 // Max SYNs/sec before dropping (default: 100)
		CookieThreshold       uint32 // SYNs/sec to trigger cookies (default: 50)
		SynEnabled            uint32 // 1 = SYN flood protection enabled
		ConnRateThreshold     uint32 // Max conns/sec before dropping (default: 50)
		ConnRateEnabled       uint32 // 1 = connection rate limiting enabled
		UDPPktThreshold       uint32 // Max UDP packets/sec (default: 1000) - P0-7
		UDPBandwidthThreshold uint32 // Max UDP bytes/sec (default: 100MB) - P0-7
		UDPEnabled            uint32 // 1 = UDP flood protection enabled - P0-7
		Reserved              uint32 // Future expansion
	}

	var currentCfg dpSecurityRateConfig
	var key C.uint = 0

	// ABI guard (P0-1 bug class): the kernel struct dp_security_rate_config is
	// 40 packed bytes (_Static_assert in llb_kern_cdefs.h). A size skew makes
	// the bpf syscalls read/write past this struct on the Go stack.
	if unsafe.Sizeof(currentCfg) != 40 {
		return fmt.Errorf("dpSecurityRateConfig size %d != 40: kernel ABI mismatch, refusing to touch sec_rate_cfg",
			unsafe.Sizeof(currentCfg))
	}

	// Read current config to get version
	var newVersion uint32 = 1
	if C.bpf_map_lookup_elem(C.int(configFd), unsafe.Pointer(&key), unsafe.Pointer(&currentCfg)) == 0 {
		// Increment version for per-CPU cache invalidation
		newVersion = currentCfg.Version + 1
		if newVersion == 0 {
			newVersion = 1 // Avoid wrapping to 0 (would look like uninitialized)
		}
	}

	// Prepare new configuration
	cfgData := dpSecurityRateConfig{
		Version:               newVersion,
		SynThreshold:          config.SYNThreshold,
		CookieThreshold:       config.CookieThreshold,
		SynEnabled:            0,
		ConnRateThreshold:     config.RatePerSec,
		ConnRateEnabled:       0,
		UDPPktThreshold:       config.UDPPktThreshold,
		UDPBandwidthThreshold: config.UDPBandwidthMB * 1024 * 1024, // Convert MB to bytes
		UDPEnabled:            0,
		Reserved:              0,
	}

	// Convert bool to uint32
	if config.SYNEnabled {
		cfgData.SynEnabled = 1
	}
	if config.ConnRateEnabled {
		cfgData.ConnRateEnabled = 1
	}
	if config.UDPEnabled {
		cfgData.UDPEnabled = 1
	}

	// Apply defaults if not specified
	if cfgData.SynThreshold == 0 {
		cfgData.SynThreshold = 100 // SYN_FLOOD_THRESHOLD
	}
	if cfgData.CookieThreshold == 0 {
		cfgData.CookieThreshold = 50 // SYN_COOKIE_THRESHOLD
	}
	if cfgData.ConnRateThreshold == 0 {
		cfgData.ConnRateThreshold = 50 // CONN_RATE_THRESHOLD
	}
	if cfgData.UDPPktThreshold == 0 {
		cfgData.UDPPktThreshold = 1000 // UDP_PKT_THRESHOLD
	}
	if cfgData.UDPBandwidthThreshold == 0 {
		cfgData.UDPBandwidthThreshold = 100 * 1024 * 1024 // 100 MB/sec
	}

	// Update eBPF map at index 0 (CONFIG_INDEX)
	// Pattern: Following llb_add_map_elem wrapper used throughout this file
	ret := C.bpf_map_update_elem(C.int(configFd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&cfgData),
		C.BPF_ANY)

	if ret != 0 {
		return fmt.Errorf("failed to update security rate config map: ret=%d", ret)
	}

	tk.LogIt(tk.LogInfo, "[DPEBPF] Security rate config updated: version=%d syn=%v(%d/%d) conn=%v(%d) udp=%v(%d/%d)\n",
		newVersion,
		config.SYNEnabled, cfgData.SynThreshold, cfgData.CookieThreshold,
		config.ConnRateEnabled, cfgData.ConnRateThreshold,
		config.UDPEnabled, cfgData.UDPPktThreshold, cfgData.UDPBandwidthThreshold)

	// Handle whitelist map: remove only old security rate whitelist entries, then add new ones
	// NOTE: We must NOT clear all entries because the whitelist map is shared with IP Filter (P0-7)
	// v4 and v6 CIDRs go to their family-specific tries (same split as DpIPFilterMod).
	mapNum := C.int(C.LL_DP_IP_WHITELIST_MAP)
	mapNum6 := C.int(C.LL_DP_IP_WHITELIST6_MAP)
	whitelistFd := C.llb_map2fd(mapNum)
	if whitelistFd < 0 {
		tk.LogIt(tk.LogWarning, "[DPEBPF] Whitelist map not available (fd=%d)\n", whitelistFd)
	} else {
		// Remove only the whitelist entries that were previously added by security rate config
		// Get the previously configured whitelist IPs from mh.securityRateConfig
		if len(e.prevSecurityRateWhitelistIPs) > 0 {
			tk.LogIt(tk.LogInfo, "[DPEBPF] Removing %d previous security rate whitelist entries\n", len(e.prevSecurityRateWhitelistIPs))

			for _, ipCIDR := range e.prevSecurityRateWhitelistIPs {
				// Parse CIDR string
				_, ipNet, err := net.ParseCIDR(ipCIDR)
				if err != nil {
					tk.LogIt(tk.LogWarning, "[DPEBPF] Invalid previous whitelist IP CIDR '%s': %v\n", ipCIDR, err)
					continue
				}

				// Prepare LPM trie key
				key := (*C.struct_dp_ip_filter_key)(C.malloc(C.sizeof_struct_dp_ip_filter_key))
				if key == nil {
					tk.LogIt(tk.LogError, "[DPEBPF] Failed to allocate key memory for removal\n")
					continue
				}

				C.memset(unsafe.Pointer(key), 0, C.sizeof_struct_dp_ip_filter_key)

				// Set prefix length
				ones, bits := ipNet.Mask.Size()
				key.prefixlen = C.uint(ones)

				if bits == 32 {
					// IPv4
					ip4 := ipNet.IP.To4()
					if ip4 == nil {
						C.free(unsafe.Pointer(key))
						continue
					}
					dataPtr := getPtrOffset(unsafe.Pointer(key), C.sizeof_uint)
					C.memcpy(dataPtr, unsafe.Pointer(&ip4[0]), 4)
				} else if bits == 128 {
					// IPv6
					ip6 := ipNet.IP.To16()
					if ip6 == nil {
						C.free(unsafe.Pointer(key))
						continue
					}
					dataPtr := getPtrOffset(unsafe.Pointer(key), C.sizeof_uint)
					C.memcpy(dataPtr, unsafe.Pointer(&ip6[0]), 16)
				} else {
					C.free(unsafe.Pointer(key))
					continue
				}

				// Delete the entry from its family-specific trie
				entMap := mapNum
				if bits == 128 {
					entMap = mapNum6
				}
				C.llb_del_map_elem(entMap, unsafe.Pointer(key))
				tk.LogIt(tk.LogDebug, "[DPEBPF] Removed previous security rate whitelist entry: %s\n", ipCIDR)

				C.free(unsafe.Pointer(key))
			}
		}
	}

	// Populate whitelist map if WhitelistIPs are provided
	whitelistFailures := 0
	if len(config.WhitelistIPs) > 0 {
		tk.LogIt(tk.LogInfo, "[DPEBPF] ========== WHITELIST POPULATION START: %d IPs ==========\n", len(config.WhitelistIPs))

		for _, ipCIDR := range config.WhitelistIPs {
			// Parse CIDR string
			_, ipNet, err := net.ParseCIDR(ipCIDR)
			if err != nil {
				tk.LogIt(tk.LogWarning, "[DPEBPF] Invalid whitelist IP CIDR '%s': %v\n", ipCIDR, err)
				continue
			}

			// Prepare LPM trie key
			key := (*C.struct_dp_ip_filter_key)(C.malloc(C.sizeof_struct_dp_ip_filter_key))
			if key == nil {
				tk.LogIt(tk.LogError, "[DPEBPF] Failed to allocate whitelist key memory\n")
				continue
			}

			C.memset(unsafe.Pointer(key), 0, C.sizeof_struct_dp_ip_filter_key)

			// Set prefix length
			ones, bits := ipNet.Mask.Size()
			key.prefixlen = C.uint(ones)

			if bits == 32 {
				// IPv4
				ip4 := ipNet.IP.To4()
				if ip4 == nil {
					tk.LogIt(tk.LogWarning, "[DPEBPF] Invalid IPv4 address in whitelist: %s\n", ipCIDR)
					C.free(unsafe.Pointer(key))
					continue
				}
				// Copy IPv4 bytes into data array (following DpIPFilterMod pattern)
				dataPtr := getPtrOffset(unsafe.Pointer(key), C.sizeof_uint)
				C.memcpy(dataPtr, unsafe.Pointer(&ip4[0]), 4)
				tk.LogIt(tk.LogInfo, "[DPEBPF] Whitelist IPv4 key: %s -> prefixlen=%d, bytes=[%d.%d.%d.%d]\n",
					ipCIDR, ones, ip4[0], ip4[1], ip4[2], ip4[3])
			} else if bits == 128 {
				// IPv6
				ip6 := ipNet.IP.To16()
				if ip6 == nil {
					tk.LogIt(tk.LogWarning, "[DPEBPF] Invalid IPv6 address in whitelist: %s\n", ipCIDR)
					C.free(unsafe.Pointer(key))
					continue
				}
				// Copy IPv6 bytes into data array
				dataPtr := getPtrOffset(unsafe.Pointer(key), C.sizeof_uint)
				C.memcpy(dataPtr, unsafe.Pointer(&ip6[0]), 16)
			} else {
				tk.LogIt(tk.LogWarning, "[DPEBPF] Unsupported IP version in whitelist: %s\n", ipCIDR)
				C.free(unsafe.Pointer(key))
				continue
			}

			// Prepare value (whitelist rule)
			rule := (*C.struct_dp_ip_filter_rule)(C.malloc(C.sizeof_struct_dp_ip_filter_rule))
			if rule == nil {
				tk.LogIt(tk.LogError, "[DPEBPF] Failed to allocate whitelist rule memory\n")
				C.free(unsafe.Pointer(key))
				continue
			}

			C.memset(unsafe.Pointer(rule), 0, C.sizeof_struct_dp_ip_filter_rule)
			rule.action = 0     // 0 = ALLOW (whitelist)
			rule.zone = 0       // 0 = all zones
			rule.priority = 100 // Default priority

			// Add to the family-specific whitelist trie
			entMap := mapNum
			if bits == 128 {
				entMap = mapNum6
			}
			addRet := C.llb_add_map_elem(entMap, unsafe.Pointer(key), unsafe.Pointer(rule))
			if addRet != 0 {
				whitelistFailures++
				tk.LogIt(tk.LogError, "[DPEBPF] *** FAILED to add whitelist entry '%s': ret=%d, mapNum=%d ***\n", ipCIDR, addRet, entMap)
			} else {
				tk.LogIt(tk.LogInfo, "[DPEBPF] ✓ Successfully added whitelist entry: %s (prefix=%d, action=%d, zone=%d, priority=%d)\n",
					ipCIDR, ones, rule.action, rule.zone, rule.priority)
			}

			C.free(unsafe.Pointer(key))
			C.free(unsafe.Pointer(rule))
		}
	}

	// Save the current whitelist IPs for next update/delete
	e.prevSecurityRateWhitelistIPs = make([]string, len(config.WhitelistIPs))
	copy(e.prevSecurityRateWhitelistIPs, config.WhitelistIPs)

	// Fail closed: a partially-programmed whitelist means some "protected"
	// clients would be rate-limited anyway. Surface it as an API error.
	if whitelistFailures > 0 {
		return fmt.Errorf("failed to program %d of %d whitelist entries into datapath",
			whitelistFailures, len(config.WhitelistIPs))
	}

	return nil
}

// DpSecurityRateGetStats - Get unified security rate limiting statistics (P0-5 + P0-6)
// Pattern: Follows DpIPFilterGet patterns
// Returns combined statistics from eBPF maps
func (e *DpEbpfH) DpSecurityRateGetStats() (SecurityRateStats, error) {
	stats := SecurityRateStats{}

	// Get statistics map file descriptor
	// Map contains 11 stat indices (see llb_kern_synflood.c):
	// 0: STAT_SYN_BLOCKED
	// 1: STAT_SYN_PASSED
	// 2: STAT_SYN_COOKIES
	// 3: STAT_CONN_BLOCKED
	// 4: STAT_CONN_PASSED
	// 5: reserved (concurrent limit removed)
	// 6: STAT_UNIQUE_IPS
	// 7: STAT_UDP_BLOCKED
	// 8: STAT_UDP_PASSED
	// 9: STAT_UDP_BYTES_BLOCKED
	// 10: STAT_UDP_BYTES_PASSED
	statsFd := C.llb_map2fd(C.int(C.LL_DP_SECURITY_RATE_STATS_MAP))
	if statsFd < 0 {
		return stats, fmt.Errorf("failed to get security rate stats map fd")
	}

	// Read P0-5: SYN Flood Statistics
	var key C.uint
	var val C.ulonglong
	var ret C.int

	// Index 0: SYN packets blocked
	key = 0
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.SYNBlocked = uint64(val)
	}

	// Index 1: SYN packets passed
	key = 1
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.SYNPassed = uint64(val)
	}

	// Index 2: SYN cookie activations
	key = 2
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.SYNCookies = uint64(val)
	}

	// Read P0-6: Connection Rate Statistics
	// Index 3: Connections blocked by rate limit
	key = 3
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.ConnBlocked = uint64(val)
	}

	// Index 4: Connections passed
	key = 4
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.ConnPassed = uint64(val)
	}

	// Index 5: reserved (concurrent limit removed) - not read

	// Index 6: Unique IPs - NO LONGER READ FROM EBPF STATS MAP
	// BUG FIX: eBPF counter at index 6 is monotonically increasing (LRU eviction bug)
	// Calculate by iterating tracking maps instead
	// This is done below after reading all other stats

	// Read P0-7: UDP Flood Statistics
	// Index 7: UDP packets blocked
	key = 7
	ret = C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val))
	if ret == 0 {
		stats.UDPBlocked = uint64(val)
	} else {
		tk.LogIt(tk.LogDebug, "[DPEBPF-STATS-DEBUG] UDP blocked lookup FAILED: key=%d ret=%d\n", key, ret)
	}

	// Index 8: UDP packets passed
	key = 8
	ret = C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val))
	if ret == 0 {
		stats.UDPPassed = uint64(val)
	} else {
		tk.LogIt(tk.LogDebug, "[DPEBPF-STATS-DEBUG] UDP passed lookup FAILED: key=%d ret=%d\n", key, ret)
	}

	// Index 9: UDP bytes blocked
	key = 9
	ret = C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val))
	if ret == 0 {
		stats.UDPBytesBlocked = uint64(val)
	} else {
		tk.LogIt(tk.LogDebug, "[DPEBPF-STATS-DEBUG] UDP bytes blocked lookup FAILED: key=%d ret=%d\n", key, ret)
	}

	// Index 10: UDP bytes passed
	key = 10
	ret = C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val))
	if ret == 0 {
		stats.UDPBytesPassed = uint64(val)
	} else {
		tk.LogIt(tk.LogDebug, "[DPEBPF-STATS-DEBUG] UDP bytes passed lookup FAILED: key=%d ret=%d\n", key, ret)
	}

	// BUG FIX: Always count actual map entries for UniqueIPs (don't use eBPF counter at index 6)
	// Issue: eBPF counter was incremented on new entry but never decremented on LRU eviction
	// Result: UniqueIPs would grow continuously and never reflect actual tracked IPs
	// Solution: Count current map size (provides accurate real-time unique IP count)
	// Pattern: iterate tracking maps to count unique IPs

	// Count IPv4 tracking map entries
	v4Fd := C.llb_map2fd(C.int(C.LL_DP_SECURITY_RATE_V4_TRACKING_MAP))
	if v4Fd >= 0 {
		var v4Key C.uint
		var v4NextKey C.uint
		var v4Count uint64 = 0

		// Initialize for first iteration
		C.memset(unsafe.Pointer(&v4Key), 0, C.sizeof_uint)

		// Iterate to count entries
		for C.bpf_map_get_next_key(C.int(v4Fd), unsafe.Pointer(&v4Key), unsafe.Pointer(&v4NextKey)) == 0 {
			v4Count++
			v4Key = v4NextKey

			// Safety limit (LRU map max is 100K per llb_dpapi.h:54)
			if v4Count > 200000 {
				tk.LogIt(tk.LogWarning, "[DPEBPF] Security rate IPv4 map iteration limit reached\n")
				break
			}
		}

		// Count IPv6 tracking map entries
		v6Fd := C.llb_map2fd(C.int(C.LL_DP_SECURITY_RATE_V6_TRACKING_MAP))
		if v6Fd >= 0 {
			// IPv6 key is struct in6_addr (16 bytes)
			var v6Key [16]C.uchar
			var v6NextKey [16]C.uchar
			var v6Count uint64 = 0

			C.memset(unsafe.Pointer(&v6Key[0]), 0, 16)

			for C.bpf_map_get_next_key(C.int(v6Fd), unsafe.Pointer(&v6Key[0]), unsafe.Pointer(&v6NextKey[0])) == 0 {
				v6Count++
				C.memcpy(unsafe.Pointer(&v6Key[0]), unsafe.Pointer(&v6NextKey[0]), 16)

				if v6Count > 200000 {
					tk.LogIt(tk.LogWarning, "[DPEBPF] Security rate IPv6 map iteration limit reached\n")
					break
				}
			}

			stats.UniqueIPs = v4Count + v6Count
		} else {
			stats.UniqueIPs = v4Count
		}
	} else {
		// IPv4 map not available
		stats.UniqueIPs = 0
	}

	return stats, nil
}

// DpCtErrorGetStats - read always-on, unsampled L4 connection-error counters from
// the ct_err_stats eBPF ARRAY map. Trace-INDEPENDENT: these are bumped directly by
// the CT state machine (llb_kern_ct.c) on each transition into a reset/error state,
// so the metric is exact and present regardless of the L4 trace build/runtime/
// sampling state. Mirrors DpSecurityRateGetStats. Indices match CT_ERR_STAT_*.
func (e *DpEbpfH) DpCtErrorGetStats() (CtErrorStats, error) {
	stats := CtErrorStats{}

	statsFd := C.llb_map2fd(C.int(C.LL_DP_CT_ERR_STATS_MAP))
	if statsFd < 0 {
		return stats, fmt.Errorf("failed to get ct error stats map fd")
	}

	var key C.uint
	var val C.ulonglong

	// Index 0: TCP RST from client (CT_TCP_CW, dir IN)
	key = 0
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.TCPRstClient = uint64(val)
	}

	// Index 1: TCP RST from backend (CT_TCP_CW, dir OUT)
	key = 1
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.TCPRstServer = uint64(val)
	}

	// Index 2: TCP protocol error / half-open (CT_TCP_ERR)
	key = 2
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.TCPErr = uint64(val)
	}

	// Index 3: SCTP ABORT (CT_SCTP_ABRT)
	key = 3
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.SCTPAbort = uint64(val)
	}

	// Index 4: SCTP error (CT_SCTP_ERR)
	key = 4
	if C.bpf_map_lookup_elem(C.int(statsFd), unsafe.Pointer(&key), unsafe.Pointer(&val)) == 0 {
		stats.SCTPErr = uint64(val)
	}

	return stats, nil
}

// DpSecurityRateResetStats - Reset unified security rate limiting statistics
// Pattern: Follows session reset pattern but for global statistics array
// Purpose: Clear accumulated counters for testing or monitoring resets
func (e *DpEbpfH) DpSecurityRateResetStats() error {
	// Get statistics map file descriptor
	statsFd := C.llb_map2fd(C.int(C.LL_DP_SECURITY_RATE_STATS_MAP))
	if statsFd < 0 {
		return fmt.Errorf("failed to get security rate stats map fd")
	}

	// Reset all statistics counters to 0
	// Statistics indices: 0-10 (P0-5 + P0-6 + P0-7)
	var zero C.ulonglong = 0
	for i := C.uint(0); i <= 10; i++ {
		ret := C.bpf_map_update_elem(C.int(statsFd), unsafe.Pointer(&i), unsafe.Pointer(&zero), C.BPF_ANY)
		if ret != 0 {
			tk.LogIt(tk.LogWarning, "[DPEBPF] Failed to reset security rate stat index %d: ret=%d\n", i, ret)
			// Continue resetting other counters even if one fails
		}
	}

	tk.LogIt(tk.LogInfo, "[DPEBPF] Security rate statistics reset completed\n")
	return nil
}

// DpSockVIPMod - routine to work on a ebpf local VIP-port rewrite modification
func (e *DpEbpfH) DpSockVIPMod(w *SockVIPDpWorkQ) int {
	key := new(vipKey)

	if tk.IsNetIPv6(w.VIP.String()) {
		return EbpfErrSockVIPMod
	}

	C.memset(unsafe.Pointer(key), 0, C.sizeof_struct_sock_rwr_key)
	key.vip[0] = C.uint(tk.IPtonl(w.VIP))
	key.port = C.ushort(tk.Htons(w.Port))

	if w.Work == DpCreate {
		dat := new(vipAct)
		C.memset(unsafe.Pointer(dat), 0, C.sizeof_struct_sock_rwr_action)
		dat.rw_port = C.ushort(tk.Htons(w.RwPort))

		ret := C.llb_add_map_elem(C.LL_DP_SOCK_RWR_MAP,
			unsafe.Pointer(key),
			unsafe.Pointer(dat))

		if ret != 0 {
			*w.Status = 1
			tk.LogIt(tk.LogError, "sock-vip rwr add failed\n")
			return EbpfErrSockVIPAdd
		}

		tk.LogIt(tk.LogDebug, "sock-vip (%s:%v) rwr (%v) added\n",
			w.VIP.String(), w.Port, w.RwPort)

		*w.Status = 0

	} else if w.Work == DpRemove {
		C.llb_del_map_elem(C.LL_DP_SOCK_RWR_MAP, unsafe.Pointer(key))
		return 0
	}
	return 0
}

// DpSockVIPAdd - routine to work on a ebpf local VIP-port rewrite addition
func (e *DpEbpfH) DpSockVIPAdd(w *SockVIPDpWorkQ) int {
	ec := e.DpSockVIPMod(w)
	if ec != 0 {
		*w.Status = DpCreateErr
	} else {
		*w.Status = 0
	}
	return ec
}

// DpSockVIPDel - routine to work on a ebpf local VIP-port rewrite delete
func (e *DpEbpfH) DpSockVIPDel(w *SockVIPDpWorkQ) int {
	ec := e.DpSockVIPMod(w)
	if ec != 0 {
		*w.Status = DpRemoveErr
	} else {
		*w.Status = 0
	}
	return ec
}

//export goMapNotiHandler
func goMapNotiHandler(m *mapNoti) {

	ctKey := (*C.struct_dp_ct_key)(unsafe.Pointer(m.key))

	// Only connection oriented protocols
	if m.addop == 0 || mh.dpEbpf == nil || (ctKey.l4proto != 6 && ctKey.l4proto != 132) {
		return
	}

	goCtEnt := new(DpCtInfo)
	goCtEnt.PKey = C.GoBytes(unsafe.Pointer(m.key), m.key_len)
	if m.addop != 0 {
		// No value in delete op
		goCtEnt.PVal = C.GoBytes(unsafe.Pointer(m.val), m.val_len)
	}

	dpCTMapNotifierWorker(goCtEnt)
	//mh.dpEbpf.ToMapCh <- goCtEnt
}

func dpCTMapNotifierWorker(cti *DpCtInfo) {
	var tact *C.struct_dp_ct_tact
	var act *C.struct_dp_ct_dat
	var addOp bool
	var opStr string

	ctKey := (*C.struct_dp_ct_key)(unsafe.Pointer(&cti.PKey[0]))
	if len(cti.PVal) != 0 {
		tact = (*C.struct_dp_ct_tact)(unsafe.Pointer(&cti.PVal[0]))
		act = &tact.ctd
		if (uint)(act.nid) != mh.dpEbpf.nID {
			return
		}
		addOp = true
		opStr = "Add"
	} else {
		addOp = false
		tact = nil
		act = nil
		opStr = "Delete"
	}

	cti.convDPCt2GoObj(ctKey, act)
	cti.LTs = time.Now()

	if addOp {
		// Need to completely initialize the cti
		mh.mtx.Lock()
		r := mh.zr.Rules.GetLBRuleByID(uint32(act.rid))
		mh.mtx.Unlock()
		if r == nil {
			return
		}
		cti.ServiceIP = r.tuples.l3Dst.addr.IP
		cti.L4ServPort = r.tuples.l4Dst.valMin
		cti.L4ServPortMax = r.tuples.l4Dst.valMax
		cti.BlockNum = r.tuples.pref
		cti.RuleID = uint32(act.rid)
		cti.CI = r.ci
		if r.tuples.l4Prot.val == 6 {
			cti.ServProto = "tcp"
		} else if r.tuples.l4Prot.val == 132 {
			cti.ServProto = "sctp"
		} else {
			return
		}
	}

	mh.dpEbpf.mtx.Lock()
	defer mh.dpEbpf.mtx.Unlock()

	if !addOp {
		cti = mh.dpEbpf.ctMap[cti.Key()]
		if cti == nil || cti.Deleted > 0 {
			return
		}
		cti.Deleted = 1
		cti.XSync = true
		cti.NTs = time.Now()
		// Immediately notify for delete
		//ret := mh.dp.DpXsyncRPC(DpSyncDelete, cti)
		//if ret == 0 {
		//	delete(mh.dpEbpf.ctMap, cti.Key)
		// This is a strange fix - Sometimes loxilb runs as multiple docker
		// instances in the same host. So, the map tracing infra can send notifications
		// generated by other instances here. Depending on the timing, it is possible
		// that the original deleter gets notified after it is handled in the remote
		// instance. This is to handle such special cases.
		//	C.llb_del_map_elem(C.LL_DP_CT_MAP, unsafe.Pointer(cti.PKey[0]))
		//}
	} else {
		cte := mh.dpEbpf.ctMap[cti.Key()]
		if cte != nil {
			if cte.CState == cti.CState && cte.CAct == cti.CAct {
				return
			}
			delete(mh.dpEbpf.ctMap, cti.Key())
		}
		mh.dpEbpf.ctMap[cti.Key()] = cti
		if cti.CState == "est" {
			cti.XSync = true
			cti.NTs = time.Now()
		}
	}

	tk.LogIt(tk.LogTrace, "[CT] %s - %s\n", opStr, cti.String())
}

func dpCTMapBcast() {
	mh.dpEbpf.mtx.Lock()

	for _, cti := range mh.dpEbpf.ctMap {
		if cti.Deleted <= 0 && cti.CState == "est" {
			cti.XSync = true
		}
	}

	mh.dpEbpf.mtx.Unlock()

	cti := new(DpCtInfo)
	cti.Proto = "xsync"
	cti.Sport = uint16(mh.self)
	mh.dp.DpXsyncRPC(DpSyncBcast, cti)
	tk.LogIt(tk.LogInfo, "[CT]  CTBcast Complete \n")
}

func dpCTMapChkUpdates() {
	mh.dpEbpf.mtx.Lock()
	// NOTE: do NOT use defer here — we must release the lock before calling
	// dpCTMapDpuOffloadScan, which acquires mh.dpEbpf.mtx itself.
	var tact C.struct_dp_ct_tact
	var act *C.struct_dp_ct_dat
	var blkCti []DpCtInfo
	var blkDelCti []DpCtInfo

	tc := time.Now()
	fd := C.llb_map2fd(C.LL_DP_CT_MAP)

	if len(mh.dpEbpf.ctMap) > 0 {
		tk.LogIt(tk.LogTrace, "[CT] Map size %d\n", len(mh.dpEbpf.ctMap))
	}

	for _, cti := range mh.dpEbpf.ctMap {
		// tk.LogIt(tk.LogDebug, "[CT] check %s:%s:%v\n", cti.Key, cti.CState, cti.XSync)
		if cti.CState != "est" {
			if C.bpf_map_lookup_elem(C.int(fd), unsafe.Pointer(&cti.PKey[0]), unsafe.Pointer(&tact)) != 0 {
				delete(mh.dpEbpf.ctMap, cti.Key())
				continue
			}

			act = &tact.ctd
			goCtEnt := new(DpCtInfo)
			goCtEnt.convDPCt2GoObj((*C.struct_dp_ct_key)(unsafe.Pointer(&cti.PKey[0])), act)
			goCtEnt.LTs = tc

			if goCtEnt.CState != cti.CState ||
				goCtEnt.CAct != cti.CState {
				goCtEnt.PKey = cti.PKey
				// Key will remain the same but value might change
				goCtEnt.PVal = C.GoBytes(unsafe.Pointer(&tact), C.sizeof_struct_dp_ct_tact)

				// Copy rule associations
				goCtEnt.ServiceIP = cti.ServiceIP
				goCtEnt.L4ServPort = cti.L4ServPort
				goCtEnt.L4ServPortMax = cti.L4ServPortMax
				goCtEnt.BlockNum = cti.BlockNum
				goCtEnt.RuleID = cti.RuleID
				goCtEnt.ServProto = cti.ServProto
				goCtEnt.CI = cti.CI
				delete(mh.dpEbpf.ctMap, cti.Key())
				mh.dpEbpf.ctMap[goCtEnt.Key()] = goCtEnt
				ctStr := goCtEnt.String()
				tk.LogIt(tk.LogTrace, "[CT] %s - %s\n", "update", ctStr)
				if goCtEnt.CState == "est" {
					goCtEnt.XSync = true
					goCtEnt.NTs = tc
				}
				// /33: offload/retry established TCP/UDP flows to DOCA (NAT and non-NAT)
				if (goCtEnt.CState == "est" || goCtEnt.CState == "udp-est") &&
					(goCtEnt.Proto == "tcp" || goCtEnt.Proto == "udp") &&
					mh.dpuMgr != nil {
					if goCtEnt.NatFlags != 0 {
						if err := mh.dpuMgr.ShadowLBFlowOffload(goCtEnt, int(goCtEnt.RuleID)); err != nil {
							// -03: EnqueueRetry for transient DOCA failures
							mh.dpuMgr.EnqueueRetry(goCtEnt.Key(), goCtEnt, true)
						}
					} else {
						// non-NAT route flows — periodic scan retry.
						// cp_ring fires once at CT_SMR_EST; if ARP was unresolved then,
						// RouteFlowOffload returns nil (no d.entries entry created).
						// This scan path retries every CT scan cycle until ARP resolves.
						tk.LogIt(tk.LogDebug, "[CT-DPU] scan retry: non-NAT route flow=%s\n", goCtEnt.Key())
						if err := mh.dpuMgr.ShadowRouteFlowOffload(goCtEnt, int(goCtEnt.RuleID)); err != nil {
							// -03: EnqueueRetry for transient DOCA failures
							mh.dpuMgr.EnqueueRetry(goCtEnt.Key(), goCtEnt, false)
						}
					}
				}
				continue
			}
		} else {
			var b uint64
			var p uint64

			// Make sure CT shadow entries are in sync
			if time.Duration(tc.Sub(cti.LTs).Seconds()) >= time.Duration(5*60) {
				tk.LogIt(tk.LogInfo, "[CT] out-of-sync %s:%s:%v\n", cti.Key(), cti.CState, cti.XSync)
				if C.bpf_map_lookup_elem(C.int(fd), unsafe.Pointer(&cti.PKey[0]), unsafe.Pointer(&tact)) != 0 {
					tk.LogIt(tk.LogInfo, "[CT] out-of-sync not found %s:%s:%v\n", cti.Key(), cti.CState, cti.XSync)
					delete(mh.dpEbpf.ctMap, cti.Key())
					continue
				}
				cti.PVal = C.GoBytes(unsafe.Pointer(&tact), C.sizeof_struct_dp_ct_tact)
				cti.LTs = tc
			}

			if len(cti.PVal) > 0 && cti.XSync == false {
				if time.Duration(tc.Sub(cti.NTs).Seconds()) < time.Duration(60) {
					continue
				}
				if C.bpf_map_lookup_elem(C.int(fd), unsafe.Pointer(&cti.PKey[0]), unsafe.Pointer(&tact)) != 0 {
					tk.LogIt(tk.LogDebug, "[CT] ent not found %s\n", cti.Key())
					//delete(mh.dpEbpf.ctMap, cti.Key)
					cti.Deleted++
					cti.XSync = true
				} else {
					ptact := (*C.struct_dp_ct_tact)(unsafe.Pointer(&cti.PVal[0]))
					ret := C.llb_fetch_map_stats_cached(C.int(C.LL_DP_CT_STATS_MAP), C.uint(ptact.ca.cidx), C.int(0),
						(unsafe.Pointer(&b)), unsafe.Pointer(&p))
					if ret == 0 {
						if cti.Packets != p+uint64(tact.ctd.pb.packets) {
							cti.Bytes = b + uint64(tact.ctd.pb.bytes)
							cti.Packets = p + uint64(tact.ctd.pb.packets)
							cti.XSync = true
							cti.NTs = tc
							cti.LTs = tc
						}
					}
				}
			}
		}
		if cti.XSync == true &&
			time.Duration(tc.Sub(cti.NTs).Seconds()) >= time.Duration(10) {
			tk.LogIt(tk.LogTrace, "[CT] Sync - %s\n", cti.String())

			ret := 0
			if cti.Deleted > 0 {
				//ret = mh.dp.DpXsyncRPC(DpSyncDelete, cti)
				blkDelCti = append(blkDelCti, *cti)
				cti.Deleted++
			} else {
				blkCti = append(blkCti, *cti)
				//ret = mh.dp.DpXsyncRPC(DpSyncAdd, cti)
			}
			if ret == 0 || cti.Deleted > ctiDeleteSyncRetries {
				cti.XSync = false

				if cti.Deleted > 0 {
					// remove DOCA entry before CT map cleanup
					if (cti.Proto == "tcp" || cti.Proto == "udp") && mh.dpuMgr != nil {
						tk.LogIt(tk.LogDebug, "[CT-DPU] XSync delete: removing offload flow=%s\n", cti.Key())
						mh.dpuMgr.ShadowLBFlowRemove(cti)
						// mh.dpEbpf.mtx is already held by the outer dpCTMapChkUpdates lock;
						// no inner Lock/Unlock needed here.
						delete(dpuOffloadedFlows, cti.Key())
					}
					delete(mh.dpEbpf.ctMap, cti.Key())
					// This is a strange fix - See comment above. Do we still need it ?
					// C.llb_del_map_elem(C.LL_DP_CT_MAP, unsafe.Pointer(cti.PKey[0]))
				}
			}
		}

		if len(blkCti) >= blkCtiMaxLen {
			tk.LogIt(tk.LogTrace, "[CT] Block Add Sync - \n")
			tc1 := time.Now()
			mh.dp.DpXsyncRPC(DpSyncAdd, blkCti)
			tc2 := time.Now()
			tk.LogIt(tk.LogTrace, "[CT] Block Add Sync %d took %v- \n", len(blkCti), time.Duration(tc2.Sub(tc1)))
			blkCti = nil
		}

		if len(blkDelCti) >= blkCtiMaxLen {
			tk.LogIt(tk.LogTrace, "[CT] Block Del Sync - \n")
			mh.dp.DpXsyncRPC(DpSyncDelete, blkDelCti)
			blkDelCti = nil
		}
	}

	if len(blkCti) > 0 {
		tc1 := time.Now()
		tk.LogIt(tk.LogTrace, "[CT] Block Add Sync - \n")
		mh.dp.DpXsyncRPC(DpSyncAdd, blkCti)
		tc2 := time.Now()
		tk.LogIt(tk.LogTrace, "[CT] Block Add Sync %d took %v- \n", len(blkCti), time.Duration(tc2.Sub(tc1)))
	}

	if len(blkDelCti) > 0 {
		tk.LogIt(tk.LogTrace, "[CT] Block Del Sync - \n")
		mh.dp.DpXsyncRPC(DpSyncDelete, blkDelCti)
	}

	// Release the CT map lock before the DPU offload scan.
	// dpCTMapDpuOffloadScan acquires mh.dpEbpf.mtx internally to protect
	// dpuOffloadedFlows from goCtHwOffloadHandler; calling it with the lock
	// already held would deadlock.
	mh.dpEbpf.mtx.Unlock()

	// DPU offload: direct CT map scan for established flows (NAT + non-NAT).
	// The kprobe-based notifier may not fire on all kernels, so we scan
	// the eBPF CT map directly to find offload candidates.
	if mh.dpuMgr != nil && mh.dpuMgr.IsEnabled() {
		dpCTMapDpuOffloadScan(fd)
	}
}

// dpuOffloadedFlows tracks flows offloaded to DOCA by the direct scan.
// Key is the CT flow key string; value is the DpCtInfo needed for cleanup.
var dpuOffloadedFlows = make(map[string]*DpCtInfo)

// dpCTMapDpuOffloadScan handles cleanup of DOCA offload entries for flows
// that are no longer present in the eBPF CT map. Offload creation is handled
// by the event-driven goCtHwOffloadHandler callback (via cp_ring perf buffer).
func dpCTMapDpuOffloadScan(fd C.int) {
	var key, nextKey C.struct_dp_ct_key
	var tact C.struct_dp_ct_tact

	// Lock protects dpuOffloadedFlows against concurrent writes from
	// goCtHwOffloadHandler (called from C perf buffer pthread).
	mh.dpEbpf.mtx.Lock()
	if len(dpuOffloadedFlows) == 0 {
		mh.dpEbpf.mtx.Unlock()
		return
	}
	mh.dpEbpf.mtx.Unlock()

	// Collect currently active CT flows from eBPF map.
	// Value is tact.lts (last eBPF-processed packet timestamp, ns) for idle timeout detection.
	// No lock needed here — eBPF map access is thread-safe.
	activeFlows := make(map[string]uint64)

	for C.bpf_map_get_next_key(C.int(fd), unsafe.Pointer(&key), unsafe.Pointer(&nextKey)) == 0 {
		key = nextKey
		if C.bpf_map_lookup_elem(C.int(fd), unsafe.Pointer(&key), unsafe.Pointer(&tact)) != 0 {
			continue
		}

		act := &tact.ctd
		// Only track TCP/UDP flows. Note: rid==0 is valid for non-NAT routing
		// flows — they are offloaded via RouteFlowOffload and must not be skipped.
		if key.l4proto != 6 && key.l4proto != 17 {
			continue
		}

		goCtEnt := new(DpCtInfo)
		goCtEnt.convDPCt2GoObj(&key, act)
		activeFlows[goCtEnt.Key()] = uint64(tact.lts) // capture lts for idle check
	}

	// ctHWOffloadITO: when a flow is DOCA-offloaded, eBPF lts freezes at offload time because
	// all packets (including TCP FIN/RST) are handled by hardware and never reach eBPF.
	// The C-side GC (ll_age_ctmap) uses CT_V4_CPTO=30min — stale entries linger that long.
	// This timeout force-expires entries whose eBPF lts has been frozen for too long.
	//
	// NOTE: the architecturally correct fix is a DOCA TCP FIN/RST detection pipe that sends
	// FIN/RST to to_kernel so the eBPF CT SM processes closes normally. This lts-based
	// check is the interim workaround.
	// LIMITATION: active connections running longer than ctHWOffloadITO from their last
	// eBPF packet (i.e., from offload time, typically ~connection start) will be falsely expired.
	const ctHWOffloadITO = uint64(5 * 60 * 1_000_000_000) // 5 minutes in nanoseconds
	now := uint64(C.get_os_nsecs())

	// Cleanup: remove DOCA entries for flows no longer in eBPF CT map,
	// and force-expire HW-offloaded flows whose eBPF lts has been idle too long.
	// Both NAT and non-NAT entries are tracked in d.entries under "ct" pipeKey.
	mh.dpEbpf.mtx.Lock()
	for flowKey, ct := range dpuOffloadedFlows {
		lts, inEbpf := activeFlows[flowKey]
		if !inEbpf {
			// Flow no longer in eBPF CT map — remove DOCA entry.
			tk.LogIt(tk.LogInfo, "[CT-HW] flow expired → removing offload flow=%s\n", flowKey)
			mh.dpuMgr.ShadowLBFlowRemove(ct)
			delete(dpuOffloadedFlows, flowKey)
			continue
		}
		// Flow still in eBPF map: check lts-based HW idle timeout.
		if lts == 0 || now <= lts || now-lts < ctHWOffloadITO {
			continue
		}
		// Force-expire: eBPF lts frozen too long — connection is likely dead but
		// FIN/RST was handled entirely in DOCA hardware, bypassing eBPF CT SM.
		tk.LogIt(tk.LogInfo, "[CT-DPU] HW-idle timeout: force-expiring flow=%s age=%ds\n",
			flowKey, (now-lts)/1_000_000_000)
		C.llb_del_map_elem(C.LL_DP_CT_MAP, unsafe.Pointer(&ct.PKey[0]))
		mh.dpuMgr.ShadowLBFlowRemove(ct)
		delete(dpuOffloadedFlows, flowKey)
		// Trigger Go ctMap XSync deletion path so it cleans up within ~10s
		// rather than waiting for the next 60s idle check cycle.
		if cte := mh.dpEbpf.ctMap[flowKey]; cte != nil {
			cte.Deleted = 1
			cte.XSync = true
			cte.NTs = time.Now()
		}
	}
	mh.dpEbpf.mtx.Unlock()
}

// dpCtTombstone deletes a CT entry from the eBPF map and cleans up associated
// tracking state. Called by DpDocaBf2.handleAgedEntry when DOCA aging evicts a flow.
// The caller (DOCA worker thread) does NOT hold mh.dpEbpf.mtx — we acquire it here.
func dpCtTombstone(flowKey string, pkey []byte) {
	if len(pkey) == 0 {
		return
	}
	mh.dpEbpf.mtx.Lock()
	defer mh.dpEbpf.mtx.Unlock()

	// Delete from eBPF CT map — same pattern as dpCTMapDpuOffloadScan:4228
	C.llb_del_map_elem(C.LL_DP_CT_MAP, unsafe.Pointer(&pkey[0]))

	// Clean dpuOffloadedFlows tracking map
	delete(dpuOffloadedFlows, flowKey)

	// Mark Go ctMap entry for XSync deletion so it cleans up within ~10s
	if cte := mh.dpEbpf.ctMap[flowKey]; cte != nil {
		cte.Deleted = 1
		cte.XSync = true
		cte.NTs = time.Now()
	}

	tk.LogIt(tk.LogDebug, "[CT-DPU] tombstone: flow=%s removed from eBPF CT map\n", flowKey)
}

// dpMapNotifierWorker - Work on any map notifications
func dpMapNotifierWorker(f chan int, ch chan interface{}) {
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
		select {
		case m := <-ch:
			switch mq := m.(type) {
			case *DpCtInfo:
				dpCTMapNotifierWorker(mq)
			}
		case <-f:
			return
		}
	}
}

// DpCtAdd - routine to work on a ebpf ct add request
func (e *DpEbpfH) DpCtAdd(w *DpCtInfo) int {
	var serv cmn.LbServiceArg

	serv.ServIP = w.ServiceIP.String()
	serv.Proto = w.ServProto
	serv.ServPort = w.L4ServPort
	serv.ServPortMax = w.L4ServPortMax
	serv.BlockNum = w.BlockNum

	mh.mtx.Lock()
	r := mh.zr.Rules.GetLBRuleByServArgs(serv)
	mh.mtx.Unlock()

	if r == nil || len(w.PVal) == 0 || len(w.PKey) == 0 || w.CState != "est" {
		tk.LogIt(tk.LogError, "Invalid CT op/No LB - %v\n", serv)
		return EbpfErrCtAdd
	}

	// Fix few things
	ptact := (*C.struct_dp_ct_tact)(unsafe.Pointer(&w.PVal[0]))
	ptact.ctd.rid = C.ushort(r.ruleNum) // Race-condition here
	ptact.ctd.nid = C.uint(mh.dpEbpf.nID)
	ptact.lts = C.get_os_nsecs()

	mh.dpEbpf.mtx.Lock()
	defer mh.dpEbpf.mtx.Unlock()

	mapKey := w.Key()
	cti := new(DpCtInfo)
	*cti = *w

	cte := mh.dpEbpf.ctMap[mapKey]
	if cte != nil {
		if cte.CState != cti.CState ||
			cte.CAct != cti.CAct {
			delete(mh.dpEbpf.ctMap, mapKey)
			mh.dpEbpf.ctMap[mapKey] = cti
			cte = cti
		}
	} else {
		mh.dpEbpf.ctMap[mapKey] = cti
		cte = cti
	}

	cte.XSync = false
	cte.NTs = time.Now()
	//cte.LTs = cti.NTs
	cte.LTs = time.Now()

	ret := C.llb_add_map_elem(C.LL_DP_CT_MAP, unsafe.Pointer(&cti.PKey[0]), unsafe.Pointer(&cti.PVal[0]))
	if ret != 0 {
		delete(mh.dpEbpf.ctMap, mapKey)
		tk.LogIt(tk.LogError, "ctInfo (%s) rpc add error\n", cti.String())
		return EbpfErrCtAdd
	}

	return 0
}

// DpCtDel - routine to work on a ebpf ct delete request
func (e *DpEbpfH) DpCtDel(w *DpCtInfo) int {
	mh.dpEbpf.mtx.Lock()
	defer mh.dpEbpf.mtx.Unlock()

	if len(w.PKey) == 0 {
		tk.LogIt(tk.LogDebug, "Invalid CT op - %v", w)
		return EbpfErrCtDel
	}

	mapKey := w.Key()
	cti := mh.dpEbpf.ctMap[mapKey]
	if cti == nil {
		tk.LogIt(tk.LogDebug, "ctInfo-key (%v) not present\n", mapKey)
		return 0
	}

	// remove DOCA entry before CT map cleanup (xsync-originated deletions)
	if (cti.Proto == "tcp" || cti.Proto == "udp") && mh.dpuMgr != nil {
		tk.LogIt(tk.LogDebug, "[CT-DPU] DpCtDel: removing offload flow=%s\n", mapKey)
		mh.dpuMgr.ShadowLBFlowRemove(cti)
		delete(dpuOffloadedFlows, mapKey)
	}

	delete(mh.dpEbpf.ctMap, mapKey)
	C.llb_del_map_elem(C.LL_DP_CT_MAP, unsafe.Pointer(&w.PKey[0]))

	return 0
}

// DpCtGetAsync - routine to work on a ebpf ct get async request
func (e *DpEbpfH) DpCtGetAsync() {
	e.ctBcast <- true
}

// DpTakeLock - routine to take underlying DP lock
func (e *DpEbpfH) DpGetLock() {
	C.llb_xh_lock()
}

// DpRelLock - routine to release underlying DP lock
func (e *DpEbpfH) DpRelLock() {
	C.llb_xh_unlock()
}

// DpTableGC - Work on table garbage collection
func (e *DpEbpfH) DpTableGC() {
	e.trigGC <- true
}

//export goCtHwOffloadHandler
func goCtHwOffloadHandler(ev *C.struct_ll_dp_ct_hwev) {
	if mh.dpuMgr == nil || !mh.dpuMgr.IsEnabled() || mh.dpEbpf == nil {
		return
	}

	rid := uint32(ev.rid)
	// NOTE: rid may be 0 for non-NAT routing flows (rule_id only set in NAT/LB path).
	// Guard moved below the NatFlags==0 branch so non-NAT route offload is not blocked.

	// Reconstruct the CT key to look up full entry from eBPF map
	var ctKey C.struct_dp_ct_key
	var tact C.struct_dp_ct_tact
	ctKey.daddr[0] = C.uint(ev.daddr)
	ctKey.saddr[0] = C.uint(ev.saddr)
	ctKey.dport = C.ushort(ev.dport)
	ctKey.sport = C.ushort(ev.sport)
	ctKey.l4proto = C.uchar(ev.l4proto)
	ctKey.zone = 1

	fd := C.llb_map2fd(C.LL_DP_CT_MAP)
	if C.bpf_map_lookup_elem(C.int(fd), unsafe.Pointer(&ctKey), unsafe.Pointer(&tact)) != 0 {
		return
	}

	act := &tact.ctd
	goCtEnt := new(DpCtInfo)
	goCtEnt.convDPCt2GoObj(&ctKey, act)

	if goCtEnt.CState != "est" && goCtEnt.CState != "udp-est" {
		return
	}

	flowKey := goCtEnt.Key()

	if goCtEnt.NatFlags == 0 {
		// Non-NAT established flow: offload as route/switching CT entry
		tk.LogIt(tk.LogDebug, "[CT-HW] non-NAT EST event: flow=%s proto=%s sip=%s dip=%s\n",
			flowKey, goCtEnt.Proto, goCtEnt.SIP.String(), goCtEnt.DIP.String())
		mh.dpEbpf.mtx.Lock()
		if dpuOffloadedFlows[flowKey] != nil {
			mh.dpEbpf.mtx.Unlock()
			tk.LogIt(tk.LogDebug, "[CT-HW] non-NAT already tracked, skip: flow=%s\n", flowKey)
			return
		}
		dpuOffloadedFlows[flowKey] = goCtEnt
		mh.dpEbpf.mtx.Unlock()

		tk.LogIt(tk.LogInfo, "[CT-HW] EST event → route offload flow=%s rid=%d\n",
			flowKey, rid)

		if err := mh.dpuMgr.ShadowRouteFlowOffload(goCtEnt, int(rid)); err != nil {
			// -03: EnqueueRetry for transient DOCA failures on route offload
			mh.dpuMgr.EnqueueRetry(flowKey, goCtEnt, false)
		}
		return
	}

	// NAT path: rid is required for GetLBRuleByID lookup
	if rid == 0 {
		return
	}

	goCtEnt.RuleID = rid

	// Look up rule for ServiceIP
	mh.mtx.Lock()
	r := mh.zr.Rules.GetLBRuleByID(rid)
	mh.mtx.Unlock()
	if r == nil {
		return
	}

	goCtEnt.ServiceIP = r.tuples.l3Dst.addr.IP
	goCtEnt.L4ServPort = r.tuples.l4Dst.valMin

	// bidir kill-switch gate. When OFF, take the legacy path
	// bit-for-bit (do NOT refactor the legacy branch — see RESEARCH).
	if !mh.dpuMgr.GetBidirEnabled() {
		// === Legacy per-direction path (pre- behavior, unchanged) ===
		mh.dpEbpf.mtx.Lock()
		if dpuOffloadedFlows[flowKey] != nil {
			mh.dpEbpf.mtx.Unlock()
			return
		}
		dpuOffloadedFlows[flowKey] = goCtEnt
		mh.dpEbpf.mtx.Unlock()

		tk.LogIt(tk.LogInfo, "[CT-HW] EST event → offload flow=%s rid=%d nat=%v:%d\n",
			flowKey, rid, goCtEnt.NatIP, goCtEnt.NatPort)

		if err := mh.dpuMgr.ShadowLBFlowOffload(goCtEnt, int(rid)); err != nil {
			// -03: EnqueueRetry for transient DOCA failures on LB offload
			mh.dpuMgr.EnqueueRetry(flowKey, goCtEnt, true)
		}
		return
	}

	// === paired path ===
	// The de-dup gate must check WITHOUT writing — the write happens below
	// only if pairing dispatched a successful paired DOCA add.
	// Subsequent re-fires for either direction become no-ops once both keys
	// are in dpuOffloadedFlows.
	mh.dpEbpf.mtx.Lock()
	if dpuOffloadedFlows[flowKey] != nil {
		mh.dpEbpf.mtx.Unlock()
		return
	}
	mh.dpEbpf.mtx.Unlock()
	tk.LogIt(tk.LogInfo, "[CT-HW] EST event (bidir) → flow=%s rid=%d nat=%v:%d natFlags=%d\n",
		flowKey, rid, goCtEnt.NatIP, goCtEnt.NatPort, goCtEnt.NatFlags)

	paired, fwdK, revK := mh.dpuMgr.ShadowPairOrDispatch(goCtEnt, int(rid))
	if paired {
		// Both directions programmed atomically — write the de-dup keys now.
		mh.dpEbpf.mtx.Lock()
		dpuOffloadedFlows[fwdK] = goCtEnt
		dpuOffloadedFlows[revK] = goCtEnt
		mh.dpEbpf.mtx.Unlock()
	}
}

//export goLinuxArpResolver
func goLinuxArpResolver(dIP C.uint) {
	goDest := uint32(dIP)
	utils.ArpResolver(goDest)
}

func SysctlInit() {
	utils.WriteFile("/proc/sys/net/ipv4/conf/all/arp_accept", "1")
	utils.WriteFile("/proc/sys/net/ipv4/conf/default/arp_accept", "1")
	utils.WriteFile("/proc/sys/net/ipv4/ip_forward", "1")
}

func SysctlPostInit() {
	utils.WriteFile("/proc/sys/net/ipv4/conf/llb0/rp_filter", "0")
}

// ============================================================================
// GPU-Aware Load Balancing: Runtime Control and Metrics Management
// ============================================================================

// IsGPUMonitoringEnabled checks if GPU monitoring is currently active
func (e *DpEbpfH) IsGPUMonitoringEnabled() bool {
	if !gpuRoutingEnabled {
		return false
	}
	return e.gpuMonitoringEnabled.Load()
}

// EnableGPUMonitoring activates GPU-aware routing and starts cleanup thread
func (e *DpEbpfH) EnableGPUMonitoring() error {
	if e.gpuMonitoringEnabled.Load() {
		return fmt.Errorf("GPU monitoring already enabled")
	}

	// Check if GPU routing is available at compile-time
	if !gpuRoutingEnabled {
		return fmt.Errorf("GPU routing not compiled: rebuild with -DHAVE_DP_GPU_ROUTING=1 in CFLAGS")
	}

	// Check if GPU routing maps are loaded (runtime check)
	if e.routingModeMapFD <= 0 || e.workerGPUStatsMapFD <= 0 || e.endpointToGPUIndexMapFD <= 0 {
		return fmt.Errorf("GPU routing maps not loaded (check eBPF program compilation)")
	}

	// Update eBPF routing mode to GPU-aware
	if err := e.setRoutingMode(true); err != nil {
		return fmt.Errorf("failed to enable eBPF routing mode: %w", err)
	}

	// PRODUCTION CRITICAL: Start conversation cleanup background thread
	e.conversationCleanupStop = make(chan struct{})
	e.conversationCleanupTicker = time.NewTicker(5 * time.Minute)
	// B1: best-effort skip; relies on process exit (RESEARCH §Open Q5).
	go e.conversationCleanupThread()

	// Update userspace flag
	e.gpuMonitoringEnabled.Store(true)

	tk.LogIt(tk.LogInfo, "GPU-aware load balancing ENABLED (conversation cleanup every 5 minutes)\n")
	return nil
}

// DisableGPUMonitoring deactivates GPU-aware routing and stops cleanup thread
func (e *DpEbpfH) DisableGPUMonitoring() error {
	if !e.gpuMonitoringEnabled.Load() {
		return fmt.Errorf("GPU monitoring already disabled")
	}

	// PRODUCTION CRITICAL: Stop conversation cleanup background thread
	if e.conversationCleanupTicker != nil {
		e.conversationCleanupTicker.Stop()
		close(e.conversationCleanupStop)
	}

	// Update eBPF routing mode to standard CHWBL
	if err := e.setRoutingMode(false); err != nil {
		return fmt.Errorf("failed to disable eBPF routing mode: %w", err)
	}

	// Update userspace flag
	e.gpuMonitoringEnabled.Store(false)

	tk.LogIt(tk.LogInfo, "GPU-aware load balancing DISABLED, falling back to standard CHWBL\n")
	return nil
}

// setRoutingMode updates eBPF routing_mode_map
func (e *DpEbpfH) setRoutingMode(gpuAware bool) error {
	// Check if GPU routing maps are available
	if e.routingModeMapFD <= 0 {
		return fmt.Errorf("routing_mode_map not available (GPU routing not compiled)")
	}

	var mode uint8 = 0 // 0 = standard CHWBL
	if gpuAware {
		mode = 1 // 1 = GPU-aware
	}

	key := uint32(0)
	ret := C.bpf_map_update_elem(
		C.int(e.routingModeMapFD),
		unsafe.Pointer(&key),
		unsafe.Pointer(&mode),
		C.BPF_ANY,
	)

	if ret != 0 {
		return fmt.Errorf("bpf_map_update_elem failed: errno=%d", ret)
	}

	tk.LogIt(tk.LogDebug, "Routing mode updated: %d (0=CHWBL, 1=GPU-aware)\n", mode)
	return nil
}

// GetGPUMonitoringStatus returns current GPU monitoring state
func (e *DpEbpfH) GetGPUMonitoringStatus() *GPUMonitoringStatus {
	if !gpuRoutingEnabled {
		return &GPUMonitoringStatus{
			Enabled:       false,
			RoutingMode:   "disabled",
			EbpfMapLoaded: false,
		}
	}
	var routingMode string
	if e.gpuMonitoringEnabled.Load() {
		routingMode = "gpu_aware"
	} else {
		routingMode = "standard_chwbl"
	}

	// Count active workers and find last update time
	workerCount := 0
	var lastUpdate time.Time
	e.workerMetrics.Range(func(key, value interface{}) bool {
		workerCount++
		metrics := value.(WorkerMetrics)
		if metrics.LastUpdate.After(lastUpdate) {
			lastUpdate = metrics.LastUpdate
		}
		return true
	})

	return &GPUMonitoringStatus{
		Enabled:           e.gpuMonitoringEnabled.Load(),
		RoutingMode:       routingMode,
		WorkerCount:       workerCount,
		LastMetricsUpdate: lastUpdate,
		EbpfMapLoaded:     e.workerGPUStatsMapFD > 0,
	}
}

// CheckMetricsStaleness returns list of workers with stale metrics (>5s old)
// This helps detect when metrics agent has stopped updating
func (e *DpEbpfH) CheckMetricsStaleness() map[string]time.Duration {
	if !gpuRoutingEnabled {
		return make(map[string]time.Duration)
	}
	staleWorkers := make(map[string]time.Duration)
	now := time.Now()
	stalenessThreshold := 5 * time.Second // Must match METRICS_STALENESS_SEC in sockproxy.h

	e.workerMetrics.Range(func(key, value interface{}) bool {
		endpointIP := key.(string)
		metrics := value.(WorkerMetrics)

		age := now.Sub(metrics.LastUpdate)
		if age > stalenessThreshold {
			staleWorkers[endpointIP] = age
		}
		return true
	})

	return staleWorkers
}

// GetWorkerMetricsAge returns the age of metrics for all workers
// Useful for monitoring and debugging metrics agent health
func (e *DpEbpfH) GetWorkerMetricsAge() map[string]time.Duration {
	if !gpuRoutingEnabled {
		return make(map[string]time.Duration)
	}
	workerAges := make(map[string]time.Duration)
	now := time.Now()

	e.workerMetrics.Range(func(key, value interface{}) bool {
		endpointIP := key.(string)
		metrics := value.(WorkerMetrics)
		workerAges[endpointIP] = now.Sub(metrics.LastUpdate)
		return true
	})

	return workerAges
}

// conversationCleanupThread runs background cleanup every 5 minutes
func (e *DpEbpfH) conversationCleanupThread() {
	tk.LogIt(tk.LogInfo, "Conversation cleanup thread started (interval: 5 minutes)\n")

	for {
		select {
		case <-e.conversationCleanupTicker.C:
			// Cleanup conversations inactive for more than 1 hour
			cutoffTime := time.Now().Add(-1 * time.Hour)
			deleted, oldestHours, err := e.CleanupStaleConversations(cutoffTime)
			if err != nil {
				tk.LogIt(tk.LogError, "Automatic conversation cleanup failed: %v\n", err)
			} else {
				tk.LogIt(tk.LogInfo, "Automatic conversation cleanup: deleted=%d, oldest_remaining=%.1fh\n",
					deleted, oldestHours)
			}

			// Check for stale metrics (agent health monitoring)
			if e.gpuMonitoringEnabled.Load() {
				staleWorkers := e.CheckMetricsStaleness()
				if len(staleWorkers) > 0 {
					tk.LogIt(tk.LogWarning, "⚠️  METRICS STALENESS DETECTED: %d workers have stale metrics (>5s)\n", len(staleWorkers))
					for endpoint, age := range staleWorkers {
						tk.LogIt(tk.LogWarning, "  - %s: metrics are %.1fs old (STALE - will fallback to hash routing)\n",
							endpoint, age.Seconds())
					}
					tk.LogIt(tk.LogWarning, "  → Action: Check metrics agent health. GPU-aware routing has fallen back to hash-based CHWBL.\n")
				}
			}

		case <-e.conversationCleanupStop:
			tk.LogIt(tk.LogInfo, "Conversation cleanup thread stopped\n")
			return
		}
	}
}

// CleanupStaleConversations removes conversation mappings older than cutoffTime
// Returns: (deleted_count, oldest_remaining_hours, error)
func (e *DpEbpfH) CleanupStaleConversations(cutoffTime time.Time) (int, float64, error) {
	if !gpuRoutingEnabled {
		return 0, 0, fmt.Errorf("GPU routing not compiled")
	}
	e.conversationMapMutex.Lock()
	defer e.conversationMapMutex.Unlock()

	deletedCount := 0
	oldestRemaining := time.Time{}

	// NOTE: This is a placeholder implementation
	// In the actual implementation, this would iterate through proxy_map_ent_t
	// entries and clean up conversation_mapping_t structures
	// See IMPL_2_EBPF_INTEGRATION.md for full implementation details

	tk.LogIt(tk.LogDebug, "Conversation cleanup completed: deleted=%d\n", deletedCount)

	// Calculate oldest remaining age in hours
	var oldestRemainingHours float64
	if !oldestRemaining.IsZero() {
		oldestRemainingHours = time.Since(oldestRemaining).Hours()
	}

	return deletedCount, oldestRemainingHours, nil
}

// StoreWorkerMetricsCache updates ONLY the Go-side workerMetrics cache (the
// REST introspection/staleness surface). The built-in vLLM scraper uses it so
// its samples are visible over REST; the eBPF hysteresis map is NOT touched —
// the scraper feeds the data plane through its own cgo bridge
// (llb_ai_update_ep_queue_depth), and double-pushing here would fight the
// REST push path's hysteresis bookkeeping.
func (e *DpEbpfH) StoreWorkerMetricsCache(endpointIP string, metrics WorkerMetrics) {
	e.workerMetrics.Store(endpointIP, metrics)
}

// UpdateWorkerMetrics updates both in-memory cache and eBPF map
func (e *DpEbpfH) UpdateWorkerMetrics(endpointIP string, req interface{}) error {
	if !gpuRoutingEnabled {
		return fmt.Errorf("GPU routing not compiled")
	}
	// Type assertion to WorkerMetrics-compatible struct
	var metrics WorkerMetrics
	metrics.EndpointIP = endpointIP

	// Handle the request from API handler
	switch v := req.(type) {
	case *WorkerMetrics:
		metrics = *v
	default:
		// Use reflection to extract fields from anonymous struct (from API handler)
		rv := reflect.ValueOf(req)
		if rv.Kind() == reflect.Ptr {
			rv = rv.Elem()
		}

		if rv.Kind() != reflect.Struct {
			return fmt.Errorf("invalid metrics type: expected struct, got %v", rv.Kind())
		}

		// Extract required fields using reflection
		if queuedField := rv.FieldByName("QueuedRequests"); queuedField.IsValid() {
			metrics.QueuedRequests = uint32(queuedField.Uint())
		}
		if swappedField := rv.FieldByName("SwappedRequests"); swappedField.IsValid() {
			metrics.SwappedRequests = uint32(swappedField.Uint())
		}
		if kvCacheField := rv.FieldByName("KVCacheUsagePerc"); kvCacheField.IsValid() {
			metrics.KVCacheUsagePerc = uint32(kvCacheField.Uint())
		}
		if numBlocksField := rv.FieldByName("NumGPUBlocks"); numBlocksField.IsValid() {
			metrics.NumGPUBlocks = uint32(numBlocksField.Uint())
		}
		if lastUpdateField := rv.FieldByName("LastUpdate"); lastUpdateField.IsValid() {
			if t, ok := lastUpdateField.Interface().(time.Time); ok {
				metrics.LastUpdate = t
			}
		}
		if overloadedField := rv.FieldByName("IsOverloaded"); overloadedField.IsValid() {
			metrics.IsOverloaded = overloadedField.Bool()
		}
		if overloadStartField := rv.FieldByName("OverloadStart"); overloadStartField.IsValid() {
			if t, ok := overloadStartField.Interface().(time.Time); ok {
				metrics.OverloadStart = t
			}
		}
	}

	// CRITICAL: Check if GPU monitoring is enabled
	if !e.gpuMonitoringEnabled.Load() {
		return fmt.Errorf("GPU monitoring is disabled")
	}

	// CRITICAL: Check if GPU maps are available
	if e.workerGPUStatsMapFD <= 0 {
		return fmt.Errorf("GPU worker stats map not available (HAVE_DP_GPU_ROUTING not compiled)")
	}

	// CRITICAL FIX: Strip port from endpoint_ip if present
	// API receives "IP:port" format, but index map uses just "IP"
	endpointIPOnly := endpointIP
	if idx := strings.LastIndex(endpointIP, ":"); idx != -1 {
		endpointIPOnly = endpointIP[:idx]
		tk.LogIt(tk.LogDebug, "Worker metrics: stripped port from %s → %s\n", endpointIP, endpointIPOnly)
	}

	// Get or assign endpoint index (using IP only, not IP:port)
	epIdx, err := e.GetOrAssignEndpointIndex(endpointIPOnly)
	if err != nil {
		return fmt.Errorf("failed to get endpoint index: %w", err)
	}

	// Store in userspace cache
	e.workerMetrics.Store(endpointIP, metrics)

	// Sync to eBPF map
	if err := e.updateWorkerGPUStatsMap(epIdx, &metrics); err != nil {
		return fmt.Errorf("failed to update eBPF map: %w", err)
	}

	tk.LogIt(tk.LogDebug, "Worker metrics updated: ep=%s idx=%d queue=%d swapped=%d kv_cache=%d%%\n",
		endpointIP, epIdx, metrics.QueuedRequests, metrics.SwappedRequests, metrics.KVCacheUsagePerc)

	return nil
}

// GetOrAssignEndpointIndex returns existing GPU worker index or assigns a new one
func (e *DpEbpfH) GetOrAssignEndpointIndex(endpointIP string) (uint32, error) {
	if !gpuRoutingEnabled {
		return 0, fmt.Errorf("GPU routing not compiled")
	}
	if idx, exists := e.workerIndexMap.Load(endpointIP); exists {
		return idx.(uint32), nil
	}

	newIdx := e.nextEndpointIndex.Add(1) - 1
	if newIdx >= 512 {
		return 0, fmt.Errorf("exceeded max GPU workers (512)")
	}

	actual, loaded := e.workerIndexMap.LoadOrStore(endpointIP, newIdx)
	if loaded {
		return actual.(uint32), nil
	}

	tk.LogIt(tk.LogInfo, "GPU worker assigned: %s → index %d\n", endpointIP, newIdx)
	return newIdx, nil
}

// UpdateEndpointToGPUIndexMap populates the eBPF map that maps endpoint IP:port to GPU worker index
// This is CRITICAL for GPU-aware selection algorithm to work - without this, all lookups fail
func (e *DpEbpfH) UpdateEndpointToGPUIndexMap(epIP net.IP, epPort uint16, gpuIdx uint32) error {
	if !gpuRoutingEnabled {
		return fmt.Errorf("GPU routing not compiled")
	}
	if e.endpointToGPUIndexMapFD <= 0 {
		return fmt.Errorf("endpoint_to_gpu_index_map not initialized (FD=%d)", e.endpointToGPUIndexMapFD)
	}

	// Prepare key structure (must match endpoint_to_gpu_key in llb_dpapi.h)
	// Store in network byte order to match C lookup expectations
	var key C.struct_endpoint_to_gpu_key

	if epIP.To4() != nil {
		ipHost := tk.IPtonl(epIP)
		key.ip = C.__be32(tk.Htonl(ipHost))
		key.port = C.__be16(tk.Htons(epPort))
		key._pad = 0
	} else {
		return fmt.Errorf("IPv6 endpoints not yet supported for GPU worker mapping")
	}

	gpuIndex := C.__u32(gpuIdx)

	// DEBUG: Show exact key values being stored
	tk.LogIt(tk.LogDebug, "GPU-Aware DEBUG: Storing key ip_net=0x%08x port_net=0x%04x → GPU index %d\n",
		uint32(key.ip), uint16(key.port), gpuIdx)

	ret := C.bpf_map_update_elem(
		C.int(e.endpointToGPUIndexMapFD),
		unsafe.Pointer(&key),
		unsafe.Pointer(&gpuIndex),
		C.BPF_ANY,
	)

	if ret != 0 {
		return fmt.Errorf("failed to map endpoint %s:%d to GPU worker %d (errno=%d)",
			epIP.String(), epPort, gpuIdx, ret)
	}

	tk.LogIt(tk.LogInfo, "GPU-Aware: eBPF map updated %s:%d → GPU global index %d\n",
		epIP.String(), epPort, gpuIdx)

	return nil
}

// deleteEndpointFromGPUIndexMap removes an endpoint from the GPU worker mapping
func (e *DpEbpfH) DeleteEndpointFromGPUIndexMap(epIP net.IP, epPort uint16) error {
	if !gpuRoutingEnabled {
		return fmt.Errorf("GPU routing not compiled")
	}
	if e.endpointToGPUIndexMapFD <= 0 {
		return nil // Map not initialized, nothing to delete
	}

	var key C.struct_endpoint_to_gpu_key

	if epIP.To4() != nil {
		// Use network byte order to match insert
		ipHost := tk.IPtonl(epIP)
		key.ip = C.__be32(tk.Htonl(ipHost))
		key.port = C.__be16(tk.Htons(epPort))
		key._pad = 0
	} else {
		return nil // IPv6 not supported yet
	}

	ret := C.bpf_map_delete_elem(
		C.int(e.endpointToGPUIndexMapFD),
		unsafe.Pointer(&key),
	)

	if ret != 0 {
		tk.LogIt(tk.LogDebug, "GPU-Aware: Failed to delete endpoint %s:%d from GPU map (errno=%d)\n",
			epIP.String(), epPort, ret)
	} else {
		tk.LogIt(tk.LogDebug, "GPU-Aware: Deleted endpoint %s:%d from GPU map\n",
			epIP.String(), epPort)
	}

	return nil
}

// updateWorkerGPUStatsMap syncs metrics to eBPF map
func (e *DpEbpfH) updateWorkerGPUStatsMap(epIdx uint32, metrics *WorkerMetrics) error {
	// Check if GPU maps are available
	if e.workerGPUStatsMapFD <= 0 {
		return fmt.Errorf("worker_gpu_stats_map not available (HAVE_DP_GPU_ROUTING not compiled)")
	}

	// STEP 1: Get old stats from eBPF map (for version increment decision)
	var oldStats C.struct_worker_gpu_stats
	key := C.__u32(epIdx)
	ret := C.bpf_map_lookup_elem(
		C.int(e.workerGPUStatsMapFD),
		unsafe.Pointer(&key),
		unsafe.Pointer(&oldStats),
	)

	hasOldStats := (ret == 0) // false if this is first metrics update

	// STEP 2: Convert new Go struct to C struct
	var newStats C.struct_worker_gpu_stats
	newStats.queued_requests = C.__u32(metrics.QueuedRequests)
	newStats.swapped_requests = C.__u32(metrics.SwappedRequests)
	newStats.kv_cache_usage_perc = C.__u32(metrics.KVCacheUsagePerc)
	newStats.num_gpu_blocks = C.__u32(metrics.NumGPUBlocks)

	// Set timestamps (convert to seconds since epoch)
	newStats.last_update_ts = C.__u64(metrics.LastUpdate.Unix())
	if metrics.IsOverloaded {
		newStats.is_overloaded = 1
		newStats.overload_start_ts = C.__u64(metrics.OverloadStart.Unix())
	} else {
		newStats.is_overloaded = 0
		newStats.overload_start_ts = 0
	}

	// STEP 3: Determine if metrics changed significantly (version increment decision)
	// Use same scoring logic as dynamic routing for consistency
	shouldIncrementVersion := false

	if hasOldStats {
		// Check if metrics changed significantly using score-based comparison
		// This ensures version increments only when change affects routing decisions
		shouldIncrementVersion = e.metricsChangedSignificantly(&oldStats, &newStats, metrics.EndpointIP)

		if shouldIncrementVersion {
			// Increment version - this will trigger revalidation of cached conversations
			newStats.metrics_version = oldStats.metrics_version + 1
			tk.LogIt(tk.LogDebug, "Metrics version incremented: ep=%s idx=%d ver=%d→%d\n",
				metrics.EndpointIP, epIdx, uint64(oldStats.metrics_version), uint64(newStats.metrics_version))
		} else {
			// Keep same version - cached conversations will skip revalidation
			newStats.metrics_version = oldStats.metrics_version
		}
	} else {
		// First metrics update - start at version 1
		newStats.metrics_version = 1
		shouldIncrementVersion = true
		tk.LogIt(tk.LogDebug, "Metrics initialized: ep=%s idx=%d ver=1 (first update)\n",
			metrics.EndpointIP, epIdx)
	}

	// STEP 4: Update eBPF map with new stats (including version)
	ret = C.bpf_map_update_elem(
		C.int(e.workerGPUStatsMapFD),
		unsafe.Pointer(&key),
		unsafe.Pointer(&newStats),
		C.BPF_ANY,
	)

	if ret != 0 {
		return fmt.Errorf("bpf_map_update_elem failed: errno=%d", ret)
	}

	return nil
}

// metricsChangedSignificantly determines if metrics changed enough to warrant version increment
// Uses same scoring calculation as dynamic routing for consistency
func (e *DpEbpfH) metricsChangedSignificantly(
	oldStats *C.struct_worker_gpu_stats,
	newStats *C.struct_worker_gpu_stats,
	endpointIP string) bool {

	// Check 1: Overload state changed (always significant)
	if oldStats.is_overloaded != newStats.is_overloaded {
		tk.LogIt(tk.LogDebug, "Metrics: ep=%s overload state changed %d→%d (significant)\n",
			endpointIP, oldStats.is_overloaded, newStats.is_overloaded)
		return true
	}

	// Check 2: Calculate scores using same formula as dynamic routing
	// For simplicity, use default catalog weights (can be enhanced to lookup actual catalog)
	oldScore := e.calculateWorkerScore(oldStats)
	newScore := e.calculateWorkerScore(newStats)

	// Score delta threshold: 10% of old score (or 100 if old_score is 0)
	deltaThreshold := oldScore / 10
	if deltaThreshold < 100 {
		deltaThreshold = 100
	}

	scoreDelta := uint32(0)
	if newScore > oldScore {
		scoreDelta = newScore - oldScore
	} else {
		scoreDelta = oldScore - newScore
	}

	if scoreDelta > deltaThreshold {
		tk.LogIt(tk.LogDebug, "Metrics: ep=%s score changed %d→%d (delta=%d > threshold=%d, significant)\n",
			endpointIP, oldScore, newScore, scoreDelta, deltaThreshold)
		return true
	}

	tk.LogIt(tk.LogDebug, "Metrics: ep=%s score changed %d→%d (delta=%d ≤ threshold=%d, skip version increment)\n",
		endpointIP, oldScore, newScore, scoreDelta, deltaThreshold)
	return false
}

// calculateWorkerScore computes routing score using same formula as C code
// This ensures consistency between version increment decision and routing selection
func (e *DpEbpfH) calculateWorkerScore(stats *C.struct_worker_gpu_stats) uint32 {
	// Use default weights (50/30/20) - can be enhanced to lookup catalog
	const (
		queueWeight   = 50
		swapWeight    = 30
		kvCacheWeight = 20
	)

	// TIER 1: Queue depth (EXPONENTIAL - latency killer)
	queuePenalty := uint32(stats.queued_requests) * uint32(stats.queued_requests)

	// TIER 2: Swap penalty (LINEAR - each swap = 30s model reload)
	swapPenalty := uint32(stats.swapped_requests) * 100

	// TIER 3: KV cache (EXPONENTIAL when >80% - OOM risk)
	kvPenalty := uint32(0)
	if stats.kv_cache_usage_perc > 80 {
		kvPenalty = uint32(stats.kv_cache_usage_perc) * uint32(stats.kv_cache_usage_perc)
	} else {
		kvPenalty = uint32(stats.kv_cache_usage_perc)
	}

	// Composite score
	score := (queuePenalty * queueWeight) +
		(swapPenalty * swapWeight) +
		(kvPenalty * kvCacheWeight)

	return score
}

// GetAllWorkerMetrics retrieves all cached worker metrics
func (e *DpEbpfH) GetAllWorkerMetrics() []interface{} {
	if !gpuRoutingEnabled {
		return []interface{}{}
	}
	var result []interface{}

	e.workerMetrics.Range(func(key, value interface{}) bool {
		metrics := value.(WorkerMetrics)
		result = append(result, metrics)
		return true
	})

	return result
}

// DeleteWorkerMetrics removes endpoint from tracking
func (e *DpEbpfH) DeleteWorkerMetrics(endpointIP string) error {
	if !gpuRoutingEnabled {
		return fmt.Errorf("GPU routing not compiled")
	}
	// Get endpoint index
	idx, exists := e.workerIndexMap.Load(endpointIP)
	if !exists {
		tk.LogIt(tk.LogWarning, "Worker metrics deletion: endpoint %s not found in index map (may have been cleared)\n", endpointIP)
		return fmt.Errorf("endpoint not found: %s", endpointIP)
	}

	epIdx := idx.(uint32)

	// Delete from eBPF map
	key := C.__u32(epIdx)
	ret := C.bpf_map_delete_elem(
		C.int(e.workerGPUStatsMapFD),
		unsafe.Pointer(&key),
	)

	if ret != 0 && ret != -C.ENOENT {
		return fmt.Errorf("failed to delete GPU worker %d metrics (errno=%d)", epIdx, ret)
	}

	// Delete from userspace caches
	e.workerMetrics.Delete(endpointIP)
	e.workerIndexMap.Delete(endpointIP)

	tk.LogIt(tk.LogInfo, "GPU worker metrics deleted: %s (index %d)\n", endpointIP, epIdx)
	return nil
}

// SetServiceTracingCatalog sets catalog_id for deep inspection via simple C API
// Called from rules.go Part 8B when trace_type is specified
func (e *DpEbpfH) SetServiceTracingCatalog(
	vipIP net.IP,
	port uint16,
	protocol uint8,
	catalogID uint16) error {

	// Convert VIP to network byte order (big endian) - same as DpLBEndpointHealthUpdate
	vipNetOrder := tk.IPtonl(vipIP)

	// Convert port to network byte order - same as DpLBEndpointHealthUpdate
	portNetOrder := tk.Htons(port)

	tk.LogIt(tk.LogDebug, "[CATALOG] Looking for service: vip=%v port=%d proto=%d (converted: 0x%08x:0x%04x)\n",
		vipIP, port, protocol, vipNetOrder, portNetOrder)

	// Call C API to set catalog_id in sockproxy
	ret := C.proxy_set_service_catalog(
		C.uint32_t(vipNetOrder),
		C.uint16_t(portNetOrder),
		C.uint8_t(protocol),
		C.uint16_t(catalogID),
	)

	if ret != 0 {
		return fmt.Errorf("failed to set catalog_id (service not found in proxy_map)")
	}

	tk.LogIt(tk.LogInfo, "[CATALOG] Service %s:%d using catalog_id=%d for deep inspection\n",
		vipIP.String(), port, catalogID)

	return nil
}

// NetTraceParserRegistryGet returns the TraceParserRegistry for API operations
func (e *DpEbpfH) NetTraceParserRegistryGet() (interface{}, error) {
	if mh.ringConsumer == nil {
		return nil, fmt.Errorf("tracing not enabled")
	}

	registry := mh.ringConsumer.GetParserRegistry()
	if registry == nil {
		return nil, fmt.Errorf("parser registry not initialized")
	}

	return registry, nil
}

// NetTraceCatalogInfoGet returns catalog name and parser_type for a given catalog ID
func (e *DpEbpfH) NetTraceCatalogInfoGet(catalogID uint16) (string, string, error) {
	if e.tracingCatalogManager == nil {
		return "", "", fmt.Errorf("tracing catalog manager not initialized")
	}

	// Look up catalog by ID
	catalog, ok := e.tracingCatalogManager.catalogsByID[catalogID]
	if !ok {
		return "", "", fmt.Errorf("catalog ID %d not found", catalogID)
	}

	return catalog.CatalogName, catalog.DeepInspection.ParserType, nil
}

// NetTraceParserListGet returns list of available parsers with metadata
func (e *DpEbpfH) NetTraceParserListGet() ([]cmn.NetTraceParserMeta, error) {
	if mh.ringConsumer == nil {
		return nil, fmt.Errorf("tracing not enabled")
	}

	registry := mh.ringConsumer.GetParserRegistry()
	if registry == nil {
		return nil, fmt.Errorf("parser registry not initialized")
	}

	parserNames := registry.ListAvailableParsers()
	var parsers []cmn.NetTraceParserMeta

	for _, name := range parserNames {
		parser := registry.GetParserByName(name)
		if parser == nil {
			continue
		}

		meta := parser.Metadata()
		parsers = append(parsers, cmn.NetTraceParserMeta{
			Name:           meta.Name,
			Version:        meta.Version,
			Protocol:       meta.Protocol,
			SupportedPaths: meta.SupportedPaths,
		})
	}

	return parsers, nil
}

// NetTraceCatalogParserGet returns the parser name assigned to a catalog
func (e *DpEbpfH) NetTraceCatalogParserGet(catalogID uint16) (string, error) {
	if mh.ringConsumer == nil {
		return "", fmt.Errorf("tracing not enabled")
	}

	registry := mh.ringConsumer.GetParserRegistry()
	if registry == nil {
		return "", fmt.Errorf("parser registry not initialized")
	}

	parserName := registry.GetCatalogParserName(catalogID)
	if parserName == "" {
		return "", fmt.Errorf("no parser assigned to catalog %d", catalogID)
	}

	return parserName, nil
}

// NetTraceCatalogParserUpdate updates the parser assignment for a catalog
func (e *DpEbpfH) NetTraceCatalogParserUpdate(catalogID uint16, parserName string) error {
	if mh.ringConsumer == nil {
		return fmt.Errorf("tracing not enabled")
	}

	registry := mh.ringConsumer.GetParserRegistry()
	if registry == nil {
		return fmt.Errorf("parser registry not initialized")
	}

	// Validate parser exists
	parser := registry.GetParserByName(parserName)
	if parser == nil {
		return fmt.Errorf("parser '%s' not found", parserName)
	}

	// Update catalog -> parser mapping
	return registry.SyncCatalogParser(catalogID, parserName)
}

// NetTraceCatalogParserDelete removes the parser assignment for a catalog
func (e *DpEbpfH) NetTraceCatalogParserDelete(catalogID uint16) error {
	if mh.ringConsumer == nil {
		return fmt.Errorf("tracing not enabled")
	}

	registry := mh.ringConsumer.GetParserRegistry()
	if registry == nil {
		return fmt.Errorf("parser registry not initialized")
	}

	registry.RemoveCatalogParser(catalogID)
	return nil
}

// DpProxyConfigureMTLS - Configure mTLS for a sockproxy rule
// This function updates the proxy_arg for an existing rule to add mTLS configuration.
// mTLS config is not stored in eBPF maps since it's only needed by sockproxy userspace code.
func DpProxyConfigureMTLS(serviceIP net.IP, port uint16, proto uint8, frontendCfg *cmn.MTLSFrontendConfig, backendCfg *cmn.MTLSBackendConfig) int {
	tk.LogIt(tk.LogInfo, "[DP] Configuring mTLS for %s:%d proto=%d\n", serviceIP.String(), port, proto)

	// Build proxy key to identify the rule
	var proxyKey C.struct_proxy_ent
	if serviceIP.To4() != nil {
		proxyKey.xip = C.uint(tk.IPtonl(serviceIP))
	} else {
		tk.LogIt(tk.LogError, "[DP] mTLS: IPv6 not yet supported\n")
		return -1
	}
	proxyKey.xport = C.ushort(tk.Htons(port))
	proxyKey.protocol = C.uchar(proto)

	// Prepare frontend mTLS config
	var frontendC *C.struct_mtls_frontend_config
	if frontendCfg != nil {
		frontendC = (*C.struct_mtls_frontend_config)(C.malloc(C.sizeof_struct_mtls_frontend_config))
		defer C.free(unsafe.Pointer(frontendC))

		C.memset(unsafe.Pointer(frontendC), 0, C.sizeof_struct_mtls_frontend_config)

		// Map client_cert_mode string to numeric value
		switch frontendCfg.ClientCertMode {
		case "required":
			frontendC.mode = 2
		case "optional":
			frontendC.mode = 1
		default: // "disabled" or empty
			frontendC.mode = 0
		}

		if frontendCfg.ClientCAPath != "" {
			cPath := C.CString(frontendCfg.ClientCAPath)
			defer C.free(unsafe.Pointer(cPath))
			C.strncpy(&frontendC.client_ca_path[0], cPath, 255)
		}

		if frontendCfg.ClientCACertData != "" {
			cData := C.CString(frontendCfg.ClientCACertData)
			defer C.free(unsafe.Pointer(cData))
			C.strncpy(&frontendC.client_ca_cert_data[0], cData, 4095)
		}

		if frontendCfg.RequireClientCN {
			frontendC.require_client_cn = 1
		}

		if frontendCfg.ClientCNPattern != "" {
			cPattern := C.CString(frontendCfg.ClientCNPattern)
			defer C.free(unsafe.Pointer(cPattern))
			C.strncpy(&frontendC.client_cn_pattern[0], cPattern, 255)
		}

		tk.LogIt(tk.LogInfo, "[DP] Frontend mTLS: mode=%s ca_path=%s require_cn=%v pattern=%s\n",
			frontendCfg.ClientCertMode, frontendCfg.ClientCAPath, frontendCfg.RequireClientCN, frontendCfg.ClientCNPattern)
	}

	// Prepare backend mTLS config
	var backendC *C.struct_mtls_backend_config
	if backendCfg != nil {
		backendC = (*C.struct_mtls_backend_config)(C.malloc(C.sizeof_struct_mtls_backend_config))
		defer C.free(unsafe.Pointer(backendC))

		C.memset(unsafe.Pointer(backendC), 0, C.sizeof_struct_mtls_backend_config)

		if backendCfg.VerifyServerCert {
			backendC.verify_server_cert = 1
		}

		if backendCfg.BackendCAPath != "" {
			cPath := C.CString(backendCfg.BackendCAPath)
			defer C.free(unsafe.Pointer(cPath))
			C.strncpy(&backendC.backend_ca_path[0], cPath, 255)
		}

		if backendCfg.ClientCertPath != "" {
			cPath := C.CString(backendCfg.ClientCertPath)
			defer C.free(unsafe.Pointer(cPath))
			C.strncpy(&backendC.client_cert_path[0], cPath, 255)
		}

		if backendCfg.ClientKeyPath != "" {
			cPath := C.CString(backendCfg.ClientKeyPath)
			defer C.free(unsafe.Pointer(cPath))
			C.strncpy(&backendC.client_key_path[0], cPath, 255)
		}

		if backendCfg.ClientCertData != "" {
			cData := C.CString(backendCfg.ClientCertData)
			defer C.free(unsafe.Pointer(cData))
			C.strncpy(&backendC.client_cert_data[0], cData, 4095)
		}

		if backendCfg.ClientKeyData != "" {
			cData := C.CString(backendCfg.ClientKeyData)
			defer C.free(unsafe.Pointer(cData))
			C.strncpy(&backendC.client_key_data[0], cData, 4095)
		}

		tk.LogIt(tk.LogInfo, "[DP] Backend mTLS: verify=%v ca_path=%s client_cert=%s\n",
			backendCfg.VerifyServerCert, backendCfg.BackendCAPath, backendCfg.ClientCertPath)
	}

	// Call C function to update proxy entry's mTLS configuration
	ret := C.proxy_update_mtls_config(&proxyKey, frontendC, backendC)
	if ret != 0 {
		tk.LogIt(tk.LogError, "[DP] Failed to configure mTLS for %s:%d - ret=%d\n",
			serviceIP.String(), port, int(ret))
		return -1
	}

	tk.LogIt(tk.LogInfo, "[DP] mTLS configuration applied successfully for %s:%d\n",
		serviceIP.String(), port)
	return 0
}

// DpProxyCleanupMTLS - Clean up mTLS configuration when a rule is deleted
// This prevents memory leaks by removing stored mTLS config from the bridge storage
func DpProxyCleanupMTLS(serviceIP net.IP, port uint16, proto uint8) int {
	tk.LogIt(tk.LogDebug, "[DP] Cleaning up mTLS config for %s:%d proto=%d\n",
		serviceIP.String(), port, proto)

	// Build proxy key to identify the rule
	var proxyKey C.struct_proxy_ent
	if serviceIP.To4() != nil {
		proxyKey.xip = C.uint(tk.IPtonl(serviceIP))
	} else {
		// IPv6 not yet supported, but don't fail cleanup
		return 0
	}
	proxyKey.xport = C.ushort(tk.Htons(port))
	proxyKey.protocol = C.uchar(proto)

	// Call C function to remove stored mTLS configuration
	ret := C.proxy_cleanup_mtls_config(&proxyKey)
	if ret != 0 {
		// Don't treat cleanup failure as critical error
		tk.LogIt(tk.LogDebug, "[DP] mTLS cleanup returned %d (may not exist)\n", int(ret))
	}

	return 0
}

// --- certId registry bridge (13) --------------------
//
// DpProxyRegisterCert / DpProxyRotateCert / DpProxyDeleteCert bridge the Go control
// plane to the 77-02 C certId registry (proxy_register_cert / proxy_rotate_cert /
// proxy_delete_cert), layered over the hostname-keyed SNI store. The inline-PEM upload
// is persisted to the managed dir by the REST handler (cert.go) BEFORE these are called;
// register auto-derives the SAN/CN hostnames and registers them into the SNI store,
// rotate atomically swaps the cert object (zero-downtime), delete unregisters them.

// DpProxyRegisterCert registers a certId — loads server.crt/server.key from the managed
// dir, auto-derives the SAN/CN hostname(s), and registers each into the SNI store.
// Returns the number of hostnames registered (>=1) on success, negative on failure.
func DpProxyRegisterCert(certId string) int {
	cID := C.CString(certId)
	defer C.free(unsafe.Pointer(cID))
	ret := int(C.proxy_register_cert(cID))
	if ret < 0 {
		tk.LogIt(tk.LogError, "[DP] proxy_register_cert(%s) failed: %d\n", certId, ret)
	}
	return ret
}

// DpProxyRotateCert atomically rotates a certId's material (zero-downtime swap).
func DpProxyRotateCert(certId string) int {
	cID := C.CString(certId)
	defer C.free(unsafe.Pointer(cID))
	ret := int(C.proxy_rotate_cert(cID))
	if ret != 0 {
		tk.LogIt(tk.LogError, "[DP] proxy_rotate_cert(%s) failed: %d\n", certId, ret)
	}
	return ret
}

// DpProxyDeleteCert removes a certId — unregisters its derived hostnames from the SNI store.
func DpProxyDeleteCert(certId string) int {
	cID := C.CString(certId)
	defer C.free(unsafe.Pointer(cID))
	ret := int(C.proxy_delete_cert(cID))
	if ret != 0 {
		tk.LogIt(tk.LogDebug, "[DP] proxy_delete_cert(%s) returned %d (may not exist)\n", certId, ret)
	}
	return ret
}

// --- L7 content-routing policy attach bridge --------
//
// DpProxyAttachL7Policy / DpProxyDetachL7Policy carry the validated L7 route IR to
// the running sockproxy via a SEPARATE CGO call (proxy_attach_l7_policy), modeled on
// DpProxyConfigureMTLS — NEVER inline on proxy_arg (the 4096-byte _Static_assert).
// The Go side builds a contiguous C l7_route_t array from the cmn IR and hands
// ownership to the C side (which deep-copies, regcomp's each REGEX ONCE, sorts by
// position, and populates the proxy_map_ent has_l7_policy/l7_routes/n_l7_routes
// discriminator fields). Go NEVER compiles a regex (re_valid stays 0) — regcomp is
// the C attach's single compile site (ReDoS/08).

// l7 enum value maps (mirror the canonical sockproxy_l7policy.h enumerators + the
// swagger/handler string enums). Unknown strings map to -1 so the C side ignores
// (the handler already validated, so an unknown value here is a programmer error).
func l7FieldEnum(s string) C.int {
	switch s {
	case "HOST":
		return 0
	case "PATH":
		return 1
	case "HEADER":
		return 2
	case "COOKIE":
		return 3
	case "FILE_TYPE":
		return 4
	case "METHOD":
		return 5
	case "QUERY":
		return 6
	}
	return -1
}

func l7OpEnum(s string) C.int {
	switch s {
	case "EQUAL_TO":
		return 0
	case "STARTS_WITH":
		return 1
	case "SEGMENT_PREFIX":
		return 2
	case "ENDS_WITH":
		return 3
	case "CONTAINS":
		return 4
	case "REGEX":
		return 5
	}
	return -1
}

func l7PathOpEnum(s string) C.int {
	switch s {
	case "REPLACE_FULL":
		return 1
	case "REPLACE_PREFIX":
		return 2
	default: // "NONE" / empty
		return 0
	}
}

// l7HdrOpEnum maps an insertHeaders op string to l7_hdr_op_t.
// Case-insensitive; an unknown op defaults to SET (the safest overwrite op) but
// the REST handler already 400s anything outside {SET,ADD,REMOVE}.
func l7HdrOpEnum(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ADD":
		return 1 // L7HDR_ADD
	case "REMOVE":
		return 2 // L7HDR_REMOVE
	default: // "SET" / empty
		return 0 // L7HDR_SET
	}
}

// DpProxyAttachL7Policy - attach an ordered L7 route array to a running sockproxy
// rule keyed by VIP:port:proto. routes is the validated IR from the handler.
func DpProxyAttachL7Policy(serviceIP net.IP, port uint16, proto uint8, routes []cmn.L7RuleArg) int {
	tk.LogIt(tk.LogInfo, "[DP] Attaching L7 policy for %s:%d proto=%d (%d routes)\n",
		serviceIP.String(), port, proto, len(routes))

	if len(routes) == 0 {
		return DpProxyDetachL7Policy(serviceIP, port, proto)
	}

	// Build the proxy key (copied from the MTLS key-build).
	var proxyKey C.struct_proxy_ent
	if serviceIP.To4() != nil {
		proxyKey.xip = C.uint(tk.IPtonl(serviceIP))
	} else {
		tk.LogIt(tk.LogError, "[DP] L7 policy: IPv6 not yet supported\n")
		return -1
	}
	proxyKey.xport = C.ushort(tk.Htons(port))
	proxyKey.protocol = C.uchar(proto)

	// Malloc a contiguous C l7_route_t array; the C attach deep-copies it, so we
	// free our copy on return.
	n := len(routes)
	cRoutes := (*C.l7_route_t)(C.calloc(C.size_t(n), C.sizeof_l7_route_t))
	if cRoutes == nil {
		tk.LogIt(tk.LogError, "[DP] L7 policy: calloc failed\n")
		return -1
	}
	defer C.free(unsafe.Pointer(cRoutes))

	cArr := (*[1 << 16]C.l7_route_t)(unsafe.Pointer(cRoutes))[:n:n]
	for i := range routes {
		r := &routes[i]
		dst := &cArr[i]
		dst.position = C.int(r.Position)

		nSets := len(r.MatchSets)
		if nSets > int(C.L7_MAX_SETS_PER_ROUTE) {
			nSets = int(C.L7_MAX_SETS_PER_ROUTE)
		}
		dst.n_sets = C.uint8_t(nSets)
		for si := 0; si < nSets; si++ {
			set := &r.MatchSets[si]
			nConds := len(set.Conditions)
			if nConds > int(C.L7_MAX_CONDS_PER_SET) {
				nConds = int(C.L7_MAX_CONDS_PER_SET)
			}
			dst.sets[si].n_conds = C.uint8_t(nConds)
			for ci := 0; ci < nConds; ci++ {
				c := &set.Conditions[ci]
				cond := &dst.sets[si].conds[ci]
				cond.field = l7FieldEnum(c.Field)
				cond.op = l7OpEnum(c.Op)
				goCStrCopy(&cond.key[0], C.L7_KEY_MAX, c.Key)
				goCStrCopy(&cond.value[0], C.L7_VALUE_MAX, c.Value)
				if c.Invert {
					cond.invert = 1
				}
				// re_valid stays 0 — the C attach regcomp's REGEX conditions ONCE.
				cond.re_valid = 0
			}
		}

		// Action tagged union.
		switch r.Action.Kind {
		case "FORWARD":
			dst.action.kind = 0
			fwd := (*C.l7_forward_t)(unsafe.Pointer(&dst.action.u))
			if r.Action.Forward != nil {
				fwd.pool_id = C.uint32_t(r.Action.Forward.PoolId)
				nRefs := len(r.Action.Forward.BackendRefs)
				if nRefs > int(C.L7_MAX_PROXY_EP) {
					nRefs = int(C.L7_MAX_PROXY_EP)
				}
				fwd.n_refs = C.uint8_t(nRefs)
				for bi := 0; bi < nRefs; bi++ {
					fwd.refs[bi].ep = C.uint32_t(r.Action.Forward.BackendRefs[bi].Ep)
					fwd.refs[bi].weight = C.uint8_t(r.Action.Forward.BackendRefs[bi].Weight)
				}
			}
		case "REDIRECT":
			dst.action.kind = 1
			redir := (*C.l7_redirect_t)(unsafe.Pointer(&dst.action.u))
			if r.Action.Redirect != nil {
				goCStrCopy(&redir.scheme[0], 8, r.Action.Redirect.Scheme)
				goCStrCopy(&redir.host[0], 256, r.Action.Redirect.Host)
				redir.port = C.uint16_t(r.Action.Redirect.Port)
				redir.path_op = l7PathOpEnum(r.Action.Redirect.PathOp)
				goCStrCopy(&redir.value[0], C.L7_VALUE_MAX, r.Action.Redirect.Value)
				redir.status_code = C.uint16_t(r.Action.Redirect.StatusCode)
			}
		case "REJECT":
			dst.action.kind = 2
			rej := (*C.l7_reject_t)(unsafe.Pointer(&dst.action.u))
			if r.Action.Reject != nil {
				rej.status_code = C.uint16_t(r.Action.Reject.StatusCode)
			}
		}

		// copy the bounded insertHeaders SET/ADD/REMOVE filter
		// list into the contiguous C l7_route_t.hdr_filters[] array. Go NEVER builds C
		// state beyond this copy; the C attach deep-copies the whole route array. The op
		// strings were validated to {SET,ADD,REMOVE} by the REST handler (400 otherwise);
		// l7HdrOpEnum maps them to l7_hdr_op_t (0/1/2). Over-count is bounded here
		//, mirroring the matchSets/conds copy above.
		nFilters := len(r.InsertHeaders)
		if nFilters > int(C.L7_MAX_HDR_FILTERS) {
			nFilters = int(C.L7_MAX_HDR_FILTERS)
		}
		dst.n_hdr_filters = C.uint8_t(nFilters)
		for hi := 0; hi < nFilters; hi++ {
			f := &r.InsertHeaders[hi]
			dst.hdr_filters[hi].op = C.uint8_t(l7HdrOpEnum(f.Op))
			goCStrCopy(&dst.hdr_filters[hi].name[0], C.L7_HDR_NAME_MAX, f.Name)
			goCStrCopy(&dst.hdr_filters[hi].value[0], C.L7_HDR_VALUE_MAX, f.Value)
		}

		// HTTP_COOKIE session-persistence marker. Engine is;
		// only carries the flag so the IR round-trips (additive, default-off).
		if strings.EqualFold(strings.TrimSpace(r.SessionPersistence), "HTTP_COOKIE") {
			dst.cookie_persist = 1
		}
	}

	ret := C.proxy_attach_l7_policy(&proxyKey, cRoutes, C.int(n))
	if ret != 0 {
		tk.LogIt(tk.LogError, "[DP] Failed to attach L7 policy for %s:%d - ret=%d (bad regex or no such service)\n",
			serviceIP.String(), port, int(ret))
		return -1
	}
	tk.LogIt(tk.LogInfo, "[DP] L7 policy attached for %s:%d (%d routes)\n",
		serviceIP.String(), port, n)
	return 0
}

// DpProxyDetachL7Policy - detach the L7 policy from a rule (regfrees every compiled
// REGEX program on the C side). Mirrors DpProxyCleanupMTLS.
func DpProxyDetachL7Policy(serviceIP net.IP, port uint16, proto uint8) int {
	tk.LogIt(tk.LogDebug, "[DP] Detaching L7 policy for %s:%d proto=%d\n",
		serviceIP.String(), port, proto)

	var proxyKey C.struct_proxy_ent
	if serviceIP.To4() != nil {
		proxyKey.xip = C.uint(tk.IPtonl(serviceIP))
	} else {
		return 0
	}
	proxyKey.xport = C.ushort(tk.Htons(port))
	proxyKey.protocol = C.uchar(proto)

	ret := C.proxy_detach_l7_policy(&proxyKey)
	if ret != 0 {
		tk.LogIt(tk.LogDebug, "[DP] L7 policy detach returned %d (may not exist)\n", int(ret))
	}
	return 0
}

// goCStrCopy copies a Go string into a fixed C char buffer, NUL-terminating and
// truncating to capacity-1 (bounded copy, mirrors the strncpy idiom MTLS uses).
func goCStrCopy(dst *C.char, cap C.int, s string) {
	if dst == nil || cap <= 0 {
		return
	}
	max := int(cap) - 1
	b := []byte(s)
	if len(b) > max {
		b = b[:max]
	}
	buf := (*[1 << 16]C.char)(unsafe.Pointer(dst))
	for i := 0; i < len(b); i++ {
		buf[i] = C.char(b[i])
	}
	buf[len(b)] = 0
}
