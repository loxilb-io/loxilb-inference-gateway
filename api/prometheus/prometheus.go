/*
 * Copyright (c) 2023 NetLOX Inc
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
package prometheus

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-openapi/errors"
	"github.com/loxilb-io/loxilb/common"
	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/loxilb-io/loxilb/options"
	tk "github.com/loxilb-io/loxilib"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func readCPUUtilization() (float64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0, fmt.Errorf("empty /proc/stat")
	}
	line := scanner.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return 0, fmt.Errorf("unexpected /proc/stat format")
	}

	// Fields: user nice system idle iowait irq softirq steal guest guest_nice
	parts := strings.Fields(line)
	var vals []uint64
	for _, p := range parts[1:] {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return 0, err
		}
		vals = append(vals, v)
	}
	if len(vals) < 4 {
		return 0, fmt.Errorf("insufficient cpu fields")
	}
	idle := vals[3]
	// total is sum of all
	var total uint64
	for _, v := range vals {
		total += v
	}

	if !cpuInited {
		prevCPUIdle = idle
		prevCPUTotal = total
		cpuInited = true
		return 0, nil // first sample has no delta
	}

	idleDelta := float64(idle - prevCPUIdle)
	totalDelta := float64(total - prevCPUTotal)
	prevCPUIdle = idle
	prevCPUTotal = total

	if totalDelta <= 0 {
		return 0, fmt.Errorf("non-positive total delta")
	}
	usage := (1.0 - idleDelta/totalDelta) * 100.0
	if usage < 0 {
		usage = 0
	} else if usage > 100 {
		usage = 100
	}
	return usage, nil
}

// readMemoryUtilization reads /proc/meminfo to compute used percentage
func readMemoryUtilization() (float64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var total, available uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				total, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				available, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
		if total > 0 && available > 0 {
			break
		}
	}
	if total == 0 {
		return 0, fmt.Errorf("memtotal not found")
	}
	used := float64(total-available) / float64(total) * 100.0
	if used < 0 {
		used = 0
	} else if used > 100 {
		used = 100
	}
	return used, nil
}

// readDiskUtilization uses Statfs on root filesystem
func readDiskUtilization() (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, err
	}
	total := float64(st.Blocks) * float64(st.Bsize)
	avail := float64(st.Bavail) * float64(st.Bsize)
	if total <= 0 {
		return 0, fmt.Errorf("invalid disk size")
	}
	used := (1.0 - (avail / total)) * 100.0
	if used < 0 {
		used = 0
	} else if used > 100 {
		used = 100
	}
	return used, nil
}

// RunSystemUtilization periodically samples system metrics and updates gauges
func RunSystemUtilization(ctx context.Context) {
	ticker := time.NewTicker(PrometheusDefaultPeriod)
	defer ticker.Stop()

	safeGoroutineOperation(func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			// Normal shutdown - the outer loop exits on the next iteration
			return nil
		case <-ticker.C:
			if cpu, host, err := sampleCPUUtilization(); err == nil {
				lastSystemCPU = cpu
				systemCPUUtilization.Set(cpu)
				hostCPUUtilization.Set(host)
			} else {
				return fmt.Errorf("CPU util read error: %v", err)
			}
			if mem, err := readMemoryUtilization(); err == nil {
				lastSystemMem = mem
				systemMemoryUtilization.Set(mem)
			} else {
				return fmt.Errorf("memory util read error: %v", err)
			}
			if du, err := readDiskUtilization(); err == nil {
				lastSystemDisk = du
				systemDiskUtilization.Set(du)
			} else {
				return fmt.Errorf("disk util read error: %v", err)
			}
		}
		return nil
	}, "system_utilization", ctx)
}

type Stats struct {
	Bytes   uint64
	Packets uint64
}
type ConntrackKey string

var (
	hooks                   cmn.NetHookInterface
	ConntrackInfo           []cmn.CtInfo
	EndPointInfo            []cmn.EndPointMod
	LBRuleInfo              []cmn.LbRuleMod
	FWRuleInfo              []cmn.FwRuleMod
	err                     error
	mutex                   = &sync.Mutex{}        // Protects ConntrackInfo/ConntrackStats/EndPointInfo/LBRuleInfo/FWRuleInfo
	ConntrackStats          map[ConntrackKey]Stats // Key [string] : sip dip pro sport dport
	PreFlowCounts           int
	PrometheusDefaultPeriod = 10 * time.Second
	PrometheusPartialPeriod = (PrometheusDefaultPeriod / 6)
	prometheusCtx           context.Context
	prometheusCancel        context.CancelFunc
	initMutex               sync.Mutex // Guards Init/PrometheusTurnOff lifecycle state (prometheusCtx/prometheusCancel)
	MaxPoolStatsServiceSize = 16       // Maximum size of the conntrack info slice pool

	activeConntrackCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricActiveConntrackCount,
			Help: "Number of active established connections from clients to targets.",
		},
	)
	activeFlowCountTcp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricActiveFlowCountTCP,
			Help: "Number of concurrent TCP flows (or connections) from clients to targets.",
		},
	)
	activeFlowCountUdp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricActiveFlowCountUDP,
			Help: "Number of concurrent UDP flows (or connections) from clients to targets.",
		},
	)
	activeFlowCountSctp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricActiveFlowCountSCTP,
			Help: "Number of concurrent SCTP flows (or connections) from clients to targets.",
		},
	)
	healthyHostCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricHealthyEndpointsCount,
			Help: "Number of healthy targets.",
		},
	)
	unHealthyHostCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricUnhealthyEndpointsCount,
			Help: "Number of unhealthy targets.",
		},
	)
	ruleCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricLBRuleCount,
			Help: "Total number of load balancing rules.",
		},
	)
	newFlowCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricNewFlowCount,
			Help: "The number of new TCP connections from clients to targets.",
		},
	)
	processedBytes = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricProcessedBytesTotal,
			Help: "The total number of bytes processed by the load balancer, including protocol and IP headers. Fed from the cumulative data-plane rule counters (exact, includes flows of any lifetime).",
		},
	)
	processedTCPBytes = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricProcessedTCPBytes,
			Help: "The total number of TCP bytes processed by the load balancer, including TCP/IP headers.",
		},
	)
	processedUDPBytes = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricProcessedUDPBytes,
			Help: "The total number of UDP bytes processed by the load balancer, including UDP/IP headers.",
		},
	)
	processedSCTPBytes = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricProcessedSCTPBytes,
			Help: "The total number of SCTP bytes processed by the load balancer, including SCTP/IP headers.",
		},
	)
	processedTCPPackets = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricProcessedTCPPackets,
			Help: "The total number of TCP packets processed by the load balancer.",
		},
	)
	processedUDPPackets = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricProcessedUDPPackets,
			Help: "The total number of UDP packets processed by the load balancer.",
		},
	)
	processedSCTPPackets = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricProcessedSCTPPackets,
			Help: "The total number of SCTP packets processed by the load balancer.",
		},
	)
	processedPackets = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricProcessedPacketsTotal,
			Help: "The total number of packets processed by the load balancer. Fed from the cumulative data-plane rule counters (exact, includes flows of any lifetime).",
		},
	)
	// Processed bytes per LB rule PromQL : sum(rate(loxilb_lb_rule_interaction_bytes_total[1m])) by (service)
	// Processed bytes per endpoint PromQL: sum(rate(loxilb_lb_rule_interaction_bytes_total[1m])) by (dip)
	lbRuleInteractionBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricLBRuleInteractionBytes,
			Help: "Total bytes exchanged between load balancer and IPs",
		},
		[]string{"service", "sip", "dip"},
	)
	lbRuleInteractionPackets = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricLBRuleInteractionPackets,
			Help: "Total packets exchanged between load balancer and IPs",
		},
		[]string{"service", "sip", "dip"},
	)

	// Traffic distribution metrics for monitoring
	serviceTrafficBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricServiceTrafficBytes,
			Help: "Total bytes per NAMED service, from the exact data-plane rule counters. Unnamed LB rules have no per-service series.",
		},
		[]string{"service"},
	)
	serviceTrafficPackets = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricServiceTrafficPackets,
			Help: "Total packets per NAMED service, from the exact data-plane rule counters. Unnamed LB rules have no per-service series.",
		},
		[]string{"service"},
	)
	endpointTrafficBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricEndpointTrafficBytes,
			Help: "Total bytes per endpoint per service. PERSISTENT-FLOW VIEW: conntrack-sweep derived; flows shorter than one 10s sweep are not counted.",
		},
		[]string{"service", "dip"},
	)
	clientTrafficPackets = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricClientTrafficPackets,
			Help: "Total packets per client per service. PERSISTENT-FLOW VIEW: conntrack-sweep derived; flows shorter than one 10s sweep are not counted.",
		},
		[]string{"service", "sip"},
	)

	// Per-backend exact traffic counters. Unlike loxilb_endpoint_traffic_bytes
	// (conntrack persistent-flow view, dip only), bytes/packets here come from
	// the CUMULATIVE data-plane rule counters, so flows of any lifetime are
	// counted and the endpoint label carries the configured "ip:port". Series
	// cardinality is bounded by the configured named-service x endpoint set;
	// bytes/packets children are deleted when the endpoint leaves the rule
	// config (same sweep that detects it). Connections children are NOT
	// deleted on endpoint removal: they are fed by the separate conntrack
	// sweep goroutine, and a cross-goroutine delete can be resurrected by an
	// in-flight Add for a draining flow (the ghost-series class fixed under
	// kvSeriesMu for the KV subscriber gauges) — a frozen counter child is
	// harmless, a resurrected one is not.
	backendTrafficBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricBackendTrafficBytes,
			Help: "Total bytes per endpoint per NAMED service, from the exact cumulative data-plane rule counters (flows of any lifetime). endpoint is \"ip:port\".",
		},
		[]string{"service", "endpoint"},
	)
	backendTrafficPackets = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricBackendTrafficPackets,
			Help: "Total packets per endpoint per NAMED service, from the exact cumulative data-plane rule counters (flows of any lifetime). endpoint is \"ip:port\".",
		},
		[]string{"service", "endpoint"},
	)
	backendTrafficConnections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricBackendTrafficConnections,
			Help: "Sampled new sessions per endpoint per NAMED service. PERSISTENT-FLOW VIEW: conntrack-sweep derived; sessions born and closed within one 10s sweep are not counted. endpoint is \"ip:port\".",
		},
		[]string{"service", "endpoint"},
	)

	// Request counters; requests-per-second is derived in PromQL:
	// rate(loxilb_requests_total[1m])
	totalRequests = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricTotalRequests,
			Help: "Sampled new sessions observed by the 10s conntrack sweep. Sessions born and closed within one sweep are not counted - treat as a trend indicator, not an exact request count.",
		},
	)

	totalRequestsPerService = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricTotalRequestsPerService,
			Help: "Sampled new sessions per service observed by the 10s conntrack sweep. Sessions born and closed within one sweep are not counted.",
		},
		[]string{"service"},
	)

	totalErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricTotalErrors,
			Help: "Total number of errors",
		},
	)

	totalErrorsPerService = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricTotalErrorsPerService,
			Help: "Total number of errors per service",
		},
		[]string{"service"},
	)

	// Firewall drop counters: the data plane exposes cumulative per-rule drop
	// counters; RunGetFwRule adds per-cycle deltas so rate() works as expected.
	totalDropsByFw = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricTotalFwDrops,
			Help: "Total number of packets dropped by firewall rules",
		},
	)

	totalDropsByFwPerRule = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricTotalFwDropsPerRule,
			Help: "Total number of packets dropped by firewall, per rule preference",
		},
		[]string{"fw_rule"},
	)

	fwRuleCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricFirewallRulesCount,
			Help: "Number of active firewall rules",
		},
	)

	prevConntrackStats = make(map[ConntrackKey]Stats)
	prevConntrackInfo  = make(map[ConntrackKey]bool)

	// finalizedClosedFlows remembers closed conntrack entries whose final metrics
	// were already captured, so an entry lingering in the conntrack table across
	// collection cycles is not re-counted every cycle. Pruned automatically once
	// the entry leaves the table. Protected by conntrackRWMutex.
	finalizedClosedFlows = make(map[ConntrackKey]bool)

	// prevErrorFlows tracks flows that were already in an error state last cycle,
	// so the error counters count error transitions (events), not error state
	// per sweep. Protected by conntrackRWMutex.
	prevErrorFlows = make(map[ConntrackKey]bool)

	// firstCollectionCycle marks the first sweep after Init: baselines are seeded
	// without adding to counters, so pre-existing long-lived flows do not appear
	// as a phantom traffic burst when metrics are (re-)enabled.
	firstCollectionCycle = true

	// Cumulative per-rule firewall drop baselines for delta computation, keyed by
	// rule preference. Only touched by the RunGetFwRule goroutine.
	prevFwRuleDrops = make(map[string]uint64)

	// Cumulative per-LB-endpoint traffic baselines (from the data-plane rule
	// counters) for delta computation, keyed by service tuple + endpoint. Only
	// touched by the RunGetLBRule goroutine; reset in Init like the fw baselines.
	// The DP counters — not the conntrack sweep — feed the aggregate processed_*
	// and service_traffic_* counters, because the sweep misses every flow shorter
	// than one collection period (finding D2: 869 DP packets vs 43 sweep-observed).
	prevLbEpStats = make(map[string]Stats)

	// prevBackendEpPairs is the (named service, "ip:port" endpoint) set seen by
	// the previous RunGetLBRule sweep — the departure signal for deleting
	// backend_traffic_{bytes,packets} children when an endpoint leaves the rule
	// config. Only touched by the RunGetLBRule goroutine.
	prevBackendEpPairs = make(map[[2]string]bool)

	// lbStatsFirstCycle marks the first RunGetLBRule pass after Init: baselines
	// are seeded without adding, so pre-existing cumulative DP totals do not
	// appear as a phantom burst when metrics are (re-)enabled.
	lbStatsFirstCycle = true

	// Previous security stats for delta calculation (like conntrack overflow handling)
	prevSecurityStats cmn.SecurityRateStats
	prevIPFilterStats map[string]struct {
		Packets uint64
		Bytes   uint64
	}

	// Collection-pipeline self-diagnostics
	counterResetEvents = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_conntrack_stat_resets_total",
			Help: "Total number of conntrack statistics reset events detected",
		},
	)
	closedConnectionsProcessed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "loxilb_closed_connections_processed_total",
			Help: "Total number of closed connections with final metrics captured",
		},
	)

	conntrackRWMutex sync.RWMutex // Protects prevConntrackStats and prevConntrackInfo

	// Bound on prevConntrackStats size to prevent unbounded growth
	MaxPrevConntrackEntries = 1000000
	prevStatsCleanupCount   uint64 // Track cleanup cycles for logging

	// System utilization gauges
	systemCPUUtilization = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricSystemCPUUtilization,
			Help: "CPU utilization percentage [0-100] of the scope loxilb runs in: " +
				"this container's share of its CPU allowance when containerized, " +
				"the whole machine otherwise",
		},
	)
	hostCPUUtilization = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricHostCPUUtilization,
			Help: "Whole-machine CPU utilization percentage [0-100], including " +
				"processes outside this container",
		},
	)
	systemMemoryUtilization = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricSystemMemoryUtilization,
			Help: "Total system memory utilization percentage [0-100]",
		},
	)
	systemDiskUtilization = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricSystemDiskUtilization,
			Help: "Total system disk utilization percentage [0-100] (root filesystem)",
		},
	)

	// Security rate limiting metrics
	securitySYNBlocked = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSecuritySYNBlocked,
			Help: "Total number of SYN packets blocked by SYN flood protection",
		},
	)

	securitySYNPassed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSecuritySYNPassed,
			Help: "Total number of SYN packets passed by SYN flood protection",
		},
	)

	securitySYNCookies = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSecuritySYNCookies,
			Help: "Total number of SYN cookie activations",
		},
	)

	securityConnBlocked = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSecurityConnBlocked,
			Help: "Total number of connections blocked by rate limiting",
		},
	)

	securityConnPassed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSecurityConnPassed,
			Help: "Total number of connections passed by rate limiting",
		},
	)

	securityUniqueIPs = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricSecurityUniqueIPs,
			Help: "Number of unique IPs being tracked for security rate limiting",
		},
	)

	securityUDPBlocked = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSecurityUDPBlocked,
			Help: "Total number of UDP packets blocked by UDP flood protection",
		},
	)

	securityUDPPassed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSecurityUDPPassed,
			Help: "Total number of UDP packets passed by UDP flood protection",
		},
	)

	securityUDPBytesBlocked = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSecurityUDPBytesBlocked,
			Help: "Total number of UDP bytes blocked by UDP flood protection",
		},
	)

	securityUDPBytesPassed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: MetricSecurityUDPBytesPassed,
			Help: "Total number of UDP bytes passed by UDP flood protection",
		},
	)

	// IP filter metrics
	ipFilterBlacklistPackets = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricIPFilterBlacklistPackets,
			Help: "Total number of packets blocked by IP blacklist rules",
		},
		[]string{"cidr", "priority", "zone"},
	)

	ipFilterBlacklistBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricIPFilterBlacklistBytes,
			Help: "Total number of bytes blocked by IP blacklist rules",
		},
		[]string{"cidr", "priority", "zone"},
	)

	ipFilterWhitelistPackets = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricIPFilterWhitelistPackets,
			Help: "Total number of packets allowed by IP whitelist rules",
		},
		[]string{"cidr", "priority", "zone"},
	)

	ipFilterWhitelistBytes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricIPFilterWhitelistBytes,
			Help: "Total number of bytes allowed by IP whitelist rules",
		},
		[]string{"cidr", "priority", "zone"},
	)

	ipFilterTotalRules = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: MetricIPFilterTotalRules,
			Help: "Total number of active IP filter rules",
		},
		[]string{"type"},
	)

	// Cached latest values for DB collection
	lastSystemCPU  float64
	lastSystemMem  float64
	lastSystemDisk float64

	// Previous CPU counters for delta computation
	prevCPUIdle  uint64
	prevCPUTotal uint64
	cpuInited    bool

	// === ISOLATION FRAMEWORK VARIABLES ===
	// Core health tracking - using atomic for thread safety
	metricsHealthy  atomic.Bool  // Master enable (Init/PrometheusTurnOff)
	lastMetricError atomic.Int64 // Unix timestamp of last error (any collector)

	// Isolation framework configuration
	MaxMetricErrors  = int64(3)        // Trip after 3 consecutive errors
	RetryInterval    = int64(300)      // Wait 5 minutes before retry (300 seconds)
	OperationTimeout = 5 * time.Second // Max operation duration
)

func PrometheusRegister(hook common.NetHookInterface) {
	hooks = hook
}

// CheckInit reports whether the Prometheus subsystem is registered and running
func CheckInit() error {
	if hooks == nil {
		return errors.New(http.StatusBadRequest, "Prometheus API hooks are not registered")
	}
	initMutex.Lock()
	running := prometheusCtx != nil
	initMutex.Unlock()
	if !running {
		return errors.New(http.StatusBadRequest, "Prometheus is not running")
	}
	return nil
}

// OptionStateChange sets the state of Prometheus
func OptionStateChange(state bool) {
	options.Opts.Prometheus = state
}

// PrometheusTurnOff turns off the Prometheus metrics collection
// NOTE: eBPF hooks are preserved to maintain load balancing functionality
func PrometheusTurnOff() error {
	initMutex.Lock()
	defer initMutex.Unlock()

	if prometheusCancel == nil {
		return nil // already off
	}

	tk.LogIt(tk.LogInfo, "[Metrics] Shutting down metrics collection...\n")

	// Signal all goroutines to stop
	prometheusCancel()

	// Disable metrics processing immediately
	metricsHealthy.Store(false)

	// Clear prometheus-specific resources (but preserve eBPF hooks for load balancing)
	prometheusCancel = nil
	prometheusCtx = nil
	// hooks preserved intentionally - load balancing continues

	tk.LogIt(tk.LogInfo, "[Metrics] Stopped - Load balancing continues with preserved eBPF hooks\n")
	return nil
}

func generateLabelsKey(name string, labels map[string]string) string {
	// Sort label names: Go map iteration order is random, and an unsorted key
	// would split one logical series across up to n! shared-metric entries
	names := make([]string, 0, len(labels))
	for key := range labels {
		names = append(names, key)
	}
	sort.Strings(names)

	var builder strings.Builder
	builder.WriteString(name)
	for _, key := range names {
		builder.WriteString(fmt.Sprintf("|%s=%s", key, labels[key]))
	}
	return builder.String()
}

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()

	// Idempotent: a second Init while collection is running would leak a full
	// set of collector goroutines and orphan the previous cancel func
	if prometheusCtx != nil {
		tk.LogIt(tk.LogInfo, "[Metrics] Already running - skipping duplicate init\n")
		return
	}

	// Initialize health state - MUST be first
	metricsHealthy.Store(true) // Master enable
	lastMetricError.Store(0)   // No previous errors
	resetAllBreakers()         // Per-collector breakers start healthy

	prometheusCtx, prometheusCancel = context.WithCancel(context.Background())

	// Reset collection state so a re-enable starts from fresh baselines
	mutex.Lock()
	ConntrackStats = make(map[ConntrackKey]Stats)
	mutex.Unlock()
	prevIPFilterStats = make(map[string]struct {
		Packets uint64
		Bytes   uint64
	})
	prevLbEpStats = make(map[string]Stats)
	prevBackendEpPairs = make(map[[2]string]bool)
	lbStatsFirstCycle = true
	conntrackRWMutex.Lock()
	prevConntrackStats = make(map[ConntrackKey]Stats)
	prevConntrackInfo = make(map[ConntrackKey]bool)
	finalizedClosedFlows = make(map[ConntrackKey]bool)
	prevErrorFlows = make(map[ConntrackKey]bool)
	firstCollectionCycle = true
	conntrackRWMutex.Unlock()

	go RunGetConntrack(prometheusCtx)
	go RunGetEndpoint(prometheusCtx)
	go RunGetFwRule(prometheusCtx)
	go RunGetLBRule(prometheusCtx)
	// Start system utilization sampler
	go RunSystemUtilization(prometheusCtx)

	go RunActiveConntrackCount(prometheusCtx)

	// Start sockproxy metrics collection (TIER 1-3 metrics for AI/LLM workloads)
	// TIER 1: 10s interval - Critical cache backpressure and session affinity metrics
	// TIER 2: 30s interval - Important observability (connections, HTTP/2 sessions)
	// TIER 3: 2m interval - Operational debugging (drain events, graceful closes, TTL expirations)
	go RunSockproxyMetrics(prometheusCtx)

	// Start security metrics collection
	go RunSecurityRateStats(prometheusCtx)
	go RunIPFilterStats(prometheusCtx)

	// Start always-on L4 connection-error metrics (event-driven, trace-independent).
	// Feeds loxilb_l4_error_events_total — the source of truth for LoxilbL4ErrorBurst.
	go RunL4ErrorStats(prometheusCtx)

	tk.LogIt(tk.LogInfo, "[Metrics] System initialized with isolation protection\n")
}

func toJSON(v interface{}) string {
	bytes, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(bytes)
}

func MakeConntrackKey(c cmn.CtInfo) (key ConntrackKey) {
	// The data plane reports flows of UNNAMED lb rules with ServiceName "-"
	// (and sometimes ""). Normalize to "" here — the single choke point every
	// consumer parses the service name back out of — so the serviceName != ""
	// guards keep placeholder per-service series ("-" or empty) out of every
	// labeled metric (finding D1).
	svc := c.ServiceName
	if svc == "-" {
		svc = ""
	}
	return ConntrackKey(fmt.Sprintf("%s|%05d|%s|%05d|%v|%s",
		c.Sip, c.Sport, c.Dip, c.Dport, c.Proto, svc))
}

func isErrorState(c cmn.CtInfo) bool {
	// Error conditions. NOTE: the eBPF data plane encodes SCTP error/abort as
	// CState ("err"/"abort", see dpebpf_linux.go), NOT CAct — CAct only ever holds
	// NAT-action strings ("n/a", "fdnat-…", "fp|…"). The previous CAct=="err"/"abort"
	// checks were therefore dead code and every SCTP error/abort flow went uncounted
	// in loxilb_errors_total (LoxilbL4ErrorBurst was blind to all SCTP failures).
	return c.CState == "h/e" || c.CState == "closed-wait" ||
		c.CState == "err" || c.CState == "abort"
}

func RunGetConntrack(ctx context.Context) {
	tk.LogIt(tk.LogInfo, "[Metrics] Starting conntrack collection goroutine\n")
	safeGoroutineOperation(func(ctx context.Context) error {
		tk.LogIt(tk.LogDebug, "[Metrics] Attempting conntrack collection - hooks available: %v\n", hooks != nil)

		if hooks == nil {
			tk.LogIt(tk.LogError, "[Metrics] eBPF hooks not available for conntrack collection\n")
			time.Sleep(PrometheusDefaultPeriod)
			return nil
		}

		localConntrackInfo, err := hooks.NetCtInfoGet()
		if err != nil {
			// Log but don't treat as fatal error - eBPF hooks may be temporarily unavailable
			tk.LogIt(tk.LogWarning, "[Metrics] Conntrack collection temporarily unavailable: %v\n", err)
			time.Sleep(PrometheusDefaultPeriod)
			return nil // Return success to prevent circuit breaker
		}

		tk.LogIt(tk.LogDebug, "[Metrics] Successfully collected %d conntrack entries\n", len(localConntrackInfo))

		// Debug: Log first few entries to understand data structure
		for i, ct := range localConntrackInfo {
			if i < 3 { // Log first 3 entries for debugging
				tk.LogIt(tk.LogDebug, "[Metrics] ConntrackInfo[%d]: SIP=%s, DIP=%s, Sport=%d, Dport=%d, Proto=%s, Service=%s, State=%s, Bytes=%d, Pkts=%d\n",
					i, ct.Sip, ct.Dip, ct.Sport, ct.Dport, ct.Proto, ct.ServiceName, ct.CState, ct.Bytes, ct.Pkts)
			}
		}

		localStats := make(map[ConntrackKey]Stats, len(localConntrackInfo))
		for _, ct := range localConntrackInfo {
			key := MakeConntrackKey(ct)
			localStats[key] = Stats{
				Bytes:   ct.Bytes,
				Packets: ct.Pkts,
			}
		}

		mutex.Lock()
		ConntrackInfo = localConntrackInfo // Update global ConntrackInfo with fresh data from eBPF
		ConntrackStats = localStats
		tk.LogIt(tk.LogDebug, "[Metrics] Updated global ConntrackInfo with %d entries and ConntrackStats with %d entries\n", len(ConntrackInfo), len(localStats))
		mutex.Unlock()

		time.Sleep(PrometheusDefaultPeriod)
		return nil
	}, "conntrack_collection", ctx)
}

func RunGetEndpoint(ctx context.Context) {
	safeGoroutineOperation(func(ctx context.Context) error {
		if hooks == nil {
			time.Sleep(PrometheusDefaultPeriod)
			return nil
		}
		info, err := hooks.NetEpHostGet()
		if err != nil {
			return fmt.Errorf("endpoint info get failed: %v", err)
		}

		mutex.Lock()
		EndPointInfo = info
		mutex.Unlock()

		// Update Prometheus gauge metrics for endpoint health.
		// Single definition: anything not "ok" counts as unhealthy.
		var healthyCount, unhealthyCount uint64
		for _, ep := range info {
			if ep.CurrState == "ok" {
				healthyCount++
			} else {
				unhealthyCount++
			}
		}
		healthyHostCount.Set(float64(healthyCount))
		unHealthyHostCount.Set(float64(unhealthyCount))

		if enableSharedMetrics {
			SetSharedMetric("healthy_host_count", float64(healthyCount))
			SetSharedMetric("unhealthy_host_count", float64(unhealthyCount))
		}

		time.Sleep(PrometheusDefaultPeriod)
		return nil
	}, "endpoint_collection", ctx)
}

func RunGetLBRule(ctx context.Context) {
	safeGoroutineOperation(func(ctx context.Context) error {
		if hooks == nil {
			time.Sleep(PrometheusDefaultPeriod)
			return nil
		}
		info, err := hooks.NetLbRuleGet()
		if err != nil {
			return fmt.Errorf("LB rule get failed: %v", err)
		}

		mutex.Lock()
		LBRuleInfo = info
		mutex.Unlock()

		ruleCount.Set(float64(len(info)))

		if enableSharedMetrics {
			SetSharedMetric("lb_rule_count", float64(len(info)))
		}

		collectLbRuleTraffic(info)

		time.Sleep(PrometheusDefaultPeriod)
		return nil
	}, "lbrule_collection", ctx)
}

// collectLbRuleTraffic feeds the aggregate traffic counters (processed_* and
// per-service service_traffic_*) from the CUMULATIVE data-plane per-endpoint
// rule counters, using the same delta-accumulation idiom as RunGetFwRule.
//
// Rationale (finding D2): the conntrack-sweep path only ever sees flows alive
// across a 10s sweep boundary, so with short-lived connections it undercounts
// systematically (measured: DP rule counter +869 pkts vs +43 via the sweep).
// The DP counters are exact. Flow-identity breakdowns (per-client sip /
// per-endpoint dip) and the active-connection gauges necessarily stay
// conntrack-derived — they are documented as a persistent-flow view.
func collectLbRuleTraffic(info []cmn.LbRuleMod) {
	seed := lbStatsFirstCycle

	var totBytes, totPackets uint64
	protoBytes := make(map[string]uint64, 3)
	protoPackets := make(map[string]uint64, 3)
	svcBytes := make(map[string]uint64)
	svcPackets := make(map[string]uint64)
	epBytes := make(map[[2]string]uint64)
	epPackets := make(map[[2]string]uint64)
	currentPairs := make(map[[2]string]bool, len(prevBackendEpPairs))

	currentEps := make(map[string]bool, len(prevLbEpStats))
	for i := range info {
		rule := &info[i]
		proto := strings.ToLower(rule.Serv.Proto)
		svc := rule.Serv.Name
		if svc == "-" { // placeholder for unnamed rules, same contract as MakeConntrackKey
			svc = ""
		}
		ruleIdent := fmt.Sprintf("%s|%d|%d|%s", rule.Serv.ServIP, rule.Serv.ServPort, rule.Serv.BlockNum, proto)
		for j := range rule.Eps {
			ep := &rule.Eps[j]
			pkts, bytes, ok := parseCounterPacketsBytes(ep.Counters)
			if !ok {
				continue
			}
			key := fmt.Sprintf("%s|%s|%d", ruleIdent, ep.EpIP, ep.EpPort)
			currentEps[key] = true

			// Register config presence for the per-backend series even on the
			// seed cycle, so the departure detector below never mistakes a
			// seed pass for a mass endpoint removal.
			var pair [2]string
			if svc != "" {
				pair = [2]string{svc, fmt.Sprintf("%s:%d", ep.EpIP, ep.EpPort)}
				currentPairs[pair] = true
			}

			// First sight or counter reset (rule/endpoint re-created with a
			// fresh DP counter): the full current value is the delta
			deltaPkts, deltaBytes := pkts, bytes
			if prev, seen := prevLbEpStats[key]; seen && pkts >= prev.Packets && bytes >= prev.Bytes {
				deltaPkts = pkts - prev.Packets
				deltaBytes = bytes - prev.Bytes
			}
			prevLbEpStats[key] = Stats{Bytes: bytes, Packets: pkts}
			if seed {
				// Baseline-only: cumulative totals of pre-existing rules must
				// not appear as a phantom burst on (re-)enable
				continue
			}

			totBytes += deltaBytes
			totPackets += deltaPkts
			protoBytes[proto] += deltaBytes
			protoPackets[proto] += deltaPkts
			if svc != "" {
				svcBytes[svc] += deltaBytes
				svcPackets[svc] += deltaPkts
				epBytes[pair] += deltaBytes
				epPackets[pair] += deltaPkts
			}
		}
	}

	// Drop baselines for endpoints that no longer exist so rule churn cannot
	// leak memory (same pattern as the firewall collector)
	for key := range prevLbEpStats {
		if !currentEps[key] {
			delete(prevLbEpStats, key)
		}
	}

	lbStatsFirstCycle = false
	if seed {
		prevBackendEpPairs = currentPairs
		return
	}

	processedBytes.Add(float64(totBytes))
	processedPackets.Add(float64(totPackets))
	processedTCPBytes.Add(float64(protoBytes["tcp"]))
	processedUDPBytes.Add(float64(protoBytes["udp"]))
	processedSCTPBytes.Add(float64(protoBytes["sctp"]))
	processedTCPPackets.Add(float64(protoPackets["tcp"]))
	processedUDPPackets.Add(float64(protoPackets["udp"]))
	processedSCTPPackets.Add(float64(protoPackets["sctp"]))

	for svc, b := range svcBytes {
		serviceTrafficBytes.WithLabelValues(svc).Add(float64(b))
	}
	for svc, p := range svcPackets {
		serviceTrafficPackets.WithLabelValues(svc).Add(float64(p))
	}

	for pair, b := range epBytes {
		backendTrafficBytes.WithLabelValues(pair[0], pair[1]).Add(float64(b))
	}
	for pair, p := range epPackets {
		backendTrafficPackets.WithLabelValues(pair[0], pair[1]).Add(float64(p))
	}
	// Reap per-backend series whose endpoint left the rule config, so churn
	// cannot accumulate stale children (same hygiene as the prevLbEpStats
	// baseline cleanup above). Both vecs are fed only by this goroutine, so
	// a delete cannot race a concurrent Add back into existence.
	for pair := range prevBackendEpPairs {
		if !currentPairs[pair] {
			backendTrafficBytes.DeleteLabelValues(pair[0], pair[1])
			backendTrafficPackets.DeleteLabelValues(pair[0], pair[1])
		}
	}
	prevBackendEpPairs = currentPairs

	if enableSharedMetrics {
		AddSharedMetric("processed_bytes", float64(totBytes))
		AddSharedMetric("processed_packets", float64(totPackets))
		AddSharedMetric("processed_tcp_bytes", float64(protoBytes["tcp"]))
		AddSharedMetric("processed_udp_bytes", float64(protoBytes["udp"]))
		AddSharedMetric("processed_sctp_bytes", float64(protoBytes["sctp"]))
	}
}

// RunActiveConntrackCount is the main entry point - delegates to optimized version
func RunActiveConntrackCount(ctx context.Context) {
	safeGoroutineOperation(func(ctx context.Context) error {
		RunOptimizedActiveConntrackCount(ctx)
		return nil
	}, "active_conntrack", ctx)
}

// RunOptimizedActiveConntrackCount - periodic conntrack processing feeding Prometheus metrics
func RunOptimizedActiveConntrackCount(ctx context.Context) {
	ticker := time.NewTicker(GetCollectionInterval(Critical)) // 10s
	defer ticker.Stop()

	tk.LogIt(tk.LogInfo, "[Metrics] Conntrack metrics collection started (interval: %v)\n", GetCollectionInterval(Critical))

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			conntrackData := getConntrackDataOptimized()
			processConntrackDataOptimized(conntrackData)
		}
	}
}

// getConntrackDataOptimized retrieves a snapshot copy of the current conntrack data
func getConntrackDataOptimized() []cmn.CtInfo {
	mutex.Lock()
	defer mutex.Unlock()

	conntrackSlice := make([]cmn.CtInfo, len(ConntrackInfo))
	copy(conntrackSlice, ConntrackInfo)

	return conntrackSlice
}

// UnifiedMetrics holds all metric values to ensure consistency across systems
type UnifiedMetrics struct {
	// Connection tracking metrics
	ActiveCount uint64
	TcpCount    uint64
	UdpCount    uint64
	SctpCount   uint64
	ClosedCount uint64
	NewFlows    uint64
	ErrorCount  uint64

	// Traffic metrics
	TotalBytes           uint64
	TotalPackets         uint64
	TcpBytesProcessed    uint64
	UdpBytesProcessed    uint64
	SctpBytesProcessed   uint64
	TcpPacketsProcessed  uint64
	UdpPacketsProcessed  uint64
	SctpPacketsProcessed uint64

	// Service-level metrics
	ServiceRequests map[string]uint64
	ServiceErrors   map[string]uint64
	ServiceBytes    map[string]uint64
	ServicePackets  map[string]uint64

	// New sessions per (service, "dip:dport" endpoint) — mirrors the
	// ServiceRequests exactly-once semantics (counted at creation, or at
	// close for flows never seen active) with the backend attribution kept.
	ServiceEpConnections map[string]map[string]uint64

	// Distribution metrics
	ServiceTraffic    map[string]float64
	ServiceDipTraffic map[string]map[string]float64
	ServiceSipPackets map[string]map[string]float64 // NEW: service -> client_ip -> packet_count
}

// addEpConnection records one new session for (service, "dip:dport") in the
// unified accumulator; flushed to backend_traffic_connections_total by
// updateAllMetricSystems on non-seed sweeps.
func (u *UnifiedMetrics) addEpConnection(service, dip, dport string) {
	if service == "" || dip == "" {
		return
	}
	m := u.ServiceEpConnections[service]
	if m == nil {
		m = make(map[string]uint64)
		u.ServiceEpConnections[service] = m
	}
	m[dip+":"+dport]++
}

// processConntrackDataOptimized processes conntrack data with unified metrics across all systems.
// Semantics:
//   - A request is counted exactly once per connection: at creation for flows
//     seen active, or at close for short-lived flows that appear already closed.
//   - Closed entries lingering in the conntrack table are finalized once and
//     then ignored (finalizedClosedFlows), never re-counted per sweep.
//   - Errors are counted on state transition, not per sweep.
//   - The first sweep after Init only seeds baselines (no counter adds), so
//     pre-existing flows do not produce a phantom traffic burst.
func processConntrackDataOptimized(info []cmn.CtInfo) {
	// Initialize unified metrics structure
	unified := &UnifiedMetrics{
		ServiceRequests:      make(map[string]uint64),
		ServiceErrors:        make(map[string]uint64),
		ServiceBytes:         make(map[string]uint64),
		ServicePackets:       make(map[string]uint64),
		ServiceEpConnections: make(map[string]map[string]uint64),
		ServiceTraffic:       make(map[string]float64, MaxPoolStatsServiceSize),
		ServiceDipTraffic:    make(map[string]map[string]float64, MaxPoolStatsServiceSize),
		ServiceSipPackets:    make(map[string]map[string]float64, MaxPoolStatsServiceSize),
	}

	currentConntrackInfo := make(map[ConntrackKey]bool)
	currentConntrackStats := make(map[ConntrackKey]Stats)
	currentClosedFlows := make(map[ConntrackKey]bool)
	currentErrorFlows := make(map[ConntrackKey]bool)

	// Get current ConntrackStats with proper locking
	mutex.Lock()
	localConntrackStats := make(map[ConntrackKey]Stats, len(ConntrackStats))
	for k, stats := range ConntrackStats {
		localConntrackStats[k] = stats
	}
	mutex.Unlock()

	conntrackRWMutex.RLock()
	seedOnly := firstCollectionCycle
	localPrevConntrackInfo := make(map[ConntrackKey]bool, len(prevConntrackInfo))
	for k, v := range prevConntrackInfo {
		localPrevConntrackInfo[k] = v
	}
	localPrevConntrackStats := make(map[ConntrackKey]Stats, len(prevConntrackStats))
	for k, v := range prevConntrackStats {
		localPrevConntrackStats[k] = v
	}
	localFinalizedClosed := make(map[ConntrackKey]bool, len(finalizedClosedFlows))
	for k, v := range finalizedClosedFlows {
		localFinalizedClosed[k] = v
	}
	localPrevErrorFlows := make(map[ConntrackKey]bool, len(prevErrorFlows))
	for k, v := range prevErrorFlows {
		localPrevErrorFlows[k] = v
	}
	conntrackRWMutex.RUnlock()

	// Process each conntrack entry and accumulate unified metrics
	tk.LogIt(tk.LogDebug, "[Metrics] Processing %d conntrack entries for unified metrics\n", len(info))
	for _, ct := range info {
		key := MakeConntrackKey(ct)

		// Process closed connections' FINAL metrics exactly once
		if ct.CState == "closed" {
			unified.ClosedCount++
			currentClosedFlows[key] = true

			// Already finalized in an earlier cycle - the entry is just
			// lingering in the conntrack table; don't re-count it
			if localFinalizedClosed[key] {
				continue
			}

			// Extract serviceName from KEY (always available): for closed
			// connections ct.ServiceName may be empty/cleared by eBPF, but the
			// serviceName is preserved in the ConntrackKey from establishment
			sip, _, dip, dport, _, serviceName := parseConntrackKey(key)

			// Capture final metrics for closed connection
			if currentStats, exists := localConntrackStats[key]; exists && !seedOnly {
				wasTracked := localPrevConntrackInfo[key]
				var finalDiffBytes, finalDiffPackets uint64

				// Check if we've seen this connection before (has previous stats)
				if prevStats, hasPrevStats := localPrevConntrackStats[key]; hasPrevStats {
					// Connection was tracked previously - calculate delta
					if currentStats.Bytes >= prevStats.Bytes {
						finalDiffBytes = currentStats.Bytes - prevStats.Bytes
					}
					if currentStats.Packets >= prevStats.Packets {
						finalDiffPackets = currentStats.Packets - prevStats.Packets
					}
				} else {
					// Short-lived connection that appeared and closed between
					// collection cycles: use TOTAL stats as its traffic
					finalDiffBytes = currentStats.Bytes
					finalDiffPackets = currentStats.Packets
					tk.LogIt(tk.LogDebug, "[Metrics] NEW closed connection (short-lived): %s->%s, TotalBytes=%d, TotalPkts=%d\n",
						ct.Sip, ct.Dip, finalDiffBytes, finalDiffPackets)
				}

				// Add final metrics to unified totals
				unified.TotalBytes += finalDiffBytes
				unified.TotalPackets += finalDiffPackets

				// Protocol-specific tracking for closed connections
				switch ct.Proto {
				case "tcp":
					unified.TcpBytesProcessed += finalDiffBytes
					unified.TcpPacketsProcessed += finalDiffPackets
				case "udp":
					unified.UdpBytesProcessed += finalDiffBytes
					unified.UdpPacketsProcessed += finalDiffPackets
				case "sctp":
					unified.SctpBytesProcessed += finalDiffBytes
					unified.SctpPacketsProcessed += finalDiffPackets
				}

				// Per-service tracking for closed connections - USE serviceName from KEY
				if serviceName != "" {
					unified.ServiceBytes[serviceName] += finalDiffBytes
					unified.ServicePackets[serviceName] += finalDiffPackets

					// Count a request only if the flow was never seen active:
					// flows seen active were already counted at creation
					if !wasTracked {
						unified.NewFlows++
						unified.ServiceRequests[serviceName]++
						unified.addEpConnection(serviceName, dip, dport)
					}

					// Update Prometheus counters for traffic visibility
					lbRuleInteractionBytes.WithLabelValues(serviceName, sip, dip).Add(float64(finalDiffBytes))
					lbRuleInteractionPackets.WithLabelValues(serviceName, sip, dip).Add(float64(finalDiffPackets))
					if enableSharedMetrics {
						AddLabeledMetric("lb_rule_interaction_bytes", map[string]string{"service": serviceName, "sip": sip, "dip": dip}, float64(finalDiffBytes))
						AddLabeledMetric("lb_rule_interaction_packets", map[string]string{"service": serviceName, "sip": sip, "dip": dip}, float64(finalDiffPackets))
					}

					// Update distribution tracking
					if _, exists := unified.ServiceTraffic[serviceName]; !exists {
						unified.ServiceTraffic[serviceName] = 0
						unified.ServiceDipTraffic[serviceName] = make(map[string]float64)
						unified.ServiceSipPackets[serviceName] = make(map[string]float64)
					}
					unified.ServiceTraffic[serviceName] += float64(finalDiffBytes)
					unified.ServiceDipTraffic[serviceName][dip] += float64(finalDiffBytes)
					unified.ServiceSipPackets[serviceName][sip] += float64(finalDiffPackets)
				}

				closedConnectionsProcessed.Inc()
				tk.LogIt(tk.LogDebug, "[Metrics] Processed CLOSED flow final metrics: %s->%s, FinalBytes=%d, FinalPkts=%d, ServiceName=%s\n",
					ct.Sip, ct.Dip, finalDiffBytes, finalDiffPackets, serviceName)
			}
			// Closed connections are NOT added to currentConntrackInfo (they're gone)
			continue
		}

		isNewFlow := !localPrevConntrackInfo[key]

		if isNewFlow && !seedOnly {
			unified.NewFlows++
			tk.LogIt(tk.LogDebug, "[Metrics] Found new flow: %s (Service: %s)\n", string(key), ct.ServiceName)

			// Request counting: a request is counted exactly once, at flow creation.
			// CRITICAL: Extract serviceName from KEY (always preserved) not ct.ServiceName (may be empty)
			_, _, newDip, newDport, _, serviceNameForRequest := parseConntrackKey(key)
			if serviceNameForRequest != "" {
				unified.ServiceRequests[serviceNameForRequest]++
				unified.addEpConnection(serviceNameForRequest, newDip, newDport)
			}
		}
		unified.ActiveCount++
		tk.LogIt(tk.LogDebug, "[Metrics] Active flow: %s->%s, Service=%s, Bytes=%d, Pkts=%d\n",
			ct.Sip, ct.Dip, ct.ServiceName, ct.Bytes, ct.Pkts)

		// Protocol-specific flow counting
		switch ct.Proto {
		case "tcp":
			unified.TcpCount++
		case "udp":
			unified.UdpCount++
		case "sctp":
			unified.SctpCount++
		}

		currentConntrackInfo[key] = true

		// Error accounting: count transitions INTO an error state, not error
		// state per sweep - a single stuck connection must not produce a
		// constant fake error rate
		if isErrorState(ct) {
			currentErrorFlows[key] = true
			if !seedOnly && !localPrevErrorFlows[key] {
				unified.ErrorCount++
				// CRITICAL: Use serviceName from KEY (always preserved) not ct.ServiceName
				_, _, _, _, _, serviceNameError := parseConntrackKey(key)
				if serviceNameError != "" {
					unified.ServiceErrors[serviceNameError]++
				}
			}
		}

		// Handle byte/packet counter overflow with unified metrics
		if currentStats, exists := localConntrackStats[key]; exists {
			// Store current stats for next cycle (always, even for new flows)
			currentConntrackStats[key] = currentStats

			if isNewFlow {
				if seedOnly {
					// First sweep after Init: only seed the baseline; adding the
					// cumulative totals of pre-existing flows would produce a
					// phantom traffic burst on (re-)enable
					continue
				}
				// Truly new flow - use current stats as its initial traffic so
				// the first cycle's traffic is captured instead of lost
				unified.TotalBytes += currentStats.Bytes
				unified.TotalPackets += currentStats.Packets

				switch ct.Proto {
				case "tcp":
					unified.TcpBytesProcessed += currentStats.Bytes
					unified.TcpPacketsProcessed += currentStats.Packets
				case "udp":
					unified.UdpBytesProcessed += currentStats.Bytes
					unified.UdpPacketsProcessed += currentStats.Packets
				case "sctp":
					unified.SctpBytesProcessed += currentStats.Bytes
					unified.SctpPacketsProcessed += currentStats.Packets
				}

				// CRITICAL: Use serviceName from KEY (always preserved)
				sip, _, dip, _, _, serviceName := parseConntrackKey(key)
				if serviceName != "" {
					unified.ServiceBytes[serviceName] += currentStats.Bytes
					unified.ServicePackets[serviceName] += currentStats.Packets

					// Update distribution tracking for new flows
					if _, exists := unified.ServiceTraffic[serviceName]; !exists {
						unified.ServiceTraffic[serviceName] = 0
						unified.ServiceDipTraffic[serviceName] = make(map[string]float64)
						unified.ServiceSipPackets[serviceName] = make(map[string]float64)
					}
					unified.ServiceTraffic[serviceName] += float64(currentStats.Bytes)
					unified.ServiceDipTraffic[serviceName][dip] += float64(currentStats.Bytes)
					unified.ServiceSipPackets[serviceName][sip] += float64(currentStats.Packets)

					// Update Prometheus counters (every 10s for real-time monitoring)
					lbRuleInteractionBytes.WithLabelValues(serviceName, sip, dip).Add(float64(currentStats.Bytes))
					lbRuleInteractionPackets.WithLabelValues(serviceName, sip, dip).Add(float64(currentStats.Packets))
					if enableSharedMetrics {
						AddLabeledMetric("lb_rule_interaction_bytes", map[string]string{"service": serviceName, "sip": sip, "dip": dip}, float64(currentStats.Bytes))
						AddLabeledMetric("lb_rule_interaction_packets", map[string]string{"service": serviceName, "sip": sip, "dip": dip}, float64(currentStats.Packets))
					}
				}

				tk.LogIt(tk.LogDebug, "[Conntrack] NEW flow first-cycle capture: key=%s, Bytes=%d, Pkts=%d\n",
					string(key), currentStats.Bytes, currentStats.Packets)

				continue // Move to next entry after processing new flow
			}

			prevStats, hasPrevStats := localPrevConntrackStats[key]
			if !hasPrevStats {
				// This shouldn't happen since isNewFlow would be true, but handle defensively
				tk.LogIt(tk.LogWarning, "[Conntrack] Missing prev stats for existing flow %s, using current as baseline\n", string(key))
				continue
			}

			var diffBytes, diffPackets uint64
			counterResetDetected := false

			if prevStats.Bytes > currentStats.Bytes {
				// Counter reset detected - use current value as the delta (new baseline)
				counterResetEvents.Inc()
				counterResetDetected = true
				diffBytes = currentStats.Bytes // Use current as new baseline delta
				tk.LogIt(tk.LogWarning, "[Conntrack] Byte counter RESET: key=%s prev=%d curr=%d, using current=%d as delta\n",
					string(key), prevStats.Bytes, currentStats.Bytes, diffBytes)
			} else {
				diffBytes = currentStats.Bytes - prevStats.Bytes

				// Additional validation: detect and log unreasonably large jumps
				if diffBytes > 10*1024*1024*1024 {
					tk.LogIt(tk.LogWarning, "[Conntrack] SPIKE ALERT: Huge byte diff for key=%s prev=%d curr=%d diff=%d (%.2fGB in 10s)\n",
						string(key), prevStats.Bytes, currentStats.Bytes, diffBytes, float64(diffBytes)/(1024*1024*1024))
				}
			}

			// Handle packet counter with proper reset detection
			if prevStats.Packets > currentStats.Packets {
				counterResetDetected = true
				diffPackets = currentStats.Packets // Use current as new baseline delta
				tk.LogIt(tk.LogWarning, "[Conntrack] Packet counter RESET: key=%s prev=%d curr=%d, using current=%d as delta\n",
					string(key), prevStats.Packets, currentStats.Packets, diffPackets)
			} else {
				diffPackets = currentStats.Packets - prevStats.Packets

				if diffPackets > 10*1000*1000 {
					tk.LogIt(tk.LogWarning, "[Conntrack] SPIKE ALERT: Huge packet diff for key=%s prev=%d curr=%d diff=%d (%.2fM in 10s)\n",
						string(key), prevStats.Packets, currentStats.Packets, diffPackets, float64(diffPackets)/(1000*1000))
				}
			}

			// Log counter reset but DON'T skip metrics
			if counterResetDetected {
				tk.LogIt(tk.LogDebug, "[Conntrack] Counter reset handled for flow %s, using deltas: bytes=%d, pkts=%d\n",
					string(key), diffBytes, diffPackets)
			}

			// Accumulate unified totals
			unified.TotalBytes += diffBytes
			unified.TotalPackets += diffPackets

			// Protocol-specific byte and packet tracking using unified approach
			switch ct.Proto {
			case "tcp":
				unified.TcpBytesProcessed += diffBytes
				unified.TcpPacketsProcessed += diffPackets
			case "udp":
				unified.UdpBytesProcessed += diffBytes
				unified.UdpPacketsProcessed += diffPackets
			case "sctp":
				unified.SctpBytesProcessed += diffBytes
				unified.SctpPacketsProcessed += diffPackets
			}

			// Parse conntrack key for service and endpoint information
			// (serviceName from the KEY is always preserved; ct.ServiceName may be empty)
			sip, _, dip, _, _, serviceName := parseConntrackKey(key)

			// Accumulate per-service totals in unified metrics. Flows from
			// unnamed LB rules have an empty serviceName in the conntrack key;
			// skip them entirely (same contract as the closed-flow path) so no
			// empty-`service`-label series are ever emitted (finding D1).
			if serviceName != "" {
				unified.ServiceBytes[serviceName] += diffBytes
				unified.ServicePackets[serviceName] += diffPackets

				// Per-service and per-endpoint traffic calculation for distribution ratios
				if _, exists := unified.ServiceTraffic[serviceName]; !exists {
					unified.ServiceTraffic[serviceName] = 0
					unified.ServiceDipTraffic[serviceName] = make(map[string]float64)
					unified.ServiceSipPackets[serviceName] = make(map[string]float64)
				}
				unified.ServiceTraffic[serviceName] += float64(diffBytes)
				unified.ServiceDipTraffic[serviceName][dip] += float64(diffBytes)
				unified.ServiceSipPackets[serviceName][sip] += float64(diffPackets)

				// Update Prometheus counters for traffic visibility (every 10s for real-time monitoring)
				lbRuleInteractionBytes.WithLabelValues(serviceName, sip, dip).Add(float64(diffBytes))
				lbRuleInteractionPackets.WithLabelValues(serviceName, sip, dip).Add(float64(diffPackets))
				if enableSharedMetrics {
					AddLabeledMetric("lb_rule_interaction_bytes", map[string]string{"service": serviceName, "sip": sip, "dip": dip}, float64(diffBytes))
					AddLabeledMetric("lb_rule_interaction_packets", map[string]string{"service": serviceName, "sip": sip, "dip": dip}, float64(diffPackets))
				}
			}
		}

	}

	// Update all prometheus and shared metrics using unified values
	updateAllMetricSystems(unified, seedOnly)

	if !seedOnly {
		// Per-endpoint (dip) and per-client (sip) breakdowns stay
		// conntrack-derived: flow identity only exists here. They are a
		// PERSISTENT-FLOW VIEW — flows shorter than one 10s sweep are not
		// visible (finding D2). The aggregate service_traffic_* and
		// processed_* counters are fed from the exact DP rule counters in
		// collectLbRuleTraffic instead, so they must NOT be added here.
		for service := range unified.ServiceTraffic {
			// Send raw endpoint traffic data per service
			for dip, dipTraffic := range unified.ServiceDipTraffic[service] {
				endpointTrafficBytes.WithLabelValues(service, dip).Add(dipTraffic)
			}

			// Send raw client(source ip) request packet data per service
			for sip, sipPackets := range unified.ServiceSipPackets[service] {
				clientTrafficPackets.WithLabelValues(service, sip).Add(sipPackets)
			}
		}
	}

	// Only keep stats for connections still present in currentConntrackInfo, so
	// closed/disappeared connections cannot persist and cause phantom metrics
	cleanedPrevStats := make(map[ConntrackKey]Stats, len(currentConntrackInfo))
	for key := range currentConntrackInfo {
		// Only store stats for connections that are currently active
		// This ensures closed connections are removed from tracking
		if stats, exists := localConntrackStats[key]; exists {
			cleanedPrevStats[key] = stats
		}
	}

	// Enforce the bounded-map limit; on overflow trim arbitrary entries (maps
	// are unordered) and log a warning
	if len(cleanedPrevStats) > MaxPrevConntrackEntries {
		trimCount := len(cleanedPrevStats) - MaxPrevConntrackEntries
		trimmed := 0
		for key := range cleanedPrevStats {
			if trimmed >= trimCount {
				break
			}
			delete(cleanedPrevStats, key)
			trimmed++
		}
		tk.LogIt(tk.LogWarning, "[Metrics] MEMORY PROTECTION: Trimmed %d entries from prevConntrackStats (max=%d)\n",
			trimmed, MaxPrevConntrackEntries)
	}

	// Log cleanup stats for observability
	removedCount := len(localPrevConntrackStats) - len(cleanedPrevStats)
	if removedCount > 0 {
		tk.LogIt(tk.LogDebug, "[Metrics] Cleaned up %d disappeared connections from tracking (prev=%d, current=%d)\n",
			removedCount, len(localPrevConntrackStats), len(cleanedPrevStats))
		atomic.AddUint64(&prevStatsCleanupCount, uint64(removedCount))
	}

	// Update the previous conntrack info and stats for overflow handling
	conntrackRWMutex.Lock()
	prevConntrackInfo = currentConntrackInfo
	// Use cleaned stats instead of raw localConntrackStats
	prevConntrackStats = cleanedPrevStats
	// Closed keys seen this cycle are all finalized now (processed this cycle or
	// earlier); keys that left the conntrack table drop out automatically
	finalizedClosedFlows = currentClosedFlows
	prevErrorFlows = currentErrorFlows
	firstCollectionCycle = false
	conntrackRWMutex.Unlock()
}

// updateAllMetricSystems updates prometheus and shared metrics using unified
// values. With seedOnly (first sweep after Init), only point-in-time gauges are
// updated; cumulative counters are skipped because the sweep only seeded
// baselines.
func updateAllMetricSystems(unified *UnifiedMetrics, seedOnly bool) {
	// 1. Update point-in-time gauges
	activeConntrackCount.Set(float64(unified.ActiveCount))
	activeFlowCountTcp.Set(float64(unified.TcpCount))
	activeFlowCountUdp.Set(float64(unified.UdpCount))
	activeFlowCountSctp.Set(float64(unified.SctpCount))
	newFlowCount.Set(float64(unified.NewFlows))

	// Mirror the gauges into the shared-metrics store for the /metrics/* REST endpoints
	if enableSharedMetrics {
		SetSharedMetric("active_conntrack_count", float64(unified.ActiveCount))
		SetSharedMetric("active_flow_count_tcp", float64(unified.TcpCount))
		SetSharedMetric("active_flow_count_udp", float64(unified.UdpCount))
		SetSharedMetric("active_flow_count_sctp", float64(unified.SctpCount))
		SetSharedMetric("inactive_flow_count", float64(unified.ClosedCount))
		SetSharedMetric("new_flow_count", float64(unified.NewFlows))
	}

	if seedOnly {
		return
	}

	// 2. Update cumulative counters
	// Request counting: unified exactly-once semantics (counted at creation, or
	// at close for short-lived flows never seen active). SWEEP-SAMPLED (D2):
	// sessions born and closed inside one 10s sweep are not observable here, so
	// these are "sampled new sessions", not an exact request count. The DP rule
	// counters cannot replace them — they count packets, not sessions — and the
	// meaning is kept unchanged so existing consumers are not silently rescaled.
	totalRequests.Add(float64(unified.NewFlows))
	totalErrors.Add(float64(unified.ErrorCount))

	// NOTE: processed_* and service_traffic_* are fed from the exact DP rule
	// counters in collectLbRuleTraffic (finding D2) — not added here anymore.

	// Update per-service Prometheus metrics
	for service, count := range unified.ServiceRequests {
		totalRequestsPerService.WithLabelValues(service).Add(float64(count))
	}
	for service, count := range unified.ServiceErrors {
		totalErrorsPerService.WithLabelValues(service).Add(float64(count))
	}
	for service, eps := range unified.ServiceEpConnections {
		for endpoint, count := range eps {
			backendTrafficConnections.WithLabelValues(service, endpoint).Add(float64(count))
		}
	}

	// Mirror the cumulative counters into the shared-metrics store (the
	// processed_* mirrors moved to collectLbRuleTraffic with their source)
	if enableSharedMetrics {
		AddSharedMetric("total_requests", float64(unified.NewFlows))
		AddSharedMetric("total_errors", float64(unified.ErrorCount))
		for service, count := range unified.ServiceRequests {
			AddLabeledMetric("total_requests_per_service", map[string]string{"service": service}, float64(count))
		}
		for service, count := range unified.ServiceErrors {
			AddLabeledMetric("total_errors_per_service", map[string]string{"service": service}, float64(count))
		}
	}
}

func parseConntrackKey(key ConntrackKey) (sip, sport, dip, dport, proto, serviceName string) {
	parts := strings.Split(string(key), "|")
	if len(parts) == 6 {
		return parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
	}
	return "", "", "", "", "", ""
}

// parseCounterPacketsBytes parses a data-plane counter string formatted as
// "packets:bytes" (see pkg/loxinet/rules.go) into both components.
func parseCounterPacketsBytes(counter string) (packets, bytes uint64, ok bool) {
	fields := strings.SplitN(counter, ":", 2)
	if len(fields) != 2 {
		return 0, 0, false
	}
	p, errP := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 64)
	b, errB := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64)
	if errP != nil || errB != nil {
		return 0, 0, false
	}
	return p, b, true
}

// parseFwCounterPackets parses the data-plane rule counter string, formatted as
// "packets:bytes" (see pkg/loxinet/rules.go), and returns the packets count.
func parseFwCounterPackets(counter string) (uint64, bool) {
	fields := strings.SplitN(counter, ":", 2)
	if len(fields) == 0 || fields[0] == "" {
		return 0, false
	}
	v, parseErr := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 64)
	if parseErr != nil {
		return 0, false
	}
	return v, true
}

func RunGetFwRule(ctx context.Context) {
	safeGoroutineOperation(func(ctx context.Context) error {
		if hooks == nil {
			time.Sleep(PrometheusDefaultPeriod)
			return nil
		}
		info, err := hooks.NetFwRuleGet()
		if err != nil {
			return fmt.Errorf("firewall rule get failed: %v", err)
		}

		mutex.Lock()
		FWRuleInfo = info
		mutex.Unlock()

		// The data-plane drop counters are cumulative per rule; add per-cycle
		// deltas to the Prometheus counters so rate() behaves correctly
		var totalDropsCumulative uint64
		currentRules := make(map[string]bool, len(info))
		for _, rule := range info {
			drops, ok := parseFwCounterPackets(rule.Opts.Counter)
			if !ok {
				tk.LogIt(tk.LogDebug, "[Metrics] Unparsable firewall counter %q for pref %d\n",
					rule.Opts.Counter, rule.Rule.Pref)
				continue
			}
			ruleID := strconv.Itoa(int(rule.Rule.Pref))
			currentRules[ruleID] = true
			totalDropsCumulative += drops

			delta := drops
			if prev, seen := prevFwRuleDrops[ruleID]; seen && drops >= prev {
				delta = drops - prev
			}
			// On first sight or counter reset (rule re-created), the full
			// current value is the delta
			if delta > 0 {
				totalDropsByFwPerRule.WithLabelValues(ruleID).Add(float64(delta))
				totalDropsByFw.Add(float64(delta))
			}
			prevFwRuleDrops[ruleID] = drops

			if enableSharedMetrics {
				SetLabeledMetric("total_fw_drops_per_rule", map[string]string{"fw_rule": ruleID}, float64(drops))
			}
		}

		// Remove series and baselines for rules that no longer exist
		for ruleID := range prevFwRuleDrops {
			if !currentRules[ruleID] {
				delete(prevFwRuleDrops, ruleID)
				totalDropsByFwPerRule.DeleteLabelValues(ruleID)
				if enableSharedMetrics {
					DeleteLabeledMetric("total_fw_drops_per_rule", map[string]string{"fw_rule": ruleID})
				}
			}
		}

		fwRuleCount.Set(float64(len(info)))

		if enableSharedMetrics {
			SetSharedMetric("total_fw_drops", float64(totalDropsCumulative))
			SetSharedMetric("firewall_rules_count", float64(len(info)))
		}

		time.Sleep(PrometheusDefaultPeriod)
		return nil
	}, "firewall_collection", ctx)
}

// RunSecurityRateStats - Collect unified security rate limiting statistics
// (SYN flood, connection rate and UDP flood protection)
func RunSecurityRateStats(ctx context.Context) {
	safeGoroutineOperation(func(ctx context.Context) error {
		stats, err := hooks.NetSecurityRateStatsGet()
		if err != nil {
			return fmt.Errorf("security rate stats get failed: %v", err)
		}

		// Calculate deltas (eBPF counters are cumulative, following conntrack pattern)
		// Handle counter overflow/reset by checking if current < previous
		var (
			deltaSYNBlocked      uint64
			deltaSYNPassed       uint64
			deltaSYNCookies      uint64
			deltaConnBlocked     uint64
			deltaConnPassed      uint64
			deltaUDPBlocked      uint64
			deltaUDPPassed       uint64
			deltaUDPBytesBlocked uint64
			deltaUDPBytesPassed  uint64
		)

		// SYN flood deltas with overflow protection
		if stats.SYNBlocked >= prevSecurityStats.SYNBlocked {
			deltaSYNBlocked = stats.SYNBlocked - prevSecurityStats.SYNBlocked
		}
		if stats.SYNPassed >= prevSecurityStats.SYNPassed {
			deltaSYNPassed = stats.SYNPassed - prevSecurityStats.SYNPassed
		}
		if stats.SYNCookies >= prevSecurityStats.SYNCookies {
			deltaSYNCookies = stats.SYNCookies - prevSecurityStats.SYNCookies
		}

		// Connection rate deltas with overflow protection
		if stats.ConnBlocked >= prevSecurityStats.ConnBlocked {
			deltaConnBlocked = stats.ConnBlocked - prevSecurityStats.ConnBlocked
		}
		if stats.ConnPassed >= prevSecurityStats.ConnPassed {
			deltaConnPassed = stats.ConnPassed - prevSecurityStats.ConnPassed
		}

		// UDP flood deltas with overflow protection
		if stats.UDPBlocked >= prevSecurityStats.UDPBlocked {
			deltaUDPBlocked = stats.UDPBlocked - prevSecurityStats.UDPBlocked
		}
		if stats.UDPPassed >= prevSecurityStats.UDPPassed {
			deltaUDPPassed = stats.UDPPassed - prevSecurityStats.UDPPassed
		}
		if stats.UDPBytesBlocked >= prevSecurityStats.UDPBytesBlocked {
			deltaUDPBytesBlocked = stats.UDPBytesBlocked - prevSecurityStats.UDPBytesBlocked
		}
		if stats.UDPBytesPassed >= prevSecurityStats.UDPBytesPassed {
			deltaUDPBytesPassed = stats.UDPBytesPassed - prevSecurityStats.UDPBytesPassed
		}

		// Update Prometheus metrics with deltas (Counter.Add)
		securitySYNBlocked.Add(float64(deltaSYNBlocked))
		securitySYNPassed.Add(float64(deltaSYNPassed))
		securitySYNCookies.Add(float64(deltaSYNCookies))
		securityConnBlocked.Add(float64(deltaConnBlocked))
		securityConnPassed.Add(float64(deltaConnPassed))
		securityUDPBlocked.Add(float64(deltaUDPBlocked))
		securityUDPPassed.Add(float64(deltaUDPPassed))
		securityUDPBytesBlocked.Add(float64(deltaUDPBytesBlocked))
		securityUDPBytesPassed.Add(float64(deltaUDPBytesPassed))

		// Unique IPs is a gauge (point-in-time value, not cumulative)
		securityUniqueIPs.Set(float64(stats.UniqueIPs))

		// Store current stats for next cycle
		prevSecurityStats = stats

		time.Sleep(PrometheusDefaultPeriod)
		return nil
	}, "security_rate_stats", ctx)
}

// RunIPFilterStats - Collect IP filter (whitelist/blacklist) statistics
// Pattern: Follows RunGetFwRule pattern for periodic metrics collection
// Collects: Per-rule packet/byte counters for both blacklist and whitelist
func RunIPFilterStats(ctx context.Context) {
	safeGoroutineOperation(func(ctx context.Context) error {
		entries, err := hooks.NetIPFilterGet()
		if err != nil {
			return fmt.Errorf("IP filter get failed: %v", err)
		}

		// Track rule counts by type
		blacklistCount := 0
		whitelistCount := 0
		currentFilters := make(map[string]bool, len(entries))

		// Update per-rule metrics
		for _, entry := range entries {
			cidr := entry.CIDR
			priority := fmt.Sprintf("%d", entry.Priority)
			zone := fmt.Sprintf("%d", entry.Zone)

			// Create unique key for this filter rule
			filterKey := fmt.Sprintf("%s|%s|%d|%d|", entry.FilterType, cidr, entry.Priority, entry.Zone)
			currentFilters[filterKey] = true

			// Calculate deltas (eBPF counters are cumulative)
			var deltaPackets, deltaBytes uint64
			if prevStats, exists := prevIPFilterStats[filterKey]; exists {
				if entry.Packets >= prevStats.Packets {
					deltaPackets = entry.Packets - prevStats.Packets
				}
				if entry.Bytes >= prevStats.Bytes {
					deltaBytes = entry.Bytes - prevStats.Bytes
				}
			} else {
				// First time seeing this rule, use current values as delta
				deltaPackets = entry.Packets
				deltaBytes = entry.Bytes
			}

			// Store current stats for next cycle
			prevIPFilterStats[filterKey] = struct {
				Packets uint64
				Bytes   uint64
			}{Packets: entry.Packets, Bytes: entry.Bytes}

			if entry.FilterType == "blacklist" {
				blacklistCount++
				ipFilterBlacklistPackets.WithLabelValues(cidr, priority, zone).Add(float64(deltaPackets))
				ipFilterBlacklistBytes.WithLabelValues(cidr, priority, zone).Add(float64(deltaBytes))
			} else if entry.FilterType == "whitelist" {
				whitelistCount++
				ipFilterWhitelistPackets.WithLabelValues(cidr, priority, zone).Add(float64(deltaPackets))
				ipFilterWhitelistBytes.WithLabelValues(cidr, priority, zone).Add(float64(deltaBytes))
			}
		}

		// Remove series and baselines for rules that no longer exist - deleted
		// rules would otherwise leak Prometheus series forever (unbounded
		// cardinality on rule churn). Same pattern as the firewall collector.
		for key := range prevIPFilterStats {
			if currentFilters[key] {
				continue
			}
			delete(prevIPFilterStats, key)
			// key layout: type|cidr|priority|zone| (label values use the same
			// string formatting as the key segments)
			parts := strings.Split(key, "|")
			if len(parts) >= 4 {
				ftype, cidr, prio, zone := parts[0], parts[1], parts[2], parts[3]
				if ftype == "blacklist" {
					ipFilterBlacklistPackets.DeleteLabelValues(cidr, prio, zone)
					ipFilterBlacklistBytes.DeleteLabelValues(cidr, prio, zone)
				} else if ftype == "whitelist" {
					ipFilterWhitelistPackets.DeleteLabelValues(cidr, prio, zone)
					ipFilterWhitelistBytes.DeleteLabelValues(cidr, prio, zone)
				}
			}
		}

		// Update total rule counts
		ipFilterTotalRules.WithLabelValues("blacklist").Set(float64(blacklistCount))
		ipFilterTotalRules.WithLabelValues("whitelist").Set(float64(whitelistCount))

		time.Sleep(PrometheusDefaultPeriod)
		return nil
	}, "ip_filter_stats", ctx)
}

// === ISOLATION FRAMEWORK SAFETY FUNCTIONS ===

// === PHASE 2: COMPREHENSIVE OPERATION WRAPPERS ===

// safeMetricsCollection - Wrapper for metrics data collection operations
func safeMetricsCollection(operation func() (interface{}, error), operationName string) interface{} {
	if !isMetricsSafe(operationName) {
		return nil // Skip collection if metrics are unhealthy
	}

	// 3-second timeout for collection operations
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resultChan := make(chan interface{}, 1)
	errorChan := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errorChan <- fmt.Errorf("collection panic: %v", r)
			}
		}()

		result, err := operation()
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
			recordMetricsSuccess(operationName) // Record success
		}
	}()

	select {
	case result := <-resultChan:
		return result
	case err := <-errorChan:
		recordMetricsError(operationName, err)
		return nil
	case <-ctx.Done():
		recordMetricsError(operationName, fmt.Errorf("collection timeout"))
		return nil
	}
}

// safeAPIOperation - Wrapper for API-related operations
func safeAPIOperation(operation func() error, operationName string) error {
	if !isMetricsSafe(operationName) {
		return fmt.Errorf("metrics system unavailable") // Return error but don't crash
	}

	defer func() {
		if r := recover(); r != nil {
			recordMetricsError(operationName, fmt.Errorf("API panic: %v", r))
		}
	}()

	err := operation()
	if err != nil {
		recordMetricsError(operationName, err)
		return err
	}

	recordMetricsSuccess(operationName)
	return nil
}

// safeGoroutineOperation - Wrapper for long-running goroutine operations.
// Each iteration recovers from panics individually, so a single panic degrades
// one cycle instead of permanently killing the collection goroutine.
func safeGoroutineOperation(operation func(context.Context) error, operationName string, ctx context.Context) {
	runOnce := func() (opErr error) {
		defer func() {
			if r := recover(); r != nil {
				tk.LogIt(tk.LogError, "[Metrics] Goroutine %s recovered from panic: %v - LOAD BALANCING CONTINUES\n", operationName, r)
				opErr = fmt.Errorf("goroutine panic: %v", r)
			}
		}()
		return operation(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			tk.LogIt(tk.LogInfo, "[Metrics] Goroutine %s stopped gracefully\n", operationName)
			return
		default:
			if !isMetricsSafe(operationName) {
				time.Sleep(10 * time.Second) // Wait during unhealthy state
				continue
			}

			if err := runOnce(); err != nil {
				recordMetricsError(operationName, err)
				time.Sleep(5 * time.Second) // Brief pause on error
			} else {
				recordMetricsSuccess(operationName)
			}
		}
	}
}

// safeBatchOperation - Wrapper for batch processing operations
func safeBatchOperation(operation func([]interface{}) error, data []interface{}, operationName string) error {
	if !isMetricsSafe(operationName) {
		return nil // Skip batch processing if unhealthy
	}

	if len(data) == 0 {
		return nil // Nothing to process
	}

	// 10-second timeout for batch operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errorChan := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errorChan <- fmt.Errorf("batch panic: %v", r)
			}
		}()

		err := operation(data)
		errorChan <- err
	}()

	select {
	case err := <-errorChan:
		if err != nil {
			recordMetricsError(operationName, err)
			return err
		}
		recordMetricsSuccess(operationName)
		return nil
	case <-ctx.Done():
		recordMetricsError(operationName, fmt.Errorf("batch timeout"))
		return fmt.Errorf("batch operation timeout")
	}
}

// Per-collector circuit breakers (metrics audit: ONE global consecutive-
// error counter shared by ~12 collectors froze ALL metrics for 300s after 3
// errors from any mix — e.g. one flaky sysfs read silenced conntrack,
// firewall and security collection too). metricsHealthy remains the MASTER
// enable toggled by Init/PrometheusTurnOff; each named operation now trips
// and recovers its own breaker independently.
type componentBreaker struct {
	healthy   atomic.Bool
	lastError atomic.Int64 // Unix timestamp of last error
	errors    atomic.Int64 // Consecutive error counter
}

var (
	breakerMu sync.Mutex
	breakers  = map[string]*componentBreaker{}
)

func breakerFor(component string) *componentBreaker {
	breakerMu.Lock()
	defer breakerMu.Unlock()
	b, ok := breakers[component]
	if !ok {
		b = &componentBreaker{}
		b.healthy.Store(true)
		breakers[component] = b
	}
	return b
}

// resetAllBreakers restores every component breaker (called from Init so a
// re-enable starts clean).
func resetAllBreakers() {
	breakerMu.Lock()
	defer breakerMu.Unlock()
	for _, b := range breakers {
		b.healthy.Store(true)
		b.errors.Store(0)
		b.lastError.Store(0)
	}
}

// isMetricsSafe checks if this component's operations should be attempted.
func isMetricsSafe(component string) bool {
	if !metricsHealthy.Load() {
		return false // master disable (TurnOff)
	}
	b := breakerFor(component)
	if b.healthy.Load() {
		return true
	}

	// Component is unhealthy - check if retry interval passed
	lastErr := b.lastError.Load()
	currentTime := time.Now().Unix()

	if currentTime-lastErr > RetryInterval {
		tk.LogIt(tk.LogInfo, "[Metrics] %s: retry attempt after %d second cooldown - ALLOWING SINGLE OPERATION\n", component, RetryInterval)
		// Do not auto-heal here: allow ONE operation to proceed while staying
		// in the unhealthy state; recovery happens only via recordMetricsSuccess
		// when that operation actually succeeds
		b.lastError.Store(currentTime) // Reset cooldown timer for next retry
		return true
	}

	// Still in cooldown period
	return false
}

// recordMetricsError handles an error from one named component.
func recordMetricsError(component string, err error) {
	b := breakerFor(component)
	count := b.errors.Add(1)
	b.lastError.Store(time.Now().Unix())
	lastMetricError.Store(time.Now().Unix())

	tk.LogIt(tk.LogWarning, "[Metrics] Error in %s: %v (consecutive errors: %d)\n",
		component, err, count)

	if count >= MaxMetricErrors {
		tk.LogIt(tk.LogError, "[Metrics] Collector %s disabled after %d errors - other collectors and LOAD BALANCING CONTINUE\n",
			component, count)
		b.healthy.Store(false)
	}
}

// recordMetricsSuccess resets one component's error tracking on success.
func recordMetricsSuccess(component string) {
	b := breakerFor(component)
	wasUnhealthy := !b.healthy.Load()
	if b.errors.Load() > 0 || wasUnhealthy {
		tk.LogIt(tk.LogInfo, "[Metrics] %s: operation successful - resetting error count and restoring health\n", component)
		b.errors.Store(0)
		if wasUnhealthy {
			tk.LogIt(tk.LogInfo, "[Metrics] HEALTH RESTORED: collector %s recovered after successful operation\n", component)
			b.healthy.Store(true)
		}
	}
}

// RunSockproxyMetrics is defined in sockproxy_metrics.go
// (Must be in CGO file due to C package file-scope limitation)

// GetMetricsHealth returns current metrics system health status.
// consecutive_errors reports the WORST per-collector breaker;
// unhealthy_collectors lists breakers currently tripped.
func GetMetricsHealth() map[string]interface{} {
	var maxErrors int64
	unhealthy := []string{}
	breakerMu.Lock()
	for name, b := range breakers {
		if e := b.errors.Load(); e > maxErrors {
			maxErrors = e
		}
		if !b.healthy.Load() {
			unhealthy = append(unhealthy, name)
		}
	}
	breakerMu.Unlock()
	return map[string]interface{}{
		"load_balancer_core":        "RUNNING", // Assume core is always running
		"ebpf_hooks_available":      hooks != nil,
		"metrics_enabled":           metricsHealthy.Load(),
		"consecutive_errors":        maxErrors,
		"unhealthy_collectors":      unhealthy,
		"last_error_seconds_ago":    time.Now().Unix() - lastMetricError.Load(),
		"retry_interval_seconds":    RetryInterval,
		"max_allowed_errors":        MaxMetricErrors,
		"operation_timeout_seconds": int(OperationTimeout.Seconds()),
	}
}

// GetMetricsHealthSimple returns basic health check for external monitoring
func GetMetricsHealthSimple() bool {
	return hooks != nil // Only care if core eBPF hooks are available
}

// IsHooksAvailable checks if eBPF hooks are available for load balancing
func IsHooksAvailable() bool {
	return hooks != nil
}

var (
	conntrackMaxOnce  sync.Once
	conntrackMaxGauge prometheus.Gauge
)

// SetConntrackMaxEntries publishes the datapath conntrack table capacity as
// the loxilb_conntrack_max_entries gauge. Registered lazily on the first
// positive value so the family is absent on builds without a datapath
// capacity — absence means "not applicable", never a fake 0 (which would make
// utilization ratios divide by zero).
func SetConntrackMaxEntries(n int) {
	if n <= 0 {
		return
	}
	conntrackMaxOnce.Do(func() {
		conntrackMaxGauge = promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: MetricConntrackMaxEntries,
				Help: "Capacity of the datapath conntrack table (maximum concurrently tracked sessions).",
			},
		)
	})
	conntrackMaxGauge.Set(float64(n))
}
