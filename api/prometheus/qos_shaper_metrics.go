package prometheus

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdint.h>

// Twin declaration of proxy_qos_svc_stat_t. CANONICAL definition lives in
// loxilb-ebpf/common/sockproxy_metrics.h; a weak stub for CGO-only builds
// (go test, no sockproxy object) lives in proxy_metrics_stub.c. All THREE
// must move in lockstep, same commit — tail-append only, never reorder.
//
// Direction-indexed arrays: index 0 = upload (client->backend), 1 = download
// (backend->client). Byte units are PLAINTEXT payload bytes, never the Tier-0
// eBPF policer's L3 wire bytes.
// Cap on services reported per call; lockstep with PROXY_QOS_STAT_MAX in
// sockproxy_metrics.h.
#define PROXY_QOS_STAT_MAX 256

typedef struct proxy_qos_svc_stat {
    uint32_t xip;
    uint16_t xport;
    uint8_t  protocol;
    uint8_t  dir;
    uint64_t cir_bps;
    uint32_t cbs_bytes;
    uint32_t n_parked[2];
    uint32_t pad;
    uint64_t bytes_pass[2];
    uint64_t bytes_delayed[2];
    uint64_t parks[2];
    uint64_t park_ns[2];
    int64_t  tokens[2];
} proxy_qos_svc_stat_t;

extern int proxy_get_qos_stats(proxy_qos_svc_stat_t *out, int max);
*/
import "C"

import (
	"fmt"
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// TIER-1 BYTE SHAPER (QoS) METRICS - per-service, per-direction
// ============================================================================
// The shaper's counters live on the per-service proxy_map_ent buckets in the
// sockproxy (loxilb-ebpf/common/sockproxy_qos.h) and were invisible outside a
// debugger. They are exported here as labelled series so a shaped VIP can be
// operated: how much payload the bucket passed, how much of it had to wait,
// how often and for how long readers were parked, and the live bucket depth.
//
// Collection follows the ttfbCollector idiom in sockproxy_metrics.go: the 10s
// RunSockproxyMetrics cycle refreshes a Go-side store (writer) and the
// collector emits ConstMetrics from it on scrape (reader). The C call walks
// the service list under the proxy read lock, so it stays off the scrape path.
//
// Counters are emitted RAW, not as deltas: they are cumulative per bucket, and
// a service delete/re-create genuinely resets them, which Prometheus already
// interprets correctly as a counter reset.
// ============================================================================

// QOS direction bits, mirroring QOS_DIR_* in sockproxy_qos.h.
const (
	qosDirUploadBit   = 0x1
	qosDirDownloadBit = 0x2
)

// qosDirectionLabels indexes the C direction arrays: 0 = upload, 1 = download.
var qosDirectionLabels = [2]string{"upload", "download"}

// qosShaperSample is one shaped service's state in one direction, already
// converted to Go types and label strings.
type qosShaperSample struct {
	vip       string
	port      string
	proto     string
	direction string

	bytesPassed    float64
	bytesDelayed   float64
	parks          float64
	parkSeconds    float64
	parkedConns    float64
	tokens         float64
	cirBytesPerSec float64
	cbsBytes       float64
}

// qosShaperStore is the state shared between the collection loop (writer) and
// qosShaperCollector.Collect (reader, on scrape). Replaced wholesale each
// cycle so a deleted service's series stop being emitted instead of freezing
// at their last value.
var (
	qosShaperStoreMutex sync.Mutex
	qosShaperStore      []qosShaperSample
)

var (
	qosBytesPassedDesc = prometheus.NewDesc(
		"loxilb_proxy_qos_bytes_passed_total",
		"Payload bytes granted by the Tier-1 byte shaper, per shaped service and direction. Plaintext payload bytes, not L3 wire bytes.",
		qosShaperLabels, nil,
	)
	qosBytesDelayedDesc = prometheus.NewDesc(
		"loxilb_proxy_qos_bytes_delayed_total",
		"Payload bytes that waited for at least one park/resume cycle before the shaper granted them. Ratio against bytes_passed shows how much traffic the CIR actually held back.",
		qosShaperLabels, nil,
	)
	qosParksDesc = prometheus.NewDesc(
		"loxilb_proxy_qos_parks_total",
		"Times the shaper parked a reader because its bucket was empty.",
		qosShaperLabels, nil,
	)
	qosParkSecondsDesc = prometheus.NewDesc(
		"loxilb_proxy_qos_park_seconds_total",
		"Summed park-to-resume wall time of readers the shaper throttled. Divided by parks_total it gives the mean park duration; parks that never resumed (connection torn down while throttled) are not counted.",
		qosShaperLabels, nil,
	)
	qosParkedConnsDesc = prometheus.NewDesc(
		"loxilb_proxy_qos_parked_connections",
		"Readers parked by the shaper right now (bucket park-ring depth).",
		qosShaperLabels, nil,
	)
	qosTokensDesc = prometheus.NewDesc(
		"loxilb_proxy_qos_tokens_bytes",
		"Current shaper bucket level in bytes. Sitting near zero means the service is rate-bound.",
		qosShaperLabels, nil,
	)
	qosCirDesc = prometheus.NewDesc(
		"loxilb_proxy_qos_cir_bytes_per_second",
		"Configured committed information rate of the shaper, in bytes per second. Each enabled direction refills at the full CIR - the directions are independent meters, not halves of a shared budget.",
		qosShaperLabels, nil,
	)
	qosCbsDesc = prometheus.NewDesc(
		"loxilb_proxy_qos_cbs_bytes",
		"Effective shaper burst depth in bytes (configured CBS, or 100ms of CIR when unset).",
		qosShaperLabels, nil,
	)
)

var qosShaperLabels = []string{"vip", "port", "proto", "direction"}

// qosShaperCollector emits the shaper series from qosShaperStore on scrape.
// With no service shaped the store is empty and the collector emits nothing,
// which is the correct representation of "the feature is not in use".
type qosShaperCollector struct{}

// Describe implements prometheus.Collector.
func (qosShaperCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- qosBytesPassedDesc
	ch <- qosBytesDelayedDesc
	ch <- qosParksDesc
	ch <- qosParkSecondsDesc
	ch <- qosParkedConnsDesc
	ch <- qosTokensDesc
	ch <- qosCirDesc
	ch <- qosCbsDesc
}

// Collect implements prometheus.Collector.
func (qosShaperCollector) Collect(ch chan<- prometheus.Metric) {
	qosShaperStoreMutex.Lock()
	samples := qosShaperStore
	qosShaperStoreMutex.Unlock()

	for _, s := range samples {
		lv := []string{s.vip, s.port, s.proto, s.direction}
		ch <- prometheus.MustNewConstMetric(qosBytesPassedDesc, prometheus.CounterValue, s.bytesPassed, lv...)
		ch <- prometheus.MustNewConstMetric(qosBytesDelayedDesc, prometheus.CounterValue, s.bytesDelayed, lv...)
		ch <- prometheus.MustNewConstMetric(qosParksDesc, prometheus.CounterValue, s.parks, lv...)
		ch <- prometheus.MustNewConstMetric(qosParkSecondsDesc, prometheus.CounterValue, s.parkSeconds, lv...)
		ch <- prometheus.MustNewConstMetric(qosParkedConnsDesc, prometheus.GaugeValue, s.parkedConns, lv...)
		ch <- prometheus.MustNewConstMetric(qosTokensDesc, prometheus.GaugeValue, s.tokens, lv...)
		ch <- prometheus.MustNewConstMetric(qosCirDesc, prometheus.GaugeValue, s.cirBytesPerSec, lv...)
		ch <- prometheus.MustNewConstMetric(qosCbsDesc, prometheus.GaugeValue, s.cbsBytes, lv...)
	}
}

// init registers the shaper collector once with the default registry (the same
// registry the promauto metrics use).
func init() {
	prometheus.MustRegister(qosShaperCollector{})
}

// qosVipString renders a proxy_ent xip (network byte order: least significant
// byte is the first octet) as dotted quad. Pure Go - unit tested without CGO.
func qosVipString(xip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		xip&0xff, (xip>>8)&0xff, (xip>>16)&0xff, (xip>>24)&0xff)
}

// qosProtoString names the well-known L4 protocols the proxy serves and falls
// back to the numeric value for anything else, so an unexpected protocol shows
// up in the series instead of being silently relabelled. Pure Go.
func qosProtoString(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 132:
		return "sctp"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

// sortQosSamples orders the store deterministically (vip, port, direction) so
// the exposition output is stable between scrapes. Pure Go.
func sortQosSamples(samples []qosShaperSample) {
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].vip != samples[j].vip {
			return samples[i].vip < samples[j].vip
		}
		if samples[i].port != samples[j].port {
			return samples[i].port < samples[j].port
		}
		return samples[i].direction < samples[j].direction
	})
}

// refreshQosShaperStore pulls the per-service shaper state from the sockproxy
// and republishes the store. Called once per RunSockproxyMetrics cycle.
//
// Only the directions the service actually shapes are published: an un-shaped
// direction's bucket is never drained, so exporting its zeros would read as
// "shaped, and idle" instead of "not shaped".
func refreshQosShaperStore() {
	var raw [C.PROXY_QOS_STAT_MAX]C.proxy_qos_svc_stat_t

	n := int(C.proxy_get_qos_stats(&raw[0], C.int(len(raw))))
	if n < 0 {
		n = 0
	}
	if n > len(raw) {
		n = len(raw)
	}

	samples := make([]qosShaperSample, 0, n*2)
	for i := 0; i < n; i++ {
		st := raw[i]
		vip := qosVipString(uint32(st.xip))
		port := fmt.Sprintf("%d", uint16(st.xport))
		proto := qosProtoString(uint8(st.protocol))
		dirMask := uint8(st.dir)

		for d := 0; d < 2; d++ {
			bit := uint8(qosDirUploadBit)
			if d == 1 {
				bit = qosDirDownloadBit
			}
			if dirMask&bit == 0 {
				continue
			}
			samples = append(samples, qosShaperSample{
				vip:            vip,
				port:           port,
				proto:          proto,
				direction:      qosDirectionLabels[d],
				bytesPassed:    float64(st.bytes_pass[d]),
				bytesDelayed:   float64(st.bytes_delayed[d]),
				parks:          float64(st.parks[d]),
				parkSeconds:    float64(st.park_ns[d]) / 1e9,
				parkedConns:    float64(st.n_parked[d]),
				tokens:         float64(st.tokens[d]),
				cirBytesPerSec: float64(st.cir_bps),
				cbsBytes:       float64(st.cbs_bytes),
			})
		}
	}
	sortQosSamples(samples)

	qosShaperStoreMutex.Lock()
	qosShaperStore = samples
	qosShaperStoreMutex.Unlock()
}
