/*
 * Copyright (c) 2026 NetLOX Inc
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
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// Half-close observation
// ============================================================================
// The proxy's datapath (loxilb-ebpf/common/sockproxy_hc.c) records what a
// client's FIN looked like when it arrived and how responses progressed
// towards the client, and hands the cumulative state over in the metrics
// snapshot. These families export it. They are observation only: nothing in
// the proxy decides anything from them.
//
// The C side keeps cumulative le buckets like the TTFB histogram, so the same
// sanitize/merge treatment applies (torn reads within one snapshot, and never
// going backwards across snapshots), and the collector emits const metrics on
// scrape.
//
// The label values below are the C enums' order in sockproxy_hc_core.h; the
// snapshot dimensions are fixed there and mirrored in the cgo preamble.
// ============================================================================

const (
	hcEntrySampled = 4  // entries whose FIN carries a gap sample
	hcEntries      = 7  // enum hc_entry
	hcOutcomes     = 6  // enum hc_outcome
	hcStreams      = 3  // enum hc_stream
	hcTLSPaths     = 3  // enum hc_tls_path
	hcUAFamilies   = 13 // enum hc_ua
	hcBounds       = 15 // finite bucket bounds of both histograms
)

var (
	hcEntryLabels   = [hcEntries]string{"eof", "connect_wait", "setup_park", "fc_park", "qos", "backpressure", "other_pause"}
	hcOutcomeLabels = [hcOutcomes]string{"owed", "idle", "partial", "residue", "tls", "accel"}
	hcStreamLabels  = [hcStreams]string{"unknown", "true", "false"}
	hcTLSPathLabels = [hcTLSPaths]string{"ktls", "close_notify", "unexpected_eof"}
	hcUALabels      = [hcUAFamilies]string{"none", "curl", "python_requests", "python_httpx",
		"python_aiohttp", "python_urllib", "openai_python", "openai_node", "go", "node",
		"java", "browser", "other"}
)

// hcFinBounds and hcProgBounds are the bucket upper bounds in SECONDS. They
// must match hc_fin_bounds_us and hc_prog_bounds_us (microseconds) in
// loxilb-ebpf/common/sockproxy_hc_core.h. 100ms is the early-FIN edge.
var (
	hcFinBounds  = [hcBounds]float64{0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60}
	hcProgBounds = [hcBounds]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800}
)

// hcHist is one cumulative histogram as the C side keeps it.
type hcHist struct {
	buckets [hcBounds]uint64 // cumulative counts keyed by bound index
	count   uint64           // total samples, including those past the last bound
	sumSecs float64
}

// halfCloseSnapshot is the half-close state taken from one C snapshot.
type halfCloseSnapshot struct {
	finGap        [hcEntrySampled][hcStreams]hcHist
	finTotal      [hcEntries][hcOutcomes]uint64
	accelEarlyFin uint64
	tlsFin        [hcTLSPaths][2]uint64
	clientReset   uint64
	userAgent     [hcUAFamilies]uint64
	firstGap      [hcStreams]hcHist
	maxGap        [hcStreams]hcHist
}

// sanitizeHcHist clamps a torn read within one snapshot, as
// sanitizeTtfbSnapshot does: the cumulative sequence is made non-decreasing
// and the count at least the highest bucket.
func sanitizeHcHist(raw hcHist) hcHist {
	s := raw
	for i := 1; i < len(s.buckets); i++ {
		if s.buckets[i] < s.buckets[i-1] {
			s.buckets[i] = s.buckets[i-1]
		}
	}
	if s.count < s.buckets[len(s.buckets)-1] {
		s.count = s.buckets[len(s.buckets)-1]
	}
	return s
}

// mergeHcHist keeps the exposed histogram from going backwards, as
// mergeTtfbSnapshot does, including its reading of a count below half the
// previous one as a genuine reset.
func mergeHcHist(prev, next hcHist) hcHist {
	if next.count < prev.count/2 {
		return next
	}
	merged := next
	for i := range merged.buckets {
		if prev.buckets[i] > merged.buckets[i] {
			merged.buckets[i] = prev.buckets[i]
		}
	}
	if prev.count > merged.count {
		merged.count = prev.count
	}
	if prev.sumSecs > merged.sumSecs {
		merged.sumSecs = prev.sumSecs
	}
	return merged
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// mergeHalfClose sanitizes next and merges it into prev. Counters are single
// atomics on the C side and cannot tear, so they only need to not go
// backwards.
func mergeHalfClose(prev, next halfCloseSnapshot) halfCloseSnapshot {
	m := next
	for e := range m.finGap {
		for s := range m.finGap[e] {
			m.finGap[e][s] = mergeHcHist(prev.finGap[e][s], sanitizeHcHist(next.finGap[e][s]))
		}
	}
	for s := 0; s < hcStreams; s++ {
		m.firstGap[s] = mergeHcHist(prev.firstGap[s], sanitizeHcHist(next.firstGap[s]))
		m.maxGap[s] = mergeHcHist(prev.maxGap[s], sanitizeHcHist(next.maxGap[s]))
	}
	for e := range m.finTotal {
		for o := range m.finTotal[e] {
			m.finTotal[e][o] = maxU64(prev.finTotal[e][o], next.finTotal[e][o])
		}
	}
	for p := range m.tlsFin {
		for b := range m.tlsFin[p] {
			m.tlsFin[p][b] = maxU64(prev.tlsFin[p][b], next.tlsFin[p][b])
		}
	}
	for f := range m.userAgent {
		m.userAgent[f] = maxU64(prev.userAgent[f], next.userAgent[f])
	}
	m.accelEarlyFin = maxU64(prev.accelEarlyFin, next.accelEarlyFin)
	m.clientReset = maxU64(prev.clientReset, next.clientReset)
	return m
}

var (
	halfCloseStoreMutex sync.Mutex
	halfCloseStore      halfCloseSnapshot
)

// updateHalfCloseStore merges a raw snapshot into the store. Called once per
// collection cycle by RunSockproxyMetrics.
func updateHalfCloseStore(raw halfCloseSnapshot) {
	halfCloseStoreMutex.Lock()
	halfCloseStore = mergeHalfClose(halfCloseStore, raw)
	halfCloseStoreMutex.Unlock()
}

var halfCloseFinGapDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_fin_gap_seconds",
	"Time from a request's completion to the client's FIN, sampled once per FIN where an answer was still owed, on connections without TLS whose bytes the kernel never carried. A half-close's FIN follows the request within milliseconds; a cancel's comes after at least a time to first token; 0.1s is the early-FIN edge. entry is where the FIN was first seen: the read path's EOF, or an RDHUP while the request waited for a backend connect or in the setup or keep-alive queue. stream is the request's stream field where the proxy read the body, else unknown (which does not mean non-streaming).",
	[]string{"entry", "stream"}, nil,
)

var halfCloseFinDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_fin_total",
	"Client FINs, counted once each where first seen. outcome: owed (an answer was still owed; the case loxilb_proxy_halfclose_fin_gap_seconds samples), idle (nothing owed: an ordinary close), partial (the request was not complete when the FIN came and nothing was owed, or reads were paused mid-request by the byte shaper, relay backpressure or another pause: counted, never sampled), residue (an answer was still owed and the next request was still arriving: a pipeline's remainder, counted only), tls (a TLS connection), accel (the kernel was given a direction of the connection, so the proxy's answer count is not reliable there). entry adds qos, backpressure and other_pause, the paused-read places.",
	[]string{"entry", "outcome"}, nil,
)

var halfCloseAccelEarlyFinDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_accel_early_fin_total",
	"Client FINs within 0.1s of a request's completion on connections whose response direction, and not their request direction, was given to the kernel. These are half-closes the plaintext fix cannot see: a FIN that raced the pairing, or one after it.",
	nil, nil,
)

var halfCloseTLSFinDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_tls_fin_total",
	"TLS client connections whose read ended at the peer's FIN, once each, by how: ktls (kTLS, a FIN without close_notify), close_notify, or unexpected_eof (a FIN without close_notify on a userspace TLS connection). early_owed is true when the FIN came within 0.1s of a request's completion with an answer still owed: the population a half-close over TLS would show up in.",
	[]string{"path", "early_owed"}, nil,
)

var proxyClientResetDesc = prometheus.NewDesc(
	"loxilb_proxy_client_reset_total",
	"Client connections that ended with a reset, seen on a read or as the socket's pending error at teardown, once each. A lower bound on closes that were certainly not a half-close; not a count of cancels.",
	nil, nil,
)

var halfCloseUserAgentDesc = prometheus.NewDesc(
	"loxilb_proxy_halfclose_user_agent_total",
	"The User-Agent family of the request behind each sampled FIN (one per loxilb_proxy_halfclose_fin_gap_seconds sample). none is a request without the header; other is any agent outside the listed families.",
	[]string{"family"}, nil,
)

var proxyResponseFirstWriteGapDesc = prometheus.NewDesc(
	"loxilb_proxy_response_first_write_gap_seconds",
	"Per response, the time from handing the request to the backend to the first successful write of the response to the client socket. Taken on plaintext connections whose bytes the kernel never carried, once the response has reached the client's socket. stream is as in loxilb_proxy_halfclose_fin_gap_seconds.",
	[]string{"stream"}, nil,
)

var proxyResponseMaxWriteGapDesc = prometheus.NewDesc(
	"loxilb_proxy_response_max_write_gap_seconds",
	"Per response, the longest time between two successful writes of the response to the client socket, including the relay cache's drain after the backend finished. 0 for a response written at once. Same scope as loxilb_proxy_response_first_write_gap_seconds; with pipelined requests the next response's writes can fall in the same sample.",
	[]string{"stream"}, nil,
)

func hcBucketMap(bounds [hcBounds]float64, h hcHist) map[float64]uint64 {
	m := make(map[float64]uint64, len(bounds))
	for i, ub := range bounds {
		m[ub] = h.buckets[i]
	}
	return m
}

func hcBool(b int) string {
	if b != 0 {
		return "true"
	}
	return "false"
}

// halfCloseCollector emits the half-close families from halfCloseStore on
// every scrape. Every series is present from the start, at zero.
type halfCloseCollector struct{}

// Describe implements prometheus.Collector.
func (halfCloseCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- halfCloseFinGapDesc
	ch <- halfCloseFinDesc
	ch <- halfCloseAccelEarlyFinDesc
	ch <- halfCloseTLSFinDesc
	ch <- proxyClientResetDesc
	ch <- halfCloseUserAgentDesc
	ch <- proxyResponseFirstWriteGapDesc
	ch <- proxyResponseMaxWriteGapDesc
}

// Collect implements prometheus.Collector.
func (halfCloseCollector) Collect(ch chan<- prometheus.Metric) {
	halfCloseStoreMutex.Lock()
	s := halfCloseStore
	halfCloseStoreMutex.Unlock()

	for e := 0; e < hcEntrySampled; e++ {
		for st := 0; st < hcStreams; st++ {
			h := s.finGap[e][st]
			ch <- prometheus.MustNewConstHistogram(halfCloseFinGapDesc, h.count, h.sumSecs,
				hcBucketMap(hcFinBounds, h), hcEntryLabels[e], hcStreamLabels[st])
		}
	}
	for e := 0; e < hcEntries; e++ {
		for o := 0; o < hcOutcomes; o++ {
			ch <- prometheus.MustNewConstMetric(halfCloseFinDesc, prometheus.CounterValue,
				float64(s.finTotal[e][o]), hcEntryLabels[e], hcOutcomeLabels[o])
		}
	}
	ch <- prometheus.MustNewConstMetric(halfCloseAccelEarlyFinDesc, prometheus.CounterValue,
		float64(s.accelEarlyFin))
	for p := 0; p < hcTLSPaths; p++ {
		for b := 0; b < 2; b++ {
			ch <- prometheus.MustNewConstMetric(halfCloseTLSFinDesc, prometheus.CounterValue,
				float64(s.tlsFin[p][b]), hcTLSPathLabels[p], hcBool(b))
		}
	}
	ch <- prometheus.MustNewConstMetric(proxyClientResetDesc, prometheus.CounterValue,
		float64(s.clientReset))
	for f := 0; f < hcUAFamilies; f++ {
		ch <- prometheus.MustNewConstMetric(halfCloseUserAgentDesc, prometheus.CounterValue,
			float64(s.userAgent[f]), hcUALabels[f])
	}
	for st := 0; st < hcStreams; st++ {
		h := s.firstGap[st]
		ch <- prometheus.MustNewConstHistogram(proxyResponseFirstWriteGapDesc, h.count, h.sumSecs,
			hcBucketMap(hcProgBounds, h), hcStreamLabels[st])
		h = s.maxGap[st]
		ch <- prometheus.MustNewConstHistogram(proxyResponseMaxWriteGapDesc, h.count, h.sumSecs,
			hcBucketMap(hcProgBounds, h), hcStreamLabels[st])
	}
}

func init() {
	datapathRegisterer{}.MustRegister(halfCloseCollector{})
}
