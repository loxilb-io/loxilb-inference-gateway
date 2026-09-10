package prometheus

// ============================================================================
// POLICER ATTACHMENT METRIC - per-policer programmed/pending state
// ============================================================================
// A policer may legitimately be created before its attachment target exists:
// PolObj2DP flags the attachment (Sync=1) and PolTicker re-drives it until
// the target appears. That design is sound but was invisible — a policer
// whose target never materialises (e.g. a typo'd VIP) reports success at
// create time and then shapes nothing, forever. This gauge is the alarmable
// signal for that state: 1 = the policer and every attachment point are
// programmed in the datapath, 0 = at least one is still pending re-drive.
//
// Collection follows the qosShaperCollector idiom: the policer control path
// (create/delete and every PolTicker tick) republishes a Go-side store
// wholesale, and the collector emits ConstMetrics from it on scrape. A
// deleted policer's series therefore vanishes instead of freezing — the same
// presence contract the loxilb_proxy_qos_* families follow.
// ============================================================================

import (
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// PolicerAttachmentSample is one policer's attachment state as published by
// the control path.
type PolicerAttachmentSample struct {
	// Ident is the policer's name (the API's policyIdent).
	Ident string
	// Attached is true only when the policer object and all of its
	// attachment points are programmed in the datapath.
	Attached bool
}

var (
	policerAttachmentStoreMutex sync.Mutex
	policerAttachmentStore      []PolicerAttachmentSample
)

var policerAttachedDesc = prometheus.NewDesc(
	"loxilb_policer_attached",
	"Whether the policer and all of its attachment points are programmed in the datapath (1) or at least one attachment is pending re-drive and the policer currently shapes nothing (0). A series exists per configured policer; a deleted policer's series disappears.",
	[]string{"ident"}, nil,
)

// policerAttachmentCollector emits the attachment series from the store on
// scrape. With no policer configured the store is empty and the collector
// emits nothing, which is the correct representation of "not in use".
type policerAttachmentCollector struct{}

// Describe implements prometheus.Collector.
func (policerAttachmentCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- policerAttachedDesc
}

// Collect implements prometheus.Collector.
func (policerAttachmentCollector) Collect(ch chan<- prometheus.Metric) {
	policerAttachmentStoreMutex.Lock()
	samples := policerAttachmentStore
	policerAttachmentStoreMutex.Unlock()

	for _, s := range samples {
		v := 0.0
		if s.Attached {
			v = 1.0
		}
		ch <- prometheus.MustNewConstMetric(policerAttachedDesc, prometheus.GaugeValue, v, s.Ident)
	}
}

func init() {
	prometheus.MustRegister(policerAttachmentCollector{})
}

// PublishPolicerAttachment replaces the attachment store with the given
// snapshot. The caller passes the full set of configured policers each time;
// ordering is normalised here so exposition stays deterministic.
func PublishPolicerAttachment(samples []PolicerAttachmentSample) {
	sorted := make([]PolicerAttachmentSample, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Ident < sorted[j].Ident })

	policerAttachmentStoreMutex.Lock()
	policerAttachmentStore = sorted
	policerAttachmentStoreMutex.Unlock()
}
