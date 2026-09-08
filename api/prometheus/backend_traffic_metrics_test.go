/*
 * Copyright (c) 2026 LoxiLB Authors
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
	"testing"

	"github.com/loxilb-io/loxilb/common"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func counterVecValue(vec *prometheus.CounterVec, lvs ...string) float64 {
	c := vec.WithLabelValues(lvs...)
	m := &dto.Metric{}
	if err := c.Write(m); err != nil || m.Counter == nil || m.Counter.Value == nil {
		return 0
	}
	return *m.Counter.Value
}

func counterVecChildren(vec *prometheus.CounterVec) int {
	ch := make(chan prometheus.Metric, 256)
	go func() {
		vec.Collect(ch)
		close(ch)
	}()
	n := 0
	for range ch {
		n++
	}
	return n
}

// resetBackendTrafficState puts the RunGetLBRule sweep state back to the
// just-initialized shape so each test starts from a seed cycle, and reaps
// any children left by earlier tests (counters are process-global).
func resetBackendTrafficState() {
	prevLbEpStats = make(map[string]Stats)
	prevBackendEpPairs = make(map[[2]string]bool)
	lbStatsFirstCycle = true
	backendTrafficBytes.Reset()
	backendTrafficPackets.Reset()
	backendTrafficConnections.Reset()
}

func lbRule(name, vip string, port uint16, eps ...common.LbEndPointArg) common.LbRuleMod {
	return common.LbRuleMod{
		Serv: common.LbServiceArg{
			ServIP:   vip,
			ServPort: port,
			Proto:    "tcp",
			Name:     name,
		},
		Eps: eps,
	}
}

// The per-backend counters must carry the exact rule-counter deltas per
// (service, "ip:port") — not the whole cumulative value, and not the
// service-level sum smeared across endpoints.
func TestBackendTrafficExactDeltasPerEndpoint(t *testing.T) {
	resetBackendTrafficState()

	info := []common.LbRuleMod{
		lbRule("svcA", "20.20.20.1", 8080,
			common.LbEndPointArg{EpIP: "31.31.31.1", EpPort: 9090, Counters: "100:10000"},
			common.LbEndPointArg{EpIP: "31.31.31.2", EpPort: 9090, Counters: "50:5000"},
		),
	}
	collectLbRuleTraffic(info) // seed: baselines only, no adds

	if got := counterVecChildren(backendTrafficBytes); got != 0 {
		t.Fatalf("seed cycle must not create series, got %d children", got)
	}

	info[0].Eps[0].Counters = "160:16000" // +60 pkts / +6000 bytes
	info[0].Eps[1].Counters = "50:5000"   // idle
	collectLbRuleTraffic(info)

	if got := counterVecValue(backendTrafficBytes, "svcA", "31.31.31.1:9090"); got != 6000 {
		t.Errorf("bytes ep1 = %v, want 6000", got)
	}
	if got := counterVecValue(backendTrafficPackets, "svcA", "31.31.31.1:9090"); got != 60 {
		t.Errorf("packets ep1 = %v, want 60", got)
	}
	// The idle endpoint is CONFIGURED, so its child must exist at 0
	// (P-activation: "configured but idle" is distinguishable from absent;
	// cardinality stays config-bounded and departure reaps the child).
	if got := counterVecChildren(backendTrafficBytes); got != 2 {
		t.Errorf("configured idle endpoint must have a child, got %d children", got)
	}
	if got := counterVecValue(backendTrafficBytes, "svcA", "31.31.31.2:9090"); got != 0 {
		t.Errorf("idle endpoint bytes = %v, want 0", got)
	}
}

// Unnamed rules have no service identity: they must produce no per-backend
// series at all (same contract as service_traffic_*).
func TestBackendTrafficUnnamedRuleExcluded(t *testing.T) {
	resetBackendTrafficState()

	info := []common.LbRuleMod{
		lbRule("-", "20.20.20.2", 80,
			common.LbEndPointArg{EpIP: "31.31.31.9", EpPort: 8080, Counters: "10:1000"},
		),
	}
	collectLbRuleTraffic(info)
	info[0].Eps[0].Counters = "20:2000"
	collectLbRuleTraffic(info)

	if got := counterVecChildren(backendTrafficBytes); got != 0 {
		t.Errorf("unnamed rule produced %d backend series, want 0", got)
	}
}

// A data-plane counter reset (rule re-created with a fresh counter) must
// count the full current value as the delta, not go backwards or stall.
func TestBackendTrafficCounterReset(t *testing.T) {
	resetBackendTrafficState()

	info := []common.LbRuleMod{
		lbRule("svcR", "20.20.20.3", 8080,
			common.LbEndPointArg{EpIP: "31.31.31.3", EpPort: 9090, Counters: "1000:100000"},
		),
	}
	collectLbRuleTraffic(info) // seed
	info[0].Eps[0].Counters = "1100:110000"
	collectLbRuleTraffic(info)          // +100/+10000
	info[0].Eps[0].Counters = "40:4000" // reset: fresh DP counter
	collectLbRuleTraffic(info)          // full value counts

	if got := counterVecValue(backendTrafficBytes, "svcR", "31.31.31.3:9090"); got != 14000 {
		t.Errorf("bytes after reset = %v, want 14000 (10000 + 4000)", got)
	}
	if got := counterVecValue(backendTrafficPackets, "svcR", "31.31.31.3:9090"); got != 140 {
		t.Errorf("packets after reset = %v, want 140 (100 + 40)", got)
	}
}

// When an endpoint leaves the rule config its bytes/packets children must be
// reaped in the same sweep that detects the departure — endpoint churn must
// not accumulate stale series.
func TestBackendTrafficEndpointDepartureReapsSeries(t *testing.T) {
	resetBackendTrafficState()

	two := []common.LbRuleMod{
		lbRule("svcD", "20.20.20.4", 8080,
			common.LbEndPointArg{EpIP: "31.31.31.4", EpPort: 9090, Counters: "10:1000"},
			common.LbEndPointArg{EpIP: "31.31.31.5", EpPort: 9090, Counters: "10:1000"},
		),
	}
	collectLbRuleTraffic(two) // seed
	two[0].Eps[0].Counters = "20:2000"
	two[0].Eps[1].Counters = "20:2000"
	collectLbRuleTraffic(two)
	if got := counterVecChildren(backendTrafficBytes); got != 2 {
		t.Fatalf("expected 2 children before departure, got %d", got)
	}

	one := []common.LbRuleMod{
		lbRule("svcD", "20.20.20.4", 8080,
			common.LbEndPointArg{EpIP: "31.31.31.4", EpPort: 9090, Counters: "30:3000"},
		),
	}
	collectLbRuleTraffic(one)

	if got := counterVecChildren(backendTrafficBytes); got != 1 {
		t.Errorf("departed endpoint's series not reaped: %d children, want 1", got)
	}
	if got := counterVecChildren(backendTrafficPackets); got != 1 {
		t.Errorf("departed endpoint's packets series not reaped: %d children, want 1", got)
	}
	if got := counterVecValue(backendTrafficBytes, "svcD", "31.31.31.4:9090"); got != 2000 {
		t.Errorf("surviving endpoint bytes = %v, want 2000", got)
	}
	// The survivor's child must still be the pre-departure one (no reset).
	backendTrafficBytes.DeleteLabelValues("svcD", "31.31.31.4:9090")
	backendTrafficPackets.DeleteLabelValues("svcD", "31.31.31.4:9090")
}

// Cardinality bound: the series set equals the configured named-service x
// endpoint pairs — N rules with M endpoints each never yield more than N*M
// children even across many sweeps.
func TestBackendTrafficCardinalityBound(t *testing.T) {
	resetBackendTrafficState()

	info := []common.LbRuleMod{
		lbRule("svc1", "20.20.21.1", 8080,
			common.LbEndPointArg{EpIP: "31.31.32.1", EpPort: 9090, Counters: "1:100"},
			common.LbEndPointArg{EpIP: "31.31.32.2", EpPort: 9090, Counters: "1:100"},
		),
		lbRule("svc2", "20.20.21.2", 8080,
			common.LbEndPointArg{EpIP: "31.31.32.1", EpPort: 9091, Counters: "1:100"},
		),
	}
	collectLbRuleTraffic(info) // seed
	for i := 0; i < 5; i++ {
		info[0].Eps[0].Counters = "9:900"
		info[0].Eps[1].Counters = "9:900"
		info[1].Eps[0].Counters = "9:900"
		collectLbRuleTraffic(info)
	}
	if got := counterVecChildren(backendTrafficBytes); got != 3 {
		t.Errorf("children = %d, want exactly 3 (named service x endpoint pairs)", got)
	}
}

// The connections accumulator mirrors ServiceRequests exactly-once
// semantics with backend attribution kept, and unnamed/empty identities are
// dropped rather than emitted as empty-label series.
func TestBackendConnectionsAccumulator(t *testing.T) {
	backendTrafficConnections.Reset()

	u := &UnifiedMetrics{
		ServiceRequests:      make(map[string]uint64),
		ServiceErrors:        make(map[string]uint64),
		ServiceEpConnections: make(map[string]map[string]uint64),
	}
	u.addEpConnection("svcC", "31.31.31.7", "9090")
	u.addEpConnection("svcC", "31.31.31.7", "9090")
	u.addEpConnection("svcC", "31.31.31.8", "9090")
	u.addEpConnection("", "31.31.31.7", "9090") // unnamed: dropped
	u.addEpConnection("svcC", "", "9090")       // no endpoint identity: dropped

	if len(u.ServiceEpConnections) != 1 || len(u.ServiceEpConnections["svcC"]) != 2 {
		t.Fatalf("accumulator shape wrong: %+v", u.ServiceEpConnections)
	}

	for service, eps := range u.ServiceEpConnections {
		for endpoint, count := range eps {
			backendTrafficConnections.WithLabelValues(service, endpoint).Add(float64(count))
		}
	}
	if got := counterVecValue(backendTrafficConnections, "svcC", "31.31.31.7:9090"); got != 2 {
		t.Errorf("connections ep7 = %v, want 2", got)
	}
	if got := counterVecValue(backendTrafficConnections, "svcC", "31.31.31.8:9090"); got != 1 {
		t.Errorf("connections ep8 = %v, want 1", got)
	}
	backendTrafficConnections.Reset()
}
