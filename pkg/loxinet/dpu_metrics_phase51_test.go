package loxinet

// TestPhase51_DirectionLabelInMetric — cardinality test.
//
// Asserts that the doca_pipe_hw_pkts_total / doca_pipe_hw_bytes_total Prometheus
// CounterVecs each carry exactly 15 children (5 pipes x 3 directions) at
// package init, that the label set is {pipe, direction} only, that the pipe
// values are a subset of {ct, udp_ct, route, fdb, acl}, and that the direction
// values are exactly {forward, reply, ""} with at least one child per direction.
//
// Pattern source: dpu_metrics_test.go::TestPipeMetricsCardinality (P49-R2).
// Cardinality threat: (label-cardinality DoS) — direction is a
// fixed 3-value enum; this test guards against accidental cardinality explosion.

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestPhase51_DirectionLabelInMetric(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("DefaultGatherer.Gather() failed: %v", err)
	}

	wantedPipes := map[string]bool{
		"ct": true, "udp_ct": true, "route": true, "fdb": true, "acl": true,
	}
	wantedDirections := map[string]bool{
		"forward": true, "reply": true, "": true,
	}

	matchedMetric := map[string]bool{
		"doca_pipe_hw_pkts_total":  false,
		"doca_pipe_hw_bytes_total": false,
	}

	for _, mf := range mfs {
		name := mf.GetName()
		if _, ok := matchedMetric[name]; !ok {
			continue
		}
		matchedMetric[name] = true

		children := mf.GetMetric()
		if got := len(children); got != 15 {
			t.Errorf("%s has %d label children, want 15 (5 pipes x 3 directions)", name, got)
		}

		// Track that every (pipe, direction) tuple appears at most once.
		seenForThisMetric := map[string]bool{}
		// Track that each direction value is observed at least once across all children.
		seenDirections := map[string]bool{}

		for _, child := range children {
			var pipeVal, directionVal string
			labels := child.GetLabel()
			if got := len(labels); got != 2 {
				t.Errorf("%s child has %d labels, want 2 (pipe + direction)", name, got)
			}
			for _, lp := range labels {
				switch lp.GetName() {
				case "pipe":
					pipeVal = lp.GetValue()
				case "direction":
					directionVal = lp.GetValue()
				default:
					t.Errorf("%s has unexpected label %q on child (only 'pipe' and 'direction' allowed)", name, lp.GetName())
				}
			}

			if !wantedPipes[pipeVal] {
				t.Errorf("%s has forbidden pipe value %q (allowed: ct, udp_ct, route, fdb, acl)", name, pipeVal)
			}
			if _, ok := wantedDirections[directionVal]; !ok {
				t.Errorf("%s has forbidden direction value %q (allowed: forward, reply, \"\")", name, directionVal)
			}

			tupleKey := pipeVal + "|" + directionVal
			if seenForThisMetric[tupleKey] {
				t.Errorf("%s has duplicate (pipe=%q, direction=%q) child", name, pipeVal, directionVal)
			}
			seenForThisMetric[tupleKey] = true
			seenDirections[directionVal] = true
		}

		for dir := range wantedDirections {
			if !seenDirections[dir] {
				t.Errorf("%s missing pre-instantiated direction=%q child — init did not enumerate all directions", name, dir)
			}
		}
	}

	for metricName, seen := range matchedMetric {
		if !seen {
			t.Errorf("metric %q not present in Gather() output — var not registered at init", metricName)
		}
	}
}
