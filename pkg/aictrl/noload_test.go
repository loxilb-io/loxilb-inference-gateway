// noload_test.go — the P1 structural tripwire.
//
// P1 (day-1 locked design decision): the controller→loxilb snapshot carries
// NO per-EP load-like fields — no live counters, no scraped gauges, nothing
// the data plane could mistake for its own local health inputs. Root cause
// this guards against: hot-spot investigation found a scraped load
// value displacing the live active_conns signal in the selection path — the
// vLLM-side proxy under-counted active connections ~2.7x, silently skewing
// routing. A schema is the one place that class of bug can be banned
// STRUCTURALLY: if the field cannot exist, it cannot be read.
//
// The scan walks EVERY message descriptor registered by this package via
// protoreflect (recursively, including any future nested messages) and fails
// on any field whose name contains a forbidden load-like substring. Together
// with golden_test.go, a load field cannot appear without BOTH a golden-file
// diff and this named tripwire failing.
package aictrl

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// forbiddenSubstrings are the load-like name fragments structurally banned
// from every loxilb.aictrl.v1 field name (case-insensitive substring match).
var forbiddenSubstrings = []string{
	"load",
	"queue",
	"conn",
	"util",
	"depth",
	"inflight",
	"pressure",
	"latency",
	"ttft",
}

// forbiddenMatch returns the first forbidden substring contained in the
// (lowercased) field name, or "" when the name is clean.
func forbiddenMatch(fieldName string) string {
	lower := strings.ToLower(fieldName)
	for _, bad := range forbiddenSubstrings {
		if strings.Contains(lower, bad) {
			return bad
		}
	}
	return ""
}

// scanMessage checks every field of md and recurses into nested message
// declarations. seen guards against (currently nonexistent) recursion cycles.
func scanMessage(t *testing.T, md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) {
	t.Helper()
	if seen[md.FullName()] {
		return
	}
	seen[md.FullName()] = true

	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if bad := forbiddenMatch(string(fd.Name())); bad != "" {
			t.Errorf("P1 VIOLATION: field %s.%s contains forbidden load-like substring %q — "+
				"the aictrl snapshot must be instruction-only (weights/states), never observed load "+
				"(hot-spot: scraped load displaced live active_conns, 2.7x under-count)",
				md.FullName(), fd.Name(), bad)
		}
		// Recurse through message-typed fields too (covers map values and
		// imported message types reachable from this contract).
		if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
			scanMessage(t, fd.Message(), seen)
		}
	}

	nested := md.Messages()
	for i := 0; i < nested.Len(); i++ {
		scanMessage(t, nested.Get(i), seen)
	}
}

// TestNoLoadFields walks ALL top-level messages in the aictrl proto file and
// fails on any load-like field name anywhere in the reachable descriptor graph.
func TestNoLoadFields(t *testing.T) {
	fileDesc := File_pkg_aictrl_aictrl_proto
	msgs := fileDesc.Messages()
	if msgs.Len() == 0 {
		t.Fatal("no message descriptors found in File_pkg_aictrl_aictrl_proto — tripwire is vacuous")
	}
	seen := make(map[protoreflect.FullName]bool)
	for i := 0; i < msgs.Len(); i++ {
		scanMessage(t, msgs.Get(i), seen)
	}
	if len(seen) < 6 {
		// Snapshot, ServiceSnapshot, EpEntry, WatchRequest, Ack, AckResponse.
		t.Fatalf("tripwire scanned only %d messages — expected the full v1 contract (>=6); "+
			"did the descriptor walk regress?", len(seen))
	}
}

// TestForbiddenMatcherCatchesKnownBadNames is the negative self-check: it
// proves the matcher would catch real load-like names (e.g. the exact shape
// of xsync.proto VllmWorkerMetrics, which is what aictrl must NOT become).
// If someone weakens forbiddenSubstrings, this fails first.
func TestForbiddenMatcherCatchesKnownBadNames(t *testing.T) {
	cases := []struct {
		name    string
		wantHit string
	}{
		// xsync VllmWorkerMetrics shapes — the canonical counter-example.
		{"queue_depth", "queue"},
		{"gpu_cache_load_pct", "load"},
		// live local-health signals that must never ride the snapshot
		{"active_conns", "conn"},
		{"connection_count", "conn"},
		{"gpu_utilization", "util"},
		{"inflight_requests", "inflight"},
		{"kv_pressure", "pressure"},
		{"p99_latency_ms", "latency"},
		{"ttft_ms", "ttft"},
		{"LoadFactor", "load"}, // case-insensitivity
		// clean names must NOT match
		{"weight", ""},
		{"ep_idx", ""},
		{"staleness_deadline_unix_ms", ""},
		{"boot_id", ""},
	}
	for _, tc := range cases {
		if got := forbiddenMatch(tc.name); got != tc.wantHit {
			t.Errorf("forbiddenMatch(%q) = %q, want %q", tc.name, got, tc.wantHit)
		}
	}
}
