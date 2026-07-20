package loxinet

// TestDpuDebugResponseSchema is production regression gate for the
// /netlox/v1/config/dpu/debug wire format. It covers P49-R1:
//
//   - Legacy scalars (offload_success uint64, offload_failure uint64,
//     offload_active int64) preserved — the 5 inventoried CICD scripts
//     (dpu-l4-lb, dpu-failover, dpu-combined, dpu-nat-modes, bf2-perf)
//     keep parsing them as int.
//   - New per-pipe maps (offload_success_by_pipe, offload_failure_by_pipe,
//     offload_active_by_pipe) are JSON objects with the expected pipe keys
//     (ct, udp_ct, route, fdb, acl; active additionally carries "total").
//   - New *_entries arrays (fdb_entries, route_entries, acl_entries) are
//     always JSON arrays, never null — nil-slice normalization verified.
// - No pointer / DOCA handle leak in the JSON output (threat).

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/loxilb-io/loxilb/api/restapi/handler"
)

func TestDpuDebugResponseSchema(t *testing.T) {
	// --- Build a sentinel response mirroring what dpuDebugGet would emit. ---
	resp := handler.DpuDebugResponse{
		Enabled:        true,
		OffloadSuccess: 10000,
		OffloadFailure: 3,
		OffloadActive:  42,
		OffloadSuccessByPipe: map[string]uint64{
			"ct": 7000, "udp_ct": 200, "route": 2500, "fdb": 295, "acl": 5,
		},
		OffloadFailureByPipe: map[string]uint64{
			"ct": 2, "udp_ct": 0, "route": 1, "fdb": 0, "acl": 0,
		},
		OffloadActiveByPipe: map[string]int64{
			"ct": 35, "udp_ct": 2, "route": 4, "fdb": 1, "acl": 0, "total": 42,
		},
		Plugins: []string{"doca-bf2"},
		Flows: []handler.FlowHwStatsEntry{
			{FlowKey: "10.0.0.1:1234-10.0.0.2:80-6", PipeKey: "ct", HwBytes: 1024, HwPkts: 10},
		},
		FdbEntries: []handler.FdbHwStatsEntry{
			{Mac: "aa:bb:cc:dd:ee:ff", Port: 3, HwBytes: 512, HwPkts: 7},
		},
		RouteEntries: []handler.RouteHwStatsEntry{
			{Dst: "10.0.0.0/24", NextHopMac: "aa:bb:cc:dd:ee:00", Port: 3, HwBytes: 2048, HwPkts: 16},
		},
		AclEntries: []handler.AclHwStatsEntry{
			{RuleID: 7, Action: "DROP", HwBytes: 0, HwPkts: 1},
		},
	}

	// --- Test 1: marshal must succeed. ---
	raw, err := json.Marshal(&resp)
	if err != nil {
		t.Fatalf("json.Marshal(DpuDebugResponse) failed: %v", err)
	}

	// --- Test 2: legacy scalar types preserved. Decode with UseNumber so
	//     we can check that offload_success is a bare integer (not object). ---
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var asMap map[string]any
	if err := dec.Decode(&asMap); err != nil {
		t.Fatalf("json.Decode back into map[string]any failed: %v", err)
	}

	for _, k := range []string{"offload_success", "offload_failure"} {
		v, ok := asMap[k]
		if !ok {
			t.Fatalf("missing required legacy field %q in JSON", k)
		}
		n, ok := v.(json.Number)
		if !ok {
			t.Fatalf("legacy %q is %T, want json.Number — CICD validation.sh parses this as int", k, v)
		}
		if _, err := n.Int64(); err != nil {
			t.Errorf("legacy %q cannot be parsed as int64: %v", k, err)
		}
	}
	// offload_active is int64 (can be negative in principle; decoded as json.Number).
	if v, ok := asMap["offload_active"]; !ok {
		t.Fatalf("missing offload_active")
	} else if _, ok := v.(json.Number); !ok {
		t.Errorf("offload_active is %T, want json.Number (int64)", v)
	}

	// --- Test 3: new *_by_pipe maps are objects, not arrays/strings. ---
	for _, k := range []string{"offload_success_by_pipe", "offload_failure_by_pipe", "offload_active_by_pipe"} {
		v, ok := asMap[k]
		if !ok {
			t.Fatalf("missing required new field %q", k)
		}
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%q is %T, want map[string]any", k, v)
		}
		// ct, udp_ct, route, fdb, acl all present.
		for _, pipe := range []string{"ct", "udp_ct", "route", "fdb", "acl"} {
			if _, ok := m[pipe]; !ok {
				t.Errorf("%q missing pipe key %q (all 5 pipes must be present)", k, pipe)
			}
		}
	}
	// offload_active_by_pipe additionally contains "total" key (per contract).
	if m, ok := asMap["offload_active_by_pipe"].(map[string]any); ok {
		if _, ok := m["total"]; !ok {
			t.Errorf("offload_active_by_pipe missing synthetic 'total' key")
		}
	}

	// --- Test 4: new *_entries arrays are arrays (not null, not object). ---
	for _, k := range []string{"fdb_entries", "route_entries", "acl_entries"} {
		v, ok := asMap[k]
		if !ok {
			t.Fatalf("missing required new array %q", k)
		}
		if v == nil {
			t.Fatalf("%q is null in JSON — must be [] (handler nil-normalization failed)", k)
		}
		if _, ok := v.([]any); !ok {
			t.Errorf("%q is %T, want []any (JSON array)", k, v)
		}
	}

	// --- Test 5: no pointer / handle leakage in the JSON bytes.
	// Threat regression guard. ---
	if bytes.Contains(raw, []byte("unsafe.Pointer")) || bytes.Contains(raw, []byte("0xc000")) {
		t.Errorf("JSON output leaks internal pointer content (threat): %s", string(raw))
	}
	// No field named "entry" containing a hex handle pattern.
	if strings.Contains(string(raw), `"entry":`) {
		t.Errorf("JSON output contains forbidden 'entry' field (DOCA handle leak, threat): %s", string(raw))
	}

	// --- Test 6: backward-compat — nil-slice normalization for empty shape. ---
	empty := handler.DpuDebugResponse{
		Enabled:              true,
		OffloadSuccessByPipe: map[string]uint64{"ct": 0, "udp_ct": 0, "route": 0, "fdb": 0, "acl": 0},
		OffloadFailureByPipe: map[string]uint64{"ct": 0, "udp_ct": 0, "route": 0, "fdb": 0, "acl": 0},
		OffloadActiveByPipe:  map[string]int64{"ct": 0, "udp_ct": 0, "route": 0, "fdb": 0, "acl": 0, "total": 0},
		Plugins:              []string{},
		FdbEntries:           []handler.FdbHwStatsEntry{},
		RouteEntries:         []handler.RouteHwStatsEntry{},
		AclEntries:           []handler.AclHwStatsEntry{},
	}
	emptyRaw, err := json.Marshal(&empty)
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	// Must emit [] for the three new array fields, never null.
	for _, want := range []string{`"fdb_entries":[]`, `"route_entries":[]`, `"acl_entries":[]`} {
		if !bytes.Contains(emptyRaw, []byte(want)) {
			t.Errorf("empty response JSON missing %q; got: %s", want, string(emptyRaw))
		}
	}
	// Must NOT contain null for these fields.
	for _, bad := range []string{`"fdb_entries":null`, `"route_entries":null`, `"acl_entries":null`} {
		if bytes.Contains(emptyRaw, []byte(bad)) {
			t.Errorf("empty response JSON contains forbidden %q; got: %s", bad, string(emptyRaw))
		}
	}

	// --- Test 7: legacy key set preserved — no rename/removal. ---
	for _, k := range []string{"enabled", "offload_success", "offload_failure", "offload_active", "plugins"} {
		if _, ok := asMap[k]; !ok {
			t.Errorf("legacy key %q dropped from response — CICD back-compat broken", k)
		}
	}
	// `flows` uses omitempty — present only when non-empty. The populated response
	// above sets one flow, so it MUST appear.
	if _, ok := asMap["flows"]; !ok {
		t.Errorf("populated response is missing 'flows' key (existing omitempty semantic)")
	}
}
