package models

import (
	"encoding/json"
	"testing"
)

// A successful statistics response must distinguish a measured zero from a
// missing observation. Empty/error bodies must never masquerade as idle reap.
func TestLoadbalanceStatsWireKeepsZeroCounters(t *testing.T) {
	for _, s := range []LoadbalanceStats{{}, {ActiveConnections: 2, BytesIn: 7, TotalConnections: 3}} {
		raw, err := s.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]uint64
		if err = json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		want := map[string]uint64{"activeConnections": s.ActiveConnections, "bytesIn": s.BytesIn, "bytesOut": s.BytesOut, "totalConnections": s.TotalConnections}
		if len(fields) != len(want) {
			t.Fatalf("missing zero counter: %s", raw)
		}
		for name, value := range want {
			got, present := fields[name]
			if !present || got != value {
				t.Fatalf("%s: present=%v got=%d want=%d; wire=%s", name, present, got, value, raw)
			}
		}
	}
}
