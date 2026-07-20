// golden_test.go — freezes the loxilb.aictrl.v1 wire format with committed
// golden bytes.
//
// ANY change to the proto field set — number, type, name, addition, removal —
// changes the deterministic marshal output and breaks the byte-exact compare
// against pkg/aictrl/testdata/*.golden.bin. Intentional contract changes must
// regenerate the goldens explicitly and pass review:
//
//	go test ./pkg/aictrl/ -run TestAictrlGolden -update
//
// This is one half of the schema-review tripwire; the other half is the P1
// structural no-load-fields scan in noload_test.go.
package aictrl

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

// -update regenerates the committed golden files from the canonical fixtures.
var update = flag.Bool("update", false, "regenerate testdata/*.golden.bin from the canonical fixtures")

const (
	snapshotGolden = "snapshot_v1.golden.bin"
	ackGolden      = "ack_v1.golden.bin"
)

// canonicalSnapshot is the frozen, fully-populated Snapshot fixture. It mirrors
// a reference GPU-testbed topology (VIP 10.0.0.12:9003, prefill EPs .7/.8/.9/.11
// on :8100, decode EP .10 on :8200) so the golden bytes exercise every field
// the applier will see in production.
func canonicalSnapshot() *Snapshot {
	return &Snapshot{
		Epoch:                   42,
		BootId:                  "b0000000-0000-0000-0000-000000000001",
		StalenessDeadlineUnixMs: 1783041574000,
		MinApplierVersion:       1,
		Nonce:                   "nonce-epoch-42",
		Services: []*ServiceSnapshot{
			{
				ServiceKey: "10.0.0.12:9003:tcp",
				Eps: []*EpEntry{
					{EpIdx: 0, EpAddr: "10.0.0.7:8100", Role: Role_ROLE_PREFILL, Weight: 100, State: EpState_EP_STATE_ACTIVE},
					{EpIdx: 1, EpAddr: "10.0.0.8:8100", Role: Role_ROLE_PREFILL, Weight: 100, State: EpState_EP_STATE_ACTIVE},
					{EpIdx: 2, EpAddr: "10.0.0.9:8100", Role: Role_ROLE_PREFILL, Weight: 100, State: EpState_EP_STATE_ACTIVE},
					{EpIdx: 3, EpAddr: "10.0.0.11:8100", Role: Role_ROLE_PREFILL, Weight: 100, State: EpState_EP_STATE_ACTIVE},
					{EpIdx: 4, EpAddr: "10.0.0.10:8200", Role: Role_ROLE_DECODE, Weight: 100, State: EpState_EP_STATE_ACTIVE},
				},
			},
		},
	}
}

// canonicalAck is the frozen, fully-populated Ack fixture.
func canonicalAck() *Ack {
	return &Ack{
		Epoch:       42,
		Nonce:       "nonce-epoch-42",
		Status:      AckStatus_ACK_STATUS_APPLIED,
		ErrorDetail: "",
		GatewayId:   "loxilb-gw-10.0.0.12",
	}
}

// marshalDeterministic marshals with map/ordering determinism so the golden
// bytes are stable across runs on the pinned protobuf version (v1.33.0).
func marshalDeterministic(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatalf("deterministic marshal failed: %v", err)
	}
	return b
}

func goldenPath(name string) string {
	return filepath.Join("testdata", name)
}

// compareOrUpdate byte-compares got against the committed golden file, or
// rewrites the golden when -update is set.
func compareOrUpdate(t *testing.T, name string, got []byte) {
	t.Helper()
	path := goldenPath(name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		t.Logf("regenerated %s (%d bytes)", path, len(got))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to generate): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire format drift: %s marshal (%d bytes) != committed golden (%d bytes).\n"+
			"The loxilb.aictrl.v1 contract is FROZEN — if this change is intentional, "+
			"regenerate with `go test ./pkg/aictrl/ -run TestAictrlGolden -update` and get review.",
			name, len(got), len(want))
	}
}

func TestAictrlGolden(t *testing.T) {
	t.Run("snapshot_bytes", func(t *testing.T) {
		compareOrUpdate(t, snapshotGolden, marshalDeterministic(t, canonicalSnapshot()))
	})

	t.Run("ack_bytes", func(t *testing.T) {
		compareOrUpdate(t, ackGolden, marshalDeterministic(t, canonicalAck()))
	})

	t.Run("snapshot_roundtrip", func(t *testing.T) {
		want, err := os.ReadFile(goldenPath(snapshotGolden))
		if err != nil {
			t.Fatalf("read golden: %v", err)
		}
		var snap Snapshot
		if err := proto.Unmarshal(want, &snap); err != nil {
			t.Fatalf("unmarshal golden snapshot: %v", err)
		}
		got := marshalDeterministic(t, &snap)
		if !bytes.Equal(got, want) {
			t.Fatalf("snapshot round-trip not byte-identical: got %d bytes, want %d", len(got), len(want))
		}
	})

	t.Run("ack_roundtrip", func(t *testing.T) {
		want, err := os.ReadFile(goldenPath(ackGolden))
		if err != nil {
			t.Fatalf("read golden: %v", err)
		}
		var ack Ack
		if err := proto.Unmarshal(want, &ack); err != nil {
			t.Fatalf("unmarshal golden ack: %v", err)
		}
		got := marshalDeterministic(t, &ack)
		if !bytes.Equal(got, want) {
			t.Fatalf("ack round-trip not byte-identical: got %d bytes, want %d", len(got), len(want))
		}
	})

	// Forward-compat: a NEWER controller may add fields the applier does not
	// know. proto3 unknown-field semantics must preserve decode of the known
	// fields — appending an unknown varint field to the frozen bytes must
	// still unmarshal cleanly with the known fields intact.
	t.Run("snapshot_unknown_field_forward_compat", func(t *testing.T) {
		want, err := os.ReadFile(goldenPath(snapshotGolden))
		if err != nil {
			t.Fatalf("read golden: %v", err)
		}
		// Unknown field number 999, wire type 0 (varint), value 1.
		// tag = (999<<3)|0 = 7992 -> varint 0xB8 0x3E; value 1 -> 0x01.
		extended := append(append([]byte{}, want...), 0xB8, 0x3E, 0x01)
		var snap Snapshot
		if err := proto.Unmarshal(extended, &snap); err != nil {
			t.Fatalf("unmarshal with unknown field failed (forward-compat broken): %v", err)
		}
		canon := canonicalSnapshot()
		if snap.GetEpoch() != canon.GetEpoch() ||
			snap.GetBootId() != canon.GetBootId() ||
			snap.GetStalenessDeadlineUnixMs() != canon.GetStalenessDeadlineUnixMs() ||
			snap.GetMinApplierVersion() != canon.GetMinApplierVersion() ||
			snap.GetNonce() != canon.GetNonce() ||
			len(snap.GetServices()) != len(canon.GetServices()) ||
			len(snap.GetServices()[0].GetEps()) != len(canon.GetServices()[0].GetEps()) {
			t.Fatalf("known fields corrupted after unknown-field decode: %+v", &snap)
		}
		if !proto.Equal(&snap, canon) {
			// proto.Equal ignores unknown fields' presence? It does NOT —
			// unknown fields make messages unequal, so compare a stripped clone.
			clone := proto.Clone(&snap).(*Snapshot)
			clone.ProtoReflect().SetUnknown(nil)
			if !proto.Equal(clone, canon) {
				t.Fatalf("known-field content diverged from canonical fixture after unknown-field decode")
			}
		}
	})
}
