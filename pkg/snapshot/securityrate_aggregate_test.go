package snapshot

import (
	"bytes"
	"reflect"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
)

// Historical golden snapshots must keep their exact bytes and checksum (the
// existing current/legacy golden tests enforce that). Positive opt-in budgets
// must also survive capture/encode/decode/restore without persisting counters.
func TestSecurityRateAggregateSnapshotRoundTrip(t *testing.T) {
	cfg := cmn.SecurityRateConfig{SYNEnabled: true, SYNThreshold: 100, CookieThreshold: 50,
		RatePerSec: 50, UDPPktThreshold: 1000, UDPBandwidthMB: 100,
		AggregateSYNThreshold: 120, AggregateConnRatePerSec: 130,
		AggregateUDPPktThreshold: 140, AggregateUDPBandwidthMB: 2,
		WhitelistIPs: []string{"192.0.2.1/32"}}
	source := newMockHooks()
	source.secRate = &cmn.SecurityRateState{Config: cfg, Stats: cmn.SecurityRateStats{
		AggregateSYNBlocked: 3, AggregateConnBlocked: 4, AggregateUDPBlocked: 5,
		TrackingFailures: 6, UnsupportedPacketBlocked: 7, ResetGenerations: [16]uint64{9}}}
	doc := NewDocument("test", "test-host", TriggerManual)
	doc.IncludedDomains = []string{DomainSecurityRate}
	if err := getSecurityRate(source, doc); err != nil {
		t.Fatal(err)
	}
	if doc.Domains.SecurityRate.Stats != (cmn.SecurityRateStats{}) {
		t.Fatal("runtime counters leaked into snapshot")
	}
	raw, err := Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksum(decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Domains.SecurityRate.Config, cfg) {
		t.Fatalf("budget lost: %+v", decoded.Domains.SecurityRate.Config)
	}
	target := newMockHooks()
	e := newTestEngine(target, t.TempDir())
	res, err := e.Restore(raw, RestoreOptions{Mode: ModeCommit})
	if err != nil {
		t.Fatal(err)
	}
	if res.Result != ResultOK || target.secRate == nil || !reflect.DeepEqual(target.secRate.Config, cfg) {
		t.Fatalf("restore lost aggregate policy: %+v / %+v", res, target.secRate)
	}
	// Budget mutation without a new checksum must be refused before any apply.
	decoded.Domains.SecurityRate.Config.AggregateSYNThreshold++
	if err := VerifyChecksum(decoded); err == nil {
		t.Fatal("tampered budget accepted")
	}
}
