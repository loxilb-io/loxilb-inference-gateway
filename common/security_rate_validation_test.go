package common

import "testing"

func TestSecurityRateSnapshotBandwidthCannotWrap(t *testing.T) {
	for _, n := range []uint32{4096, 1 << 22, ^uint32(0)} {
		for _, c := range []SecurityRateConfig{{UDPBandwidthMB: n}, {AggregateUDPBandwidthMB: n}} {
			if ValidateSecurityRateAggregate(c) == nil {
				t.Fatalf("overflow accepted: %+v", c)
			}
		}
	}
	if err := ValidateSecurityRateAggregate(SecurityRateConfig{UDPBandwidthMB: 4095, AggregateUDPBandwidthMB: 4095}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecurityRateAggregate(SecurityRateConfig{}); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityRateAggregateSnapshotPacketBudgetsBounded(t *testing.T) {
	for _, n := range []uint32{1<<24 + 1, ^uint32(0)} {
		for _, c := range []SecurityRateConfig{{AggregateSYNThreshold: n}, {AggregateConnRatePerSec: n}, {AggregateUDPPktThreshold: n}} {
			if ValidateSecurityRateAggregate(c) == nil {
				t.Fatalf("unbounded snapshot accepted: %+v", c)
			}
		}
	}
	if err := ValidateSecurityRateAggregate(SecurityRateConfig{AggregateSYNThreshold: 1 << 24, AggregateConnRatePerSec: 1 << 24, AggregateUDPPktThreshold: 1 << 24}); err != nil {
		t.Fatal(err)
	}
}
