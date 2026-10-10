package prometheus

import (
	cmn "github.com/loxilb-io/loxilb/common"
	"testing"
)

func TestSecurityRateDeltaAfterResetDoesNotLoseNewDrops(t *testing.T) {
	for _, tc := range []struct{ previous, current, want uint64 }{
		{380, 10, 10}, {380, 0, 0}, {380, 385, 5}, {0, 380, 380}, {380, 380, 0},
	} {
		if got := securityRateCounterDelta(tc.current, tc.previous); got != tc.want {
			t.Fatalf("kernel counter %d -> %d: exporter delta %d, want %d", tc.previous, tc.current, got, tc.want)
		}
	}
}

func TestSecurityRateResetEpochWithLargerNewCount(t *testing.T) {
	for _, tc := range []struct{ epoch, want uint64 }{{0, 120}, {1, 500}, {2, 500}} {
		current := cmn.SecurityRateStats{UDPBlocked: 500}
		current.ResetGenerations[7] = tc.epoch
		previous := securityRatePrevious(current, cmn.SecurityRateStats{UDPBlocked: 380})
		if got := securityRateCounterDelta(current.UDPBlocked, previous.UDPBlocked); got != tc.want {
			t.Fatalf("epoch %d got %d want %d", tc.epoch, got, tc.want)
		}
	}
}

func TestSecurityRatePartialResetPreservesUnresetCounters(t *testing.T) {
	current := cmn.SecurityRateStats{UDPBlocked: 500, SYNBlocked: 500}
	current.ResetGenerations[7] = 1
	previous := securityRatePrevious(current, cmn.SecurityRateStats{UDPBlocked: 380, SYNBlocked: 380})
	if securityRateCounterDelta(current.UDPBlocked, previous.UDPBlocked) != 500 {
		t.Fatal("reset UDP counter lost new drops")
	}
	if securityRateCounterDelta(current.SYNBlocked, previous.SYNBlocked) != 120 {
		t.Fatal("unreset SYN counter was double-counted")
	}
}

func TestSecurityRateFragmentCounterPartialReset(t *testing.T) {
	current := cmn.SecurityRateStats{UnsupportedPacketBlocked: 500, AggregateUDPBlocked: 500}
	current.ResetGenerations[15] = 1
	previous := securityRatePrevious(current, cmn.SecurityRateStats{UnsupportedPacketBlocked: 380, AggregateUDPBlocked: 380})
	if securityRateCounterDelta(current.UnsupportedPacketBlocked, previous.UnsupportedPacketBlocked) != 500 {
		t.Fatal("reset fragment counter lost drops")
	}
	if securityRateCounterDelta(current.AggregateUDPBlocked, previous.AggregateUDPBlocked) != 120 {
		t.Fatal("unreset aggregate counter double counted")
	}
}
