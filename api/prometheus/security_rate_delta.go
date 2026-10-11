package prometheus

import cmn "github.com/loxilb-io/loxilb/common"

// The kernel reset endpoint can reset counters between collection cycles.
// Drops accumulated after that reset must still reach the cumulative exporter.
func securityRateCounterDelta(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

// Per-counter epochs catch resets followed by larger counts and prevent a
// partially failed reset from double-counting counters that were not reset.
func securityRatePrevious(stats, previous cmn.SecurityRateStats) cmn.SecurityRateStats {
	for _, c := range []struct {
		index int
		value *uint64
	}{
		{0, &previous.SYNBlocked}, {1, &previous.SYNPassed}, {2, &previous.SYNCookies},
		{3, &previous.ConnBlocked}, {4, &previous.ConnPassed},
		{7, &previous.UDPBlocked}, {8, &previous.UDPPassed},
		{9, &previous.UDPBytesBlocked}, {10, &previous.UDPBytesPassed},
		{11, &previous.AggregateSYNBlocked}, {12, &previous.AggregateConnBlocked},
		{13, &previous.AggregateUDPBlocked}, {14, &previous.TrackingFailures}, {15, &previous.UnsupportedPacketBlocked},
	} {
		if stats.ResetGenerations[c.index] != previous.ResetGenerations[c.index] {
			*c.value = 0
		}
	}
	return previous
}
