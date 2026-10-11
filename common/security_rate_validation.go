package common

import "fmt"

// ValidateSecurityRateAggregate also protects snapshot/direct-hook callers,
// which do not traverse the REST model's int64 validators.
func ValidateSecurityRateAggregate(c SecurityRateConfig) error {
	for _, v := range []struct {
		name           string
		value, maximum uint32
	}{
		{"aggregateSynThreshold", c.AggregateSYNThreshold, 1 << 24},
		{"aggregateConnRatePerSec", c.AggregateConnRatePerSec, 1 << 24},
		{"aggregateUdpPktThreshold", c.AggregateUDPPktThreshold, 1 << 24},
		{"aggregateUdpBandwidthMB", c.AggregateUDPBandwidthMB, 4095},
		{"udpBandwidthMB", c.UDPBandwidthMB, 4095},
	} {
		if v.value > v.maximum {
			return fmt.Errorf("invalid %s: %d exceeds %d", v.name, v.value, v.maximum)
		}
	}
	return nil
}
