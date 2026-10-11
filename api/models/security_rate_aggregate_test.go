package models

import (
	"encoding/json"
	"github.com/go-openapi/strfmt"
	"testing"
)

func TestSecurityRateAggregateOptionalAndBoundaryContract(t *testing.T) {
	base := `{"synEnabled":false,"synThreshold":100,"cookieThreshold":50,"connRateEnabled":false,"ratePerSec":50,"udpEnabled":true,"udpPktThreshold":1000,"udpBandwidthMB":100}`
	for _, tc := range []struct {
		extra string
		valid bool
	}{
		{"", true}, {`,"aggregateSynThreshold":null`, true},
		{`,"aggregateSynThreshold":0,"aggregateUdpBandwidthMB":0`, true},
		{`,"aggregateSynThreshold":16777216,"aggregateConnRatePerSec":16777216,"aggregateUdpPktThreshold":16777216,"aggregateUdpBandwidthMB":4095`, true},
		{`,"aggregateSynThreshold":-1`, false}, {`,"aggregateConnRatePerSec":-1`, false},
		{`,"aggregateUdpPktThreshold":16777217`, false}, {`,"aggregateUdpBandwidthMB":4096`, false},
		{`,"aggregateSynThreshold":4294967296`, false}, {`,"aggregateUdpBandwidthMB":1.5`, false},
	} {
		var c SecurityRateConfigMod
		err := json.Unmarshal([]byte(base[:len(base)-1]+tc.extra+"}"), &c)
		if err == nil {
			err = c.Validate(strfmt.Default)
		}
		if (err == nil) != tc.valid {
			t.Fatalf("extra %s validity %v, error %v", tc.extra, tc.valid, err)
		}
	}
}
