package models

import (
	"strings"
	"testing"

	"github.com/go-openapi/strfmt"
)

// These are transport-boundary tests: accepted JSON values must fit the
// downstream uint8/uint16/uint32 fields without changing their meaning.
func TestAIMultitierNumericBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		arg   LoadbalanceEntryServiceArguments
	}{
		{"balance threshold wraps to zero", "pd_balance_abs_threshold", LoadbalanceEntryServiceArguments{PdBalanceAbsThreshold: 256}},
		{"block size wraps to zero", "kvBlockSize", LoadbalanceEntryServiceArguments{KvBlockSize: 1 << 32}},
		{"warmup wraps to zero", "kvWarmupSec", LoadbalanceEntryServiceArguments{KvWarmupSec: 1 << 32}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.arg.Validate(strfmt.Default); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("want rejection naming %s before REST narrowing, got %v", tc.field, err)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		field string
		ep    LoadbalanceEntryEndpointsItems0
	}{
		{"negative endpoint role", "ep_role", LoadbalanceEntryEndpointsItems0{EpRole: -1}},
		{"unknown endpoint role", "ep_role", LoadbalanceEntryEndpointsItems0{EpRole: 3}},
		{"negative NIXL port", "nixl_port", LoadbalanceEntryEndpointsItems0{NixlPort: -1}},
		{"overflow NIXL port", "nixl_port", LoadbalanceEntryEndpointsItems0{NixlPort: 65536}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aiMultitierEndpointControl(&tc.ep)
			if err := tc.ep.Validate(strfmt.Default); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("want rejection naming %s, got %v", tc.field, err)
			}
		})
	}
}

func TestAIMultitierNumericBoundaryControls(t *testing.T) {
	for _, arg := range []LoadbalanceEntryServiceArguments{
		{},
		{PdBalanceAbsThreshold: 255, KvBlockSize: (1 << 32) - 1, KvWarmupSec: (1 << 32) - 1},
	} {
		if err := arg.Validate(strfmt.Default); err != nil {
			t.Fatalf("representable control rejected: %v", err)
		}
	}
	for _, role := range []int32{0, 1, 2} {
		for _, port := range []int32{0, 1, 65535} {
			ep := LoadbalanceEntryEndpointsItems0{EpRole: role, NixlPort: port}
			aiMultitierEndpointControl(&ep)
			if err := ep.Validate(strfmt.Default); err != nil {
				t.Fatalf("role=%d port=%d: %v", role, port, err)
			}
		}
	}
}

func aiMultitierEndpointControl(ep *LoadbalanceEntryEndpointsItems0) {
	ip, port, weight := "192.0.2.10", int64(8000), int64(1)
	ep.EndpointIP, ep.TargetPort, ep.Weight = &ip, &port, &weight
}
