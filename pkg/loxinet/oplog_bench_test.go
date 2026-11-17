// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 LoxiLB Authors

package loxinet

import (
	"io"
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilb/internal/tk"
)

func BenchmarkRequestKeyValidationFiltered(b *testing.B) {
	logger, err := tk.NewLogger(io.Discard, tk.LogInfo, false)
	if err != nil {
		b.Fatal(err)
	}
	previous := tk.SwapDefaultLogger(logger)
	b.Cleanup(func() { tk.SwapDefaultLogger(previous) })

	svc := &mockAPIKeyValidator{entry: &cmn.ApiKeyEntry{KeyID: "test-key", TenantID: "test-tenant", Enabled: true}}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if decision, _, _, _, _ := validateAPIKeyInternal(svc, "test-key", "test-model"); decision != 0 {
				b.Errorf("unexpected API-key decision: %d", decision)
			}
		}
	})
}
