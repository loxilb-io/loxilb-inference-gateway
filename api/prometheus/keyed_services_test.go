/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package prometheus

import (
	"testing"

	cmn "github.com/loxilb-io/loxilb/common"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func lbRuleWithAuth(policy string) cmn.LbRuleMod {
	var r cmn.LbRuleMod
	r.Serv.ApiKeyAuth = policy
	return r
}

// The keyed-services gauge counts only api_key_auth=required declarations:
// unset ("") and explicit "disabled" are both unkeyed postures. The count is
// what arms the unmetered-traffic alert, so over-counting would resurrect the
// keyless-deployment false positive and under-counting would blind a keyed
// deployment.
func TestCountKeyedServices(t *testing.T) {
	cases := []struct {
		name string
		info []cmn.LbRuleMod
		want int
	}{
		{"no rules", nil, 0},
		{"all unset", []cmn.LbRuleMod{lbRuleWithAuth(""), lbRuleWithAuth("")}, 0},
		{"explicit disabled is unkeyed", []cmn.LbRuleMod{lbRuleWithAuth(cmn.ApiKeyAuthDisabled)}, 0},
		{"one required among mixed", []cmn.LbRuleMod{
			lbRuleWithAuth(""), lbRuleWithAuth(cmn.ApiKeyAuthDisabled), lbRuleWithAuth(cmn.ApiKeyAuthRequired)}, 1},
		{"all required", []cmn.LbRuleMod{
			lbRuleWithAuth(cmn.ApiKeyAuthRequired), lbRuleWithAuth(cmn.ApiKeyAuthRequired)}, 2},
	}
	for _, tc := range cases {
		if got := countKeyedServices(tc.info); got != tc.want {
			t.Errorf("%s: countKeyedServices == %d, want %d", tc.name, got, tc.want)
		}
	}

	// Writer path: the gauge reflects the count and transitions back to 0
	// (the disarm that lets a drill's transient required-rule stop guarding).
	keyedServiceCount.Set(float64(countKeyedServices(cases[3].info)))
	if v := testutil.ToFloat64(keyedServiceCount); v != 1 {
		t.Fatalf("gauge == %v after mixed set, want 1", v)
	}
	keyedServiceCount.Set(float64(countKeyedServices(nil)))
	if v := testutil.ToFloat64(keyedServiceCount); v != 0 {
		t.Fatalf("gauge == %v after clear, want 0", v)
	}
}
