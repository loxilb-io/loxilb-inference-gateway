/*
 * Copyright (c) 2022 NetLOX Inc
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

package loxinet

import (
	"net"
	"testing"
)

// TestModelNameRuleKeyDistinct verifies that two ruleTuples differing only in
// modelName produce different rule keys, preventing collision in the LB table.
func TestModelNameRuleKeyDistinct(t *testing.T) {
	// Build a shared base tuple (VIP 10.0.0.1:443/TCP)
	_, ipNet, _ := net.ParseCIDR("10.0.0.1/32")
	l3dst := ruleIPTuple{addr: *ipNet}
	l4prot := rule8Tuple{val: 6, valid: 0xff} // TCP
	l4dst := rule16RTuple{valMin: 443, valMax: 443, valid: true}

	rtLlama := ruleTuples{
		l3Dst:     l3dst,
		l4Prot:    l4prot,
		l4Dst:     l4dst,
		pref:      0,
		modelName: "llama-70b",
	}

	rtMistral := ruleTuples{
		l3Dst:     l3dst,
		l4Prot:    l4prot,
		l4Dst:     l4dst,
		pref:      0,
		modelName: "mistral-7b",
	}

	keyLlama := rtLlama.ruleKey()
	keyMistral := rtMistral.ruleKey()

	if keyLlama == keyMistral {
		t.Errorf("expected distinct keys for modelName='llama-70b' vs 'mistral-7b', got same key: %q", keyLlama)
	}

	// Verify backward compatibility: empty modelName matches wildcard pool
	rtWildcard := ruleTuples{
		l3Dst:     l3dst,
		l4Prot:    l4prot,
		l4Dst:     l4dst,
		pref:      0,
		modelName: "",
	}

	keyWildcard := rtWildcard.ruleKey()
	if keyWildcard == keyLlama {
		t.Errorf("wildcard (empty modelName) should not collide with 'llama-70b'")
	}
	if keyWildcard == keyMistral {
		t.Errorf("wildcard (empty modelName) should not collide with 'mistral-7b'")
	}
}
