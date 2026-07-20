/*
 * Copyright (c) 2025 LoxiLB Authors
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

package opa

import (
	"testing"
)

func TestNormalize_ValidRuleRoundTrip(t *testing.T) {
	rn := NewRuleNormalizer()

	resp := &OPAPolicyResponse{}
	resp.Result.L4.FirewallAccessRules = []OPARule{
		{
			SourceIP:           "10.0.0.0/8",
			DestinationIP:      "192.168.1.0/24",
			Protocol:           6,
			MinSourcePort:      1024,
			MaxSourcePort:      65535,
			MinDestinationPort: 80,
			MaxDestinationPort: 80,
			Action:             "allow",
			Preference:         100,
		},
	}

	rules, opts, err := rn.Normalize(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(opts) != 1 {
		t.Fatalf("expected 1 opt, got %d", len(opts))
	}

	// Verify the rule content
	for key, rule := range rules {
		if rule.SrcIP != "10.0.0.0/8" {
			t.Errorf("expected SrcIP 10.0.0.0/8, got %s", rule.SrcIP)
		}
		if rule.DstIP != "192.168.1.0/24" {
			t.Errorf("expected DstIP 192.168.1.0/24, got %s", rule.DstIP)
		}
		if rule.Proto != 6 {
			t.Errorf("expected Proto 6, got %d", rule.Proto)
		}
		if rule.SrcPortMin != 1024 {
			t.Errorf("expected SrcPortMin 1024, got %d", rule.SrcPortMin)
		}
		if rule.SrcPortMax != 65535 {
			t.Errorf("expected SrcPortMax 65535, got %d", rule.SrcPortMax)
		}
		if rule.DstPortMin != 80 {
			t.Errorf("expected DstPortMin 80, got %d", rule.DstPortMin)
		}
		if rule.DstPortMax != 80 {
			t.Errorf("expected DstPortMax 80, got %d", rule.DstPortMax)
		}
		if rule.Pref != 100 {
			t.Errorf("expected Pref 100, got %d", rule.Pref)
		}

		opt := opts[key]
		if !opt.Allow {
			t.Error("expected Allow=true")
		}
		if opt.Drop {
			t.Error("expected Drop=false")
		}
	}

	// Verify DiffKey round-trip (dst port range 80-80 per the documented
	// "{DstPortMin}-{DstPortMax}" key format)
	for _, rule := range rules {
		key := rn.MakeDiffKey(rule)
		expected := DiffKey("10.0.0.0/8|192.168.1.0/24|6|1024-65535|80-80|100")
		if key != expected {
			t.Errorf("expected DiffKey %q, got %q", expected, key)
		}
	}
}

func TestNormalize_InvalidCIDRSkipped(t *testing.T) {
	rn := NewRuleNormalizer()

	resp := &OPAPolicyResponse{}
	resp.Result.L4.FirewallAccessRules = []OPARule{
		{
			SourceIP:           "not-a-cidr",
			DestinationIP:      "192.168.1.0/24",
			Protocol:           6,
			MinSourcePort:      0,
			MaxSourcePort:      0,
			MinDestinationPort: 80,
			MaxDestinationPort: 80,
			Action:             "deny",
			Preference:         200,
		},
	}

	rules, opts, err := rn.Normalize(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules (invalid CIDR skipped), got %d", len(rules))
	}
	if len(opts) != 0 {
		t.Errorf("expected 0 opts, got %d", len(opts))
	}
}

func TestNormalize_UnknownActionSkipped(t *testing.T) {
	rn := NewRuleNormalizer()

	resp := &OPAPolicyResponse{}
	resp.Result.L4.FirewallAccessRules = []OPARule{
		{
			SourceIP:           "10.0.0.0/8",
			DestinationIP:      "192.168.1.0/24",
			Protocol:           6,
			MinSourcePort:      0,
			MaxSourcePort:      0,
			MinDestinationPort: 443,
			MaxDestinationPort: 443,
			Action:             "redirect",
			Preference:         100,
		},
	}

	rules, _, err := rn.Normalize(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules (unknown action skipped), got %d", len(rules))
	}
}

func TestNormalize_EmptyResponse(t *testing.T) {
	rn := NewRuleNormalizer()

	resp := &OPAPolicyResponse{}

	rules, opts, err := rn.Normalize(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
	if len(opts) != 0 {
		t.Errorf("expected 0 opts, got %d", len(opts))
	}
}

func TestNormalize_NilResponse(t *testing.T) {
	rn := NewRuleNormalizer()

	rules, opts, err := rn.Normalize(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
	if len(opts) != 0 {
		t.Errorf("expected 0 opts, got %d", len(opts))
	}
}

func TestNormalize_PortMinGreaterThanMaxSkipped(t *testing.T) {
	rn := NewRuleNormalizer()

	resp := &OPAPolicyResponse{}
	resp.Result.L4.FirewallAccessRules = []OPARule{
		{
			SourceIP:           "10.0.0.0/8",
			DestinationIP:      "192.168.1.0/24",
			Protocol:           6,
			MinSourcePort:      5000,
			MaxSourcePort:      1000, // min > max
			MinDestinationPort: 80,
			MaxDestinationPort: 80,
			Action:             "allow",
			Preference:         100,
		},
		{
			SourceIP:           "10.0.0.0/8",
			DestinationIP:      "192.168.1.0/24",
			Protocol:           17,
			MinSourcePort:      0,
			MaxSourcePort:      0,
			MinDestinationPort: 8080,
			MaxDestinationPort: 80, // min > max
			Action:             "deny",
			Preference:         200,
		},
	}

	rules, _, err := rn.Normalize(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules (port range violations skipped), got %d", len(rules))
	}
}

func TestNormalize_UnknownProtocolSkipped(t *testing.T) {
	rn := NewRuleNormalizer()

	resp := &OPAPolicyResponse{}
	resp.Result.L4.FirewallAccessRules = []OPARule{
		{
			SourceIP:           "10.0.0.0/8",
			DestinationIP:      "192.168.1.0/24",
			Protocol:           99, // unsupported
			MinSourcePort:      0,
			MaxSourcePort:      0,
			MinDestinationPort: 80,
			MaxDestinationPort: 80,
			Action:             "allow",
			Preference:         100,
		},
	}

	rules, _, err := rn.Normalize(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules (unknown protocol skipped), got %d", len(rules))
	}
}

func TestNormalize_EmptyIPDefaultsToCIDR(t *testing.T) {
	rn := NewRuleNormalizer()

	resp := &OPAPolicyResponse{}
	resp.Result.L4.FirewallAccessRules = []OPARule{
		{
			SourceIP:           "",
			DestinationIP:      "",
			Protocol:           0,
			MinSourcePort:      0,
			MaxSourcePort:      0,
			MinDestinationPort: 0,
			MaxDestinationPort: 0,
			Action:             "allow",
			Preference:         50,
		},
	}

	rules, _, err := rn.Normalize(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	for _, rule := range rules {
		if rule.SrcIP != "0.0.0.0/0" {
			t.Errorf("expected SrcIP 0.0.0.0/0, got %s", rule.SrcIP)
		}
		if rule.DstIP != "0.0.0.0/0" {
			t.Errorf("expected DstIP 0.0.0.0/0, got %s", rule.DstIP)
		}
	}
}

func TestNormalize_DenyAction(t *testing.T) {
	rn := NewRuleNormalizer()

	resp := &OPAPolicyResponse{}
	resp.Result.L4.FirewallAccessRules = []OPARule{
		{
			SourceIP:           "172.16.0.0/12",
			DestinationIP:      "10.0.0.0/8",
			Protocol:           17,
			MinSourcePort:      0,
			MaxSourcePort:      65535,
			MinDestinationPort: 53,
			MaxDestinationPort: 53,
			Action:             "deny",
			Preference:         300,
		},
	}

	_, opts, err := rn.Normalize(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(opts) != 1 {
		t.Fatalf("expected 1 opt, got %d", len(opts))
	}

	for _, opt := range opts {
		if !opt.Drop {
			t.Error("expected Drop=true for deny action")
		}
		if opt.Allow {
			t.Error("expected Allow=false for deny action")
		}
	}
}
