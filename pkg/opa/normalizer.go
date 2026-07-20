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
	"fmt"
	"net"

	tk "github.com/loxilb-io/loxilib"

	cmn "github.com/loxilb-io/loxilb/common"
)

// validProtocols defines the set of accepted protocol numbers.
// 0 = any, 6 = TCP, 17 = UDP, 132 = SCTP.
var validProtocols = map[int]bool{
	0:   true,
	6:   true,
	17:  true,
	132: true,
}

// RuleNormalizer converts OPA policy rules into LoxiLB firewall rule arguments.
type RuleNormalizer struct{}

// NewRuleNormalizer creates a RuleNormalizer.
func NewRuleNormalizer() *RuleNormalizer {
	return &RuleNormalizer{}
}

// MakeDiffKey produces a stable string key from a FwRuleArg for use in rule diffing.
// Format: "{SrcIP}|{DstIP}|{Proto}|{SrcPortMin}-{SrcPortMax}|{DstPortMin}-{DstPortMax}|{Pref}"
func (rn *RuleNormalizer) MakeDiffKey(rule cmn.FwRuleArg) DiffKey {
	return DiffKey(fmt.Sprintf("%s|%s|%d|%d-%d|%d-%d|%d",
		rule.SrcIP,
		rule.DstIP,
		rule.Proto,
		rule.SrcPortMin,
		rule.SrcPortMax,
		rule.DstPortMin,
		rule.DstPortMax,
		rule.Pref,
	))
}

// Normalize converts an OPA policy response into maps of FwRuleArg and FwOptArg
// keyed by DiffKey. Invalid rules are logged and skipped.
func (rn *RuleNormalizer) Normalize(resp *OPAPolicyResponse) (map[DiffKey]cmn.FwRuleArg, map[DiffKey]cmn.FwOptArg, error) {
	rules := make(map[DiffKey]cmn.FwRuleArg)
	opts := make(map[DiffKey]cmn.FwOptArg)

	if resp == nil {
		return rules, opts, nil
	}

	for i, opaRule := range resp.Result.L4.FirewallAccessRules {
		fwRule, fwOpt, err := rn.convertRule(opaRule)
		if err != nil {
			tk.LogIt(tk.LogWarning, "[OPA-L4][WARN] skipping rule %d: %v\n", i, err)
			continue
		}

		key := rn.MakeDiffKey(fwRule)
		rules[key] = fwRule
		opts[key] = fwOpt
	}

	return rules, opts, nil
}

// convertRule transforms a single OPARule into FwRuleArg and FwOptArg.
func (rn *RuleNormalizer) convertRule(opaRule OPARule) (cmn.FwRuleArg, cmn.FwOptArg, error) {
	var fwRule cmn.FwRuleArg
	var fwOpt cmn.FwOptArg

	// Validate and normalize action
	switch opaRule.Action {
	case "allow":
		fwOpt.Allow = true
	case "deny":
		fwOpt.Drop = true
	default:
		return fwRule, fwOpt, fmt.Errorf("unknown action %q", opaRule.Action)
	}

	// Validate protocol
	if !validProtocols[opaRule.Protocol] {
		return fwRule, fwOpt, fmt.Errorf("unsupported protocol %d", opaRule.Protocol)
	}

	// Normalize source IP
	srcIP, err := rn.normalizeCIDR(opaRule.SourceIP)
	if err != nil {
		return fwRule, fwOpt, fmt.Errorf("invalid sourceIP %q: %w", opaRule.SourceIP, err)
	}

	// Normalize destination IP
	dstIP, err := rn.normalizeCIDR(opaRule.DestinationIP)
	if err != nil {
		return fwRule, fwOpt, fmt.Errorf("invalid destinationIP %q: %w", opaRule.DestinationIP, err)
	}

	// Validate port ranges
	if opaRule.MinSourcePort > opaRule.MaxSourcePort {
		return fwRule, fwOpt, fmt.Errorf("source port min %d > max %d", opaRule.MinSourcePort, opaRule.MaxSourcePort)
	}
	if opaRule.MinDestinationPort > opaRule.MaxDestinationPort {
		return fwRule, fwOpt, fmt.Errorf("destination port min %d > max %d", opaRule.MinDestinationPort, opaRule.MaxDestinationPort)
	}

	// Normalize full-range ports (0-65535) to (0-0). LoxiLB's eBPF firewall
	// treats (min=0, max=0) as "no port filter" (match all), whereas
	// (min=0, max=65535) with valid=true creates an explicit port range check
	// that can fail for protocol=0 (any) packets without L4 headers.
	srcPortMin := uint16(opaRule.MinSourcePort)
	srcPortMax := uint16(opaRule.MaxSourcePort)
	if srcPortMin == 0 && srcPortMax == 65535 {
		srcPortMin = 0
		srcPortMax = 0
	}
	dstPortMin := uint16(opaRule.MinDestinationPort)
	dstPortMax := uint16(opaRule.MaxDestinationPort)
	if dstPortMin == 0 && dstPortMax == 65535 {
		dstPortMin = 0
		dstPortMax = 0
	}

	fwRule = cmn.FwRuleArg{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Proto:      uint8(opaRule.Protocol),
		SrcPortMin: srcPortMin,
		SrcPortMax: srcPortMax,
		DstPortMin: dstPortMin,
		DstPortMax: dstPortMax,
		Pref:       uint32(opaRule.Preference),
	}

	return fwRule, fwOpt, nil
}

// normalizeCIDR validates and normalizes an IP/CIDR string.
// An empty string defaults to "0.0.0.0/0".
func (rn *RuleNormalizer) normalizeCIDR(s string) (string, error) {
	if s == "" {
		return "0.0.0.0/0", nil
	}

	_, _, err := net.ParseCIDR(s)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %w", err)
	}

	return s, nil
}
