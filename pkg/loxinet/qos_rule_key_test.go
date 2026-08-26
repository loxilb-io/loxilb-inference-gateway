/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

func TestParseLBRuleKeyIPv4AndBracketedIPv6(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		ip    string
		port  uint16
		proto uint8
	}{
		{name: "legacy IPv4", key: "20.20.20.1:443:tcp", ip: "20.20.20.1", port: 443, proto: 6},
		{name: "bracketed IPv6", key: "[2001:db8::20]:8443:sctp", ip: "2001:db8::20", port: 8443, proto: 132},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseLBRuleKey(tc.key)
			if err != nil {
				t.Fatalf("parseLBRuleKey(%q) failed: %v", tc.key, err)
			}
			if !parsed.exact || !parsed.vip.Equal(net.ParseIP(tc.ip)) || parsed.port != tc.port || parsed.proto != tc.proto {
				t.Fatalf("parseLBRuleKey(%q) = %+v, want %s:%d proto %d", tc.key, parsed, tc.ip, tc.port, tc.proto)
			}
		})
	}
}

func TestParseLBRuleKeyRejectsMalformedAndBracketlessIPv6(t *testing.T) {
	for _, key := range []string{
		"2001:db8::20:443:tcp",
		"[2001:db8::20:443:tcp",
		"[2001:db8::20]:0:tcp",
		"[2001:db8::20]:65536:tcp",
		"[2001:db8::20]:443:icmp",
		"[20.20.20.1]:443:tcp",
	} {
		t.Run(key, func(t *testing.T) {
			if _, err := parseLBRuleKey(key); err == nil {
				t.Fatalf("parseLBRuleKey(%q) unexpectedly succeeded", key)
			}
		})
	}
}

func TestFormatLBRuleKeyPreservesIPv4AndBracketsIPv6(t *testing.T) {
	if got := formatLBRuleKey("20.20.20.1", 443, "TCP"); got != "20.20.20.1:443:tcp" {
		t.Fatalf("formatLBRuleKey IPv4 = %q", got)
	}
	if got := formatLBRuleKey("2001:db8::20", 443, "UDP"); got != "[2001:db8::20]:443:udp" {
		t.Fatalf("formatLBRuleKey IPv6 = %q", got)
	}
}
