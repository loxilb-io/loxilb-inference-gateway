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
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type lbRuleKeyParts struct {
	vip   net.IP
	port  uint16
	proto uint8
	exact bool
}

// parseLBRuleKey is the single parser for QoS LB-rule lookup and dataplane
// meter programming. IPv4 retains the legacy VIP:PORT:PROTO form, while IPv6
// must use [VIP]:PORT:PROTO so address colons cannot be confused with fields.
// A bare IP remains supported for the historical first-rule-by-VIP lookup.
func parseLBRuleKey(key string) (lbRuleKeyParts, error) {
	var parsed lbRuleKeyParts
	if key == "" || strings.TrimSpace(key) != key {
		return parsed, errors.New("empty or whitespace-padded lb-rule key")
	}
	if ip := net.ParseIP(key); ip != nil {
		parsed.vip = ip
		return parsed, nil
	}

	protoSep := strings.LastIndexByte(key, ':')
	if protoSep <= 0 || protoSep == len(key)-1 {
		return parsed, errors.New("lb-rule key must use VIP:PORT:PROTO or [VIP]:PORT:PROTO")
	}
	hostPort, protoName := key[:protoSep], strings.ToLower(key[protoSep+1:])
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		if strings.Count(hostPort, ":") > 1 && !strings.HasPrefix(hostPort, "[") {
			return parsed, errors.New("IPv6 VIP must be bracketed as [VIP]:PORT:PROTO")
		}
		return parsed, fmt.Errorf("malformed lb-rule key: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return parsed, errors.New("lb-rule VIP must be an IP address")
	}
	if ip.To4() != nil && strings.HasPrefix(hostPort, "[") {
		return parsed, errors.New("IPv4 VIP must use the legacy VIP:PORT:PROTO form")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return parsed, errors.New("lb-rule port must be between 1 and 65535")
	}

	switch protoName {
	case "tcp":
		parsed.proto = 6
	case "udp":
		parsed.proto = 17
	case "sctp":
		parsed.proto = 132
	default:
		return parsed, errors.New("lb-rule protocol must be tcp, udp, or sctp")
	}
	parsed.vip = ip
	parsed.port = uint16(port)
	parsed.exact = true
	return parsed, nil
}

func formatLBRuleKey(vip string, port uint16, proto string) string {
	host := strings.TrimPrefix(strings.TrimSuffix(vip, "]"), "[")
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + ip.String() + "]"
	}
	return fmt.Sprintf("%s:%d:%s", host, port, strings.ToLower(proto))
}
