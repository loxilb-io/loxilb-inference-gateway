/*
 * Copyright (c) 2022-2025 NetLOX Inc
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
 *
 * Unified Security Rate Limiting REST API Handlers (P0-5 + P0-6 + P0-7)
 * Pattern: Follows P0-7 IP Filter implementation (ipfilter.go)
 * Features: SYN Flood Protection + Connection Rate Limiting + UDP Flood Protection
 * Conditional compilation: requires HAVE_DP_SECURITY_RATE_LIMIT build flag
 */
package handler

import (
	"fmt"
	"net"

	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// Upper bounds for securityrate numeric inputs. The swagger model uses int64,
// so values are range-checked here BEFORE the uint32 casts - otherwise a
// negative or oversized value wraps silently (e.g. -1 -> 4294967295, which
// reports protection as enabled but never triggers).
const (
	secRateMaxPPSThreshold = 1 << 24 // SYN/conn/UDP packet-per-second ceilings
	// UDPBandwidthMB is converted to bytes in a uint32; 4096MB and above
	// would overflow to a tiny/zero byte limit.
	secRateMaxUDPBandwidthMB = 4095
	secRateMaxWhitelistIPs   = 1024
)

// ConfigPostSecurityRate - Configure unified security rate limiting (P0-5 SYN Flood + P0-6 Connection Rate + P0-7 UDP Flood)
// POST /config/securityrate
// Pattern: Follows ConfigPostIPFilter from P0-7 (ipfilter.go:29-67)
func ConfigPostSecurityRate(params operations.PostConfigSecurityrateParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: SecurityRate %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	// Range-check the raw int64 inputs before any uint32 conversion.
	for _, c := range []struct {
		name string
		val  int64
		max  int64
	}{
		{"synThreshold", *params.Attr.SynThreshold, secRateMaxPPSThreshold},
		{"cookieThreshold", *params.Attr.CookieThreshold, secRateMaxPPSThreshold},
		{"ratePerSec", *params.Attr.RatePerSec, secRateMaxPPSThreshold},
		{"udpPktThreshold", *params.Attr.UDPPktThreshold, secRateMaxPPSThreshold},
		{"udpBandwidthMB", *params.Attr.UDPBandwidthMB, secRateMaxUDPBandwidthMB},
	} {
		if c.val < 0 || c.val > c.max {
			tk.LogIt(tk.LogError, "[SECURITYRATE] invalid %s: %d out of range [0, %d]\n", c.name, c.val, c.max)
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(
				fmt.Sprintf("invalid %s: %d out of range [0, %d]", c.name, c.val, c.max))}
		}
	}

	// Whitelist CIDRs must parse; rejecting here beats silently skipping them
	// in the datapath layer (config-theater on a security feature).
	if len(params.Attr.WhitelistIps) > secRateMaxWhitelistIPs {
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(
			fmt.Sprintf("invalid whitelistIps: %d entries exceeds limit %d", len(params.Attr.WhitelistIps), secRateMaxWhitelistIPs))}
	}
	for _, cidr := range params.Attr.WhitelistIps {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			tk.LogIt(tk.LogError, "[SECURITYRATE] invalid whitelist CIDR '%s': %v\n", cidr, err)
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(
				fmt.Sprintf("invalid whitelistIps entry '%s': not a valid CIDR", cidr))}
		}
	}

	// Extract parameters from request body
	config := cmn.SecurityRateConfig{
		// P0-5: SYN Flood Protection
		SYNEnabled:      *params.Attr.SynEnabled,
		SYNThreshold:    uint32(*params.Attr.SynThreshold),
		CookieThreshold: uint32(*params.Attr.CookieThreshold),

		// P0-6: Connection Rate Limiting
		ConnRateEnabled: *params.Attr.ConnRateEnabled,
		RatePerSec:      uint32(*params.Attr.RatePerSec),

		// P0-7: UDP Flood Protection
		UDPEnabled:      *params.Attr.UDPEnabled,
		UDPPktThreshold: uint32(*params.Attr.UDPPktThreshold),
		UDPBandwidthMB:  uint32(*params.Attr.UDPBandwidthMB),

		// Shared Configuration
		WhitelistIPs: params.Attr.WhitelistIps,
	}

	// Validation: SYN flood thresholds
	if config.SYNEnabled {
		if config.SYNThreshold == 0 {
			tk.LogIt(tk.LogError, "[SECURITYRATE] Invalid synThreshold: must be greater than 0\n")
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid synThreshold: must be greater than 0")}
		}
		if config.CookieThreshold >= config.SYNThreshold {
			tk.LogIt(tk.LogError, "[SECURITYRATE] Invalid thresholds: cookieThreshold (%d) must be less than synThreshold (%d)\n",
				config.CookieThreshold, config.SYNThreshold)
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid cookieThreshold: must be less than synThreshold")}
		}
	}

	// Validation: Connection rate thresholds
	if config.ConnRateEnabled {
		if config.RatePerSec == 0 {
			tk.LogIt(tk.LogError, "[SECURITYRATE] Invalid ratePerSec: must be greater than 0\n")
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid ratePerSec: must be greater than 0")}
		}
	}

	// Validation: UDP flood thresholds
	if config.UDPEnabled {
		if config.UDPPktThreshold == 0 {
			tk.LogIt(tk.LogError, "[SECURITYRATE] Invalid udpPktThreshold: must be greater than 0\n")
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid udpPktThreshold: must be greater than 0")}
		}
		if config.UDPBandwidthMB == 0 {
			tk.LogIt(tk.LogError, "[SECURITYRATE] Invalid udpBandwidthMB: must be greater than 0\n")
			return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid udpBandwidthMB: must be greater than 0")}
		}
	}

	// Validation: At least one protection must be enabled
	if !config.SYNEnabled && !config.ConnRateEnabled && !config.UDPEnabled {
		tk.LogIt(tk.LogError, "[SECURITYRATE] At least one protection (SYN, ConnRate, or UDP) must be enabled\n")
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage("invalid parameters: at least one protection (synEnabled, connRateEnabled, or udpEnabled) must be true")}
	}

	tk.LogIt(tk.LogInfo, "[SECURITYRATE] Configure unified protection: synEnabled=%v (threshold=%d, cookie=%d), connRateEnabled=%v (rate=%d/s), udpEnabled=%v (pktThreshold=%d/s, bandwidthMB=%d), whitelist=%d IPs\n",
		config.SYNEnabled, config.SYNThreshold, config.CookieThreshold,
		config.ConnRateEnabled, config.RatePerSec,
		config.UDPEnabled, config.UDPPktThreshold, config.UDPBandwidthMB, len(config.WhitelistIPs))

	_, err := ApiHooks.NetSecurityRateSet(&config)
	if err != nil {
		tk.LogIt(tk.LogError, "[SECURITYRATE] Failed to configure protection: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigDeleteSecurityRate - Disable all security rate limiting
// DELETE /config/securityrate
// Pattern: Follows ConfigDeleteIPFilter from P0-7 (ipfilter.go:69-94)
func ConfigDeleteSecurityRate(params operations.DeleteConfigSecurityrateParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: SecurityRate %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	tk.LogIt(tk.LogInfo, "[SECURITYRATE] Disable unified security rate limiting\n")

	// Disable all protections
	config := cmn.SecurityRateConfig{
		SYNEnabled:      false,
		SYNThreshold:    100, // Keep defaults but disabled
		CookieThreshold: 50,
		ConnRateEnabled: false,
		RatePerSec:      50,
		UDPEnabled:      false,
		UDPPktThreshold: 1000,
		UDPBandwidthMB:  100,
	}

	_, err := ApiHooks.NetSecurityRateSet(&config)
	if err != nil {
		tk.LogIt(tk.LogError, "[SECURITYRATE] Failed to disable protection: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	return &ResultResponse{Result: "Success"}
}

// ConfigGetSecurityRateAll - Get unified security rate limiting configuration and statistics
// GET /config/securityrate/all
// Pattern: Follows ConfigGetIPFilterAll from P0-7 (ipfilter.go:5)
func ConfigGetSecurityRateAll(params operations.GetConfigSecurityrateAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: SecurityRate %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	state, err := ApiHooks.NetSecurityRateGet()
	if err != nil {
		tk.LogIt(tk.LogError, "[SECURITYRATE] Failed to get state: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	// Convert to API model
	entry := &models.SecurityRateEntry{
		// P0-5: SYN Flood Configuration
		SynEnabled:      state.Config.SYNEnabled,
		SynThreshold:    int64(state.Config.SYNThreshold),
		CookieThreshold: int64(state.Config.CookieThreshold),

		// P0-6: Connection Rate Configuration
		ConnRateEnabled: state.Config.ConnRateEnabled,
		RatePerSec:      int64(state.Config.RatePerSec),

		// P0-7: UDP Flood Configuration
		UDPEnabled:      state.Config.UDPEnabled,
		UDPPktThreshold: int64(state.Config.UDPPktThreshold),
		UDPBandwidthMB:  int64(state.Config.UDPBandwidthMB),

		// Shared Configuration
		WhitelistIps: state.Config.WhitelistIPs,

		// P0-5: SYN Flood Statistics
		SynBlocked: int64(state.Stats.SYNBlocked),
		SynPassed:  int64(state.Stats.SYNPassed),
		SynCookies: int64(state.Stats.SYNCookies),

		// P0-6: Connection Rate Statistics
		ConnBlocked: int64(state.Stats.ConnBlocked),
		ConnPassed:  int64(state.Stats.ConnPassed),

		// P0-7: UDP Flood Statistics
		UDPBlocked:      int64(state.Stats.UDPBlocked),
		UDPPassed:       int64(state.Stats.UDPPassed),
		UDPBytesBlocked: int64(state.Stats.UDPBytesBlocked),
		UDPBytesPassed:  int64(state.Stats.UDPBytesPassed),

		// Shared Statistics
		UniqueIps: int64(state.Stats.UniqueIPs),
	}

	result := []*models.SecurityRateEntry{entry}

	return operations.NewGetConfigSecurityrateAllOK().WithPayload(&operations.GetConfigSecurityrateAllOKBody{
		SecurityrateAttr: result,
	})
}

// ConfigPutSecurityRateReset - Reset security rate limiting statistics
// PUT /config/securityrate/reset
// Pattern: Simple reset operation, no request body needed
func ConfigPutSecurityRateReset(params operations.PutConfigSecurityrateResetParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: SecurityRate Reset %s API called by IP: %s. url : %s\n",
		params.HTTPRequest.Method, params.HTTPRequest.RemoteAddr, params.HTTPRequest.URL)

	_, err := ApiHooks.NetSecurityRateResetStats()
	if err != nil {
		tk.LogIt(tk.LogError, "[SECURITYRATE] Failed to reset statistics: %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}

	tk.LogIt(tk.LogInfo, "[SECURITYRATE] Statistics reset successfully\n")
	return operations.NewPutConfigSecurityrateResetNoContent()
}
