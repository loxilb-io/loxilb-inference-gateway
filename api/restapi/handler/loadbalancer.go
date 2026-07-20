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
package handler

import (
	"net"
	"strings"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	cmn "github.com/loxilb-io/loxilb/common"
	tk "github.com/loxilb-io/loxilib"
)

// stripV6Brackets normalizes an RFC-bracketed IPv6 literal ("[2001:db8::1]") to the bare
// form ServIP is stored in (net.IP.String => "2001:db8::1"). findLBRuleByKey does a raw
// string == on the UNBRACKETED ServIP, so a bracketed IPv6 path param would never match
// without this strip. Idempotent for IPv4 and already-bare input. When the stripped value
// is a valid IP literal it is returned bare; when it is NOT a parseable IP (e.g. a malformed
// path param) the stripped value is still returned so the downstream lookup simply misses
// and returns 404 rather than the handler panicking. This plan OWNS this helper;
// EXTENDS its application to the other composite-key paths (GET/PATCH/DELETE/status).
func stripV6Brackets(ip string) string {
	stripped := strings.Trim(ip, "[]")
	if net.ParseIP(stripped) == nil {
		// Not a clean IP literal after stripping — return the stripped form anyway so a
		// bracketed-but-otherwise-valid value still resolves; an outright malformed value
		// just falls through to a 404 (no rule will match it).
		return stripped
	}
	return stripped
}

func ConfigPostLoadbalancer(params operations.PostConfigLoadbalancerParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	var lbRules cmn.LbRuleMod

	if params.Attr.ServiceArguments.ExternalIP != nil {
		lbRules.Serv.ServIP = *params.Attr.ServiceArguments.ExternalIP
	}
	lbRules.Serv.PrivateIP = params.Attr.ServiceArguments.PrivateIP
	if params.Attr.ServiceArguments.Port != nil {
		lbRules.Serv.ServPort = uint16(*params.Attr.ServiceArguments.Port)
	}
	lbRules.Serv.ServPortMax = uint16(params.Attr.ServiceArguments.PortMax)
	lbRules.Serv.Proto = params.Attr.ServiceArguments.Protocol
	lbRules.Serv.BlockNum = params.Attr.ServiceArguments.Block
	lbRules.Serv.Sel = cmn.EpSelect(params.Attr.ServiceArguments.Sel)
	lbRules.Serv.Bgp = params.Attr.ServiceArguments.Bgp
	lbRules.Serv.Monitor = params.Attr.ServiceArguments.Monitor
	lbRules.Serv.Mode = cmn.LBMode(params.Attr.ServiceArguments.Mode)
	lbRules.Serv.Security = cmn.LBSec(params.Attr.ServiceArguments.Security)
	lbRules.Serv.InactiveTimeout = uint32(params.Attr.ServiceArguments.InactiveTimeOut)
	lbRules.Serv.Managed = params.Attr.ServiceArguments.Managed
	lbRules.Serv.ProbeType = params.Attr.ServiceArguments.Probetype
	lbRules.Serv.ProbePort = params.Attr.ServiceArguments.Probeport
	lbRules.Serv.ProbeReq = params.Attr.ServiceArguments.Probereq
	lbRules.Serv.ProbeResp = params.Attr.ServiceArguments.Proberesp
	lbRules.Serv.ProbeTimeout = params.Attr.ServiceArguments.ProbeTimeout
	lbRules.Serv.ProbeRetries = int(params.Attr.ServiceArguments.ProbeRetries)
	// per-listener member timeouts in MILLISECONDS (native unit,
	// no conversion). Additive/optional — 0/absent preserves today's behaviour. go-swagger
	// names the third field TimeoutTCPInspect (TCP acronym capitalization).
	lbRules.Serv.TimeoutMemberConnect = params.Attr.ServiceArguments.TimeoutMemberConnect
	lbRules.Serv.TimeoutMemberData = params.Attr.ServiceArguments.TimeoutMemberData
	lbRules.Serv.TimeoutTcpInspect = params.Attr.ServiceArguments.TimeoutTCPInspect
	lbRules.Serv.Name = params.Attr.ServiceArguments.Name
	lbRules.Serv.Oper = cmn.LBOp(params.Attr.ServiceArguments.Oper)
	lbRules.Serv.HostUrl = params.Attr.ServiceArguments.Host
	// honor a client-supplied stable opaque id verbatim; empty => the control
	// plane mints a UUIDv4 (resolveOpaqueID). Without this the POST handler silently dropped
	// the id so it could never be referenced — L7_POLICY attaches by this id.
	lbRules.Serv.Id = params.Attr.ServiceArguments.ID

	// P6: Path-based routing configuration (backward compatible - optional fields)
	lbRules.Serv.PathPrefix = params.Attr.ServiceArguments.PathPrefix
	if params.Attr.ServiceArguments.PathMatchMode != nil {
		lbRules.Serv.PathMatchMode = *params.Attr.ServiceArguments.PathMatchMode
	} else {
		lbRules.Serv.PathMatchMode = "disabled" // Default to hostname-only (backward compat)
	}

	lbRules.Serv.ProxyProtocolV2 = params.Attr.ServiceArguments.Proxyprotocolv2
	lbRules.Serv.Egress = params.Attr.ServiceArguments.Egress
	lbRules.Serv.TraceType = params.Attr.ServiceArguments.TraceType // Tracing catalog (independent from GPU routing)

	// Backend protocol capability - default to "http1" for backward compatibility
	if params.Attr.ServiceArguments.BackendProtocol != nil {
		lbRules.Serv.BackendProtocol = *params.Attr.ServiceArguments.BackendProtocol
	} else {
		lbRules.Serv.BackendProtocol = "http1" // Safe default: HTTP/1.1 only
	}

	// AI model name for pool selection (empty = wildcard, backward compatible)
	lbRules.Serv.ModelName = params.Attr.ServiceArguments.ModelName

	// SSE (Server-Sent Events) streaming configuration (US-401)
	lbRules.Serv.SSEMode = params.Attr.ServiceArguments.SseMode
	lbRules.Serv.MaxStreamDurationSec = uint32(params.Attr.ServiceArguments.MaxStreamDurationSec)
	lbRules.Serv.BackendKeepaliveIntervalSec = uint32(params.Attr.ServiceArguments.BackendKeepaliveIntervalSec)

	// P/D disaggregation mode (US-502)
	lbRules.Serv.PDDisaggMode = params.Attr.ServiceArguments.PdDisaggMode

	// P/D cache-aware routing (US-PD801)
	lbRules.Serv.PDCacheAwareMode = params.Attr.ServiceArguments.PdCacheAwareMode
	lbRules.Serv.PDSessionTTLSec = uint32(params.Attr.ServiceArguments.PdSessionTTLSec)
	lbRules.Serv.PDCacheThreshold = uint8(params.Attr.ServiceArguments.PdCacheThreshold)
	lbRules.Serv.PDBalanceAbsThreshold = uint8(params.Attr.ServiceArguments.PdBalanceAbsThreshold)

	// KV-Cache Exact Routing
	lbRules.Serv.KvExactMode = uint8(params.Attr.ServiceArguments.KvExactMode)
	lbRules.Serv.KvBlockSize = uint32(params.Attr.ServiceArguments.KvBlockSize)
	lbRules.Serv.KvHashAlgo = params.Attr.ServiceArguments.KvHashAlgo
	lbRules.Serv.KvZmqPort = uint16(params.Attr.ServiceArguments.KvZmqPort)
	lbRules.Serv.KvWarmupSec = uint32(params.Attr.ServiceArguments.KvWarmupSec)
	// per-rule KV engine + SGLang DP rank count. Absent ⇒ zero
	// values ⇒ byte-identical vLLM behavior (default-OFF additive chain).
	lbRules.Serv.KvEngineType = params.Attr.ServiceArguments.KvEngineType
	lbRules.Serv.KvDpRankCount = uint16(params.Attr.ServiceArguments.KvDpRankCount)

	// Custom session header configuration - supports both RR and Persist modes
	lbRules.Serv.SessionHeaderName = params.Attr.ServiceArguments.SessionHeaderName
	if (lbRules.Serv.Sel == cmn.LbSelRr || lbRules.Serv.Sel == cmn.LbSelRrPersist) && lbRules.Serv.SessionHeaderName != "" {
		tk.LogIt(tk.LogInfo, "api: lb-rule %s:%v session header: %s (mode: %s)\n",
			lbRules.Serv.ServIP, lbRules.Serv.ServPort, lbRules.Serv.SessionHeaderName,
			map[cmn.EpSelect]string{cmn.LbSelRr: "RR+session-learning", cmn.LbSelRrPersist: "Persist+IP-fallback"}[lbRules.Serv.Sel])
	} else if lbRules.Serv.Sel == cmn.LbSelRrPersist {
		tk.LogIt(tk.LogInfo, "api: lb-rule %s:%v persist mode: IP-based (no custom header)\n",
			lbRules.Serv.ServIP, lbRules.Serv.ServPort)
	}

	// CHWBL configuration (only used when sel=8)
	if params.Attr.ServiceArguments.ChwblPrefixHashLevel != nil {
		lbRules.Serv.CHWBLPrefixHashLevel = int(*params.Attr.ServiceArguments.ChwblPrefixHashLevel)
	}
	if params.Attr.ServiceArguments.ChwblPrefixHashFlags != nil {
		lbRules.Serv.CHWBLPrefixHashFlags = int(*params.Attr.ServiceArguments.ChwblPrefixHashFlags)
	}
	// ChwblMeanLoadFactor is int64, not pointer (has default value)
	if params.Attr.ServiceArguments.ChwblMeanLoadFactor != 0 {
		lbRules.Serv.CHWBLMeanLoadFactor = int(params.Attr.ServiceArguments.ChwblMeanLoadFactor)
	}
	// ChwblReplication is int64, not pointer (has default value)
	if params.Attr.ServiceArguments.ChwblReplication != 0 {
		lbRules.Serv.CHWBLReplication = int(params.Attr.ServiceArguments.ChwblReplication)
	}
	if params.Attr.ServiceArguments.ChwblEnableCacheSalt != nil {
		lbRules.Serv.CHWBLEnableCacheSalt = *params.Attr.ServiceArguments.ChwblEnableCacheSalt
	}

	// Log CHWBL configuration if sel=8 (CHWBL) or sel=10 (WRR_HASH)
	if lbRules.Serv.Sel == cmn.LbSelCHWBL || lbRules.Serv.Sel == cmn.LbSelWRRHash {
		tk.LogIt(tk.LogInfo, "api: lb-rule %s:%v CHWBL config: level=%d flags=0x%02x load_factor=%d replication=%d cache_salt=%v\n",
			lbRules.Serv.ServIP, lbRules.Serv.ServPort,
			lbRules.Serv.CHWBLPrefixHashLevel, lbRules.Serv.CHWBLPrefixHashFlags,
			lbRules.Serv.CHWBLMeanLoadFactor, lbRules.Serv.CHWBLReplication,
			lbRules.Serv.CHWBLEnableCacheSalt)
	}

	// mTLS Frontend Configuration
	if params.Attr.ServiceArguments.MtlsFrontend != nil {
		tk.LogIt(tk.LogDebug, "api: POST LB - parsing mTLS frontend config\n")
		lbRules.Serv.MTLSFrontend = &cmn.MTLSFrontendConfig{
			ClientCAPath:     params.Attr.ServiceArguments.MtlsFrontend.ClientCaPath,
			ClientCACertData: params.Attr.ServiceArguments.MtlsFrontend.ClientCaCertData,
			ClientCNPattern:  params.Attr.ServiceArguments.MtlsFrontend.ClientCnPattern,
		}
		// Convert pointer fields to values
		if params.Attr.ServiceArguments.MtlsFrontend.ClientCertMode != nil {
			lbRules.Serv.MTLSFrontend.ClientCertMode = *params.Attr.ServiceArguments.MtlsFrontend.ClientCertMode
			tk.LogIt(tk.LogDebug, "api: POST LB - ClientCertMode='%s'\n", lbRules.Serv.MTLSFrontend.ClientCertMode)
		}
		if params.Attr.ServiceArguments.MtlsFrontend.RequireClientCn != nil {
			lbRules.Serv.MTLSFrontend.RequireClientCN = *params.Attr.ServiceArguments.MtlsFrontend.RequireClientCn
			tk.LogIt(tk.LogDebug, "api: POST LB - RequireClientCN=%v\n", lbRules.Serv.MTLSFrontend.RequireClientCN)
		}
		// explicit client-cert CRL path (leaf-only X509_V_FLAG_CRL_CHECK).
		// Additive/default-off — empty preserves today's behaviour (77-04 sibling-crl convention).
		lbRules.Serv.MTLSFrontend.ClientCRLPath = params.Attr.ServiceArguments.MtlsFrontend.ClientCrlPath
		tk.LogIt(tk.LogDebug, "api: POST LB - mTLS frontend stored: %+v\n", lbRules.Serv.MTLSFrontend)
	}

	// mTLS Backend Configuration
	if params.Attr.ServiceArguments.MtlsBackend != nil {
		lbRules.Serv.MTLSBackend = &cmn.MTLSBackendConfig{
			BackendCAPath:  params.Attr.ServiceArguments.MtlsBackend.BackendCaPath,
			ClientCertPath: params.Attr.ServiceArguments.MtlsBackend.ClientCertPath,
			ClientKeyPath:  params.Attr.ServiceArguments.MtlsBackend.ClientKeyPath,
			ClientCertData: params.Attr.ServiceArguments.MtlsBackend.ClientCertData,
			ClientKeyData:  params.Attr.ServiceArguments.MtlsBackend.ClientKeyData,
		}
		// Convert pointer field to value
		if params.Attr.ServiceArguments.MtlsBackend.VerifyServerCert != nil {
			lbRules.Serv.MTLSBackend.VerifyServerCert = *params.Attr.ServiceArguments.MtlsBackend.VerifyServerCert
		}
	}

	// ingest opaque projectId + annotations from the request so they
	// reach the control plane (stored + round-tripped on GET). Mirrors the serialize path;
	// without this the POSTed values are dropped and the ?projectId= filter + round-trip fail.
	lbRules.Serv.ProjectId = params.Attr.ServiceArguments.ProjectID
	lbRules.Serv.Annotations = params.Attr.ServiceArguments.Annotations

	// vip_qos_policy_id — associate a pre-existing /config/policy ident to the
	// VIP rule (policer association). Additive/default-off (empty ⇒ rule unchanged).
	lbRules.Serv.VipQosPolicyId = params.Attr.ServiceArguments.VipQosPolicyID

	// TLS-hardening additive fields. All optional/default-off —
	// empty/nil/0 ⇒ today's behaviour, round-trips byte-identical when unset.
	// Threaded to the proxy_arg scalars 77-02 added via the CGO export in dpebpf_linux.go.
	lbRules.Serv.AlpnProtocols = params.Attr.ServiceArguments.AlpnProtocols                 //
	lbRules.Serv.TlsCiphers = params.Attr.ServiceArguments.TLSCiphers                       //
	lbRules.Serv.TlsVersions = params.Attr.ServiceArguments.TLSVersions                     //
	lbRules.Serv.HstsMaxAge = uint32(params.Attr.ServiceArguments.HstsMaxAge)               //
	lbRules.Serv.HstsIncludeSubdomains = params.Attr.ServiceArguments.HstsIncludeSubdomains //
	lbRules.Serv.HstsPreload = params.Attr.ServiceArguments.HstsPreload                     //
	lbRules.Serv.BackendCaCertId = params.Attr.ServiceArguments.BackendCaCertID             //
	lbRules.Serv.BackendClientCertId = params.Attr.ServiceArguments.BackendClientCertID     //

	if lbRules.Serv.Proto == "sctp" {
		for _, data := range params.Attr.SecondaryIPs {
			lbRules.SecIPs = append(lbRules.SecIPs, cmn.LbSecIPArg{
				SecIP: data.SecondaryIP,
			})
		}
	}

	// Octavia /07: ingest structured secondaryVIPs[] (ALL protocols, ALONGSIDE
	// the flat SCTP-gated secondaryIPs above). Stored opaque + round-tripped on GET.
	for _, data := range params.Attr.SecondaryVIPs {
		lbRules.SecVIPs = append(lbRules.SecVIPs, cmn.LbSecVIPArg{
			Address:  data.Address,
			SubnetId: data.SubnetID,
			PortId:   data.PortID,
			Proto:    data.Proto,
		})
	}

	for _, data := range params.Attr.AllowedSources {
		lbRules.SrcIPs = append(lbRules.SrcIPs, cmn.LbAllowedSrcIPArg{
			Prefix: data.Prefix,
		})
	}

	for _, data := range params.Attr.Endpoints {

		var epIP string
		var epTargetPort uint16
		var epWeight uint8
		if data.EndpointIP != nil {
			epIP = *data.EndpointIP
		}
		if data.TargetPort != nil {
			epTargetPort = uint16(*data.TargetPort)
		}
		if data.Weight != nil {
			epWeight = uint8(*data.Weight)
		}

		// ingest the additive member fields so backup-tier
		// selection, monitorAddress probing, and subnetId round-trip actually receive them.
		// Backup is a *bool in the regenerated model (absent => primary, today's behavior).
		epBackup := false
		if data.Backup != nil {
			epBackup = *data.Backup
		}
		lbRules.Eps = append(lbRules.Eps, cmn.LbEndPointArg{
			EpIP:           epIP,
			EpPort:         epTargetPort,
			Weight:         epWeight,
			EpRole:         int(data.EpRole),
			NixlPort:       uint16(data.NixlPort),
			Backup:         epBackup,
			SubnetId:       data.SubnetID,
			MonitorAddress: data.MonitorAddress,
		})
	}

	if lbRules.Serv.Mode == cmn.LBModeDSR && lbRules.Serv.Sel != cmn.LbSelHash {
		return &ResultResponse{Result: "Error: Only Hash Selection criteria allowed for DSR mode"}
	}

	tk.LogIt(tk.LogDebug, "api: lbRules : %v\n", lbRules)
	_, err := ApiHooks.NetLbRuleAdd(&lbRules)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

func ConfigDeleteLoadbalancer(params operations.DeleteConfigLoadbalancerHosturlHosturlExternalipaddressIPAddressPortPortProtocolProtoParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	var lbServ cmn.LbServiceArg
	var lbRules cmn.LbRuleMod
	// Normalize a bracketed IPv6 path param to the bare form the rule key stores (ServIP is
	// unbracketed); net.ParseIP inside stripV6Brackets gates malformed input.
	lbServ.ServIP = stripV6Brackets(params.IPAddress)
	lbServ.ServPort = uint16(params.Port)
	lbServ.Proto = params.Proto
	if params.Hosturl == "any" {
		lbServ.HostUrl = ""
	} else {
		lbServ.HostUrl = params.Hosturl
	}
	if params.Block != nil {
		lbServ.BlockNum = uint32(*params.Block)
	}
	if params.Bgp != nil {
		lbServ.Bgp = *params.Bgp
	}
	// Support selective deletion by path prefix (P6)
	if params.PathPrefix != nil {
		lbServ.PathPrefix = *params.PathPrefix
	}
	if params.PathMatchMode != nil {
		lbServ.PathMatchMode = *params.PathMatchMode
	} else {
		// CRITICAL FIX: Always default to "disabled" to match creation behavior
		// Previously only set when HostUrl != "", causing deletion failures for rules without HostUrl
		lbServ.PathMatchMode = "disabled"
	}
	// Support model_name in deletion — rule key includes model_name but swagger
	// spec does not have it as a parameter; extract from raw query string.
	if mn := params.HTTPRequest.URL.Query().Get("model_name"); mn != "" {
		lbServ.ModelName = mn
	}

	lbRules.Serv = lbServ
	tk.LogIt(tk.LogDebug, "api: lbRules : %v\n", lbRules)
	_, err := ApiHooks.NetLbRuleDel(&lbRules)

	// Backward compatibility: If deletion fails and PathMatchMode was defaulted to "disabled",
	// retry with empty PathMatchMode to match rules created before PathMatchMode default was added
	if err != nil && params.PathMatchMode == nil && lbServ.PathMatchMode == "disabled" {
		tk.LogIt(tk.LogDebug, "api: Retry deletion with empty PathMatchMode for backward compatibility\n")
		lbServ.PathMatchMode = ""
		lbRules.Serv = lbServ
		_, err = ApiHooks.NetLbRuleDel(&lbRules)
	}

	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

func ConfigDeleteLoadbalancerPortRange(params operations.DeleteConfigLoadbalancerHosturlHosturlExternalipaddressIPAddressPortPortPortmaxPortmaxProtocolProtoParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	var lbServ cmn.LbServiceArg
	var lbRules cmn.LbRuleMod
	// Normalize a bracketed IPv6 path param to the bare form the rule key stores (ServIP is
	// unbracketed); net.ParseIP inside stripV6Brackets gates malformed input.
	lbServ.ServIP = stripV6Brackets(params.IPAddress)
	lbServ.ServPort = uint16(params.Port)
	lbServ.ServPortMax = uint16(params.Portmax)
	lbServ.Proto = params.Proto
	if params.Hosturl == "any" {
		lbServ.HostUrl = ""
	} else {
		lbServ.HostUrl = params.Hosturl
	}
	if params.Block != nil {
		lbServ.BlockNum = uint32(*params.Block)
	}
	if params.Bgp != nil {
		lbServ.Bgp = *params.Bgp
	}
	// Support selective deletion by path prefix (P6)
	if params.PathPrefix != nil {
		lbServ.PathPrefix = *params.PathPrefix
	}
	if params.PathMatchMode != nil {
		lbServ.PathMatchMode = *params.PathMatchMode
	} else {
		// CRITICAL FIX: Always default to "disabled" to match creation behavior
		// Previously only set when HostUrl != "", causing deletion failures for rules without HostUrl
		lbServ.PathMatchMode = "disabled"
	}
	// Support model_name in deletion — rule key includes model_name but swagger
	// spec does not have it as a parameter; extract from raw query string.
	if mn := params.HTTPRequest.URL.Query().Get("model_name"); mn != "" {
		lbServ.ModelName = mn
	}

	lbRules.Serv = lbServ
	tk.LogIt(tk.LogDebug, "api: lbRules : %v\n", lbRules)
	_, err := ApiHooks.NetLbRuleDel(&lbRules)

	// Backward compatibility: If deletion fails and PathMatchMode was defaulted to "disabled",
	// retry with empty PathMatchMode to match rules created before PathMatchMode default was added
	if err != nil && params.PathMatchMode == nil && lbServ.PathMatchMode == "disabled" {
		tk.LogIt(tk.LogDebug, "api: Retry deletion with empty PathMatchMode for backward compatibility\n")
		lbServ.PathMatchMode = ""
		lbRules.Serv = lbServ
		_, err = ApiHooks.NetLbRuleDel(&lbRules)
	}

	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

func ConfigDeleteLoadbalancerWithoutPath(params operations.DeleteConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	var lbServ cmn.LbServiceArg
	var lbRules cmn.LbRuleMod
	// Normalize a bracketed IPv6 path param to the bare form the rule key stores (ServIP is
	// unbracketed); net.ParseIP inside stripV6Brackets gates malformed input.
	lbServ.ServIP = stripV6Brackets(params.IPAddress)
	lbServ.ServPort = uint16(params.Port)
	lbServ.ServPortMax = 0
	lbServ.Proto = params.Proto
	lbServ.HostUrl = ""
	if params.Block != nil {
		lbServ.BlockNum = uint32(*params.Block)
	}
	if params.Bgp != nil {
		lbServ.Bgp = *params.Bgp
	}
	// CRITICAL FIX: Default PathMatchMode to "disabled" for backward compatibility
	// This ensures deletion rule keys match creation rule keys (rule key includes pathMatchMode)
	lbServ.PathMatchMode = "disabled"
	// Support model_name in deletion — rule key includes model_name but swagger
	// spec does not have it as a parameter; extract from raw query string.
	if mn := params.HTTPRequest.URL.Query().Get("model_name"); mn != "" {
		lbServ.ModelName = mn
	}

	lbRules.Serv = lbServ
	tk.LogIt(tk.LogDebug, "api: lbRules (w/o Path): %v\n", lbRules)
	_, err := ApiHooks.NetLbRuleDel(&lbRules)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

func ConfigDeleteLoadbalancerPortRangeWithoutPath(params operations.DeleteConfigLoadbalancerExternalipaddressIPAddressPortPortPortmaxPortmaxProtocolProtoParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	var lbServ cmn.LbServiceArg
	var lbRules cmn.LbRuleMod
	// Normalize a bracketed IPv6 path param to the bare form the rule key stores (ServIP is
	// unbracketed); net.ParseIP inside stripV6Brackets gates malformed input.
	lbServ.ServIP = stripV6Brackets(params.IPAddress)
	lbServ.ServPort = uint16(params.Port)
	lbServ.ServPortMax = uint16(params.Portmax)
	lbServ.Proto = params.Proto
	lbServ.HostUrl = ""
	if params.Block != nil {
		lbServ.BlockNum = uint32(*params.Block)
	}
	if params.Bgp != nil {
		lbServ.Bgp = *params.Bgp
	}
	// CRITICAL FIX: Default PathMatchMode to "disabled" for backward compatibility
	// This ensures deletion rule keys match creation rule keys (rule key includes pathMatchMode)
	lbServ.PathMatchMode = "disabled"
	// Support model_name in deletion — rule key includes model_name but swagger
	// spec does not have it as a parameter; extract from raw query string.
	if mn := params.HTTPRequest.URL.Query().Get("model_name"); mn != "" {
		lbServ.ModelName = mn
	}

	lbRules.Serv = lbServ
	tk.LogIt(tk.LogDebug, "api: lbRules (w/o Path): %v\n", lbRules)
	_, err := ApiHooks.NetLbRuleDel(&lbRules)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	return &ResultResponse{Result: "Success"}
}

// serializeLBRule maps a single control-plane cmn.LbRuleMod into the generated
// models.LoadbalanceEntry. Extracted from ConfigGetLoadbalancer so the GET-all,
// GET-by-key, and GET-by-id handlers share one mapping (Octavia).
func serializeLBRule(lb cmn.LbRuleMod) *models.LoadbalanceEntry {
	var tmpLB models.LoadbalanceEntry
	var tmpSvc models.LoadbalanceEntryServiceArguments

	// opaque id + admin_state on every GET.
	tmpSvc.ID = lb.Serv.Id
	if lb.Serv.AdminStateUp != nil {
		tmpSvc.AdminStateUp = *lb.Serv.AdminStateUp
	} else {
		tmpSvc.AdminStateUp = true
	}
	// Octavia + : opaque projectId + annotations round-trip on
	// every GET. NOTE: ProjectID/Annotations are surfaced by go-swagger regen of the new
	// serviceArguments props (deferred to the remote/AWS gate; handler will not compile until then).
	tmpSvc.ProjectID = lb.Serv.ProjectId
	tmpSvc.Annotations = lb.Serv.Annotations

	// Service Arg match
	tmpSvc.ExternalIP = &lb.Serv.ServIP
	tmpSvc.Bgp = lb.Serv.Bgp
	port := int64(lb.Serv.ServPort)
	tmpSvc.Port = &port
	tmpSvc.PortMax = int64(lb.Serv.ServPortMax)
	tmpSvc.Protocol = lb.Serv.Proto
	tmpSvc.Block = uint32(lb.Serv.BlockNum)
	tmpSvc.Sel = int64(lb.Serv.Sel)
	tmpSvc.Mode = int32(lb.Serv.Mode)
	tmpSvc.Security = int32(lb.Serv.Security)
	tmpSvc.InactiveTimeOut = int32(lb.Serv.InactiveTimeout)
	tmpSvc.Monitor = lb.Serv.Monitor
	tmpSvc.Managed = lb.Serv.Managed
	tmpSvc.Probetype = lb.Serv.ProbeType
	tmpSvc.Probeport = lb.Serv.ProbePort
	tmpSvc.Name = lb.Serv.Name
	tmpSvc.Snat = lb.Serv.Snat
	tmpSvc.Host = lb.Serv.HostUrl
	tmpSvc.PathPrefix = lb.Serv.PathPrefix // P6: Return path prefix in GET
	// P6: PathMatchMode is a pointer in the API model
	if lb.Serv.PathMatchMode != "" {
		pathMatchMode := lb.Serv.PathMatchMode
		tmpSvc.PathMatchMode = &pathMatchMode
	}
	tmpSvc.Proxyprotocolv2 = lb.Serv.ProxyProtocolV2
	tmpSvc.Egress = lb.Serv.Egress
	tmpSvc.TraceType = lb.Serv.TraceType // Tracing catalog (independent from GPU routing)
	// Backend protocol capability - only meaningful for fullproxy mode (mode 4)
	if lb.Serv.Mode == cmn.LBModeFullProxy {
		backendProtocol := lb.Serv.BackendProtocol
		if backendProtocol == "" {
			backendProtocol = "http1" // Show explicit default
		}
		tmpSvc.BackendProtocol = &backendProtocol
	}

	// AI model name for pool selection
	if lb.Serv.ModelName != "" {
		tmpSvc.ModelName = lb.Serv.ModelName
	}

	// Custom session header name - supports both RR and Persist modes
	if (lb.Serv.Sel == cmn.LbSelRr || lb.Serv.Sel == cmn.LbSelRrPersist) && lb.Serv.SessionHeaderName != "" {
		tmpSvc.SessionHeaderName = lb.Serv.SessionHeaderName
	}

	// SSE streaming configuration (US-401)
	if lb.Serv.SSEMode {
		tmpSvc.SseMode = lb.Serv.SSEMode
	}
	if lb.Serv.MaxStreamDurationSec != 0 {
		tmpSvc.MaxStreamDurationSec = int32(lb.Serv.MaxStreamDurationSec)
	}
	if lb.Serv.BackendKeepaliveIntervalSec != 0 {
		tmpSvc.BackendKeepaliveIntervalSec = int32(lb.Serv.BackendKeepaliveIntervalSec)
	}

	// P/D disaggregation mode (US-502)
	if lb.Serv.PDDisaggMode {
		tmpSvc.PdDisaggMode = lb.Serv.PDDisaggMode
	}

	// P/D cache-aware routing (US-PD801)
	if lb.Serv.PDCacheAwareMode {
		tmpSvc.PdCacheAwareMode = lb.Serv.PDCacheAwareMode
	}
	if lb.Serv.PDSessionTTLSec != 0 {
		tmpSvc.PdSessionTTLSec = int32(lb.Serv.PDSessionTTLSec)
	}
	if lb.Serv.PDCacheThreshold != 0 {
		tmpSvc.PdCacheThreshold = int32(lb.Serv.PDCacheThreshold)
	}
	if lb.Serv.PDBalanceAbsThreshold != 0 {
		tmpSvc.PdBalanceAbsThreshold = int32(lb.Serv.PDBalanceAbsThreshold)
	}

	// KV-Cache Exact Routing
	if lb.Serv.KvExactMode != 0 {
		tmpSvc.KvExactMode = int64(lb.Serv.KvExactMode)
	}
	if lb.Serv.KvBlockSize != 0 {
		tmpSvc.KvBlockSize = int64(lb.Serv.KvBlockSize)
	}
	if lb.Serv.KvHashAlgo != "" {
		tmpSvc.KvHashAlgo = lb.Serv.KvHashAlgo
	}
	if lb.Serv.KvZmqPort != 0 {
		tmpSvc.KvZmqPort = int64(lb.Serv.KvZmqPort)
	}
	if lb.Serv.KvWarmupSec != 0 {
		tmpSvc.KvWarmupSec = int64(lb.Serv.KvWarmupSec)
	}
	// zero-suppressed — legacy rules round-trip with the
	// fields absent (swagger additive-only contract).
	if lb.Serv.KvEngineType != "" {
		tmpSvc.KvEngineType = lb.Serv.KvEngineType
	}
	if lb.Serv.KvDpRankCount != 0 {
		tmpSvc.KvDpRankCount = int32(lb.Serv.KvDpRankCount)
	}

	// CHWBL configuration (present when sel=8 CHWBL or sel=10 WRR_HASH)
	if lb.Serv.Sel == cmn.LbSelCHWBL || lb.Serv.Sel == cmn.LbSelWRRHash {
		if lb.Serv.CHWBLPrefixHashLevel != 0 {
			level := int64(lb.Serv.CHWBLPrefixHashLevel)
			tmpSvc.ChwblPrefixHashLevel = &level
		}
		if lb.Serv.CHWBLPrefixHashFlags != 0 {
			flags := int64(lb.Serv.CHWBLPrefixHashFlags)
			tmpSvc.ChwblPrefixHashFlags = &flags
		}
		if lb.Serv.CHWBLMeanLoadFactor != 0 {
			tmpSvc.ChwblMeanLoadFactor = int64(lb.Serv.CHWBLMeanLoadFactor)
		}
		if lb.Serv.CHWBLReplication != 0 {
			tmpSvc.ChwblReplication = int64(lb.Serv.CHWBLReplication)
		}
		if lb.Serv.CHWBLEnableCacheSalt {
			cacheSalt := true
			tmpSvc.ChwblEnableCacheSalt = &cacheSalt
		}
	}

	// mTLS Frontend Configuration
	if lb.Serv.MTLSFrontend != nil {
		clientCertMode := lb.Serv.MTLSFrontend.ClientCertMode
		requireClientCN := lb.Serv.MTLSFrontend.RequireClientCN
		mtlsFrontend := &models.LoadbalanceEntryServiceArgumentsMtlsFrontend{
			ClientCertMode:   &clientCertMode,
			ClientCaPath:     lb.Serv.MTLSFrontend.ClientCAPath,
			ClientCaCertData: lb.Serv.MTLSFrontend.ClientCACertData,
			RequireClientCn:  &requireClientCN,
			ClientCnPattern:  lb.Serv.MTLSFrontend.ClientCNPattern,
		}
		tmpSvc.MtlsFrontend = mtlsFrontend
	}

	// mTLS Backend Configuration
	if lb.Serv.MTLSBackend != nil {
		verifyServerCert := lb.Serv.MTLSBackend.VerifyServerCert
		mtlsBackend := &models.LoadbalanceEntryServiceArgumentsMtlsBackend{
			VerifyServerCert: &verifyServerCert,
			BackendCaPath:    lb.Serv.MTLSBackend.BackendCAPath,
			ClientCertPath:   lb.Serv.MTLSBackend.ClientCertPath,
			ClientKeyPath:    lb.Serv.MTLSBackend.ClientKeyPath,
			ClientCertData:   lb.Serv.MTLSBackend.ClientCertData,
			ClientKeyData:    lb.Serv.MTLSBackend.ClientKeyData,
		}
		tmpSvc.MtlsBackend = mtlsBackend
	}

	tmpLB.ServiceArguments = &tmpSvc

	for _, sip := range lb.SecIPs {
		tmpSIP := new(models.LoadbalanceEntrySecondaryIPsItems0)
		tmpSIP.SecondaryIP = sip.SecIP
		tmpLB.SecondaryIPs = append(tmpLB.SecondaryIPs, tmpSIP)
	}

	// Octavia /07: structured secondaryVIPs round-trip on every GET, ALONGSIDE
	// the flat secondaryIPs above (left untouched). Stored opaque for all protocols.
	// SecondaryVIPs / LoadbalanceEntrySecondaryVIPsItems0 are surfaced by go-swagger regen
	// (deferred to the remote/AWS gate; handler will not compile until then).
	for _, svip := range lb.SecVIPs {
		tmpSVIP := new(models.LoadbalanceEntrySecondaryVIPsItems0)
		tmpSVIP.Address = svip.Address
		tmpSVIP.SubnetID = svip.SubnetId
		tmpSVIP.PortID = svip.PortId
		tmpSVIP.Proto = svip.Proto
		tmpLB.SecondaryVIPs = append(tmpLB.SecondaryVIPs, tmpSVIP)
	}

	for _, src := range lb.SrcIPs {
		tmpSIP := new(models.LoadbalanceEntryAllowedSourcesItems0)
		tmpSIP.Prefix = src.Prefix
		tmpLB.AllowedSources = append(tmpLB.AllowedSources, tmpSIP)
	}

	// Endpoints match
	for _, ep := range lb.Eps {
		tmpEp := new(models.LoadbalanceEntryEndpointsItems0)
		tmpEp.EndpointIP = &ep.EpIP
		targetPort := int64(ep.EpPort)
		tmpEp.TargetPort = &targetPort
		weight := int64(ep.Weight)
		tmpEp.Weight = &weight
		tmpEp.State = ep.State
		tmpEp.Counter = ep.Counters
		if ep.EpRole != 0 {
			tmpEp.EpRole = int32(ep.EpRole)
		}
		if ep.NixlPort != 0 {
			tmpEp.NixlPort = int32(ep.NixlPort)
		}
		// round-trip the additive member fields. Backup/SubnetID/
		// MonitorAddress are surfaced by go-swagger regen (deferred to the remote/AWS gate).
		// wires backup/monitorAddress dataplane behavior; subnetId is round-trip only.
		epBackup := ep.Backup
		tmpEp.Backup = &epBackup
		tmpEp.SubnetID = ep.SubnetId
		tmpEp.MonitorAddress = ep.MonitorAddress
		tmpLB.Endpoints = append(tmpLB.Endpoints, tmpEp)
	}

	return &tmpLB
}

// resolveEffectiveAdminStateUp mirrors the control-plane resolveAdminStateUp back-compat
// rule in the handler layer: nil/absent AdminStateUp resolves to enabled (true); only an
// explicit false pauses the rule (Octavia).
func resolveEffectiveAdminStateUp(lb cmn.LbRuleMod) bool {
	return lb.Serv.AdminStateUp == nil || *lb.Serv.AdminStateUp
}

// deriveOperatingStatus aggregates per-endpoint State into the Octavia
// operatingStatus vocabulary: NO_MONITOR when health monitoring is off, ONLINE when
// all endpoints are up, OFFLINE when all are down, DEGRADED when some are down.
//
// a service whose EFFECTIVE adminStateUp is false is PAUSED — it
// forwards no new connections (the control plane drains the active backend set, Plan
// 72-04). A paused service therefore surfaces as OFFLINE regardless of endpoint
// health, because no backend is selectable for new traffic. Membership is intact (the
// endpoint list is unchanged); only the operating status reflects the pause.
func deriveOperatingStatus(lb cmn.LbRuleMod) string {
	if !resolveEffectiveAdminStateUp(lb) {
		return "OFFLINE"
	}
	if !lb.Serv.Monitor {
		return "NO_MONITOR"
	}
	if len(lb.Eps) == 0 {
		return "OFFLINE"
	}
	up, down := 0, 0
	for _, ep := range lb.Eps {
		// GetLBRule serializes a healthy endpoint State as "active"; an out-of-service
		// endpoint as "inactive".
		if ep.State == "active" {
			up++
		} else {
			down++
		}
	}
	switch {
	case down == 0:
		return "ONLINE"
	case up == 0:
		return "OFFLINE"
	default:
		return "DEGRADED"
	}
}

// findLBRuleByKey returns the rule matching the VIP/port/proto composite key, or nil.
// The ip path param is normalized with stripV6Brackets BEFORE the raw-string ServIP ==
// comparison (ServIP is stored UNBRACKETED, net.IP.String), so a bracketed IPv6 literal
// ("[2001:db8::1]") resolves the rule rather than 404ing. Centralizing the strip here covers
// every caller routed through findLBRuleByKey (GET-by-key, .../status, .../stats); DELETE
// handlers that build the rule key directly apply the strip at their own key-construction
// site. Idempotent for bare IPv4 (Trim is a no-op).
func findLBRuleByKey(ip string, port int64, proto string) (*cmn.LbRuleMod, error) {
	ip = stripV6Brackets(ip)
	res, err := ApiHooks.NetLbRuleGet()
	if err != nil {
		return nil, err
	}
	for i := range res {
		if res[i].Serv.ServIP == ip && int64(res[i].Serv.ServPort) == port && res[i].Serv.Proto == proto {
			return &res[i], nil
		}
	}
	return nil, nil
}

// findLBRuleByOpaqueID returns the rule carrying the opaque id, or nil.
func findLBRuleByOpaqueID(id string) (*cmn.LbRuleMod, error) {
	res, err := ApiHooks.NetLbRuleGet()
	if err != nil {
		return nil, err
	}
	for i := range res {
		if res[i].Serv.Id == id {
			return &res[i], nil
		}
	}
	return nil, nil
}

// ConfigGetLoadbalancerByKey - GET a single LB rule by its VIP/port/protocol
// composite key (Octavia).
func ConfigGetLoadbalancerByKey(params operations.GetConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	lb, err := findLBRuleByKey(params.IPAddress, int64(params.Port), params.Proto)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	if lb == nil {
		return operations.NewGetConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoNotFound()
	}
	return operations.NewGetConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoOK().WithPayload(serializeLBRule(*lb))
}

// ConfigGetLoadbalancerByID - GET a single LB rule by its stable opaque id
// (Octavia).
func ConfigGetLoadbalancerByID(params operations.GetConfigLoadbalancerIDParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	lb, err := findLBRuleByOpaqueID(params.ID)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	if lb == nil {
		return operations.NewGetConfigLoadbalancerIDNotFound()
	}
	return operations.NewGetConfigLoadbalancerIDOK().WithPayload(serializeLBRule(*lb))
}

// ConfigGetLoadbalancerStatus - GET per-LB lifecycle status
// {adminStateUp, operatingStatus, lastUpdated} for a rule by composite key
// (Octavia).
func ConfigGetLoadbalancerStatus(params operations.GetConfigLoadbalancerStatusParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	lb, err := findLBRuleByKey(params.IPAddress, int64(params.Port), params.Proto)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	if lb == nil {
		return operations.NewGetConfigLoadbalancerStatusNotFound()
	}

	adminStateUp := true
	if lb.Serv.AdminStateUp != nil {
		adminStateUp = *lb.Serv.AdminStateUp
	}

	// report the rule's ACTUAL in-memory last-mutation timestamp,
	// plumbed through GetNatLbRule -> LbServiceArg.LastUpdated (transient json:"-").
	// This is decoupled from the request time, so a client polling status twice with no
	// intervening mutation sees a STABLE lastUpdated (not a fresh "now" on every read).
	// If unset (zero value — a rule that has never been mutated since boot), fall back to
	// the request time so the field is always a valid RFC3339 value.
	lastUpdated := lb.Serv.LastUpdated
	if lastUpdated.IsZero() {
		lastUpdated = time.Now()
	}

	status := &models.LoadbalanceStatus{
		AdminStateUp:    adminStateUp,
		OperatingStatus: deriveOperatingStatus(*lb),
		LastUpdated:     strfmt.DateTime(lastUpdated.UTC()),
	}
	return operations.NewGetConfigLoadbalancerStatusOK().WithPayload(status)
}

// ConfigGetLoadbalancerStats - GET the per-service statistics quad
// {activeConnections, bytesIn, bytesOut, totalConnections} for a rule by its composite key
// (Octavia). Structural sibling of ConfigGetLoadbalancerStatus: it reuses
// findLBRuleByKey (no new internal lookup walk) and the id index, returns 404 on miss, and
// serializes a small typed payload on hit.
//
// The IPv6 path param is normalized with stripV6Brackets BEFORE the lookup so a bracketed
// IPv6 literal ("[2001:db8::1]") resolves the moment /stats ships (findLBRuleByKey compares
// against the UNBRACKETED ServIP). The four values come from the rule's in-memory counters
// (recomputed each RulesSync from the conntrack walk): activeConns is the SAME selector-
// agnostic live count the connectionLimit gate enforces; bytesIn/bytesOut are the
// real per-direction CT_DIR_IN/CT_DIR_OUT byte totals ((a)); totalConns is the
// monotonic cumulative counter.
func ConfigGetLoadbalancerStats(params operations.GetConfigLoadbalancerStatsParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	lb, err := findLBRuleByKey(stripV6Brackets(params.IPAddress), int64(params.Port), params.Proto)
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	if lb == nil {
		return operations.NewGetConfigLoadbalancerStatsNotFound()
	}

	stats := &models.LoadbalanceStats{
		ActiveConnections: lb.Serv.ActiveConns,
		BytesIn:           lb.Serv.BytesIn,
		BytesOut:          lb.Serv.BytesOut,
		TotalConnections:  lb.Serv.TotalConns,
	}
	return operations.NewGetConfigLoadbalancerStatsOK().WithPayload(stats)
}

func ConfigGetLoadbalancer(params operations.GetConfigLoadbalancerAllParams, principal interface{}) middleware.Responder {
	// Get LB rules
	tk.LogIt(tk.LogTrace, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	res, err := ApiHooks.NetLbRuleGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	var result []*models.LoadbalanceEntry
	result = make([]*models.LoadbalanceEntry, 0)
	for _, lb := range res {
		// optional ?projectId= convenience filter — when supplied,
		// skip rules whose projectId does not match. This is NOT a tenant-isolation/authz
		// boundary: an unfiltered GET (params.ProjectID nil) returns ALL rules regardless of
		// projectId. params.ProjectID *string is surfaced by go-swagger regen of the new /all
		// query parameter (deferred to the remote/AWS gate; handler will not compile until then).
		if params.ProjectID != nil && lb.Serv.ProjectId != *params.ProjectID {
			continue
		}
		result = append(result, serializeLBRule(lb))
	}
	return operations.NewGetConfigLoadbalancerAllOK().WithPayload(&operations.GetConfigLoadbalancerAllOKBody{LbAttr: result})
}

func ConfigDeleteAllLoadbalancer(params operations.DeleteConfigLoadbalancerAllParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	res, err := ApiHooks.NetLbRuleGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	for _, lbRules := range res {

		tk.LogIt(tk.LogDebug, "api: lbRules : %v\n", lbRules)
		_, err := ApiHooks.NetLbRuleDel(&lbRules)
		if err != nil {
			tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		}
	}

	return &ResultResponse{Result: "Success"}
}

func ConfigDeleteLoadbalancerByName(params operations.DeleteConfigLoadbalancerNameLbNameParams, principal interface{}) middleware.Responder {
	tk.LogIt(tk.LogDebug, "api: Load balancer %s API called. url : %s\n", params.HTTPRequest.Method, params.HTTPRequest.URL)

	res, err := ApiHooks.NetLbRuleGet()
	if err != nil {
		tk.LogIt(tk.LogDebug, "api: Error occur : %v\n", err)
		return &ErrorResponse{Payload: ResultErrorResponseErrorMessage(err.Error())}
	}
	for _, lbRules := range res {

		if lbRules.Serv.Name != params.LbName {
			continue
		}

		tk.LogIt(tk.LogDebug, "api: lbRules : %v\n", lbRules)
		_, err := ApiHooks.NetLbRuleDel(&lbRules)
		if err != nil {
			tk.LogIt(tk.LogDebug, "api: Error : %v\n", err)
		}
	}

	return &ResultResponse{Result: "Success"}
}
