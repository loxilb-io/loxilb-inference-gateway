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
package restapi

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"strings"

	opts "github.com/loxilb-io/loxilb/options"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"

	"github.com/loxilb-io/loxilb/api/apiutils/cors"
	"github.com/loxilb-io/loxilb/api/restapi/handler"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	"github.com/loxilb-io/loxilb/api/restapi/operations/ai"
	"github.com/loxilb-io/loxilb/api/restapi/operations/auth"
	"github.com/loxilb-io/loxilb/api/restapi/operations/l4_tracing"
	"github.com/loxilb-io/loxilb/api/restapi/operations/metadata"
	"github.com/loxilb-io/loxilb/api/restapi/operations/tracing"
	"github.com/loxilb-io/loxilb/api/restapi/operations/users"
)

// opaWatcherHandler stores the OPA watcher HTTP handler, set during configureAPI.
// Needed because setupGlobalMiddleware's "handler" parameter shadows the package import.
var opaWatcherHandler func(http.ResponseWriter, *http.Request)

// apiKeyPatchHandler stores the PATCH /config/ai/apikey/{key_id} handler.
// The keyID is extracted from the URL and passed as a 3rd argument.
var apiKeyPatchHandler func(http.ResponseWriter, *http.Request, string)

// dpuDebugHandler stores the DPU debug HTTP handler for /netlox/v1/config/dpu/debug.
var dpuDebugHandler func(http.ResponseWriter, *http.Request)

// dpuHwCountersHandler stores the DPU HW counters HTTP handler for /netlox/v1/config/dpu/hwcounters.
var dpuHwCountersHandler func(http.ResponseWriter, *http.Request)

// kvInventoryHandler stores the AI KV inventory HTTP handler for /netlox/v1/config/ai/kv/inventory.
var kvInventoryHandler func(http.ResponseWriter, *http.Request)

//go:generate swagger generate server --target ../../api --name LoxilbRestAPI --spec ../swagger.yml --principal interface{}

func configureFlags(api *operations.LoxilbRestAPIAPI) {
	api.CommandLineOptionsGroups = append(api.CommandLineOptionsGroups,
		swag.CommandLineOptionsGroup{
			Options: &opts.Opts,
		},
	)

}

func configureAPI(api *operations.LoxilbRestAPIAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()
	// Applies when the "Authorization" header is set
	api.BearerAuthAuth = handler.BearerAuthAuth
	// Set your custom authorizer if needed. Default one is security.Authorized
	api.APIAuthorizer = handler.Authorized()

	// Load balancer add and delete and get
	api.PostConfigLoadbalancerHandler = operations.PostConfigLoadbalancerHandlerFunc(handler.ConfigPostLoadbalancer)
	api.DeleteConfigLoadbalancerHosturlHosturlExternalipaddressIPAddressPortPortProtocolProtoHandler = operations.DeleteConfigLoadbalancerHosturlHosturlExternalipaddressIPAddressPortPortProtocolProtoHandlerFunc(handler.ConfigDeleteLoadbalancer)
	api.DeleteConfigLoadbalancerHosturlHosturlExternalipaddressIPAddressPortPortPortmaxPortmaxProtocolProtoHandler = operations.DeleteConfigLoadbalancerHosturlHosturlExternalipaddressIPAddressPortPortPortmaxPortmaxProtocolProtoHandlerFunc(handler.ConfigDeleteLoadbalancerPortRange)
	api.DeleteConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoHandler = operations.DeleteConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoHandlerFunc(handler.ConfigDeleteLoadbalancerWithoutPath)
	api.DeleteConfigLoadbalancerExternalipaddressIPAddressPortPortPortmaxPortmaxProtocolProtoHandler = operations.DeleteConfigLoadbalancerExternalipaddressIPAddressPortPortPortmaxPortmaxProtocolProtoHandlerFunc(handler.ConfigDeleteLoadbalancerPortRangeWithoutPath)
	api.GetConfigLoadbalancerAllHandler = operations.GetConfigLoadbalancerAllHandlerFunc(handler.ConfigGetLoadbalancer)
	api.DeleteConfigLoadbalancerAllHandler = operations.DeleteConfigLoadbalancerAllHandlerFunc(handler.ConfigDeleteAllLoadbalancer)
	api.DeleteConfigLoadbalancerNameLbNameHandler = operations.DeleteConfigLoadbalancerNameLbNameHandlerFunc(handler.ConfigDeleteLoadbalancerByName)
	// GET by composite key, GET by opaque id, GET status
	api.GetConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoHandler = operations.GetConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoHandlerFunc(handler.ConfigGetLoadbalancerByKey)
	api.GetConfigLoadbalancerIDHandler = operations.GetConfigLoadbalancerIDHandlerFunc(handler.ConfigGetLoadbalancerByID)
	api.GetConfigLoadbalancerStatusHandler = operations.GetConfigLoadbalancerStatusHandlerFunc(handler.ConfigGetLoadbalancerStatus)
	// per-service statistics quad {activeConnections, bytesIn, bytesOut, totalConnections} by composite key
	api.GetConfigLoadbalancerStatsHandler = operations.GetConfigLoadbalancerStatsHandlerFunc(handler.ConfigGetLoadbalancerStats)
	// PATCH (RFC 7386 JSON merge-patch) by composite key
	api.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoHandler = operations.PatchConfigLoadbalancerExternalipaddressIPAddressPortPortProtocolProtoHandlerFunc(handler.ConfigPatchLoadbalancer)

	// L7_POLICY content-routing resource (CRUD by opaque id, referencing the LB by its id)
	api.PostConfigL7PolicyHandler = operations.PostConfigL7PolicyHandlerFunc(handler.ConfigPostL7Policy)
	api.GetConfigL7PolicyAllHandler = operations.GetConfigL7PolicyAllHandlerFunc(handler.ConfigGetL7PolicyAll)
	api.GetConfigL7PolicyIDHandler = operations.GetConfigL7PolicyIDHandlerFunc(handler.ConfigGetL7PolicyByID)
	api.DeleteConfigL7PolicyIDHandler = operations.DeleteConfigL7PolicyIDHandlerFunc(handler.ConfigDeleteL7Policy)

	// certId TLS-material management — the canonical store
	// (upload/rotate/delete inline PEM by opaque certId; persists to the managed dir + drives
	// the C registry → SNI store). Wired at the l7policy registration site or the endpoints
	// are defined in swagger but unreachable.
	api.PostConfigCertHandler = operations.PostConfigCertHandlerFunc(handler.ConfigPostCert)
	api.PutConfigCertCertIDHandler = operations.PutConfigCertCertIDHandlerFunc(handler.ConfigPutCert)
	api.DeleteConfigCertCertIDHandler = operations.DeleteConfigCertCertIDHandlerFunc(handler.ConfigDeleteCert)
	api.GetConfigCertCertIDHandler = operations.GetConfigCertCertIDHandlerFunc(handler.ConfigGetCert)

	// SNI Certificate Management
	api.PostSniCertificatesHandler = operations.PostSniCertificatesHandlerFunc(handler.ConfigPostSNICertificate)
	api.DeleteSniCertificatesHandler = operations.DeleteSniCertificatesHandlerFunc(handler.ConfigDeleteSNICertificate)
	api.GetSniCertificatesHandler = operations.GetSniCertificatesHandlerFunc(handler.ConfigGetSNICertificates)

	// Conntrack get
	api.GetConfigConntrackAllHandler = operations.GetConfigConntrackAllHandlerFunc(handler.ConfigGetConntrack)

	// Port get
	api.GetConfigPortAllHandler = operations.GetConfigPortAllHandlerFunc(handler.ConfigGetPort)

	// route add and delete
	api.PostConfigRouteHandler = operations.PostConfigRouteHandlerFunc(handler.ConfigPostRoute)
	api.DeleteConfigRouteDestinationIPNetIPAddressMaskHandler = operations.DeleteConfigRouteDestinationIPNetIPAddressMaskHandlerFunc(handler.ConfigDeleteRoute)
	api.GetConfigRouteAllHandler = operations.GetConfigRouteAllHandlerFunc(handler.ConfigGetRoute)

	// Session, SessionUlCl Add and delete
	api.PostConfigSessionHandler = operations.PostConfigSessionHandlerFunc(handler.ConfigPostSession)
	api.PostConfigSessionulclHandler = operations.PostConfigSessionulclHandlerFunc(handler.ConfigPostSessionUlCl)
	api.DeleteConfigSessionIdentIdentHandler = operations.DeleteConfigSessionIdentIdentHandlerFunc(handler.ConfigDeleteSession)
	api.DeleteConfigSessionulclIdentIdentUlclAddressIPAddressHandler = operations.DeleteConfigSessionulclIdentIdentUlclAddressIPAddressHandlerFunc(handler.ConfigDeleteSessionUlCl)
	api.GetConfigSessionAllHandler = operations.GetConfigSessionAllHandlerFunc(handler.ConfigGetSession)
	api.GetConfigSessionulclAllHandler = operations.GetConfigSessionulclAllHandlerFunc(handler.ConfigGetSessionUlCl)

	// Policy Add, Delete and Get
	api.PostConfigPolicyHandler = operations.PostConfigPolicyHandlerFunc(handler.ConfigPostPolicy)
	api.DeleteConfigPolicyIdentIdentHandler = operations.DeleteConfigPolicyIdentIdentHandlerFunc(handler.ConfigDeletePolicy)
	api.GetConfigPolicyAllHandler = operations.GetConfigPolicyAllHandlerFunc(handler.ConfigGetPolicy)

	// IPv4 add And Delete
	api.PostConfigIpv4addressHandler = operations.PostConfigIpv4addressHandlerFunc(handler.ConfigPostIPv4Address)
	api.DeleteConfigIpv4addressIPAddressMaskDevIfNameHandler = operations.DeleteConfigIpv4addressIPAddressMaskDevIfNameHandlerFunc(handler.ConfigDeleteIPv4Address)
	api.GetConfigIpv4addressAllHandler = operations.GetConfigIpv4addressAllHandlerFunc(handler.ConfigGetIPv4Address)

	// IPv6 add And Delete (: 1:1 mirror of the IPv4 address surface)
	api.PostConfigIpv6addressHandler = operations.PostConfigIpv6addressHandlerFunc(handler.ConfigPostIPv6Address)
	api.DeleteConfigIpv6addressIPAddressMaskDevIfNameHandler = operations.DeleteConfigIpv6addressIPAddressMaskDevIfNameHandlerFunc(handler.ConfigDeleteIPv6Address)
	api.GetConfigIpv6addressAllHandler = operations.GetConfigIpv6addressAllHandlerFunc(handler.ConfigGetIPv6Address)

	// Mirror Add and Delete
	api.PostConfigMirrorHandler = operations.PostConfigMirrorHandlerFunc(handler.ConfigPostMirror)
	api.DeleteConfigMirrorIdentIdentHandler = operations.DeleteConfigMirrorIdentIdentHandlerFunc(handler.ConfigDeleteMirror)
	api.GetConfigMirrorAllHandler = operations.GetConfigMirrorAllHandlerFunc(handler.ConfigGetMirror)

	// Status
	api.GetStatusProcessHandler = operations.GetStatusProcessHandlerFunc(handler.ConfigGetProcess)
	api.GetStatusDeviceHandler = operations.GetStatusDeviceHandlerFunc(handler.ConfigGetDevice)
	api.GetStatusFilesystemHandler = operations.GetStatusFilesystemHandlerFunc(handler.ConfigGetFileSystem)

	// VLAN
	api.GetConfigVlanAllHandler = operations.GetConfigVlanAllHandlerFunc(handler.ConfigGetVLAN)
	api.PostConfigVlanHandler = operations.PostConfigVlanHandlerFunc(handler.ConfigPostVLAN)
	api.DeleteConfigVlanVlanIDHandler = operations.DeleteConfigVlanVlanIDHandlerFunc(handler.ConfigDeleteVLAN)

	// VLAN MEMBER
	api.PostConfigVlanVlanIDMemberHandler = operations.PostConfigVlanVlanIDMemberHandlerFunc(handler.ConfigPostVLANMember)
	api.DeleteConfigVlanVlanIDMemberIfNameTaggedTaggedHandler = operations.DeleteConfigVlanVlanIDMemberIfNameTaggedTaggedHandlerFunc(handler.ConfigDeleteVLANMember)

	// VxLAN
	api.GetConfigTunnelVxlanAllHandler = operations.GetConfigTunnelVxlanAllHandlerFunc(handler.ConfigGetVxLAN)
	api.PostConfigTunnelVxlanHandler = operations.PostConfigTunnelVxlanHandlerFunc(handler.ConfigPostVxLAN)
	api.DeleteConfigTunnelVxlanVxlanIDHandler = operations.DeleteConfigTunnelVxlanVxlanIDHandlerFunc(handler.ConfigDeleteVxLAN)

	//VxLAN Peer
	api.PostConfigTunnelVxlanVxlanIDPeerHandler = operations.PostConfigTunnelVxlanVxlanIDPeerHandlerFunc(handler.ConfigPostVxLANPeer)
	api.DeleteConfigTunnelVxlanVxlanIDPeerPeerIPHandler = operations.DeleteConfigTunnelVxlanVxlanIDPeerPeerIPHandlerFunc(handler.ConfigDeleteVxLANPeer)

	// Neighbor
	api.PostConfigNeighborHandler = operations.PostConfigNeighborHandlerFunc(handler.ConfigPostNeighbor)
	api.DeleteConfigNeighborIPAddressDevIfNameHandler = operations.DeleteConfigNeighborIPAddressDevIfNameHandlerFunc(handler.ConfigDeleteNeighbor)
	api.GetConfigNeighborAllHandler = operations.GetConfigNeighborAllHandlerFunc(handler.ConfigGetNeighbor)

	// FDB
	api.GetConfigFdbAllHandler = operations.GetConfigFdbAllHandlerFunc(handler.ConfigGetFDB)
	api.PostConfigFdbHandler = operations.PostConfigFdbHandlerFunc(handler.ConfigPostFDB)
	api.DeleteConfigFdbMacAddressDevIfNameHandler = operations.DeleteConfigFdbMacAddressDevIfNameHandlerFunc(handler.ConfigDeleteFDB)

	// Cluster Instance
	api.GetConfigCistateAllHandler = operations.GetConfigCistateAllHandlerFunc(handler.ConfigGetCIState)
	api.PostConfigCistateHandler = operations.PostConfigCistateHandlerFunc(handler.ConfigPostCIState)

	// BFD
	api.GetConfigBfdAllHandler = operations.GetConfigBfdAllHandlerFunc(handler.ConfigGetBFDSession)
	api.PostConfigBfdHandler = operations.PostConfigBfdHandlerFunc(handler.ConfigPostBFDSession)
	api.DeleteConfigBfdRemoteIPRemoteIPHandler = operations.DeleteConfigBfdRemoteIPRemoteIPHandlerFunc(handler.ConfigDeleteBFDSession)

	// Firewall
	api.GetConfigFirewallAllHandler = operations.GetConfigFirewallAllHandlerFunc(handler.ConfigGetFW)
	api.PostConfigFirewallHandler = operations.PostConfigFirewallHandlerFunc(handler.ConfigPostFW)
	api.DeleteConfigFirewallHandler = operations.DeleteConfigFirewallHandlerFunc(handler.ConfigDeleteFW)

	// OPA L4 Policy Watcher — wired via setupGlobalMiddleware path routing
	// (not swagger-generated; see HandleOPAWatcher in handler/opa_watcher.go)
	opaWatcherHandler = handler.HandleOPAWatcher
	apiKeyPatchHandler = handler.ConfigPatchAIApikey

	// DPU Debug — wired via setupGlobalMiddleware path routing
	// (not swagger-generated; see HandleDpuDebug in handler/dpu_debug.go)
	dpuDebugHandler = handler.HandleDpuDebug

	// DPU HW Counters — wired via setupGlobalMiddleware path routing
	// (not swagger-generated; see HandleDpuHwCounters in handler/dpu_hwcounters.go)
	dpuHwCountersHandler = handler.HandleDpuHwCounters

	// AI KV Inventory — wired via setupGlobalMiddleware path routing
	// (not swagger-generated; see HandleKvInventory in handler/ai_kv_inventory.go)
	kvInventoryHandler = handler.HandleKvInventory

	// IPsec - strongSwan API Integration
	api.GetConfigIpsecHandler = operations.GetConfigIpsecHandlerFunc(handler.ConfigGetIPsec)
	api.PostConfigIpsecHandler = operations.PostConfigIpsecHandlerFunc(handler.ConfigPostIPsec)
	api.GetConfigIpsecTunnelsAllHandler = operations.GetConfigIpsecTunnelsAllHandlerFunc(handler.ConfigGetIPsecTunnelsAll)
	api.PostConfigIpsecTunnelsHandler = operations.PostConfigIpsecTunnelsHandlerFunc(handler.ConfigPostIPsecTunnels)
	api.GetConfigIpsecTunnelsNameHandler = operations.GetConfigIpsecTunnelsNameHandlerFunc(handler.ConfigGetIPsecTunnelsName)
	api.PutConfigIpsecTunnelsNameHandler = operations.PutConfigIpsecTunnelsNameHandlerFunc(handler.ConfigPutIPsecTunnelsName)
	api.DeleteConfigIpsecTunnelsNameHandler = operations.DeleteConfigIpsecTunnelsNameHandlerFunc(handler.ConfigDeleteIPsecTunnelsName)
	api.PostConfigIpsecTunnelsNameActionHandler = operations.PostConfigIpsecTunnelsNameActionHandlerFunc(handler.ConfigPostIPsecTunnelsNameAction)
	api.GetConfigIpsecTunnelsNamePeerconfigHandler = operations.GetConfigIpsecTunnelsNamePeerconfigHandlerFunc(handler.ConfigGetIPsecTunnelsNamePeerconfig)
	api.GetConfigIpsecSasAllHandler = operations.GetConfigIpsecSasAllHandlerFunc(handler.ConfigGetIPsecSasAll)
	api.GetConfigIpsecStatsHandler = operations.GetConfigIpsecStatsHandlerFunc(handler.ConfigGetIPsecStats)
	api.DeleteConfigIpsecStatsHandler = operations.DeleteConfigIpsecStatsHandlerFunc(handler.ConfigDeleteIPsecStats)
	api.GetConfigIpsecCertificatesAllHandler = operations.GetConfigIpsecCertificatesAllHandlerFunc(handler.ConfigGetIPsecCertificatesAll)
	api.PostConfigIpsecCertificatesHandler = operations.PostConfigIpsecCertificatesHandlerFunc(handler.ConfigPostIPsecCertificates)
	api.GetConfigIpsecCertificatesNameHandler = operations.GetConfigIpsecCertificatesNameHandlerFunc(handler.ConfigGetIPsecCertificatesName)
	api.DeleteConfigIpsecCertificatesNameHandler = operations.DeleteConfigIpsecCertificatesNameHandlerFunc(handler.ConfigDeleteIPsecCertificatesName)
	api.PostConfigIpsecCertificatesValidateHandler = operations.PostConfigIpsecCertificatesValidateHandlerFunc(handler.ConfigPostIPsecCertificatesValidate)
	api.GetConfigIpsecCaCertificatesAllHandler = operations.GetConfigIpsecCaCertificatesAllHandlerFunc(handler.ConfigGetIPsecCaCertificatesAll)
	api.PostConfigIpsecCaCertificatesHandler = operations.PostConfigIpsecCaCertificatesHandlerFunc(handler.ConfigPostIPsecCaCertificates)
	api.GetConfigIpsecCaCertificatesNameHandler = operations.GetConfigIpsecCaCertificatesNameHandlerFunc(handler.ConfigGetIPsecCaCertificatesName)
	api.DeleteConfigIpsecCaCertificatesNameHandler = operations.DeleteConfigIpsecCaCertificatesNameHandlerFunc(handler.ConfigDeleteIPsecCaCertificatesName)

	// IP Filter (Whitelist/Blacklist)
	api.GetConfigIpfilterAllHandler = operations.GetConfigIpfilterAllHandlerFunc(handler.ConfigGetIPFilterAll)
	api.PostConfigIpfilterHandler = operations.PostConfigIpfilterHandlerFunc(handler.ConfigPostIPFilter)
	api.DeleteConfigIpfilterHandler = operations.DeleteConfigIpfilterHandlerFunc(handler.ConfigDeleteIPFilter)

	// Unified Security Rate Limiting (P0-5 + P0-6)
	api.GetConfigSecurityrateAllHandler = operations.GetConfigSecurityrateAllHandlerFunc(handler.ConfigGetSecurityRateAll)
	api.PostConfigSecurityrateHandler = operations.PostConfigSecurityrateHandlerFunc(handler.ConfigPostSecurityRate)
	api.DeleteConfigSecurityrateHandler = operations.DeleteConfigSecurityrateHandlerFunc(handler.ConfigDeleteSecurityRate)
	api.PutConfigSecurityrateResetHandler = operations.PutConfigSecurityrateResetHandlerFunc(handler.ConfigPutSecurityRateReset)

	// EndPoint
	api.GetConfigEndpointAllHandler = operations.GetConfigEndpointAllHandlerFunc(handler.ConfigGetEndPoint)
	api.PostConfigEndpointHandler = operations.PostConfigEndpointHandlerFunc(handler.ConfigPostEndPoint)
	api.DeleteConfigEndpointEpipaddressIPAddressHandler = operations.DeleteConfigEndpointEpipaddressIPAddressHandlerFunc(handler.ConfigDeleteEndPoint)
	api.PostConfigEndpointhoststateHandler = operations.PostConfigEndpointhoststateHandlerFunc(handler.ConfigPostEndPointHostState)

	// Params
	api.PostConfigParamsHandler = operations.PostConfigParamsHandlerFunc(handler.ConfigPostParams)
	api.GetConfigParamsHandler = operations.GetConfigParamsHandlerFunc(handler.ConfigGetParams)

	// Prometheus
	api.GetMetricsHandler = operations.GetMetricsHandlerFunc(handler.ConfigGetPrometheusCounter)
	api.GetConfigMetricsHandler = operations.GetConfigMetricsHandlerFunc(handler.ConfigGetPrometheusOption)
	api.PostConfigMetricsHandler = operations.PostConfigMetricsHandlerFunc(handler.ConfigPostPrometheus)
	api.DeleteConfigMetricsHandler = operations.DeleteConfigMetricsHandlerFunc(handler.ConfigDeletePrometheus)

	// HTTP/HTTPS Protocol Analyzer (Distributed Tracing)
	api.TracingPostConfigTraceEnableHandler = tracing.PostConfigTraceEnableHandlerFunc(handler.ConfigEnableTrace)
	api.TracingPostConfigTraceDisableHandler = tracing.PostConfigTraceDisableHandlerFunc(handler.ConfigDisableTrace)
	api.TracingGetConfigTraceStatusHandler = tracing.GetConfigTraceStatusHandlerFunc(handler.ConfigGetTraceStatus)
	api.TracingPostConfigTraceOtlpHandler = tracing.PostConfigTraceOtlpHandlerFunc(handler.ConfigSetOtlpEndpoint)
	api.TracingGetConfigTraceOtlpHandler = tracing.GetConfigTraceOtlpHandlerFunc(handler.ConfigGetOtlpEndpoint)

	// L4 Connection Tracing (TCP/SCTP)
	api.L4TracingPostConfigL4traceEnableHandler = l4_tracing.PostConfigL4traceEnableHandlerFunc(handler.ConfigEnableL4Trace)
	api.L4TracingPostConfigL4traceDisableHandler = l4_tracing.PostConfigL4traceDisableHandlerFunc(handler.ConfigDisableL4Trace)
	api.L4TracingGetConfigL4traceStatusHandler = l4_tracing.GetConfigL4traceStatusHandlerFunc(handler.ConfigGetL4TraceStatus)
	api.L4TracingPutConfigL4traceSamplingHandler = l4_tracing.PutConfigL4traceSamplingHandlerFunc(handler.ConfigUpdateL4TraceSampling)
	api.L4TracingPostConfigL4traceStatsResetHandler = l4_tracing.PostConfigL4traceStatsResetHandlerFunc(handler.ConfigResetL4TraceStats)

	// GPU-Aware Load Balancing
	api.PostConfigGpuEnableHandler = operations.PostConfigGpuEnableHandlerFunc(handler.ConfigPostGPUEnable)
	api.PostConfigGpuDisableHandler = operations.PostConfigGpuDisableHandlerFunc(handler.ConfigPostGPUDisable)
	api.GetConfigGpuStatusHandler = operations.GetConfigGpuStatusHandlerFunc(handler.ConfigGetGPUStatus)
	api.PostConfigGpuConversationsCleanupHandler = operations.PostConfigGpuConversationsCleanupHandlerFunc(handler.ConfigPostConfigGPUConversationsCleanup)
	api.PostConfigWorkerMetricsHandler = operations.PostConfigWorkerMetricsHandlerFunc(handler.ConfigPostConfigWorkerMetrics)
	api.GetConfigWorkerMetricsHandler = operations.GetConfigWorkerMetricsHandlerFunc(handler.ConfigGetConfigWorkerMetrics)

	// Trace Parser Management (Dynamic parser configuration)
	api.TracingGetTraceParsersHandler = tracing.GetTraceParsersHandlerFunc(handler.ConfigGetTraceParsers)
	api.TracingGetCatalogParserHandler = tracing.GetCatalogParserHandlerFunc(handler.ConfigGetCatalogParser)
	api.TracingUpdateCatalogParserHandler = tracing.UpdateCatalogParserHandlerFunc(handler.ConfigUpdateCatalogParser)
	api.TracingDeleteCatalogParserHandler = tracing.DeleteCatalogParserHandlerFunc(handler.ConfigDeleteCatalogParser)

	// PII Detection (Presidio Integration)
	api.PostConfigPiiEnableHandler = operations.PostConfigPiiEnableHandlerFunc(handler.ConfigPostPIIEnable)
	api.PostConfigPiiConfigureHandler = operations.PostConfigPiiConfigureHandlerFunc(handler.ConfigPostPIIConfigure)
	api.PostConfigPiiURLPatternsHandler = operations.PostConfigPiiURLPatternsHandlerFunc(handler.ConfigPostPIIURLPatterns)
	api.GetConfigPiiStatusHandler = operations.GetConfigPiiStatusHandlerFunc(handler.ConfigGetPIIStatus)
	api.GetConfigPiiStatsHandler = operations.GetConfigPiiStatsHandlerFunc(handler.ConfigGetPIIStats)

	// LlamaFirewall AI Security (AI Security Scanner Integration)
	api.PostConfigLlamafirewallEnableHandler = operations.PostConfigLlamafirewallEnableHandlerFunc(handler.ConfigPostLlamaFirewallEnable)
	api.PostConfigLlamafirewallConfigureHandler = operations.PostConfigLlamafirewallConfigureHandlerFunc(handler.ConfigPostLlamaFirewallConfigure)
	api.PostConfigLlamafirewallScannersHandler = operations.PostConfigLlamafirewallScannersHandlerFunc(handler.ConfigPostLlamaFirewallScanners)
	api.GetConfigLlamafirewallStatusHandler = operations.GetConfigLlamafirewallStatusHandlerFunc(handler.ConfigGetLlamaFirewallStatus)
	api.GetConfigLlamafirewallStatsHandler = operations.GetConfigLlamafirewallStatsHandlerFunc(handler.ConfigGetLlamaFirewallStats)
	api.PostConfigLlamafirewallHealthHandler = operations.PostConfigLlamafirewallHealthHandlerFunc(handler.ConfigPostLlamaFirewallHealth)

	// BGP Peer
	api.GetConfigBgpNeighAllHandler = operations.GetConfigBgpNeighAllHandlerFunc(handler.ConfigGetBGPNeigh)
	api.PostConfigBgpGlobalHandler = operations.PostConfigBgpGlobalHandlerFunc(handler.ConfigPostBGPGlobal)
	api.PostConfigBgpNeighHandler = operations.PostConfigBgpNeighHandlerFunc(handler.ConfigPostBGPNeigh)
	api.DeleteConfigBgpNeighIPAddressHandler = operations.DeleteConfigBgpNeighIPAddressHandlerFunc(handler.ConfigDeleteBGPNeigh)

	// BGP Policy Defined set
	api.GetConfigBgpPolicyDefinedsetsDefinesetTypeTypeNameHandler = operations.GetConfigBgpPolicyDefinedsetsDefinesetTypeTypeNameHandlerFunc(handler.ConfigGetBGPPolicyDefinedSetGet)
	api.PostConfigBgpPolicyDefinedsetsDefinesetTypeHandler = operations.PostConfigBgpPolicyDefinedsetsDefinesetTypeHandlerFunc(handler.ConfigPostBGPPolicyDefinedsets)
	api.DeleteConfigBgpPolicyDefinedsetsDefinesetTypeTypeNameHandler = operations.DeleteConfigBgpPolicyDefinedsetsDefinesetTypeTypeNameHandlerFunc(handler.ConfigDeleteBGPPolicyDefinedsets)

	// BGP Policy Definitions
	api.PostConfigBgpPolicyDefinitionsHandler = operations.PostConfigBgpPolicyDefinitionsHandlerFunc(handler.ConfigPostBGPPolicyDefinitions)
	api.DeleteConfigBgpPolicyDefinitionsPolicyNameHandler = operations.DeleteConfigBgpPolicyDefinitionsPolicyNameHandlerFunc(handler.ConfigDeleteBGPPolicyDefinitions)
	api.GetConfigBgpPolicyDefinitionsAllHandler = operations.GetConfigBgpPolicyDefinitionsAllHandlerFunc(handler.ConfigGetBGPPolicyDefinitions)

	// BGP Policy Apply
	api.PostConfigBgpPolicyApplyHandler = operations.PostConfigBgpPolicyApplyHandlerFunc(handler.ConfigPostBGPPolicyApply)
	api.DeleteConfigBgpPolicyApplyHandler = operations.DeleteConfigBgpPolicyApplyHandlerFunc(handler.ConfigDeleteBGPPolicyApply)

	// Metrics
	api.GetMetricsFlowcountHandler = operations.GetMetricsFlowcountHandlerFunc(handler.ConfigGetFlowCount)
	api.GetMetricsLbrulecountHandler = operations.GetMetricsLbrulecountHandlerFunc(handler.ConfigGetLbRuleCount)
	api.GetMetricsNewflowcountHandler = operations.GetMetricsNewflowcountHandlerFunc(handler.ConfigGetNewFlowCount)
	api.GetMetricsRequestcountHandler = operations.GetMetricsRequestcountHandlerFunc(handler.ConfigGetRequestCount)
	api.GetMetricsErrorcountHandler = operations.GetMetricsErrorcountHandlerFunc(handler.ConfigGetErrorCount)
	api.GetMetricsProcessedtrafficHandler = operations.GetMetricsProcessedtrafficHandlerFunc(handler.ConfigGetProcessedTraffic)
	api.GetMetricsLbprocessedtrafficHandler = operations.GetMetricsLbprocessedtrafficHandlerFunc(handler.ConfigGetLbProcessedTraffic)
	api.GetMetricsEpdisttrafficHandler = operations.GetMetricsEpdisttrafficHandlerFunc(handler.ConfigGetEpDistTraffic)
	api.GetMetricsServicedisttrafficHandler = operations.GetMetricsServicedisttrafficHandlerFunc(handler.ConfigGetServiceDistTraffic)
	api.GetMetricsFwdropsHandler = operations.GetMetricsFwdropsHandlerFunc(handler.ConfigGetFwDrops)
	api.GetMetricsReqcountperclientHandler = operations.GetMetricsReqcountperclientHandlerFunc(handler.ConfigGetReqCounterPerClient)
	api.GetMetricsHostcountHandler = operations.GetMetricsHostcountHandlerFunc(handler.ConfigGetHostCount)

	// Log
	api.GetLogsHandler = operations.GetLogsHandlerFunc(handler.ConfigGetLogs)
	api.GetLogArchivesHandler = operations.GetLogArchivesHandlerFunc(handler.ConfigGetLogArchives)
	api.GetLogArchivesFilenameHandler = operations.GetLogArchivesFilenameHandlerFunc(handler.ConfigGetLogArchivesFilename)

	// Version
	api.GetVersionHandler = operations.GetVersionHandlerFunc(handler.ConfigGetVersion)

	// metadata
	api.MetadataGetMetaHandler = metadata.GetMetaHandlerFunc(handler.ConfigGetMetadata)
	api.AuthPostAuthTokenUpgradeHandler = auth.PostAuthTokenUpgradeHandlerFunc(handler.AuthPostManualTokenUpdate)

	// It works only if the UserServiceEnable option is enabled.
	if opts.Opts.UserServiceEnable {
		// Authentication API
		api.AuthPostAuthLoginHandler = auth.PostAuthLoginHandlerFunc(handler.AuthPostLogin)
		api.AuthPostAuthLogoutHandler = auth.PostAuthLogoutHandlerFunc(handler.AuthPostLogout)

		// Users API
		api.UsersGetAuthUsersHandler = users.GetAuthUsersHandlerFunc(handler.UsersGetUsers)
		api.UsersPostAuthUsersHandler = users.PostAuthUsersHandlerFunc(handler.UsersPostUsers)
		api.UsersDeleteAuthUsersIDHandler = users.DeleteAuthUsersIDHandlerFunc(handler.UsersDeleteUsers)
		api.UsersPutAuthUsersIDHandler = users.PutAuthUsersIDHandlerFunc(handler.UsersPutUsers)

		// AI Gateway - API key lifecycle management
		api.AiPostConfigAiApikeyHandler = ai.PostConfigAiApikeyHandlerFunc(handler.ConfigPostAIApikey)
		api.AiGetConfigAiApikeyHandler = ai.GetConfigAiApikeyHandlerFunc(handler.ConfigGetAIApikeys)
		api.AiGetConfigAiApikeyKeyIDHandler = ai.GetConfigAiApikeyKeyIDHandlerFunc(handler.ConfigGetAIApikeyByID)
		api.AiDeleteConfigAiApikeyKeyIDHandler = ai.DeleteConfigAiApikeyKeyIDHandlerFunc(handler.ConfigDeleteAIApikey)
		api.AiPostConfigAiTenantRatelimitHandler = ai.PostConfigAiTenantRatelimitHandlerFunc(handler.ConfigPostAITenantRateLimit)
		api.AiGetConfigAiTenantRatelimitTenantIDHandler = ai.GetConfigAiTenantRatelimitTenantIDHandlerFunc(handler.ConfigGetAITenantRateLimit)
	}

	if opts.Opts.Oauth2Enable {
		// OAuth2 API
		handler.InitOAuthConfigs()
		api.AuthGetOauthProviderHandler = auth.GetOauthProviderHandlerFunc(handler.AuthGetOauthProvider)
		api.AuthGetOauthProviderCallbackHandler = auth.GetOauthProviderCallbackHandlerFunc(handler.AuthGetOauthProviderCallback)
		api.AuthGetOauthProviderTokenHandler = auth.GetOauthProviderTokenHandlerFunc(handler.RefreshTokenHandler)
	}
	// CORS configuration
	api.GetConfigCorsAllHandler = operations.GetConfigCorsAllHandlerFunc(handler.ConfigGetCors)
	api.PostConfigCorsHandler = operations.PostConfigCorsHandlerFunc(handler.ConfigPostCors)
	api.DeleteConfigCorsCorsURLHandler = operations.DeleteConfigCorsCorsURLHandlerFunc(handler.ConfigDeleteCors)

	// Configuration import and export
	api.GetConfigExportHandler = operations.GetConfigExportHandlerFunc(handler.ConfigGetExport)
	api.PostConfigImportHandler = operations.PostConfigImportHandlerFunc(handler.ConfigPostImport)

	// Instance snapshot & restore (replaces export/import; see docs/SNAPSHOT-DESIGN.md §5)
	api.GetConfigSnapshotHandler = operations.GetConfigSnapshotHandlerFunc(handler.ConfigGetSnapshot)
	api.PostConfigRestoreHandler = operations.PostConfigRestoreHandlerFunc(handler.ConfigPostRestore)

	// Persistence convergence (§6.1): explicit save-as-an-API plus the
	// debounced auto-persist that keeps snapshot.json current.
	api.PostConfigPersistHandler = operations.PostConfigPersistHandlerFunc(handler.ConfigPostPersist)
	handler.InitAutoPersist()

	api.PreServerShutdown = func() {}
	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix".
func configureServer(s *http.Server, scheme, addr string) {
}

// SIGINT ownership convention.
//
// The "Server already shutting down" guard at api/restapi/server.go:495 is
// in go-swagger generated code (regenerated by `swagger generate server`).
// We do NOT patch it.
//
// Convention: loxinet (pkg/loxinet/loxinet.go) owns the SIGINT/SIGTERM
// escalation path. signal.Notify(mh.sigCh, ...) is registered BEFORE
// apiserver.RunAPIServer so loxinet's channel is in the broadcast set
// when the apiserver later registers its own internal signalNotify.
// Both handlers race on each signal delivery; on the SECOND signal,
// loxinet's atomic Swap(true) takes the escalation path and runs
// os.Exit(1) BEFORE the apiserver's "already shutting down" guard can
// swallow the request. The apiserver's internal handleInterrupt is
// allowed to fire as a no-op afterward — by then loxinet has already
// exited.
//
// IsInterruptOwnerLoxinet is a semantic marker used by runbooks and
// CICD assertions to confirm the convention is in place. Always returns
// true; flipping this to false in code review is a sign someone is
// trying to install the apiserver as the SIGINT owner instead, which
// would re-introduce the EVIDENCE wedge.
func IsInterruptOwnerLoxinet() bool {
	return true
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation.
func setupMiddlewares(handler http.Handler) http.Handler {
	// Kick the §6.1 auto-persist debouncer on successful mutating config
	// calls (innermost, so it sees the real response status), then freeze
	// mutating calls while a snapshot restore is in progress (§5.3 stages
	// 4-7 must not interleave with other config writes).
	frozen := snapshotFreeze(autoPersistKick(handler))
	// User service is disabled, so we need to set a valid token for the Authorization header.
	if !opts.Opts.UserServiceEnable {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set a any token for the Authorization header.
			if r.Header.Get("Authorization") == "" {
				r.Header.Set("Authorization", "valid")
			}
			frozen.ServeHTTP(w, r)
		})
	}
	return frozen
}

// CORS adds Cross-Origin Resource Sharing headers to responses
func corsCheck(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedOrigins := cors.GetCORSManager().GetOrigin()
		// Set CORS headers
		origin := r.Header.Get("Origin")
		if allowedOrigins["*"] {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		// Handle preflight OPTIONS requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Pass request to the next handler
		handler.ServeHTTP(w, r)
	})
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics.
//
// withRawPatchBody aliases handler.WithRawPatchBody at package scope. Inside
// setupGlobalMiddleware the `handler` parameter shadows the handler package
// import, so the package function must be referenced through this alias.
var withRawPatchBody = handler.WithRawPatchBody

// snapshotFreeze aliases handler.SnapshotFreezeMiddleware for the same
// shadowing reason.
var snapshotFreeze = handler.SnapshotFreezeMiddleware

// autoPersistKick aliases handler.AutoPersistMiddleware for the same
// shadowing reason.
var autoPersistKick = handler.AutoPersistMiddleware

func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedOrigins := cors.GetCORSManager().GetOrigin()
		// Set CORS headers
		origin := r.Header.Get("Origin")

		// Handle CORS origin header with development-friendly defaults
		if allowedOrigins != nil && len(allowedOrigins) > 0 {
			if allowedOrigins["*"] {
				// Allow all origins with wildcard
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else if origin != "" && allowedOrigins[origin] {
				// Allow specific origin if it's in the allowed list
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else {
				// For development: allow any origin that's not explicitly configured
				// To disable this behavior for production, set specific origins or "*" in CORS config
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
		} else {
			// Default behavior when no CORS configuration exists: allow all (development mode)
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
		}

		// Always set these headers regardless of origin status
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin, Cache-Control")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		w.Header().Set("Vary", "Origin")                  // Important for proper caching with different origins

		// Handle preflight OPTIONS requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return // Important: return here to prevent further processing
		}

		// capture the raw PATCH merge-patch body so the generated
		// ConfigPatchLoadbalancer handler can do RFC 7386 presence detection
		// (map[string]json.RawMessage) — distinguishing an absent field from a zero
		// value. go-swagger's body bind drains r.Body, so we
		// tee it here and stash the bytes in the request context, then re-attach a fresh
		// reader for the generated consumer. Scoped to PATCH on the LB composite-key path.
		if r.Method == http.MethodPatch &&
			strings.HasPrefix(r.URL.Path, "/netlox/v1/config/loadbalancer/externalipaddress/") &&
			r.Body != nil {
			if raw, err := io.ReadAll(r.Body); err == nil {
				r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(raw))
				r = r.WithContext(withRawPatchBody(r.Context(), raw))
			}
		}

		// OPA L4 Policy Watcher endpoint (not swagger-generated)
		if r.URL.Path == "/netlox/v1/config/opa/watcher" && opaWatcherHandler != nil {
			opaWatcherHandler(w, r)
			return
		}

		// DPU HW Counters endpoint (not swagger-generated)
		if r.URL.Path == "/netlox/v1/config/dpu/hwcounters" && dpuHwCountersHandler != nil {
			dpuHwCountersHandler(w, r)
			return
		}

		// DPU Debug endpoint (not swagger-generated)
		if r.URL.Path == "/netlox/v1/config/dpu/debug" && dpuDebugHandler != nil {
			dpuDebugHandler(w, r)
			return
		}

		// AI KV Inventory endpoint (not swagger-generated)
		if r.URL.Path == "/netlox/v1/config/ai/kv/inventory" && kvInventoryHandler != nil {
			kvInventoryHandler(w, r)
			return
		}

		// PATCH /config/ai/apikey/{key_id} — not swagger-generated (PB-2 fix)
		if strings.HasPrefix(r.URL.Path, "/netlox/v1/config/ai/apikey/") && r.Method == http.MethodPatch {
			keyID := strings.TrimPrefix(r.URL.Path, "/netlox/v1/config/ai/apikey/")
			apiKeyPatchHandler(w, r, keyID)
			return
		}

		// Delegate to the main handler for all other requests
		handler.ServeHTTP(w, r)
	})
}
