package loxilog

// Error code constants organized by subsystem band.
// Each subsystem occupies a 1000-wide band with explicit numeric values (no iota).
// Codes are globally unique across the entire LoxiLB codebase.

// Network error codes: 1000-1099
const (
	ErrNatPoolExhausted    = 1001
	ErrBackendUnreachable  = 1002
	ErrRuleConflict        = 1003
	ErrSessionPersistFail  = 1004
	ErrEndpointNotFound    = 1005
	ErrPortRangeExhausted  = 1006
	ErrVIPConflict         = 1007
	ErrHealthCheckFail     = 1008
	ErrLBRuleLimit         = 1009
	ErrBackendWeightInvald = 1010
	ErrProxyInitFail       = 1011
	ErrDNSResolveFail      = 1012
	ErrQOSPolicyFail       = 1013
	ErrMirrorRuleFail      = 1014
)

// Cluster error codes: 2000-2099
const (
	ErrHAFailover       = 2001
	ErrClusterSplit     = 2002
	ErrStateSync        = 2003
	ErrLeaderElection   = 2004
	ErrPeerUnreachable  = 2005
	ErrBFDSessionDown   = 2006
	ErrKeepaliveTimeout = 2007
	ErrClusterNodeJoin  = 2008
	ErrClusterNodeLeave = 2009
	ErrGRPCSyncFail     = 2010
	ErrBGPPeerDown      = 2011
	ErrBGPRouteWithdraw = 2012
)

// Auth error codes: 3000-3099
const (
	ErrTokenExpired       = 3001
	ErrUnauthorized       = 3002
	ErrInvalidCredentials = 3003
	ErrOAuth2Fail         = 3004
	ErrSessionExpired     = 3005
	ErrAPIKeyInvalid      = 3006
	ErrAPIKeyRevoked      = 3007
	ErrTLSHandshakeFail   = 3008
	ErrCertNotFound       = 3009
	ErrCertExpired        = 3010
	ErrTokenGenerateFail  = 3011
	ErrDBAuthFail         = 3012
)

// Dataplane error codes: 4000-4099
const (
	ErrEBPFLoadFailed    = 4001
	ErrMapUpdateFailed   = 4002
	ErrMapDeleteFailed   = 4003
	ErrMapLookupFailed   = 4004
	ErrConntrackOverflow = 4005
	ErrRingBufferFull    = 4006
	ErrBPFVerifierReject = 4007
	ErrPinFailed         = 4008
	ErrXDPAttachFail     = 4009
	ErrTCAttachFail      = 4010
	ErrFDBUpdateFail     = 4011
	ErrNeighUpdateFail   = 4012
	ErrRouteUpdateFail   = 4013
	ErrVlanConfigFail    = 4014
	ErrBondConfigFail    = 4015
)

// AI Gateway error codes: 5000-5099
const (
	ErrModelNotFound    = 5001
	ErrQuotaExceeded    = 5002
	ErrPrefillFailed    = 5003
	ErrDecodeFailed     = 5004
	ErrSSEStreamFail    = 5005
	ErrAIBackendUnhlthy = 5006
	ErrAICatalogConflct = 5007
	ErrAPIKeyRateLimit  = 5008
	ErrTenantRateLimit  = 5009
	ErrKVTransferFail   = 5010
	ErrPDRebalanceFail  = 5011
	ErrRequestIDGenFail = 5012
	ErrJSONRewriteFail  = 5013
	ErrAIRouteNotFound  = 5014
	ErrTokenCountFail   = 5015
)

// System error codes: 6000-6099
const (
	ErrCertExpiry      = 6001
	ErrConfigInvalid   = 6002
	ErrInitFailed      = 6003
	ErrShutdownTimeout = 6004
	ErrFileWriteFail   = 6005
	ErrLogRotateFail   = 6006
	ErrPrometheusRegFl = 6007
	ErrSignalReceived  = 6008
	ErrResourceExhstd  = 6009
	ErrDiskSpaceLow    = 6010
	ErrNetlinkFail     = 6011
	ErrSysctlFail      = 6012
)
