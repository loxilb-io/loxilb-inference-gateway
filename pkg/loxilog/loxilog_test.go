package loxilog

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// --- ECS Field Constants Tests ---

func TestECSFields(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"ECSVersion", FieldECSVersion, "ecs.version"},
		{"EventAction", FieldEventAction, "event.action"},
		{"EventOutcome", FieldEventOutcome, "event.outcome"},
		{"EventCategory", FieldEventCategory, "event.category"},
		{"EventType", FieldEventType, "event.type"},
		{"EventReason", FieldEventReason, "event.reason"},
		{"EventSeverity", FieldEventSeverity, "event.severity"},
		{"Component", FieldComponent, "service.component"},
		{"ErrCode", FieldErrCode, "error.code"},
		{"LogLogger", FieldLogLogger, "log.logger"},
		{"TraceID", FieldTraceID, "trace.id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("got %q, want %q", tt.constant, tt.expected)
			}
		})
	}
}

func TestECSOutcomeValues(t *testing.T) {
	if OutcomeSuccess != "success" {
		t.Errorf("OutcomeSuccess = %q, want %q", OutcomeSuccess, "success")
	}
	if OutcomeFailure != "failure" {
		t.Errorf("OutcomeFailure = %q, want %q", OutcomeFailure, "failure")
	}
	if OutcomeUnknown != "unknown" {
		t.Errorf("OutcomeUnknown = %q, want %q", OutcomeUnknown, "unknown")
	}
}

// --- Category Level Tests ---

func TestCategoryEnumValues(t *testing.T) {
	if CatNetwork != 0 {
		t.Errorf("CatNetwork = %d, want 0", CatNetwork)
	}
	if CatAuth != 1 {
		t.Errorf("CatAuth = %d, want 1", CatAuth)
	}
	if CatCluster != 2 {
		t.Errorf("CatCluster = %d, want 2", CatCluster)
	}
	if CatDataplane != 3 {
		t.Errorf("CatDataplane = %d, want 3", CatDataplane)
	}
	if CatAI != 4 {
		t.Errorf("CatAI = %d, want 4", CatAI)
	}
	if CatSystem != 5 {
		t.Errorf("CatSystem = %d, want 5", CatSystem)
	}
	if catCount != 6 {
		t.Errorf("catCount = %d, want 6", catCount)
	}
}

func TestCategoryLevelDefaultIsDebug(t *testing.T) {
	for i := Category(0); i < catCount; i++ {
		level := GetCategoryLevel(i)
		if level != zerolog.DebugLevel {
			t.Errorf("default level for category %d = %v, want DebugLevel", i, level)
		}
	}
}

func TestSetGetCategoryLevel(t *testing.T) {
	// Save original and restore after test
	origLevels := make([]zerolog.Level, catCount)
	for i := Category(0); i < catCount; i++ {
		origLevels[i] = GetCategoryLevel(i)
	}
	defer func() {
		for i := Category(0); i < catCount; i++ {
			SetCategoryLevel(i, origLevels[i])
		}
	}()

	tests := []struct {
		cat   Category
		level zerolog.Level
	}{
		{CatNetwork, zerolog.WarnLevel},
		{CatAuth, zerolog.ErrorLevel},
		{CatCluster, zerolog.InfoLevel},
		{CatDataplane, zerolog.TraceLevel},
		{CatAI, zerolog.FatalLevel},
		{CatSystem, zerolog.DebugLevel},
	}

	for _, tt := range tests {
		SetCategoryLevel(tt.cat, tt.level)
		got := GetCategoryLevel(tt.cat)
		if got != tt.level {
			t.Errorf("category %d: got level %v, want %v", tt.cat, got, tt.level)
		}
	}
}

func TestCategoryFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected Category
		ok       bool
	}{
		{"network", CatNetwork, true},
		{"auth", CatAuth, true},
		{"cluster", CatCluster, true},
		{"dataplane", CatDataplane, true},
		{"ai", CatAI, true},
		{"system", CatSystem, true},
		{"NETWORK", CatNetwork, true},
		{"unknown", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		cat, ok := CategoryFromString(tt.input)
		if ok != tt.ok {
			t.Errorf("CategoryFromString(%q): ok = %v, want %v", tt.input, ok, tt.ok)
		}
		if ok && cat != tt.expected {
			t.Errorf("CategoryFromString(%q) = %d, want %d", tt.input, cat, tt.expected)
		}
	}
}

func TestCategoryName(t *testing.T) {
	if CategoryName(CatNetwork) != "network" {
		t.Errorf("CategoryName(CatNetwork) = %q, want %q", CategoryName(CatNetwork), "network")
	}
	if CategoryName(CatAI) != "ai" {
		t.Errorf("CategoryName(CatAI) = %q, want %q", CategoryName(CatAI), "ai")
	}
	if CategoryName(Category(99)) != "unknown" {
		t.Errorf("CategoryName(99) = %q, want %q", CategoryName(Category(99)), "unknown")
	}
}

// --- Error Code Constants Tests ---

func TestErrorCodeBands(t *testing.T) {
	// Network: 1000-1099
	networkCodes := []int{
		ErrNatPoolExhausted, ErrBackendUnreachable, ErrRuleConflict,
		ErrSessionPersistFail, ErrEndpointNotFound, ErrPortRangeExhausted,
		ErrVIPConflict, ErrHealthCheckFail, ErrLBRuleLimit,
		ErrBackendWeightInvald, ErrProxyInitFail, ErrDNSResolveFail,
		ErrQOSPolicyFail, ErrMirrorRuleFail,
	}
	for _, code := range networkCodes {
		if code < 1000 || code > 1099 {
			t.Errorf("network code %d outside band 1000-1099", code)
		}
	}

	// Cluster: 2000-2099
	clusterCodes := []int{
		ErrHAFailover, ErrClusterSplit, ErrStateSync,
		ErrLeaderElection, ErrPeerUnreachable, ErrBFDSessionDown,
		ErrKeepaliveTimeout, ErrClusterNodeJoin, ErrClusterNodeLeave,
		ErrGRPCSyncFail, ErrBGPPeerDown, ErrBGPRouteWithdraw,
	}
	for _, code := range clusterCodes {
		if code < 2000 || code > 2099 {
			t.Errorf("cluster code %d outside band 2000-2099", code)
		}
	}

	// Auth: 3000-3099
	authCodes := []int{
		ErrTokenExpired, ErrUnauthorized, ErrInvalidCredentials,
		ErrOAuth2Fail, ErrSessionExpired, ErrAPIKeyInvalid,
		ErrAPIKeyRevoked, ErrTLSHandshakeFail, ErrCertNotFound,
		ErrCertExpired, ErrTokenGenerateFail, ErrDBAuthFail,
	}
	for _, code := range authCodes {
		if code < 3000 || code > 3099 {
			t.Errorf("auth code %d outside band 3000-3099", code)
		}
	}

	// Dataplane: 4000-4099
	dpCodes := []int{
		ErrEBPFLoadFailed, ErrMapUpdateFailed, ErrMapDeleteFailed,
		ErrMapLookupFailed, ErrConntrackOverflow, ErrRingBufferFull,
		ErrBPFVerifierReject, ErrPinFailed, ErrXDPAttachFail,
		ErrTCAttachFail, ErrFDBUpdateFail, ErrNeighUpdateFail,
		ErrRouteUpdateFail, ErrVlanConfigFail, ErrBondConfigFail,
	}
	for _, code := range dpCodes {
		if code < 4000 || code > 4099 {
			t.Errorf("dataplane code %d outside band 4000-4099", code)
		}
	}

	// AI Gateway: 5000-5099
	aiCodes := []int{
		ErrModelNotFound, ErrQuotaExceeded, ErrPrefillFailed,
		ErrDecodeFailed, ErrSSEStreamFail, ErrAIBackendUnhlthy,
		ErrAICatalogConflct, ErrAPIKeyRateLimit, ErrTenantRateLimit,
		ErrKVTransferFail, ErrPDRebalanceFail, ErrRequestIDGenFail,
		ErrJSONRewriteFail, ErrAIRouteNotFound, ErrTokenCountFail,
	}
	for _, code := range aiCodes {
		if code < 5000 || code > 5099 {
			t.Errorf("ai-gateway code %d outside band 5000-5099", code)
		}
	}

	// System: 6000-6099
	sysCodes := []int{
		ErrCertExpiry, ErrConfigInvalid, ErrInitFailed,
		ErrShutdownTimeout, ErrFileWriteFail, ErrLogRotateFail,
		ErrPrometheusRegFl, ErrSignalReceived, ErrResourceExhstd,
		ErrDiskSpaceLow, ErrNetlinkFail, ErrSysctlFail,
	}
	for _, code := range sysCodes {
		if code < 6000 || code > 6099 {
			t.Errorf("system code %d outside band 6000-6099", code)
		}
	}
}

func TestErrorCodesNoDuplicates(t *testing.T) {
	allCodes := []int{
		// Network
		ErrNatPoolExhausted, ErrBackendUnreachable, ErrRuleConflict,
		ErrSessionPersistFail, ErrEndpointNotFound, ErrPortRangeExhausted,
		ErrVIPConflict, ErrHealthCheckFail, ErrLBRuleLimit,
		ErrBackendWeightInvald, ErrProxyInitFail, ErrDNSResolveFail,
		ErrQOSPolicyFail, ErrMirrorRuleFail,
		// Cluster
		ErrHAFailover, ErrClusterSplit, ErrStateSync,
		ErrLeaderElection, ErrPeerUnreachable, ErrBFDSessionDown,
		ErrKeepaliveTimeout, ErrClusterNodeJoin, ErrClusterNodeLeave,
		ErrGRPCSyncFail, ErrBGPPeerDown, ErrBGPRouteWithdraw,
		// Auth
		ErrTokenExpired, ErrUnauthorized, ErrInvalidCredentials,
		ErrOAuth2Fail, ErrSessionExpired, ErrAPIKeyInvalid,
		ErrAPIKeyRevoked, ErrTLSHandshakeFail, ErrCertNotFound,
		ErrCertExpired, ErrTokenGenerateFail, ErrDBAuthFail,
		// Dataplane
		ErrEBPFLoadFailed, ErrMapUpdateFailed, ErrMapDeleteFailed,
		ErrMapLookupFailed, ErrConntrackOverflow, ErrRingBufferFull,
		ErrBPFVerifierReject, ErrPinFailed, ErrXDPAttachFail,
		ErrTCAttachFail, ErrFDBUpdateFail, ErrNeighUpdateFail,
		ErrRouteUpdateFail, ErrVlanConfigFail, ErrBondConfigFail,
		// AI Gateway
		ErrModelNotFound, ErrQuotaExceeded, ErrPrefillFailed,
		ErrDecodeFailed, ErrSSEStreamFail, ErrAIBackendUnhlthy,
		ErrAICatalogConflct, ErrAPIKeyRateLimit, ErrTenantRateLimit,
		ErrKVTransferFail, ErrPDRebalanceFail, ErrRequestIDGenFail,
		ErrJSONRewriteFail, ErrAIRouteNotFound, ErrTokenCountFail,
		// System
		ErrCertExpiry, ErrConfigInvalid, ErrInitFailed,
		ErrShutdownTimeout, ErrFileWriteFail, ErrLogRotateFail,
		ErrPrometheusRegFl, ErrSignalReceived, ErrResourceExhstd,
		ErrDiskSpaceLow, ErrNetlinkFail, ErrSysctlFail,
	}

	seen := make(map[int]bool, len(allCodes))
	for _, code := range allCodes {
		if seen[code] {
			t.Errorf("duplicate error code: %d", code)
		}
		seen[code] = true
	}

	// Verify we have approximately 80 codes.
	if len(allCodes) < 70 || len(allCodes) > 100 {
		t.Errorf("expected ~80 error codes, got %d", len(allCodes))
	}
}

// --- Error Code Registry Tests ---

func TestErrorCodeRegistryNonEmpty(t *testing.T) {
	if len(errorCodesJSON) == 0 {
		t.Fatal("errorCodesJSON is empty after go:embed")
	}
}

func TestGetErrorCode(t *testing.T) {
	entry := GetErrorCode(1001)
	if entry == nil {
		t.Fatal("GetErrorCode(1001) returned nil")
	}
	if entry.Name != "NatPoolExhausted" {
		t.Errorf("Name = %q, want %q", entry.Name, "NatPoolExhausted")
	}
	if entry.RootCause == "" {
		t.Error("RootCause is empty")
	}
	if entry.Remediation == "" {
		t.Error("Remediation is empty")
	}
	if entry.Category != "network" {
		t.Errorf("Category = %q, want %q", entry.Category, "network")
	}
}

func TestGetErrorCodeUnknown(t *testing.T) {
	entry := GetErrorCode(9999)
	if entry != nil {
		t.Errorf("GetErrorCode(9999) should return nil, got %+v", entry)
	}
}

func TestGetAllErrorCodes(t *testing.T) {
	entries := GetAllErrorCodes()
	if len(entries) < 70 || len(entries) > 100 {
		t.Errorf("expected ~80 entries, got %d", len(entries))
	}
}

func TestEveryCodeConstantHasRegistryEntry(t *testing.T) {
	allCodes := []int{
		// Network
		ErrNatPoolExhausted, ErrBackendUnreachable, ErrRuleConflict,
		ErrSessionPersistFail, ErrEndpointNotFound, ErrPortRangeExhausted,
		ErrVIPConflict, ErrHealthCheckFail, ErrLBRuleLimit,
		ErrBackendWeightInvald, ErrProxyInitFail, ErrDNSResolveFail,
		ErrQOSPolicyFail, ErrMirrorRuleFail,
		// Cluster
		ErrHAFailover, ErrClusterSplit, ErrStateSync,
		ErrLeaderElection, ErrPeerUnreachable, ErrBFDSessionDown,
		ErrKeepaliveTimeout, ErrClusterNodeJoin, ErrClusterNodeLeave,
		ErrGRPCSyncFail, ErrBGPPeerDown, ErrBGPRouteWithdraw,
		// Auth
		ErrTokenExpired, ErrUnauthorized, ErrInvalidCredentials,
		ErrOAuth2Fail, ErrSessionExpired, ErrAPIKeyInvalid,
		ErrAPIKeyRevoked, ErrTLSHandshakeFail, ErrCertNotFound,
		ErrCertExpired, ErrTokenGenerateFail, ErrDBAuthFail,
		// Dataplane
		ErrEBPFLoadFailed, ErrMapUpdateFailed, ErrMapDeleteFailed,
		ErrMapLookupFailed, ErrConntrackOverflow, ErrRingBufferFull,
		ErrBPFVerifierReject, ErrPinFailed, ErrXDPAttachFail,
		ErrTCAttachFail, ErrFDBUpdateFail, ErrNeighUpdateFail,
		ErrRouteUpdateFail, ErrVlanConfigFail, ErrBondConfigFail,
		// AI Gateway
		ErrModelNotFound, ErrQuotaExceeded, ErrPrefillFailed,
		ErrDecodeFailed, ErrSSEStreamFail, ErrAIBackendUnhlthy,
		ErrAICatalogConflct, ErrAPIKeyRateLimit, ErrTenantRateLimit,
		ErrKVTransferFail, ErrPDRebalanceFail, ErrRequestIDGenFail,
		ErrJSONRewriteFail, ErrAIRouteNotFound, ErrTokenCountFail,
		// System
		ErrCertExpiry, ErrConfigInvalid, ErrInitFailed,
		ErrShutdownTimeout, ErrFileWriteFail, ErrLogRotateFail,
		ErrPrometheusRegFl, ErrSignalReceived, ErrResourceExhstd,
		ErrDiskSpaceLow, ErrNetlinkFail, ErrSysctlFail,
	}

	for _, code := range allCodes {
		entry := GetErrorCode(code)
		if entry == nil {
			t.Errorf("error code %d has no registry entry in error-codes.json", code)
		}
	}
}

func TestGetErrorCodesJSON(t *testing.T) {
	raw := GetErrorCodesJSON()
	if len(raw) == 0 {
		t.Fatal("GetErrorCodesJSON() returned empty bytes")
	}
	// Should start with '[' (JSON array).
	if raw[0] != '[' {
		t.Errorf("error-codes.json should start with '[', got %q", string(raw[0]))
	}
}

// --- Logger Engine Tests ---

// resetLogger resets the initialized flag so Init can be called again in tests.
func resetLogger() {
	if initialized.Load() {
		Close()
	}
	initialized.Store(false)
}

func initTestLogger(t *testing.T, format string) string {
	t.Helper()
	resetLogger()

	dir := t.TempDir()
	cfg := Config{
		LogDir:    dir,
		LogFormat: format,
		LogLevel:  "debug",
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	return dir
}

func TestInitCreatesFiles(t *testing.T) {
	dir := initTestLogger(t, "both")
	defer resetLogger()

	// Check JSON file exists.
	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Errorf("JSON log file not created: %s", jsonPath)
	}

	// Check text file exists.
	txtPath := filepath.Join(dir, "loxilb.log")
	if _, err := os.Stat(txtPath); os.IsNotExist(err) {
		t.Errorf("text log file not created: %s", txtPath)
	}
}

func TestEventWritesDualOutput(t *testing.T) {
	dir := initTestLogger(t, "both")
	defer resetLogger()

	ctx := context.TODO()
	Event(ctx).
		Component("network").
		Action("rule-add").
		Outcome(OutcomeSuccess).
		ErrCode(ErrNatPoolExhausted).
		Msg("NAT rule created")

	// Close to flush diode.
	Close()

	// Check JSON output.
	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}

	if len(jsonData) == 0 {
		t.Fatal("JSON log file is empty")
	}

	var entry map[string]interface{}
	// Parse first line.
	lines := strings.Split(strings.TrimSpace(string(jsonData)), "\n")
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse JSON line: %v", err)
	}

	// Verify ECS fields.
	if entry[FieldECSVersion] != ECSVersion {
		t.Errorf("ecs.version = %v, want %s", entry[FieldECSVersion], ECSVersion)
	}
	if entry[FieldEventAction] != "rule-add" {
		t.Errorf("event.action = %v, want rule-add", entry[FieldEventAction])
	}
	if entry[FieldEventOutcome] != OutcomeSuccess {
		t.Errorf("event.outcome = %v, want success", entry[FieldEventOutcome])
	}
	if entry[FieldComponent] != "network" {
		t.Errorf("service.component = %v, want network", entry[FieldComponent])
	}
	// error.code comes as float64 from JSON.
	if code, ok := entry[FieldErrCode].(float64); !ok || int(code) != ErrNatPoolExhausted {
		t.Errorf("error.code = %v, want %d", entry[FieldErrCode], ErrNatPoolExhausted)
	}
	if entry["message"] != "NAT rule created" {
		t.Errorf("message = %v, want 'NAT rule created'", entry["message"])
	}

	// Check text file has content.
	txtPath := filepath.Join(dir, "loxilb.log")
	txtData, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatalf("read text log: %v", err)
	}
	if len(txtData) == 0 {
		t.Fatal("text log file is empty")
	}
	if !strings.Contains(string(txtData), "NAT rule created") {
		t.Errorf("text log does not contain expected message")
	}
}

func TestCategoryFilterSuppressesEvent(t *testing.T) {
	dir := initTestLogger(t, "json")
	defer resetLogger()

	// Save and restore category level.
	origLevel := GetCategoryLevel(CatNetwork)
	defer SetCategoryLevel(CatNetwork, origLevel)

	// Set network category to ErrorLevel.
	SetCategoryLevel(CatNetwork, zerolog.ErrorLevel)

	ctx := context.TODO()
	// Emit an Info-level event for network category — should be suppressed.
	Event(ctx).
		Level(zerolog.InfoLevel).
		Category(CatNetwork).
		Component("network").
		Action("test-suppressed").
		Msg("this should not appear")

	Close()

	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}

	if strings.Contains(string(data), "test-suppressed") {
		t.Error("Info-level event should have been suppressed by ErrorLevel category filter")
	}
}

func TestSecurityBypassOverridesFilter(t *testing.T) {
	dir := initTestLogger(t, "json")
	defer resetLogger()

	origLevel := GetCategoryLevel(CatAuth)
	defer SetCategoryLevel(CatAuth, origLevel)

	// Set auth category to ErrorLevel.
	SetCategoryLevel(CatAuth, zerolog.ErrorLevel)

	ctx := context.TODO()
	// SecurityBypass event at Info level should still emit.
	Event(ctx).
		Level(zerolog.InfoLevel).
		Category(CatAuth).
		SecurityBypass().
		Component("auth").
		Action("security-event").
		Msg("bypass event")

	Close()

	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}

	if !strings.Contains(string(data), "bypass event") {
		t.Error("SecurityBypass event should have been emitted despite ErrorLevel filter")
	}
}

func TestDPEventWritesToDPFile(t *testing.T) {
	dir := initTestLogger(t, "json")
	defer resetLogger()

	ctx := context.TODO()
	DPEvent(ctx).
		Component("dataplane").
		Action("dp-test").
		Msg("dp event")

	Close()

	// DP event should be in DP file.
	dpPath := filepath.Join(dir, "loxilb-dp-audit.json.log")
	dpData, err := os.ReadFile(dpPath)
	if err != nil {
		t.Fatalf("read DP JSON log: %v", err)
	}
	if !strings.Contains(string(dpData), "dp-test") {
		t.Error("DP event not found in DP log file")
	}

	// DP event should NOT be in CP file.
	cpPath := filepath.Join(dir, "loxilb-audit.json.log")
	cpData, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatalf("read CP JSON log: %v", err)
	}
	if strings.Contains(string(cpData), "dp-test") {
		t.Error("DP event should not appear in CP log file")
	}
}

func TestCloseFlushesEvents(t *testing.T) {
	dir := initTestLogger(t, "json")

	ctx := context.TODO()
	Event(ctx).Action("flush-test").Msg("pre-close")

	// Close flushes.
	Close()

	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}
	if !strings.Contains(string(data), "flush-test") {
		t.Error("event not flushed by Close()")
	}
}

func TestBuilderLevelMethod(t *testing.T) {
	dir := initTestLogger(t, "json")
	defer resetLogger()

	ctx := context.TODO()
	Event(ctx).Level(zerolog.WarnLevel).Action("warn-test").Msg("warning msg")

	Close()

	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}

	var entry map[string]interface{}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("no log lines")
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if entry["level"] != "warn" {
		t.Errorf("level = %v, want warn", entry["level"])
	}
}

func TestBuilderStrAndInt(t *testing.T) {
	dir := initTestLogger(t, "json")
	defer resetLogger()

	ctx := context.TODO()
	Event(ctx).
		Str("custom_key", "custom_value").
		Int("custom_int", 42).
		Msg("custom fields")

	Close()

	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}

	var entry map[string]interface{}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if entry["custom_key"] != "custom_value" {
		t.Errorf("custom_key = %v, want custom_value", entry["custom_key"])
	}
	if v, ok := entry["custom_int"].(float64); !ok || int(v) != 42 {
		t.Errorf("custom_int = %v, want 42", entry["custom_int"])
	}
}

func TestTraceIDFromContext(t *testing.T) {
	dir := initTestLogger(t, "json")
	defer resetLogger()

	ctx := WithTraceID(context.TODO(), "abc-123")
	Event(ctx).Action("trace-test").Msg("traced")

	Close()

	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}

	var entry map[string]interface{}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if entry[FieldTraceID] != "abc-123" {
		t.Errorf("trace.id = %v, want abc-123", entry[FieldTraceID])
	}
}

func TestSendMethodEqualsEmptyMsg(t *testing.T) {
	dir := initTestLogger(t, "json")
	defer resetLogger()

	ctx := context.TODO()
	Event(ctx).Action("send-test").Send()

	Close()

	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}
	if !strings.Contains(string(data), "send-test") {
		t.Error("Send() did not emit event")
	}
}

func TestInitFallbackToTmp(t *testing.T) {
	resetLogger()

	cfg := Config{
		LogDir:    "/nonexistent/path/that/does/not/exist/",
		LogFormat: "json",
		LogLevel:  "debug",
	}
	err := Init(cfg)
	if err != nil {
		t.Fatalf("Init should fall back to /tmp/, got error: %v", err)
	}
	defer resetLogger()

	// Verify files were created in /tmp/.
	if _, err := os.Stat("/tmp/loxilb-audit.json.log"); os.IsNotExist(err) {
		t.Error("fallback JSON log not created in /tmp/")
	}
	Close()

	// Clean up /tmp/ test files.
	os.Remove("/tmp/loxilb-audit.json.log")
	os.Remove("/tmp/loxilb.log")
	os.Remove("/tmp/loxilb-dp-audit.json.log")
	os.Remove("/tmp/loxilb-dp.log")
}

func TestJSONOnlyFormat(t *testing.T) {
	dir := initTestLogger(t, "json")
	defer resetLogger()

	ctx := context.TODO()
	Event(ctx).Action("json-only-test").Msg("json only")
	Close()

	// JSON file should exist and have content.
	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}
	if !strings.Contains(string(data), "json-only-test") {
		t.Error("JSON-only event not found")
	}
}

func TestTextOnlyFormat(t *testing.T) {
	dir := initTestLogger(t, "text")
	defer resetLogger()

	ctx := context.TODO()
	Event(ctx).Action("text-only-test").Msg("text only")
	Close()

	txtPath := filepath.Join(dir, "loxilb.log")
	data, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatalf("read text log: %v", err)
	}
	if !strings.Contains(string(data), "text only") {
		t.Error("text-only event not found")
	}
}

func TestWithTraceIDAndExtract(t *testing.T) {
	ctx := context.TODO()
	if id := TraceIDFromCtx(ctx); id != "" {
		t.Errorf("empty context should return empty trace ID, got %q", id)
	}

	ctx = WithTraceID(ctx, "test-trace-456")
	if id := TraceIDFromCtx(ctx); id != "test-trace-456" {
		t.Errorf("TraceIDFromCtx = %q, want test-trace-456", id)
	}
}

func TestEventReasonAndType(t *testing.T) {
	dir := initTestLogger(t, "json")
	defer resetLogger()

	ctx := context.TODO()
	Event(ctx).
		Action("reason-type-test").
		Reason("pool exhausted").
		Type(TypeCreation).
		EventCategory(CategoryNetwork).
		Msg("test")

	Close()

	jsonPath := filepath.Join(dir, "loxilb-audit.json.log")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON log: %v", err)
	}

	var entry map[string]interface{}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if entry[FieldEventReason] != "pool exhausted" {
		t.Errorf("event.reason = %v, want 'pool exhausted'", entry[FieldEventReason])
	}
	if entry[FieldEventType] != TypeCreation {
		t.Errorf("event.type = %v, want %s", entry[FieldEventType], TypeCreation)
	}
	if entry[FieldEventCategory] != CategoryNetwork {
		t.Errorf("event.category = %v, want %s", entry[FieldEventCategory], CategoryNetwork)
	}
}

// Ensure unused imports don't cause issues.
var _ = bufio.NewReader
var _ = time.Now
var _ = filepath.Join
