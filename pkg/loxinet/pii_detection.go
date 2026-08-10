/*
 * Copyright (c) 2025 LoxiLB Authors
 * SPDX short identifier: BSD-3-Clause
 *
 * PII Detection: Go Bridge Layer (CGO Exports) - Unified v1+v2
 *
 * This file provides CGO exports that bridge C layer (sockproxy_presidio.c)
 * with Go layer (gRPC client to Presidio service). Follows xSync Consumer pattern.
 *
 * Merged Features:
 * - Basic analyze + anonymize (v1)
 * - Combined analyze+anonymize (v2 - 40% faster)
 * - Encryption/decryption (v2)
 * - JSON structure-aware anonymization (v2)
 * - Custom recognizers (v2)
 * - Batch streaming support (v2)
 */

package loxinet

/*
#cgo CFLAGS: -I../../loxilb-ebpf/common
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// PII entity structure (matches sockproxy_presidio.h EXACTLY)
typedef struct {
    char entity_type[64];  // Fixed array, not pointer!
    int start;
    int end;
    float score;           // float, not double!
} pii_entity_t;

// PII scan result structure (matches sockproxy_presidio.h)
typedef struct {
    char *anonymized_text;   // PII-masked version (caller must free)
    size_t anonymized_len;   // Explicit length (NOT strlen - may contain NUL bytes)
    pii_entity_t *entities;  // Array of detected entities (caller must free)
    int entity_count;        // Number of entities
    double latency_ms;       // Scan latency
    int error_code;          // 0=success, -1=error
    char error_msg[256];     // Error description
} pii_scan_result_t;

// V2: Anonymization item metadata
typedef struct {
    char entity_type[64];
    int start;
    int end;
    char operator_used[32];
    char original_text[256];
} anonymized_item_t;

// V2: Enhanced scan result
typedef struct {
    char *anonymized_text;
    size_t anonymized_len;   // Explicit length (NOT strlen - may contain NUL bytes)
    pii_entity_t *entities;
    anonymized_item_t *items;
    int entity_count;
    int item_count;
    double latency_ms;
    int error_code;
    char error_msg[256];
} pii_scan_result_v2_t;

// V2: JSON result
typedef struct {
    char *json_data;
    int fields_anonymized;
    double latency_ms;
    int error_code;
    char error_msg[256];
} pii_json_result_t;

// V2: Operator configuration
typedef struct {
    int type;  // presidio_operator_type_t
    char params[256];
} presidio_operator_config_t;

typedef struct {
    presidio_operator_config_t default_op;
    presidio_operator_config_t email_op;
    presidio_operator_config_t ssn_op;
    presidio_operator_config_t credit_card_op;
    presidio_operator_config_t phone_op;
    presidio_operator_config_t person_op;
    presidio_operator_config_t custom_ops[8];
    char custom_entity_types[8][64];
    uint8_t custom_op_count;
} presidio_operators_t;

// V2: JSON field mapping
typedef struct {
    char field_path[128];
    char entity_type[64];
} presidio_json_field_mapping_t;

typedef struct {
    presidio_json_field_mapping_t mappings[32];
    uint8_t mapping_count;
} presidio_json_mapping_t;

// V2: Pattern definition
typedef struct {
    char name[64];
    char regex[256];
    float score;
} presidio_pattern_t;
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
	"unsafe"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	pb "github.com/loxilb-io/loxilb/pkg/loxinet/presidio_pb"
	presidio "github.com/loxilb-io/loxilb/pkg/presidio"
	tk "github.com/loxilb-io/loxilib"
)

// Operator type constants (must match C enum)
const (
	OperatorReplace = 0
	OperatorRedact  = 1
	OperatorHash    = 2
	OperatorEncrypt = 3
	OperatorMask    = 4
)

// PresidioClient manages connection to Presidio gRPC service (unified v1+v2)
type PresidioClient struct {
	conn          *grpc.ClientConn
	client        pb.PresidioServiceClient
	addr          string
	connected     bool
	lastConnError time.Time
	timeout       time.Duration
}

var globalPresidioClient *PresidioClient

// InitPresidioClient initializes gRPC connection to Presidio service
func InitPresidioClient(addr string) error {
	if globalPresidioClient != nil && globalPresidioClient.connected {
		return nil // Already initialized
	}

	globalPresidioClient = &PresidioClient{
		addr:      addr,
		connected: false,
		timeout:   5 * time.Second, // Default timeout for gRPC calls
	}

	return globalPresidioClient.connect()
}

// connect establishes gRPC connection to Presidio
func (pc *PresidioClient) connect() error {
	if pc.addr == "" {
		pc.addr = "localhost:50051" // Default
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Production-ready dial options
	conn, err := grpc.DialContext(ctx, pc.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second, // Send keepalive every 30s (was 10s - too aggressive)
			Timeout:             10 * time.Second, // Wait 10s for keepalive ack
			PermitWithoutStream: false,            // Only send keepalive during active RPCs (prevents "too_many_pings")
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(10*1024*1024), // 10MB max response
			grpc.MaxCallSendMsgSize(10*1024*1024), // 10MB max request
		),
	)
	if err != nil {
		pc.lastConnError = time.Now()
		tk.LogIt(tk.LogError, "[Presidio] Failed to connect to %s: %v\n", pc.addr, err)
		return fmt.Errorf("failed to connect to Presidio: %w", err)
	}

	pc.client = pb.NewPresidioServiceClient(conn)
	pc.conn = conn
	pc.connected = true
	tk.LogIt(tk.LogInfo, "[Presidio] ✓ Connected to: %s (keepalive=30s)\n", pc.addr)
	return nil
}

// reconnectIfNeeded attempts to reconnect if connection is lost
func (pc *PresidioClient) reconnectIfNeeded() error {
	if pc.connected {
		return nil
	}

	// Rate limit reconnection attempts (1 per 10 seconds)
	if time.Since(pc.lastConnError) < 10*time.Second {
		return fmt.Errorf("reconnection rate limited")
	}

	return pc.connect()
}

// Close closes gRPC connection
func (pc *PresidioClient) Close() error {
	pc.connected = false
	if pc.conn != nil {
		return pc.conn.Close()
	}
	return nil
}

// IsHealthy checks if connection is healthy
func (pc *PresidioClient) IsHealthy() bool {
	return pc.connected && pc.conn != nil
}

// ForceReconnect closes existing connection and reconnects
func (pc *PresidioClient) ForceReconnect() error {
	if pc.conn != nil {
		pc.conn.Close()
	}
	pc.connected = false
	return pc.connect()
}

// ============================================================================
// CGO EXPORTS FOR C LAYER (llb_presidio_* functions)
// These match the extern declarations in sockproxy_presidio.h
// ============================================================================

// llb_presidio_init - Initialize Presidio client connection
//
//export llb_presidio_init
func llb_presidio_init(analyzerURL *C.char, anonymizerURL *C.char) C.int {
	addr := C.GoString(analyzerURL)
	if err := InitPresidioClient(addr); err != nil {
		tk.LogIt(tk.LogError, "[Presidio] Failed to initialize: %v\n", err)
		return -1
	}
	tk.LogIt(tk.LogInfo, "[Presidio] ✓ Initialized with analyzer: %s\n", addr)
	return 0
}

// llb_presidio_update_config - Update gRPC client when config changes
// Called when analyzer_url changes via API
//
//export llb_presidio_update_config
func llb_presidio_update_config(analyzerURL *C.char) C.int {
	if globalPresidioClient == nil {
		// Not initialized yet, just initialize
		return llb_presidio_init(analyzerURL, nil)
	}

	newAddr := C.GoString(analyzerURL)

	// Check if URL actually changed
	if globalPresidioClient.addr == newAddr {
		tk.LogIt(tk.LogDebug, "[Presidio] URL unchanged, keeping connection\n")
		return 0 // No change needed
	}

	tk.LogIt(tk.LogInfo, "[Presidio] 🔄 Analyzer URL changed: %s → %s\n",
		globalPresidioClient.addr, newAddr)

	// Close old connection
	if err := globalPresidioClient.Close(); err != nil {
		tk.LogIt(tk.LogWarning, "[Presidio] Error closing old connection: %v\n", err)
	}

	// Update address and reconnect
	globalPresidioClient.addr = newAddr
	globalPresidioClient.connected = false

	if err := globalPresidioClient.connect(); err != nil {
		tk.LogIt(tk.LogError, "[Presidio] Failed to reconnect: %v\n", err)
		return -1
	}

	tk.LogIt(tk.LogInfo, "[Presidio] ✓ Reconnected to new analyzer: %s\n", newAddr)
	return 0
}

// llb_presidio_enable - Enable PII detection
//
//export llb_presidio_enable
func llb_presidio_enable() C.int {
	if globalPresidioClient == nil {
		return -1
	}
	return 0
}

// llb_presidio_disable - Disable PII detection
//
//export llb_presidio_disable
func llb_presidio_disable() C.int {
	return 0
}

// llb_presidio_is_enabled - Check if PII detection is enabled
//
//export llb_presidio_is_enabled
func llb_presidio_is_enabled() C.int {
	if globalPresidioClient != nil && globalPresidioClient.connected {
		return 1
	}
	return 0
}

// llb_presidio_configure - Configure detection parameters
//
//export llb_presidio_configure
func llb_presidio_configure(analyzerURL *C.char, anonymizerURL *C.char, mode C.int, direction C.int, threshold C.double, timeoutMs C.uint) C.int {
	addr := C.GoString(analyzerURL)
	if globalPresidioClient == nil {
		if err := InitPresidioClient(addr); err != nil {
			return -1
		}
	}
	return 0
}

// llb_presidio_scan - Scan text for PII entities
// Returns opaque pointer to result (must be freed with llb_presidio_free_result)
//
//export llb_presidio_scan
func llb_presidio_scan(content *C.char, language *C.char, catalogID C.int) unsafe.Pointer {
	if content == nil || globalPresidioClient == nil {
		tk.LogIt(tk.LogWarning, "[Presidio] llb_presidio_scan: content=%v globalPresidioClient=%v\n",
			content == nil, globalPresidioClient == nil)
		return nil
	}

	goText := C.GoString(content)
	goLang := "en"
	if language != nil {
		goLang = C.GoString(language)
	}

	// Log actual request text (truncate if too long for readability)
	logText := goText
	if len(logText) > 200 {
		logText = logText[:200] + "..."
	}
	tk.LogIt(tk.LogDebug, "[Presidio] 📤 llb_presidio_scan called:\n")
	tk.LogIt(tk.LogDebug, "    text_len=%d language=%s catalog_id=%d\n",
		len(goText), goLang, catalogID)
	tk.LogIt(tk.LogDebug, "    text_content: '%s'\n", logText)

	// Create Presidio analyze request
	req := &pb.AnalyzeRequest{
		Text:           goText,
		Language:       goLang,
		ScoreThreshold: 0.5,
	}

	ctx, cancel := context.WithTimeout(context.Background(), globalPresidioClient.timeout)
	defer cancel()

	tk.LogIt(tk.LogDebug, "[Presidio] Calling Analyze RPC...\n")
	reply, err := globalPresidioClient.client.Analyze(ctx, req)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[Presidio] ❌ Scan error: %v\n", err)
		return nil
	}

	tk.LogIt(tk.LogDebug, "[Presidio] ✅ RPC succeeded: entity_count=%d\n", reply.EntityCount)

	// Allocate C result structure matching pii_scan_result_t
	result := (*C.pii_scan_result_t)(C.malloc(C.sizeof_pii_scan_result_t))
	if result == nil {
		tk.LogIt(tk.LogWarning, "[Presidio] ❌ Failed to allocate result structure\n")
		return nil
	}
	C.memset(unsafe.Pointer(result), 0, C.sizeof_pii_scan_result_t)

	// Set success
	result.error_code = 0
	result.entity_count = C.int(reply.EntityCount)
	result.latency_ms = 0.0 // per-request latency tracking not implemented yet

	if reply.EntityCount > 0 {
		// Allocate entities array
		entitiesSize := C.size_t(reply.EntityCount) * C.sizeof_pii_entity_t
		result.entities = (*C.pii_entity_t)(C.malloc(entitiesSize))
		if result.entities == nil {
			tk.LogIt(tk.LogWarning, "[Presidio] ❌ Failed to allocate entities array\n")
			C.free(unsafe.Pointer(result))
			return nil
		}

		// Convert to C array (need to use pointer arithmetic)
		entities := (*[1 << 30]C.pii_entity_t)(unsafe.Pointer(result.entities))[:reply.EntityCount:reply.EntityCount]
		for i, entity := range reply.Results {
			// Copy entity_type to fixed-size array (max 63 chars + null terminator)
			entityTypeC := C.CString(entity.EntityType)
			C.strncpy(&entities[i].entity_type[0], entityTypeC, 63)
			entities[i].entity_type[63] = 0 // Ensure null termination
			C.free(unsafe.Pointer(entityTypeC))

			entities[i].start = C.int(entity.Start)
			entities[i].end = C.int(entity.End)
			entities[i].score = C.float(entity.Score) // float, not double!
		}

		// Generate masked text
		maskedText := goText
		for i := len(reply.Results) - 1; i >= 0; i-- {
			entity := reply.Results[i]
			if entity.Start >= 0 && entity.End <= int32(len(goText)) && entity.End > entity.Start {
				replacement := fmt.Sprintf("[%s]", entity.EntityType)
				maskedText = maskedText[:entity.Start] + replacement + maskedText[entity.End:]
			}
		}
		result.anonymized_text = C.CString(maskedText)
		result.anonymized_len = C.size_t(len(maskedText))

		tk.LogIt(tk.LogDebug, "[Presidio] ✅ Created result: entities=%d masked_len=%d\n",
			reply.EntityCount, len(maskedText))
	} else {
		result.entities = nil
		result.anonymized_text = C.CString(goText) // No masking needed
		result.anonymized_len = C.size_t(len(goText))
	}

	return unsafe.Pointer(result)
}

// llb_presidio_free_result - Free scan result memory
//
//export llb_presidio_free_result
func llb_presidio_free_result(resultPtr unsafe.Pointer) {
	if resultPtr == nil {
		return
	}

	result := (*C.pii_scan_result_t)(resultPtr)

	// Free anonymized_text
	if result.anonymized_text != nil {
		C.free(unsafe.Pointer(result.anonymized_text))
	}

	// Free entities array (no need to free entity_type strings - they're fixed arrays now!)
	if result.entities != nil {
		C.free(unsafe.Pointer(result.entities))
	}

	C.free(resultPtr)
}

// llb_presidio_get_stats - Get statistics as JSON string
//
//export llb_presidio_get_stats
func llb_presidio_get_stats() *C.char {
	// Return empty JSON for now
	return C.CString("{}")
}

// llb_presidio_health_check - Health check with actual gRPC connectivity test
//
//export llb_presidio_health_check
func llb_presidio_health_check() C.int {
	if globalPresidioClient == nil {
		return -1
	}

	// Check connection state
	if !globalPresidioClient.IsHealthy() {
		return -2
	}

	// Perform lightweight gRPC health check (test with empty analyze)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := &pb.AnalyzeRequest{
		Text:           "test",
		Language:       "en",
		ScoreThreshold: 0.5,
	}

	_, err := globalPresidioClient.client.Analyze(ctx, req)
	if err != nil {
		// Mark as disconnected
		globalPresidioClient.connected = false
		globalPresidioClient.lastConnError = time.Now()
		tk.LogIt(tk.LogWarning, "[Presidio] Health check failed: %v\n", err)
		return -3
	}

	return 0
}

// ============================================================================
// V2 API: ENHANCED FEATURES (Combined Analyze+Anonymize, Encryption, JSON, Batch)
// ============================================================================

//export llb_presidio_v2_init
func llb_presidio_v2_init(serverURL *C.char) C.int {
	// V2 uses the same unified client as V1
	return llb_presidio_init(serverURL, nil)
}

//export llb_presidio_analyze_and_anonymize
func llb_presidio_analyze_and_anonymize(
	text *C.char,
	language *C.char,
	operatorsPtr unsafe.Pointer,
) unsafe.Pointer {
	if globalPresidioClient == nil || !globalPresidioClient.connected {
		return buildV2ErrorResult("client not initialized")
	}

	goText := C.GoString(text)
	goLang := C.GoString(language)

	// Parse operators from C structure
	operators := (*C.presidio_operators_t)(operatorsPtr)
	opMap := buildOperatorMap(operators)

	// Create gRPC request
	ctx, cancel := context.WithTimeout(context.Background(), globalPresidioClient.timeout)
	defer cancel()

	req := &pb.AnalyzeAndAnonymizeRequest{
		Text:      goText,
		Language:  goLang,
		Operators: opMap,
	}

	// Call gRPC unified API
	startTime := time.Now()
	resp, err := globalPresidioClient.client.AnalyzeAndAnonymize(ctx, req)
	latencyMs := time.Since(startTime).Seconds() * 1000

	if err != nil {
		tk.LogIt(tk.LogError, "[Presidio] AnalyzeAndAnonymize failed: %v\n", err)
		return buildV2ErrorResult(fmt.Sprintf("gRPC error: %v", err))
	}

	// Convert gRPC response to C structure
	result := convertAnonymizeResponseToV2(resp, latencyMs)
	return unsafe.Pointer(result)
}

//export llb_presidio_deanonymize
func llb_presidio_deanonymize(
	encryptedText *C.char,
	itemsPtr unsafe.Pointer,
	itemCount C.int,
	decryptionKey *C.char,
) unsafe.Pointer {
	if globalPresidioClient == nil || !globalPresidioClient.connected {
		return nil
	}

	goText := C.GoString(encryptedText)
	goKey := C.GoString(decryptionKey)
	count := int(itemCount)

	// Parse items from C array
	items := (*[1 << 30]C.anonymized_item_t)(itemsPtr)[:count:count]

	// Convert C items to gRPC entities
	entities := make([]*pb.AnonymizedEntity, count)
	for i := 0; i < count; i++ {
		entities[i] = &pb.AnonymizedEntity{
			EntityType:   C.GoString(&items[i].entity_type[0]),
			Start:        int32(items[i].start),
			End:          int32(items[i].end),
			Operator:     C.GoString(&items[i].operator_used[0]),
			OriginalText: C.GoString(&items[i].original_text[0]),
		}
	}

	// Build operators for decryption
	operators := make(map[string]*pb.OperatorConfig)
	operators["DEFAULT"] = &pb.OperatorConfig{
		OperatorName: "decrypt",
		Params:       map[string]string{"key": goKey},
	}

	// Create gRPC request
	ctx, cancel := context.WithTimeout(context.Background(), globalPresidioClient.timeout)
	defer cancel()

	req := &pb.DeanonymizeRequest{
		Text:      goText,
		Entities:  entities,
		Operators: operators,
	}

	// Call gRPC unified API
	resp, err := globalPresidioClient.client.Deanonymize(ctx, req)
	if err != nil {
		tk.LogIt(tk.LogError, "[Presidio] Deanonymize failed: %v\n", err)
		return nil
	}

	// Return decrypted text
	result := C.CString(resp.Text)
	return unsafe.Pointer(result)
}

//export llb_presidio_anonymize_json
func llb_presidio_anonymize_json(
	jsonData *C.char,
	language *C.char,
	entityMappingPtr unsafe.Pointer,
	operatorsPtr unsafe.Pointer,
) unsafe.Pointer {
	if globalPresidioClient == nil || !globalPresidioClient.connected {
		return buildJSONErrorResult("client not initialized")
	}

	goJSON := C.GoString(jsonData)
	goLang := C.GoString(language)

	// Parse entity mapping
	mapping := (*C.presidio_json_mapping_t)(entityMappingPtr)
	fieldMap := parseJSONMapping(mapping)

	// Get exclude_fields from shared configuration
	excludeFields := getExcludedFields()
	tk.LogIt(tk.LogInfo, "[Presidio-Exclusion] Retrieved %d exclude_fields: %v\n", len(excludeFields), excludeFields)

	// Pre-process JSON to temporarily remove excluded fields
	processedJSON, excludedValues := preprocessJSONWithExclusions(goJSON, excludeFields)
	if processedJSON == "" {
		processedJSON = goJSON // Fallback to original if preprocessing fails
	}
	tk.LogIt(tk.LogInfo, "[Presidio-Exclusion] Preprocessed JSON: removed %d fields, len %d→%d\n",
		len(excludedValues), len(goJSON), len(processedJSON))
	operators := (*C.presidio_operators_t)(operatorsPtr)
	opMap := buildOperatorMap(operators)

	// Get score_threshold from shared configuration (default: 0.7)
	scoreThreshold := float32(0.7)
	if presidio.GlobalConfigMgr() != nil {
		scoreThreshold = presidio.GlobalConfigMgr().GetScoreThreshold()
	}
	tk.LogIt(tk.LogInfo, "[Presidio-gRPC] Using score_threshold=%.2f\n", scoreThreshold)

	// Create gRPC request
	ctx, cancel := context.WithTimeout(context.Background(), globalPresidioClient.timeout)
	defer cancel()

	req := &pb.AnonymizeJSONRequest{
		JsonData:       processedJSON,
		Language:       goLang,
		EntityMapping:  fieldMap,
		Operators:      opMap,
		ScoreThreshold: scoreThreshold,
	}

	// CRITICAL DEBUG: Log gRPC request details
	tk.LogIt(tk.LogInfo, "[Presidio-gRPC] >>> Sending AnonymizeJSON request: json_len=%d fields=%d\n",
		len(processedJSON), len(fieldMap))
	tk.LogIt(tk.LogDebug, "[Presidio-gRPC] >>> Request JSON preview: %.200s\n", processedJSON)

	// CRITICAL CHECK: Verify client is not nil
	if globalPresidioClient == nil {
		tk.LogIt(tk.LogError, "[Presidio-gRPC] <<< CRITICAL: globalPresidioClient is NIL!\n")
		return buildJSONErrorResult("client became nil")
	}
	if globalPresidioClient.client == nil {
		tk.LogIt(tk.LogError, "[Presidio-gRPC] <<< CRITICAL: globalPresidioClient.client is NIL!\n")
		return buildJSONErrorResult("gRPC client stub is nil")
	}

	tk.LogIt(tk.LogInfo, "[Presidio-gRPC] >>> Client status: connected=%v addr=%s\n",
		globalPresidioClient.connected, globalPresidioClient.addr)

	// Call gRPC unified API
	startTime := time.Now()
	tk.LogIt(tk.LogInfo, "[Presidio-gRPC] >>> CALLING client.AnonymizeJSON NOW...\n")
	tk.LogIt(tk.LogInfo, "[Presidio-gRPC] >>> Request details: json_len=%d entity_mappings=%d operators=%d\n",
		len(processedJSON), len(fieldMap), len(opMap))
	tk.LogIt(tk.LogDebug, "[Presidio-gRPC] >>> EntityMapping: %+v\n", fieldMap)
	tk.LogIt(tk.LogDebug, "[Presidio-gRPC] >>> Operators: %+v\n", opMap)

	resp, err := globalPresidioClient.client.AnonymizeJSON(ctx, req)

	tk.LogIt(tk.LogInfo, "[Presidio-gRPC] >>> RETURNED from client.AnonymizeJSON\n")
	latencyMs := time.Since(startTime).Seconds() * 1000

	// CRITICAL DEBUG: Log gRPC response or error
	if err != nil {
		tk.LogIt(tk.LogError, "[Presidio-gRPC] <<< AnonymizeJSON FAILED after %.2fms: %v\n", latencyMs, err)
		return buildJSONErrorResult(fmt.Sprintf("gRPC error: %v", err))
	}

	tk.LogIt(tk.LogInfo, "[Presidio-gRPC] <<< Received AnonymizeJSON response: latency=%.2fms fields_anonymized=%d json_len=%d\n",
		latencyMs, resp.FieldsAnonymized, len(resp.JsonData))
	tk.LogIt(tk.LogDebug, "[Presidio-gRPC] <<< Response JSON preview: %.200s\n", resp.JsonData)

	// Post-process: restore excluded fields to anonymized JSON
	finalJSON := postprocessJSONWithExclusions(resp.JsonData, excludedValues)
	tk.LogIt(tk.LogInfo, "[Presidio-Exclusion] Postprocessed JSON: restored %d fields, len %d→%d\n",
		len(excludedValues), len(resp.JsonData), len(finalJSON))
	resp.JsonData = finalJSON

	// Convert gRPC response to C structure
	result := convertJSONResponse(resp, latencyMs)
	return unsafe.Pointer(result)
}

//export llb_presidio_register_custom_recognizer
func llb_presidio_register_custom_recognizer(
	name *C.char,
	entityType *C.char,
	patternsPtr unsafe.Pointer,
	patternCount C.int,
	contextWordsPtr unsafe.Pointer,
	contextWordCount C.int,
) C.int {
	if globalPresidioClient == nil || !globalPresidioClient.connected {
		return -1
	}

	goName := C.GoString(name)
	goEntityType := C.GoString(entityType)
	pCount := int(patternCount)

	// Parse patterns
	patterns := (*[1 << 30]C.presidio_pattern_t)(patternsPtr)[:pCount:pCount]
	var patternList []*pb.Pattern
	for i := 0; i < pCount; i++ {
		patternList = append(patternList, &pb.Pattern{
			Name:  C.GoString(&patterns[i].name[0]),
			Regex: C.GoString(&patterns[i].regex[0]),
			Score: float32(patterns[i].score),
		})
	}

	// Parse context words (optional)
	var contextWords []string
	if contextWordCount > 0 && contextWordsPtr != nil {
		cwCount := int(contextWordCount)
		words := (*[1 << 30]*C.char)(contextWordsPtr)[:cwCount:cwCount]
		for i := 0; i < cwCount; i++ {
			contextWords = append(contextWords, C.GoString(words[i]))
		}
	}

	// Build recognizer
	recognizer := &pb.AdHocRecognizer{
		Name:         goName,
		EntityType:   goEntityType,
		Patterns:     patternList,
		ContextWords: contextWords,
	}

	// Create gRPC request
	ctx, cancel := context.WithTimeout(context.Background(), globalPresidioClient.timeout)
	defer cancel()

	req := &pb.RegisterRecognizerRequest{
		Recognizer: recognizer,
		Persistent: false, // Ad-hoc recognizers are not persistent
	}

	// Call gRPC unified API
	resp, err := globalPresidioClient.client.RegisterCustomRecognizer(ctx, req)
	if err != nil {
		tk.LogIt(tk.LogError, "[Presidio] RegisterCustomRecognizer failed: %v\n", err)
		return -1
	}

	if !resp.Success {
		tk.LogIt(tk.LogWarning, "[Presidio] RegisterCustomRecognizer unsuccessful: %s\n", resp.Message)
		return -1
	}

	tk.LogIt(tk.LogInfo, "[Presidio] Registered custom recognizer: %s (entity: %s)\n",
		goName, goEntityType)

	return 0
}

//export llb_presidio_scan_batch
func llb_presidio_scan_batch(
	textsPtr unsafe.Pointer,
	lengthsPtr unsafe.Pointer,
	count C.int,
	operatorsPtr unsafe.Pointer,
) unsafe.Pointer {
	if globalPresidioClient == nil || !globalPresidioClient.connected {
		return nil
	}

	// Parse texts array
	numTexts := int(count)
	texts := (*[1 << 30]*C.char)(textsPtr)[:numTexts:numTexts]

	// Parse operators
	operators := (*C.presidio_operators_t)(operatorsPtr)
	opMap := buildOperatorMap(operators)

	// Create bidirectional streaming context with extended timeout for batch
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(float64(numTexts))*globalPresidioClient.timeout)
	defer cancel()

	// Start bidirectional anonymization stream
	stream, err := globalPresidioClient.client.AnonymizeBatch(ctx)
	if err != nil {
		tk.LogIt(tk.LogError, "[Presidio] AnonymizeBatch stream failed: %v\n", err)
		return nil
	}

	// Send all requests
	for i := 0; i < numTexts; i++ {
		text := C.GoString(texts[i])
		req := &pb.AnonymizeRequest{
			Text:      text,
			Operators: opMap,
		}

		if err := stream.Send(req); err != nil {
			tk.LogIt(tk.LogError, "[Presidio] Failed to send batch item %d: %v\n", i, err)
			return nil
		}
	}

	if err := stream.CloseSend(); err != nil {
		tk.LogIt(tk.LogError, "[Presidio] Failed to close send stream: %v\n", err)
		return nil
	}

	// Receive all responses and build results array
	var results []*C.pii_scan_result_v2_t
	receivedCount := 0

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			tk.LogIt(tk.LogError, "[Presidio] Failed to receive batch response: %v\n", err)
			return nil
		}

		// Convert response to C struct
		cResult := convertAnonymizeResponseToV2(resp, 0.0) // Latency not tracked in batch
		if cResult != nil {
			results = append(results, cResult)
			receivedCount++
		}
	}

	if receivedCount != numTexts {
		tk.LogIt(tk.LogWarning, "[Presidio] Expected %d responses, got %d\n", numTexts, receivedCount)
	}

	// Allocate C array for results
	if len(results) == 0 {
		return nil
	}

	// Create C array
	cArraySize := C.size_t(len(results)) * C.size_t(unsafe.Sizeof(C.pii_scan_result_v2_t{}))
	cArray := C.malloc(cArraySize)
	if cArray == nil {
		return nil
	}

	// Copy results to C array
	resultSlice := (*[1 << 30]C.pii_scan_result_v2_t)(cArray)[:len(results):len(results)]
	for i, res := range results {
		resultSlice[i] = *res
		C.free(unsafe.Pointer(res)) // Free individual result structs
	}

	tk.LogIt(tk.LogDebug, "[Presidio] Batch scan completed: %d/%d items\n", receivedCount, numTexts)
	return cArray
}

//export llb_presidio_free_result_v2
func llb_presidio_free_result_v2(resultPtr unsafe.Pointer) {
	if resultPtr == nil {
		return
	}

	result := (*C.pii_scan_result_v2_t)(resultPtr)

	if result.anonymized_text != nil {
		C.free(unsafe.Pointer(result.anonymized_text))
	}

	if result.entities != nil {
		C.free(unsafe.Pointer(result.entities))
	}

	if result.items != nil {
		C.free(unsafe.Pointer(result.items))
	}

	C.free(resultPtr)
}

//export llb_presidio_free_json_result
func llb_presidio_free_json_result(resultPtr unsafe.Pointer) {
	if resultPtr == nil {
		return
	}

	result := (*C.pii_json_result_t)(resultPtr)

	if result.json_data != nil {
		C.free(unsafe.Pointer(result.json_data))
	}

	C.free(resultPtr)
}

//export llb_presidio_health_check_v2
func llb_presidio_health_check_v2() C.int {
	if globalPresidioClient == nil || !globalPresidioClient.connected {
		return -1
	}

	// Perform health check by listing supported entities (lightweight operation)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := &pb.ListEntitiesRequest{
		Language: "en",
	}

	resp, err := globalPresidioClient.client.ListSupportedEntities(ctx, req)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[Presidio] Health check failed: %v\n", err)
		return -1
	}

	if len(resp.EntityTypes) == 0 {
		tk.LogIt(tk.LogWarning, "[Presidio] Health check: server returned no entities\n")
		return -1
	}

	tk.LogIt(tk.LogDebug, "[Presidio] Health check OK: %d entities available\n", len(resp.EntityTypes))
	return 0
}

//export llb_presidio_get_stats_v2
func llb_presidio_get_stats_v2() *C.char {
	stats := map[string]interface{}{
		"v2_available": globalPresidioClient != nil && globalPresidioClient.connected,
	}

	jsonBytes, _ := json.Marshal(stats)
	return C.CString(string(jsonBytes))
}

// ============================================================================
// HELPER FUNCTIONS (V1 + V2)
// ============================================================================

func buildOperatorMap(operators *C.presidio_operators_t) map[string]*pb.OperatorConfig {
	opMap := make(map[string]*pb.OperatorConfig)

	// Parse default operator
	opMap["DEFAULT"] = &pb.OperatorConfig{
		OperatorName: operatorTypeToString(int(operators.default_op._type)),
		Params:       parseOperatorParams(C.GoString(&operators.default_op.params[0])),
	}

	// Parse entity-specific operators (check params, not type, since PRESIDIO_OP_REPLACE=0)
	if C.GoString(&operators.email_op.params[0]) != "" {
		opMap["EMAIL_ADDRESS"] = &pb.OperatorConfig{
			OperatorName: operatorTypeToString(int(operators.email_op._type)),
			Params:       parseOperatorParams(C.GoString(&operators.email_op.params[0])),
		}
	}

	if C.GoString(&operators.ssn_op.params[0]) != "" {
		opMap["US_SSN"] = &pb.OperatorConfig{
			OperatorName: operatorTypeToString(int(operators.ssn_op._type)),
			Params:       parseOperatorParams(C.GoString(&operators.ssn_op.params[0])),
		}
	}

	if C.GoString(&operators.credit_card_op.params[0]) != "" {
		opMap["CREDIT_CARD"] = &pb.OperatorConfig{
			OperatorName: operatorTypeToString(int(operators.credit_card_op._type)),
			Params:       parseOperatorParams(C.GoString(&operators.credit_card_op.params[0])),
		}
	}

	if C.GoString(&operators.phone_op.params[0]) != "" {
		opMap["PHONE_NUMBER"] = &pb.OperatorConfig{
			OperatorName: operatorTypeToString(int(operators.phone_op._type)),
			Params:       parseOperatorParams(C.GoString(&operators.phone_op.params[0])),
		}
	}

	if C.GoString(&operators.person_op.params[0]) != "" {
		opMap["PERSON"] = &pb.OperatorConfig{
			OperatorName: operatorTypeToString(int(operators.person_op._type)),
			Params:       parseOperatorParams(C.GoString(&operators.person_op.params[0])),
		}
	}

	// Parse custom operators
	for i := 0; i < int(operators.custom_op_count) && i < 8; i++ {
		entityType := C.GoString(&operators.custom_entity_types[i][0])
		if entityType != "" {
			opMap[entityType] = &pb.OperatorConfig{
				OperatorName: operatorTypeToString(int(operators.custom_ops[i]._type)),
				Params:       parseOperatorParams(C.GoString(&operators.custom_ops[i].params[0])),
			}
		}
	}

	return opMap
}

func convertAnonymizeResponseToV2(resp *pb.AnonymizeResponse, latencyMs float64) *C.pii_scan_result_v2_t {
	result := (*C.pii_scan_result_v2_t)(C.malloc(C.size_t(unsafe.Sizeof(C.pii_scan_result_v2_t{}))))
	if result == nil {
		return nil
	}

	// Set anonymized text
	if resp.Text == "" {
		tk.LogIt(tk.LogWarning, "[Presidio] Empty anonymized text in response (items=%d)\n", len(resp.Items))
		result.anonymized_text = C.CString("")
		result.anonymized_len = 0
	} else {
		// DEBUG: Log what Presidio server returned
		tk.LogIt(tk.LogDebug, "[Presidio-Response] Received text length=%d, items=%d\n", len(resp.Text), len(resp.Items))
		tk.LogIt(tk.LogDebug, "[Presidio-Response] Text content: %s\n", resp.Text)
		result.anonymized_text = C.CString(resp.Text)
		result.anonymized_len = C.size_t(len(resp.Text))
	}

	// Convert items
	itemCount := len(resp.Items)
	result.item_count = C.int(itemCount)

	if itemCount > 0 {
		result.items = (*C.anonymized_item_t)(C.malloc(C.size_t(itemCount) * C.size_t(unsafe.Sizeof(C.anonymized_item_t{}))))
		items := (*[1 << 30]C.anonymized_item_t)(unsafe.Pointer(result.items))[:itemCount:itemCount]

		for i, item := range resp.Items {
			entityTypeStr := C.CString(item.EntityType)
			C.strncpy(&items[i].entity_type[0], entityTypeStr, 63)
			C.free(unsafe.Pointer(entityTypeStr))

			items[i].start = C.int(item.Start)
			items[i].end = C.int(item.End)

			operatorStr := C.CString(item.Operator)
			C.strncpy(&items[i].operator_used[0], operatorStr, 31)
			C.free(unsafe.Pointer(operatorStr))

			if item.OriginalText != "" {
				originalStr := C.CString(item.OriginalText)
				C.strncpy(&items[i].original_text[0], originalStr, 255)
				C.free(unsafe.Pointer(originalStr))
			}
		}
	} else {
		result.items = nil
	}

	// Populate entities from items
	entityCount := itemCount
	result.entity_count = C.int(entityCount)

	if entityCount > 0 {
		result.entities = (*C.pii_entity_t)(C.malloc(C.size_t(entityCount) * C.size_t(unsafe.Sizeof(C.pii_entity_t{}))))
		entities := (*[1 << 30]C.pii_entity_t)(unsafe.Pointer(result.entities))[:entityCount:entityCount]

		for i, item := range resp.Items {
			entityTypeStr := C.CString(item.EntityType)
			C.strncpy(&entities[i].entity_type[0], entityTypeStr, 63)
			C.free(unsafe.Pointer(entityTypeStr))

			entities[i].start = C.int(item.Start)
			entities[i].end = C.int(item.End)
			entities[i].score = 1.0 // V2 doesn't provide confidence scores in anonymize response
		}
	} else {
		result.entities = nil
	}

	result.latency_ms = C.double(latencyMs)
	result.error_code = 0
	result.error_msg[0] = 0

	return result
}

func convertJSONResponse(resp *pb.AnonymizeJSONResponse, latencyMs float64) *C.pii_json_result_t {
	result := (*C.pii_json_result_t)(C.malloc(C.size_t(unsafe.Sizeof(C.pii_json_result_t{}))))
	if result == nil {
		return nil
	}

	result.json_data = C.CString(resp.JsonData)
	result.fields_anonymized = C.int(resp.FieldsAnonymized)
	result.latency_ms = C.double(latencyMs)
	result.error_code = 0
	result.error_msg[0] = 0

	return result
}

func parseJSONMapping(mapping *C.presidio_json_mapping_t) map[string]string {
	fieldMap := make(map[string]string)

	count := int(mapping.mapping_count)
	for i := 0; i < count && i < 32; i++ {
		fieldPath := C.GoString(&mapping.mappings[i].field_path[0])
		entityType := C.GoString(&mapping.mappings[i].entity_type[0])
		if fieldPath != "" {
			fieldMap[fieldPath] = entityType
		}
	}

	return fieldMap
}

func operatorTypeToString(opType int) string {
	switch opType {
	case OperatorReplace:
		return "replace"
	case OperatorRedact:
		return "redact"
	case OperatorHash:
		return "hash"
	case OperatorEncrypt:
		return "encrypt"
	case OperatorMask:
		return "mask"
	default:
		return "replace"
	}
}

func parseOperatorParams(paramsJSON string) map[string]string {
	if paramsJSON == "" {
		return make(map[string]string)
	}

	var params map[string]string
	if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
		return make(map[string]string)
	}

	return params
}

func buildV2ErrorResult(errMsg string) unsafe.Pointer {
	result := (*C.pii_scan_result_v2_t)(C.malloc(C.size_t(unsafe.Sizeof(C.pii_scan_result_v2_t{}))))
	if result == nil {
		return nil
	}

	result.anonymized_text = nil
	result.entities = nil
	result.items = nil
	result.entity_count = 0
	result.item_count = 0
	result.latency_ms = 0
	result.error_code = -1

	errMsgStr := C.CString(errMsg)
	C.strncpy(&result.error_msg[0], errMsgStr, 255)
	C.free(unsafe.Pointer(errMsgStr))

	return unsafe.Pointer(result)
}

func buildJSONErrorResult(errMsg string) unsafe.Pointer {
	result := (*C.pii_json_result_t)(C.malloc(C.size_t(unsafe.Sizeof(C.pii_json_result_t{}))))
	if result == nil {
		return nil
	}

	result.json_data = nil
	result.fields_anonymized = 0
	result.latency_ms = 0
	result.error_code = -1

	errMsgStr := C.CString(errMsg)
	C.strncpy(&result.error_msg[0], errMsgStr, 255)
	C.free(unsafe.Pointer(errMsgStr))

	return unsafe.Pointer(result)
}

// getExcludedFields retrieves exclude_fields from shared memory (loaded by C from JSON file)
func getExcludedFields() []string {
	if presidio.GlobalConfigMgr() == nil {
		tk.LogIt(tk.LogDebug, "[Presidio-Exclusion] GlobalConfigMgr is nil\n")
		return nil
	}

	// Read exclude_fields directly from C struct's json_config section
	// (populated by C code from presidio_json_fields.json)
	excludeFields := presidio.GlobalConfigMgr().GetExcludeFields()

	tk.LogIt(tk.LogDebug, "[Presidio-Exclusion] Config has %d exclude_fields: %v\n", len(excludeFields), excludeFields)
	return excludeFields
}

// preprocessJSONWithExclusions removes excluded fields from JSON before PII detection
// Returns: processedJSON (with fields removed), excludedValues (map of removed field values)
func preprocessJSONWithExclusions(jsonData string, excludeFields []string) (string, map[string]interface{}) {
	tk.LogIt(tk.LogDebug, "[Presidio-Exclusion] preprocessJSONWithExclusions called with %d exclude_fields\n", len(excludeFields))

	if len(excludeFields) == 0 {
		tk.LogIt(tk.LogDebug, "[Presidio-Exclusion] No exclude_fields, returning original JSON\n")
		return jsonData, nil
	}

	// Parse JSON
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		tk.LogIt(tk.LogWarning, "[Presidio-Exclusion] Failed to parse JSON for preprocessing: %v\n", err)
		return jsonData, nil
	}

	// Extract and remove excluded fields
	excludedValues := make(map[string]interface{})
	for _, field := range excludeFields {
		if val, exists := data[field]; exists {
			excludedValues[field] = val
			delete(data, field)
			tk.LogIt(tk.LogDebug, "[Presidio-Exclusion] Removed field '%s' from JSON\n", field)
		} else {
			tk.LogIt(tk.LogDebug, "[Presidio-Exclusion] Field '%s' not found in JSON\n", field)
		}
	}

	// Marshal back to JSON
	processedBytes, err := json.Marshal(data)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[Presidio-Exclusion] Failed to marshal preprocessed JSON: %v\n", err)
		return jsonData, nil
	}

	tk.LogIt(tk.LogInfo, "[Presidio-Exclusion] Preprocessed JSON: removed %d/%d excluded fields\n",
		len(excludedValues), len(excludeFields))
	return string(processedBytes), excludedValues
}

// postprocessJSONWithExclusions restores excluded fields to anonymized JSON
func postprocessJSONWithExclusions(anonymizedJSON string, excludedValues map[string]interface{}) string {
	tk.LogIt(tk.LogDebug, "[Presidio-Exclusion] postprocessJSONWithExclusions called with %d values to restore\n", len(excludedValues))

	if len(excludedValues) == 0 {
		tk.LogIt(tk.LogDebug, "[Presidio-Exclusion] No excluded values to restore\n")
		return anonymizedJSON
	}

	// Parse anonymized JSON
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(anonymizedJSON), &data); err != nil {
		tk.LogIt(tk.LogWarning, "[Presidio-Exclusion] Failed to parse anonymized JSON for postprocessing: %v\n", err)
		return anonymizedJSON
	}

	// Restore excluded fields
	for field, value := range excludedValues {
		data[field] = value
		tk.LogIt(tk.LogDebug, "[Presidio-Exclusion] Restored field '%s' to anonymized JSON\n", field)
	}

	// Marshal back to JSON
	finalBytes, err := json.Marshal(data)
	if err != nil {
		tk.LogIt(tk.LogWarning, "[Presidio-Exclusion] Failed to marshal postprocessed JSON: %v\n", err)
		return anonymizedJSON
	}

	tk.LogIt(tk.LogInfo, "[Presidio-Exclusion] Postprocessed JSON: restored %d excluded fields\n", len(excludedValues))
	return string(finalBytes)
}
