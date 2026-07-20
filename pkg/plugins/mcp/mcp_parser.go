/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSlause
 */

// MCP Protocol Parser - Production parser for Model Context Protocol deep inspection
// Supports: JSON-RPC 2.0, Tools API, Prompts API, Resources API
// Extracts: Method names, tool calls, prompt requests, resource access, error categorization
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/loxilb-io/loxilb/pkg/parser"
	tk "github.com/loxilb-io/loxilib"
)

// MCPParser implements PayloadParser for Model Context Protocol
type MCPParser struct {
	enableDebug bool // Set via environment variable for debugging
}

// NewMCPParser creates MCP parser with optional debug logging
func NewMCPParser() *MCPParser {
	debugEnabled := os.Getenv("LOXILB_TRACE_DEBUG") != ""
	if debugEnabled {
		tk.LogIt(tk.LogDebug, "[MCPParser] Debug logging enabled\n")
	}
	return &MCPParser{
		enableDebug: debugEnabled,
	}
}

// Parse implements PayloadParser interface
func (p *MCPParser) Parse(ctx context.Context, req *parser.ParseRequest) (*parser.ParseResponse, error) {
	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[MCPParser] Parsing %s request to %s (%d bytes)\n",
			req.Method, req.Path, len(req.Body))
	}

	// Determine if this is a request or response based on Method presence
	isRequest := req.Method != ""

	var attrs map[string]interface{}
	if isRequest {
		attrs = p.parseRequest(req.Body)
	} else {
		attrs = p.parseResponse(req.Body)
	}

	// Add metadata from request
	attrs["mcp.path"] = req.Path
	attrs["mcp.catalog_id"] = req.CatalogID

	return &parser.ParseResponse{
		Attributes: attrs,
	}, nil
}

// Metadata returns MCP parser information
func (p *MCPParser) Metadata() parser.PluginMetadata {
	return parser.PluginMetadata{
		Name:        "mcp_v1",
		Version:     "1.0.0",
		Protocol:    "mcp",
		Description: "Model Context Protocol (JSON-RPC 2.0) parser with tool/prompt/resource tracking",
		Author:      "LoxiLB Team",
		SupportedPaths: []string{
			"/mcp",
			"/mcp/v1",
			"/api/mcp",
		},
		SupportsStreaming: false,
		SupportsRedaction: false,
	}
}

// Validate checks if body is valid MCP JSON-RPC 2.0 format
func (p *MCPParser) Validate(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	// Quick JSON validation
	var js map[string]interface{}
	if err := json.Unmarshal(body, &js); err != nil {
		return false
	}

	// Check for JSON-RPC 2.0 signatures
	if jsonrpc, ok := js["jsonrpc"].(string); ok && jsonrpc == "2.0" {
		// Request must have method
		if _, hasMethod := js["method"]; hasMethod {
			return true
		}
		// Response must have result or error
		if _, hasResult := js["result"]; hasResult {
			return true
		}
		if _, hasError := js["error"]; hasError {
			return true
		}
	}

	return false
}

// parseRequest extracts attributes from MCP requests (JSON-RPC 2.0 format)
func (p *MCPParser) parseRequest(body []byte) map[string]interface{} {
	attrs := make(map[string]interface{})
	attrs["mcp.body.size"] = len(body)
	attrs["mcp.message_type"] = "request"

	// Parse JSON-RPC 2.0 structure
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		tk.LogIt(tk.LogWarning, "[MCPParser] Request JSON parse error: %v\n", err)
		attrs["mcp.parse_error"] = true
		return attrs
	}

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[MCPParser] Parsed request JSON: %d top-level keys\n", len(req))
	}

	// Validate JSON-RPC 2.0 format
	if jsonrpc, ok := req["jsonrpc"].(string); ok {
		attrs["mcp.jsonrpc_version"] = jsonrpc
		if jsonrpc != "2.0" {
			tk.LogIt(tk.LogWarning, "[MCPParser] Invalid JSON-RPC version: %s\n", jsonrpc)
			attrs["mcp.invalid_version"] = true
		}
	}

	// Extract request ID (can be string or number)
	if id, ok := req["id"]; ok {
		attrs["mcp.request_id"] = fmt.Sprintf("%v", id)
	}

	// Extract method (required for JSON-RPC requests)
	method, ok := req["method"].(string)
	if !ok {
		tk.LogIt(tk.LogWarning, "[MCPParser] Missing or invalid 'method' field\n")
		attrs["mcp.invalid_request"] = true
		return attrs
	}

	attrs["mcp.method"] = method
	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[MCPParser] Method: %s\n", method)
	}

	// Extract params
	params, hasParams := req["params"]
	if hasParams {
		attrs["mcp.has_params"] = true

		// Method-specific parameter extraction
		switch method {
		case "initialize":
			p.extractInitializeParams(params, attrs)
		case "tools/list":
			p.extractToolsListParams(params, attrs)
		case "tools/call":
			p.extractToolsCallParams(params, attrs)
		case "prompts/list":
			p.extractPromptsListParams(params, attrs)
		case "prompts/get":
			p.extractPromptsGetParams(params, attrs)
		case "resources/list":
			p.extractResourcesListParams(params, attrs)
		case "resources/read":
			p.extractResourcesReadParams(params, attrs)
		case "resources/subscribe":
			p.extractResourcesSubscribeParams(params, attrs)
		case "completion/complete":
			p.extractCompletionParams(params, attrs)
		default:
			if p.enableDebug {
				tk.LogIt(tk.LogDebug, "[MCPParser] Unknown method: %s\n", method)
			}
			attrs["mcp.method_category"] = "unknown"
		}
	}

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[MCPParser] Extracted %d attributes from request\n", len(attrs))
	}

	return attrs
}

// parseResponse extracts attributes from MCP responses
func (p *MCPParser) parseResponse(body []byte) map[string]interface{} {
	attrs := make(map[string]interface{})
	attrs["mcp.body.size"] = len(body)
	attrs["mcp.message_type"] = "response"

	// Parse JSON-RPC 2.0 structure
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		tk.LogIt(tk.LogWarning, "[MCPParser] Response JSON parse error: %v\n", err)
		attrs["mcp.parse_error"] = true
		return attrs
	}

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[MCPParser] Parsed response JSON: %d top-level keys\n", len(resp))
	}

	// Validate JSON-RPC 2.0 format
	if jsonrpc, ok := resp["jsonrpc"].(string); ok {
		attrs["mcp.jsonrpc_version"] = jsonrpc
	}

	// Extract response ID (correlates with request)
	if id, ok := resp["id"]; ok {
		attrs["mcp.response_id"] = fmt.Sprintf("%v", id)
	}

	// Check for error response
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		p.extractErrorInfo(errObj, attrs)
		return attrs
	}

	// Extract result
	if result, ok := resp["result"]; ok {
		attrs["mcp.has_result"] = true
		p.extractResultInfo(result, attrs)
	}

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[MCPParser] Extracted %d attributes from response\n", len(attrs))
	}

	return attrs
}

// extractInitializeParams extracts initialization handshake parameters
func (p *MCPParser) extractInitializeParams(params interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.method_category"] = "initialization"

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return
	}

	if protocolVersion, ok := paramsMap["protocolVersion"].(string); ok {
		attrs["mcp.protocol_version"] = protocolVersion
		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[MCPParser] Protocol version: %s\n", protocolVersion)
		}
	}

	if clientInfo, ok := paramsMap["clientInfo"].(map[string]interface{}); ok {
		if name, ok := clientInfo["name"].(string); ok {
			attrs["mcp.client_name"] = name
		}
		if version, ok := clientInfo["version"].(string); ok {
			attrs["mcp.client_version"] = version
		}
	}

	if capabilities, ok := paramsMap["capabilities"].(map[string]interface{}); ok {
		attrs["mcp.client_capabilities"] = len(capabilities)
		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[MCPParser] Client capabilities: %d\n", len(capabilities))
		}
	}
}

// extractToolsListParams extracts tools list parameters
func (p *MCPParser) extractToolsListParams(params interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.method_category"] = "tools"

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return
	}

	if cursor, ok := paramsMap["cursor"].(string); ok {
		attrs["mcp.has_cursor"] = true
		attrs["mcp.cursor_length"] = len(cursor)
	}
}

// extractToolsCallParams extracts tool call parameters
func (p *MCPParser) extractToolsCallParams(params interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.method_category"] = "tools"

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return
	}

	if name, ok := paramsMap["name"].(string); ok {
		attrs["mcp.tool_name"] = name
		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[MCPParser] Tool call: %s\n", name)
		}
	}

	if arguments, ok := paramsMap["arguments"].(map[string]interface{}); ok {
		attrs["mcp.argument_count"] = len(arguments)

		// Extract common argument patterns
		if filePath, ok := arguments["path"].(string); ok {
			attrs["mcp.file_path"] = filePath
		}
		if query, ok := arguments["query"].(string); ok {
			attrs["mcp.query_length"] = len(query)
		}

		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[MCPParser] Tool arguments: %d\n", len(arguments))
		}
	}
}

// extractPromptsListParams extracts prompts list parameters
func (p *MCPParser) extractPromptsListParams(params interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.method_category"] = "prompts"

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return
	}

	if _, ok := paramsMap["cursor"].(string); ok {
		attrs["mcp.has_cursor"] = true
	}
}

// extractPromptsGetParams extracts prompt get parameters
func (p *MCPParser) extractPromptsGetParams(params interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.method_category"] = "prompts"

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return
	}

	if name, ok := paramsMap["name"].(string); ok {
		attrs["mcp.prompt_name"] = name
		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[MCPParser] Prompt get: %s\n", name)
		}
	}

	if arguments, ok := paramsMap["arguments"].(map[string]interface{}); ok {
		attrs["mcp.prompt_argument_count"] = len(arguments)
	}
}

// extractResourcesListParams extracts resources list parameters
func (p *MCPParser) extractResourcesListParams(params interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.method_category"] = "resources"

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return
	}

	if _, ok := paramsMap["cursor"].(string); ok {
		attrs["mcp.has_cursor"] = true
	}
}

// extractResourcesReadParams extracts resource read parameters
func (p *MCPParser) extractResourcesReadParams(params interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.method_category"] = "resources"

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return
	}

	if uri, ok := paramsMap["uri"].(string); ok {
		attrs["mcp.resource_uri"] = uri
		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[MCPParser] Resource read: %s\n", uri)
		}
	}
}

// extractResourcesSubscribeParams extracts resource subscribe parameters
func (p *MCPParser) extractResourcesSubscribeParams(params interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.method_category"] = "resources"

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return
	}

	if uri, ok := paramsMap["uri"].(string); ok {
		attrs["mcp.resource_uri"] = uri
		attrs["mcp.subscription"] = true
	}
}

// extractCompletionParams extracts completion/autocomplete parameters
func (p *MCPParser) extractCompletionParams(params interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.method_category"] = "completion"

	paramsMap, ok := params.(map[string]interface{})
	if !ok {
		return
	}

	if ref, ok := paramsMap["ref"].(map[string]interface{}); ok {
		if refType, ok := ref["type"].(string); ok {
			attrs["mcp.completion_ref_type"] = refType
		}
	}

	if argument, ok := paramsMap["argument"].(map[string]interface{}); ok {
		if name, ok := argument["name"].(string); ok {
			attrs["mcp.completion_argument"] = name
		}
	}
}

// extractErrorInfo extracts error information from response
func (p *MCPParser) extractErrorInfo(errObj map[string]interface{}, attrs parser.ParsedAttributes) {
	attrs["mcp.error"] = true

	if code, ok := errObj["code"].(float64); ok {
		errorCode := int(code)
		attrs["mcp.error_code"] = errorCode
		attrs["mcp.error_category"] = categorizeErrorCode(errorCode)

		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[MCPParser] Error code: %d\n", errorCode)
		}
	}

	if message, ok := errObj["message"].(string); ok {
		attrs["mcp.error_message"] = truncateString(message, 200)
		tk.LogIt(tk.LogWarning, "[MCPParser] MCP error: %s\n", message)
	}

	if data, ok := errObj["data"]; ok {
		attrs["mcp.error_has_data"] = true
		if dataMap, ok := data.(map[string]interface{}); ok {
			attrs["mcp.error_data_keys"] = len(dataMap)
		}
	}
}

// extractResultInfo extracts result information from successful response
func (p *MCPParser) extractResultInfo(result interface{}, attrs parser.ParsedAttributes) {
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return
	}

	// Tools list response
	if tools, ok := resultMap["tools"].([]interface{}); ok {
		attrs["mcp.result_type"] = "tools_list"
		attrs["mcp.tools_count"] = len(tools)

		toolNames := extractToolNamesFromList(tools)
		if len(toolNames) > 0 {
			attrs["mcp.tool_names"] = strings.Join(toolNames, ",")
			if p.enableDebug {
				tk.LogIt(tk.LogDebug, "[MCPParser] Tools list: %s\n", strings.Join(toolNames, ","))
			}
		}
	}

	// Tool call result (content array)
	if content, ok := resultMap["content"].([]interface{}); ok {
		attrs["mcp.result_type"] = "content"
		attrs["mcp.content_items"] = len(content)

		// Extract content types
		contentTypes := extractContentTypes(content)
		if len(contentTypes) > 0 {
			attrs["mcp.content_types"] = strings.Join(contentTypes, ",")
		}
	}

	// Prompts list response
	if prompts, ok := resultMap["prompts"].([]interface{}); ok {
		attrs["mcp.result_type"] = "prompts_list"
		attrs["mcp.prompts_count"] = len(prompts)
	}

	// Prompt get response
	if description, ok := resultMap["description"].(string); ok {
		attrs["mcp.result_type"] = "prompt"
		attrs["mcp.prompt_description_length"] = len(description)
	}

	// Resources list response
	if resources, ok := resultMap["resources"].([]interface{}); ok {
		attrs["mcp.result_type"] = "resources_list"
		attrs["mcp.resources_count"] = len(resources)
	}

	// Resource read response
	if contents, ok := resultMap["contents"].([]interface{}); ok {
		attrs["mcp.result_type"] = "resource_contents"
		attrs["mcp.resource_content_items"] = len(contents)
	}

	// Server info (from initialize response)
	if serverInfo, ok := resultMap["serverInfo"].(map[string]interface{}); ok {
		attrs["mcp.result_type"] = "initialize"
		if name, ok := serverInfo["name"].(string); ok {
			attrs["mcp.server_name"] = name
		}
		if version, ok := serverInfo["version"].(string); ok {
			attrs["mcp.server_version"] = version
		}
	}

	// Completion response
	if completion, ok := resultMap["completion"].(map[string]interface{}); ok {
		attrs["mcp.result_type"] = "completion"
		if values, ok := completion["values"].([]interface{}); ok {
			attrs["mcp.completion_values_count"] = len(values)
		}
	}
}

// categorizeErrorCode maps JSON-RPC error codes to categories
func categorizeErrorCode(code int) string {
	switch code {
	case -32700:
		return "parse_error"
	case -32600:
		return "invalid_request"
	case -32601:
		return "method_not_found"
	case -32602:
		return "invalid_params"
	case -32603:
		return "internal_error"
	default:
		if code >= -32099 && code <= -32000 {
			return "server_error"
		}
		return "application_error"
	}
}

// extractToolNamesFromList extracts tool names from tools array
func extractToolNamesFromList(tools []interface{}) []string {
	var names []string
	for _, tool := range tools {
		if toolMap, ok := tool.(map[string]interface{}); ok {
			if name, ok := toolMap["name"].(string); ok {
				names = append(names, name)
			}
		}
	}
	return names
}

// extractContentTypes extracts content types from content array
func extractContentTypes(content []interface{}) []string {
	var types []string
	seenTypes := make(map[string]bool)

	for _, item := range content {
		if itemMap, ok := item.(map[string]interface{}); ok {
			if contentType, ok := itemMap["type"].(string); ok {
				if !seenTypes[contentType] {
					types = append(types, contentType)
					seenTypes[contentType] = true
				}
			}
		}
	}
	return types
}

// Helper: Truncate string with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
