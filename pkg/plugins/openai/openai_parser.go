/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSlause
 */

// OpenAI Protocol Parser - Production parser for OpenAI API deep inspection
// Supports: Chat Completions, Completions, Embeddings, Streaming responses
// Extracts: Model info, token usage, function/tool calls, cost estimation
package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/loxilb-io/loxilb/pkg/parser"
	tk "github.com/loxilb-io/loxilib"
)

// OpenAIParser implements PayloadParser for OpenAI APIs
type OpenAIParser struct {
	enableDebug bool // Set via environment variable for debugging
}

// NewOpenAIParser creates OpenAI parser with optional debug logging
func NewOpenAIParser() *OpenAIParser {
	debugEnabled := os.Getenv("LOXILB_TRACE_DEBUG") != ""
	if debugEnabled {
		tk.LogIt(tk.LogDebug, "[OpenAIParser] Debug logging enabled\n")
	}
	return &OpenAIParser{
		enableDebug: debugEnabled,
	}
}

// Parse implements PayloadParser interface
func (p *OpenAIParser) Parse(ctx context.Context, req *parser.ParseRequest) (*parser.ParseResponse, error) {
	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[OpenAIParser] Parsing %s request to %s (%d bytes)\n",
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
	attrs["openai.path"] = req.Path
	attrs["openai.catalog_id"] = req.CatalogID

	return &parser.ParseResponse{
		Attributes: attrs,
	}, nil
}

// Metadata returns OpenAI parser information
func (p *OpenAIParser) Metadata() parser.PluginMetadata {
	return parser.PluginMetadata{
		Name:        "openai_v1",
		Version:     "1.0.0",
		Protocol:    "openai",
		Description: "OpenAI-compatible API parser with token tracking and cost estimation",
		Author:      "LoxiLB Team",
		SupportedPaths: []string{
			"/v1/chat/completions",
			"/v1/completions",
			"/v1/embeddings",
			"/v1/images/generations",
			"/v1/audio/transcriptions",
		},
		SupportsStreaming: true,
		SupportsRedaction: false,
	}
}

// Validate checks if body is valid OpenAI JSON format
func (p *OpenAIParser) Validate(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	// Quick JSON validation
	var js map[string]interface{}
	if err := json.Unmarshal(body, &js); err != nil {
		return false
	}

	// Check for OpenAI request signatures
	if _, hasModel := js["model"]; hasModel {
		return true
	}

	// Check for OpenAI response signatures
	if _, hasID := js["id"]; hasID {
		if _, hasObject := js["object"]; hasObject {
			return true
		}
	}

	// Check for streaming SSE format
	if bytes.HasPrefix(body, []byte("data: ")) {
		return true
	}

	return false
}

// parseRequest extracts attributes from OpenAI API requests
func (p *OpenAIParser) parseRequest(body []byte) map[string]interface{} {
	attrs := make(map[string]interface{})
	attrs["openai.body.size"] = len(body)

	// Parse JSON structure
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		tk.LogIt(tk.LogWarning, "[OpenAIParser] Request JSON parse error: %v\n", err)
		attrs["openai.parse_error"] = true
		return attrs
	}

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[OpenAIParser] Parsed request JSON: %d top-level keys\n", len(req))
	}

	// Extract model (required for all OpenAI APIs)
	if model, ok := req["model"].(string); ok {
		attrs["openai.model"] = model
		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[OpenAIParser] Detected model: %s\n", model)
		}
	}

	// Detect API type by structure
	apiType := detectAPIType(req)
	attrs["openai.api_type"] = apiType

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[OpenAIParser] Detected API type: %s\n", apiType)
	}

	// API-specific extraction
	switch apiType {
	case "chat_completions":
		p.extractChatCompletionsRequest(req, attrs)
	case "completions":
		p.extractCompletionsRequest(req, attrs)
	case "embeddings":
		p.extractEmbeddingsRequest(req, attrs)
	}

	// Common parameters
	if temp, ok := req["temperature"].(float64); ok {
		attrs["openai.temperature"] = temp
	}
	if maxTokens, ok := req["max_tokens"].(float64); ok {
		attrs["openai.max_tokens"] = int(maxTokens)
	}
	if stream, ok := req["stream"].(bool); ok {
		attrs["openai.stream"] = stream
	}

	// Estimate input tokens (simple heuristic: ~4 chars per token)
	estimatedTokens := len(body) / 4
	attrs["openai.estimated_input_tokens"] = estimatedTokens

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[OpenAIParser] Extracted %d attributes from request\n", len(attrs))
	}

	return attrs
}

// parseResponse extracts attributes from OpenAI API responses
func (p *OpenAIParser) parseResponse(body []byte) map[string]interface{} {
	attrs := make(map[string]interface{})
	attrs["openai.body.size"] = len(body)

	// Check if streaming response (SSE format)
	if isStreamingSSE(body) {
		return p.parseStreamingResponse(body, attrs)
	}

	// Parse JSON response
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		tk.LogIt(tk.LogWarning, "[OpenAIParser] Response JSON parse error: %v\n", err)
		attrs["openai.parse_error"] = true
		return attrs
	}

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[OpenAIParser] Parsed response JSON: %d top-level keys\n", len(resp))
	}

	// Extract usage information (tokens)
	if usage, ok := resp["usage"].(map[string]interface{}); ok {
		if promptTokens, ok := usage["prompt_tokens"].(float64); ok {
			attrs["openai.usage.prompt_tokens"] = int(promptTokens)
		}
		if completionTokens, ok := usage["completion_tokens"].(float64); ok {
			attrs["openai.usage.completion_tokens"] = int(completionTokens)
		}
		if totalTokens, ok := usage["total_tokens"].(float64); ok {
			attrs["openai.usage.total_tokens"] = int(totalTokens)
		}

		// Estimate cost (simplified pricing)
		if model, ok := resp["model"].(string); ok {
			cost := estimateCost(model, usage)
			if cost > 0 {
				attrs["openai.estimated_cost_usd"] = cost
				if p.enableDebug {
					tk.LogIt(tk.LogDebug, "[OpenAIParser] Estimated cost: $%.6f\n", cost)
				}
			}
		}
	}

	// Extract choices (completions)
	if choices, ok := resp["choices"].([]interface{}); ok {
		attrs["openai.choices_count"] = len(choices)

		if len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				// Finish reason
				if finishReason, ok := choice["finish_reason"].(string); ok {
					attrs["openai.finish_reason"] = finishReason
				}

				// Extract message content (for chat completions)
				if message, ok := choice["message"].(map[string]interface{}); ok {
					if content, ok := message["content"].(string); ok {
						preview := truncateString(content, 100)
						attrs["openai.response_preview"] = preview
					}

					// Tool/function calls
					if toolCalls, ok := message["tool_calls"].([]interface{}); ok {
						attrs["openai.tool_calls_count"] = len(toolCalls)
						toolNames := extractToolNames(toolCalls)
						if len(toolNames) > 0 {
							attrs["openai.tool_calls"] = strings.Join(toolNames, ",")
							if p.enableDebug {
								tk.LogIt(tk.LogDebug, "[OpenAIParser] Tool calls: %s\n", strings.Join(toolNames, ","))
							}
						}
					}

					// Function calls (older format)
					if functionCall, ok := message["function_call"].(map[string]interface{}); ok {
						if name, ok := functionCall["name"].(string); ok {
							attrs["openai.function_called"] = name
							if p.enableDebug {
								tk.LogIt(tk.LogDebug, "[OpenAIParser] Function called: %s\n", name)
							}
						}
					}
				}
			}
		}
	}

	// Error detection
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		if errMsg, ok := errObj["message"].(string); ok {
			attrs["openai.error"] = true
			attrs["openai.error_message"] = truncateString(errMsg, 200)
			if errType, ok := errObj["type"].(string); ok {
				attrs["openai.error_type"] = errType
			}
			tk.LogIt(tk.LogWarning, "[OpenAIParser] API error detected: %s\n", errMsg)
		}
	}

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[OpenAIParser] Extracted %d attributes from response\n", len(attrs))
	}

	return attrs
}

// parseStreamingResponse handles Server-Sent Events (SSE) format
func (p *OpenAIParser) parseStreamingResponse(body []byte, attrs map[string]interface{}) map[string]interface{} {
	attrs["openai.streaming"] = true

	scanner := bufio.NewScanner(bytes.NewReader(body))
	chunkCount := 0
	var lastContent strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		chunkCount++

		// Parse JSON chunk
		var chunk map[string]interface{}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}

		// Extract content from delta
		if choices, ok := chunk["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if delta, ok := choice["delta"].(map[string]interface{}); ok {
					if content, ok := delta["content"].(string); ok {
						lastContent.WriteString(content)
					}

					// Tool calls in streaming
					if toolCalls, ok := delta["tool_calls"].([]interface{}); ok && len(toolCalls) > 0 {
						attrs["openai.streaming_tool_calls"] = true
					}
				}
			}
		}
	}

	attrs["openai.stream_chunks"] = chunkCount
	if lastContent.Len() > 0 {
		preview := truncateString(lastContent.String(), 100)
		attrs["openai.response_preview"] = preview
	}

	if p.enableDebug {
		tk.LogIt(tk.LogDebug, "[OpenAIParser] Parsed streaming response: %d chunks\n", chunkCount)
	}

	return attrs
}

// extractChatCompletionsRequest extracts chat-specific attributes
func (p *OpenAIParser) extractChatCompletionsRequest(req map[string]interface{}, attrs parser.ParsedAttributes) {
	if messages, ok := req["messages"].([]interface{}); ok {
		attrs["openai.message_count"] = len(messages)

		// Extract last message for preview
		if len(messages) > 0 {
			if lastMsg, ok := messages[len(messages)-1].(map[string]interface{}); ok {
				if role, ok := lastMsg["role"].(string); ok {
					attrs["openai.last_message_role"] = role
				}
				if content, ok := lastMsg["content"].(string); ok {
					preview := truncateString(content, 100)
					attrs["openai.prompt_preview"] = preview
					if p.enableDebug {
						tk.LogIt(tk.LogDebug, "[OpenAIParser] Prompt preview: %s\n", preview)
					}
				}
			}
		}
	}

	// Function/tool definitions
	if functions, ok := req["functions"].([]interface{}); ok {
		attrs["openai.functions_count"] = len(functions)
	}
	if tools, ok := req["tools"].([]interface{}); ok {
		attrs["openai.tools_count"] = len(tools)
	}

	// Response format (structured output)
	if respFormat, ok := req["response_format"].(map[string]interface{}); ok {
		if formatType, ok := respFormat["type"].(string); ok {
			attrs["openai.response_format"] = formatType
		}
	}
}

// extractCompletionsRequest extracts completions-specific attributes
func (p *OpenAIParser) extractCompletionsRequest(req map[string]interface{}, attrs parser.ParsedAttributes) {
	if prompt, ok := req["prompt"].(string); ok {
		preview := truncateString(prompt, 100)
		attrs["openai.prompt_preview"] = preview
		attrs["openai.prompt_length"] = len(prompt)
		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[OpenAIParser] Prompt length: %d chars\n", len(prompt))
		}
	} else if prompts, ok := req["prompt"].([]interface{}); ok {
		attrs["openai.prompt_count"] = len(prompts)
	}

	if suffix, ok := req["suffix"].(string); ok {
		attrs["openai.has_suffix"] = true
		attrs["openai.suffix_length"] = len(suffix)
	}
}

// extractEmbeddingsRequest extracts embeddings-specific attributes
func (p *OpenAIParser) extractEmbeddingsRequest(req map[string]interface{}, attrs parser.ParsedAttributes) {
	if input, ok := req["input"].(string); ok {
		attrs["openai.input_length"] = len(input)
		attrs["openai.input_type"] = "string"
	} else if inputs, ok := req["input"].([]interface{}); ok {
		attrs["openai.input_count"] = len(inputs)
		attrs["openai.input_type"] = "array"
		if p.enableDebug {
			tk.LogIt(tk.LogDebug, "[OpenAIParser] Embeddings input count: %d\n", len(inputs))
		}
	}

	if dimensions, ok := req["dimensions"].(float64); ok {
		attrs["openai.dimensions"] = int(dimensions)
	}
}

// Helper: Detect API type from request structure
func detectAPIType(req map[string]interface{}) string {
	if _, ok := req["messages"]; ok {
		return "chat_completions"
	}
	if _, ok := req["input"]; ok {
		if _, ok := req["model"]; ok {
			// Embeddings API has 'input' field
			return "embeddings"
		}
	}
	if _, ok := req["prompt"]; ok {
		return "completions"
	}
	return "unknown"
}

// Helper: Check if body is Server-Sent Events format
func isStreamingSSE(body []byte) bool {
	return bytes.HasPrefix(body, []byte("data: ")) ||
		bytes.Contains(body[:min(200, len(body))], []byte("data: {"))
}

// Helper: Estimate cost based on token usage
// Simplified pricing (as of 2024 - should be updated regularly)
func estimateCost(model string, usage map[string]interface{}) float64 {
	promptTokens, _ := usage["prompt_tokens"].(float64)
	completionTokens, _ := usage["completion_tokens"].(float64)

	var inputCostPer1k, outputCostPer1k float64

	// Pricing table (USD per 1K tokens)
	switch {
	case strings.Contains(model, "gpt-4-turbo"):
		inputCostPer1k = 0.01
		outputCostPer1k = 0.03
	case strings.Contains(model, "gpt-4"):
		inputCostPer1k = 0.03
		outputCostPer1k = 0.06
	case strings.Contains(model, "gpt-3.5-turbo"):
		inputCostPer1k = 0.0005
		outputCostPer1k = 0.0015
	default:
		return 0.0 // Unknown model
	}

	inputCost := (promptTokens / 1000.0) * inputCostPer1k
	outputCost := (completionTokens / 1000.0) * outputCostPer1k

	return inputCost + outputCost
}

// Helper: Extract tool names from tool_calls array
func extractToolNames(toolCalls []interface{}) []string {
	var names []string
	for _, tc := range toolCalls {
		if tcMap, ok := tc.(map[string]interface{}); ok {
			if function, ok := tcMap["function"].(map[string]interface{}); ok {
				if name, ok := function["name"].(string); ok {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

// Helper: Truncate string with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Helper: Min function for int
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
