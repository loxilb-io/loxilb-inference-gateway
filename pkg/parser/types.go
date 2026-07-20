/*
 * Copyright (c) 2025 NetLOX Inc
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

// Package parser defines common types and interfaces for payload parsers
// This package breaks the import cycle between loxinet and parser plugins
package parser

import (
	"context"
	"time"
)

// PayloadParser is the core interface all plugins must implement
// This enables extensible HTTP/HTTPS payload parsing for deep inspection
type PayloadParser interface {
	// Parse extracts structured attributes from HTTP body
	// Context: Used for timeout control (5s default)
	// Request: Contains body, headers, catalog config
	// Response: Map of OpenTelemetry attribute keys to values
	// Error: Parser failures return error WITHOUT breaking tracing
	Parse(ctx context.Context, req *ParseRequest) (*ParseResponse, error)

	// Metadata returns plugin information (name, version, capabilities)
	// Called once during registration
	Metadata() PluginMetadata

	// Validate checks if payload is valid for this parser
	// Used for: auto-detection, early rejection, error prevention
	// Fast path: should return in <1ms
	Validate(body []byte) bool
}

// ParseRequest contains all data needed for parsing
type ParseRequest struct {
	// === HTTP Payload ===
	Body    []byte            // HTTP request/response body
	Headers map[string]string // HTTP headers for context

	// === Request Metadata ===
	Method      string // HTTP method (GET, POST, etc.)
	Path        string // URL path (v1/chat/completions)
	ContentType string // Content-Type header value
	CatalogID   uint16 // Service classification ID

	// === Parser Configuration ===
	Config PluginConfig
}

// ParseResponse contains extracted attributes and optional redacted body
type ParseResponse struct {
	// === Extracted Attributes ===
	Attributes map[string]interface{} // OpenTelemetry attribute key-value pairs

	// === Optional: Redacted Body ===
	RedactedBody []byte // Body with sensitive data removed (future feature)

	// === Optional: Parser Metadata ===
	Metadata map[string]string // Parser-specific metadata
}

// PluginMetadata describes parser capabilities
type PluginMetadata struct {
	Name        string // Plugin name (e.g., "openai_v1")
	Version     string // Plugin version (e.g., "1.0.0")
	Protocol    string // Protocol identifier (e.g., "openai", "mcp")
	Description string // Human-readable description
	Author      string // Plugin author/maintainer

	// Routing hints
	SupportedPaths []string // URL paths this parser handles

	// Capabilities
	SupportsStreaming bool // Can parse streaming responses (SSE, chunked)
	SupportsRedaction bool // Can redact sensitive data
}

// PluginConfig contains parser configuration
type PluginConfig struct {
	Timeout      time.Duration     // Max parse time (default: 5s)
	MaxBodySize  int               // Max body size to parse (default: 64KB)
	EnableDebug  bool              // Enable debug logging
	CustomConfig map[string]string // Parser-specific config
}

// ParsedAttributes is an alias for attribute map
type ParsedAttributes map[string]interface{}
