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

package loxinet

import (
	"context"
	"encoding/json"
	"fmt"
)

// internalMockParser is a simple test parser built into loxinet
// Used as default/fallback parser for testing
type internalMockParser struct{}

// Parse extracts mock attributes from body
func (m *internalMockParser) Parse(ctx context.Context, req *ParseRequest) (*ParseResponse, error) {
	// Try to parse as JSON (best effort)
	var bodyMap map[string]interface{}
	if err := json.Unmarshal(req.Body, &bodyMap); err != nil {
		// Not JSON, return generic attributes
		return &ParseResponse{
			Attributes: map[string]interface{}{
				"mock.parser":       "mock_v1",
				"mock.body_size":    len(req.Body),
				"mock.method":       req.Method,
				"mock.path":         req.Path,
				"mock.content_type": req.ContentType,
			},
		}, nil
	}

	// Extract all JSON fields as attributes
	attrs := make(map[string]interface{})
	attrs["mock.parser"] = "mock_v1"
	attrs["mock.body_size"] = len(req.Body)
	attrs["mock.method"] = req.Method
	attrs["mock.path"] = req.Path
	attrs["mock.content_type"] = req.ContentType

	// Flatten JSON to dot-notation attributes
	for key, value := range bodyMap {
		attrs[fmt.Sprintf("mock.json.%s", key)] = value
	}

	return &ParseResponse{
		Attributes: attrs,
	}, nil
}

// Metadata returns mock parser information
func (m *internalMockParser) Metadata() PluginMetadata {
	return PluginMetadata{
		Name:              "mock_parser",
		Version:           "1.0.0",
		Protocol:          "mock",
		Description:       "Internal mock parser for testing",
		Author:            "LoxiLB Team",
		SupportedPaths:    []string{"/test", "/mock", "/debug"},
		SupportsStreaming: false,
		SupportsRedaction: false,
	}
}

// Validate checks if body is valid (always true for mock)
func (m *internalMockParser) Validate(body []byte) bool {
	return len(body) > 0
}

// newInternalMockParser creates a new mock parser instance
func newInternalMockParser() *internalMockParser {
	return &internalMockParser{}
}
