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

package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/loxilb-io/loxilb/pkg/loxinet"
)

// MockParser is a test parser that always succeeds
// Used for testing the plugin architecture without OpenAI complexity
type MockParser struct {
	// Optional: Configure parser behavior for testing
	DelayMs        int  // Simulate slow parsing
	ShouldFail     bool // Simulate parse errors
	ShouldPanic    bool // Simulate parser panics
	ValidateResult bool // Control Validate return value
}

// Parse extracts mock attributes from body
func (m *MockParser) Parse(ctx context.Context, req *loxinet.ParseRequest) (*loxinet.ParseResponse, error) {
	// Simulate delay if configured
	if m.DelayMs > 0 {
		time.Sleep(time.Duration(m.DelayMs) * time.Millisecond)
	}

	// Simulate panic if configured
	if m.ShouldPanic {
		panic("intentional panic for testing")
	}

	// Simulate error if configured
	if m.ShouldFail {
		return nil, fmt.Errorf("intentional error for testing")
	}

	// Try to parse as JSON (best effort)
	var bodyMap map[string]interface{}
	if err := json.Unmarshal(req.Body, &bodyMap); err != nil {
		// Not JSON, return generic attributes
		return &loxinet.ParseResponse{
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

	return &loxinet.ParseResponse{
		Attributes: attrs,
	}, nil
}

// Metadata returns mock parser information
func (m *MockParser) Metadata() loxinet.PluginMetadata {
	return loxinet.PluginMetadata{
		Name:        "mock_parser",
		Version:     "1.0.0",
		Protocol:    "mock",
		Description: "Mock parser for testing plugin architecture",
		Author:      "LoxiLB Team",
		SupportedPaths: []string{
			"/test",
			"/mock",
			"/debug",
		},
		SupportsStreaming: false,
		SupportsRedaction: false,
	}
}

// Validate checks if body is valid (always true unless configured otherwise)
func (m *MockParser) Validate(body []byte) bool {
	if m.ValidateResult {
		return true
	}
	// By default, accept any non-empty body
	return len(body) > 0
}
